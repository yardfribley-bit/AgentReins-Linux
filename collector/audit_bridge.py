#!/usr/bin/env python3
"""Normalize Linux audit records into the existing AgentReins evidence stream."""
import collections
import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import time

LOG = '/var/log/audit/audit.log'
OUT = '/var/log/agentreins/audit.jsonl'
CURSOR = '/var/log/agentreins/audit.cursor'
FIELDS = re.compile(r'(\w+)=("[^"]*"|\S+)')
GROUP = re.compile(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):')
cache = {}

def decode(value):
    if value.startswith('"'):
        return value[1:-1]
    if len(value) % 2 == 0 and re.fullmatch(r'[0-9A-Fa-f]+', value):
        return bytes.fromhex(value).decode('utf-8', 'replace')
    return value

def redact(value):
    value = re.sub(r'(?i)((?:password|passwd|token|secret|api[_-]?key|cookie)\s*[=:]\s*)[^\s"\']+', r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(--(?:password|passwd|token|secret|api[_-]?key)\s+)\S+', r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(Authorization:\s*(?:Bearer|Basic)\s+)\S+', r'\1[REDACTED]', value)
    return re.sub(r'(https?://[^\s/:]+:)[^@/\s]+@', r'\1[REDACTED]@', value)

def identity(pid):
    try:
        cg = open(f'/proc/{pid}/cgroup').read()
        match = re.search(r'([0-9a-f]{64})', cg)
        ns = {}
        for name in ('pid', 'mnt', 'net', 'user'):
            ns[name] = os.readlink(f'/proc/{pid}/ns/{name}')
        result = {'containerId': match[1][:12] if match else '', 'cgroup': cg.strip(), 'namespaces': ns}
        cache[pid] = (time.monotonic(), result)
        return result
    except OSError:
        old = cache.get(pid)
        return dict(old[1], attribution='RECENT_PID_CACHE') if old and time.monotonic()-old[0] < 5 else {'containerId': '', 'attribution': 'UNKNOWN'}

def destination(value):
    try:
        raw = bytes.fromhex(value)
        family = int.from_bytes(raw[:2], 'little')
        port = int.from_bytes(raw[2:4], 'big')
        if family == 2:
            address = socket.inet_ntop(socket.AF_INET, raw[4:8])
        elif family == 10:
            address = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        else:
            return None
        return address, port
    except (ValueError, OSError):
        return None

def emit(timestamp, serial, records):
    calls = [f for t, f in records if t == 'SYSCALL']
    if not calls:
        return
    call = calls[0]
    key = decode(call.get('key', ''))
    if not key.startswith('agentreins_'):
        return
    pid = int(call.get('pid', '0'))
    ident = next((f for t,f in records if t == 'IDENTITY'), None) or identity(pid)
    arguments = {}
    fragments = collections.defaultdict(dict)
    proctitle = ''
    for kind, fields in records:
        if kind == 'EXECVE':
            for k,v in fields.items():
                if re.fullmatch(r'a\d+', k):
                    arguments[int(k[1:])] = decode(v)
                else:
                    match = re.fullmatch(r'a(\d+)\[(\d+)\]', k)
                    if match:
                        fragments[int(match[1])][int(match[2])] = decode(v)
        if kind == 'PROCTITLE':
            proctitle = decode(fields.get('proctitle', '')).replace('\0', ' ')
    for index, parts in fragments.items():
        arguments[index] = ''.join(part for _,part in sorted(parts.items()))
    cmd = ' '.join(value for _,value in sorted(arguments.items())) or proctitle
    resource = redact(cmd or decode(call.get('exe', '')))
    category, operation = 'kernel', 'AUDIT_EXEC'
    extra = {'syscall': call.get('syscall'), 'arch': call.get('arch'), 'uid': call.get('uid'), 'auid': call.get('auid'), 'exit': call.get('exit'), 'auditSerial': serial, **ident}
    extra['cwd'] = next((decode(f.get('cwd','')) for t,f in records if t == 'CWD'), '')
    if key == 'agentreins_network':
        endpoint = next((destination(f.get('saddr','')) for t,f in records if t == 'SOCKADDR'), None)
        if not endpoint:
            return
        address, port = endpoint
        category = 'network'
        operation = 'AUDIT_SENDTO' if (call.get('arch') == 'c000003e' and call.get('syscall') == '44') or (call.get('arch') == '40000003' and call.get('syscall') == '369') else 'AUDIT_CONNECT'
        resource = f'{address}:{port}'
        extra.update(destination=address, port=port, classification='EXTERNAL_EGRESS' if ipaddress.ip_address(address).is_global else 'PRIVATE_OR_LOCAL')
    elif key == 'agentreins_sandbox':
        category, operation = 'sandbox', 'AUDIT_BOUNDARY'
        extra['arguments'] = {k: call[k] for k in ('a0','a1','a2','a3') if k in call}
    elif key == 'agentreins_files':
        category, operation = 'kernel', 'AUDIT_FILE'
        resource = ', '.join(decode(f.get('name','')) for t,f in records if t == 'PATH')
    event = {'time': datetime.datetime.fromtimestamp(float(timestamp)).astimezone().isoformat(), 'component': 'HostAudit', 'category': category, 'operation': operation, 'process': decode(call.get('exe','')), 'pid': pid, 'ppid': int(call.get('ppid','0')), 'containerId': ident.get('containerId',''), 'container': ident.get('containerId',''), 'resource': resource, 'data': json.dumps(extra, ensure_ascii=False), 'result': 'SUCCESS' if call.get('success') == 'yes' else 'FAILED_OR_PENDING', 'source': 'Linux audit subsystem', 'evidence': extra}
    if operation == 'AUDIT_CONNECT' and call.get('exit') == '-115':
        event['result'] = 'CONNECT_PENDING'
    event['eventKey'] = hashlib.sha256(f'{timestamp}:{serial}:{operation}'.encode()).hexdigest()
    line = (json.dumps(event, ensure_ascii=False)+'\n').encode()
    for path in (OUT, '/var/log/agentreins/host.jsonl'):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)

def main():
    pending = collections.OrderedDict()
    handle = open(LOG)
    try:
        cursor = json.load(open(CURSOR))
        if cursor['inode'] == os.fstat(handle.fileno()).st_ino and cursor['offset'] <= os.fstat(handle.fileno()).st_size:
            handle.seek(cursor['offset'])
    except (OSError, ValueError, KeyError):
        pass
    checkpoint = time.monotonic()
    while True:
        offset = handle.tell()
        line = handle.readline()
        if line:
            match = GROUP.search(line)
            if match:
                kind, timestamp, serial = match.groups()
                item = pending.setdefault((timestamp,serial), [time.monotonic(), [], offset])
                fields = dict(FIELDS.findall(line[match.end():]))
                item[1].append((kind, fields))
                if kind == 'SYSCALL' and fields.get('key', '').strip('"').startswith('agentreins_'):
                    ident = identity(int(fields.get('pid','0')))
                    if ident.get('attribution') == 'UNKNOWN':
                        parent = identity(int(fields.get('ppid','0')))
                        if parent.get('containerId'):
                            ident = {'containerId': parent['containerId'], 'attribution': 'PARENT_CORRELATION'}
                    item[1].append(('IDENTITY', ident))
                if kind == 'EOE':
                    emit(timestamp, serial, pending.pop((timestamp,serial))[1])
            continue
        for group, (created,records,_offset) in list(pending.items()):
            if time.monotonic()-created > 2:
                emit(*group, records)
                pending.pop(group)
        try:
            if os.stat(LOG).st_ino != os.fstat(handle.fileno()).st_ino:
                for group, (_created,records,_offset) in pending.items():
                    emit(*group, records)
                pending.clear()
                handle.close()
                handle = open(LOG)
        except FileNotFoundError:
            pass
        if time.monotonic()-checkpoint > 2:
            cursor = {'inode': os.fstat(handle.fileno()).st_ino, 'offset': min((item[2] for item in pending.values()), default=handle.tell())}
            with open(CURSOR+'.tmp', 'w') as output:
                json.dump(cursor, output)
            os.replace(CURSOR+'.tmp', CURSOR)
            checkpoint = time.monotonic()
        if len(cache) > 10000:
            cache.clear()
        time.sleep(0.2)

if __name__ == '__main__':
    main()
