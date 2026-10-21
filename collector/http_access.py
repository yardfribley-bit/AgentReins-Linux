#!/usr/bin/env python3
"""Tail JSON access logs and emit one 60-second summary per agent.

Raw lines stay in a local JSONL. The summary keeps counts, path hashes, and
category labels. Request URIs are not copied into the event the engine stores.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import select
import sys
import time

def _imports():
    try:
        from runtime.agents_config import agent_for_access, load_agents, login_path, request_path
        from runtime.redact import redact_text
        return agent_for_access, load_agents, login_path, request_path, redact_text
    except ImportError:
        sys.path.insert(0, os.environ.get('AGENTREINS_RUNTIME', '/opt/agentreins-runtime'))
        from agents_config import agent_for_access, load_agents, login_path, request_path
        from redact import redact_text
        return agent_for_access, load_agents, login_path, request_path, redact_text

agent_for_access, load_agents, login_path, request_path, redact_text = _imports()

# Query separators are not a category: a normal search string contains "&".
# Patterns here are labels only. Tests inject a placeholder category and do not
# need these expressions.
DEFAULT_CATEGORIES = (
    (re.compile(r'(?i)\bunion\s+(?:all\s+)?select\b'), 'sql_union'),
    (re.compile(r'(?i)\b(?:or|and)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+'), 'sql_tautology'),
    (re.compile(r'(?i)\b(?:sleep|benchmark|pg_sleep)\s*\('), 'sql_time'),
    (re.compile(r'(?i)\binformation_schema\b|\bsqlite_master\b'), 'sql_schema'),
    (re.compile(r'(?i)(?:\.\./){2,}|(?:%2e%2e%2f){2,}|(?:%2e%2e/){2,}'), 'path_traversal'),
    (re.compile(r'(?i)<\s*script\b|javascript\s*:'), 'script_markup'),
    (re.compile(r'(?i)\b(?:sqlmap|nikto|nmap|dirbuster|gobuster|wpscan|acunetix|nessus|masscan)\b'), 'scanner_ua'),
    (re.compile(r'(?i)(?:^|/)(?:wp-login\.php|phpmyadmin|admin\.php|xmlrpc\.php)(?:$|[/?])'), 'scanner_path'),
)


def classify_request(text, extra=()):
    """Return category labels for a URI, query, or user agent. Empty text is clean."""
    if not isinstance(text, str) or not text:
        return []
    found = []
    for pattern, label in tuple(DEFAULT_CATEGORIES) + tuple(extra or ()):
        if not re.fullmatch(r'[a-z0-9_]{1,40}', label or ''):
            continue
        if pattern.search(text) and label not in found:
            found.append(label)
        if len(found) >= 8:
            break
    return found


def _status(record):
    try:
        return int(record.get('status') if record.get('status') not in (None, '') else record.get('status_code') or 0)
    except (TypeError, ValueError):
        return 0


def _client(record):
    return str(record.get('remote_addr') or record.get('ip') or record.get('client') or record.get('address') or '-')[:64]


def _query(record):
    if record.get('query'):
        return str(record.get('query'))[:1024]
    raw = str(record.get('uri') or record.get('request_uri') or '')
    if '?' in raw:
        return raw.split('?', 1)[1][:1024]
    return ''


def _when(value, fallback):
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.datetime.fromisoformat(value).timestamp()
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            return fallback
    return fallback


class AccessWindow:
    """Aggregate one log source. One summary per agent per closed window."""

    def __init__(self, agents, window=60, client_cap=64, category_cap=32, extra_categories=()):
        self.agents = list(agents or [])
        self.window = max(1, int(window))
        self.client_cap = max(1, int(client_cap))
        self.category_cap = max(1, int(category_cap))
        self.extra_categories = tuple(extra_categories or ())
        self.buckets = {}

    def add(self, record, log_source='access', now=None):
        agent = agent_for_access(self.agents, record, log_source)
        if agent is None or not isinstance(record, dict):
            return None
        moment = _when(record.get('time'), time.time() if now is None else now)
        start = int(moment // self.window) * self.window
        key = (str(log_source or 'access'), agent['id'], start)
        bucket = self.buckets.get(key)
        if bucket is None:
            bucket = {'logSource': key[0], 'agentId': agent['id'], 'windowStart': start, 'agent': agent, 'clients': {}}
            self.buckets[key] = bucket
        address = _client(record)
        client = bucket['clients'].get(address)
        if client is None:
            client = {'requests': 0, 'paths': set(), 'notFound': 0, 'authFailures': 0, 'clientErrors': 0, 'serverErrors': 0, 'categories': {}}
            bucket['clients'][address] = client
        path = request_path(record)
        status = _status(record)
        client['requests'] += 1
        client['paths'].add(hashlib.sha256(path.encode()).hexdigest()[:16])
        if status == 404:
            client['notFound'] += 1
        if 400 <= status <= 499:
            client['clientErrors'] += 1
        if 500 <= status <= 599:
            client['serverErrors'] += 1
        if status in (401, 403) and login_path(agent, path):
            client['authFailures'] += 1
        labels = classify_request(path + (('?' + _query(record)) if _query(record) else '') + '\n' + str(record.get('ua') or record.get('user_agent') or ''), self.extra_categories)
        for label in labels:
            client['categories'][label] = client['categories'].get(label, 0) + 1
        return agent['id']

    def pop_ready(self, now, force=False):
        ready = []
        for key, bucket in list(self.buckets.items()):
            if force or now >= bucket['windowStart'] + self.window:
                ready.append(self._summary(bucket))
                del self.buckets[key]
        ready.sort(key=lambda item: (item['evidence']['windowStart'], item.get('agentId') or ''))
        return ready

    def _summary(self, bucket):
        ranked = sorted(bucket['clients'].items(), key=lambda item: (-item[1]['notFound'], -len(item[1]['paths']), -item[1]['authFailures'], -item[1]['requests'], item[0]))
        clients = []
        totals = {'requests': 0, 'distinctPaths': 0, 'notFound': 0, 'authFailures': 0, 'clientErrors': 0, 'serverErrors': 0, 'clients': len(ranked)}
        hits = []
        for address, client in ranked:
            distinct = len(client['paths'])
            totals['requests'] += client['requests']
            totals['distinctPaths'] += distinct
            totals['notFound'] += client['notFound']
            totals['authFailures'] += client['authFailures']
            totals['clientErrors'] += client['clientErrors']
            totals['serverErrors'] += client['serverErrors']
            if len(clients) < self.client_cap:
                clients.append({
                    'address': address,
                    'requests': client['requests'],
                    'distinctPaths': distinct,
                    'notFound': client['notFound'],
                    'authFailures': client['authFailures'],
                    'clientErrors': client['clientErrors'],
                    'serverErrors': client['serverErrors'],
                })
            for label, count in client['categories'].items():
                hits.append({'address': address, 'category': label, 'count': count})
        hits.sort(key=lambda item: (-item['count'], item['category'], item['address']))
        hits = hits[:self.category_cap]
        if len(ranked) > len(clients):
            totals['omittedClients'] = len(ranked) - len(clients)
        end = bucket['windowStart'] + self.window
        stamp = datetime.datetime.fromtimestamp(end, datetime.timezone.utc).isoformat()
        evidence = {
            'agentId': bucket['agentId'],
            'confidence': 'observed',
            'windowStart': bucket['windowStart'],
            'windowSeconds': self.window,
            'logSource': bucket['logSource'],
            'clients': clients,
            'totals': totals,
            'categoryHits': hits,
        }
        return {
            'time': stamp,
            'operation': 'HTTP_SUMMARY',
            'category': 'http',
            'agentId': bucket['agentId'],
            'pid': 0,
            'result': 'SUCCESS',
            'source': 'http access summary',
            'resource': bucket['logSource'],
            'eventKey': hashlib.sha256(('%s|%s|%s' % (bucket['logSource'], bucket['agentId'], bucket['windowStart'])).encode()).hexdigest(),
            'evidence': evidence,
        }


def consume_lines(lines, window, log_source='access', now=None):
    accepted = 0
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        if window.add(record, log_source, now=now):
            accepted += 1
    return accepted


def _append(path, line):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, 'a', encoding='utf-8') as handle:
        handle.write(line)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Summarize JSON access logs per agent')
    parser.add_argument('--access-log', required=True)
    parser.add_argument('--agents', default=os.environ.get('AGENTREINS_AGENTS', '/etc/agentreins/agents.yaml'))
    parser.add_argument('--out', default=os.environ.get('AGENTREINS_HOST_LOG', '/var/log/agentreins/host.jsonl'))
    parser.add_argument('--raw', default='/var/log/agentreins/http-raw.jsonl')
    parser.add_argument('--log-source', default='access')
    parser.add_argument('--window', type=int, default=60)
    args = parser.parse_args(argv)
    agents = load_agents(args.agents)
    window = AccessWindow(agents, window=args.window)
    while not os.path.exists(args.access_log):
        time.sleep(1)
    proc = __import__('subprocess').Popen(['tail', '-F', '-n', '0', args.access_log], stdout=__import__('subprocess').PIPE, text=True, bufsize=1)
    try:
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if ready:
                line = proc.stdout.readline()
                if not line:
                    break
                if line.strip():
                    _append(args.raw, redact_text(line if line.endswith('\n') else line + '\n'))
                    consume_lines([line], window, args.log_source)
            for summary in window.pop_ready(time.time()):
                _append(args.out, json.dumps(summary, ensure_ascii=False) + '\n')
            if proc.poll() is not None:
                break
        for summary in window.pop_ready(time.time(), force=True):
            _append(args.out, json.dumps(summary, ensure_ascii=False) + '\n')
    finally:
        if proc.poll() is None:
            proc.terminate()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
