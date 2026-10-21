"""Untrusted-segment and tool-argument extraction.

Untrusted means a message role or source category, never a text classifier.
Excerpts are cleaned and length-limited. Full prompts are not retained.
"""
import hashlib
import json
import posixpath
import re
import urllib.parse

try:
    from runtime.redact import redact_text
except ImportError:
    from redact import redact_text

EXCERPT_LIMIT = 512
PAYLOAD_LIMIT = 8192
SHELL_NAME_TOKENS = (
    'terminal', 'shell', 'code_interpreter', 'bash', 'powershell',
    'code-interpreter', 'code_exec', 'command', 'exec',
)
COMMAND_KEYS = ('command', 'cmd', 'shell_command', 'script', 'code', 'input')
UNTRUSTED_SOURCES = {
    'tool_result', 'retrieval', 'knowledge', 'document', 'upload', 'web', 'file', 'url',
}
_URL = re.compile(r'https?://[^\s\'"<>]+', re.I)
_HOST_PORT = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::(\d{1,5}))?\b')


def digest_text(value):
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(value.encode()).hexdigest()


def content_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                parts.append(str(part.get('text') or part.get('content') or ''))
        return '\n'.join(parts)
    if content is None:
        return ''
    return json.dumps(content, ensure_ascii=False, sort_keys=True)[:4000]


def _source_kind(message):
    for key in ('sourceKind', 'source', 'origin'):
        value = str(message.get(key) or '').strip().lower()
        if not value:
            continue
        if value in UNTRUSTED_SOURCES:
            return value
        if any(token in value for token in ('retriev', 'knowledge', 'upload', 'document', 'webpage')):
            return 'retrieval'
    content = message.get('content')
    if isinstance(content, list):
        for part in content:
            if not isinstance(part, dict):
                continue
            kind = str(part.get('type') or '').lower()
            if kind in ('file', 'input_file', 'document', 'image_url'):
                return 'upload'
            nested = str(part.get('sourceKind') or part.get('source') or '').lower()
            if nested in UNTRUSTED_SOURCES:
                return nested
    return ''


def untrusted_segments(messages):
    """Segments that can trigger S02/S03 have confidence observed. Unknown never triggers."""
    segments = []
    for message in messages or []:
        if not isinstance(message, dict):
            continue
        role = str(message.get('role') or '')
        source = _source_kind(message)
        if role == 'tool':
            source = source or 'tool_result'
            confidence = 'observed'
        elif source in UNTRUSTED_SOURCES:
            confidence = 'observed'
        elif role in ('system', 'developer', 'assistant', 'user'):
            continue
        else:
            source = source or 'unknown'
            confidence = 'unknown'
        raw = content_text(message.get('content'))
        cleaned, truncated = _excerpt(raw, EXCERPT_LIMIT)
        segments.append({
            'role': role or 'unknown',
            'sourceKind': source or 'tool_result',
            'digest': digest_text(raw),
            'excerpt': cleaned,
            'truncated': truncated,
            'confidence': confidence,
        })
    return segments


def triggering_untrusted(segments):
    return [segment for segment in (segments or []) if segment.get('confidence') == 'observed']


def _excerpt(text, limit):
    cleaned = redact_text(text or '')
    return cleaned[:limit], len(cleaned) > limit


def extract_entities(tool_name, arguments):
    parsed = _parse_arguments(arguments)
    urls, hosts, paths, commands = [], [], [], []

    def add_url(value):
        if not isinstance(value, str) or not value.lower().startswith(('http://', 'https://')):
            return
        value = value.rstrip(').,;')
        if value not in urls:
            urls.append(value)
        parts = urllib.parse.urlsplit(value)
        if parts.hostname:
            host = parts.hostname
            if parts.port:
                host = host + ':' + str(parts.port)
            if host not in hosts:
                hosts.append(host)

    def add_path(value):
        if not isinstance(value, str) or not value.startswith('/') or value.startswith('//'):
            return
        norm = posixpath.normpath(value.split()[0])
        if norm not in paths and len(norm) >= 2:
            paths.append(norm)

    def add_command(value):
        if isinstance(value, str) and value.strip() and value.strip() not in commands:
            commands.append(redact_text(value.strip())[:2048])

    def walk(value, key=''):
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, str(child_key))
            return
        if isinstance(value, list):
            for child in value[:100]:
                walk(child, key)
            return
        if not isinstance(value, str):
            return
        lowered = key.lower()
        if lowered in COMMAND_KEYS or lowered in ('query',):
            if lowered in COMMAND_KEYS:
                add_command(value)
        if lowered in ('url', 'uri', 'endpoint', 'href'):
            add_url(value)
        if lowered in ('path', 'file', 'filepath', 'filename', 'output', 'dest'):
            add_path(value)
        if lowered in ('host', 'hostname', 'ip', 'destination'):
            if value not in hosts:
                hosts.append(value)
        for match in _URL.findall(value):
            add_url(match)
        stripped = _URL.sub(' ', value)
        for match in re.findall(r'(?<![\w])(/[\w./@+\-]{2,})', stripped):
            add_path(match)

    walk(parsed)
    if isinstance(arguments, str):
        walk(arguments)
    for command in list(commands):
        for match in _URL.findall(command):
            add_url(match)
        stripped = _URL.sub(' ', command)
        for match in re.findall(r'(?<![\w])(/[\w./@+\-]{2,})', stripped):
            add_path(match)
    canonical = json.dumps(parsed if parsed != arguments else arguments, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return {
        'urls': urls[:32],
        'hosts': hosts[:32],
        'paths': paths[:32],
        'commands': commands[:32],
        'argsDigest': hashlib.sha256(redact_text(canonical).encode()).hexdigest(),
        'toolName': tool_name or '',
    }


def _parse_arguments(arguments):
    if isinstance(arguments, (dict, list)):
        return arguments
    if not isinstance(arguments, str) or not arguments.strip():
        return {}
    try:
        value = json.loads(arguments)
    except ValueError:
        return {'_raw': arguments[:4096]}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {'_raw': value[:4096]}
    return value


def high_risk_reasons(tool_name, entities, allowed_networks=None):
    """Reasons a tool call is high risk. Empty means it cannot open an S02/S03 alert."""
    try:
        from runtime.engine import network_allowed, risky_command, sensitive_path
    except ImportError:
        from engine import network_allowed, risky_command, sensitive_path

    reasons = []
    name = (tool_name or '').lower().replace('-', '_')
    if any(token in name for token in SHELL_NAME_TOKENS):
        reasons.append('tool_name')
    entities = entities or {}
    for path in entities.get('paths') or []:
        if sensitive_path(path) or _persistence(path):
            reasons.append('sensitive_or_persist_path')
            break
    for command in entities.get('commands') or []:
        if risky_command(command) or re.search(r'\b(curl|wget)\b', command):
            reasons.append('command_pattern')
            break
        if re.search(r'(?:^|[/\s])(?:bash|sh|dash|zsh|nc|ncat)\b', command) and len(command) > 12:
            reasons.append('shell_command')
            break
    if allowed_networks:
        for host in entities.get('hosts') or []:
            address, _, port_text = host.partition(':')
            port = int(port_text) if port_text.isdigit() else None
            if not network_allowed(address, port, allowed_networks):
                reasons.append('non_allowlisted_destination')
                break
    return list(dict.fromkeys(reasons))


def _persistence(path):
    try:
        from runtime.engine import persistence_path
    except ImportError:
        from engine import persistence_path
    return persistence_path(path)


def bound_event(event):
    """Keep a semantic event payload within 8 KiB. Digests are preserved; text is cut."""
    event = dict(event)
    event.pop('resource', None)

    def shrink():
        return len(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode())

    if shrink() <= PAYLOAD_LIMIT:
        return event
    event['truncated'] = True
    for key in ('textExcerpt', 'command'):
        if isinstance(event.get(key), str) and len(event[key]) > EXCERPT_LIMIT:
            event[key] = event[key][:EXCERPT_LIMIT]
    segments = []
    for segment in (event.get('untrustedSegments') or [])[:8]:
        item = dict(segment)
        if isinstance(item.get('excerpt'), str):
            item['excerpt'] = item['excerpt'][:256]
        segments.append(item)
    event['untrustedSegments'] = segments
    entities = dict(event.get('argsEntities') or {})
    for key in ('urls', 'hosts', 'paths', 'commands'):
        entities[key] = [str(x)[:256] for x in (entities.get(key) or [])[:8]]
    event['argsEntities'] = entities
    if shrink() > PAYLOAD_LIMIT:
        event['untrustedSegments'] = [{'digest': s.get('digest'), 'confidence': s.get('confidence'), 'sourceKind': s.get('sourceKind'), 'role': s.get('role')} for s in segments]
        event['textExcerpt'] = ''
    return event


class ChainBook:
    """Join rounds by the tool_call_id the client already echoes. Responses are not rewritten."""

    def __init__(self, limit=10000):
        self.tool_to_chain = {}
        self.chain_untrusted = {}
        self.order = []
        self.limit = limit

    def observe_request(self, request_id, messages):
        echoed = []
        for message in messages or []:
            if not isinstance(message, dict):
                continue
            if message.get('role') == 'tool' and message.get('tool_call_id'):
                echoed.append(str(message['tool_call_id']))
            if message.get('role') == 'assistant':
                for call in message.get('tool_calls') or []:
                    if isinstance(call, dict) and call.get('id'):
                        echoed.append(str(call['id']))
        found = []
        for tool_id in echoed:
            chain = self.tool_to_chain.get(tool_id)
            if chain and chain not in found:
                found.append(chain)
        conflict = len(found) > 1
        if len(found) == 1:
            chain_id = found[0]
            joined = True
        else:
            chain_id = request_id
            joined = False
        segments = untrusted_segments(messages)
        if triggering_untrusted(segments) and not conflict:
            self.chain_untrusted[chain_id] = True
        return {
            'chainId': chain_id,
            'joined': joined,
            'conflict': conflict,
            'chainConfidence': 'unknown' if conflict else 'correlated' if joined else 'observed',
            'untrustedSegments': segments,
            'chainHasUntrusted': bool(self.chain_untrusted.get(chain_id)) and not conflict,
        }

    def remember_tool(self, chain_id, tool_call_id):
        if not tool_call_id or not chain_id:
            return
        self.tool_to_chain[str(tool_call_id)] = chain_id
        self.order.append(str(tool_call_id))
        if len(self.order) > self.limit:
            stale = self.order.pop(0)
            self.tool_to_chain.pop(stale, None)
