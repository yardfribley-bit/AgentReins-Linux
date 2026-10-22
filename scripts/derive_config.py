#!/usr/bin/env python3
"""Suggest deploy config from a capture. Read-only.

Reads the runtime SQLite database and an optional gateway JSONL. Prints a YAML
patch: allowedTools, toolThresholds (p99 x 3), allowedNetworks, and candidate
knowledgeMarkers. It does not write the database or the live config.
"""
import argparse
import json
import math
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_TAG = re.compile(r'<([A-Za-z][\w:.-]{0,32})>(.{1,4000}?)</\1>', re.S)


def epoch(value):
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return float(text)


def _in_window(when, start, end):
    if when is None:
        return False
    if start is not None and when < start:
        return False
    if end is not None and when > end:
        return False
    return True


def _json_object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value[:1] in '{[':
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def read_db(path, start, end):
    uri = 'file:%s?mode=ro' % Path(path).resolve().as_posix()
    connection = sqlite3.connect(uri, uri=True)
    connection.execute('PRAGMA query_only=ON')
    try:
        rows = connection.execute('SELECT payload FROM events').fetchall()
    finally:
        connection.close()
    events = []
    for (payload,) in rows:
        try:
            event = json.loads(payload)
        except (TypeError, ValueError):
            continue
        if _in_window(float(event.get('time') or 0), start, end):
            events.append(event)
    return events


def read_log(path, start, end):
    records = []
    with open(path, 'r', encoding='utf-8', errors='replace') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            when = epoch(record.get('time'))
            if when is None or _in_window(when, start, end):
                record['_epoch'] = when
                records.append(record)
    return records


def _tool_calls(events, records):
    calls = []
    for event in events:
        if event.get('operation') != 'TOOL_CALL' and event.get('kind') != 'tool':
            continue
        if event.get('operation') and event.get('operation') != 'TOOL_CALL':
            continue
        name = event.get('toolName')
        if not name:
            continue
        calls.append({
            'agent': str(event.get('agentId') or ''),
            'name': str(name),
            'time': float(event.get('time') or 0),
            'chain': str(event.get('chainId') or event.get('runId') or ''),
        })
    for record in records:
        evidence = record.get('evidence') if isinstance(record.get('evidence'), dict) else {}
        if record.get('operation') != 'TOOL_CALL' and not evidence.get('toolName'):
            continue
        if record.get('operation') not in (None, 'TOOL_CALL'):
            continue
        name = evidence.get('toolName')
        if not name:
            continue
        calls.append({
            'agent': str(evidence.get('agentId') or record.get('agentId') or ''),
            'name': str(name),
            'time': float(record.get('_epoch') or 0),
            'chain': str(evidence.get('chainId') or ''),
        })
    return calls


def _networks(events, records):
    found = []
    for event in events:
        if event.get('kind') != 'network' and event.get('operation') not in ('AUDIT_CONNECT', 'AUDIT_SENDTO'):
            continue
        destination = event.get('destination')
        if not destination:
            continue
        found.append({
            'agent': str(event.get('agentId') or ''),
            'destination': str(destination),
            'port': _port(event.get('port')),
        })
    for record in records:
        evidence = record.get('evidence') if isinstance(record.get('evidence'), dict) else {}
        destination = evidence.get('destination') or record.get('destination')
        if record.get('operation') not in ('AUDIT_CONNECT', 'AUDIT_SENDTO', 'NETWORK') and not destination:
            continue
        if not destination:
            continue
        found.append({
            'agent': str(evidence.get('agentId') or record.get('agentId') or ''),
            'destination': str(destination),
            'port': _port(evidence.get('port') if evidence.get('port') is not None else record.get('port')),
        })
    return found


def _message_text(message):
    content = message.get('content')
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get('text'), str):
                parts.append(part['text'])
            elif isinstance(part, str):
                parts.append(part)
        if parts:
            return '\n'.join(parts)
    return ''


def _system_texts(records):
    grouped = defaultdict(list)
    for record in records:
        evidence = record.get('evidence') if isinstance(record.get('evidence'), dict) else {}
        agent = str(evidence.get('agentId') or record.get('agentId') or '')
        blobs = [record, _json_object(record.get('resource')), evidence, _json_object(evidence.get('resource'))]
        for blob in blobs:
            messages = blob.get('messages') if isinstance(blob, dict) else None
            if not isinstance(messages, list):
                continue
            for message in messages:
                if not isinstance(message, dict) or message.get('role') not in ('system', 'developer'):
                    continue
                text = _message_text(message)
                if text:
                    grouped[agent].append(text)
    return grouped


def candidate_markers(texts):
    counts = Counter()
    for text in texts:
        seen = set()
        for match in _TAG.finditer(text):
            pair = ('<' + match.group(1) + '>', '</' + match.group(1) + '>')
            if pair in seen:
                continue
            seen.add(pair)
            counts[pair] += 1
    ranked = [(pair, count) for pair, count in counts.items() if count >= 2]
    ranked.sort(key=lambda item: (-item[1], item[0][0]))
    if not ranked:
        return None
    (start, end), count = ranked[0]
    return {'start': start, 'end': end, 'count': count}


def p99(values):
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(0.99 * len(ordered)))
    return ordered[rank - 1]


def _thresholds(calls):
    per_agent = {}
    per_minute = defaultdict(int)
    per_chain = defaultdict(int)
    for call in calls:
        minute = int(call['time'] // 60)
        per_minute[(call['agent'], minute)] += 1
        if call['chain']:
            per_chain[(call['agent'], call['chain'], call['name'])] += 1
    agents = sorted({call['agent'] for call in calls})
    for agent in agents:
        minutes = [count for (item_agent, _minute), count in per_minute.items() if item_agent == agent]
        chains = [count for (item_agent, _chain, _name), count in per_chain.items() if item_agent == agent]
        minute_p = p99(minutes)
        chain_p = p99(chains)
        per_agent[agent] = {
            'perMinute': None if minute_p is None else int(minute_p * 3),
            'perChainTool': None if chain_p is None else int(chain_p * 3),
        }
    minute_values = list(per_minute.values())
    chain_values = list(per_chain.values())
    global_minute = p99(minute_values)
    global_chain = p99(chain_values)
    return per_agent, {
        'perMinute': None if global_minute is None else int(global_minute * 3),
        'perChainTool': None if global_chain is None else int(global_chain * 3),
    }


def _port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ip_literal(value):
    text = str(value or '')
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', text) or ':' in text:
        try:
            import ipaddress
            ipaddress.ip_address(text)
            return text
        except ValueError:
            return ''
    return ''


def suggest(events, records):
    calls = _tool_calls(events, records)
    networks = _networks(events, records)
    per_agent_thresholds, global_thresholds = _thresholds(calls)
    agent_ids = {item for item in ([call['agent'] for call in calls] + [item['agent'] for item in networks]) if item}
    by_agent = {agent: {'tools': sorted({call['name'] for call in calls if call['agent'] == agent}), 'networks': []} for agent in agent_ids}
    for item in networks:
        agent = item['agent']
        if not agent:
            continue
        body = by_agent.setdefault(agent, {'tools': [], 'networks': []})
        ip = _ip_literal(item['destination'])
        if not ip:
            body.setdefault('names', []).append(item['destination'])
            continue
        body['networks'].append((ip, item.get('port')))
    unscoped = None
    for agent, texts in _system_texts(records).items():
        found = candidate_markers(texts)
        if not found:
            continue
        if not agent:
            unscoped = found
            continue
        body = by_agent.setdefault(agent, {'tools': [], 'networks': []})
        body['markers'] = found
    return {
        'agents': by_agent,
        'thresholds': global_thresholds,
        'perAgentThresholds': per_agent_thresholds,
        'markers': unscoped,
        'toolCalls': len(calls),
    }


def _quote(value):
    text = str(value)
    if re.fullmatch(r'[A-Za-z0-9_./:+-]+', text) and not re.fullmatch(r'-?\d+', text):
        return text
    return json.dumps(text, ensure_ascii=False)


def render(suggestion):
    lines = [
        '# generated by derive_config.py',
        '# Review before use. This file is a suggestion, not a live config.',
        '# A short capture understates p99. The drill template floor is perMinute 30 and perChainTool 12.',
        '# Keep the greater of that floor and the number below when the window is shorter than a busy hour.',
        '# Addresses below are whatever the capture contained. Do not commit a filled production file.',
    ]
    thresholds = suggestion.get('thresholds') or {}
    if thresholds.get('perMinute') is None and thresholds.get('perChainTool') is None:
        lines.append('# toolThresholds: no tool calls in this window')
    else:
        lines.append('toolThresholds:')
        if thresholds.get('perMinute') is not None:
            lines.append('  perMinute: %d' % thresholds['perMinute'])
        if thresholds.get('perChainTool') is not None:
            lines.append('  perChainTool: %d' % thresholds['perChainTool'])
        for agent, item in sorted((suggestion.get('perAgentThresholds') or {}).items()):
            lines.append('# %s perMinute p99x3=%s perChainTool p99x3=%s' % (agent or '(no agent)', item.get('perMinute'), item.get('perChainTool')))
    agents = suggestion.get('agents') or {}
    names = sorted(agents)
    if not names:
        lines.append('agents: []')
    else:
        lines.append('agents:')
    for agent in names:
        body = agents[agent]
        lines.append('  - id: %s' % _quote(agent))
        tools = body.get('tools') or []
        if tools:
            lines.append('    allowedTools: [%s]' % ', '.join(_quote(name) for name in tools))
        else:
            lines.append('    # allowedTools: none observed for this agent')
        grouped = defaultdict(set)
        for ip, port in body.get('networks') or []:
            grouped[ip].add(port)
        if grouped:
            lines.append('    allowedNetworks:')
            for ip in sorted(grouped):
                ports = sorted(port for port in grouped[ip] if isinstance(port, int))
                lines.append('      - cidr: %s' % _quote(ip + '/32'))
                if ports:
                    lines.append('        ports: [%s]' % ', '.join(str(port) for port in ports))
        else:
            lines.append('    # allowedNetworks: no IP literals observed for this agent')
        hostnames = sorted({str(item) for item in (body.get('names') or [])})
        for name in hostnames:
            lines.append('    # hostname not usable for S05: %s' % _quote(name))
        markers = body.get('markers')
        if markers:
            lines.append('    # candidate knowledgeMarkers from %d system texts. TO-VERIFY before enabling I1.' % markers['count'])
            lines.append('    knowledgeMarkers:')
            lines.append('      start: %s' % _quote(markers['start']))
            lines.append('      end: %s' % _quote(markers['end']))
    markers = suggestion.get('markers')
    scoped = any(isinstance(body, dict) and body.get('markers') for body in agents.values())
    if markers:
        lines.append('# candidate knowledgeMarkers from repeated system-prompt wrappers (%d texts). TO-VERIFY before enabling I1.' % markers['count'])
        lines.append('knowledgeMarkers:')
        lines.append('  start: %s' % _quote(markers['start']))
        lines.append('  end: %s' % _quote(markers['end']))
    elif not scoped:
        lines.append('# knowledgeMarkers: no repeated wrapper found. TO-VERIFY against a captured system prompt.')
    lines.append('')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Suggest allowedTools, thresholds, networks, and knowledge markers')
    parser.add_argument('--db', action='append', default=[], help='runtime SQLite path; opened read-only; repeatable')
    parser.add_argument('--gateway-log', action='append', default=[], help='gateway or semantic JSONL; repeatable')
    parser.add_argument('--since', help='window start, ISO-8601 or epoch seconds')
    parser.add_argument('--until', help='window end, ISO-8601 or epoch seconds')
    parser.add_argument('--out', help='also write the YAML patch to this path')
    args = parser.parse_args(argv)
    start = epoch(args.since) if args.since else None
    end = epoch(args.until) if args.until else None
    events = []
    for path in args.db:
        events.extend(read_db(path, start, end))
    records = []
    for path in args.gateway_log:
        records.extend(read_log(path, start, end))
    text = render(suggest(events, records))
    sys.stdout.write(text)
    if args.out:
        Path(args.out).write_text(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
