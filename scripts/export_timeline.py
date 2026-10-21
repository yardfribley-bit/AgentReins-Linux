#!/usr/bin/env python3
"""Read-only time-window export of events, alerts, reviews, and coverage.

Writes JSONL, CSV, and Markdown. Each JSONL record carries prev and self
hashes (SHA-256 of the previous hash plus this record's canonical JSON).
SHA256SUMS covers the exported files. The database is opened mode=ro.
"""
import argparse
import csv
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from runtime.engine import clean
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from runtime.engine import clean


def parse_time(value):
    if value is None or value == '':
        return None
    try:
        return float(value)
    except ValueError:
        pass
    text = value.replace('Z', '+00:00')
    return datetime.fromisoformat(text).timestamp()


def connect(path):
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    db = sqlite3.connect(uri, uri=True, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    return db


def rows(db, sql, params=()):
    try:
        return list(db.execute(sql, params))
    except sqlite3.Error:
        return []


def mask(value):
    return clean(value)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def chain_records(records):
    previous = ''
    chained = []
    for record in records:
        body = canonical(record)
        current = hashlib.sha256((previous + '\n' + body).encode()).hexdigest()
        chained.append({'prev': previous, 'self': current, 'record': record})
        previous = current
    return chained, previous


def write_jsonl(path, records):
    chained, head = chain_records(records)
    with path.open('w') as handle:
        for item in chained:
            handle.write(json.dumps(item, ensure_ascii=False) + '\n')
    return head


def write_csv(path, records, columns):
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key, '') for key in columns})


def load_db(path, since, until):
    db = connect(path)
    try:
        events = []
        for row in rows(db, 'SELECT payload FROM events ORDER BY time'):
            item = json.loads(row['payload'])
            if not in_window(item.get('time'), since, until):
                continue
            item['recordType'] = 'event'
            events.append(mask(item))
        alerts = []
        for row in rows(db, 'SELECT payload FROM alerts ORDER BY time'):
            item = json.loads(row['payload'])
            if not in_window(item.get('createdAt') or item.get('firstSeen'), since, until):
                continue
            item['recordType'] = 'alert'
            alerts.append(mask(item))
        reviews = []
        for row in rows(db, 'SELECT payload FROM reviews ORDER BY time'):
            item = json.loads(row['payload'])
            if not in_window(item.get('time'), since, until):
                continue
            item['recordType'] = 'review'
            reviews.append(mask(item))
        coverage = []
        for row in rows(db, 'SELECT id, seen, payload FROM sources'):
            item = json.loads(row['payload'])
            item['recordType'] = 'coverage'
            item['source'] = row['id']
            item['seen'] = row['seen']
            coverage.append(mask(item))
        losses = []
        for row in rows(db, 'SELECT source, time, audit, sensor FROM coverage_losses ORDER BY time'):
            if not in_window(row['time'], since, until):
                continue
            losses.append({'recordType': 'coverage_loss', 'source': row['source'], 'time': row['time'], 'audit': row['audit'], 'sensor': row['sensor']})
        return events, alerts, reviews, coverage, losses
    finally:
        db.close()


def in_window(value, since, until):
    if value is None:
        return since is None and until is None
    value = float(value)
    if since is not None and value < since:
        return False
    if until is not None and value > until:
        return False
    return True


def keep(record, chain_id, agent_id):
    if not chain_id and not agent_id:
        return True
    blob = canonical(record)
    if chain_id and chain_id not in blob:
        return False
    if agent_id and agent_id not in blob:
        return False
    return True


def flat_event(event):
    return {
        'time': event.get('time'),
        'source': event.get('source'),
        'agentId': event.get('agentId'),
        'chainId': event.get('chainId'),
        'sessionId': event.get('sessionId'),
        'kind': event.get('kind'),
        'operation': event.get('operation'),
        'workload': event.get('workload'),
        'toolCallId': event.get('toolCallId'),
        'path': event.get('path'),
        'destination': event.get('destination'),
        'port': event.get('port'),
        'command': event.get('command') or event.get('textExcerpt') or '',
    }


def flat_alert(alert):
    relation = alert.get('relation') or {}
    return {
        'time': alert.get('createdAt'),
        'id': alert.get('id'),
        'rule': alert.get('rule'),
        'phase': alert.get('phase'),
        'confidence': relation.get('confidence'),
        'strength': relation.get('strength'),
        'agentId': alert.get('agentId'),
        'chainId': alert.get('chainId'),
        'toolCallId': alert.get('toolCallId'),
        'sessionId': alert.get('sessionId'),
        'severity': alert.get('severity'),
        'status': alert.get('status'),
        'title': alert.get('title'),
        'source': alert.get('source'),
    }


def markdown(events, alerts, coverage, head):
    by_rule = {}
    for alert in alerts:
        by_rule[alert.get('rule')] = by_rule.get(alert.get('rule'), 0) + 1
    chains = {}
    for alert in alerts:
        if alert.get('chainId') and alert.get('rule') in ('S02', 'S03'):
            chains.setdefault(alert['chainId'], []).append(alert)
    lines = ['# AgentReins timeline export', '', 'Observe-only export. Kernel blocking is off. Values that can authenticate are masked.', '']
    lines.append('Chain head: `%s`' % head)
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    lines.append('- events: %d' % len(events))
    lines.append('- alerts: %d' % len(alerts))
    lines.append('- rules: %s' % (', '.join('%s=%d' % (key, by_rule[key]) for key in sorted(by_rule)) or 'none'))
    lines.append('- sources: %s' % ', '.join(sorted({str(item.get('source')) for item in coverage}) or {'none'}))
    lines.append('')
    lines.append('## S02/S03 chains')
    lines.append('')
    if not chains:
        lines.append('No S02/S03 chain in this window.')
    for chain_id, items in sorted(chains.items()):
        lines.append('### %s' % chain_id)
        lines.append('')
        for alert in items:
            relation = alert.get('relation') or {}
            lines.append('- %s phase=%s confidence=%s agent=%s tool=%s' % (alert.get('rule'), alert.get('phase'), relation.get('confidence'), alert.get('agentId'), alert.get('toolCallId')))
            for link in relation.get('links') or []:
                lines.append('  - %s -> %s (%s) %s' % (link.get('from'), link.get('to'), link.get('confidence'), link.get('basis')))
        lines.append('')
    lines.append('## Coverage')
    lines.append('')
    for item in coverage:
        layers = item.get('layers') or {}
        lines.append('- %s state=%s model=%s tool=%s' % (item.get('source'), item.get('state') or 'snapshot', layers.get('model'), layers.get('tool')))
    lines.append('')
    lines.append('Volumes and bind mounts are not part of this export. File bytes are not included.')
    lines.append('')
    return '\n'.join(lines)


def export_window(databases, out_dir, since=None, until=None, chain_id=None, agent_id=None):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    events, alerts, reviews, coverage, losses = [], [], [], [], []
    for database in databases:
        ev, al, rv, cov, loss = load_db(database, since, until)
        events.extend(ev)
        alerts.extend(al)
        reviews.extend(rv)
        coverage.extend(cov)
        losses.extend(loss)
    events = [item for item in events if keep(item, chain_id, agent_id)]
    alerts = [item for item in alerts if keep(item, chain_id, agent_id)]
    reviews = [item for item in reviews if keep(item, chain_id, agent_id)]
    events.sort(key=lambda item: (float(item.get('time') or 0), str(item.get('source')), str(item.get('id'))))
    alerts.sort(key=lambda item: (float(item.get('createdAt') or 0), str(item.get('id'))))
    reviews.sort(key=lambda item: (float(item.get('time') or 0), str(item.get('id'))))
    timeline = sorted(
        events + alerts + reviews + losses,
        key=lambda item: (float(item.get('time') or item.get('createdAt') or item.get('seen') or 0), item.get('recordType', ''), str(item.get('id', ''))),
    )
    heads = {
        'events': write_jsonl(out / 'events.jsonl', events),
        'alerts': write_jsonl(out / 'alerts.jsonl', alerts),
        'reviews': write_jsonl(out / 'reviews.jsonl', reviews),
        'coverage': write_jsonl(out / 'coverage.jsonl', coverage + losses),
        'timeline': write_jsonl(out / 'timeline.jsonl', timeline),
    }
    write_csv(out / 'events.csv', [flat_event(item) for item in events], ['time', 'source', 'agentId', 'chainId', 'sessionId', 'kind', 'operation', 'workload', 'toolCallId', 'path', 'destination', 'port', 'command'])
    write_csv(out / 'alerts.csv', [flat_alert(item) for item in alerts], ['time', 'id', 'rule', 'phase', 'confidence', 'strength', 'agentId', 'chainId', 'toolCallId', 'sessionId', 'severity', 'status', 'title', 'source'])
    write_csv(out / 'coverage.csv', [{'source': item.get('source'), 'seen': item.get('seen'), 'model': (item.get('layers') or {}).get('model'), 'tool': (item.get('layers') or {}).get('tool'), 'state': item.get('state')} for item in coverage], ['source', 'seen', 'model', 'tool', 'state'])
    (out / 'timeline.md').write_text(markdown(events, alerts, coverage, heads['timeline']))
    sums = []
    for path in sorted(out.iterdir()):
        if path.name == 'SHA256SUMS':
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append('%s  %s' % (digest, path.name))
    (out / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    return {'events': len(events), 'alerts': len(alerts), 'chainHead': heads['timeline'], 'out': str(out)}


def verify_jsonl(path):
    previous = ''
    with open(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get('prev') != previous:
                return False
            body = canonical(item['record'])
            current = hashlib.sha256((previous + '\n' + body).encode()).hexdigest()
            if item.get('self') != current:
                return False
            previous = current
    return True


def verify_sums(directory):
    directory = Path(directory)
    listed = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, _, name = line.partition('  ')
        listed[name] = digest
    for path in directory.iterdir():
        if path.name == 'SHA256SUMS':
            continue
        if listed.get(path.name) != hashlib.sha256(path.read_bytes()).hexdigest():
            return False
    return set(listed) == {path.name for path in directory.iterdir() if path.name != 'SHA256SUMS'}


def main():
    parser = argparse.ArgumentParser(description='Read-only runtime timeline export')
    parser.add_argument('--db', action='append', required=True, help='SQLite path, repeat for each host')
    parser.add_argument('--out', required=True)
    parser.add_argument('--since')
    parser.add_argument('--until')
    parser.add_argument('--chain-id')
    parser.add_argument('--agent-id')
    args = parser.parse_args()
    summary = export_window(args.db, args.out, parse_time(args.since), parse_time(args.until), args.chain_id, args.agent_id)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == '__main__':
    main()
