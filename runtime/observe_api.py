"""Read-only observe APIs. Nothing here ingests, reviews, or blocks."""
import datetime
import hashlib
import json
import os
import queue
import re
import statistics
import threading
import time
from collections import Counter, deque
from pathlib import Path
from urllib.parse import unquote

try:
    from runtime.engine import RULES, compact, rule_layer
except ImportError:
    from engine import RULES, compact, rule_layer

VERSION = 'observe-0.1'
ID_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,160}$')
P0_RULES = ('S01', 'S02', 'S03', 'S04', 'S05', 'S08')
FRESH_RULES = tuple('S%02d' % n for n in range(12, 23))
PUBLIC_ALERT_KEYS = ('id', 'rule', 'severity', 'status', 'createdAt', 'count', 'firstSeen', 'lastSeen')
TARGET = 0.9

ASI = [
    {'id': 'ASI01', 'name': '目标劫持', 'level': 'partial', 'rules': ['S03']},
    {'id': 'ASI02', 'name': '工具滥用', 'level': 'partial', 'rules': ['S02', 'S03', 'S14', 'S15', 'S16']},
    {'id': 'ASI03', 'name': '身份权限', 'level': 'partial', 'rules': ['S01', 'S08', 'S13']},
    {'id': 'ASI04', 'name': '供应链', 'level': 'partial', 'rules': ['S04']},
    {'id': 'ASI05', 'name': '意外执行代码', 'level': 'full', 'rules': ['S03', 'S04', 'S22']},
    {'id': 'ASI06', 'name': '记忆投毒', 'level': 'partial', 'rules': [], 'note': '知识库标记缺失时可信度是 unknown，不告警'},
    {'id': 'ASI07', 'name': 'Agent 间通信', 'level': 'none', 'rules': []},
    {'id': 'ASI08', 'name': '级联故障', 'level': 'none', 'rules': []},
    {'id': 'ASI09', 'name': '人机信任', 'level': 'none', 'rules': []},
    {'id': 'ASI10', 'name': '失控 Agent', 'level': 'partial', 'rules': ['S14', 'S15']},
]
LANES = (
    {'id': 'input', 'name': '输入层', 'hint': '模型收到什么'},
    {'id': 'decision', 'name': '决策层', 'hint': '模型想做什么'},
    {'id': 'behavior', 'name': '行为层', 'hint': '主机实际做了什么'},
    {'id': 'alert', 'name': '告警', 'hint': 'S03 两段 / S02 / S01 / S08'},
)


def can_read_evidence(principal):
    return bool(principal and principal.get('role') in ('operator', 'referee'))


def alias_of(value):
    if not value:
        return None
    return 'ag-' + hashlib.sha256(str(value).encode()).hexdigest()[:6]


def chain_alias(value):
    if not value:
        return None
    return 'ch-' + hashlib.sha256(str(value).encode()).hexdigest()[:6]


def rule_name(rule_id):
    for rule in RULES:
        if rule['id'] == rule_id:
            return rule['name']
    return rule_id or ''


def first(query, key):
    if not query:
        return ''
    value = query.get(key, [''])
    if isinstance(value, list):
        return str(value[0] if value else '')
    return str(value or '')


def parse_time(value):
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        raise ValueError('时间格式无效')
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError('时间格式无效') from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def short_text(value, limit=72):
    text = str(value or '').replace('\n', ' ')
    if len(text) <= limit:
        return text
    return text[:limit - 1] + '…'


def short_hash(value):
    if not value:
        return None
    text = str(value)
    if len(text) <= 12:
        return text
    return text[:4] + '…' + text[-2:]


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        return None, '未安装 PyYAML，无法读取 ' + Path(path).name
    try:
        data = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return None, Path(path).name + ' 无法解析'
    if not isinstance(data, dict):
        return None, Path(path).name + ' 没有对象'
    return data, None


def agents_path(config):
    return config.get('agentsFile') or os.environ.get('AGENTREINS_AGENTS') or ''


def load_agents(config):
    path = agents_path(config)
    if not path:
        return [], '未配置 agentsFile，按 agent 生效的规则状态未知'
    if not Path(path).is_file():
        return [], 'agents 文件不存在，按 agent 生效的规则状态未知'
    data, err = load_yaml(path)
    if err:
        return [], err
    agents = data.get('agents') if isinstance(data, dict) else None
    if not isinstance(agents, list):
        return [], 'agents 文件没有 agents 列表'
    return [item for item in agents if isinstance(item, dict)], None


def drill_path(config):
    chosen = config.get('drillFile') or os.environ.get('AGENTREINS_DRILL')
    if chosen:
        return Path(chosen)
    etc = Path('/etc/agentreins-runtime/drill.yaml')
    if etc.is_file():
        return etc
    return Path(__file__).resolve().parent.parent / 'config' / 'drill.yaml'


def load_drill(config):
    path = drill_path(config)
    if not path.is_file():
        return {'version': 1, 'public': False, 'label': '未配置演练', 'scenarios': []}, '未找到 drill.yaml，计分板为空'
    data, err = load_yaml(path)
    if err:
        return {'version': 1, 'public': False, 'label': '演练配置不可读', 'scenarios': []}, err
    data.setdefault('scenarios', [])
    data.setdefault('public', False)
    data.setdefault('label', path.name)
    return data, None


def replay_dataset():
    path = Path(__file__).with_name('replay_dataset.json')
    return json.loads(path.read_text(encoding='utf-8'))


def rule_enabled(rule_id, config, agents, agents_err):
    if rule_id == 'P01':
        return True, '只保护已接入的执行器；观测台不能放行或阻断'
    if rule_id == 'S15':
        thresholds = config.get('toolThresholds') or {}
        enabled = bool(thresholds.get('perMinute') or thresholds.get('perChainTool'))
        return enabled, 'toolThresholds 已配置' if enabled else 'runtime 未配置 toolThresholds，频率规则不启用'
    per_agent = {
        'S02': ('allowedNetworks', '非白名单外联只在该 agent 配置了 allowedNetworks 时成立'),
        'S05': ('allowedNetworks', '没有 agent 配置 allowedNetworks，授权范围外连接不启用'),
        'S14': ('allowedTools', '没有 agent 配置 allowedTools，未登记工具规则不启用'),
        'S22': ('webServers', '没有 agent 配置 webServers，派生 shell 规则不启用'),
    }
    if rule_id in per_agent:
        key, reason = per_agent[rule_id]
        if agents_err:
            return None, agents_err
        enabled = any(item.get(key) for item in agents)
        return enabled, '至少有一个 agent 已配置 ' + key if enabled else reason
    if rule_id == 'S19':
        if agents_err:
            return None, agents_err
        enabled = any((item.get('inbound') or {}).get('loginPaths') for item in agents)
        return enabled, '已登记 loginPaths' if enabled else '没有登记 loginPaths，认证失败规则不启用'
    return True, '始终告警，不阻断'


def decorate_rule(rule, config, agents, agents_err):
    item = dict(rule)
    item['asi'] = [row['id'] for row in ASI if rule['id'] in row['rules']]
    enabled, reason = rule_enabled(rule['id'], config, agents, agents_err)
    item['enabled'] = enabled
    item['enabledReason'] = reason
    return item


def rules_payload(app, principal):
    agents, err = load_agents(app.config)
    items = [decorate_rule(rule, app.config, agents, err) for rule in RULES]
    intelligence = app.store.intelligence() if principal and principal.get('role') == 'operator' else []
    return {'items': items, 'asi': ASI, 'intelligence': intelligence, 'version': VERSION}


def inactive_rules(config, agents, agents_err):
    rows = []
    for rule in RULES:
        if rule['id'] == 'P01':
            continue
        enabled, reason = rule_enabled(rule['id'], config, agents, agents_err)
        if enabled is False:
            rows.append({'id': rule['id'], 'name': rule['name'], 'reason': reason})
    if agents_err:
        rows.append({'id': 'config', 'name': '采集配置', 'reason': agents_err})
    return rows


def project_alert(alert, evidence):
    if not isinstance(alert, dict):
        return {}
    if not evidence:
        projected = {key: alert.get(key) for key in PUBLIC_ALERT_KEYS}
        projected['ruleName'] = rule_name(alert.get('rule'))
        projected['phase'] = alert.get('phase')
        projected['layer'] = alert.get('layer') or rule_layer(alert.get('rule') or '')
        return projected
    relation = alert.get('relation') or {}
    return {
        'id': alert.get('id'),
        'rule': alert.get('rule'),
        'ruleName': rule_name(alert.get('rule')),
        'severity': alert.get('severity'),
        'status': alert.get('status'),
        'createdAt': alert.get('createdAt'),
        'count': alert.get('count'),
        'firstSeen': alert.get('firstSeen'),
        'lastSeen': alert.get('lastSeen'),
        'phase': alert.get('phase'),
        'layer': alert.get('layer'),
        'chainId': alert.get('chainId'),
        'agentId': alert.get('agentId'),
        'agentAlias': alias_of(alert.get('agentId')),
        'title': alert.get('title'),
        'confidence': relation.get('confidence'),
    }


class Hub:
    def __init__(self):
        self.lock = threading.Lock()
        self.subs = []
        self.seq = 0
        self.ring = deque(maxlen=100)

    def publish(self, kind, payload):
        with self.lock:
            self.seq += 1
            event = {'id': self.seq, 'kind': str(kind or 'message'), 'payload': payload, 'time': time.time()}
            self.ring.append(event)
            stale = []
            for sub in self.subs:
                try:
                    sub.put_nowait(event)
                except queue.Full:
                    stale.append(sub)
            for sub in stale:
                self.subs.remove(sub)

    def subscribe(self, replay_after=0):
        sub = queue.Queue(maxsize=200)
        with self.lock:
            backlog = [event for event in self.ring if event['id'] > replay_after]
            self.subs.append(sub)
        for event in backlog:
            try:
                sub.put_nowait(event)
            except queue.Full:
                break
        return sub

    def unsubscribe(self, sub):
        with self.lock:
            if sub in self.subs:
                self.subs.remove(sub)


class Observe:
    def __init__(self, app):
        self.app = app
        self.hub = Hub()

    def on_change(self, kind, payload):
        self.hub.publish(kind, payload)

    def rules(self, principal):
        return rules_payload(self.app, principal)

    def dispatch(self, path, query, principal):
        parts = [unquote(part) for part in path.split('/') if part]
        if len(parts) < 4 or parts[:3] != ['runtime', 'api', 'v2']:
            raise KeyError('不存在')
        head, rest = parts[3], parts[4:]
        evidence = can_read_evidence(principal)
        if head == 'overview' and not rest:
            return 200, self.overview(query, evidence)
        if head == 'coverage' and not rest:
            return 200, self.coverage(evidence)
        if head == 'drill' and not rest:
            return 200, self.drill(evidence)
        if head == 'alerts' and not rest:
            return 200, self.alerts(query, evidence)
        if head == 'chains' and not rest:
            return 200, self.chains(query, evidence)
        if head == 'chains' and len(rest) == 1:
            return self.chain(rest[0], query, evidence)
        if head == 'agents' and not rest:
            return 200, self.agents(query, evidence)
        if head == 'agents' and len(rest) == 1:
            return self.agent(rest[0], evidence)
        raise KeyError('不存在')

    def stream(self, handler, principal):
        evidence = can_read_evidence(principal)
        try:
            replay_after = int(handler.headers.get('Last-Event-ID') or 0)
        except ValueError:
            replay_after = 0
        sub = self.hub.subscribe(replay_after)
        handler.close_connection = True
        try:
            handler.send_response(200)
            handler.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            handler.send_header('Cache-Control', 'no-store')
            handler.send_header('X-Accel-Buffering', 'no')
            handler.send_header('X-Content-Type-Options', 'nosniff')
            handler.send_header('Transfer-Encoding', 'chunked')
            handler.end_headers()
            role = principal.get('role') if principal else 'viewer'
            self._chunk(handler, ('event: hello\ndata: ' + compact({'version': VERSION, 'role': role}) + '\n\n').encode())
            idle = 0
            while not self.app.stop.is_set():
                try:
                    event = sub.get(timeout=1)
                except queue.Empty:
                    idle += 1
                    if idle >= 15:
                        idle = 0
                        self._chunk(handler, b': ping\n\n')
                        self._chunk(handler, self._sse({'id': 0, 'kind': 'heartbeat', 'payload': {'serverTime': self.app.store.clock()}}, evidence, numbered=False))
                    continue
                idle = 0
                self._chunk(handler, self._sse(event, evidence, numbered=True))
        except Exception:
            return
        finally:
            self.hub.unsubscribe(sub)
            handler.close_connection = True

    def _chunk(self, handler, payload):
        if not payload:
            return
        handler.wfile.write(b'%X\r\n' % len(payload))
        handler.wfile.write(payload)
        handler.wfile.write(b'\r\n')
        handler.wfile.flush()

    def _sse(self, event, evidence, numbered):
        data = compact(self._project_stream(event.get('kind'), event.get('payload'), evidence))
        prefix = ('id: %s\n' % event['id']) if numbered and event.get('id') else ''
        kind = re.sub(r'[^a-z0-9_]', '', str(event.get('kind') or 'message')) or 'message'
        return (prefix + 'event: ' + kind + '\ndata: ' + data + '\n\n').encode()

    def _project_stream(self, kind, payload, evidence):
        if kind == 'heartbeat':
            return {'serverTime': (payload or {}).get('serverTime') or self.app.store.clock()}
        if kind == 'coverage':
            body = {'state': (payload or {}).get('state'), 'degraded': bool((payload or {}).get('degraded'))}
            if evidence:
                body['source'] = (payload or {}).get('source')
            return body
        if kind in ('alert', 's03_upgrade'):
            return project_alert(payload or {}, evidence)
        return {'ok': True}

    def _range(self, query, drill):
        name = first(query, 'range') or '1h'
        now = self.app.store.clock()
        if name == '15m':
            return now - 900, now, '15m'
        if name == 'today':
            local = time.localtime(now)
            start = time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, local.tm_isdst))
            return start, now, 'today'
        if name == 'drill':
            if drill.get('start') and drill.get('end'):
                try:
                    return parse_time(drill['start']), parse_time(drill['end']), 'drill'
                except ValueError:
                    pass
            return now - 7200, now, 'drill'
        return now - 3600, now, '1h'

    def _since_until(self, query, default_start, default_end):
        start, end = default_start, default_end
        if first(query, 'since'):
            start = parse_time(first(query, 'since'))
        if first(query, 'until'):
            end = parse_time(first(query, 'until'))
        if end < start:
            raise ValueError('时间范围无效')
        return start, end

    def overview(self, query, evidence):
        if first(query, 'dataset') == 'replay':
            body = dict(replay_dataset()['overview'])
            body['dataset'] = 'replay'
            body['publicSummary'] = not evidence
            body['version'] = VERSION
            return body
        drill, _err = load_drill(self.app.config)
        start, end, name = self._range(query, drill)
        alerts = self._alerts_between(start, end)
        sources = self._sources()
        agents, agents_err = load_agents(self.app.config)
        counts = Counter(item.get('state') for item in sources)
        severity = Counter(item.get('severity') for item in alerts)
        chained = [item for item in alerts if item.get('chainId')]
        s03 = [item for item in alerts if item.get('rule') == 'S03']
        confirmed = [item for item in s03 if item.get('phase') == 'host_confirmed']
        delays = [float(item['hostConfirmedAt']) - float(item['hostEventTime']) for item in confirmed if item.get('hostConfirmedAt') is not None and item.get('hostEventTime') is not None]
        buckets = self._buckets(name, start, end)
        for item in alerts:
            layer = item.get('layer') or rule_layer(item.get('rule') or '')
            slot = self._bucket_index(buckets, float(item.get('createdAt') or item.get('time') or start))
            if slot is None:
                continue
            if layer == 'D':
                buckets[slot]['decision'] += 1
            else:
                buckets[slot]['behavior'] += 1
        top = Counter(item.get('rule') for item in alerts)
        agent_rows = self._agent_rows(evidence, agents, sources, alerts)
        linked = sum(1 for row in agent_rows if row.get('model') == 'linked')
        body = {
            'version': VERSION,
            'dataset': 'live',
            'publicSummary': not evidence,
            'range': name,
            'since': start,
            'until': end,
            'serverTime': self.app.store.clock(),
            'kernelBlock': False,
            'sources': {'online': counts.get('online', 0), 'degraded': counts.get('degraded', 0), 'offline': counts.get('offline', 0), 'total': len(sources)},
            'agents': {'total': len(agent_rows), 'modelLinked': linked},
            'alerts': {
                'total': len(alerts),
                'high': severity.get('high', 0),
                'medium': severity.get('medium', 0),
                'low': severity.get('low', 0),
                'inChains': len(chained),
            },
            's03': {'confirmed': len(confirmed), 'total': len(s03), 'p50HostSeconds': round(statistics.median(delays), 3) if delays else None},
            'timeline': buckets,
            'topRules': [{'rule': rule, 'name': rule_name(rule), 'count': count} for rule, count in top.most_common(5) if rule],
            'agentRows': agent_rows,
            'recentChains': self._recent_chains(alerts, evidence),
            'asi': ASI,
            'inactiveRules': inactive_rules(self.app.config, agents, agents_err),
            'coverageNote': self._coverage_note(sources),
        }
        return body

    def _coverage_note(self, sources):
        if not sources:
            return '还没有采集心跳。没有告警只说明窗口里没有命中，不表示已经覆盖。'
        degraded = sum(1 for item in sources if item.get('state') == 'degraded')
        offline = sum(1 for item in sources if item.get('state') == 'offline')
        if degraded or offline:
            return '有采集源降级或离线。没有告警不能当成没有风险。'
        return '采集心跳在线。没有告警仍然要看未启用的规则。'

    def _buckets(self, name, start, end):
        if name == 'today':
            count = max(1, min(24, int((end - start) / 3600) + 1))
        else:
            count = 6
        width = (end - start) / count if end > start else 1
        rows = []
        for index in range(count):
            begin = start + index * width
            rows.append({'start': begin, 'end': start + (index + 1) * width, 'label': time.strftime('%H:%M', time.localtime(begin)), 'decision': 0, 'behavior': 0})
        return rows

    def _bucket_index(self, buckets, stamp):
        for index, bucket in enumerate(buckets):
            if bucket['start'] <= stamp < bucket['end'] or (index == len(buckets) - 1 and stamp <= bucket['end']):
                return index
        return None

    def _sources(self):
        with self.app.store.db(write=False) as cursor:
            return [self.app.store.coverage(cursor, row[0]) for row in cursor.execute('SELECT id FROM sources')]

    def _alerts_between(self, start, end):
        with self.app.store.db(write=False) as cursor:
            rows = cursor.execute("SELECT payload FROM alerts WHERE status!='merged' AND time>=? AND time<=? ORDER BY time ASC LIMIT 2000", (start, end)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _recent_chains(self, alerts, evidence):
        ordered = []
        seen = set()
        for item in sorted(alerts, key=lambda row: float(row.get('createdAt') or 0), reverse=True):
            chain_id = item.get('chainId')
            if not chain_id or chain_id in seen:
                continue
            seen.add(chain_id)
            related = [row for row in alerts if row.get('chainId') == chain_id]
            phase = 'host_confirmed' if any(row.get('rule') == 'S03' and row.get('phase') == 'host_confirmed' for row in related) else (related[0].get('phase') if related else None)
            entry = {
                'phase': phase,
                'rules': sorted({row.get('rule') for row in related if row.get('rule')}),
                'lastAt': max(float(row.get('createdAt') or 0) for row in related),
                'agentAlias': alias_of(item.get('agentId')),
            }
            if evidence:
                entry['chainId'] = chain_id
                entry['agentId'] = item.get('agentId')
            else:
                entry['chainAlias'] = chain_alias(chain_id)
            ordered.append(entry)
            if len(ordered) == 5:
                break
        return ordered

    def _agent_rows(self, evidence, configured, sources, alerts):
        now = self.app.store.clock()
        configured_by_id = {str(item.get('id')): item for item in configured if item.get('id')}
        routes = {}
        for source in sources:
            for agent_id in source.get('agentRoutes') or []:
                routes.setdefault(str(agent_id), source)
        baselines = {}
        semantic = {}
        event_source = {}
        with self.app.store.db(write=False) as cursor:
            for row in cursor.execute('SELECT agent_id, tool_name, first_seen, last_seen, calls FROM tool_baselines'):
                baselines.setdefault(row['agent_id'], []).append(dict(row))
            for row in cursor.execute("SELECT json_extract(payload,'$.agentId') agent, max(time) seen FROM events WHERE kind IN ('model','tool') AND json_extract(payload,'$.agentId') IS NOT NULL GROUP BY agent"):
                if row['agent']:
                    semantic[row['agent']] = row['seen']
            for row in cursor.execute("SELECT json_extract(payload,'$.agentId') agent, source, max(time) seen FROM events WHERE json_extract(payload,'$.agentId') IS NOT NULL GROUP BY agent"):
                if row['agent']:
                    event_source[row['agent']] = row['source']
        ids = set(configured_by_id) | set(routes) | set(baselines) | set(semantic) | {item.get('agentId') for item in alerts if item.get('agentId')}
        rows = []
        for agent_id in sorted(ids):
            spec = configured_by_id.get(agent_id, {})
            source = routes.get(agent_id)
            if source is None and event_source.get(agent_id):
                source = next((item for item in sources if item.get('source') == event_source[agent_id]), None)
            fresh_semantic = semantic.get(agent_id) and now - float(semantic[agent_id]) <= 300
            routed = agent_id in routes
            if fresh_semantic:
                model = 'linked'
            elif routed and source and source.get('state') in ('online', 'degraded'):
                model = 'gateway_bound'
            elif routed:
                model = 'gateway_unbound'
            else:
                model = 'not_connected'
            tools = baselines.get(agent_id) or []
            allowed = [str(name) for name in (spec.get('allowedTools') or [])]
            seen = [item['tool_name'] for item in tools]
            if allowed:
                hit = len(set(seen) & set(allowed))
                baseline = {'status': 'established' if set(allowed) <= set(seen) else 'learning', 'tools': len(seen), 'expected': len(allowed), 'label': ('已建立 · %d 个' % len(seen)) if set(allowed) <= set(seen) else ('学习中 %d/%d' % (hit, len(allowed)))}
            elif seen:
                baseline = {'status': 'established', 'tools': len(seen), 'label': '已建立 · %d 个' % len(seen)}
            else:
                baseline = {'status': 'empty', 'tools': 0, 'label': '未见工具调用'}
            if evidence:
                baseline['names'] = seen
            role = spec.get('role') or spec.get('side') or ''
            role_text = {'offense': '攻方', 'red': '攻方', 'attacker': '攻方', 'defense': '防守', 'blue': '防守'}.get(str(role), str(role) or '未标注')
            row = {
                'alias': alias_of(agent_id),
                'role': role_text if evidence or role_text == '未标注' else role_text,
                'state': (source or {}).get('state') or 'unknown',
                'model': model,
                'toolBaseline': baseline,
                'alerts': sum(1 for item in alerts if item.get('agentId') == agent_id),
            }
            if evidence:
                row['id'] = agent_id
            rows.append(row)
        return rows

    def coverage(self, evidence):
        sources = self._sources()
        agents, agents_err = load_agents(self.app.config)
        counts = Counter(item.get('state') for item in sources)
        body = {
            'version': VERSION,
            'dataset': 'live',
            'publicSummary': not evidence,
            'serverTime': self.app.store.clock(),
            'sources': {'online': counts.get('online', 0), 'degraded': counts.get('degraded', 0), 'offline': counts.get('offline', 0), 'total': len(sources)},
            'recentLoss': any((item.get('recentLoss') or {}).get('total') or item.get('degraded') for item in sources),
            'gapCount': sum(len(item.get('gaps') or []) for item in sources),
            'inactiveRules': inactive_rules(self.app.config, agents, agents_err),
            'note': self._coverage_note(sources),
            'kernelBlock': False,
        }
        if evidence:
            body['sourceDetails'] = [{
                'source': item.get('source'),
                'state': item.get('state'),
                'ageSeconds': item.get('ageSeconds'),
                'degraded': item.get('degraded'),
                'recentLoss': item.get('recentLoss'),
                'historicalLoss': item.get('historicalLoss'),
                'gaps': item.get('gaps'),
                'layers': item.get('layers'),
                'host': item.get('host'),
                'auditLost': item.get('auditLost'),
                'lossWarning': item.get('lossWarning'),
                'limitations': item.get('limitations'),
            } for item in sources]
        return body

    def alerts(self, query, evidence):
        drill, _err = load_drill(self.app.config)
        default_start, default_end, _name = self._range(query, drill)
        if not first(query, 'range') and not first(query, 'since') and not first(query, 'until'):
            default_start = 0
        start, end = self._since_until(query, default_start, default_end)
        where = ["status!='merged'", 'time>=?', 'time<=?']
        params = [start, end]
        for key in ('rule', 'severity', 'status'):
            value = first(query, key)
            if value:
                where.append(key + '=?')
                params.append(value)
        if evidence:
            for key in ('chainId', 'agentId', 'layer', 'phase'):
                value = first(query, key)
                if value:
                    where.append("json_extract(payload,'$." + key + "')=?")
                    params.append(value)
        sql = ' WHERE ' + ' AND '.join(where)
        offset = max(0, int(first(query, 'offset') or 0))
        limit = min(100, max(1, int(first(query, 'limit') or 50)))
        with self.app.store.db(write=False) as cursor:
            total = cursor.execute('SELECT count(*) FROM alerts' + sql, params).fetchone()[0]
            rows = cursor.execute('SELECT payload FROM alerts' + sql + ' ORDER BY time DESC LIMIT ? OFFSET ?', (*params, limit, offset)).fetchall()
            groups = None
            group = {'chain': 'chainId', 'agent': 'agentId', 'layer': 'layer'}.get(first(query, 'group'))
            if evidence and group:
                groups = [{'key': row[0] or '', 'count': row[1]} for row in cursor.execute("SELECT json_extract(payload,'$." + group + "') k, count(*) n FROM alerts" + sql + ' GROUP BY k ORDER BY n DESC LIMIT 500', params)]
        items = [project_alert(json.loads(row[0]), evidence) for row in rows]
        agents, agents_err = load_agents(self.app.config)
        sources = self._sources()
        counts = Counter(item.get('state') for item in sources)
        return {
            'version': VERSION,
            'dataset': 'live',
            'publicSummary': not evidence,
            'items': items,
            'total': total,
            'offset': offset,
            'limit': limit,
            'groups': groups,
            'since': start,
            'until': end,
            'serverTime': self.app.store.clock(),
            'coverageSummary': {'online': counts.get('online', 0), 'degraded': counts.get('degraded', 0), 'offline': counts.get('offline', 0)},
            'inactiveRules': inactive_rules(self.app.config, agents, agents_err),
            'note': '匿名列表只有规则、级别、阶段和层。主机、路径、参数和调用链需要操作员或裁判身份。' if not evidence else '',
        }

    def chains(self, query, evidence):
        if not evidence or first(query, 'dataset') == 'replay':
            items = [self._chain_summary(item, public=not evidence) for item in replay_dataset().get('chains') or []]
            return {'version': VERSION, 'dataset': 'replay', 'publicSummary': True, 'items': items, 'total': len(items), 'note': '匿名和回放只提供事先脱敏的演练调用链，不返回线上链路。'}
        start, end, _name = self._range(query, load_drill(self.app.config)[0])
        params = [start, end]
        agent_filter = first(query, 'agentId')
        sql = "SELECT json_extract(payload,'$.chainId') cid, min(time) first_at, max(time) last_at, count(*) n FROM alerts WHERE status!='merged' AND time>=? AND time<=? AND json_extract(payload,'$.chainId') IS NOT NULL"
        if agent_filter:
            sql += " AND json_extract(payload,'$.agentId')=?"
            params.append(agent_filter)
        sql += ' GROUP BY cid ORDER BY last_at DESC LIMIT 50'
        with self.app.store.db(write=False) as cursor:
            rows = cursor.execute(sql, params).fetchall()
        items = []
        for row in rows:
            items.append(self._live_summary(row['cid'], evidence))
        return {'version': VERSION, 'dataset': 'live', 'publicSummary': False, 'items': items, 'total': len(items), 'serverTime': self.app.store.clock()}

    def _chain_summary(self, chain, public):
        return {
            'chainId': chain.get('chainId'),
            'agentId': None if public else chain.get('agentId'),
            'agentAlias': chain.get('agentAlias') or alias_of(chain.get('agentId')),
            'role': chain.get('role'),
            'phase': chain.get('phase'),
            'confidence': chain.get('confidence'),
            'rules': sorted({item.get('rule') for item in chain.get('alerts') or [] if item.get('rule')}),
            'alertCount': len(chain.get('alerts') or []),
            'dataset': 'replay',
        }

    def _live_summary(self, chain_id, evidence):
        with self.app.store.db(write=False) as cursor:
            rows = cursor.execute("SELECT payload FROM alerts WHERE json_extract(payload,'$.chainId')=? ORDER BY time DESC LIMIT 50", (chain_id,)).fetchall()
        alerts = [json.loads(row[0]) for row in rows]
        phase = 'host_confirmed' if any(item.get('rule') == 'S03' and item.get('phase') == 'host_confirmed' for item in alerts) else next((item.get('phase') for item in alerts if item.get('phase')), None)
        agent_id = next((item.get('agentId') for item in alerts if item.get('agentId')), None)
        summary = {
            'chainId': chain_id if evidence else None,
            'chainAlias': None if evidence else chain_alias(chain_id),
            'agentId': agent_id if evidence else None,
            'agentAlias': alias_of(agent_id),
            'phase': phase,
            'rules': sorted({item.get('rule') for item in alerts if item.get('rule')}),
            'alertCount': len(alerts),
            'lastAt': max((float(item.get('createdAt') or 0) for item in alerts), default=None),
            'dataset': 'live',
        }
        return summary

    def chain(self, chain_id, query, evidence):
        if not ID_RE.match(chain_id or ''):
            raise ValueError('chainId 无效')
        replay = next((item for item in replay_dataset().get('chains') or [] if item.get('chainId') == chain_id), None)
        if first(query, 'dataset') == 'replay' or not evidence:
            if replay:
                body = dict(replay)
                body['dataset'] = 'replay'
                body['publicSummary'] = True
                body['version'] = VERSION
                return 200, body
            if not evidence:
                return 403, {'error': '匿名只能查看事先脱敏的回放调用链'}
        built = self._build_chain(chain_id)
        if not built:
            raise KeyError('调用链不存在')
        built['dataset'] = 'live'
        built['publicSummary'] = False
        built['version'] = VERSION
        return 200, built

    def _build_chain(self, chain_id):
        with self.app.store.db(write=False) as cursor:
            event_rows = cursor.execute("SELECT payload FROM events WHERE json_extract(payload,'$.chainId')=? OR json_extract(payload,'$.runId')=? ORDER BY time ASC LIMIT 500", (chain_id, chain_id)).fetchall()
            alert_rows = cursor.execute("SELECT payload FROM alerts WHERE json_extract(payload,'$.chainId')=? ORDER BY time ASC LIMIT 100", (chain_id,)).fetchall()
            alerts = [json.loads(row[0]) for row in alert_rows]
            extra_ids = []
            for alert in alerts:
                extra_ids.extend(alert.get('sampleEventIds') or [])
                extra_ids.extend(item.get('id') for item in (alert.get('evidence') or []) if isinstance(item, dict) and item.get('id'))
            extra_ids = [item for item in dict.fromkeys(extra_ids) if item][:500]
            extra_rows = []
            if extra_ids:
                marks = ','.join('?' for _ in extra_ids)
                extra_rows = cursor.execute('SELECT payload FROM events WHERE id IN (' + marks + ')', extra_ids).fetchall()
        events = []
        seen = set()
        for row in list(event_rows) + list(extra_rows):
            item = json.loads(row[0])
            if item.get('id') in seen:
                continue
            seen.add(item.get('id'))
            events.append(item)
        events.sort(key=lambda item: float(item.get('time') or 0))
        if not events and not alerts:
            return None
        stamps = [float(item.get('time') or 0) for item in events] or [float(item.get('createdAt') or 0) for item in alerts]
        origin = min(stamps) if stamps else 0
        blocks = []
        for event in events:
            blocks.extend(self._event_blocks(event, origin))
        blocks.extend(self._alert_blocks(alerts, origin))
        blocks.sort(key=lambda item: (item['t'], item['lane'] != 'alert'))
        s03 = [item for item in alerts if item.get('rule') == 'S03']
        semantic_at = None
        confirmed_at = None
        if s03:
            semantic_at = max(0.0, min(float(item.get('createdAt') or origin) for item in s03) - origin)
            confirmed = [float(item['hostConfirmedAt']) - origin for item in s03 if item.get('hostConfirmedAt')]
            confirmed_at = max(0.0, min(confirmed)) if confirmed else None
        semantic_delays, host_delays = [], []
        for item in s03:
            if item.get('createdAt') is not None and item.get('firstSeen') is not None:
                semantic_delays.append(float(item['createdAt']) - float(item['firstSeen']))
            if item.get('hostConfirmedAt') is not None and item.get('hostEventTime') is not None:
                host_delays.append(float(item['hostConfirmedAt']) - float(item['hostEventTime']))
        agent_id = next((item.get('agentId') for item in events if item.get('agentId')), None) or next((item.get('agentId') for item in alerts if item.get('agentId')), None)
        phase = 'host_confirmed' if any(item.get('phase') == 'host_confirmed' for item in s03) else ('semantic' if s03 else None)
        confidences = [(item.get('relation') or {}).get('confidence') for item in alerts]
        confidence = 'correlated' if 'correlated' in confidences else ('observed' if 'observed' in confidences else (confidences[0] if confidences else None))
        basis = next(((item.get('relation') or {}).get('basis') for item in s03 if (item.get('relation') or {}).get('basis')), None)
        if basis is None:
            basis = next(((item.get('relation') or {}).get('basis') for item in alerts if (item.get('relation') or {}).get('basis')), '')
        span = max([item['t'] for item in blocks] + [semantic_at or 0, confirmed_at or 0, 1])
        return {
            'chainId': chain_id,
            'agentId': agent_id,
            'agentAlias': alias_of(agent_id),
            'role': self._role(agent_id),
            'phase': phase,
            'confidence': confidence,
            'basis': basis,
            'semanticAt': semantic_at,
            'confirmedAt': confirmed_at,
            'spanSeconds': span,
            'latency': {
                'semanticSeconds': round(statistics.median(semantic_delays), 3) if semantic_delays else None,
                'hostSeconds': round(statistics.median(host_delays), 3) if host_delays else None,
            },
            'events': blocks,
            'edges': self._edges(alerts, blocks),
            'files': self._files(events, alerts),
            'alerts': [project_alert(item, True) for item in alerts],
            'lanes': list(LANES),
        }

    def _role(self, agent_id):
        if not agent_id:
            return '未标注'
        agents, _err = load_agents(self.app.config)
        for item in agents:
            if str(item.get('id')) == str(agent_id):
                raw = str(item.get('role') or item.get('side') or '')
                return {'offense': '攻方', 'red': '攻方', 'attacker': '攻方', 'defense': '防守', 'blue': '防守'}.get(raw, raw or '未标注')
        return '未标注'

    def _event_blocks(self, event, origin):
        kind = event.get('kind')
        stamp = max(0.0, float(event.get('time') or origin) - origin)
        blocks = []
        if kind == 'model' or event.get('operation') in ('TOOL_RESULT', 'MODEL_REQUEST', 'MODEL_RESPONSE'):
            segments = [item for item in (event.get('untrustedSegments') or []) if isinstance(item, dict)]
            for index, segment in enumerate(segments[:8]):
                observed = segment.get('confidence') == 'observed'
                blocks.append(self._block(
                    '%s:seg:%d' % (event.get('id'), index), stamp, 'input',
                    '不受信片段' if observed else '输入片段',
                    '%s · %s' % (segment.get('sourceKind') or segment.get('role') or 'unknown', segment.get('confidence') or 'unknown'),
                    'untrusted' if observed else None, event,
                ))
            if not segments and kind == 'model':
                blocks.append(self._block(event.get('id'), stamp, 'input', event.get('operation') or '模型事件', event.get('confidence') or 'observed', None, event))
            return blocks
        if kind == 'tool' and event.get('operation') == 'TOOL_CALL':
            entities = event.get('argsEntities') or {}
            preview = (entities.get('commands') or entities.get('urls') or entities.get('paths') or [''])[0]
            risky = self._risky(event)
            block = self._block(event.get('id'), stamp, 'decision', 'TOOL_CALL ' + str(event.get('toolName') or ''), short_text(preview) or '参数已清洗', 'risky' if risky else None, event)
            block['toolCallId'] = event.get('toolCallId')
            return [block]
        if kind == 'process':
            command = str(event.get('command') or '')
            title = 'EXEC ' + (command.split()[:1] or ['进程'])[0]
            return [self._block(event.get('id'), stamp, 'behavior', title, short_text('%s · pid %s' % (event.get('workload') or '', event.get('pid') if event.get('pid') is not None else '')), None, event)]
        if kind == 'file':
            access = str(event.get('access') or '')
            verb = 'WRITE' if access.startswith('write') or 'write' in access else 'READ'
            return [self._block(event.get('id'), stamp, 'behavior', verb + ' ' + str(event.get('path') or ''), access or 'file', None, event)]
        if kind == 'network':
            dest = str(event.get('destination') or '')
            port = event.get('port')
            title = 'CONNECT ' + dest + ((':' + str(port)) if port else '')
            return [self._block(event.get('id'), stamp, 'behavior', title, '网络连接', None, event)]
        return blocks

    def _risky(self, event):
        try:
            from runtime.semantic_extract import high_risk_reasons
        except ImportError:
            from semantic_extract import high_risk_reasons
        try:
            return bool(high_risk_reasons(event.get('toolName'), event.get('argsEntities') or {}, (event.get('policy') or {}).get('allowedNetworks')))
        except Exception:
            return False

    def _block(self, block_id, stamp, lane, title, sub, kind, event):
        drawer = {
            'eventId': event.get('id'),
            'time': event.get('time'),
            'kind': event.get('kind'),
            'operation': event.get('operation'),
            'toolName': event.get('toolName'),
            'arguments': event.get('arguments'),
            'argsEntities': event.get('argsEntities'),
            'command': event.get('command'),
            'path': event.get('path'),
            'pid': event.get('pid'),
            'ppid': event.get('ppid'),
            'containerId': event.get('containerId'),
            'cgroup': event.get('cgroup'),
            'workload': event.get('workload'),
            'confidence': event.get('confidence'),
            'sha256Before': event.get('sha256Before'),
            'sha256After': event.get('sha256After'),
            'textExcerpt': event.get('textExcerpt'),
            'note': '哈希链序号在 export_timeline.py 的 JSONL 里计算，页面不重算整库哈希',
        }
        drawer = {key: value for key, value in drawer.items() if value not in (None, '', [], {})}
        return {
            'id': str(block_id),
            't': stamp,
            'lane': lane,
            'title': short_text(title, 48),
            'sub': short_text(sub, 80),
            'kind': kind,
            'eventId': event.get('id'),
            'toolCallId': event.get('toolCallId'),
            'drawer': drawer,
        }

    def _alert_blocks(self, alerts, origin):
        blocks = []
        for alert in alerts:
            if alert.get('rule') == 'S03':
                blocks.append({
                    'id': alert['id'] + ':semantic',
                    't': max(0.0, float(alert.get('createdAt') or origin) - origin),
                    'lane': 'alert',
                    'title': 'S03 语义段',
                    'sub': 'phase=semantic',
                    'kind': 'alert',
                    'onlyConfirmed': False,
                    'confirmedTitle': 'S03 已确认' if alert.get('phase') == 'host_confirmed' else None,
                    'confirmedSub': 'phase=host_confirmed' if alert.get('phase') == 'host_confirmed' else None,
                    'eventId': alert.get('id'),
                })
                if alert.get('phase') == 'host_confirmed' and alert.get('hostConfirmedAt'):
                    blocks.append({
                        'id': alert['id'] + ':upgrade',
                        't': max(0.0, float(alert['hostConfirmedAt']) - origin),
                        'lane': 'alert',
                        'title': 'S03 升级',
                        'sub': '主机事件后确认',
                        'kind': 'alert',
                        'onlyConfirmed': True,
                        'eventId': alert.get('id'),
                    })
                continue
            blocks.append({
                'id': alert.get('id'),
                't': max(0.0, float(alert.get('createdAt') or origin) - origin),
                'lane': 'alert',
                'title': '%s %s' % (alert.get('rule') or '', short_text(alert.get('title') or '', 36)),
                'sub': alert.get('phase') or '',
                'kind': 'alert',
                'onlyConfirmed': alert.get('phase') == 'host_confirmed',
                'eventId': alert.get('id'),
            })
        return blocks

    def _edges(self, alerts, blocks):
        untrusted = [item['id'] for item in blocks if item.get('kind') == 'untrusted']
        tools = {}
        hosts = {}
        for item in blocks:
            if item.get('lane') == 'decision':
                tools[item.get('toolCallId') or item.get('eventId')] = item['id']
            if item.get('lane') == 'behavior' and item.get('eventId'):
                hosts[item['eventId']] = item['id']
        edges = []
        seen = set()

        def add(src, dst, label, only, dashed):
            if not src or not dst or src == dst or (src, dst) in seen:
                return
            seen.add((src, dst))
            edges.append({'from': src, 'to': dst, 'label': short_text(label, 40), 'onlyConfirmed': only, 'dashed': dashed})

        for alert in alerts:
            for link in (alert.get('relation') or {}).get('links') or []:
                if not isinstance(link, dict):
                    continue
                tool_id = link.get('toolCallId') or alert.get('toolCallId')
                if link.get('from') == 'untrustedSegment':
                    add(untrusted[0] if untrusted else None, tools.get(tool_id), '不受信 → 高风险调用', False, True)
                host_id = link.get('hostEventId')
                if host_id:
                    add(tools.get(tool_id), hosts.get(host_id), link.get('basis') or '主机实体一致', True, False)
        return edges

    def _files(self, events, alerts):
        rows = []
        seen = set()
        for event in events:
            if event.get('kind') != 'file':
                continue
            path = event.get('path')
            if not path or path in seen:
                continue
            if not (event.get('sha256Before') or event.get('sha256After')):
                continue
            seen.add(path)
            access = str(event.get('access') or '')
            rows.append({
                'path': path,
                'before': short_hash(event.get('sha256Before')) or ('无' if event.get('sha256After') else None),
                'after': short_hash(event.get('sha256After')),
                'rule': 'S08' if 'write' in access else 'S01',
            })
        for alert in alerts:
            digest = alert.get('fileDigest') or {}
            if not digest:
                continue
            path = next((item.get('path') for item in (alert.get('evidence') or []) if isinstance(item, dict) and item.get('path')), None)
            if not path or path in seen:
                continue
            seen.add(path)
            rows.append({'path': path, 'before': short_hash(digest.get('before')) or '无', 'after': short_hash(digest.get('after')), 'rule': alert.get('rule')})
        return rows

    def agents(self, query, evidence):
        drill, _err = load_drill(self.app.config)
        start, end, _name = self._range(query, drill)
        alerts = self._alerts_between(start, end)
        configured, _err = load_agents(self.app.config)
        rows = self._agent_rows(evidence, configured, self._sources(), alerts)
        return {'version': VERSION, 'dataset': 'live', 'publicSummary': not evidence, 'items': rows, 'total': len(rows), 'serverTime': self.app.store.clock()}

    def agent(self, agent_id, evidence):
        if not ID_RE.match(agent_id or ''):
            raise ValueError('agentId 无效')
        rows = self.agents({}, evidence)['items']
        if evidence:
            found = next((item for item in rows if item.get('id') == agent_id), None)
        else:
            found = next((item for item in rows if item.get('alias') in (agent_id, alias_of(agent_id))), None)
            if found:
                found = dict(found)
                found.pop('id', None)
                baseline = dict(found.get('toolBaseline') or {})
                baseline.pop('names', None)
                found['toolBaseline'] = baseline
        if not found:
            raise KeyError('Agent 不存在')
        return 200, found

    def drill(self, evidence):
        doc, err = load_drill(self.app.config)
        public = bool(doc.get('public') or self.app.config.get('drillPublic'))
        if not evidence and not public:
            return {
                'version': VERSION,
                'dataset': 'live',
                'publicSummary': True,
                'hidden': True,
                'label': doc.get('label') or '演练',
                'note': '演练计分板默认不对匿名开放。drill.yaml 写 public: true 后只公开汇总，不含命令和告警编号。',
                'rates': self._empty_rates(),
                'rows': [],
                'target': TARGET,
            }
        scenarios = [item for item in (doc.get('scenarios') or []) if isinstance(item, dict)]
        windows = []
        for scenario in scenarios:
            for window in scenario.get('windows') or []:
                if isinstance(window, dict) and window.get('start') and window.get('end'):
                    try:
                        windows.append((parse_time(window['start']), parse_time(window['end'])))
                    except ValueError:
                        continue
        alerts = []
        if windows:
            alerts = self._alerts_between(min(item[0] for item in windows), max(item[1] for item in windows))
        rows = [self._score_scenario(scenario, alerts, evidence) for scenario in scenarios]
        return {
            'version': VERSION,
            'dataset': 'live',
            'publicSummary': not evidence,
            'hidden': False,
            'label': doc.get('label') or '演练',
            'note': err or '每个 window 算一次尝试。P0 与 S12–S22 分开计。低于 90% 由页面标出。平台只读，不在这里登记开始或结束。',
            'target': TARGET,
            'rates': {
                'p0': self._rate(scenarios, alerts, P0_RULES, 'P0', 'P0 检出率'),
                's02': self._rate(scenarios, alerts, ('S02',), 'P0', 'S02'),
                's03': self._rate(scenarios, alerts, ('S03',), 'P0', 'S03'),
                'fresh': self._rate(scenarios, alerts, FRESH_RULES, 'fresh', 'S12–S22'),
            },
            'rows': rows,
            'serverTime': self.app.store.clock(),
        }

    def _empty_rates(self):
        return {
            'p0': {'rate': None, 'belowTarget': False, 'detail': '未公开', 'label': 'P0 检出率'},
            's02': {'rate': None, 'belowTarget': False, 'detail': '未公开', 'label': 'S02'},
            's03': {'rate': None, 'belowTarget': False, 'detail': '未公开', 'label': 'S03'},
            'fresh': {'rate': None, 'belowTarget': False, 'detail': '未公开', 'label': 'S12–S22'},
        }

    def _prepared_windows(self, scenario):
        prepared = []
        for window in scenario.get('windows') or []:
            if not isinstance(window, dict) or not window.get('start') or not window.get('end'):
                continue
            try:
                prepared.append({
                    'start': parse_time(window['start']),
                    'end': parse_time(window['end']),
                    'agentId': window.get('agentId'),
                    'chainId': window.get('chainId'),
                })
            except ValueError:
                continue
        return prepared

    def _hits(self, windows, alerts, rule):
        count = 0
        matched = []
        for window in windows:
            found = [item for item in alerts if item.get('rule') == rule and self._in_window(item, window)]
            if found:
                count += 1
                matched.extend(found)
        return count, matched

    def _in_window(self, alert, window):
        stamp = float(alert.get('createdAt') or alert.get('firstSeen') or 0)
        if stamp < window['start'] or stamp > window['end']:
            return False
        if window.get('agentId') and alert.get('agentId') != window['agentId']:
            return False
        if window.get('chainId') and alert.get('chainId') != window['chainId']:
            return False
        return True

    def _rate(self, scenarios, alerts, rules, cohort, label):
        hit = total = 0
        for scenario in scenarios:
            if scenario.get('cohort', 'P0') != cohort:
                continue
            windows = self._prepared_windows(scenario)
            if not windows:
                continue
            for rule in scenario.get('expected') or []:
                if rule not in rules:
                    continue
                total += len(windows)
                hit += self._hits(windows, alerts, rule)[0]
        if total == 0:
            return {'rate': None, 'belowTarget': False, 'detail': '未演练', 'label': label, 'hit': 0, 'total': 0}
        rate = hit / total
        return {'rate': rate, 'belowTarget': rate < TARGET, 'detail': '%d/%d' % (hit, total), 'label': label, 'hit': hit, 'total': total}

    def _score_scenario(self, scenario, alerts, evidence):
        windows = self._prepared_windows(scenario)
        expected = [str(item) for item in (scenario.get('expected') or [])]
        missed = [str(item) for item in (scenario.get('expectedMiss') or [])]
        runs = len(windows)
        hit_map = {}
        matched = []
        for rule in expected + missed:
            count, found = self._hits(windows, alerts, rule) if runs else (0, [])
            hit_map[rule] = count
            if rule in expected:
                matched.extend(found)
        cohort = scenario.get('cohort') or 'P0'
        label = {'P0': 'P0', 'fresh': '新规则', 'coverage': '覆盖'}.get(cohort, str(cohort))
        if missed:
            label += ' / 缺口'
        if cohort == 'coverage':
            result = '未自动判定' if runs else '未登记时间窗'
            tone = 'neutral'
            latency = scenario.get('latency') or '—'
        elif runs == 0:
            result, tone, latency = '未登记时间窗', 'neutral', '—'
        else:
            if not missed and expected and len({hit_map[rule] for rule in expected}) == 1:
                result = '%d/%d' % (hit_map[expected[0]], runs)
            elif not expected:
                result = '0/%d' % runs
            else:
                result = ' · '.join('%s %d/%d' % (rule, hit_map[rule], runs) for rule in expected + missed)
            if expected and all(hit_map[rule] == runs for rule in expected) and all(hit_map[rule] == 0 for rule in missed):
                tone = 'success'
            elif any(hit_map[rule] == 0 for rule in expected):
                tone = 'danger'
            else:
                tone = 'warning'
            latency = self._latency(matched)
        row = {
            'id': scenario.get('id'),
            'action': scenario.get('action') or '',
            'expected': ' + '.join(expected) if expected else (scenario.get('expectedText') or '—'),
            'result': result,
            'tone': tone,
            'latency': latency,
            'cohort': label,
            'note': scenario.get('note') or '',
        }
        if missed:
            row['expected'] = ' + '.join(expected) + ('（%s 预期漏）' % '、'.join(missed) if missed else '')
        if evidence:
            shown = []
            for alert in matched[:12]:
                shown.append({'alertId': alert.get('id'), 'chainId': alert.get('chainId'), 'rule': alert.get('rule'), 'command': self._command(alert)})
            row['matches'] = shown
        return row

    def _latency(self, alerts):
        semantic, host = [], []
        for alert in alerts:
            if alert.get('createdAt') is not None and alert.get('firstSeen') is not None:
                semantic.append(float(alert['createdAt']) - float(alert['firstSeen']))
            if alert.get('hostConfirmedAt') is not None and alert.get('hostEventTime') is not None:
                host.append(float(alert['hostConfirmedAt']) - float(alert['hostEventTime']))

        def fmt(value):
            return ('%.1f s' % value) if abs(value) >= 0.1 else ('%.2f s' % value)

        if semantic and host:
            return fmt(statistics.median(semantic)) + ' / ' + fmt(statistics.median(host))
        if semantic:
            return fmt(statistics.median(semantic))
        if host:
            return fmt(statistics.median(host))
        return '—'

    def _command(self, alert):
        for event in alert.get('evidence') or []:
            if not isinstance(event, dict):
                continue
            if event.get('command'):
                return short_text(event['command'], 180)
            commands = (event.get('argsEntities') or {}).get('commands') or []
            if commands:
                return short_text(commands[0], 180)
        return None
