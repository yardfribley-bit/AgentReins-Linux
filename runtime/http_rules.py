"""S13–S22 checks. Web summaries do not open or upgrade a model chain.

Inbound alerts stay on their own agentId. A chainId is copied only when the
tool event already has one. Time proximity never joins an HTTP summary to S03.
"""
import ipaddress
import re
import shlex

_EGRESS = ('http', 'fetch', 'request', 'curl', 'wget', 'browser', 'web', 'post', 'upload')
_SSRF_ROLES = {'web', 'api', 'worker', 'plugin', 'sandbox'}
_WEB_ROLES = {'web', 'api'}
_SHELLS = {'sh', 'bash', 'dash', 'zsh', 'csh', 'ksh', 'curl', 'wget', 'nc', 'ncat'}
_BUILTIN_NETS = ('169.254.0.0/16', '127.0.0.0/8', '::1/128')


def _allowed(destination, port, allowed):
    try:
        from runtime.engine import network_allowed
    except ImportError:
        from engine import network_allowed
    return network_allowed(destination, port, allowed)


def http_thresholds(config):
    raw = (config or {}).get('httpThresholds') or {}

    def num(key, default, lo, hi, cast=int):
        try:
            value = cast(raw.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(lo, min(hi, value))

    return {
        'distinctPaths': num('distinctPaths', 20, 1, 100000),
        'notFound': num('notFound', 20, 1, 100000),
        'authFailures': num('authFailures', 8, 1, 100000),
        'minSample': num('minSample', 30, 1, 100000),
        'categoryHits': num('categoryHits', 3, 1, 100000),
        'errorRate': num('errorRate', 0.5, 0.01, 1.0, float),
    }


def tool_thresholds(config):
    """S15 stays off until toolThresholds is set. Zero disables a side."""
    raw = (config or {}).get('toolThresholds')
    if not isinstance(raw, dict):
        return None

    def num(key):
        try:
            return max(0, int(raw.get(key, 0) or 0))
        except (TypeError, ValueError):
            return 0

    return {'perMinute': num('perMinute'), 'perChainTool': num('perChainTool')}


def _split_host(value):
    text = str(value or '').strip()
    if not text:
        return '', None
    if text.startswith('['):
        host, _, rest = text[1:].partition(']')
        if rest.startswith(':') and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if text.count(':') == 1:
        host, port = text.split(':', 1)
        if port.isdigit():
            return host, int(port)
    return text, None


def _in_nets(ip, nets):
    for item in nets or []:
        cidr = item.get('cidr') if isinstance(item, dict) else item
        try:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False


def matched_internal(host, policy, port=None):
    """IP literals in metadata, loopback, host gateways, or other agents' nets.

    A destination inside this agent's allowedNetworks is not a match. An empty
    allowlist does not suppress the built-in ranges. Hostnames do not match.
    """
    name, parsed = _split_host(host)
    if parsed is None and port is not None:
        try:
            parsed = int(port)
        except (TypeError, ValueError):
            parsed = None
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return ''
    allowed = (policy or {}).get('allowedNetworks') or []
    if allowed and _allowed(str(ip), parsed, allowed):
        return ''
    nets = list(_BUILTIN_NETS)
    nets.extend((policy or {}).get('hostGateways') or [])
    nets.extend((policy or {}).get('peerInternalNetworks') or [])
    if _in_nets(ip, nets):
        return str(ip)
    return ''


def _entity_hosts(event):
    entities = event.get('argsEntities') or {}
    hosts = []
    for host in entities.get('hosts') or []:
        if host and host not in hosts:
            hosts.append(str(host))
    return hosts


def _egress(event):
    name = str(event.get('toolName') or '').lower()
    if any(token in name for token in _EGRESS):
        return True
    entities = event.get('argsEntities') or {}
    return bool(entities.get('urls') or entities.get('hosts'))


def _findings(event):
    found = []
    for item in event.get('secretFindings') or []:
        if isinstance(item, dict) and item.get('category') and item.get('digest') and 'PLACEHOLDER' not in str(item.get('digest')):
            found.append({'category': str(item['category'])[:40], 'digest': str(item['digest'])[:64]})
    return found[:16]


def _cited(event):
    cited = []
    for segment in event.get('untrustedSegments') or []:
        if not isinstance(segment, dict) or segment.get('confidence') != 'observed':
            continue
        cited.append({
            'digest': segment.get('digest'),
            'sourceKind': segment.get('sourceKind'),
            'role': segment.get('role'),
            'confidence': 'observed',
        })
    return cited[:4]


def _probe(event, **fields):
    probe = dict(event)
    probe.update(fields)
    return probe


def _tool_ref(event, extra):
    ref = {
        'id': event.get('id'),
        'time': event.get('time'),
        'kind': 'tool',
        'operation': 'TOOL_CALL',
        'workload': event.get('workload'),
        'agentId': event.get('agentId'),
        'chainId': event.get('chainId'),
        'toolCallId': event.get('toolCallId'),
        'toolName': event.get('toolName'),
        'source': event.get('source'),
        'identity': event.get('identity'),
        'argsDigest': event.get('argsDigest'),
    }
    ref.update(extra)
    return ref


def program_name(command):
    if not command:
        return ''
    try:
        parts = shlex.split(str(command))
    except ValueError:
        parts = str(command).split()
    if not parts:
        return ''
    return parts[0].rsplit('/', 1)[-1]


def _count_tools(cursor, event, predicate, span):
    rows = cursor.execute(
        'SELECT payload FROM events WHERE source=? AND workload=? AND kind=? AND time>=? AND time<=? ORDER BY time DESC LIMIT 200',
        (event.get('source'), event.get('workload'), 'tool', float(event.get('time') or 0) - span, float(event.get('time') or 0)),
    )
    count = 0
    for row in rows:
        try:
            import json
            other = json.loads(row[0])
        except (TypeError, ValueError):
            continue
        if other.get('operation') == 'TOOL_CALL' and predicate(other):
            count += 1
    return count


def detect_extra(store, cursor, event):
    kind = event.get('kind')
    if kind == 'http':
        _http(store, cursor, event)
    elif kind == 'tool' and event.get('operation') == 'TOOL_CALL':
        _tool(store, cursor, event)
    elif kind == 'network':
        _ssrf(store, cursor, event)
    elif kind == 'process':
        _web_child(store, cursor, event)


def _http(store, cursor, event):
    if event.get('operation') != 'HTTP_SUMMARY':
        return
    limits = http_thresholds(store.config)
    for client in (event.get('clients') or [])[:64]:
        if not isinstance(client, dict):
            continue
        address = str(client.get('address') or '')
        distinct = int(client.get('distinctPaths') or 0)
        missing = int(client.get('notFound') or 0)
        failed = int(client.get('authFailures') or 0)
        if distinct >= limits['distinctPaths'] or missing >= limits['notFound']:
            probe = _probe(event, destination=address, path='scan', command=None)
            store._alert(cursor, 'S17', probe, [event], '入站扫描或路径枚举：' + address, 'explicit', '同一来源在 60 秒汇总内的不同路径数或 404 数达到阈值；原始 URI 不入库', confidence='observed')
        if failed >= limits['authFailures']:
            probe = _probe(event, destination=address, path='auth', command=None)
            store._alert(cursor, 'S19', probe, [event], '认证失败突发：' + address, 'explicit', '同一来源在 60 秒汇总内对已登记登录路径的 401/403 达到阈值', confidence='observed')
    for hit in (event.get('categoryHits') or [])[:32]:
        if not isinstance(hit, dict):
            continue
        label = str(hit.get('category') or '')
        if not re.fullmatch(r'[a-z0-9_]{1,40}', label):
            continue
        if int(hit.get('count') or 0) < limits['categoryHits']:
            continue
        probe = _probe(event, destination=str(hit.get('address') or ''), path=label, command=None)
        store._alert(cursor, 'S21', probe, [event], '入站请求特征：' + label, 'explicit', '60 秒汇总内的 URI 或 UA 类别计数达到阈值；不保留原始 URI', confidence='observed')
    totals = event.get('totals') or {}
    try:
        requests = int(totals.get('requests') or 0)
    except (TypeError, ValueError):
        requests = 0
    if requests < limits['minSample']:
        return
    try:
        server = int(totals.get('serverErrors') or 0)
        client_errors = int(totals.get('clientErrors') or 0)
    except (TypeError, ValueError):
        return
    if server / requests >= limits['errorRate'] or client_errors / requests >= limits['errorRate']:
        probe = _probe(event, destination=event.get('agentId') or '', path='error-rate', command=None)
        store._alert(cursor, 'S18', probe, [event], '入站错误率突增：' + str(event.get('agentId') or ''), 'explicit', '60 秒汇总内 4xx 或 5xx 比例达到阈值且样本数足够；不区分攻击和故障', confidence='observed')


def _tool(store, cursor, event):
    findings = _findings(event)
    if findings and _egress(event):
        probe = _probe(event, destination=event.get('toolCallId') or event.get('argsDigest') or 'tool', path=event.get('toolName') or '', command=None, secretFindings=findings)
        store._alert(cursor, 'S13', probe, [_tool_ref(event, {'secretFindings': findings})], '工具参数携带敏感数据', 'explicit', '外发类工具参数命中凭据遮盖规则；只保留类别和摘要哈希', confidence='observed')
    matched = []
    for host in _entity_hosts(event):
        ip = matched_internal(host, event.get('policy'))
        if ip and ip not in matched:
            matched.append(ip)
    if matched:
        cited = _cited(event)
        confidence = 'correlated' if cited else 'observed'
        probe = _probe(event, destination=matched[0], path=event.get('toolName') or '', command=None)
        basis = '参数中的 IP 落在元数据段、回环、宿主机网关或其他 Agent 网段，且不在该 Agent 的允许范围'
        if cited:
            basis += '；同链不受信片段仅作引用，不是触发前提'
        store._alert(cursor, 'S16', probe, [_tool_ref(event, {'matchedHosts': matched, 'untrustedSegments': cited})], '工具参数指向内网、元数据或本机：' + matched[0], 'explicit', basis, confidence=confidence)
    tools = (event.get('policy') or {}).get('allowedTools')
    name = str(event.get('toolName') or '')
    if isinstance(tools, list) and tools and name not in [str(item) for item in tools]:
        probe = _probe(event, destination=event.get('agentId') or '', path=name, command=None)
        store._alert(cursor, 'S14', probe, [_tool_ref(event, {})], '调用未登记工具：' + name, 'explicit', '该 agent 配置了非空 allowedTools，且本次 toolName 不在其中', confidence='observed')
    limits = tool_thresholds(store.config)
    if not limits:
        return
    if limits['perMinute']:
        count = _count_tools(cursor, event, lambda _other: True, 60)
        if count >= limits['perMinute']:
            probe = _probe(event, destination=event.get('agentId') or '', path='per-minute', command=None)
            store._alert(cursor, 'S15', probe, [_tool_ref(event, {'count': count})], '工具调用频率异常：' + str(event.get('agentId') or ''), 'explicit', '同一 agent 一分钟内的 TOOL_CALL 数达到配置阈值', confidence='observed')
    if limits['perChainTool'] and event.get('chainId') and name:
        count = _count_tools(cursor, event, lambda other: other.get('chainId') == event.get('chainId') and other.get('toolName') == name, 3600)
        if count >= limits['perChainTool']:
            probe = _probe(event, destination=event.get('chainId'), path=name, command=None)
            store._alert(cursor, 'S15', probe, [_tool_ref(event, {'count': count})], '同一链路内工具调用过多：' + name, 'explicit', '同一 chainId 上同一工具的调用数达到配置阈值', confidence='observed')


def _ssrf(store, cursor, event):
    role = str(event.get('containerRole') or '').lower()
    if role not in _SSRF_ROLES or not event.get('destination'):
        return
    ip = matched_internal(event.get('destination'), event.get('policy'), event.get('port'))
    if not ip:
        return
    probe = _probe(event, destination=ip, path=role, command=None)
    store._alert(cursor, 'S20', probe, [event], '应用容器连接元数据、回环或其他 Agent 网段：' + ip, 'explicit', '容器角色属于 web/api/worker/plugin/sandbox；数据库和缓存角色不触发；代理后的真实目的未接入', confidence='observed')


def _parent_command(cursor, event):
    try:
        ppid = int(event.get('ppid') or 0)
    except (TypeError, ValueError):
        return None
    if ppid <= 0:
        return None
    import json
    rows = cursor.execute(
        'SELECT payload FROM events WHERE source=? AND workload=? AND kind=? AND time>=? AND time<=? ORDER BY time DESC LIMIT 100',
        (event.get('source'), event.get('workload'), 'process', float(event.get('time') or 0) - 120, float(event.get('time') or 0)),
    )
    for row in rows:
        try:
            other = json.loads(row[0])
        except (TypeError, ValueError):
            continue
        try:
            pid = int(other.get('pid') or 0)
        except (TypeError, ValueError):
            continue
        if pid == ppid:
            return other.get('command') or ''
    return None


def _web_child(store, cursor, event):
    role = str(event.get('containerRole') or '').lower()
    if role == 'sandbox' or role not in _WEB_ROLES:
        return
    servers = [str(item) for item in ((event.get('policy') or {}).get('webServers') or [])]
    if not servers:
        return
    child = program_name(event.get('command'))
    if child not in _SHELLS:
        return
    parent = _parent_command(cursor, event)
    if parent is None:
        try:
            ppid = int(event.get('ppid') or 0)
        except (TypeError, ValueError):
            ppid = 0
        if ppid <= 0:
            return
        probe = _probe(event, destination='unresolved', path=child, command=None)
        store._alert(cursor, 'S22', probe, [event], 'Web 容器内出现 shell 或下载工具，父进程不可见', 'candidate', '子进程是 shell 或下载工具，但 120 秒内看不到父进程；可信度为 inferred，不记为已观察的派生关系', confidence='inferred')
        return
    parent_name = program_name(parent)
    if parent_name not in servers:
        return
    probe = _probe(event, destination=parent_name, path=child, command=None)
    store._alert(cursor, 'S22', probe, [event], 'Web 服务派生 shell 或下载工具：' + parent_name + ' → ' + child, 'explicit', 'Web/API 容器内，已登记的 Web 服务进程派生了 shell 或下载工具；sandbox 角色不适用', confidence='observed')
