"""S02/S03 correlation. Time proximity is only a constraint, never a reason to link.

Semantic stage: an observed untrusted segment, then a high-risk tool call on the
same chain. Host stage: an argument entity equals a host event for the same
agent. Inferred first-token matches are not recorded as links.
"""
import json
import urllib.parse

try:
    from runtime.semantic_extract import high_risk_reasons, triggering_untrusted
except ImportError:
    from semantic_extract import high_risk_reasons, triggering_untrusted

HOST_WINDOW = 120
CHAIN_LOOKBACK = 3600


def observe(store, cursor, event):
    kind = event.get('kind')
    if kind == 'tool' and event.get('operation') == 'TOOL_CALL':
        _semantic(store, cursor, event)
    elif kind in ('process', 'file', 'network'):
        _confirm_from_host(store, cursor, event)


def _semantic(store, cursor, event):
    segments = _segments_for_tool(store, cursor, event)
    if not segments:
        return None
    reasons = _reasons(event)
    if not reasons:
        return None
    basis = '不受信片段与高风险工具调用在同一 chainId 上对齐（' + ','.join(reasons) + '）；不是提示注入判定'
    links = [{
        'from': 'untrustedSegment',
        'to': 'toolCall',
        'confidence': 'correlated',
        'basis': basis,
    }]
    refs = _semantic_refs(store, cursor, event, segments)
    alert_id = store.open_chain_alert(
        cursor, 'S03', event, refs,
        '可疑模型到命令执行链',
        phase='semantic', confidence='correlated', basis=basis, links=links,
    )
    if alert_id:
        _confirm_forward(store, cursor, event, alert_id, segments)
    return alert_id


def _confirm_from_host(store, cursor, host):
    if not host.get('agentId'):
        return None
    for tool in _tools_before(store, cursor, host):
        segments = _segments_for_tool(store, cursor, tool)
        if not segments:
            continue
        match = match_host(tool, host)
        if not match:
            continue
        confidence, basis = match
        if confidence != 'correlated':
            continue
        alert_id = _semantic(store, cursor, tool)
        if not alert_id:
            continue
        _upgrade(store, cursor, alert_id, tool, host, basis)
        if host.get('kind') == 'network':
            _maybe_s02(store, cursor, tool, host, segments, basis)
        return alert_id
    return None


def _confirm_forward(store, cursor, tool, alert_id, segments):
    for host in _hosts_after(store, cursor, tool):
        match = match_host(tool, host)
        if not match or match[0] != 'correlated':
            continue
        _upgrade(store, cursor, alert_id, tool, host, match[1])
        if host.get('kind') == 'network':
            _maybe_s02(store, cursor, tool, host, segments, match[1])


def _upgrade(store, cursor, alert_id, tool, host, basis):
    link = {
        'from': 'toolCall',
        'to': 'hostEvent',
        'confidence': 'correlated',
        'basis': basis + '；同一 agentId，时间只作为窗口约束',
        'hostEventId': host.get('id'),
        'toolCallId': tool.get('toolCallId'),
    }
    store.upgrade_chain_alert(cursor, alert_id, host, link, basis)


def _maybe_s02(store, cursor, tool, host, segments, host_basis):
    try:
        from runtime.engine import network_allowed
    except ImportError:
        from engine import network_allowed
    allowed = (host.get('policy') or {}).get('allowedNetworks')
    if not (isinstance(allowed, list) and allowed):
        return None
    if network_allowed(host.get('destination'), host.get('port'), allowed):
        return None
    basis = '不受信输入后的工具调用与授权范围外连接按目的实体对齐；' + host_basis
    links = [
        {
            'from': 'untrustedSegment',
            'to': 'toolCall',
            'confidence': 'correlated',
            'basis': '同一 chainId 已有不受信片段与该工具调用',
        },
        {
            'from': 'toolCall',
            'to': 'network',
            'confidence': 'correlated',
            'basis': host_basis,
            'hostEventId': host.get('id'),
        },
    ]
    refs = [tool, host]
    return store.open_chain_alert(
        cursor, 'S02', host, refs,
        '工具后的非白名单外联',
        phase='host_confirmed', confidence='correlated', basis=basis, links=links,
        chain_id=tool.get('chainId'), tool_call_id=tool.get('toolCallId'), agent_event=tool,
    )


def match_host(tool, host):
    """Exact entity match only. Returns (confidence, basis) or None."""
    if tool.get('agentId') and host.get('agentId') and tool['agentId'] != host['agentId']:
        return None
    if not tool.get('agentId') or not host.get('agentId'):
        return None
    start = float(tool.get('time') or 0)
    end = start + float(tool.get('hostWindowSeconds') or HOST_WINDOW)
    host_time = float(host.get('time') or 0)
    if host_time < start or host_time > end:
        return None
    entities = tool.get('argsEntities') or {}
    kind = host.get('kind')
    if kind == 'file':
        path = host.get('path') or ''
        if path and path in (entities.get('paths') or []):
            return 'correlated', '路径实体与主机文件路径一致：' + path
        return None
    if kind == 'network':
        return _match_network(entities, host)
    if kind == 'process':
        return _match_process(entities, host)
    return None


def _match_network(entities, host):
    destination = str(host.get('destination') or '')
    port = host.get('port')
    if not destination:
        return None
    for item in entities.get('hosts') or []:
        address, separator, port_text = str(item).rpartition(':')
        if separator and port_text.isdigit():
            if destination == address and (port is None or str(port) == port_text):
                return 'correlated', '主机实体与连接目的一致：' + str(item)
        elif destination == str(item):
            return 'correlated', '主机实体与连接目的一致：' + str(item)
    for url in entities.get('urls') or []:
        hostname = urllib.parse.urlsplit(str(url)).hostname or ''
        if hostname and hostname == destination:
            return 'correlated', 'URL 主机与连接目的一致：' + destination
    return None


def _match_process(entities, host):
    try:
        from runtime.engine import canonical_command
    except ImportError:
        from engine import canonical_command
    command = host.get('command') or ''
    canonical_host = canonical_command(command)
    for path in entities.get('paths') or []:
        if path and (path in (host.get('execPaths') or []) or path == host.get('path')):
            return 'correlated', '路径实体与执行路径一致：' + path
    for raw in entities.get('commands') or []:
        canonical_tool = canonical_command(raw)
        if len(canonical_tool) >= 4 and (canonical_tool == canonical_host or canonical_tool in canonical_host or canonical_tool in command):
            return 'correlated', '命令实体与主机 command 一致或为其子串'
        if len(canonical_host) >= 8 and ' ' in canonical_host and canonical_host in canonical_tool:
            return 'correlated', '主机 command 是工具命令实体的子串且含参数'
    return None


def _reasons(event):
    entities = dict(event.get('argsEntities') or {})
    entities.setdefault('urls', [])
    return high_risk_reasons(event.get('toolName'), entities, (event.get('policy') or {}).get('allowedNetworks'))


def _segments_for_tool(store, cursor, tool):
    if tool.get('chainConfidence') == 'unknown':
        return []
    own = triggering_untrusted(tool.get('untrustedSegments'))
    prior = []
    chain = tool.get('chainId')
    if chain:
        start = float(tool.get('time') or 0) - float(tool.get('chainLookbackSeconds') or CHAIN_LOOKBACK)
        for item in _load(cursor, tool.get('source'), start, float(tool.get('time') or 0) + 1, chain=chain, newest_first=True):
            prior.extend(triggering_untrusted(item.get('untrustedSegments')))
    # A flag without a stored segment is not evidence.
    return (own + prior)[:8]


def _semantic_refs(store, cursor, tool, segments):
    refs = []
    chain = tool.get('chainId')
    if chain:
        start = float(tool.get('time') or 0) - float(tool.get('chainLookbackSeconds') or CHAIN_LOOKBACK)
        for item in _load(cursor, tool.get('source'), start, float(tool.get('time') or 0) + 1, chain=chain):
            if triggering_untrusted(item.get('untrustedSegments')):
                refs.append(item)
                break
    refs.append(tool)
    return refs[:6]


def _tools_before(store, cursor, host):
    start = float(host.get('time') or 0) - HOST_WINDOW
    found = []
    for item in _load(cursor, host.get('source'), start, float(host.get('time') or 0) + 1, agent=host.get('agentId'), kinds=('tool',), newest_first=True):
        if item.get('kind') == 'tool' and item.get('operation') == 'TOOL_CALL' and item.get('agentId') == host.get('agentId'):
            found.append(item)
    found.sort(key=lambda item: abs(float(host.get('time') or 0) - float(item.get('time') or 0)))
    return found


def _hosts_after(store, cursor, tool):
    start = float(tool.get('time') or 0)
    end = start + HOST_WINDOW
    found = []
    for item in _load(cursor, tool.get('source'), start, end + 1, agent=tool.get('agentId'), kinds=('process', 'file', 'network')):
        if item.get('kind') in ('process', 'file', 'network') and item.get('agentId') == tool.get('agentId'):
            found.append(item)
    return found


LOAD_LIMIT = 400


def _load(cursor, source, start, end, chain=None, agent=None, kinds=None, newest_first=False, limit=LOAD_LIMIT):
    """Events of one source in [start, end], filtered in SQL before the limit.

    Chain, agent and kind filters run inside the query so unrelated traffic in the
    window cannot push the relevant events past the limit. newest_first keeps the
    events nearest to `end` when the window still holds more than `limit`; the
    result is always returned in ascending time order.
    """
    sql = 'SELECT payload FROM events WHERE source=? AND time>=? AND time<=?'
    params = [source, start, end]
    if kinds:
        sql += ' AND kind IN (%s)' % ','.join('?' * len(kinds))
        params.extend(kinds)
    if chain is not None:
        sql += " AND (json_extract(payload,'$.chainId')=? OR json_extract(payload,'$.runId')=?)"
        params.extend([chain, chain])
    if agent is not None:
        sql += " AND json_extract(payload,'$.agentId')=?"
        params.append(agent)
    sql += ' ORDER BY time %s LIMIT ?' % ('DESC' if newest_first else 'ASC')
    params.append(int(limit))
    rows = cursor.execute(sql, params).fetchall()
    if newest_first:
        rows = list(reversed(rows))
    items = []
    for row in rows:
        item = json.loads(row[0])
        if chain is not None and item.get('chainId') != chain and item.get('runId') != chain:
            continue
        if agent is not None and item.get('agentId') != agent:
            continue
        items.append(item)
    return items
