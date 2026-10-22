"""S23 tool-definition baseline. Alert only; nothing here blocks a request.

The gateway hashes each declared tool. The runtime stores one baseline per
agent and compares later requests. Learning ends at the later of N requests
and N seconds. A pinned hash wins over the learned one.
"""
import hashlib
import json
import re

try:
    from runtime.redact import redact_text
except ImportError:
    from redact import redact_text

DEFAULT_LEARN_REQUESTS = 10
DEFAULT_LEARN_SECONDS = 600
STORED_DESCRIPTION = 400
MAX_TOOLS = 64
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_INSTRUCTION = re.compile(r"(?i)ignore previous|do not tell the user|don't tell the user")
_HIDDEN = re.compile('[\u200b\u200c\u200d\u2060\ufeff\u180e]|[\U000e0000-\U000e007f]')
_BASE64 = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{201,}={0,2}(?![A-Za-z0-9+/])')


def tool_hash(name, description, parameters):
    body = {
        'name': str(name or ''),
        'description': description if isinstance(description, str) else '',
        'parameters': parameters if isinstance(parameters, (dict, list)) else {},
    }
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def param_names(schema, depth=0):
    if not isinstance(schema, dict) or depth > 4:
        return []
    names = []
    props = schema.get('properties')
    if isinstance(props, dict):
        for key, value in props.items():
            names.append(str(key)[:80])
            if isinstance(value, dict):
                names.extend(param_names(value, depth + 1))
    return names[:64]


def suspicious_categories(description):
    if not isinstance(description, str) or not description:
        return []
    found = []
    if _INSTRUCTION.search(description):
        found.append('instruction_like')
    if _HIDDEN.search(description):
        found.append('hidden_unicode')
    if _BASE64.search(description):
        found.append('base64_blob')
    return found


def present_description(description):
    text = description if isinstance(description, str) else ''
    text = _HIDDEN.sub('', text)
    text = _BASE64.sub('[BASE64]', text)
    return redact_text(text)[:STORED_DESCRIPTION]


def _hex_hash(value):
    text = str(value or '').strip().lower()
    return text if _HEX64.fullmatch(text) else ''


def iter_declared_tools(payload):
    """Return the declared tools, or None when this request did not send any.

    An empty list is a declaration. A missing tools and functions key is not,
    so a later chat turn that omits the array does not look like every tool
    disappeared.
    """
    if not isinstance(payload, dict):
        return None
    if 'tools' not in payload and 'functions' not in payload:
        return None
    found = []
    for item in payload.get('tools') or []:
        if not isinstance(item, dict):
            continue
        function = item.get('function') if isinstance(item.get('function'), dict) else item
        found.append(function)
    for item in payload.get('functions') or []:
        if isinstance(item, dict):
            found.append(item)
    by_name = {}
    for function in found:
        name = str(function.get('name') or '').strip()
        if not name or len(name) > 120:
            continue
        by_name[name] = function
    return [by_name[name] for name in sorted(by_name)]


def summarize_payload(payload):
    declared = iter_declared_tools(payload)
    if declared is None:
        return None
    tools = []
    for function in declared[:MAX_TOOLS]:
        name = str(function.get('name') or '').strip()
        description = function.get('description') if isinstance(function.get('description'), str) else ''
        parameters = function.get('parameters') if isinstance(function.get('parameters'), (dict, list)) else {}
        tools.append({
            'name': name,
            'hash': tool_hash(name, description, parameters),
            'description': present_description(description),
            'paramNames': param_names(parameters),
            'suspicious': suspicious_categories(description),
        })
    return {'tools': tools}


def annotate(event):
    """Hash the raw definition, then keep a short redacted description."""
    if not isinstance(event, dict):
        return event
    event = dict(event)
    tools = []
    for raw in (event.get('toolDefinitions') or [])[:MAX_TOOLS]:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get('name') or '').strip()
        if not name or len(name) > 120:
            continue
        description = raw.get('description') if isinstance(raw.get('description'), str) else ''
        parameters = raw.get('parameters') if isinstance(raw.get('parameters'), (dict, list)) else {}
        digest = _hex_hash(raw.get('hash')) or tool_hash(name, description, parameters)
        flags = []
        for item in list(raw.get('suspicious') or []) + suspicious_categories(description):
            text = str(item)[:40]
            if text and text not in flags:
                flags.append(text)
        names = raw.get('paramNames')
        if not isinstance(names, list) or not names:
            names = param_names(parameters)
        tools.append({
            'name': name,
            'hash': digest,
            'description': present_description(description),
            'paramNames': [str(item)[:80] for item in names[:64]],
            'suspicious': flags[:8],
        })
    event['toolDefinitions'] = tools
    return event


def _clamp_settings(raw):
    raw = raw if isinstance(raw, dict) else {}
    try:
        requests = int(raw.get('learnRequests') if raw.get('learnRequests') not in (None, '') else DEFAULT_LEARN_REQUESTS)
    except (TypeError, ValueError):
        requests = DEFAULT_LEARN_REQUESTS
    try:
        seconds = int(raw.get('learnSeconds') if raw.get('learnSeconds') not in (None, '') else DEFAULT_LEARN_SECONDS)
    except (TypeError, ValueError):
        seconds = DEFAULT_LEARN_SECONDS
    pinned = {}
    source = raw.get('pinned') if isinstance(raw.get('pinned'), dict) else {}
    for key, value in source.items():
        name = str(key).strip()
        digest = _hex_hash(value)
        if name and digest:
            pinned[name] = digest
    return {
        'learnRequests': min(100000, max(1, requests)),
        'learnSeconds': min(7 * 86400, max(0, seconds)),
        'pinned': pinned,
    }


def _settings(event):
    raw = event.get('toolBaseline') if isinstance(event.get('toolBaseline'), dict) else None
    if raw is None:
        policy = event.get('policy') if isinstance(event.get('policy'), dict) else {}
        raw = policy.get('toolDefinitionBaseline') if isinstance(policy.get('toolDefinitionBaseline'), dict) else {}
    return _clamp_settings(raw)


def _clip(text):
    text = present_description(text)
    if len(text) <= 160:
        return text
    return text[:160] + '…'


def _diff(old, new):
    parts = []
    old_text = old.get('description') or ''
    new_text = new.get('description') or ''
    if old_text != new_text:
        parts.append('description: %s → %s' % (_clip(old_text), _clip(new_text)))
    old_names = list(old.get('paramNames') or [])
    new_names = list(new.get('paramNames') or [])
    added = [name for name in new_names if name not in old_names]
    removed = [name for name in old_names if name not in new_names]
    if added:
        parts.append('params+: ' + ', '.join(added[:32]))
    if removed:
        parts.append('params-: ' + ', '.join(removed[:32]))
    if not parts:
        parts.append('hash changed; stored description and parameter names are unchanged')
    return redact_text('; '.join(parts))[:2048]


def _record(tool, pinned=False):
    return {
        'hash': tool.get('hash') or '',
        'description': tool.get('description') or '',
        'paramNames': list(tool.get('paramNames') or []),
        'pinned': bool(pinned),
        'absent': False,
    }


def _alert_definition(store, cursor, event, tool, change, old_hash, new_hash, diff, severity, suspicious=None):
    probe = dict(event)
    probe['path'] = tool.get('name') or ''
    probe['command'] = change + ':' + (new_hash or ','.join(suspicious or []))
    probe['toolDefinition'] = {
        'toolName': tool.get('name') or '',
        'change': change,
        'oldHash': old_hash or None,
        'newHash': new_hash or None,
        'diff': diff or '',
        'suspicious': list(suspicious or []),
    }
    titles = {
        'new': '工具定义在基线建立后新增：',
        'changed': '工具定义发生变化：',
        'removed': '工具定义消失：',
        'suspicious': '工具描述含隐藏或指令式文本：',
        'pinned': '工具定义与固定哈希不一致：',
    }
    basis = {
        'new': '该 agent 的工具基线已经建立，这个工具名之前不在基线里',
        'changed': '同一工具名的规范哈希与基线不同；已记录新旧哈希和截断后的差异',
        'removed': '已建立的基线里有这个工具名，本次声明里没有；只记为 info，不阻断',
        'suspicious': '工具描述命中隐藏字符、指令式短句或超长 base64；只告警',
        'pinned': 'agents.yaml 为这个工具名固定了哈希，本次声明与固定值不同',
    }
    store._alert(
        cursor, 'S23', probe, [_ref(event, probe['toolDefinition'])],
        titles[change] + (tool.get('name') or ''),
        'explicit', basis[change], confidence='observed', severity=severity,
    )


def _ref(event, definition):
    return {
        'id': event.get('id'),
        'time': event.get('time'),
        'kind': event.get('kind') or 'model',
        'operation': 'TOOL_DEFINITIONS',
        'workload': event.get('workload'),
        'agentId': event.get('agentId'),
        'chainId': event.get('chainId'),
        'source': event.get('source'),
        'identity': event.get('identity'),
        'toolName': definition.get('toolName'),
        'toolDefinition': definition,
    }


def _suspicious(store, cursor, event, tool):
    flags = list(tool.get('suspicious') or [])
    if not flags:
        return
    _alert_definition(
        store, cursor, event, tool, 'suspicious', None, tool.get('hash'),
        'categories: ' + ','.join(flags) + '; ' + _diff({'description': '', 'paramNames': []}, tool),
        'medium', flags,
    )


def _load(cursor, agent):
    row = cursor.execute('SELECT payload FROM tool_baselines WHERE agent_id=?', (agent,)).fetchone()
    if not row:
        return None
    return json.loads(row[0])


def _save(cursor, agent, row):
    encoded = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    cursor.execute('INSERT OR REPLACE INTO tool_baselines VALUES(?,?)', (agent, encoded))


def _fresh(event, settings):
    tools = {}
    for name, digest in settings['pinned'].items():
        tools[name] = {'hash': digest, 'description': '', 'paramNames': [], 'pinned': True, 'absent': False}
    return {
        'agentId': event.get('agentId'),
        'firstSeen': float(event.get('time') or 0),
        'requests': 0,
        'established': False,
        'tools': tools,
        'learnRequests': settings['learnRequests'],
        'learnSeconds': settings['learnSeconds'],
    }


def _apply_pinned_or_learn(store, cursor, event, row, tool, learning):
    name = tool['name']
    current = row['tools'].get(name)
    pinned = name in (row.get('_pinned') or {})
    _suspicious(store, cursor, event, tool)
    if pinned:
        expected = row['_pinned'][name]
        if tool.get('hash') != expected:
            _alert_definition(store, cursor, event, tool, 'pinned', expected, tool.get('hash'), _diff(current or {}, tool), 'medium')
            row['tools'][name] = {
                'hash': expected,
                'description': tool.get('description') or '',
                'paramNames': list(tool.get('paramNames') or []),
                'pinned': True,
                'absent': False,
            }
            return
        row['tools'][name] = _record(tool, pinned=True)
        row['tools'][name]['hash'] = expected
        return
    if learning:
        row['tools'][name] = _record(tool, pinned=False)
        return
    if current is None:
        _alert_definition(store, cursor, event, tool, 'new', None, tool.get('hash'), _diff({}, tool), 'medium')
        row['tools'][name] = _record(tool, pinned=False)
        return
    if current.get('hash') != tool.get('hash'):
        _alert_definition(store, cursor, event, tool, 'changed', current.get('hash'), tool.get('hash'), _diff(current, tool), 'medium')
    current_absent = current.get('absent')
    row['tools'][name] = _record(tool, pinned=False)
    if current_absent and current.get('hash') == tool.get('hash'):
        return


def observe_definitions(store, cursor, event):
    if event.get('operation') != 'TOOL_DEFINITIONS':
        return None
    agent = str(event.get('agentId') or '')
    if not agent:
        return None
    incoming = [item for item in (event.get('toolDefinitions') or []) if isinstance(item, dict) and item.get('name') and item.get('hash')]
    settings = _settings(event)
    row = _load(cursor, agent) or _fresh(event, settings)
    applied = [str(item) for item in (row.get('appliedIds') or [])]
    event_id = str(event.get('id') or '')
    if event_id and event_id in applied:
        return row
    if event_id:
        applied.append(event_id)
    row['appliedIds'] = applied[-200:]
    row['_pinned'] = settings['pinned']
    row['learnRequests'] = settings['learnRequests']
    row['learnSeconds'] = settings['learnSeconds']
    row['requests'] = int(row.get('requests') or 0) + 1
    seen = {item['name'] for item in incoming}
    learning = not row.get('established')
    for tool in incoming:
        _apply_pinned_or_learn(store, cursor, event, row, tool, learning)
    if learning:
        for name in list(row['tools']):
            if name not in seen and not row['tools'][name].get('pinned'):
                del row['tools'][name]
        elapsed = float(event.get('time') or 0) - float(row.get('firstSeen') or 0)
        if row['requests'] >= settings['learnRequests'] and elapsed >= settings['learnSeconds']:
            row['established'] = True
            row['establishedAt'] = event.get('time')
    else:
        for name, current in list(row['tools'].items()):
            if name in seen or current.get('absent'):
                continue
            placeholder = {'name': name, 'hash': None, 'description': current.get('description') or '', 'paramNames': current.get('paramNames') or [], 'suspicious': []}
            _alert_definition(store, cursor, event, placeholder, 'removed', current.get('hash'), None, 'tool absent from this request', 'info')
            current['absent'] = True
            row['tools'][name] = current
    row.pop('_pinned', None)
    _save(cursor, agent, row)
    return row
