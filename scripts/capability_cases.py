"""Placeholder cases for the pre-drill web and decision rules.

No attack payloads. Addresses are documentation ranges or loopback.
"""
import json
import tempfile
import time
from pathlib import Path

from runtime.engine import Store
from runtime.tool_definitions import tool_hash

SECRET = 'PLACEHOLDERSECRET'
SRC = '192.0.2.10'
META = '169.254.169.254'


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now


def _store(config=None):
    clock = Clock()
    root = Path(tempfile.mkdtemp(prefix='agentreins-cap-'))
    store = Store(root / 'db', clock, config=config or {})
    store.heartbeat('host', {'layers': {'process': 'active'}, 'drop': 0})
    store._root = root
    return store


def _rules(store):
    return sorted({item['rule'] for item in store.listing({})['items']})


def _dump(store):
    with store.db(write=False) as cursor:
        blobs = [row[0] for row in cursor.execute('SELECT payload FROM events')]
        blobs += [row[0] for row in cursor.execute('SELECT payload FROM alerts')]
    return '\n'.join(blobs)


def _http(agent, when, clients, totals=None, hits=None):
    totals = totals or {
        'requests': sum(int(item.get('requests') or 0) for item in clients),
        'notFound': sum(int(item.get('notFound') or 0) for item in clients),
        'clientErrors': sum(int(item.get('clientErrors') or 0) for item in clients),
        'serverErrors': sum(int(item.get('serverErrors') or 0) for item in clients),
    }
    return {
        'id': 'http-%s-%s' % (agent, int(when)),
        'time': when,
        'workload': 'http:' + agent,
        'kind': 'http',
        'operation': 'HTTP_SUMMARY',
        'identity': {'basis': '入站访问日志映射'},
        'agentId': agent,
        'pid': 0,
        'confidence': 'observed',
        'windowSeconds': 60,
        'clients': clients,
        'totals': totals,
        'categoryHits': hits or [],
        'result': 'success',
    }


def _tool(agent, when, name, entities, chain='chain-1', policy=None, arguments=None, segments=None):
    event = {
        'id': 'tool-%s-%s-%s' % (agent, name, int(when * 1000)),
        'time': when,
        'workload': 'gateway:' + agent,
        'kind': 'tool',
        'operation': 'TOOL_CALL',
        'identity': {'basis': 'gateway route'},
        'agentId': agent,
        'chainId': chain,
        'toolCallId': 'call-' + name,
        'toolName': name,
        'argsEntities': entities,
        'pid': 0,
        'confidence': 'observed',
        'result': 'success',
        'policy': policy or {},
        'untrustedSegments': segments or [],
    }
    if arguments is not None:
        event['arguments'] = arguments
    return event


def _finish(case_id, store, expect, note=''):
    rules = _rules(store)
    leaked = SECRET in _dump(store)
    return {
        'id': case_id,
        'expect': expect,
        'rules': rules,
        'ok': rules == sorted(expect) and not leaked,
        'secretLeaked': leaked,
        'note': note,
    }


def case_scan_burst():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 25, 'distinctPaths': 25, 'notFound': 25, 'authFailures': 0}])])
    return _finish('W-1', store, ['S17'], 'one client over the path threshold is one S17')


def case_scan_spread():
    store = _store()
    when = store.clock.now
    events = []
    for offset in (0, 120, 240):
        events.append(_http('target-01', when - 500 + offset, [{'address': SRC, 'requests': 15, 'distinctPaths': 15, 'notFound': 15, 'authFailures': 0}]))
    store.ingest('host', events)
    return _finish('W-2', store, [], 'each 60s window stays under the threshold')


def case_auth_burst():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 8, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 8}])])
    return _finish('W-3', store, ['S19'], 'login failures at the default threshold')


def case_one_auth_failure():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 1, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 1}])])
    return _finish('W-3-below', store, [], 'one failed login does not alert')


def case_secret_egress():
    store = _store()
    when = store.clock.now
    arguments = json.dumps({'url': 'http://192.0.2.10/p', 'api_key': SECRET})
    store.ingest('host', [_tool('target-01', when, 'http_request', {'urls': ['http://192.0.2.10/p'], 'hosts': ['192.0.2.10']}, arguments=arguments)])
    result = _finish('D-1', store, ['S13'], 'egress tool argument is a category and digest')
    alerts = [store.detail(item['id']) for item in store.listing({})['items']]
    result['categories'] = sorted({item.get('category') for alert in alerts for item in (alert.get('secretFindings') or [])})
    result['ok'] = result['ok'] and result['categories'] == ['credential_assignment']
    return result


def case_secret_local_tool():
    store = _store()
    when = store.clock.now
    arguments = json.dumps({'note': 'api_key=%s' % SECRET})
    store.ingest('host', [_tool('target-01', when, 'notes', {'urls': [], 'hosts': [], 'paths': [], 'commands': []}, arguments=arguments)])
    return _finish('D-1-benign', store, [], 'a local tool with no URL or egress name does not raise S13')


def case_metadata_argument():
    store = _store()
    when = store.clock.now
    segment = {'role': 'tool', 'sourceKind': 'tool_result', 'digest': 'abc', 'confidence': 'observed', 'excerpt': 'PLACEHOLDER_UNTRUSTED_READ'}
    store.ingest('host', [_tool(
        'target-01', when, 'lookup',
        {'urls': ['http://%s/latest' % META], 'hosts': [META]},
        policy={'allowedNetworks': [{'cidr': '192.0.2.0/24'}]},
        segments=[segment],
    )])
    result = _finish('D-4', store, ['S03', 'S16'], 'metadata IP outside the allowlist; the same chain also has an untrusted segment')
    alerts = [store.detail(item['id']) for item in store.listing({})['items'] if item['rule'] == 'S16']
    alert = alerts[0] if alerts else {}
    result['ok'] = result['ok'] and alert.get('chainId') == 'chain-1' and alert.get('relation', {}).get('confidence') == 'correlated' and alert.get('layer') == 'D'
    return result


def case_metadata_allowed():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_tool(
        'target-01', when, 'lookup',
        {'urls': ['http://%s/latest' % META], 'hosts': [META]},
        policy={'allowedNetworks': [{'cidr': '169.254.0.0/16'}]},
    )])
    return _finish('D-4-allowed', store, [], 'a destination inside allowedNetworks is not S16')


def case_hostname_not_internal():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_tool('target-01', when, 'lookup', {'urls': [], 'hosts': ['metadata.invalid']}, policy={})])
    return _finish('D-4-name', store, [], 'hostnames are not treated as metadata addresses')


def case_cross_agent():
    store = _store()
    when = store.clock.now
    store.ingest('host', [
        _http('target-02', when, [{'address': SRC, 'requests': 30, 'distinctPaths': 30, 'notFound': 0, 'authFailures': 0}]),
        _http('target-01', when + 1, [{'address': SRC, 'requests': 2, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 0}]),
    ])
    own = _rules(store)
    filtered = sorted({item['rule'] for item in store.listing({'agentId': ['target-01']})['items']})
    other = [item['agentId'] for item in store.listing({'agentId': ['target-02']})['items']]
    return {
        'id': 'V-2',
        'expect': ['S17'],
        'rules': own,
        'ok': own == ['S17'] and filtered == [] and other == ['target-02'],
        'secretLeaked': False,
        'note': 'target-02 burst does not appear under target-01',
    }


def case_error_rate():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 40, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 0, 'serverErrors': 30}], totals={'requests': 40, 'serverErrors': 30, 'clientErrors': 0})])
    return _finish('W-3-S18', store, ['S18'], 'error ratio above the sample floor')


def case_error_rate_small():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 4, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 0}], totals={'requests': 4, 'serverErrors': 4, 'clientErrors': 0})])
    return _finish('W-3-S18-small', store, [], 'a tiny sample does not raise S18')


def case_category():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 3, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 0}], hits=[{'address': SRC, 'category': 'placeholder_probe', 'count': 3}])])
    return _finish('W-4', store, ['S21'], 'category count at the default threshold')


def case_category_once():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_http('target-01', when, [{'address': SRC, 'requests': 1, 'distinctPaths': 1, 'notFound': 0, 'authFailures': 0}], hits=[{'address': SRC, 'category': 'placeholder_probe', 'count': 1}])])
    return _finish('W-4-once', store, [], 'one category hit stays under the default')


def case_allowed_tool():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_tool('target-01', when, 'other_tool', {'urls': [], 'hosts': []}, policy={'allowedTools': ['status']})])
    return _finish('D-3', store, ['S14'], 'tool name outside a non-empty allowlist')


def case_allowed_tool_unset():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_tool('target-01', when, 'other_tool', {'urls': [], 'hosts': []}, policy={})])
    return _finish('D-3-unset', store, [], 'S14 stays off when allowedTools is unset')


def case_tool_rate():
    store = _store({'toolThresholds': {'perMinute': 3, 'perChainTool': 0}})
    when = store.clock.now
    events = []
    for index in range(3):
        events.append(_tool('target-01', when, 'status', {'urls': [], 'hosts': []}, chain='rate-%d' % index))
        events[-1]['id'] = 'rate-%d' % index
        events[-1]['toolCallId'] = 'call-rate-%d' % index
    store.ingest('host', events)
    return _finish('D-4-S15', store, ['S15'], 'three calls in one minute at a configured threshold of 3')


def case_ssrf_role():
    store = _store()
    when = store.clock.now
    store.ingest('host', [{
        'id': 'net-meta', 'time': when, 'workload': 'target-01-api', 'kind': 'network', 'identity': {'basis': 'cgroup'},
        'agentId': 'target-01', 'pid': 40, 'containerRole': 'api', 'destination': META, 'port': 80, 'result': 'success',
        'policy': {},
    }])
    return _finish('W-5', store, ['S20'], 'api role connect to the metadata range')


def case_ssrf_database():
    store = _store()
    when = store.clock.now
    store.ingest('host', [{
        'id': 'net-db', 'time': when, 'workload': 'target-01-db', 'kind': 'network', 'identity': {'basis': 'cgroup'},
        'agentId': 'target-01', 'pid': 41, 'containerRole': 'database', 'destination': META, 'port': 80, 'result': 'success',
    }])
    return _finish('W-5-db', store, [], 'database role is not an application SSRF shape')


def case_web_child():
    store = _store()
    when = store.clock.now
    store.ingest('host', [
        {
            'id': 'parent-nginx', 'time': when, 'workload': 'target-01-api', 'kind': 'process', 'identity': {'basis': 'cgroup'},
            'agentId': 'target-01', 'pid': 10, 'ppid': 1, 'containerRole': 'web', 'command': '/usr/sbin/nginx',
            'policy': {'webServers': ['nginx']}, 'result': 'success',
        },
        {
            'id': 'child-curl', 'time': when + 1, 'workload': 'target-01-api', 'kind': 'process', 'identity': {'basis': 'cgroup'},
            'agentId': 'target-01', 'pid': 11, 'ppid': 10, 'containerRole': 'web', 'command': 'curl http://192.0.2.10/health',
            'policy': {'webServers': ['nginx']}, 'result': 'success',
        },
    ])
    result = _finish('W-6', store, ['S22'], 'nginx child curl')
    if result['rules']:
        alert = store.detail(store.listing({})['items'][0]['id'])
        result['ok'] = result['ok'] and alert.get('relation', {}).get('confidence') == 'observed'
    return result


def case_web_child_inferred():
    store = _store()
    when = store.clock.now
    store.ingest('host', [{
        'id': 'child-bash', 'time': when, 'workload': 'target-01-api', 'kind': 'process', 'identity': {'basis': 'cgroup'},
        'agentId': 'target-01', 'pid': 12, 'ppid': 99, 'containerRole': 'web', 'command': '/bin/bash',
        'policy': {'webServers': ['nginx']}, 'result': 'success',
    }])
    result = _finish('W-6-inferred', store, ['S22'], 'missing parent is inferred')
    if result['rules']:
        alert = store.detail(store.listing({})['items'][0]['id'])
        result['ok'] = result['ok'] and alert.get('relation', {}).get('confidence') == 'inferred'
    return result


def _tool_def(name, description='PLACEHOLDER_STATUS', parameters=None):
    if parameters is None:
        parameters = {'type': 'object', 'properties': {'q': {'type': 'string'}}}
    return {'name': name, 'description': description, 'parameters': parameters}


def _definitions(agent, when, tools, chain='chain-s23', learn_requests=None, learn_seconds=None, pinned=None, suffix=''):
    event = {
        'id': 'defs-%s-%s%s' % (agent, int(when * 1000), suffix),
        'time': when,
        'workload': 'gateway:' + agent,
        'kind': 'model',
        'operation': 'TOOL_DEFINITIONS',
        'identity': {'basis': 'gateway route'},
        'agentId': agent,
        'chainId': chain,
        'confidence': 'observed',
        'pid': 0,
        'result': 'success',
        'toolDefinitions': tools,
    }
    baseline = {}
    if learn_requests is not None:
        baseline['learnRequests'] = learn_requests
    if learn_seconds is not None:
        baseline['learnSeconds'] = learn_seconds
    if pinned is not None:
        baseline['pinned'] = pinned
    if baseline:
        event['toolBaseline'] = baseline
    return event


def _s23(store):
    return [store.detail(item['id']) for item in store.listing({})['items'] if item['rule'] == 'S23']


def _one_s23(result, store, change):
    alerts = _s23(store)
    if len(alerts) != 1:
        result['ok'] = False
        result['note'] = result['note'] + '; alerts=%d' % len(alerts)
        return None
    alert = alerts[0]
    definition = alert.get('toolDefinition') or {}
    result['ok'] = (
        result['ok']
        and definition.get('change') == change
        and alert.get('relation', {}).get('confidence') == 'observed'
        and alert.get('agentId') == 'target-01'
        and alert.get('chainId') == 'chain-s23'
        and alert.get('layer') == 'D'
    )
    return alert


def case_tool_learn():
    store = _store()
    when = store.clock.now
    events = []
    for index in range(3):
        tools = [_tool_def('status')]
        if index == 2:
            tools.append(_tool_def('lookup'))
        events.append(_definitions('target-01', when, tools, suffix='-%d' % index))
    store.ingest('host', events)
    return _finish('D-5-learn', store, [], 'a new name during the default learning window does not alert')


def case_tool_reorder():
    store = _store()
    when = store.clock.now
    first = {'type': 'object', 'properties': {'q': {'type': 'string'}, 'limit': {'type': 'integer'}}}
    second = {'properties': {'limit': {'type': 'integer'}, 'q': {'type': 'string'}}, 'type': 'object'}
    store.ingest('host', [
        _definitions('target-01', when, [_tool_def('status', parameters=first)], suffix='-a', learn_requests=1, learn_seconds=0),
        _definitions('target-01', when + 1, [_tool_def('status', parameters=second)], suffix='-b', learn_requests=1, learn_seconds=0),
    ])
    return _finish('D-5-reorder', store, [], 'JSON key order is not a definition change')


def case_tool_pinned_match():
    store = _store()
    when = store.clock.now
    tool = _tool_def('status')
    pinned = tool_hash(tool['name'], tool['description'], tool['parameters'])
    store.ingest('host', [_definitions('target-01', when, [tool], pinned={'status': pinned})])
    return _finish('D-5-pinned-match', store, [], 'a declaration that matches the pinned hash does not alert')


def case_tool_new():
    store = _store()
    when = store.clock.now
    store.ingest('host', [
        _definitions('target-01', when, [_tool_def('status')], suffix='-a', learn_requests=1, learn_seconds=0),
        _definitions('target-01', when + 1, [_tool_def('status'), _tool_def('lookup')], suffix='-b', learn_requests=1, learn_seconds=0),
    ])
    result = _finish('D-5-new', store, ['S23'], 'a name that appears after the baseline')
    alert = _one_s23(result, store, 'new')
    if alert:
        definition = alert['toolDefinition']
        result['ok'] = result['ok'] and definition.get('toolName') == 'lookup' and definition.get('newHash') and not definition.get('oldHash')
    return result


def case_tool_description():
    store = _store()
    when = store.clock.now
    store.ingest('host', [
        _definitions('target-01', when, [_tool_def('status')], suffix='-a', learn_requests=1, learn_seconds=0),
        _definitions('target-01', when + 1, [_tool_def('status', description='PLACEHOLDER_STATUS revised')], suffix='-b', learn_requests=1, learn_seconds=0),
    ])
    result = _finish('D-5-description', store, ['S23'], 'a changed description changes the hash')
    alert = _one_s23(result, store, 'changed')
    if alert:
        definition = alert['toolDefinition']
        result['ok'] = result['ok'] and definition.get('oldHash') and definition.get('newHash') and definition['oldHash'] != definition['newHash']
        result['ok'] = result['ok'] and 'PLACEHOLDER_STATUS' in definition.get('diff', '') and 'revised' in definition.get('diff', '')
        result['ok'] = result['ok'] and alert.get('severity') == 'medium'
    return result


def case_tool_schema():
    store = _store()
    when = store.clock.now
    changed = {'type': 'object', 'properties': {'query': {'type': 'string'}}}
    store.ingest('host', [
        _definitions('target-01', when, [_tool_def('status')], suffix='-a', learn_requests=1, learn_seconds=0),
        _definitions('target-01', when + 1, [_tool_def('status', parameters=changed)], suffix='-b', learn_requests=1, learn_seconds=0),
    ])
    result = _finish('D-5-schema', store, ['S23'], 'a changed parameter name changes the hash')
    alert = _one_s23(result, store, 'changed')
    if alert:
        diff = alert['toolDefinition'].get('diff') or ''
        result['ok'] = result['ok'] and 'query' in diff and 'q' in diff and alert['toolDefinition']['oldHash'] != alert['toolDefinition']['newHash']
    return result


def case_tool_hidden():
    store = _store()
    when = store.clock.now
    hidden = 'PLACEHOLDER_STATUS' + '\U000E0041'
    store.ingest('host', [_definitions('target-01', when, [_tool_def('status', description=hidden)])])
    result = _finish('D-5-hidden', store, ['S23'], 'a unicode tag in the description alerts during learning')
    alert = _one_s23(result, store, 'suspicious')
    if alert:
        result['ok'] = result['ok'] and 'hidden_unicode' in (alert['toolDefinition'].get('suspicious') or []) and alert.get('severity') == 'medium'
        result['ok'] = result['ok'] and '\U000E0041' not in _dump(store)
    return result


def case_tool_pinned_mismatch():
    store = _store()
    when = store.clock.now
    store.ingest('host', [_definitions('target-01', when, [_tool_def('status')], pinned={'status': '0' * 64})])
    result = _finish('D-5-pinned', store, ['S23'], 'a pinned hash wins over the learning window')
    alert = _one_s23(result, store, 'pinned')
    if alert:
        definition = alert['toolDefinition']
        result['ok'] = result['ok'] and definition.get('oldHash') == '0' * 64 and definition.get('newHash') and definition['newHash'] != definition['oldHash']
        result['ok'] = result['ok'] and alert.get('severity') == 'medium'
    return result


def case_tool_removed():
    store = _store()
    when = store.clock.now
    store.ingest('host', [
        _definitions('target-01', when, [_tool_def('status'), _tool_def('lookup')], suffix='-a', learn_requests=1, learn_seconds=0),
        _definitions('target-01', when + 1, [_tool_def('status')], suffix='-b', learn_requests=1, learn_seconds=0),
    ])
    result = _finish('D-5-removed', store, ['S23'], 'a tool that disappears after the baseline is info')
    alert = _one_s23(result, store, 'removed')
    if alert:
        definition = alert['toolDefinition']
        result['ok'] = result['ok'] and definition.get('toolName') == 'lookup' and definition.get('oldHash') and not definition.get('newHash')
        result['ok'] = result['ok'] and alert.get('severity') == 'info'
    return result


def case_sandbox_child():
    store = _store()
    when = store.clock.now
    store.ingest('host', [{
        'id': 'sand', 'time': when, 'workload': 'target-01-sandbox', 'kind': 'process', 'identity': {'basis': 'cgroup'},
        'agentId': 'target-01', 'pid': 13, 'ppid': 10, 'containerRole': 'sandbox', 'command': '/bin/bash',
        'policy': {'webServers': ['nginx']}, 'result': 'success',
    }])
    return _finish('W-6-sandbox', store, [], 'sandbox role does not raise S22')


CASES = [
    case_scan_burst,
    case_scan_spread,
    case_auth_burst,
    case_one_auth_failure,
    case_secret_egress,
    case_secret_local_tool,
    case_metadata_argument,
    case_metadata_allowed,
    case_hostname_not_internal,
    case_cross_agent,
    case_error_rate,
    case_error_rate_small,
    case_category,
    case_category_once,
    case_allowed_tool,
    case_allowed_tool_unset,
    case_tool_rate,
    case_ssrf_role,
    case_ssrf_database,
    case_web_child,
    case_web_child_inferred,
    case_sandbox_child,
    case_tool_learn,
    case_tool_reorder,
    case_tool_pinned_match,
    case_tool_new,
    case_tool_description,
    case_tool_schema,
    case_tool_hidden,
    case_tool_pinned_mismatch,
    case_tool_removed,
]


def run_cases(mode='all'):
    results = [case() for case in CASES]
    if mode == 'baseline':
        results = [item for item in results if item['expect'] == []]
    return {'ok': all(item['ok'] for item in results), 'cases': results}
