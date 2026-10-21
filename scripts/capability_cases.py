"""Placeholder cases for the pre-drill web and decision rules.

No attack payloads. Addresses are documentation ranges or loopback.
"""
import json
import tempfile
import time
from pathlib import Path

from runtime.engine import Store

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
]


def run_cases(mode='all'):
    results = [case() for case in CASES]
    if mode == 'baseline':
        results = [item for item in results if item['expect'] == []]
    return {'ok': all(item['ok'] for item in results), 'cases': results}
