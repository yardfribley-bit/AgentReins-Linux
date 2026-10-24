"""Observe v2 is read-only. Placeholder markers only; no live secrets."""
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.client import HTTPConnection
from pathlib import Path

from runtime.server import App

ROOT = Path(__file__).resolve().parents[2]


class ObserveApiTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        drill = Path(self.tmp.name) / 'drill.yaml'
        now = time.time()
        drill.write_text(
            'version: 1\npublic: false\nlabel: unit\nscenarios:\n'
            '  - id: A1\n    action: placeholder read\n    expected: [S01]\n    cohort: P0\n'
            '    windows:\n      - {start: "%s", end: "%s", agentId: target-01}\n'
            '  - id: A2\n    action: placeholder miss\n    expected: [S04]\n    cohort: P0\n'
            '    windows:\n      - {start: "%s", end: "%s", agentId: target-01}\n'
            % (time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now - 30)),
               time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now + 30)),
               time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now - 30)),
               time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now + 30))),
            encoding='utf-8',
        )
        self.app = App(ROOT / 'runtime', {
            'database': str(Path(self.tmp.name) / 'db'),
            'operators': {'alice': 'alice-key'},
            'referees': {'judge': 'judge-key'},
            'sources': {'source': 'source-key'},
            'drillFile': str(drill),
            'version': 'test-observe',
        })
        self.server = __import__('http.server', fromlist=['ThreadingHTTPServer']).ThreadingHTTPServer(('127.0.0.1', 0), self.app.handler())
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = 'http://127.0.0.1:%d' % self.server.server_port
        self.app.store.heartbeat('source', {'host': 'private-host', 'fileWatchScope': ['/private/.ssh'], 'drop': 0, 'agentRoutes': ['target-01']})
        self.app.store.ingest('source', [{
            'id': 'secret-read', 'time': time.time(), 'workload': 'private-agent', 'pid': 7,
            'kind': 'file', 'identity': {'basis': 'registered'}, 'agentId': 'target-01',
            'path': '/var/PLACEHOLDER_SECRET/.env', 'access': 'read_open', 'result': 'success',
        }])

    def tearDown(self):
        self.app.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def req(self, path, body=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(self.origin + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response), response.headers.get('Connection')
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc), exc.headers.get('Connection')

    def test_public_overview_hides_host_and_path(self):
        status, body, connection = self.req('/runtime/api/v2/overview')
        self.assertEqual(status, 200)
        self.assertEqual(connection, 'close')
        raw = json.dumps(body, ensure_ascii=False)
        self.assertNotIn('private-host', raw)
        self.assertNotIn('PLACEHOLDER_SECRET', raw)
        self.assertNotIn('/var/', raw)
        self.assertEqual(body['alerts']['total'], 1)
        self.assertEqual(body['alerts']['high'], 1)
        self.assertTrue(body['publicSummary'])
        self.assertFalse(body['kernelBlock'])
        self.assertEqual(body['asi'][4]['level'], 'full')
        self.assertNotIn('id', body['agentRows'][0])
        self.assertTrue(body['agentRows'][0]['alias'].startswith('ag-'))

    def test_operator_chain_and_anonymous_replay_only(self):
        self.app.store.ingest('source', [
            {'id': 'tool-1', 'time': time.time(), 'workload': 'gateway:target-01', 'kind': 'tool', 'operation': 'TOOL_CALL', 'identity': {'basis': 'gateway route'}, 'agentId': 'target-01', 'chainId': 'chain-live', 'toolCallId': 'call-1', 'toolName': 'terminal', 'argsEntities': {'commands': ['echo PLACEHOLDER_CHAIN']}, 'pid': 0, 'result': 'success'},
            {'id': 'proc-1', 'time': time.time() + 0.2, 'workload': 'private-agent', 'kind': 'process', 'operation': 'EXEC', 'identity': {'basis': 'registered'}, 'agentId': 'target-01', 'chainId': 'chain-live', 'command': 'echo PLACEHOLDER_CHAIN', 'pid': 9, 'result': 'success'},
        ])
        status, body, _conn = self.req('/runtime/api/v2/chains/chain-live')
        self.assertEqual(status, 403)
        self.assertNotIn('PLACEHOLDER_CHAIN', json.dumps(body))
        status, replay, _conn = self.req('/runtime/api/v2/chains/ch-7f3a')
        self.assertEqual(status, 200)
        self.assertEqual(replay['dataset'], 'replay')
        self.assertEqual(replay['chainId'], 'ch-7f3a')
        self.assertNotIn('private-host', json.dumps(replay))
        status, live, _conn = self.req('/runtime/api/v2/chains/chain-live', token='alice-key')
        self.assertEqual(status, 200)
        self.assertEqual(live['dataset'], 'live')
        self.assertIn('PLACEHOLDER_CHAIN', json.dumps(live))
        self.assertTrue(any(item['lane'] == 'decision' for item in live['events']))
        self.assertTrue(any(item['lane'] == 'behavior' for item in live['events']))

    def test_referee_is_read_only(self):
        status, body, _conn = self.req('/runtime/api/v2/overview', token='judge-key')
        self.assertEqual(status, 200)
        self.assertIn('target-01', json.dumps(body))
        aid = self.app.store.listing({})['items'][0]['id']
        status, denied, _conn = self.req('/runtime/api/alerts/%s/review' % aid, {'action': 'dismiss', 'reason': 'nope', 'revision': 1}, 'judge-key')
        self.assertEqual(status, 403)
        self.assertIn('只读', denied['error'])
        status, me, _conn = self.req('/runtime/api/me', token='judge-key')
        self.assertEqual(me['role'], 'referee')

    def test_rules_gain_asi_without_dropping_intelligence(self):
        status, body, _conn = self.req('/runtime/api/rules')
        self.assertEqual(status, 200)
        self.assertEqual(body['intelligence'], [])
        s03 = next(item for item in body['items'] if item['id'] == 'S03')
        self.assertIn('ASI05', s03['asi'])
        self.assertIn('enabled', s03)
        s15 = next(item for item in body['items'] if item['id'] == 'S15')
        self.assertIs(s15['enabled'], False)

    def test_drill_scores_and_stays_hidden_for_anonymous(self):
        status, hidden, _conn = self.req('/runtime/api/v2/drill')
        self.assertEqual(status, 200)
        self.assertTrue(hidden['hidden'])
        self.assertEqual(hidden['rows'], [])
        status, board, _conn = self.req('/runtime/api/v2/drill', token='alice-key')
        self.assertFalse(board['hidden'])
        by_id = {row['id']: row for row in board['rows']}
        self.assertEqual(by_id['A1']['result'], '1/1')
        self.assertEqual(by_id['A1']['tone'], 'success')
        self.assertEqual(by_id['A2']['result'], '0/1')
        self.assertEqual(by_id['A2']['tone'], 'danger')
        self.assertTrue(board['rates']['p0']['belowTarget'])
        self.assertNotIn('PLACEHOLDER_SECRET', json.dumps(hidden))

    def test_heartbeat_still_closes_and_sse_does_not(self):
        status, body, connection = self.req('/runtime/api/heartbeat', {'layers': {'process': 'active'}}, 'source-key')
        self.assertEqual(status, 200)
        self.assertEqual(body['ok'], True)
        self.assertEqual(connection, 'close')
        status, listing, _conn = self.req('/runtime/api/alerts')
        self.assertEqual(status, 200)
        self.assertTrue(listing['publicSummary'])
        self.assertNotIn('PLACEHOLDER_SECRET', json.dumps(listing))
        conn = HTTPConnection('127.0.0.1', self.server.server_port, timeout=4)
        conn.request('GET', '/runtime/api/v2/stream')
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn('text/event-stream', response.getheader('Content-Type'))
        self.assertEqual(response.getheader('Transfer-Encoding'), 'chunked')
        self.assertNotEqual((response.getheader('Connection') or '').lower(), 'close')
        buf = b''
        deadline = time.time() + 4
        while b'secret-read' not in buf and b'PLACEHOLDER_SECRET' not in buf and time.time() < deadline:
            self.app.store.ingest('source', [{
                'id': 'secret-read-2', 'time': time.time(), 'workload': 'private-agent', 'pid': 8,
                'kind': 'file', 'identity': {'basis': 'registered'}, 'agentId': 'target-01',
                'path': '/var/PLACEHOLDER_SECRET/.env', 'access': 'read_open', 'result': 'success',
            }])
            chunk = response.read(512)
            if not chunk:
                break
            buf += chunk
            if b'alert' in buf and b'S01' in buf:
                break
        text = buf.decode('utf-8', 'replace')
        self.assertIn('S01', text)
        self.assertNotIn('PLACEHOLDER_SECRET', text)
        self.assertNotIn('private-host', text)
        conn.close()

    def test_phase_filter_is_operator_only(self):
        status, public, _conn = self.req('/runtime/api/v2/alerts?phase=semantic&agentId=target-01')
        self.assertEqual(status, 200)
        self.assertGreaterEqual(public['total'], 1)
        self.assertNotIn('target-01', json.dumps(public))
        status, private, _conn = self.req('/runtime/api/v2/alerts?phase=no-such-phase', token='alice-key')
        self.assertEqual(private['total'], 0)

    def test_tool_baseline_and_index(self):
        self.app.store.ingest('source', [{
            'id': 'tool-base', 'time': time.time(), 'workload': 'gateway:target-01', 'kind': 'tool',
            'operation': 'TOOL_CALL', 'identity': {'basis': 'gateway route'}, 'agentId': 'target-01',
            'chainId': 'base-chain', 'toolName': 'status', 'pid': 0, 'result': 'success',
        }])
        with self.app.store.db(write=False) as cursor:
            names = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")]
            count = cursor.execute('SELECT calls FROM tool_baselines WHERE agent_id=? AND tool_name=?', ('target-01', 'status')).fetchone()[0]
        self.assertIn('ev_chain_time', names)
        self.assertEqual(count, 1)
        status, body, _conn = self.req('/runtime/api/v2/agents/target-01', token='alice-key')
        self.assertEqual(status, 200)
        self.assertEqual(body['id'], 'target-01')
        self.assertIn('status', body['toolBaseline']['names'])
        status, public, _conn = self.req('/runtime/api/v2/agents/target-01')
        self.assertEqual(status, 200)
        self.assertNotIn('id', public)
        self.assertNotIn('names', public['toolBaseline'])


if __name__ == '__main__':
    unittest.main()
