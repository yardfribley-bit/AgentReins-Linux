"""Regression cases for actual missing-feedback and missing-exit incidents."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'console'))
import cockpit_data
import history_store
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
import tls_relay


class ObservationRegressionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = patch.object(history_store, 'DB', str(Path(self.directory.name) / 'history.sqlite3'))
        self.database.start()
        history_store.init()
        self.sequence = 0

    def tearDown(self):
        self.database.stop()
        self.directory.cleanup()

    def insert(self, when, operation, resource, evidence=None, category='semantic', pid=10, container='sandbox'):
        self.sequence += 1
        c = history_store.connect()
        c.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                  (str(self.sequence), when, category, operation, pid, 1, container,
                   '/usr/bin/nmap', resource, 'CAPTURED', 'regression fixture', json.dumps(evidence or {})))
        c.commit()
        c.close()

    def test_second_precision_execution_matches_millisecond_model_call(self):
        rid = 'model-request-test'
        self.insert('2026-10-15T23:32:15.030000+08:00', 'MODEL_REQUEST', json.dumps({'messages': []}), {'requestId': rid})
        self.insert('2026-10-15T23:32:15.031000+08:00', 'MODEL_RESPONSE', json.dumps({'choices': []}), {'requestId': rid})
        call = {'id': 'call-test', 'function': {'name': 'terminal', 'arguments': json.dumps({'input': 'nmap -sV example.org'})}}
        self.insert('2026-10-15T23:32:15.032000+08:00', 'TOOL_CALL', json.dumps(call), {'requestId': rid})
        exchange = cockpit_data.model_for_command('/usr/bin/nmap -sV example.org', '2026-10-15T23:32:15+0800')
        self.assertEqual(exchange['id'], rid)
        self.assertIsNotNone(exchange['response'])
        self.assertIsNone(cockpit_data.model_for_command('/usr/bin/nmap -sV unrelated.example', '2026-10-15T23:32:15+0800'))
        self.assertIsNone(cockpit_data.model_for_command('/usr/bin/nmap -sV example.org', '2026-10-16T23:32:15+0800'))

    def test_relay_resets_connection_timeout_before_pumping(self):
        from unittest.mock import MagicMock
        client, remote = MagicMock(), MagicMock()
        with patch.object(tls_relay.socket, 'create_connection', return_value=remote) as connect, patch.object(tls_relay.threading, 'Thread'):
            tls_relay.handle(client, 'provider.example', 443, 660)
        connect.assert_called_once_with(('provider.example', 443), timeout=15)
        remote.settimeout.assert_called_once_with(660)
        client.settimeout.assert_called_once_with(660)

    def test_exit_retained_after_network_event_limit_and_scoped_to_container(self):
        self.insert('2026-10-15T10:00:00+08:00', 'EXEC', 'nmap example.org', category='kernel')
        for i in range(510):
            self.insert(f'2026-10-15T10:00:01.{i:06d}+08:00', 'AUDIT_SENDTO', 'example.org:443', category='network')
        self.insert('2026-10-15T10:15:00+08:00', 'EXIT', '', {'exit_code': 0}, category='kernel')
        self.insert('2026-10-15T10:16:00+08:00', 'EXIT', '', {'exit_code': 99}, category='kernel', container='other')
        timeline = history_store.process_timeline({'pid': ['10'], 'container': ['sandbox'], 'time': ['2026-10-15T10:00:00+08:00']})
        exits = [e for e in timeline['events'] if e['operation'] == 'EXIT']
        self.assertEqual(len(exits), 1)
        self.assertEqual(exits[0]['state']['exit_code'], 0)


if __name__ == '__main__':
    unittest.main()
