import base64
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import unittest
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
if '\\WindowsApps\\' in PY or not Path(PY).is_file():
    bundled = Path.home() / '.cache' / 'codex-runtimes' / 'codex-primary-runtime' / 'dependencies' / 'python' / 'python.exe'
    if bundled.is_file():
        PY = str(bundled)


class PlatformTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keep the disposable test database inside the workspace. This also
        # lets the spawned server read it in restricted Windows environments
        # where the system temp directory may not be shared with child processes.
        cls.tmp = ROOT / 'work' / 'test-runs' / f'secops-test-{uuid.uuid4().hex}'
        cls.tmp.mkdir(parents=True, exist_ok=False)
        cls.log_path = cls.tmp / 'server.log'
        cls.log = cls.log_path.open('w', encoding='utf-8')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = str(sock.getsockname()[1])
        env = os.environ.copy()
        env.update(SECOPS_DB=str(cls.tmp / 'test.db'), PORT=cls.port)
        cls.proc = subprocess.Popen([PY, str(ROOT / 'app' / 'server.py')], cwd=ROOT, env=env,
                                    stdout=cls.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                urllib.request.urlopen(f'http://127.0.0.1:{cls.port}/health', timeout=1)
                break
            except Exception:
                time.sleep(.1)
        else:
            cls.log.flush()
            details = cls.log_path.read_text(encoding='utf-8', errors='replace')
            raise RuntimeError(f'server did not start; output from {cls.log_path}:\n{details}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.proc.terminate()
            cls.proc.wait(timeout=8)
        finally:
            cls.log.close()
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def req(self, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=data,
                                     headers={'Content-Type': 'application/json'},
                                     method='GET' if body is None else 'POST')
        with urllib.request.urlopen(req, timeout=180) as response:
            return json.loads(response.read())

    def req_raw(self, path, data, content_type='application/json'):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=data,
                                     headers={'Content-Type': content_type}, method='POST')
        try:
            response = urllib.request.urlopen(req, timeout=180)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def evt(self, event_id, minute=0, device='cam-1', source='cctv', zone='Gate-A', vehicle='DXB123'):
        from datetime import datetime, timedelta, timezone
        dt = datetime(2026, 1, 15, 8, tzinfo=timezone.utc) + timedelta(minutes=minute)
        return {'event_id': event_id, 'source_type': source, 'device_id': device,
                'event_type': 'vehicle_detected', 'occurred_at': dt.isoformat(),
                'received_at': dt.isoformat(),
                'location': {'latitude': 25.2, 'longitude': 55.27, 'zone': zone},
                'severity': 'high', 'confidence': .9, 'payload': {'plate': vehicle}}

    def test_bulk_generated_50k_and_server_paging(self):
        from importlib.util import module_from_spec, spec_from_file_location
        spec = spec_from_file_location('generator', ROOT / 'tools' / 'generate.py')
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        batch = module.generate(50000, seed=7, adversarial=False)
        baseline = self.req('/health')['events']
        result = self.req('/ingest', batch)
        self.assertEqual(result['accepted'], 50000)
        self.assertEqual(self.req('/health')['events'], baseline + 50000)
        self.assertEqual(self.req('/summary')['events'], baseline + 50000)
        page = self.req('/events?page=1&limit=25')
        self.assertEqual(len(page['events']), 25)
        self.assertEqual(page['count'], baseline + 50000)

    def test_generated_truth_labels_are_separate_and_respected(self):
        from importlib.util import module_from_spec, spec_from_file_location
        spec = spec_from_file_location('generator', ROOT / 'tools' / 'generate.py')
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        rows, truth = module.generate_fixture(1000, seed=19, adversarial=True, id_prefix='truth-')
        self.assertTrue(truth['expected_groups'])
        self.assertTrue(truth['must_not_link_pairs'])
        self.assertFalse(any('expected_groups' in row or 'must_not_link_pairs' in row for row in rows))
        self.assertEqual(self.req('/ingest', rows)['accepted'], 1000)
        with sqlite3.connect(self.tmp / 'test.db') as db:
            membership = dict(db.execute('SELECT event_id,incident_id FROM incident_events WHERE event_id LIKE "truth-%"'))
            issues = {row[0] for row in db.execute('SELECT DISTINCT kind FROM quality WHERE event_id LIKE "truth-%"')}
        group = truth['expected_groups'][0]
        unrelated = truth['must_not_link_pairs'][0][1]
        self.assertEqual(len({membership[event_id] for event_id in group}), 1)
        self.assertNotEqual(membership[group[0]], membership[unrelated])
        required = {'malformed_timestamp', 'incomplete', 'invalid_location', 'invalid_confidence',
                    'invalid_payload', 'delayed', 'device_health', 'event_spike', 'out_of_order',
                    'repeated_device', 'conflicting_location', 'uncorrelatable'}
        self.assertTrue(required <= issues)
        for left, right in truth['must_not_link_pairs']:
            if left.startswith('truth-') and left.endswith('0000010'):
                self.assertNotEqual(membership[left], membership[right])
        incident_page = self.req('/incidents?source=cctv&page=1&limit=5')
        self.assertLessEqual(len(incident_page['incidents']), 5)
        briefing = self.req('/briefing')
        self.assertTrue(briefing['event_references'])

    def test_ingest_preserves_duplicates_conflicts_and_relations(self):
        a = self.evt('a')
        b = self.evt('b', 5, 'radar-1', 'radar')
        c = self.evt('c', 6, 'camera-z', 'cctv', 'Remote', 'OTHER')
        invalid = self.evt('bad')
        invalid['confidence'] = .1
        invalid['received_at'] = 'nope'
        result = self.req('/ingest', [a, b, c, invalid, a])
        self.assertEqual(result['accepted'], 4)
        self.assertEqual(result['rejected'], 1)
        with sqlite3.connect(self.tmp / 'test.db') as db:
            membership = dict(db.execute('SELECT event_id,incident_id FROM incident_events WHERE event_id IN ("a","b","c")'))
            canonical = json.loads(db.execute('SELECT raw FROM events WHERE event_id="a"').fetchone()[0])
        self.assertEqual(membership['a'], membership['b'])
        self.assertNotEqual(membership['a'], membership['c'])
        self.assertEqual(canonical, a)
        issues = self.req('/quality-issues?limit=500')['issues']
        self.assertTrue(any(issue['kind'] == 'low_confidence' for issue in issues))
        self.assertTrue(any(issue['kind'] == 'malformed_timestamp' for issue in issues))
        self.assertTrue(any(issue['kind'] == 'duplicate' for issue in issues))
        conflict = dict(a)
        conflict['payload'] = {'plate': 'DXB123', 'changed': True}
        reply = self.req('/ingest', [conflict])
        self.assertEqual(reply['conflicts'], 1)
        records = self.req('/ingest-records?event_id=a')['records']
        self.assertEqual(len(records), 3)
        self.assertEqual({row['disposition'] for row in records}, {'accepted', 'duplicate', 'conflict'})
        self.assertTrue(any(issue['kind'] == 'conflicting_duplicate' for issue in self.req('/quality-issues?limit=500')['issues']))
        source_record = self.evt('placeholder', device='source-camera')
        source_record.pop('event_id')
        source_record['source_id'] = 'vendor-event-77'
        self.assertEqual(self.req('/ingest', [source_record])['accepted'], 1)
        source_view = self.req('/events?device=source-camera')['events'][0]
        self.assertEqual(source_view['event_id'], 'vendor-event-77')
        self.assertEqual(source_view['source_event_id'], 'vendor-event-77')
        self.req('/ingest', [42])
        self.assertTrue(any(row['disposition'] == 'invalid' and row['raw'] == 42
                            for row in self.req('/ingest-records?limit=500')['records']))
        status, malformed = self.req_raw('/ingest', b'{"event_id":"truncated",')
        self.assertEqual(status, 400)
        self.assertTrue(malformed['audit_recorded'])
        invalid_records = self.req('/ingest-records?disposition=invalid&limit=500')['records']
        raw_request = next(row['raw'] for row in invalid_records if row['submission_id'] == malformed['submission_id'])
        self.assertEqual(base64.b64decode(raw_request['raw_body_base64']), b'{"event_id":"truncated",')
        jsonl_line = {'line_number': 4, 'raw_line': '{"event_id":', 'parse_error': 'Invalid JSON on this line.'}
        self.req('/ingest', [{'$raw_invalid_jsonl_line': jsonl_line}])
        self.assertTrue(any(row['raw'] == jsonl_line for row in self.req('/ingest-records?disposition=invalid&limit=500')['records']))
        self.assertEqual(self.req('/health')['status'], 'ok')

    def test_event_filter_returns_original_source_record(self):
        source = self.evt('raw-source')
        source['vendor_extension'] = {'camera_channel': 7}
        self.req('/ingest', [source])
        result = self.req('/events?event_id=raw-source&include_raw=1')
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['events'][0]['original']['vendor_extension'], {'camera_channel': 7})

    def test_out_of_order_and_spike_are_explained(self):
        from datetime import datetime, timedelta, timezone
        rows = []
        base = datetime(2026, 1, 15, 8, tzinfo=timezone.utc)
        for i in range(10):
            row = self.evt(f'spike-{i}', 0, 'radar-burst', 'radar', 'Gate-A', f'PLATE{i}')
            row['occurred_at'] = (base + timedelta(seconds=20 * i)).isoformat()
            row['received_at'] = (base + timedelta(seconds=20 * i)).isoformat()
            rows.append(row)
        rows[-1]['occurred_at'] = (base - timedelta(minutes=1)).isoformat()
        self.req('/ingest', rows)
        issues = self.req('/quality-issues?limit=500')['issues']
        self.assertTrue(any(issue['kind'] == 'out_of_order' for issue in issues))
        self.assertTrue(any(issue['kind'] == 'event_spike' for issue in issues))

    def test_assistant_lists_evidence_and_requires_confirmation(self):
        self.req('/ingest', [self.evt('asst-a'), self.evt('asst-b', 4, 'radar-9', 'radar')])
        listed = self.req('/assistant/query', {'query': 'Show unresolved high-severity incidents near Gate-A'})
        self.assertIn('answer', listed)
        self.assertTrue(listed['incident_ids'])
        self.assertTrue(listed['evidence_event_ids'])
        self.assertFalse(listed['requires_confirmation'])
        incident_id = listed['incident_ids'][0]
        evidence = self.req('/assistant/query', {'query': f'What evidence supports this alert {incident_id}?'})
        self.assertIn(incident_id, evidence['incident_ids'])
        self.assertTrue(set(evidence['evidence_event_ids']))
        close = self.req('/assistant/query', {'query': f'Close {incident_id}'})
        self.assertTrue(close['requires_confirmation'])
        self.assertTrue(close['pending_id'])
        detail = self.req(f'/incidents/{incident_id}')
        self.assertEqual(detail['status'], 'open')
        self.assertEqual(detail['timeline'], detail['related_events'])
        self.assertTrue(detail['event_ids'])
        self.assertEqual(detail['source_event_ids'], [event['source_event_id'] for event in detail['events']])
        self.assertIn('conflicts', detail)
        self.assertIn('missing_information', detail)
        self.assertIn('next_actions', detail)
        confirmed = self.req('/assistant/confirm', {'pending_id': close['pending_id'], 'confirmed': True})
        self.assertEqual(confirmed['result']['status'], 'closed')
        history = self.req('/assistant/history')
        self.assertGreaterEqual(len(history['turns']), 6)
        self.req('/ingest', [self.evt('asst-c', 10, 'cam-2', 'cctv', 'Gate-B', 'OTHER-77')])
        briefing = self.req('/assistant/query', {'query': 'Prepare a briefing for the current shift'})
        self.assertTrue(briefing['evidence_event_ids'] or briefing['incident_ids'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

