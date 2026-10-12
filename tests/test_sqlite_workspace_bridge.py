import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.core import connect, create_case, digest, import_evidence
from tests.test_recovery_acceptance import sms_database


class SQLiteWorkspaceBridgeTests(unittest.TestCase):
    def test_stdio_query_receipt_pagination_and_case_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / 'cases'
            create_case(workspace, 'one')
            create_case(workspace, 'two')
            source = base / 'source.db'
            sms_database(source, 5)
            before = digest(source)
            with connect(workspace, 'one') as (root, db):
                eid = import_evidence(root, db, source, 'android')[0]
                fid = db.execute('SELECT id FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]

            def call(action, case='one', **values):
                result = subprocess.run(
                    [sys.executable, '-m', 'lawliet_mobile.app_backend'],
                    input=json.dumps({'workspace': str(workspace), 'action': action,
                                      'case': case, **values}),
                    capture_output=True, text=True, check=False)
                data = json.loads(result.stdout)
                self.assertEqual(result.returncode, 0 if data['ok'] else 1)
                return data

            schema = call('sqlite-schema', file_id=fid)
            self.assertTrue(schema['ok'])
            query = call('sqlite-query', file_id=fid, sql='SELECT _id,body FROM sms WHERE _id>=? ORDER BY _id', parameters=[1], row_limit=3)
            self.assertTrue(query['ok'])
            result = query['result']
            self.assertEqual(result['status'], 'complete')
            self.assertTrue(result['truncated'])
            self.assertEqual(result['preview']['columns'], ['_id', 'body'])
            page = call('sqlite-query-result', run_id=result['run_id'], offset=1, limit=1)['result']
            self.assertEqual(page['rows'][0][0], 2)
            self.assertTrue(page['has_more'])
            self.assertFalse(call('sqlite-query-result', case='two', run_id=result['run_id'])['ok'])
            denied = call('sqlite-query', file_id=fid, sql='DELETE FROM sms')['result']
            self.assertEqual(denied['status'], 'failed')
            self.assertIsNone(denied['preview'])
            self.assertFalse(call('sqlite-query', file_id=fid, sql='SELECT 1', row_limit=True)['ok'])
            self.assertEqual(digest(source), before)
