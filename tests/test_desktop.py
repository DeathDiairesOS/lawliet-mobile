import json
import tempfile
import unittest
from pathlib import Path

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, connect, create_case, verify
from lawliet_mobile.parsed_import import import_parsed


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.workspace=self.base/'cases'
        create_case(self.workspace,'desktop')
        self.source=self.base/'messages.jsonl'
        self.record={'id':'original-id','evidence_id':'original-evidence','category':'messages','timestamp':'2026-10-10T12:00:00Z','title':'Test','body':'Invoice\n<script>text</script>','source_sha256':'claimed-source-hash','data':{'message':{'app':'imessage','conversation':'chat:1','conversation_id':'old-conversation','sender':'Alex'}}}
        self.source.write_text(json.dumps(self.record)+'\n')

    def call(self, action, **kwargs):
        return handle(self.workspace, {'action':action,'case':'desktop',**kwargs})

    def test_import_query_export_and_deduplicate(self):
        result=self.call('import',path=str(self.source),format='jsonl')
        self.assertEqual(result['records'],1)
        self.assertEqual(self.call('import',path=str(self.source),format='jsonl')['status'],'already_imported')
        self.assertEqual(self.call('cases')[0]['records'],1)
        source=self.call('overview')['sources'][0]
        rows=self.call('records',evidence=source['evidence'],parser=source['parser'],query='invoice')['records']
        self.assertEqual(rows[0]['body'],self.record['body'])
        self.assertNotEqual(rows[0]['source_sha256'],'claimed-source-hash')
        self.assertEqual(rows[0]['data']['_imported_record']['source_sha256'],'claimed-source-hash')
        self.assertNotEqual(rows[0]['data']['message']['conversation_id'],'old-conversation')
        self.assertEqual(len(self.call('conversations',evidence=source['evidence'])),1)
        out=self.base/'export.jsonl'
        self.assertEqual(self.call('export',path=str(out),query='invoice')['records'],1)
        self.assertEqual(json.loads(out.read_text())['body'],self.record['body'])
        self.assertTrue(self.call('verify')['ok'])

    def test_failed_import_retains_source_without_partial_rows(self):
        self.source.write_text(json.dumps(self.record)+'\nnot json\n')
        with self.assertRaisesRegex(UserError,'original report retained'):
            self.call('import',path=str(self.source),format='jsonl')
        with connect(self.workspace,'desktop') as (root,db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'failed')
            self.assertTrue(verify(root,db)['ok'])

    def test_leapp_tsv_message_mapping_and_unknown_schema(self):
        p=self.base/'SMS.tsv'
        p.write_text('Message Timestamp\tMessage\tService\tMessage Direction\tMessage Row ID\tChat ID\tSender\n2026-10-10 12:00:00+00:00\tHello\tiMessage\tIncoming\t42\t7\tAlex\n')
        self.call('import',path=str(p),format='tsv')
        self.assertEqual(self.call('records',app='imessage')['records'][0]['body'],'Hello')
        p=self.base/'Other.tsv';p.write_text('A\tB\nx\ty\n')
        self.call('import',path=str(p),format='tsv')
        self.assertEqual(len(self.call('records',category='external')['records']),1)

    def test_export_cannot_overwrite_evidence_and_invalid_case_rejected(self):
        self.call('import',path=str(self.source),format='jsonl')
        with self.assertRaises(UserError): self.call('export',path=str(self.source))
        with self.assertRaises(UserError): handle(self.workspace,{'action':'create','id':'../bad'})
