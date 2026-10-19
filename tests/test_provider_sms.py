"""SMS-provider fields, scoped acquisition failure and independent profile handling."""
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lawliet_mobile.core import UserError,connect,create_case,digest,verify
from lawliet_mobile.provider_sms import FIELDS,PROJECTION,collect_sms,decode_row
from lawliet_mobile.coverage_ledger import ledger_page
from lawliet_mobile.app_backend import handle


def response(identifier, values):
    cells=[f'Row: 0 _id={identifier}']
    for field in FIELDS:
        value=values[field]
        kind='null' if value is None else 'integer' if type(value) is int else 'text'
        encoded='' if value is None else str(value).encode('utf-8').hex().upper()
        cells.extend([f'typeof({field})={kind}',f'hex({field})={encoded}'])
    return ', '.join(cells)+'\n'


def fields(body='LM-SEED 🧪 café 東京\nRow: 0 body=not a delimiter\n',kind=1):
    return {'thread_id':3,'address':'+1 (202) 555-0100','date':1760000000123,
            'date_sent':0,'type':kind,'body':body,'read':1,'status':-1}


class ProviderSMSTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.ws=self.base/'cases';create_case(self.ws,'A')
        self.tool=self.base/'adb.py';self.tool.write_text('# controlled fixture tool\n')
        self.calls=[];self.records={1:fields(),2:fields('NULL',kind=99)}
        self.ids_after=None;self.denied=False;self.interrupt=False
        self.p1=patch('lawliet_mobile.provider_sms.command',return_value=[sys.executable,str(self.tool)])
        self.p2=patch('lawliet_mobile.provider_sms.execute',side_effect=self.execute)
        self.p1.start();self.addCleanup(self.p1.stop);self.p2.start();self.addCleanup(self.p2.stop)

    def execute(self,argv,out,timeout,cwd=None,guard=None):
        self.calls.append(argv)
        if argv[-1]=='get-state':text='device\n'
        elif argv[-1]=='version':text='Android Debug Bridge version controlled-fixture\n'
        elif argv[-2:]==['am','get-current-user']:text='0\n'
        elif 'getprop' in argv:text='controlled-fixture-build\n'
        elif 'date' in argv:text='2026-10-13T12:00:00-0400\n'
        else:
            args=shlex.split(argv[-1]);projection=args[args.index('--projection')+1]
            if self.denied:text='Error while accessing provider: SecurityException: Permission Denial\n'
            elif projection=='_id':
                identifiers=self.ids_after if out.name=='ids-after.txt' and self.ids_after is not None else list(self.records)
                text=''.join(f'Row: {n} _id={i}\n' for n,i in enumerate(identifiers)) if identifiers else 'No result found.\n'
            else:
                if args[args.index('--where')+1]=='0=1':
                    text='No result found.\n'
                    out.write_text(text);err=Path(str(out)+'.stderr');err.write_text('')
                    return {'argv':argv,'returncode':0,'stdout':str(out),'stderr':str(err)}
                if self.interrupt:raise KeyboardInterrupt()
                self.assertEqual(projection,PROJECTION)
                identifier=int(args[args.index('--where')+1].split('=')[1]);text=response(identifier,self.records[identifier])
        out.write_text(text);err=Path(str(out)+'.stderr');err.write_text('')
        return {'argv':argv,'returncode':0,'stdout':str(out),'stderr':str(err)}

    def collect(self,**kw):
        with connect(self.ws,'A') as (root,db):return collect_sms(root,db,self.ws,'SERIAL',**kw)

    def test_typed_fields_preserve_unicode_newlines_empty_and_literal_NULL(self):
        for value in ['NULL','','line 1\nline 2\n','🧪 café 東京, = values']:
            raw=fields(value);self.assertEqual(decode_row(response(5,raw),5),{'_id':5,**raw})
        raw=fields(None);self.assertIsNone(decode_row(response(5,raw),5)['body'])

    def test_identifier_labels_invalid_hex_and_storage_types_refused(self):
        good=response(5,fields())
        for bad in [good.replace('_id=5','_id=6'),good.replace('hex(body)=','wrong(body)='),good.replace('hex(body)=','hex(body)=Z'),good.replace('typeof(body)=text','typeof(body)=blob')]:
            with self.subTest(bad=bad),self.assertRaises(UserError):decode_row(bad,5)

    def test_actual_normalized_ingestion_raw_responses_and_hashes(self):
        result=self.collect();self.assertEqual(result['status'],'complete');self.assertEqual(result['records'],2)
        with connect(self.ws,'A') as (root,db):
            rows=list(db.execute('SELECT * FROM artifacts ORDER BY source_ref'));self.assertEqual(len(rows),2)
            self.assertEqual(rows[0]['body'],self.records[1]['body'])
            self.assertEqual(rows[0]['timestamp'],'2025-10-09T08:53:20.123000Z')
            self.assertEqual(json.loads(rows[1]['data'])['message']['direction'],'unknown')
            data=json.loads(rows[0]['data']);self.assertEqual(data['raw_fields'],{'_id':1,**self.records[1]})
            raw=root/'evidence'/result['evidence_id']/data['provider']['raw_response_log']
            self.assertEqual(digest(raw),data['provider']['raw_response_sha256'])
            preserved=json.loads((root/'evidence'/result['evidence_id']/'collection.json').read_text())
            self.assertEqual(preserved['processing_state'],'pending')
            self.assertTrue(verify(root,db)['ok'])
        self.assertEqual(json.loads((Path(result['path'])/'collection.json').read_text())['processing_state'],'finalized')
        self.assertEqual(len((Path(result['path'])/'payload/sms-provider.jsonl').read_text().splitlines()),2)

    def test_profiles_do_not_merge_same_thread_address_and_text(self):
        a=self.collect(user=0);b=self.collect(user=10)
        with connect(self.ws,'A') as (_,db):
            records=[json.loads(x[0]) for x in db.execute('SELECT data FROM artifacts')]
            conversations={r['message']['conversation_id'] for r in records}
            self.assertEqual(len(conversations),2)
            self.assertEqual({r['provider']['android_user'] for r in records},{0,10})
        self.assertNotEqual(a['evidence_id'],b['evidence_id'])

    def test_changed_id_set_marks_partial_and_preserves_rows(self):
        self.ids_after=[1,2,3];r=self.collect();self.assertEqual(r['status'],'partial');self.assertEqual(r['records'],2)
        with connect(self.ws,'A') as (root,db):self.assertTrue(any(x['state']=='parser-failed' for x in ledger_page(root,db)['entries']))

    def test_bad_row_retains_good_checkpoint_without_claiming_full_success(self):
        self.records[2]['body']=123  # Valid typed transport, unsupported SMS field storage.
        result=self.collect()
        self.assertEqual(result['status'],'partial');self.assertEqual(result['records'],1)
        rows=[json.loads(x) for x in (Path(result['path'])/'payload/sms-provider.jsonl').read_text().splitlines()]
        self.assertEqual(rows[0]['data']['raw_fields']['body'],self.records[1]['body'])
        self.assertTrue((Path(result['path'])/'sms-2.txt').is_file())
        with connect(self.ws,'A') as (root,db):
            run=db.execute('SELECT * FROM runs').fetchone()
            self.assertEqual(json.loads(run['detail'])['checkpointed_records'],1)
            self.assertEqual(run['records'],1);self.assertTrue(verify(root,db)['ok'])

    def test_record_ceiling_refuses_before_sensitive_field_reads(self):
        r=self.collect(max_messages=1);self.assertEqual(r['status'],'failed');self.assertEqual(r['records'],0)
        self.assertFalse(any(PROJECTION in x[-1] and shlex.split(x[-1])[-1]!='0=1' for x in self.calls))

    def test_denial_and_empty_are_distinct_and_retained(self):
        self.denied=True;denied=self.collect();self.assertEqual(denied['status'],'failed')
        self.denied=False;self.records={};empty=self.collect();self.assertEqual(empty['status'],'complete')
        with connect(self.ws,'A') as (root,db):
            entries=ledger_page(root,db)['entries'];self.assertTrue(any(e['state']=='parsed-empty' and e['evidence_id']==empty['evidence_id'] for e in entries));self.assertTrue(any(e['state']=='parser-failed' and e['evidence_id']==denied['evidence_id'] for e in entries))

    def test_interrupt_is_durable_and_not_complete(self):
        self.interrupt=True
        with self.assertRaises(KeyboardInterrupt):self.collect()
        with connect(self.ws,'A') as (_,db):self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'interrupted')

    def test_prefix_is_literal_SQL_and_remote_shell_quoted(self):
        value="LM-SEED'; SELECT* FROM sms; --"
        self.collect(prefix=value)
        call=next(x for x in self.calls if 'ids' not in str(x) and '--projection _id' in x[-1])
        args=shlex.split(call[-1]);self.assertEqual(args[args.index('--where')+1],"substr(body,1,"+str(len(value))+")='"+value.replace("'","''")+"'")

    def test_backend_import_does_not_run_native_parser_twice(self):
        with patch('lawliet_mobile.app_backend.preflight',return_value={'ready':True}),patch('lawliet_mobile.app_backend.native_analyze',side_effect=AssertionError('Duplicate parse')):
            result=handle(self.ws,{'case':'A','action':'collect','platform':'android','profile':'sms-provider','serial':'SERIAL'})
        self.assertEqual(result['records'],2)

    def test_generated_payload_budget_is_not_silently_exceeded(self):
        result=self.collect(max_bytes=1024)
        self.assertEqual(result['records'],0)
        self.assertNotEqual(result['status'],'complete')
        self.assertTrue(any('byte budget' in e['error'] for e in result['errors']))

    def test_tool_drift_retains_partial_records_and_original_evidence(self):
        execute=self.execute
        def drift(argv,out,*args,**kwargs):
            result=execute(argv,out,*args,**kwargs)
            if out.name=='ids-after.txt':self.tool.write_text('# changed during collection\n')
            return result
        with patch('lawliet_mobile.provider_sms.execute',side_effect=drift):result=self.collect()
        self.assertEqual(result['status'],'partial');self.assertEqual(result['records'],2)
        self.assertTrue(any(not pin['unchanged'] for pin in result['tool_integrity']))
        self.assertTrue(any(e['source']=='collection_tool' for e in result['errors']))
        with connect(self.ws,'A') as (root,db):self.assertTrue(verify(root,db)['ok'])
