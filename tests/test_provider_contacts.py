import json
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.core import create_case,connect,verify,select_artifacts,UserError
from lawliet_mobile.provider_contacts import collect_contacts,ids_from_output,field_from_output
from lawliet_mobile.parsers import native_analyze


class ProviderContactTests(unittest.TestCase):
    def test_response_framing_preserves_punctuation_newlines_and_rejects_errors(self):
        self.assertEqual(ids_from_output('Row: 0 _id=7\nRow: 1 _id=9\n'),[7,9])
        self.assertEqual(ids_from_output('No result found.\n'),[])
        value='A, data1=B\nRow: 1 data1=literal\n'
        self.assertEqual(field_from_output('Row: 0 data1='+value+'\n','data1'),value)
        for raw in ['java.lang.SecurityException: Denied\n','Row: 1 _id=7\n','Row: 0 _id=7\nRow: 1 _id=7\n','']:
            with self.assertRaises(UserError):ids_from_output(raw)
        with self.assertRaises(UserError):field_from_output('Row: 0 data1=NULL\n','data1')

    def test_collection_imports_derived_vcard_and_raw_provenance(self):
        self.collect_test()

    def test_denial_retains_evidence_without_contact_records(self):
        self.collect_test(denied=True)

    def test_live_id_change_marks_partial(self):
        self.collect_test(changed=True)

    def collect_test(self,denied=False,changed=False):
        with tempfile.TemporaryDirectory() as tmp:
            ws=Path(tmp)/'cases';create_case(ws,'qa');commands=[];id_queries=0
            def fake(argv,output,timeout,**kwargs):
                nonlocal id_queries
                commands.append(argv);text='device\n'
                if argv[-1]!='get-state':
                    args=shlex.split(argv[-1]);column=args[args.index('--projection')+1]
                    where=args[args.index('--where')+1] if '--where' in args else None
                    if denied:text='Error while accessing provider\njava.lang.SecurityException\n'
                    elif column=='_id' and where is None:
                        id_queries+=1;text='Row: 0 _id=7\n'
                        if changed and id_queries==2:text+='Row: 1 _id=8\n'
                    elif column=='display_name':text='Row: 0 display_name=Fixture, Contact\nsecond line\n'
                    elif column=='_id':text='Row: 0 _id=11\n' if 'phone_v2' in where else 'No result found.\n'
                    elif column=='data1':text='Row: 0 data1=+12025550100\n'
                    else:raise AssertionError(args)
                output.write_text(text);error=Path(str(output)+'.stderr');error.write_text('')
                return dict(argv=argv,returncode=0,stdout=str(output),stderr=str(error))
            with connect(ws,'qa') as (root,db),patch('lawliet_mobile.provider_contacts.command',return_value=['adb']),patch('lawliet_mobile.provider_contacts.execute',side_effect=fake):
                result=collect_contacts(root,db,ws,'SERIAL')
                self.assertEqual(result['status'],'failed' if denied else 'partial' if changed else 'complete')
                self.assertTrue(result['evidence_id']);self.assertTrue(verify(root,db)['ok'])
                native_analyze(root,db,result['evidence_id'])
                rows=select_artifacts(db,category='contacts')
                self.assertEqual(len(rows),0 if denied else 1)
                if rows:self.assertEqual(rows[0]['title'],'Fixture, Contact\nsecond line')
                manifest=json.loads((Path(result['path'])/'collection.json').read_text())
                self.assertIn('not a device-created backup',manifest['derivation'])
                self.assertTrue(manifest['log_hashes'])
                self.assertFalse(any(' grant ' in ' '.join(c) or ' install ' in ' '.join(c) for c in commands))
