"""Small fixed XML controls scored against declared values, not phone completeness."""
import json
import tempfile
import unittest
import re
from xml.parsers import expat
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect,create_case,digest,verify
from lawliet_mobile.xml_backup import xml_backup_records


@unittest.skipUnless(tuple(map(int,re.findall(r'\d+',expat.EXPAT_VERSION)[:3])) >= (2,7,2), 'XML decoding requires Expat >= 2.7.2')
class XMLBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')

    def import_xml(self,name,text):
        source=self.base/name;source.write_text(text);checksum=digest(source)
        result=handle(self.ws,{'action':'import-evidence','case':'A','path':str(source)})
        with connect(self.ws,'A') as (root,db):
            rows=[dict(r) for r in db.execute('SELECT * FROM artifacts WHERE evidence_id=?',(result['evidence_id'],))]
            run=db.execute('SELECT * FROM runs WHERE evidence_id=?',(result['evidence_id'],)).fetchone()
            detail=json.loads(run['detail']);self.assertTrue(verify(root,db)['ok'])
        self.assertEqual(digest(source),checksum)
        return result,rows,detail

    def test_exact_unicode_raw_fields_time_and_export_scope_separation(self):
        text='<smses count="2"><sms date="1760000000123" date_sent="0" type="1" address="+1 (202) 555-0100" body="🧪 café 東京 &amp; comma, newline&#10;next"/><sms date="1760000000123" type="99" address="+1 (202) 555-0100" body="NULL"/></smses>'
        _,first,_=self.import_xml('profile-0.xml',text);_,second,_=self.import_xml('profile-10.xml',text)
        self.assertEqual(len(first),2);self.assertEqual(len(second),2)
        decoded={json.loads(r['data'])['original']['type']:r for r in first}
        row=decoded['1'];self.assertEqual(row['body'],'🧪 café 東京 & comma, newline\nnext')
        self.assertEqual(row['timestamp'],'2025-10-09T08:53:20.123000Z')
        self.assertEqual(row['timestamp_raw'],'1760000000123')
        data=json.loads(row['data']);self.assertEqual(data['original']['date_sent'],'0')
        self.assertEqual(data['message']['sender'],'+1 (202) 555-0100')
        self.assertEqual(json.loads(decoded['99']['data'])['message']['direction'],'unknown')
        self.assertEqual(decoded['99']['body'],'NULL')
        self.assertNotEqual(data['message']['conversation_id'],json.loads(second[0]['data'])['message']['conversation_id'])

    def test_mms_supported_failed_and_unknown_six_with_scoped_missing_parts(self):
        text='<smses count="2"><mms date="1760000000123" msg_box="5"/><mms date="1760000000123" msg_box="6"><parts><part ct="text/plain" text="Known 🧪 body"/><part ct="image/png" cl="../../foreign.png"/></parts></mms></smses>'
        result,rows,detail=self.import_xml('mms.xml',text)
        self.assertEqual(result['analysis']['status'],'complete');self.assertEqual(len(rows),2)
        data={json.loads(r['data'])['original']['msg_box']:json.loads(r['data']) for r in rows}
        self.assertEqual(data['5']['message']['direction'],'failed');self.assertEqual(data['6']['message']['direction'],'unknown')
        self.assertEqual(data['5']['mms_coverage']['parts_state'],'absent_from_export')
        self.assertEqual(data['6']['mms_coverage']['nontext_parts_without_embedded_payload'],1)
        self.assertEqual({x['category'] for x in detail['unparsed_candidates']},{'MMS parts','MMS payloads'})
        self.assertEqual(next(r['body'] for r in rows if json.loads(r['data'])['original']['msg_box']=='6'),'Known 🧪 body')
        self.assertFalse((self.base.parent/'foreign.png').exists())

    def test_embedded_media_retained_not_decoded_or_asserted_acquired(self):
        _,rows,detail=self.import_xml('payload.xml','<smses count="1"><mms date="1760000000123" msg_box="2"><parts><part ct="image/png" data="NOT_BASE64"/></parts></mms></smses>')
        data=json.loads(rows[0]['data']);self.assertEqual(data['parts'][0]['embedded_payload']['status'],'retained_in_original_xml_not_decoded')
        self.assertEqual(detail['unparsed_candidates'][0]['state'],'unsupported')
        self.assertEqual(data['mms_coverage']['payload_decoding'],'not_performed')

    def test_hostile_and_malformed_inputs_are_retained_without_partial_indexing(self):
        valid='<sms date="1760000000123" type="1" address="x" body="known"/>'
        controls=['<!DOCTYPE smses [<!ENTITY bad SYSTEM "file:///not-opened">]><smses/>',
                  '<?execute href="https://synthetic.invalid/not-fetched"?><smses/>',
                  '<smses count="1">'+valid+'<sms/></smses>',
                  '<smses count="2">'+valid+'<sms/></smses>',
                  '<smses count="1"><sms date="1760000000123" type="1" address="x" body="known">'+'<x>'*33+'</x>'*33+'</sms></smses>']
        for n,text in enumerate(controls):
            with self.subTest(control=n):
                result,rows,detail=self.import_xml('hostile-'+str(n)+'.xml',text)
                self.assertEqual(result['analysis']['status'],'partial');self.assertEqual(rows,[]);self.assertTrue(detail['errors'])

    def test_empty_supported_and_unrecognized_roots_remain_distinct(self):
        _,rows,empty=self.import_xml('empty.xml','<smses count="0"/>')
        self.assertEqual(rows,[]);self.assertEqual(empty['unparsed_candidates'][0]['state'],'parsed-empty')
        _,rows,other=self.import_xml('other.xml','<unrelated><value/></unrelated>')
        self.assertEqual(rows,[]);self.assertEqual(other['unparsed_candidates'][0]['state'],'unsupported')

    def test_documented_optional_stylesheet_is_inert_metadata(self):
        text='<?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="https://synthetic.invalid/not-fetched"?><smses count="1"><sms date="1760000000123" type="1" address="x" body="known"/></smses>'
        _,rows,_=self.import_xml('style.xml',text)
        self.assertEqual(rows[0]['body'],'known')
        self.assertEqual(json.loads(rows[0]['data'])['stylesheet']['state'],'ignored_not_loaded_or_executed')
        for bad in [text.replace('<smses','<?xml-stylesheet href="second"?><smses'),text.replace('https://synthetic.invalid/not-fetched','x'*2049)]:
            source=self.base/'bad-style.xml';source.write_text(bad)
            with self.assertRaises(ValueError):xml_backup_records(source)

    def test_old_expat_and_lowered_structural_limits_refuse_before_indexing(self):
        p=self.base/'small.xml';p.write_text('<smses count="0"/>')
        with patch('lawliet_mobile.xml_backup.expat.EXPAT_VERSION','expat_2.6.0'),self.assertRaisesRegex(ValueError,'Expat'):xml_backup_records(p)
        p.write_text('<smses><sms/><sms/></smses>')
        with patch('lawliet_mobile.xml_backup.MAX_RECORDS',1),self.assertRaisesRegex(ValueError,'records'):xml_backup_records(p)
        with patch('lawliet_mobile.xml_backup.MAX_ELEMENTS',2),self.assertRaisesRegex(ValueError,'bound'):xml_backup_records(p)


class XMLRuntimeRefusalTests(unittest.TestCase):
    def test_unsupported_expat_is_reported_without_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'known.xml'
            source.write_text('<smses count="0"/>')
            with patch('lawliet_mobile.xml_backup.expat.EXPAT_VERSION', 'expat_2.6.0'):
                with self.assertRaisesRegex(ValueError, 'Expat >= 2.7.2'):
                    xml_backup_records(source)
