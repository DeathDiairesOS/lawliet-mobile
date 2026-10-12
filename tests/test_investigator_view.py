import copy
import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, import_evidence, select_artifacts
from lawliet_mobile.parsed_import import import_parsed
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.investigator_view import display_record


class InvestigatorViewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.workspace=self.base/'cases'
        create_case(self.workspace,'case')
        folder=self.base/'phone';folder.mkdir();source=folder/'contacts2.db'
        with sqlite3.connect(source) as db:
            db.executescript('CREATE TABLE mimetypes(_id INTEGER,mimetype TEXT);CREATE TABLE data(_id INTEGER,raw_contact_id INTEGER,mimetype_id INTEGER,data1 TEXT);INSERT INTO mimetypes VALUES(1,"vnd.android.cursor.item/name"),(2,"vnd.android.cursor.item/phone_v2");')
            for i in range(1,7):
                db.execute('INSERT INTO data VALUES(?,?,1,?)',(i*2,i,'Shady Wahab' if i==6 else f'Contact {i}'))
                db.execute('INSERT INTO data VALUES(?,?,2,?)',(i*2+1,i,'+20 117 213 7258' if i==6 else f'+1202555010{i}'))
        with connect(self.workspace,'case') as (root,db):
            self.evidence=import_evidence(root,db,folder,'android')[0]
            native_analyze(root,db,self.evidence)
            reports=self.base/'reports';reports.mkdir()
            with (reports/'Contacts.tsv').open('w') as stream:
                writer=csv.writer(stream,delimiter='\t');writer.writerow(['Mimetype','Data 1','Display Name','Phone Number'])
                for i in range(1,7):writer.writerow(['vnd.android.cursor.item/phone_v2',f'+1202555010{i}',f'Report Contact {i}',f'+1202555010{i}'])
            self.report=import_parsed(root,db,reports,'folder')['evidence_id']
    def call(self,action='records',**args):return handle(self.workspace,{'action':action,'case':'case',**args})

    def test_six_contacts_from_twelve_fields_report_records_preserved(self):
        raw=self.call(category='contacts')['records'];self.assertEqual(len(raw),18)
        normalized=self.call(category='contacts',presentation='investigator')
        self.assertEqual(len(normalized['records']),6)
        entry=next(r for r in normalized['records'] if r['display_title']=='Shady Wahab')
        self.assertIn('+20 117 213 7258',entry['display_body'])
        observations=entry['investigator_view']['observations'];self.assertEqual(len(observations),2)
        self.assertEqual({r['data']['raw_contact_id'] for r in observations},{6})
        self.assertEqual(normalized['summary']['report_entries'],6)
        self.assertEqual(len(self.call(category='contacts',presentation='investigator',contact_basis='all')['records']),12)
        self.assertEqual(len(self.call(category='contacts',presentation='investigator',contact_basis='reports')['records']),6)
        self.assertEqual(self.call('source-stats')['contact_entries']['default_entries'],6)
        self.assertEqual(self.call('source-stats')['categories']['contacts'],18)

    def test_display_field_sort_honors_interpretation(self):
        args=dict(category='contacts',presentation='investigator',sort_field='Name')
        asc=self.call(**args,sort_mode='text',sort_direction='asc')['records']
        desc=self.call(**args,sort_mode='text',sort_direction='desc')['records']
        self.assertEqual([r['id'] for r in asc],list(reversed([r['id'] for r in desc])))
        numeric=self.call(**args,sort_mode='number',sort_direction='desc')['records']
        self.assertEqual([r['id'] for r in numeric],[r['id'] for r in asc])

    def test_name_and_phone_search_keep_other_contact_fields(self):
        for args in [{'query':'SHADY'},{'phone_query':'+201172137258'}]:
            result=self.call(category='contacts',presentation='investigator',**args)
            self.assertEqual(len(result['records']),1)
            self.assertEqual(result['records'][0]['display_title'],'Shady Wahab')
            self.assertEqual(len(result['records'][0]['investigator_view']['observations']),2)
        self.assertEqual(self.call(category='contacts',presentation='investigator',since='2023-09-19')['records'],[])

    def test_source_and_case_boundaries_and_raw_rows_unchanged(self):
        with connect(self.workspace,'case') as (_,db):before=copy.deepcopy(select_artifacts(db,limit=None))
        self.call(category='contacts',presentation='investigator')
        with connect(self.workspace,'case') as (_,db):after=select_artifacts(db,limit=None)
        self.assertEqual(before,after)
        reports=self.call(category='contacts',presentation='investigator',evidence=self.report)
        self.assertEqual(len(reports['records']),6);self.assertEqual(reports['summary']['basis'],'reports')
        create_case(self.workspace,'other')
        self.assertEqual(handle(self.workspace,{'action':'records','case':'other','category':'contacts','presentation':'investigator'})['records'],[])

    def test_duplicate_contact_values_in_other_evidence_not_merged(self):
        with connect(self.workspace,'case') as (root,db):
            duplicate=self.base/'second';duplicate.mkdir()
            (duplicate/'contacts2.db').write_bytes((self.base/'phone/contacts2.db').read_bytes())
            eid=import_evidence(root,db,duplicate,'android')[0]
            native_analyze(root,db,eid)
        records=self.call(category='contacts',presentation='investigator')['records']
        self.assertEqual(len(records),12)
        self.assertEqual(len([r for r in records if r['display_title']=='Shady Wahab']),2)
        self.assertTrue(all(len(r['investigator_view']['observations'])==2 for r in records))

    def test_native_browser_visit_uses_resolved_url_not_foreign_key(self):
        row={'id':'test','evidence_id':'e','file_id':1,'parser':'native/0.1.5','category':'browser','timestamp':'2023-09-19T00:00:00Z','source_ref':'visits:id=1','source_sha256':'hash','logical_path':'History','title':'Page','body':'https://example.test/page','data':{'url':999,'browser':{'record_kind':'visit'}}}
        original=copy.deepcopy(row);view=display_record(row)
        self.assertEqual(row,original)
        self.assertIn('https://example.test/page',view['display_body']);self.assertNotIn('URL: 999',view['display_body'])
        summary=display_record({**row,'data':{'url':'https://example.test/page','browser':{'record_kind':'url_summary'}}})
        self.assertNotEqual(summary['investigator_view']['kind'],view['investigator_view']['kind'])

    def test_raw_browser_timestamp_not_promoted_to_utc_event(self):
        row={'id':'test','evidence_id':'e','file_id':1,'parser':'import/leapp','category':'external','timestamp':None,'source_ref':'report:record=2','source_sha256':'hash','logical_path':'report.tsv','title':'Browser report','body':'source','data':{'_leapp_report_name':'Browser Data - History (Mister Skinnylegs)','_leapp_fields':{'url':'https://example.test','visit time':'2023-09-19 18:47:31'}}}
        view=display_record(row);self.assertIsNone(view['timestamp'])
        self.assertIn('Timezone: Not established',view['display_body'])


class MessagePresentationTests(unittest.TestCase):
    def row(self,identifier,report='discordChats'):
        return {'id':identifier,'evidence_id':'bundle-A','file_id':1,'parser':'import/leapp',
                'source_ref':'report:record=2','source_sha256':'a'*64,'source_file':'messages.tsv',
                'title':'Discord channel 20','body':'Test message','timestamp':'2023-09-20T00:57:26.406000Z',
                'category':'messages','data':{'_leapp_report_name':report,
                    '_leapp_fields':{'Edited Timestamp':'','Attachment':'','Attachment URL':''},
                    'message':{'app':'discord','account_ids':'10','channel_id':'20','source_row_id':'30',
                        'sender':'40','sender_label':'Test sender','direction':'incoming'}}}

    def test_same_ids_payload_group_preserves_original_observations(self):
        from lawliet_mobile.investigator_view import message_entries
        rows=[self.row('a'),self.row('b','Discord - Cached Messages (API cache)')]
        before=copy.deepcopy(rows);entries=message_entries(rows)
        self.assertEqual(len(entries),1)
        self.assertEqual([r['id'] for r in entries[0]['investigator_view']['observations']],['a','b'])
        self.assertEqual(rows,before)

    def test_scope_content_edits_and_attachments_do_not_merge(self):
        from lawliet_mobile.investigator_view import message_entries
        a=self.row('a')
        for change in ('evidence','account','channel','message','sender','body','time','edit','attachment','missing_account'):
            b=self.row('b','Discord - Cached Messages (API cache)')
            if change=='evidence':b['evidence_id']='bundle-B'
            elif change in {'account','channel','message','sender'}:
                b['data']['message'][{'account':'account_ids','channel':'channel_id','message':'source_row_id','sender':'sender'}[change]]='99'
            elif change=='body':b['body']='Changed message'
            elif change=='time':b['timestamp']='2023-09-20T00:57:27.406000Z'
            elif change=='edit':b['data']['_leapp_fields']['Edited Timestamp']='2023-09-21'
            elif change=='attachment':b['data']['_leapp_fields']['Attachment URL']='https://example.test/file'
            else:b['data']['message']['account_ids']=''
            with self.subTest(change=change):self.assertEqual(len(message_entries([a,b])),2)

    def test_unknown_and_native_sources_remain_separate(self):
        from lawliet_mobile.investigator_view import message_entries
        a=self.row('a');b=self.row('b')
        for parser in ('native/0.1.5','another/parser'):
            a['parser']=b['parser']=parser
            self.assertEqual(len(message_entries([a,b])),2)


class CallDisplayTests(unittest.TestCase):
    def test_report_icon_is_removed_only_from_display(self):
        original='Outgoing <i data-feather="phone-outgoing" stroke="green"></i>'
        row={'category':'calls','title':'Call','data':{'_leapp_fields':{'Call Type':original,'Phone Number':'TEST','Call Duration':'40'}}}
        before=copy.deepcopy(row)
        result=display_record(row)
        self.assertIn('Call type (source): Outgoing',result['display_body'])
        self.assertNotIn('<i ',result['display_body'])
        self.assertEqual(result['investigator_view']['observations'][0]['data']['_leapp_fields']['Call Type'],original)
        self.assertEqual(row,before)
