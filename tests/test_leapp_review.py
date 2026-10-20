import csv
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import create_case, connect, import_evidence, select_artifacts, UserError
from lawliet_mobile.tools import configure, external_analyze


def android_fixture(source):
    contacts=source/'data/data/com.android.providers.contacts/databases/contacts2.db'
    contacts.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(contacts)) as db, db:
        db.executescript("""
        CREATE TABLE contacts(_id INTEGER);
        CREATE TABLE raw_contacts(_id INTEGER,contact_id INTEGER,display_name TEXT);
        CREATE TABLE mimetypes(_id INTEGER,mimetype TEXT);
        CREATE TABLE data(_id INTEGER,raw_contact_id INTEGER,mimetype_id INTEGER,data1 TEXT);
        INSERT INTO contacts VALUES(1);
        INSERT INTO raw_contacts VALUES(1,1,'Synthetic Contact');
        INSERT INTO mimetypes VALUES(1,'vnd.android.cursor.item/phone_v2');
        INSERT INTO data VALUES(1,1,1,'+12025550100');
        CREATE TABLE calls(number TEXT,date INTEGER,duration INTEGER,type INTEGER,name TEXT);
        INSERT INTO calls VALUES('+12025550100',1791640800000,42,1,'Synthetic Caller');
        """)
    chrome=source/'data/data/com.android.chrome/app_chrome/Default/History'
    chrome.parent.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(chrome)) as db, db:
        db.executescript("""CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER,last_visit_time INTEGER,hidden INTEGER);
        INSERT INTO urls VALUES(1,'https://validation.example/100%_literal','Synthetic Browser',1,0,13436114400000000,0);""")


class LeappReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.workspace=self.base/'cases';create_case(self.workspace,'qa')
    def call(self,action,**kwargs):
        return handle(self.workspace,{'action':action,'case':'qa',**kwargs})
    def test_report_seconds_are_not_presented_as_original_subsecond_precision(self):
        from lawliet_mobile.leapp_reports import leapp_artifact, report_review_note
        row={'Timestamp':'2020-03-22 01:10:59+00:00','Direction':'Received','Number':'+12025550100',
             'Message':'Synthetic','Backup File':'sms.xml','Source File':'files/sms.xml'}
        mapped=leapp_artifact('SMS Backup and Restore Messages',row,'e')
        self.assertEqual(mapped[5]['_timestamp_precision']['source_fractional_digits'],0)
        self.assertIn('whole seconds',report_review_note(mapped[5]))
        precise=leapp_artifact('SMS Backup and Restore Messages',{**row,'Timestamp':'2020-03-22 01:10:59.123456+00:00'},'e')
        self.assertEqual(precise[5]['_timestamp_precision']['source_fractional_digits'],6)
        self.assertNotIn('whole seconds',report_review_note(precise[5]))

    def test_acquired_address_book_schema_maps_contacts_without_guessing_time(self):
        from lawliet_mobile.leapp_reports import leapp_artifact
        row={'First Name':'Synthetic','Last Name':'Contact','Phone Numbers':'Mobile: +12025550100\rOther: +12025550101',
             'Email addresses':'lab@example.test','Modification Date':'2020-03-27 18:44:01+00:00'}
        result=leapp_artifact('Address Book',row,'e')
        self.assertEqual(result[0],'contacts')
        self.assertEqual(result[1],'2020-03-27T18:44:01.000000Z')
        self.assertEqual(result[5]['_leapp_fields'],row)
        self.assertIsNone(leapp_artifact('Address Book',{**row,'Modification Date':'2020-03-27 18:44:01'},'e')[1])
        self.assertEqual(leapp_artifact('Unrecognized Address Book',row,'e')[0],'external')
        self.assertEqual(leapp_artifact('Address Book',{'First Name':'Only'},'e')[0],'external')

    def test_sms_backup_schema_preserves_body_and_separates_backup_files(self):
        from lawliet_mobile.leapp_reports import leapp_artifact, report_review_note
        row={'Timestamp':'2026-10-10 14:00:00+00:00', 'Direction':'Received',
             'Number':'+12025550100', 'Message':'Exact\nUnicode 😀\t"quote"',
             'Backup File':'sms-one.xml', 'Source File':'files/sms-one.xml'}
        mapped=leapp_artifact('SMS Backup and Restore Messages',row,'e')
        self.assertEqual(mapped[:3],('messages','2026-10-10T14:00:00.000000Z',row['Timestamp']))
        self.assertEqual(mapped[4],row['Message'])
        self.assertEqual(mapped[5]['_leapp_fields'],row)
        self.assertEqual(mapped[5]['message']['sender'],row['Number'])
        self.assertIn('not distinct messages',report_review_note(mapped[5]))
        for changes,evidence in [({'Source File':'other/sms-one.xml'},'e'),({},'other')]:
            other=leapp_artifact('SMS Backup and Restore Messages',{**row,**changes},evidence)
            self.assertNotEqual(mapped[5]['message']['conversation_id'],other[5]['message']['conversation_id'])
        sent=leapp_artifact('SMS Backup and Restore Messages',{**row,'Direction':'Sent'},'e')
        self.assertEqual(sent[5]['message']['recipient'],row['Number'])
        unknown=leapp_artifact('SMS Backup and Restore Messages',{**row,'Direction':'3'},'e')
        self.assertEqual(unknown[5]['message']['direction'],'unknown')
        for column in ['Source File','Number']:
            self.assertEqual(leapp_artifact('SMS Backup and Restore Messages',{**row,column:''},'e')[0],'external')
        for column in row:
            incomplete={k:v for k,v in row.items() if k!=column}
            self.assertEqual(leapp_artifact('SMS Backup and Restore Messages',incomplete,'e')[0],'external')

    def test_original_column_order_survives_storage_export_and_collision(self):
        path=self.base/'Column order.tsv'
        columns=['Zulu','Timestamp','Alpha','_leapp_columns']
        with path.open('w') as stream:
            writer=csv.writer(stream,delimiter='\t');writer.writerow(columns)
            writer.writerow(['last alphabetically','2023-09-20T12:00:00Z','first alphabetically','upstream value'])
        imported=self.call('import',path=str(path),format='tsv')
        scope={'evidence':imported['evidence_id'],'parser':'import/tsv'}
        row=self.call('records',**scope)['records'][0]
        self.assertEqual(row['data']['_leapp_columns'],columns)
        self.assertEqual(row['data']['_leapp_fields']['_leapp_columns'],'upstream value')
        out=self.base/'ordered.jsonl';self.call('export',path=str(out),**scope)
        self.assertEqual(json.loads(out.read_text())['data']['_leapp_columns'],columns)
        validation=self.call('validate',**scope)
        check=next(c for c in validation['checks'] if c['check']=='leapp_report_reconciliation')
        self.assertEqual(check['status'],'pass')
        with connect(self.workspace,'qa') as (_,db):
            data=row['data'];data['_leapp_columns']=list(reversed(columns))
            db.execute('UPDATE artifacts SET data=? WHERE id=?',(json.dumps(data),row['id']));db.commit()
        check=next(c for c in self.call('validate',**scope)['checks'] if c['check']=='leapp_report_reconciliation')
        self.assertEqual(check['status'],'needs_review')
        self.assertEqual(check['examples'][0]['reason'],'Retained column order differs from report headers')
    def test_activity_timeline_uses_explicit_anchor_without_epoch_guessing(self):
        from lawliet_mobile.leapp_reports import leapp_artifact, report_review_note
        recent={'CE Profile':'0','Task ID':'6','Affinity':'example.maps',
                'Last Time Moved':'2023-09-21 01:50:29.020000+02:00',
                'Snapshot ID Time':'2023-09-22T00:00:00Z'}
        usage={'User (UID)':'0','Package':'example.maps','Usage Type':'event-log',
               'Timestamp / Last Time Active':'2023-09-20T23:50:29.020000Z'}
        for name,fields,column in [('Recent Activity',recent,'Last Time Moved'),
                                   ('Usage Stats',usage,'Timestamp / Last Time Active')]:
            result=leapp_artifact(name,fields,'evidence')
            self.assertEqual(result[0],'external')
            self.assertEqual(result[1],'2023-09-20T23:50:29.020000Z')
            self.assertEqual(result[2],fields[column])
            self.assertEqual(result[5]['_leapp_fields'],fields)
            self.assertIn(column,report_review_note(result[5]))
            for invalid in ['', '1695253829020', '1695253829',
                            '2023-09-20T23:50:29', '2023-09-20T23:50:29.1234567Z']:
                self.assertIsNone(leapp_artifact(name,{**fields,column:invalid},'e')[1])
            self.assertIsNone(leapp_artifact('Unrecognized report',fields,'e')[1])
        folder=self.base/'activity';folder.mkdir()
        for name,fields in [('Recent Activity',recent),('Usage Stats',usage)]:
            with (folder/(name+'.tsv')).open('w', newline='', encoding='utf-8') as stream:
                writer=csv.DictWriter(stream,fieldnames=fields,delimiter='\t')
                writer.writeheader();writer.writerow(fields)
        imported=self.call('import',path=str(folder),format='folder')
        scope={'evidence':imported['evidence_id'],'parser':'import/leapp'}
        self.assertEqual(self.call('source-stats',**scope)['undated'],0)
        rows=self.call('records',since='2023-09-20T23:50:29Z',until='2023-09-20T23:50:30Z',**scope)['records']
        self.assertEqual(len(rows),2)
        self.assertEqual(self.call('records',since='2023-09-21',**scope)['records'],[])

    def test_discord_reports_keep_account_and_report_scopes_and_exact_content(self):
        from lawliet_mobile.leapp_reports import leapp_artifact, report_review_note
        original={'Timestamp':'2023-09-20T20:46:02.237000+00:00','Direction':'Incoming',
                  'Username':'test display','Content':'Meeting **place**\nUnicode ❤️',
                  'Channel ID':'100','Sender ID':'200','ID':'300','Account ID':'400'}
        mapped=leapp_artifact('discordChats',original,'e')
        self.assertEqual(mapped[0],'messages');self.assertEqual(mapped[4],original['Content'])
        message=mapped[5]['message']
        self.assertEqual(message['sender'],'200');self.assertEqual(message['recipient'],'')
        self.assertIn('not distinct-message counts',report_review_note(mapped[5]))
        for changed in [{'Account ID':'401'},{'Channel ID':'101'}]:
            self.assertNotEqual(message['conversation_id'],leapp_artifact('discordChats',{**original,**changed},'e')[5]['message']['conversation_id'])
        empty={**original,'Account ID':''}
        self.assertNotEqual(leapp_artifact('discordChats',empty,'e')[5]['message']['conversation_id'],
                            leapp_artifact('discordChats',{**empty,'ID':'301'},'e')[5]['message']['conversation_id'])
        self.assertEqual(leapp_artifact('discordChats',{**original,'ID':''},'e')[0],'external')
        self.assertEqual(leapp_artifact('discordChats',{**original,'Direction':''},'e')[5]['message']['direction'],'unknown')
        cached={k:v for k,v in original.items() if k not in {'ID','Account ID'}}
        cached.update({'Message ID':'300','Account IDs':'400'})
        other=leapp_artifact('Discord - Cached Messages (API cache)',cached,'e')
        self.assertNotEqual(message['conversation_id'],other[5]['message']['conversation_id'])
        folder=self.base/'discord';folder.mkdir()
        for name,fields in [('discordChats',original),('Discord - Cached Messages (API cache)',cached)]:
            with (folder/(name+'.tsv')).open('w', newline='', encoding='utf-8') as stream:
                writer=csv.DictWriter(stream,fieldnames=fields,delimiter='\t');writer.writeheader();writer.writerow(fields)
        imported=self.call('import',path=str(folder),format='folder')
        rows=self.call('records',evidence=imported['evidence_id'],parser='import/leapp',category='messages',query='Meeting')['records']
        self.assertEqual(len(rows),2)
        self.assertTrue(all(r['body']==original['Content'] for r in rows))
        threads=self.call('conversations',evidence=imported['evidence_id'],parser='import/leapp')
        self.assertEqual({tuple(t['reports']) for t in threads},{('discordChats',),('Discord - Cached Messages (API cache)',)})
    def test_folder_all_reports_search_categories_range_export(self):
        folder=self.base/'reports';folder.mkdir()
        (folder/'Contacts.tsv').write_text('Mimetype\tData 1\tDisplay Name\nphone\t+12025550100\tStraße Contact\n')
        (folder/'Call Logs.tsv').write_text('start_date\tnumber\tduration\tcall_type\n2026-10-10T14:00:00Z\t+12025550100\t42\tIncoming\n')
        (folder/'Web History.tsv').write_text('Last Visit Time\tURL\tTitle\n2026-10-03T14:00:00Z\thttps://example.com/100%_literal\tOld visit\n2026-10-03T13:59:59Z\thttps://example.com/older\tOutside\n')
        (folder/'Unknown.tsv').write_text('Key\tValue\nOne\tNeedle in original fields\n')
        (folder/'index.html').write_text('<script>never executed</script>')
        imported=self.call('import',path=str(folder),format='folder');self.assertEqual(imported['records'],5)
        scope={'evidence':imported['evidence_id'],'parser':'import/leapp'}
        stats=self.call('source-stats',**scope)
        self.assertEqual(stats['categories'],{'browser':2,'calls':1,'contacts':1,'external':1})
        self.assertEqual(stats['undated'],2);self.assertEqual(len(stats['reports']),4)
        self.assertEqual(len(self.call('records',query='STRASSE',**scope)['records']),1)
        self.assertEqual(len(self.call('records',query='100%_literal',**scope)['records']),1)
        self.assertEqual(len(self.call('records',query='needle',report='Unknown',**scope)['records']),1)
        for days in [7,30,60,90]:
            bounds=self.call('date-range',days=days,anchor='latest',**scope)
            rows=self.call('records',since=bounds['since'],until=bounds['until'],**scope)['records']
            self.assertEqual(len(rows),2 if days==7 else 3)
        with self.assertRaises(UserError):self.call('date-range',days=8,**scope)
        out=self.base/'out.jsonl';self.assertEqual(self.call('export',path=str(out),report='Contacts',**scope)['records'],1)
        self.assertTrue(self.call('verify')['ok'])
        (folder/'bad.tsv').write_text('A\tB\nx\ty\textra\n')
        with self.assertRaises(UserError):self.call('import',path=str(folder),format='folder')
        # Run and legacy parser views can select the same observations. Check
        # stored records and each positive source view instead of summing views.
        overview = self.call('overview')
        populated = [s for s in overview['sources'] if s['records']]
        self.assertTrue(populated)
        self.assertEqual({s['evidence'] for s in populated}, {imported['evidence_id']})
        self.assertTrue(all(s['records'] == 5 for s in populated))
        with connect(self.workspace, 'qa') as (_, db):
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 5)
            failed = db.execute("SELECT id FROM runs WHERE status='failed'").fetchone()
            self.assertEqual(select_artifacts(db, run=failed['id']), [])

    @unittest.skipUnless(os.environ.get('LAWLIET_ALEAPP'),'Set LAWLIET_ALEAPP for real ALEAPP')
    def test_real_android_contacts_calls_browser_and_whole_output(self):
        source=self.base/'android';android_fixture(source)
        configure(self.workspace,'aleapp',os.environ['LAWLIET_ALEAPP'])
        with connect(self.workspace,'qa') as (root,db):
            eid=import_evidence(root,db,source,'android')[0]
            result=external_analyze(root,db,self.workspace,eid,'aleapp')
            self.assertEqual(result['status'],'complete')
            for cat in ['contacts','calls','browser']:
                rows=select_artifacts(db,run=result['run_id'],category=cat)
                self.assertEqual(len(rows),1,(cat,result))
                self.assertEqual(rows[0]['parser'],'aleapp')
            from lawliet_mobile.validation import validate_case
            validation=validate_case(root,db,self.workspace,eid,'aleapp',result['run_id'])
            check=next(c for c in validation['checks'] if c['check']=='leapp_report_reconciliation')
            self.assertEqual(check['status'],'pass',check)
            self.assertEqual(check['exact_field_rows'],3)
            output=root/'runs'/result['run_id']/'output'
        result=self.call('import',path=str(output),format='folder')
        stats=self.call('source-stats',evidence=result['evidence_id'])
        for cat in ['contacts','calls','browser']: self.assertEqual(stats['categories'][cat],1)
        validation=self.call('validate',evidence=result['evidence_id'],parser='import/leapp')
        self.assertEqual(next(c for c in validation['checks'] if c['check']=='leapp_report_reconciliation')['status'],'pass')
        self.assertTrue(self.call('verify')['ok'])

    @unittest.skipUnless(os.environ.get('LAWLIET_ILEAPP'),'Set LAWLIET_ILEAPP for real iLEAPP')
    def test_real_iphone_output_folder(self):
        from tests.test_leapp_integration import RealLeappTests
        source=self.base/'ios'
        RealLeappTests().safari(source/'private/var/mobile/Library/Safari/History.db')
        configure(self.workspace,'ileapp',os.environ['LAWLIET_ILEAPP'])
        with connect(self.workspace,'qa') as (root,db):
            eid=import_evidence(root,db,source,'ios')[0]
            result=external_analyze(root,db,self.workspace,eid,'ileapp')
            self.assertEqual(result['status'],'complete')
            output=root/'runs'/result['run_id']/'output'
        result=self.call('import',path=str(output),format='folder')
        rows=self.call('records',evidence=result['evidence_id'],category='browser')['records']
        self.assertEqual(len(rows),1)
        self.assertIn('leapp-validation.example/safari',rows[0]['body'])
        self.assertTrue(self.call('verify')['ok'])
