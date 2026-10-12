import csv
import json
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import UserError, create_case, connect


class ImportedSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.workspace = self.base/'cases'
        create_case(self.workspace, 'test')
        self.folder = self.base/'aleapp'; (self.folder/'_TSV Exports').mkdir(parents=True)
        (self.folder/'media').mkdir()
        self.image = (Path(__file__).resolve().parents[1]/'desktop/assets/mobile-icon.png').read_bytes()
        (self.folder/'media/snapshot.png').write_bytes(self.image)
        fields = {'CE Profile':'0','Task ID':'6','Affinity':'com.google.android.apps.maps',
                  'Snapshot Image':'media/snapshot.png','Last Time Moved':'2023-09-20T23:50:29Z'}
        self.report = self.folder/'_TSV Exports/Recent Activity.tsv'
        with self.report.open('w') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields,delimiter='\t');writer.writeheader();writer.writerow(fields)
        self.call('import',path=str(self.folder),format='folder')
        self.row=self.call('records',report='Recent Activity')['records'][0]

    def call(self, action, **args):
        return handle(self.workspace, {'action':action,'case':'test',**args})

    def test_complete_import_preview_exact_bytes_and_case_isolation(self):
        result=self.call('preview',artifact_id=self.row['id'])
        self.assertEqual(Path(result['path']).read_bytes(),self.image)
        self.assertEqual(result['mime'],'image/png')
        create_case(self.workspace,'other')
        with self.assertRaises(UserError):
            handle(self.workspace,{'action':'preview','case':'other','artifact_id':self.row['id']})

    def test_report_and_image_tampering_refused(self):
        with connect(self.workspace,'test') as (root,db):
            report=db.execute('SELECT * FROM files WHERE id=?',(self.row['file_id'],)).fetchone()
            path=root/'evidence'/self.row['evidence_id']/report['path']
            original=path.read_bytes();path.write_bytes(original+b'changed')
            with self.assertRaises(UserError):self.call('preview',artifact_id=self.row['id'])
            path.write_bytes(original)
            image=root/'evidence'/self.row['evidence_id']/'media/snapshot.png'
            image.write_bytes(self.image+b'changed')
            with self.assertRaises(UserError):self.call('preview',artifact_id=self.row['id'])

    def test_missing_unsafe_and_symlink_references_refused(self):
        with connect(self.workspace,'test') as (root,db):
            original=self.row['data']
            (root/'evidence'/self.row['evidence_id']/'media/other.png').write_bytes(self.image)
            for reference in ['../snapshot.png','/media/snapshot.png','media/missing.png','media/other.png','media/../snapshot.png','media\\snapshot.png',None]:
                data=json.loads(json.dumps(original));data['_leapp_fields']['Snapshot Image']=reference
                db.execute('UPDATE artifacts SET data=? WHERE id=?',(json.dumps(data),self.row['id']));db.commit()
                with self.assertRaises(UserError):self.call('preview',artifact_id=self.row['id'])
            db.execute('UPDATE artifacts SET data=? WHERE id=?',(json.dumps(original),self.row['id']));db.commit()
            path=root/'evidence'/self.row['evidence_id']/'media/snapshot.png'
            path.unlink();path.symlink_to(self.folder/'media/snapshot.png')
            with self.assertRaises(UserError):self.call('preview',artifact_id=self.row['id'])

    def test_reports_browse_unknown_ios_and_android_without_category_filter(self):
        other=self.base/'ileapp';other.mkdir()
        (other/'Installed Applications.tsv').write_text('Bundle ID\tName\ncom.example.ios\tExample iOS app\n')
        (other/'Empty.tsv').write_text('Key\tValue\n')
        self.call('import',path=str(other),format='folder')
        stats=self.call('source-stats');names={r['name'] for r in stats['reports']}
        self.assertEqual(names,{'Recent Activity','Installed Applications','Empty'})
        inventory={r['name']:r for r in stats['reports']}
        self.assertEqual(inventory['Recent Activity']['categories'],['external'])
        self.assertEqual(inventory['Empty']['categories'],[])
        rows=self.call('records',report='Installed Applications')['records']
        self.assertEqual(len(rows),1);self.assertIn('Example iOS app',rows[0]['body'])
        self.assertEqual(self.call('records',report='Empty')['records'],[])

    def test_file_inventory_literal_scope_pagination_and_preview(self):
        from lawliet_mobile.core import import_evidence
        folder=self.base/'files';folder.mkdir()
        for i in range(205):(folder/f'{i:03d}-100%_Straße.apk').write_bytes(b'fixture')
        with connect(self.workspace,'test') as (root,db):
            eid=import_evidence(root,db,folder,'android')[0]
        first=self.call('file-inventory',query='100%_STRASSE',evidence=eid)
        second=self.call('file-inventory',query='100%_STRASSE',evidence=eid,offset=100)
        third=self.call('file-inventory',query='100%_STRASSE',evidence=eid,offset=200)
        self.assertEqual(first['total'],205);self.assertEqual(len(first['files']),100)
        self.assertEqual(len(second['files']),100);self.assertEqual(len(third['files']),5)
        self.assertFalse(third['has_more'])
        self.assertEqual(len({r['id'] for page in [first,second,third] for r in page['files']}),205)
        self.assertEqual(self.call('file-inventory',query='100%_',evidence=self.row['evidence_id'])['files'],[])
        image=self.call('file-inventory',query='media/snapshot.png')['files'][0]
        result=self.call('file-preview',file_id=image['id'])
        self.assertEqual(Path(result['path']).read_bytes(),self.image)
        with connect(self.workspace,'test') as (root,db):
            (root/'evidence'/image['evidence_id']/image['logical_path']).write_bytes(b'changed')
        with self.assertRaises(UserError):self.call('file-preview',file_id=image['id'])
        with self.assertRaises(UserError):self.call('file-preview',file_id=first['files'][0]['id'])
        for args in [{'offset':-1},{'limit':101},{'limit':True}]:
            with self.assertRaises(UserError):self.call('file-inventory',**args)

    def test_browser_group_includes_raw_reports_without_rewriting_source(self):
        folder=self.base/'browser';folder.mkdir()
        (folder/'Browser Data - History (Mister Skinnylegs).tsv').write_text('url\tvisit time\nhttps://example.test/raw\t2023-09-19 18:47:31.779445\n')
        (folder/'Web History.tsv').write_text('Last Visit Time\tURL\tTitle\n2023-09-19T18:47:31Z\thttps://example.test/normalized\tVisit\n')
        self.call('import',path=str(folder),format='folder')
        rows=self.call('records',view_group='browser')['records'];self.assertEqual(len(rows),2)
        raw=next(r for r in rows if r['category']=='external')
        self.assertIsNone(raw['timestamp']);self.assertEqual(raw['data']['_leapp_fields']['visit time'],'2023-09-19 18:47:31.779445')
        self.assertEqual(len(self.call('records',view_group='browser',since='2023-09-19')['records']),1)
        self.assertEqual(len(self.call('records',view_group='browser',query='raw')['records']),1)
        stats=self.call('source-stats');self.assertEqual(stats['view_groups']['browser'],2)
        self.assertEqual(stats['categories']['browser'],1)
        report=next(r for r in stats['reports'] if r['name'].startswith('Browser Data'))
        self.assertEqual(report['categories'],['external']);self.assertEqual(report['view_group'],'browser')
