"""Read-only discovery/history using real synthetic Lawliet case databases."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from lawliet_mobile.core import create_case

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('catalog_backend',ROOT/'desktop/catalog_backend.py')
catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)


class CaseCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
    def case(self,workspace,name='same'):
        create_case(workspace,name,'Synthetic '+name,'Test examiner')
        return workspace/name
    def test_nested_duplicate_ids_are_distinct_and_bytes_unchanged(self):
        a=self.case(self.root/'a'/'review');b=self.case(self.root/'b'/'review')
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}
        r=catalog.catalog([str(self.root),str(a)])
        self.assertEqual(len(r['cases']),2);self.assertEqual({c['id'] for c in r['cases']},{'same'})
        self.assertEqual({c['path'] for c in r['cases']},{str(a),str(b)})
        self.assertTrue(all(c['available'] for c in r['cases']))
        self.assertEqual(before,{p:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()})
    def test_evidence_and_symlink_trees_are_not_traversed(self):
        a=self.case(self.root/'a');self.case(a/'evidence'/'fake')
        self.case(self.root/'evidence'/'fake')
        outside=self.case(self.root/'outside');(self.root/'a'/'alias').symlink_to(outside,target_is_directory=True)
        r=catalog.catalog([str(self.root/'a')]);self.assertEqual([x['path'] for x in r['cases']],[str(a)])
    def test_invalid_database_and_missing_root_are_visible_not_empty_success(self):
        good=self.case(self.root/'good');bad=self.root/'bad';bad.mkdir();(bad/'case.sqlite').write_bytes(b'not SQLite')
        r=catalog.catalog([str(self.root),str(self.root.with_name(self.root.name+'-missing'))]);self.assertEqual(len(r['cases']),2)
        self.assertTrue(next(x for x in r['cases'] if x['path']==str(good))['available'])
        self.assertFalse(next(x for x in r['cases'] if x['path']==str(bad))['available'])
        self.assertTrue(r['warnings']);self.assertTrue(r['partial'])
    def test_nonempty_wal_is_disclosed_and_not_read_as_current(self):
        a=self.case(self.root);wal=a/'case.sqlite-wal';wal.write_bytes(b'pending synthetic WAL')
        r=catalog.catalog([str(self.root)]);self.assertFalse(r['cases'][0]['available']);self.assertIn('WAL',r['cases'][0]['error'])
        self.assertEqual(wal.read_bytes(),b'pending synthetic WAL');self.assertFalse((a/'case.sqlite-shm').exists())
    def test_partial_limits_are_explicit(self):
        self.case(self.root/'a');self.case(self.root/'b')
        r=catalog.catalog([str(self.root)],max_cases=1);self.assertEqual(len(r['cases']),1);self.assertTrue(r['partial']);self.assertTrue(r['warnings'])
        r=catalog.catalog([str(self.root)],max_depth=0);self.assertEqual(len(r['cases']),0);self.assertTrue(r['partial'])
    def test_metadata_does_not_count_or_read_artifacts(self):
        a=self.case(self.root)
        with sqlite3.connect(a/'case.sqlite') as db:
            db.execute('DROP TABLE artifacts');db.execute("UPDATE meta SET value=? WHERE key='case_management'",('{}',))
        self.assertTrue(catalog.catalog([str(self.root)])['cases'][0]['available'])
    def test_relative_roots_are_not_implicitly_authorized(self):
        with self.assertRaisesRegex(ValueError,'absolute'):catalog.catalog(['relative/cases'])
    def test_failed_drive_is_refused_before_any_scan(self):
        with self.assertRaisesRegex(ValueError,'easystore'):catalog.catalog(['/Volumes/easystore/lawliet-mobile'])
    def test_report_history_pages_and_invalid_drafts_remain_visible(self):
        case=self.case(self.root);drafts=case/'customer-drafts';drafts.mkdir()
        for n in range(52):
            p=drafts/f'draft{n:02}';p.mkdir();(p/'manifest.json').write_text(json.dumps({'format':'ancalor-customer-bundle-v1','draft_id':p.name,'counts':{'entries':1,'unique_cited_artifacts':1}}))
        (drafts/'broken').mkdir();(drafts/'broken'/'manifest.json').write_text('bad')
        r=catalog.history(str(case));self.assertEqual(r['total'],53);self.assertEqual(len(r['items']),50);self.assertTrue(r['has_more'])
        last=catalog.history(str(case),50);self.assertEqual(len(last['items']),3);self.assertFalse(last['has_more']);self.assertFalse(next(x for x in last['items'] if x['id']=='broken')['available'])
        self.assertEqual(catalog.history(str(case),100)['items'],[])
    def test_history_rejects_symlink_and_path_escape(self):
        case=self.case(self.root);outside=self.root/'outside';outside.mkdir();(case/'customer-drafts').symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'Symlinked'):catalog.history(str(case))
        with self.assertRaises(ValueError):catalog.handle({'action':'report-history','workspace':str(self.root),'case':'../same'})
    @unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'Requires native Swift compiler')
    def test_native_model_identity_and_preferences(self):
        binary=self.root/'check'
        subprocess.run(['swiftc',str(ROOT/'desktop/CaseCatalog.swift'),str(ROOT/'tests/CaseCatalogCheck.swift'),'-o',str(binary)],check=True,capture_output=True,timeout=60)
        r=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=10)
        self.assertIn('duplicate IDs',r.stdout)
