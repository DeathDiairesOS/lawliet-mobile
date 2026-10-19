"""Selected inventory caps are enforced before parser preflight or file opening."""
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import native_container as native,core,parsers


class InventoryBounds(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        self.addCleanup(self.db.close);self.db.executescript(core.SCHEMA)
        self.eid='abcdef012345'
        self.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?)',(self.eid,'Synthetic','android','fixture','now',None,0))

    def fill(self,count,size=0):
        self.db.executemany('INSERT INTO files VALUES(?,?,?,?,?,?)',((i,self.eid,str(i),str(i),'a'*64,size) for i in range(1,count+1)))

    def test_1001_inventory_refuses_before_parser_preflight_and_limits_query(self):
        self.fill(1001);queries=[];self.db.set_trace_callback(queries.append)
        with patch.object(parsers,'_native_preflight',side_effect=AssertionError('Unbounded preflight must not run')),self.assertRaisesRegex(core.UserError,'1000'):
            native.analyze(Path('/synthetic/case'),self.db,self.eid,{})
        selection=[q for q in queries if 'SELECT id,path,logical_path,sha256,size' in q]
        self.assertEqual(len(selection),1)
        self.assertIn('LIMIT 1001',selection[0])

    def test_exact_1000_inventory_retained_without_subset(self):
        self.fill(1000);rows=native.source_manifest(self.db,self.eid)
        self.assertEqual(len(rows),1000);self.assertEqual(rows[0]['id'],1);self.assertEqual(rows[-1]['id'],1000)
        self.assertEqual(sum(f['bytes'] for f in rows),0)

    def test_whole_inventory_bytes_refuses_without_file_access(self):
        self.fill(2,17*1024**2)
        with self.assertRaisesRegex(core.UserError,'32MiB'):native.source_manifest(self.db,self.eid)

if __name__=='__main__':unittest.main()
