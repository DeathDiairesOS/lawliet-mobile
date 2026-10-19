"""The explicit container endpoint cannot race into trusted host execution."""
import os,pathlib,sqlite3,tempfile,unittest
from unittest.mock import patch
from lawliet_mobile.core import UserError,create_case,connect,import_evidence
from lawliet_mobile.sqlite_workspace import query

class EndpointFallback(unittest.TestCase):
 def test_removed_configuration_refuses_at_backend_before_run_or_host_worker(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=pathlib.Path(tmp).resolve();ws=base/'cases';create_case(ws,'A');source=base/'seed.db';db=sqlite3.connect(source);db.execute('CREATE TABLE seed(x)');db.commit();db.close()
   with connect(ws,'A') as (root,db):
    import_evidence(root,db,source,'android');fid=db.execute('SELECT id FROM files').fetchone()[0]
    with patch.dict(os.environ,{'LAWLIET_MCP_PROFILE':'sqlite-container'}),patch('lawliet_mobile.sqlite_container.configured',return_value=None),patch('lawliet_mobile.tools.execute') as host:
     with self.assertRaisesRegex(UserError,'no host fallback'):query(root,db,fid,'SELECT x FROM seed')
     host.assert_not_called()
    self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],0)
