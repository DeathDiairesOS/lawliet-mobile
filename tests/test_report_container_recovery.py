"""Audit-first recovery controls; no daemon calls or kernel/process proof."""
import json,unittest
from unittest.mock import patch
from tests import test_report_container as fixtures
from lawliet_mobile import core,report_container as rc
class Recovery(unittest.TestCase):
 setUp=fixtures.Reports.setUp
 decode=fixtures.Reports.decode
 contained=fixtures.Reports.contained
 def fixture(self,db,root):
  result=self.contained(root,db);row=db.execute('SELECT * FROM runs WHERE id=?',(result['run_id'],)).fetchone();return result,json.loads(row['detail'])
 def test_settled_offline_without_runtime_probes(self):
  with core.connect(self.ws,'A') as (root,db):
   self.fixture(db,root)
   with patch.object(rc,'validate_config',side_effect=AssertionError('offline')),patch.object(rc,'inventory',side_effect=AssertionError('offline')):rc.recover_before_retry(root,db)
 def test_missing_row_and_missing_detail_refuse_before_daemon(self):
  for case,mutation in (('A','DELETE FROM runs'),('B',"UPDATE runs SET detail='{}'")):
   with self.subTest(mutation=mutation),core.connect(self.ws,case) as (root,db):
    self.fixture(db,root);db.execute('PRAGMA foreign_keys=OFF');db.execute(mutation);db.commit()
    with patch.object(rc,'inventory',side_effect=AssertionError('must refuse first')),self.assertRaises(core.UserError):rc.recover_before_retry(root,db)
 def test_duplicate_terminal_identical_and_distinct_refuse_without_probe(self):
  for distinct in (False,True):
   case='A' if not distinct else 'B'
   with core.connect(self.ws,case) as (root,db):
    result,d=self.fixture(db,root);receipt=dict(d['container'])
    if distinct:receipt['container_id']='e'*64
    core.audit(db,'parsed_import.failed',{'run_id':result['run_id'],'container':receipt});db.commit()
    with patch.object(rc,'validate_config',side_effect=AssertionError('ambiguity before probe')),self.assertRaisesRegex(core.UserError,'ambiguous'):rc.recover_before_retry(root,db)
 def test_moved_unresolved_uses_original_audited_labels_and_missing_marker_refuses(self):
  with core.connect(self.ws,'A') as (root,db):
   result,d=self.fixture(db,root)
   # Recreate an unresolved start without a settlement, using a fresh CaseDB.
   with core.connect(self.ws,'B') as (other,otherdb):
    otherdb.execute('INSERT INTO evidence SELECT * FROM evidence WHERE 0')
    # Recovery only requires the audited run binding; evidence is copied explicitly.
    evidence=db.execute('SELECT * FROM evidence').fetchone();otherdb.execute('INSERT INTO evidence VALUES('+','.join('?' for _ in evidence)+')',tuple(evidence))
    row=db.execute('SELECT * FROM runs').fetchone();cols=[x[1] for x in db.execute('PRAGMA table_info(runs)')];values=list(row);values[cols.index('detail')]=core.json_text({k:v for k,v in d.items() if k!='container'});values[cols.index('status')]='failed';otherdb.execute('INSERT INTO runs VALUES('+','.join('?' for _ in values)+')',values)
    start=json.loads(db.execute("SELECT detail FROM audit WHERE action='parsed_import.started'").fetchone()[0]);core.audit(otherdb,'parsed_import.started',start);otherdb.commit();(other/'runs'/result['run_id']).mkdir(parents=True)
    with patch.object(rc,'validate_config',side_effect=lambda value,**kw:value),patch.object(rc,'inventory',return_value=[]) as inventory,self.assertRaisesRegex(core.UserError,'empty inventory'):rc.recover_before_retry(other,otherdb)
    self.assertEqual(inventory.call_args.args[1],d['report_container_labels']);self.assertNotEqual(rc.labels(other,result['run_id'],d['runner_ownership']),d['report_container_labels'])
 def unresolved(self,root,db):
  result,d=self.fixture(db,root);db.execute("DELETE FROM audit WHERE action='parsed_import.complete'");d.pop('container');db.execute('UPDATE runs SET detail=?,status=?',(core.json_text(d),'failed'));db.commit();return result,d
 def test_active_and_unavailable_refuse_without_removal(self):
  for case,down in [('A',False),('B',True)]:
   with core.connect(self.ws,case) as (root,db):
    result,d=self.unresolved(root,db)
    with patch.object(rc,'validate_config',side_effect=lambda value,**kw:value),patch.object(rc,'inventory',side_effect=core.UserError('daemon unavailable') if down else None,return_value=['d'*64]),patch.object(rc,'owned_state',return_value={'State':{'Running':True,'Status':'running'}}),patch.object(rc,'remove_stopped') as remove,self.assertRaises(core.UserError):rc.recover_before_retry(root,db)
    remove.assert_not_called();self.assertEqual(db.execute('SELECT records FROM runs').fetchone()[0],1)
 def test_known_stopped_recovery_receipt_and_audit_match_without_output_promotion(self):
  with core.connect(self.ws,'A') as (root,db):
   result,d=self.unresolved(root,db);before=db.execute('SELECT count(*) FROM artifacts').fetchone()[0]
   with patch.object(rc,'validate_config',side_effect=lambda value,**kw:value),patch.object(rc,'inventory',return_value=['d'*64]),patch.object(rc,'owned_state',return_value={'State':{'Running':False,'Paused':False,'Restarting':False,'Status':'exited','ExitCode':125,'OOMKilled':False}}),patch.object(rc,'remove_stopped') as remove:rc.recover_before_retry(root,db)
   receipt=json.loads(db.execute('SELECT detail FROM runs').fetchone()[0])['container'];audit=json.loads(db.execute("SELECT detail FROM audit WHERE action='parsed_import.container_reconciled'").fetchone()[0]);self.assertEqual(receipt,audit['container']);self.assertEqual(receipt['labels'],d['report_container_labels']);remove.assert_called_once();self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],before)
if __name__=='__main__':unittest.main()
