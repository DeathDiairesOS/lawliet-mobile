"""Selected retained-origin binding; real CaseDB/worker, daemon mocked."""
import hashlib,json,unittest
from unittest.mock import patch
from tests import test_report_container as fixtures
from lawliet_mobile import core,parsed_import as parsed,report_container as rc
class Origin(unittest.TestCase):
 setUp=fixtures.Reports.setUp
 decode=fixtures.Reports.decode
 def originals(self,root,db):
  ids=[]
  for _ in range(2):
   eid,_,_=core.import_evidence(root,db,self.source,expand_archives=False);ids.append(db.execute('SELECT id FROM files WHERE evidence_id=?',(eid,)).fetchone()[0])
  return ids
 def contained(self,root,db,file_id,source=None,run=None):
  with patch.object(rc,'configured',return_value=self.cfg),patch.object(rc,'run',side_effect=run or self.decode):return parsed.import_parsed(root,db,source or self.source,'jsonl',contained=True,origin_file_id=file_id)
 def test_samebytes_distinct_origin_occurrences_and_repeat_namespace(self):
  with core.connect(self.ws,'A') as (root,db):
   a,b=self.originals(root,db);one=self.contained(root,db,a);two=self.contained(root,db,b)
   self.assertEqual((one['records'],two['records']),(1,1));self.assertNotEqual(one['evidence_id'],two['evidence_id']);self.assertEqual(one['report_origin']['file_id'],a);self.assertEqual(two['report_origin']['file_id'],b)
   messages=[json.loads(row[0])['message'] for row in db.execute('SELECT data FROM artifacts ORDER BY rowid')];self.assertNotEqual(messages[0]['conversation_id'],messages[1]['conversation_id'])
   with patch.object(rc,'configured',return_value=self.cfg),patch.object(rc,'run',side_effect=AssertionError('reuse no execution')):
    for selected,result in ((a,one),(b,two)):
     repeat=parsed.import_parsed(root,db,self.source,'jsonl',contained=True,origin_file_id=selected);self.assertEqual(repeat['status'],'already_imported');self.assertEqual(repeat['evidence_id'],result['evidence_id']);self.assertEqual(repeat['report_origin'],result['report_origin']);self.assertEqual(repeat['records'],0)
 def test_rawpath_none_and_retained_origin_are_separate(self):
  with core.connect(self.ws,'A') as (root,db):
   a,_=self.originals(root,db);raw=self.contained(root,db,None);origin=self.contained(root,db,a);self.assertIsNone(raw['report_origin']);self.assertNotEqual(raw['evidence_id'],origin['evidence_id']);self.assertIsNone(self.contained(root,db,None)['report_origin'])
 def test_strict_keyword_and_noncontained_refuse_before_intake(self):
  with core.connect(self.ws,'A') as (root,db):
   for value in (True,False,1.0,'1',0,-1,2**63,{}):
    with self.subTest(value=value),self.assertRaises(core.UserError):parsed.import_parsed(root,db,self.source,'jsonl',contained=True,origin_file_id=value)
   with self.assertRaises(core.UserError):parsed.import_parsed(root,db,self.source,'jsonl',origin_file_id=1)
   self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
 def test_missing_origin_and_snapshot_hash_or_schema_mismatch_refuse_before_intake(self):
  with core.connect(self.ws,'A') as (root,db):
   a,_=self.originals(root,db);count=db.execute('SELECT count(*) FROM evidence').fetchone()[0]
   for selected,source in ((999,self.source),(a,self.source.with_name('other.jsonl'))):
    if not source.exists():source.write_bytes(self.source.read_bytes())
    with self.assertRaises(core.UserError):self.contained(root,db,selected,source)
   other=self.base/'different'/'report.jsonl';other.parent.mkdir();other.write_text('{"category":"x","body":"different","data":{}}\n')
   with self.assertRaises(core.UserError):self.contained(root,db,a,other)
   self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0],count)
 def test_changed_origin_bytes_and_leaf_link_refuse_even_on_repeat(self):
  with core.connect(self.ws,'A') as (root,db):
   a,_=self.originals(root,db);result=self.contained(root,db,a);origin=result['report_origin'];path=root/'evidence'/origin['evidence_id']/origin['path'];original=path.read_bytes();path.write_bytes(original.replace(b'caf',b'bad'))
   with self.assertRaises(core.UserError):self.contained(root,db,a)
   path.unlink();path.symlink_to(self.source)
   with self.assertRaises((core.UserError,OSError)):self.contained(root,db,a)
 def test_origin_metadata_change_during_decode_rolls_back_prefix(self):
  def change(*args):
   result=self.decode(*args);db.execute("UPDATE files SET logical_path='changed' WHERE id=?",(a,));db.commit();return result
  with core.connect(self.ws,'A') as (root,db):
   a,_=self.originals(root,db)
   with self.assertRaisesRegex(core.UserError,'origin changed'):self.contained(root,db,a,run=change)
   self.assertEqual(db.execute('SELECT status,records FROM runs').fetchone()[:],('failed',0));self.assertEqual(db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
 def test_origin_row_detail_corruption_cannot_hide_audited_binding(self):
  with core.connect(self.ws,'A') as (root,db):
   a,_=self.originals(root,db);result=self.contained(root,db,a);row=db.execute('SELECT detail FROM runs WHERE id=?',(result['run_id'],)).fetchone();d=json.loads(row[0]);d.pop('report_origin');db.execute('UPDATE runs SET detail=? WHERE id=?',(core.json_text(d),result['run_id']));db.commit()
   with patch.object(rc,'validate_config',side_effect=AssertionError('refuse before daemon')),self.assertRaisesRegex(core.UserError,'audited registration'):rc.recover_before_retry(root,db)
 def test_historical_none_registration_remains_offline_compatible(self):
  with core.connect(self.ws,'A') as (root,db):
   result=self.contained(root,db,None);db.execute("UPDATE runs SET detail=json_remove(detail,'$.report_origin')");rows=list(db.execute('SELECT id,detail FROM audit'));previous='0'*64
   for row in rows:
    d=json.loads(row['detail']);d.pop('report_origin',None);detail=core.json_text(d);event=db.execute('SELECT at,action FROM audit WHERE id=?',(row['id'],)).fetchone();digest=hashlib.sha256(core.json_text([event['at'],event['action'],detail,previous]).encode()).hexdigest();db.execute('UPDATE audit SET detail=?,previous_hash=?,hash=? WHERE id=?',(detail,previous,digest,row['id']));previous=digest
   db.commit()
   with patch.object(rc,'validate_config',side_effect=AssertionError('historical settled no runtime')):rc.recover_before_retry(root,db)
   self.assertEqual(self.contained(root,db,None)['status'],'complete')
 def rechain(self,db):
  previous='0'*64
  for event in list(db.execute('SELECT * FROM audit ORDER BY id')):
   digest=hashlib.sha256(core.json_text([event['at'],event['action'],event['detail'],previous]).encode()).hexdigest();db.execute('UPDATE audit SET previous_hash=?,hash=? WHERE id=?',(previous,digest,event['id']));previous=digest
  db.commit()
 def test_mutable_row_boolean_float_origin_aliases_refuse_before_runtime_or_newrun(self):
  for case,value,field in [('A',True,'file_id'),('B',1.0,'file_id'),('size-float',None,'size')]:
   if case not in ('A','B'):core.create_case(self.ws,case)
   with self.subTest(value=value,field=field),core.connect(self.ws,case) as (root,db):
    selected,_=self.originals(root,db);self.assertEqual(selected,1);result=self.contained(root,db,selected);row=db.execute('SELECT detail FROM runs').fetchone();d=json.loads(row[0]);d['report_origin'][field]=float(d['report_origin'][field]) if value is None else value;db.execute('UPDATE runs SET detail=?',(core.json_text(d),));db.commit();before=db.execute('SELECT count(*) FROM evidence').fetchone()[0]
    with patch.object(rc,'validate_config',side_effect=AssertionError('refuse before daemon')),self.assertRaisesRegex(core.UserError,'audited registration'):rc.recover_before_retry(root,db)
    with self.assertRaisesRegex(core.UserError,'audited registration'):self.contained(root,db,selected)
    self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],1);self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0],before)
 def test_typed_terminal_origin_aliases_refuse_for_complete_and_reconciled_before_runtime(self):
  for index,(action,value) in enumerate((('parsed_import.complete',True),('parsed_import.complete',1.0),('parsed_import.container_reconciled',True),('parsed_import.container_reconciled',1.0))):
   case='terminal-'+str(index);core.create_case(self.ws,case)
   with self.subTest(action=action,value=value),core.connect(self.ws,case) as (root,db):
    selected,_=self.originals(root,db);result=self.contained(root,db,selected);event=db.execute("SELECT id,detail FROM audit WHERE action='parsed_import.complete'").fetchone();claim=json.loads(event['detail']);claim['report_origin']['file_id']=value;db.execute('UPDATE audit SET action=?,detail=? WHERE id=?',(action,core.json_text(claim),event['id']));self.rechain(db)
    with patch.object(rc,'validate_config',side_effect=AssertionError('terminal must refuse first')),self.assertRaisesRegex(core.UserError,'terminal origin'):rc.recover_before_retry(root,db)
    with self.assertRaisesRegex(core.UserError,'terminal origin'):self.contained(root,db,selected)
    self.assertEqual(db.execute('SELECT count(*) FROM runs').fetchone()[0],1)
 def test_typed_started_origin_alias_refuses_and_none_equality_is_valid(self):
  self.assertTrue(rc._same_origin(None,None));self.assertFalse(rc._same_origin(None,{}));self.assertFalse(rc._same_origin({},{}))
  with core.connect(self.ws,'A') as (root,db):
   selected,_=self.originals(root,db);self.contained(root,db,selected);event=db.execute("SELECT id,detail FROM audit WHERE action='parsed_import.started'").fetchone();claim=json.loads(event['detail']);claim['report_origin']['file_id']=True;db.execute('UPDATE audit SET detail=? WHERE id=?',(core.json_text(claim),event['id']));self.rechain(db)
   with patch.object(rc,'validate_config',side_effect=AssertionError('start must refuse first')),self.assertRaisesRegex(core.UserError,'audited registration'):rc.recover_before_retry(root,db)
 def test_unbound_samepath_distinctpath_and_labels_always_new_occurrence(self):
  other=self.base/'other'/'report.jsonl';other.parent.mkdir();other.write_bytes(self.source.read_bytes())
  with core.connect(self.ws,'A') as (root,db),patch.object(rc,'configured',return_value=self.cfg),patch.object(rc,'run',side_effect=self.decode):
   results=[parsed.import_parsed(root,db,path,'jsonl',label,contained=True) for path,label in ((self.source,'first'),(self.source,'first'),(other,'second'))]
   self.assertEqual(len({r['evidence_id'] for r in results}),3)
   for result in results:self.assertEqual(result['status'],'complete');self.assertEqual(result['records'],1);self.assertFalse(result['reuse_available']);self.assertIn('always create a new occurrence',result['reuse_unavailable_reason'])
   messages=[json.loads(r[0])['message']['conversation_id'] for r in db.execute('SELECT data FROM artifacts')];self.assertEqual(len(set(messages)),3)
 def test_noncontained_host_rawpath_reuse_unchanged(self):
  with core.connect(self.ws,'A') as (root,db):
   one=parsed.import_parsed(root,db,self.source,'jsonl');repeat=parsed.import_parsed(root,db,self.source,'jsonl');self.assertEqual(repeat['status'],'already_imported');self.assertEqual(repeat['records'],0);self.assertEqual(repeat['evidence_id'],one['evidence_id'])
if __name__=='__main__':unittest.main()
