"""Tiny grouping-reference parity and exact budget controls; no external fixtures."""
import copy,json,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile import core,investigator_view as view
from tests import test_investigator_view as fixtures
# Small reference composition of the unchanged grouping API; no external files.
legacy=SimpleNamespace(iter_artifacts=core.iter_artifacts)
def grouped_reference(db,selection,offset,limit):
 rows=list(legacy.iter_artifacts(db,limit=view.MAX_RECORDS+1,**selection))
 entries=view.message_entries(rows)
 return {'records':entries[offset:offset+limit],'has_more':offset+limit<len(entries),'offset':offset,
         'summary':{'version':'investigator-view/2','kind':'messages','matching_entries':len(entries),
                    'source_records':len(rows),'meaning':'Matching Discord IDs and content within one evidence bundle share an entry; original report observations remain available. Other sources remain separate.'}}
legacy.investigator_records=grouped_reference
class MessagePagination(unittest.TestCase):
 def row(self,name,discord=False):
  row=fixtures.MessagePresentationTests().row(name)
  if not discord:row['parser']='native/0.1.12'
  return row
 def test_late_discord_observation_preserved_only_page_is_projected(self):
  rows=[self.row(str(i)) for i in range(8)];rows[2]=self.row('discord-first',True);rows.append({**self.row('discord-last',True),'source_ref':'report:record=99'})
  with patch.object(legacy,'iter_artifacts',side_effect=lambda *a,**k:iter(copy.deepcopy(rows))):expected=legacy.investigator_records(None,{'category':'messages'},2,1)
  with patch.object(view,'iter_artifacts',side_effect=lambda *a,**k:iter(copy.deepcopy(rows))),patch.object(view,'display_record',wraps=view.display_record) as projected:
   actual=view.investigator_records(None,{'category':'messages'},2,1)
  self.assertEqual(actual,expected);self.assertEqual(projected.call_count,1);self.assertEqual([r['id'] for r in actual['records'][0]['investigator_view']['observations']],['discord-first','discord-last']);self.assertEqual(actual['summary']['matching_entries'],8);self.assertEqual(actual['summary']['source_records'],9)
 def test_real_db_filters_sorts_pages_and_historical_slices_exactly_match(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp).resolve();ws=base/'cases';core.create_case(ws,'A');source=base/'source.txt';source.write_text('tiny fixture')
   with core.connect(ws,'A') as (root,db):
    eid=core.import_evidence(root,db,source,'android')[0];fid=db.execute('SELECT id FROM files').fetchone()[0]
    for i in range(9):
     discord=i in (1,7);r=self.row(str(i),discord);data=copy.deepcopy(r['data']);data['_leapp_fields']['Count']=str(i);stamp=r['timestamp'] if discord else f'2023-09-{19+i:02d}T00:00:00Z';body=r['body'] if discord else ('東京 %_'+str(i));core.add_artifact(db,eid,fid,'messages',stamp,None,'Title'+str(i),body,'row='+str(i),r['parser'],data)
    db.commit();before=[tuple(r) for r in db.execute('SELECT * FROM artifacts')];audit=[tuple(r) for r in db.execute('SELECT * FROM audit')]
    selections=[{}, {'query':'東京'}, {'app':'discord'}, {'since':'2023-09-20','until':'2023-09-25'}, {'evidence':eid}, {'report':'discordChats'}, {'sort_field':'Count','sort_mode':'number','sort_direction':'desc'}, {'sort_field':'Count','sort_direction':'asc'}]
    for selection in selections:
     for offset,limit in [(0,2),(1,3),(7,2),(50,2),(0,0),(-2,1),(2,-1)]:
      scope={'category':'messages',**selection}
      with self.subTest(scope=scope,offset=offset,limit=limit):self.assertEqual(view.investigator_records(db,scope,offset,limit),legacy.investigator_records(db,scope,offset,limit))
    self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM artifacts')],before);self.assertEqual([tuple(r) for r in db.execute('SELECT * FROM audit')],audit)
 def test_oversized_offpage_record_still_refuses_entire_page(self):
  rows=[self.row('first'),self.row('offpage')];rows[1]['body']='東京'*2048;budget=len(json.dumps(rows[0],ensure_ascii=False).encode())+100
  with patch.object(view,'iter_artifacts',return_value=iter(rows)),patch.object(view,'MAX_BYTES',budget),self.assertRaisesRegex(core.UserError,'byte budget'):view.investigator_records(None,{'category':'messages'},0,1)
 def test_offpage_record_sentinel_and_exact_byte_boundary_match_legacy(self):
  rows=[self.row('one'),self.row('two'),self.row('three')];size=sum(len(json.dumps(r,ensure_ascii=False).encode()) for r in rows)
  for module in (view,):
   with patch.object(module,'iter_artifacts',return_value=iter(copy.deepcopy(rows))),patch.object(module,'MAX_RECORDS',2),self.assertRaisesRegex(core.UserError,'record budget'):module.investigator_records(None,{'category':'messages'},0,1)
   for budget,accepted in ((size,True),(size-1,False)):
    with patch.object(module,'iter_artifacts',return_value=iter(copy.deepcopy(rows))),patch.object(module,'MAX_BYTES',budget):
     if accepted:self.assertEqual(len(module.investigator_records(None,{'category':'messages'},0,1)['records']),1)
     else:
      with self.assertRaisesRegex(core.UserError,'byte budget'):module.investigator_records(None,{'category':'messages'},0,1)
if __name__=='__main__':unittest.main()
