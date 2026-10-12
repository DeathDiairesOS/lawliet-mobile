import json
import subprocess
import sys
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path
from lawliet_mobile import identity_associations as ia
from lawliet_mobile.core import UserError, add_artifact, connect, create_case, import_evidence, json_text, verify


class IdentityAssociationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'cases'
        create_case(self.workspace, 'one'); create_case(self.workspace, 'two')
        self.source = Path(self.temp.name) / 'source.json'
        self.source.write_text('{"synthetic":true}')
        with connect(self.workspace, 'one') as (root, db):
            eid = import_evidence(root, db, self.source)[0]
            fid = db.execute('SELECT id FROM files WHERE evidence_id=?', (eid,)).fetchone()[0]
            for profile in ['personal', 'work', 'third']:
                add_artifact(db, eid, fid, 'contacts', None, None, 'Original contact label', '', 'fixture/'+profile, 'fixture/1',
                             {'profile': profile, 'phone': '+1 202 555 0100', 'email': 'MixedCase@Example.test',
                              'a/b': {'x~y': 'escaped'}, 'numeric_id': 123, 'null_id': None})
            self.ids = [r['id'] for r in db.execute('SELECT id FROM artifacts ORDER BY source_ref')]

    def observe(self, db, index, **updates):
        value = {'kind': 'observe', 'examiner': 'Examiner A', 'rationale': 'Source-linked observation',
                 'artifact_id': self.ids[index], 'source_field': '/data/phone',
                 'identifier_type': 'phone', 'namespace': 'phone as supplied'}
        value.update(updates)
        return ia.record(db, value)

    def merge(self, db, *nodes):
        return ia.record(db, {'kind': 'merge', 'examiner': 'Examiner A', 'rationale': 'Synthetic corroboration reviewed',
                             'observation_ids': [n['id'] for n in nodes], 'confirmed': True})

    def split(self, db, event):
        return ia.record(db, {'kind': 'split', 'examiner': 'Examiner B', 'rationale': 'Withdraw this interpretation',
                             'association_id': event['id'], 'confirmed': True})

    def test_originals_preserved_reversible_and_history_reopens(self):
        with connect(self.workspace, 'one') as (root, db):
            before = [dict(r) for r in db.execute('SELECT * FROM artifacts ORDER BY id')]
            a = self.observe(db, 0); b = self.observe(db, 1)
            self.assertEqual(len(ia.groups(db)['groups']), 2)  # Equal phones do not merge.
            association = self.merge(db, a, b)
            self.assertEqual(len(ia.groups(db)['groups']), 1)
            self.split(db, association)
            self.assertEqual(len(ia.groups(db)['groups']), 2)
            self.assertEqual(before, [dict(r) for r in db.execute('SELECT * FROM artifacts ORDER BY id')])
            self.assertEqual(a['artifact_snapshot']['title'], 'Original contact label')
            self.assertNotEqual(a['artifact_snapshot']['data']['profile'], b['artifact_snapshot']['data']['profile'])
            self.assertTrue(verify(root, db)['ok'])
        with connect(self.workspace, 'one') as (_, db):
            first = ia.list_records(db, limit=2)
            second = ia.list_records(db, after=first['next_cursor'], limit=2)
            self.assertEqual([e['kind'] for e in second['records']], ['merge', 'split'])
            self.assertFalse(second['has_more'])
            self.assertEqual(len(ia.groups(db)['observations']), 2)

    def test_overlapping_transitive_assertions_withdraw_only_selected_edge(self):
        with connect(self.workspace, 'one') as (_, db):
            a, b, c = [self.observe(db, i) for i in range(3)]
            ab = self.merge(db, a, b); bc = self.merge(db, b, c); ac = self.merge(db, a, c)
            self.assertEqual(len(ia.groups(db)['groups']), 1)
            self.split(db, ab)
            self.assertEqual(len(ia.groups(db)['groups']), 1)
            self.assertEqual({e['id'] for e in ia.groups(db)['active_associations']}, {bc['id'], ac['id']})
            self.split(db, ac)
            self.assertEqual(sorted(map(len, ia.groups(db)['groups'])), [1, 2])
            with self.assertRaises(UserError): self.split(db, ab)
            self.merge(db, a, b)
            self.assertEqual(len(ia.groups(db)['groups']), 1)

    def test_exact_types_and_pointer_escapes(self):
        with connect(self.workspace, 'one') as (_, db):
            escaped = self.observe(db, 0, source_field='/data/a~1b/x~0y', identifier_type='app-id')
            self.assertEqual(escaped['raw_value'], 'escaped')
            self.assertEqual(escaped['raw_value_type'], 'json-string')
            email = self.observe(db, 0, source_field='/data/email', identifier_type='email')
            self.assertEqual(email['raw_value'], 'MixedCase@Example.test')
            numeric = self.observe(db, 0, source_field='/data/numeric_id', identifier_type='app-id')
            self.assertEqual(numeric['raw_value'], 123)
            self.assertIs(type(numeric['raw_value']), int)
            self.assertEqual(numeric['raw_value_type'], 'json-integer')
            for pointer in ['/data/numeric_id', '/data/null_id', '/data/a~2b', '/absent']:
                with self.subTest(pointer=pointer), self.assertRaises(UserError):
                    self.observe(db, 0, source_field=pointer)
            self.assertEqual(len(ia.groups(db)['observations']), 3)

    def test_confirmation_foreign_case_and_bounds_rejected_without_append(self):
        with connect(self.workspace, 'one') as (_, db):
            a, b = self.observe(db, 0), self.observe(db, 1)
            for ids, confirmed in [([a['id'], b['id']], False), ([a['id'], a['id']], True), ([a['id'], 'foreign'], True), ([a['id'], b['id']], 1)]:
                with self.assertRaises(UserError):
                    ia.record(db, {'kind': 'merge', 'examiner': 'A', 'rationale': 'x', 'observation_ids': ids, 'confirmed': confirmed})
            self.assertEqual(len(ia.list_records(db)['records']), 2)
        with connect(self.workspace, 'two') as (_, db):
            self.assertEqual(ia.groups(db)['observations'], [])
            with self.assertRaises(UserError): self.observe(db, 0)
            with self.assertRaises(UserError): self.merge(db, a, b)

    def test_saved_provenance_survives_reparse_and_tamper_is_rejected(self):
        with connect(self.workspace, 'one') as (_, db):
            a = self.observe(db, 0)
            db.execute('UPDATE artifacts SET title=? WHERE id=?', ('Later label', self.ids[0]))
            saved = ia.groups(db)['observations'][0]
            self.assertEqual(saved['artifact_snapshot']['title'], 'Original contact label')
            self.assertEqual(saved['provenance']['source_sha256'], a['provenance']['source_sha256'])
            db.execute("UPDATE audit SET detail='{}' WHERE action=?", (ia.ACTION,))
            for operation in [lambda: ia.groups(db), lambda: ia.list_records(db), lambda: self.observe(db, 1)]:
                with self.assertRaisesRegex(UserError, 'audit chain'): operation()

    def test_pointer_array_grammar_and_capacity_fail_without_append(self):
        for pointer in ['/values/01', '/values/١', '/values/-1', '/values/-']:
            with self.subTest(pointer=pointer), self.assertRaises(UserError):
                ia._pointer({'values': ['zero', 'one']}, pointer)
        self.assertEqual(ia._pointer({'values': ['zero', 'one']}, '/values/1'), 'one')
        with connect(self.workspace, 'one') as (_, db):
            self.observe(db, 0)
            with patch.object(ia, 'MAX_EVENTS', 1), self.assertRaises(UserError):
                self.observe(db, 1)
            with patch.object(ia, 'MAX_HISTORY_BYTES', 1):
                with self.assertRaises(UserError): ia.groups(db)
                with self.assertRaises(UserError): self.observe(db, 1)
            self.assertEqual(len(ia.list_records(db)['records']), 1)

    def test_actual_stdio_bridge_reversible_and_case_scoped(self):
        def call(action, case='one', **values):
            proc = subprocess.run([sys.executable, '-m', 'lawliet_mobile.app_backend'],
                input=json.dumps({'workspace': str(self.workspace), 'case': case, 'action': action, **values}),
                text=True, capture_output=True, check=False)
            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0 if result['ok'] else 1)
            return result
        nodes=[]
        for artifact in self.ids[:2]:
            result=call('identity-record', event={'kind':'observe','artifact_id':artifact,
                'source_field':'/data/phone','identifier_type':'phone','namespace':'supplied phone',
                'examiner':'A','rationale':'Synthetic fixture observation'})
            self.assertTrue(result['ok'], result);nodes.append(result['result']['id'])
        self.assertEqual(len(call('identity-groups')['result']['groups']), 2)
        merged=call('identity-record', event={'kind':'merge','observation_ids':nodes,
            'confirmed':True,'examiner':'A','rationale':'Explicit synthetic confirmation'})
        self.assertTrue(merged['ok'], merged)
        self.assertEqual(len(call('identity-groups')['result']['groups']), 1)
        split=call('identity-record', event={'kind':'split','association_id':merged['result']['id'],
            'confirmed':True,'examiner':'A','rationale':'Withdraw assertion'})
        self.assertTrue(split['ok'], split)
        self.assertEqual(len(call('identity-groups')['result']['groups']), 2)
        self.assertEqual(len(call('identity-history')['result']['records']), 4)
        self.assertEqual(call('identity-groups',case='two')['result']['observations'], [])
        self.assertFalse(call('identity-record',event=None)['ok'])
