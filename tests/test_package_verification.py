import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.core import create_case, connect, import_evidence, add_artifact
from lawliet_mobile import investigation as inv
from lawliet_mobile import investigation_report as report
from lawliet_mobile.package_verification import verify_package, PackageError


class PackageVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / 'cases'
        create_case(self.ws, 'A')
        source = self.base / 'source.txt'
        source.write_text('PRIVATE_CANARY original evidence')
        with connect(self.ws, 'A') as (root, db):
            eid = import_evidence(root, db, source, 'unknown')[0]
            fid = db.execute('SELECT id FROM files').fetchone()[0]
            add_artifact(db, eid, fid, 'messages', None, 'unknown', 'Title', 'PRIVATE_CANARY body', 'line=1', 'native/0.1.11', {})
            aid = db.execute('SELECT id FROM artifacts').fetchone()[0]
            iid = inv.create(db, 'Question', [eid])['id']
            inv.note(db, iid, 'observation', 'PRIVATE_CANARY observation', [aid])
            inv.note(db, iid, 'question', 'Unanswered')
            draft = report.build_customer_draft(root, db, iid)
            redacted = report.create_redacted_customer_draft(root, db, draft['draft_id'], ['PRIVATE_CANARY'])
            report.approve_customer_draft(root, db, draft['draft_id'], 'Synthetic operator', 'Test only')
            report.release_customer_draft(root, db, draft['draft_id'], self.base / 'released')
        self.package = self.base / 'recipient'
        shutil.copytree(draft['path'], self.package)
        self.redacted = self.base / 'redacted'
        shutil.copytree(redacted['path'], self.redacted)
        # Deliberately remove the originating case/evidence: recipient checks
        # must work without them and must never follow reference locators.
        shutil.rmtree(self.ws)
        source.unlink()
        self.before = {p.name: p.read_bytes() for p in self.package.iterdir()}

    def rewrite(self, filename, transform):
        path = self.package / filename
        value = json.loads(path.read_text())
        transform(value)
        path.write_text(json.dumps(value))
        self.rehash()

    def rehash(self):
        path = self.package / 'manifest.json'
        manifest = json.loads(path.read_text())
        for entry in manifest['files']:
            data = (self.package / entry['path']).read_bytes()
            entry.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        path.write_text(json.dumps(manifest))

    def reconcile_investigation_receipt(self):
        path = self.package/'investigation.json.receipt.json'
        receipt = json.loads(path.read_text())
        data = (self.package/'investigation.json').read_bytes()
        receipt.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        path.write_text(json.dumps(receipt))
        self.rehash()

    def test_original_and_redacted_without_case_or_network(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = verify_package(self.package)
            masked = verify_package(self.redacted)
        self.assertTrue(result['ok'])
        self.assertEqual(result['anchor'], 'self_consistency_only')
        self.assertEqual(result['counts'], {'entries': 2, 'unique_cited_artifacts': 1})
        self.assertEqual(result['source_tiers'], {'supplied-file; acquisition tier unverified': 1})
        self.assertTrue(masked['ok'])
        self.assertEqual({p.name:p.read_bytes() for p in self.package.iterdir()}, self.before)

    def test_external_anchor_and_wrong_anchor(self):
        sha = hashlib.sha256((self.package / 'manifest.json').read_bytes()).hexdigest()
        self.assertEqual(verify_package(self.package, sha)['anchor'], 'matches_supplied_digest')
        for invalid in ['0'*64, 'bad', '../../manifest']:
            with self.assertRaises(PackageError):
                verify_package(self.package, invalid)

    def test_manifest_investigation_identity_must_match_payload(self):
        for wrong in ['other-investigation', None, '', 42]:
            with self.subTest(identity=wrong):
                manifest=json.loads(self.before['manifest.json'])
                manifest['investigation_id']=wrong
                (self.package/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(PackageError,'identit'):
                    verify_package(self.package)

    def test_export_receipt_identity_must_match_payload(self):
        for field,wrong in [('investigation_id','other-investigation'),('case_id','other-case'),
                            ('investigation_id',None),('case_id',None)]:
            with self.subTest(field=field,identity=wrong):
                receipt=json.loads(self.before['investigation.json.receipt.json'])
                receipt[field]=wrong
                (self.package/'investigation.json.receipt.json').write_text(json.dumps(receipt))
                self.rehash()
                with self.assertRaisesRegex(PackageError,'identit'):
                    verify_package(self.package)

    def test_missing_payload_identity_is_not_self_consistent(self):
        investigation=json.loads(self.before['investigation.json'])
        annex=json.loads(self.before['technical-annex.json'])
        investigation['investigation']['id']=None
        annex['investigation_id']=None
        (self.package/'investigation.json').write_text(json.dumps(investigation))
        (self.package/'technical-annex.json').write_text(json.dumps(annex))
        receipt=json.loads(self.before['investigation.json.receipt.json'])
        data=(self.package/'investigation.json').read_bytes()
        receipt.update(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))
        (self.package/'investigation.json.receipt.json').write_text(json.dumps(receipt))
        self.rehash()
        with self.assertRaisesRegex(PackageError,'identit'):verify_package(self.package)

    def test_redacted_contract_omits_manifest_and_receipt_identity(self):
        manifest=json.loads((self.redacted/'manifest.json').read_text())
        self.assertNotIn('investigation_id',manifest)
        self.assertFalse((self.redacted/'investigation.json.receipt.json').exists())
        self.assertTrue(verify_package(self.redacted)['ok'])

    def test_tampered_missing_and_unexpected_members(self):
        path = self.package / 'report.txt'
        path.write_text('tampered')
        with self.assertRaises(PackageError): verify_package(self.package)
        path.write_bytes(self.before['report.txt'])
        (self.package / 'unexpected.html').write_text('<script>inert</script>')
        with self.assertRaises(PackageError): verify_package(self.package)
        (self.package / 'unexpected.html').unlink()
        path.unlink()
        with self.assertRaises(OSError): verify_package(self.package)

    def test_paths_duplicate_manifest_and_versions_refused(self):
        original = (self.package / 'manifest.json').read_bytes()
        for transform in [lambda m:m['files'][0].update(path='../outside'),
                          lambda m:m['files'][0].update(path='/tmp/outside'),
                          lambda m:m['files'].__setitem__(0, m['files'][1]),
                          lambda m:m.update(format='future-v99'),
                          lambda m:m['files'][0].update(bytes=True)]:
            m = json.loads(original); transform(m)
            (self.package / 'manifest.json').write_text(json.dumps(m))
            with self.assertRaises(PackageError): verify_package(self.package)
        (self.package / 'manifest.json').write_bytes(b'{"format":"duplicate",'+original.lstrip()[1:])
        with self.assertRaises(PackageError): verify_package(self.package)

    def test_symlinks_hardlinks_and_fifo_refused(self):
        link = self.base / 'linked-directory'; link.symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(OSError): verify_package(link)
        target = self.package / 'report.txt'; target.unlink(); target.symlink_to(self.base / 'missing')
        with self.assertRaises(OSError): verify_package(self.package)
        target.unlink(); target.write_bytes(self.before['report.txt']); os.link(target, self.base/'hardlink')
        with self.assertRaises(PackageError): verify_package(self.package)
        (self.base/'hardlink').unlink(); target.unlink(); os.mkfifo(target)
        with self.assertRaises(PackageError): verify_package(self.package)

    def test_semantic_citation_mismatch_despite_valid_hashes(self):
        self.rewrite('technical-annex.json', lambda a:a['citations'][0].update(source_tier='fabricated'))
        with self.assertRaises(PackageError): verify_package(self.package)
        annex=json.loads((self.package/'technical-annex.json').read_text())
        (self.package/'exhibits.jsonl').write_text(json.dumps(annex['citations'][0])+'\n')
        self.rehash()
        with self.assertRaisesRegex(PackageError,'tier'):verify_package(self.package)

    def test_rehashed_tamper_cannot_match_prior_external_anchor(self):
        sha=hashlib.sha256((self.package/'manifest.json').read_bytes()).hexdigest()
        (self.package/'report.txt').write_text('replaced readable report')
        self.rehash()
        # A self-consistent attacker-controlled package cannot authenticate itself.
        self.assertTrue(verify_package(self.package)['ok'])
        with self.assertRaisesRegex(PackageError,'digest'):verify_package(self.package,sha)

    def test_unresolved_entry_despite_valid_hashes(self):
        self.rewrite('technical-annex.json', lambda a:a['entries'][0]['artifact_ids'].append('wrong-case'))
        with self.assertRaisesRegex(PackageError, 'unresolved'): verify_package(self.package)

    def test_rehashed_annex_entry_must_match_investigation(self):
        for field, value in [('text', 'CONTRADICTORY_TEXT'), ('kind', 'task'),
                             ('entry_id', 'OTHER_ENTRY'), ('artifact_ids', [])]:
            with self.subTest(field=field):
                for name, data in self.before.items():
                    (self.package/name).write_bytes(data)
                def transform(annex):
                    index = next(i for i,e in enumerate(annex['entries']) if e['artifact_ids']) if field == 'artifact_ids' else 0
                    annex['entries'][index].update({field:value})
                self.rewrite('technical-annex.json', transform)
                with self.assertRaises(PackageError):
                    verify_package(self.package)

    def test_rehashed_exhibit_and_annex_snapshot_must_match_investigation(self):
        annex = json.loads(self.before['technical-annex.json'])
        annex['citations'][0]['snapshot']['body'] = 'CONTRADICTORY_SNAPSHOT'
        (self.package/'technical-annex.json').write_text(json.dumps(annex))
        (self.package/'exhibits.jsonl').write_text(''.join(json.dumps(c)+'\n' for c in annex['citations']))
        self.rehash()
        with self.assertRaisesRegex(PackageError, 'snapshots disagree'):
            verify_package(self.package)

    def test_missing_investigation_entry_section_cannot_match_annex(self):
        investigation = json.loads(self.before['investigation.json'])
        del investigation['observation_entries']
        (self.package/'investigation.json').write_text(json.dumps(investigation))
        self.reconcile_investigation_receipt()
        with self.assertRaisesRegex(PackageError, 'entry section'):
            verify_package(self.package)

    def test_wrong_counts_and_chronology(self):
        path = self.package/'technical-annex.json'; original = path.read_bytes()
        self.rewrite('technical-annex.json', lambda a:a['chronology_artifact_ids'].append(a['chronology_artifact_ids'][0]))
        with self.assertRaisesRegex(PackageError, 'chronology'): verify_package(self.package)
        path.write_bytes(original); self.rehash()
        m=json.loads((self.package/'manifest.json').read_text());m['counts']['entries']=99
        (self.package/'manifest.json').write_text(json.dumps(m))
        with self.assertRaisesRegex(PackageError, 'counts'): verify_package(self.package)

    def test_snapshot_identity_and_locator_divergence(self):
        for key,value in [('id','wrong-id'),('source_ref','wrong-row')]:
            annex=json.loads(self.before['technical-annex.json'])
            annex['citations'][0]['snapshot'][key]=value
            (self.package/'technical-annex.json').write_text(json.dumps(annex))
            (self.package/'exhibits.jsonl').write_text(json.dumps(annex['citations'][0])+'\n')
            self.rehash()
            with self.assertRaises(PackageError):verify_package(self.package)

    def test_incomplete_locator_remains_explicit(self):
        annex=json.loads(self.before['technical-annex.json'])
        annex['citations'][0]['snapshot']['source_ref']=None
        annex['citations'][0]['source_locator']['record_table_key_or_offset']=None
        (self.package/'technical-annex.json').write_text(json.dumps(annex))
        (self.package/'exhibits.jsonl').write_text(json.dumps(annex['citations'][0])+'\n')
        investigation = json.loads(self.before['investigation.json'])
        for event in investigation['observation_entries']:
            for snapshot in event['result']['citations']:
                snapshot['source_ref'] = None
        (self.package/'investigation.json').write_text(json.dumps(investigation))
        self.reconcile_investigation_receipt()
        self.assertEqual(verify_package(self.package)['citations_with_incomplete_recorded_locators'],1)

    def test_size_limit_and_final_mutation(self):
        with patch('lawliet_mobile.package_verification.MAX_FILE', 10):
            with self.assertRaises(PackageError): verify_package(self.package)
        from lawliet_mobile import package_verification as mod
        original=mod._json
        def mutate(data):
            value=original(data)
            if isinstance(value,dict) and value.get('format')=='ancalor-investigation-export-receipt-v1':
                (self.package/'report.txt').write_text('changed during verification')
            return value
        with patch.object(mod,'_json',side_effect=mutate):
            with self.assertRaisesRegex(PackageError, 'changed'): verify_package(self.package)

    def test_local_release_receipt_is_not_authenticated_approval(self):
        result=verify_package(self.base/'released')
        self.assertTrue(result['release_receipt_present'])
        self.assertEqual(result['anchor'],'self_consistency_only')
        p=self.base/'released/release-receipt.json';r=json.loads(p.read_text());r['manifest_sha256']='0'*64;p.write_text(json.dumps(r))
        with self.assertRaisesRegex(PackageError,'receipt'):verify_package(self.base/'released')
