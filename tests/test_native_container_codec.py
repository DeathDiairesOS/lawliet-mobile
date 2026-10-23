import copy
import hashlib
import json
import math
import unittest
from unittest.mock import patch

from lawliet_mobile import native_container_codec as codec
from lawliet_mobile.core import json_text


def encode(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode() + b'\n'


class CodecTests(unittest.TestCase):
    def setUp(self):
        self.bindings = {key: 'a' * 64 for key in codec.BINDINGS}
        self.bindings.update(protocol=codec.PROTOCOL, evidence_id='abcdef012345', native_parser_version='native/0.1.12')
        self.manifest = [dict(id=1, path='sms.db', logical_path='HomeDomain/sms.db', sha256='1'*64, bytes=5),
                         dict(id=2, path='image.jpg', logical_path='MediaDomain/image.jpg', sha256='2'*64, bytes=3),
                         dict(id=3, path='sms.db-wal', logical_path='HomeDomain/sms.db-wal', sha256='3'*64, bytes=2)]
        self.row = dict(kind='artifact', seq=1, evidence_id=self.bindings['evidence_id'], file_id=1,
                        category='messages', timestamp=None, timestamp_raw='712345678900000001',
                        title='Test 雪', body='', source_ref='message:rowid=1', parser='native/0.1.12',
                        data_json=json_text({'raw_record': {'file_id': 999, 'blob_bytes': 8}}))
        self.detail = dict(sqlite_files_examined=1, databases_with_records=1, errors=[],
                           unparsed_candidates=[], coverage='Baseline only; absence not established.')
        self.runtime = dict(python_version='3.14.5', sqlite_version='3.46.1')

    def stream(self, rows=None, *, detail=None, status='complete', header=None, footer=None):
        rows = [self.row] if rows is None else rows
        frames = b''.join(encode(r) for r in rows)
        final = dict(kind='final', protocol=codec.PROTOCOL,
                     request_sha256=self.bindings['request_sha256'], source_manifest_sha256=self.bindings['source_manifest_sha256'],
                     artifact_count=len(rows), artifact_bytes=len(frames), artifacts_sha256=hashlib.sha256(frames).hexdigest(),
                     native_status=status, native_detail_json=json_text(self.detail if detail is None else detail), runtime=self.runtime)
        final.update(footer or {})
        return encode(header or {'kind': 'header', **self.bindings}) + frames + encode(final)

    def validate(self, raw=None):
        return codec.validate(self.stream() if raw is None else raw, self.bindings, self.manifest)

    def reject(self, **changes):
        with self.assertRaises(codec.ValidationError):
            self.validate(self.stream(**changes))

    def test_exact_unicode_raw_timestamp_and_unrelated_raw_file_id(self):
        result = self.validate()
        row = next(result.iter_artifacts())
        self.assertEqual(row['data_json'], self.row['data_json'])
        self.assertEqual(row['timestamp_raw'], '712345678900000001')
        self.assertEqual(row['title'], 'Test 雪')
        self.assertEqual(row['data']['raw_record']['file_id'], 999)
        self.assertEqual(list(result.iter_artifacts()), list(result.iter_artifacts()))

    def test_reviewed_parser_versions_remain_exactly_bound(self):
        for version in ('native/0.1.12', 'native/0.1.13'):
            with self.subTest(version=version):
                self.bindings['native_parser_version'] = version
                self.row['parser'] = version
                self.assertEqual(next(self.validate().iter_artifacts())['parser'], version)
                other = 'native/0.1.12' if version == 'native/0.1.13' else 'native/0.1.13'
                self.reject(rows=[{**self.row, 'parser': other}])
                self.reject(header={'kind': 'header', **self.bindings, 'native_parser_version': other})
        self.bindings['native_parser_version'] = self.row['parser'] = 'native/999.0'
        with self.assertRaisesRegex(codec.ValidationError, 'Unsupported native schema version'):
            self.validate()

    def test_current_parser_requires_explicit_codec_qualification(self):
        from lawliet_mobile.parsers import VERSION
        self.assertIn(VERSION, codec.SUPPORTED_NATIVE_VERSIONS,
                      'Parser changed: review the host codec and qualify its output before enabling this version.')

    def test_legacy_nonfinite_inner_retained(self):
        self.row['data_json'] = json_text({'a': float('nan'), 'b': float('inf'), 'c': -float('inf')})
        row = next(self.validate().iter_artifacts())
        self.assertTrue(math.isnan(row['data']['a']))
        self.assertEqual(row['data_json'], self.row['data_json'])

    def test_empty_supported_and_unsupported_are_distinct(self):
        self.detail.update(databases_with_records=0, unparsed_candidates=[dict(source='HomeDomain/sms.db', state='unsupported', reason='Unknown schema')])
        result = self.validate(self.stream(rows=[]))
        self.assertEqual(result.artifact_count, 0)
        self.assertEqual(result.detail['unparsed_candidates'][0]['state'], 'unsupported')

    def test_partial_preserves_source_failure(self):
        self.detail['errors'] = [dict(source='HomeDomain/sms.db', error='Malformed source')]
        result = self.validate(self.stream(status='partial'))
        self.assertEqual(result.footer['native_status'], 'partial')
        self.reject(status='complete')

    def test_malformed_transport(self):
        raw = self.stream()
        cases = [raw[:-1], raw + b'\n', b'\xef\xbb\xbf' + raw, raw + encode({'kind': 'final'}), raw.replace(b'Test', b'\xff'), raw.splitlines(keepends=True)[0]]
        for value in cases:
            with self.subTest(value=value[:30]), self.assertRaises(codec.ValidationError): self.validate(value)

    def test_duplicate_keys_and_outer_nonfinite(self):
        raw = self.stream()
        cases = [raw.replace(b'"kind":"header"', b'"kind":"header","kind":"header"'),
                 raw.replace(b'"seq":1', b'"seq":NaN'), raw.replace(b'"seq":1', b'"seq":1e999')]
        for value in cases:
            with self.subTest(value=value[:30]), self.assertRaises(codec.ValidationError): self.validate(value)

    def test_wrong_header_bindings(self):
        for key in codec.BINDINGS:
            header = {'kind': 'header', **self.bindings, key: 'wrong'}
            with self.subTest(key=key): self.reject(header=header)

    def test_wrong_artifact_fields(self):
        for key, value in [('seq', True), ('seq', 2), ('file_id', True), ('file_id', 999), ('evidence_id', 'foreign'), ('category', 'invented'),
                           ('parser', 'native/0.0'), ('timestamp', 12), ('timestamp_raw', 12), ('title', None), ('body', []), ('source_ref', None)]:
            with self.subTest(key=key, value=value): self.reject(rows=[{**self.row, key:value}])
        self.reject(rows=[{**self.row, 'artifact_id': 'child-controlled'}])

    def test_footer_counts_hash_binding_and_status(self):
        for key, value in [('artifact_count', True), ('artifact_count', 0), ('artifact_bytes', 1), ('artifacts_sha256', '0'*64),
                           ('request_sha256', '0'*64), ('source_manifest_sha256', '0'*64), ('protocol', 'wrong'), ('native_status', 'failed'),
                           ('native_status', 'interrupted'), ('runtime', {'python_version': 'x'})]:
            with self.subTest(key=key, value=value): self.reject(footer={key:value})

    def test_bad_inner_json(self):
        for text in ['{} ', '{"a":1}', '{"a": 1, "a": 1}', '[]', '{"a": "\\ud800"}']:
            with self.subTest(text=text): self.reject(rows=[{**self.row, 'data_json':text}])

    def test_depth_and_caps(self):
        self.reject(rows=[{**self.row, 'data_json':'{"a": ' + '['*65 + '0' + ']'*65 + '}'}])
        for name, value in [('MAX_STDOUT', 10), ('MAX_ARTIFACT_BYTES', 10), ('MAX_LINE', 10), ('MAX_COUNT', 0), ('MAX_DETAIL', 10)]:
            with self.subTest(name=name), patch.object(codec, name, value): self.reject()

    def test_retained_media_attachment_and_mms_references(self):
        ref = dict(file_id=2, logical_path='MediaDomain/image.jpg', sha256='2'*64, bytes=3)
        examples = [dict(media=dict(file_id=2, bytes=3, status='available')),
                    dict(attachment={**ref, 'status':'available'}),
                    dict(mms_schema='v1', parts=[dict(payload={**ref, 'status':'exact-retained-path-reference'})]),
                    dict(mms_schema='v1', payload={**ref, 'status':'exact-retained-path-reference'})]
        for data in examples:
            self.row['data_json'] = json_text(data)
            self.row['file_id'] = 2 if 'media' in data else 1
            self.validate()
        self.row['file_id'] = 1
        for field, value in [('file_id', 99), ('file_id', True), ('sha256', 'f'*64), ('logical_path', 'other'), ('bytes', True)]:
            data = dict(attachment={**ref, field:value, 'status':'available'})
            with self.subTest(field=field): self.reject(rows=[{**self.row, 'data_json':json_text(data)}])

    def test_unresolved_references_cannot_claim_live_ids(self):
        for status in ('not_acquired', 'external_reference', 'unsupported_reference', 'ambiguous_path'):
            self.row['data_json'] = json_text(dict(attachment=dict(file_id=None, status=status)))
            self.validate()
            self.reject(rows=[{**self.row, 'data_json':json_text(dict(attachment=dict(file_id=2, status=status)))}])
        for status in ('no-file-reference', 'unsupported-path', 'not-acquired', 'ambiguous-path'):
            self.row['data_json'] = json_text(dict(mms_schema='v1', payload=dict(file_id=None,status=status)))
            self.validate()

    def test_sidecar_and_wal_provenance(self):
        sidecar = dict(logical_path='HomeDomain/sms.db-wal', sha256='3'*64)
        data = dict(source_database='HomeDomain/sms.db', source_sidecars=[sidecar],
                    sqlite_wal_coverage=dict(source_sha256='1'*64, sidecars=[sidecar]))
        self.row['data_json'] = json_text(data)
        self.validate()
        for bad in [dict(source_database='other'), dict(source_sidecars=[{**sidecar,'sha256':'0'*64}]),
                    dict(sqlite_wal_coverage=dict(source_sha256='0'*64,sidecars=[sidecar]))]:
            self.reject(rows=[{**self.row,'data_json':json_text(bad)}])

    def test_unmapped_ambiguous_coverage_and_impossible_counts(self):
        for bad in [dict(sqlite_files_examined=True), dict(databases_with_records=2),
                    dict(unparsed_candidates=[dict(source='other')]), dict(errors=[dict(source='other')])]:
            self.reject(detail={**self.detail, **bad})
        self.manifest.append({**self.manifest[0], 'id':4, 'path':'duplicate'})
        self.reject(detail={**self.detail,'unparsed_candidates':[dict(source='HomeDomain/sms.db')]})

    def test_malformed_nested_structures_always_validation_error(self):
        for data in [dict(media=[]), dict(attachment={'status': []}), dict(mms_schema='v1',parts=None), dict(source_sidecars=[[]]), dict(sqlite_wal_coverage=[]), dict(media={'status':'available','file_id':1,'bytes':5})]:
            # Last value is valid; use a different artifact source to reject rebinding.
            row={**self.row,'data_json':json_text(data)}
            if 'media' in data and isinstance(data['media'],dict): row['file_id']=2
            self.reject(rows=[row])

    def test_unrelated_known_sidecar_cannot_substitute(self):
        self.reject(rows=[{**self.row,'data_json':json_text(dict(source_sidecars=[dict(logical_path='MediaDomain/image.jpg',sha256='2'*64)]))}])

    def test_manifest_scope_size_and_type(self):
        for field, value in [('id', True), ('bytes', True), ('bytes', 32*1024*1024+1), ('evidence_id','foreign')]:
            saved=copy.deepcopy(self.manifest)
            self.manifest[0][field]=value
            with self.subTest(field=field): self.reject()
            self.manifest=saved

    def test_many_rows_not_cached_as_decoded_objects(self):
        rows=[{**self.row,'seq':seq} for seq in range(1,2001)]
        result=self.validate(self.stream(rows=rows))
        self.assertEqual(result.artifact_count,2000)
        self.assertFalse(any(isinstance(value,list) and len(value)==2000 for value in vars(result).values()))
        self.assertEqual(sum(1 for _ in result.iter_artifacts()),2000)


if __name__ == '__main__': unittest.main()
