"""Known answers come from independent Apple Foundation archives, not our encoder."""
import hashlib
import json
from pathlib import Path
import plistlib
import random
import unittest

from lawliet_mobile.ios_messages import MAX_BYTES, MAX_OBJECTS, decode_attributed_body

FIXTURES = json.loads((Path(__file__).parent / 'fixtures/ios_attributed_body/fixtures.json').read_text())['fixtures']


def fixture(identifier):
    return bytes.fromhex(next(row['hex'] for row in FIXTURES if row['id'] == identifier))


class AttributedBodyTests(unittest.TestCase):
    def test_independent_foundation_archives_have_exact_known_text(self):
        known = {'immutable-unicode': 'LAWLIET fixture: café 🦉\nSecond line',
                 'mutable-unicode': 'LAWLIET fixture: café 🦉\nSecond line',
                 'attribute-decoy': 'Visible message only', 'long': 'x' * 200 + '🦉',
                 'empty': '', 'literal-markers': 'NSString\0NSAttributes\n\ufffc'}
        for row in FIXTURES:
            with self.subTest(fixture=row['id']):
                raw = bytes.fromhex(row['hex'])
                expected = known[row['id'].rsplit('-', 1)[0]]
                self.assertEqual(row['expected_text'], expected)
                result = decode_attributed_body(raw)
                self.assertEqual(result['state'], 'decoded', result)
                self.assertEqual(result['text'], expected)
                self.assertEqual(result['blob_sha256'], hashlib.sha256(raw).hexdigest())
                if row['format'] == 'typedstream':
                    start, end = result['source_byte_range']
                    self.assertEqual(raw[start:end].decode('utf-8'), expected)
                    self.assertEqual(result['source_byte_range_scope'],
                                     'attributedBody BLOB; zero-based bytes, end exclusive; not SQLite file offsets')
                    self.assertEqual(result['archive_validation'], 'text_field_only')

    def test_raw_binary_values_remain_unchanged(self):
        raw = bytearray(fixture('mutable-unicode-typedstream'))
        original = bytes(raw)
        self.assertEqual(decode_attributed_body(raw)['state'], 'decoded')
        self.assertEqual(raw, original)

    def test_no_substring_or_plain_text_guessing(self):
        for raw in (b'plain UTF-8 message', b'junk' + fixture('immutable-unicode-typedstream'),
                    b'<?xml version="1.0"?><plist><string>not decoded</string></plist>'):
            result = decode_attributed_body(raw)
            self.assertEqual(result['state'], 'unsupported')
            self.assertNotIn('text', result)

    def test_truncated_or_invalid_typed_text_is_not_returned(self):
        raw = fixture('immutable-unicode-typedstream')
        decoded = decode_attributed_body(raw)
        start, end = decoded['source_byte_range']
        for damaged in (raw[:30], raw[:start], raw[:end], raw[:start] + b'\xff' + raw[start + 1:],
                        raw[:end] + b'\x00' + raw[end + 1:]):
            with self.subTest(length=len(damaged)):
                result = decode_attributed_body(damaged)
                self.assertEqual(result['state'], 'malformed', result)
                self.assertNotIn('text', result)

    def test_unknown_typed_class_and_version_are_explicit(self):
        raw = fixture('immutable-unicode-typedstream')
        for damaged in (raw.replace(b'NSAttributedString', b'XXAttributedString', 1),
                        raw.replace(b'streamtyped', b'typedstream', 1)):
            self.assertEqual(decode_attributed_body(damaged)['state'], 'unsupported')

    def test_limits_reject_before_copy_hash_or_object_allocation(self):
        result = decode_attributed_body(b'x' * (MAX_BYTES + 1))
        self.assertEqual(result['state'], 'limit_exceeded')
        self.assertIsNone(result['blob_sha256'])
        raw = bytearray(fixture('immutable-unicode-keyed'))
        raw[-24:-16] = (MAX_OBJECTS + 1).to_bytes(8, 'big')
        self.assertEqual(decode_attributed_body(raw)['state'], 'limit_exceeded')

    def test_cycles_and_excessive_depth_rejected_before_plistlib(self):
        cyclic = []
        cyclic.append(cyclic)
        raw = plistlib.dumps(cyclic, fmt=plistlib.FMT_BINARY)
        self.assertEqual(decode_attributed_body(raw)['state'], 'malformed')
        nested = 'bottom'
        for _ in range(40):
            nested = [nested]
        self.assertEqual(decode_attributed_body(plistlib.dumps(nested, fmt=plistlib.FMT_BINARY))['state'], 'limit_exceeded')

    def test_previously_visited_shared_subtree_does_not_bypass_depth_limit(self):
        shared = 'bottom'
        for _ in range(20):
            shared = [shared]
        deeper = shared
        for _ in range(20):
            deeper = [deeper]
        # Visit the shared tail shallowly first, then reach it via a deeper path.
        raw = plistlib.dumps([shared, deeper], fmt=plistlib.FMT_BINARY)
        self.assertEqual(decode_attributed_body(raw)['state'], 'limit_exceeded')

    def test_keyed_version_must_be_exact_integer(self):
        for value in (100000.0, '100000', True, [], {}):
            archive = plistlib.loads(fixture('immutable-unicode-keyed'))
            archive['$version'] = value
            result = decode_attributed_body(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
            self.assertEqual(result['state'], 'unsupported')
            self.assertNotIn('text', result)

    def test_keyed_reference_and_class_shapes_do_not_fabricate_text(self):
        for modification in ('class-list', 'class-dict', 'wrong-root-class', 'bad-string-reference', 'string-cycle'):
            archive = plistlib.loads(fixture('mutable-unicode-keyed'))
            root = archive['$objects'][archive['$top']['root'].data]
            descriptor = archive['$objects'][root['$class'].data]
            if modification == 'class-list':
                descriptor['$classname'] = []
            elif modification == 'class-dict':
                descriptor['$classname'] = {}
            elif modification == 'wrong-root-class':
                descriptor['$classname'] = 'NSDictionary'
            elif modification == 'bad-string-reference':
                root['NSString'] = plistlib.UID(10000)
            else:
                root['NSString'] = archive['$top']['root']
            result = decode_attributed_body(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
            self.assertIn(result['state'], ('unsupported', 'malformed'))
            self.assertNotIn('text', result)

    def test_absent_and_nonbinary_values(self):
        for value in (None, b'', bytearray()):
            self.assertEqual(decode_attributed_body(value)['state'], 'absent')
        for value in ('text', 123, {}, []):
            self.assertEqual(decode_attributed_body(value)['state'], 'unsupported')

    def test_bounded_corrupt_archives_never_raise_or_return_decoy_text(self):
        rng = random.Random(818)
        for name in ('attribute-decoy-keyed', 'attribute-decoy-typedstream'):
            raw = fixture(name)
            for _ in range(300):
                corrupted = bytearray(raw)
                for _ in range(rng.randrange(1, 4)):
                    corrupted[rng.randrange(len(raw))] = rng.randrange(256)
                result = decode_attributed_body(corrupted)
                self.assertIn(result['state'], ('decoded', 'unsupported', 'malformed', 'limit_exceeded'))
                if result['state'] == 'decoded':
                    self.assertNotIn('DECOY ATTRIBUTE TEXT', result['text'])


if __name__ == '__main__':
    unittest.main()
