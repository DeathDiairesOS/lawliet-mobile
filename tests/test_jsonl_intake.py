import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lawliet_mobile.core import UserError, connect, create_case
from lawliet_mobile.parsed_import import import_parsed, _artifact_json


class JSONLIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.ws=self.base/'cases';create_case(self.ws,'A')

    def refuse(self, payload, message=None):
        source=self.base/'source.jsonl';source.write_bytes(payload if isinstance(payload,bytes) else payload.encode())
        expected=hashlib.sha256(source.read_bytes()).hexdigest()
        with connect(self.ws,'A') as (root,db):
            with self.assertRaisesRegex(UserError,message or 'Import failed'):
                import_parsed(root,db,source,'jsonl')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],0)
            runs=list(db.execute('SELECT status,records FROM runs'))
            self.assertTrue(runs);self.assertTrue(all(r['status']=='failed' and r['records']==0 for r in runs))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='parsed_import.failed'").fetchone()[0],len(runs))
            for row in db.execute('SELECT evidence_id,path,sha256 FROM files'):
                retained=root/'evidence'/row['evidence_id']/row['path']
                self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(),expected)
                self.assertEqual(row['sha256'],expected)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),expected)

    def test_duplicate_top_level_key_does_not_choose_last_body(self):
        self.refuse('{"category":"messages","body":"first","body":"last","data":{}}\n','Duplicate')

    def test_duplicate_nested_and_escaped_keys_refused(self):
        for text in ['{"a":1,"a":2}',r'{"a":1,"\u0061":2}']:
            with self.subTest(text=text):
                with self.assertRaisesRegex(UserError,'Duplicate'):_artifact_json(text)

    def test_nonfinite_constants_and_overflow_refused(self):
        for number in ['NaN','Infinity','-Infinity','1e9999','-1e9999']:
            with self.subTest(number=number),self.assertRaises(UserError):
                _artifact_json('{"number":'+number+'}')
        self.refuse('{"category":"external","body":"synthetic","data":{"score":NaN}}\n','Nonfinite')

    def test_depth_guard_before_decoder_and_sqlite_json_use(self):
        self.refuse('{"category":"external","body":"synthetic","data":{"nested":'+('['*1100)+'0'+(']'*1100)+'}}\n','depth')

    def test_exact_depth_and_one_over_with_lowered_control(self):
        with patch('lawliet_mobile.parsed_import.MAX_JSON_DEPTH',4):
            self.assertEqual(_artifact_json('{"x":[[{"y":1}]]}'),{'x':[[{'y':1}]]})
            with self.assertRaisesRegex(UserError,'depth'):_artifact_json('{"x":[[[{"y":1}]]]}')

    def test_brackets_and_escaped_quotes_inside_strings_are_data(self):
        value={'category':'external','body':'[{'*200+' \\" café 東京','data':{'valid':True,'score':1.25}}
        self.assertEqual(_artifact_json(json.dumps(value,ensure_ascii=False)),value)

    def test_utf8_byte_limit_not_character_limit(self):
        text=json.dumps({'category':'external','body':'東京'*30,'data':{}},ensure_ascii=False)+'\n'
        self.assertLess(len(text),140);self.assertGreater(len(text.encode()),140)
        with patch('lawliet_mobile.parsed_import.MAX_JSONL_LINE',140):self.refuse(text,'byte limit')

    def test_first_valid_line_is_rolled_back_after_invalid_line(self):
        good=json.dumps({'category':'external','body':'first','data':{}})+'\n'
        bad='{"category":"external","body":"second","data":{"x":1,"x":2}}\n'
        self.refuse(good+bad,'Duplicate')

    def test_decoder_recursion_failure_is_terminal_and_zero_indexed(self):
        with patch('lawliet_mobile.parsed_import._artifact_json',side_effect=RecursionError('controlled')):
            self.refuse('{"category":"external","body":"synthetic","data":{}}\n')

    def test_invalid_utf8_retained_with_failed_run(self):
        self.refuse(b'{"category":"external","body":"\xff","data":{}}\n')

    def test_utf8_bom_unicode_and_finite_values_round_trip(self):
        value={'category':'external','body':'café 東京\nsecond "line"','data':{'score':1.25,'large_int':9007199254740993,'truth':True,'none':None}}
        source=self.base/'source.jsonl';source.write_bytes(b'\xef\xbb\xbf'+(json.dumps(value,ensure_ascii=False)+'\n').encode())
        with connect(self.ws,'A') as (root,db):
            result=import_parsed(root,db,source,'jsonl');self.assertEqual(result['records'],1)
            row=db.execute('SELECT body,data FROM artifacts').fetchone();self.assertEqual(row['body'],value['body'])
            data=json.loads(row['data']);self.assertTrue(all(data[k]==v for k,v in value['data'].items()))

    def test_bom_before_initial_blank_lines_preserves_record_line_locator(self):
        for index,blank in enumerate([b'\n',b'\r\n',b' \t\n']):
            with self.subTest(blank=blank):
                case='BOM-'+str(index);create_case(self.ws,case)
                source=self.base/('blank-'+str(index)+'.jsonl')
                source.write_bytes(b'\xef\xbb\xbf'+blank+b'\n{"category":"external","body":"valid","data":{}}\n')
                with connect(self.ws,case) as (root,db):
                    result=import_parsed(root,db,source,'jsonl');self.assertEqual(result['records'],1)
                    row=db.execute('SELECT body,source_ref,data FROM artifacts').fetchone()
                    self.assertEqual(row['body'],'valid');self.assertEqual(row['source_ref'],'report:record=3')
                    self.assertEqual(json.loads(row['data'])['_import_report']['record'],3)
