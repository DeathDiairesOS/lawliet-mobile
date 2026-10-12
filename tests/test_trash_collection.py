import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lawliet_mobile.acquisition import collect_android
from lawliet_mobile.core import create_case, connect, verify
from lawliet_mobile.parsers import native_analyze
from lawliet_mobile.app_backend import handle

class TrashCollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ws=Path(self.tmp.name)/'cases';create_case(self.ws,'qa')
        self.remote="/sdcard/Android/.Trash/gallery/uuid/storage/DCIM/.!%#@$/photo '$(test).jpg"
        self.image=b'\xff\xd8\xff'+bytes(128)
        self.hash=hashlib.sha256(self.image).hexdigest();self.calls=[]
    def execute(self, argv, output, timeout, guard=None):
        self.calls.append(argv);output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
        if 'get-state' in argv: output.write_text('device\n')
        elif argv[-1] == 'getprop': output.write_text('[ro.product.model]: [Synthetic phone]\n')
        elif argv[-1] == 'version': output.write_text('Synthetic ADB fixture\n')
        elif argv[-1].startswith('date '): output.write_text('2026-10-11T21:10:56-0400\n')
        elif argv[-1].startswith('find '): output.write_bytes(self.listing)
        elif argv[-1].startswith('sha256sum '):
            count=sum(c[-1].startswith('sha256sum ') for c in self.calls)
            output.write_text((self.hash if not self.changed or count==1 else '0'*64)+'  '+self.remote+'\n')
        elif 'pull' in argv:
            Path(argv[-1]).write_bytes(self.image);output.write_text('copied\n')
        else: raise AssertionError(argv)
        Path(str(output)+'.stderr').write_text('')
        if guard: guard()
        return {'argv':argv,'returncode':0,'stdout':str(output),'stderr':str(output)+'.stderr'}
    def collect(self, listing=None, changed=False):
        self.listing=(self.remote+'\0').encode() if listing is None else listing;self.changed=changed
        with connect(self.ws,'qa') as (root,db), patch('lawliet_mobile.tools.command',return_value=['adb']), patch('lawliet_mobile.tools.execute',side_effect=self.execute):
            result=collect_android(root,db,self.ws,'SERIAL','trash-photos',max_bytes=2*1024**2)
            if result['evidence_id']: native_analyze(root,db,result['evidence_id'])
            self.assertTrue(verify(root,db)['ok'])
        return result
    def test_special_filename_is_quoted_and_ui_receipt_is_registered(self):
        result=self.collect();self.assertEqual(result['status'],'complete');self.assertEqual(result['verified_trash_photos'],1)
        self.assertEqual(handle(self.ws,{'action':'source-stats','case':'qa'})['categories']['trash_photos'],1)
        self.assertFalse(any(x in {'root','install','rm','restore','grant'} for call in self.calls for x in call))
        pulls=[c for c in self.calls if 'pull' in c];self.assertEqual(pulls[0][-2],self.remote)
        # The remote hashing command quotes the whole hostile-looking filename.
        import shlex
        hashes=[c[-1] for c in self.calls if c[-1].startswith('sha256sum ')]
        self.assertEqual(shlex.split(hashes[0]),['sha256sum',self.remote])
    def test_changed_source_retained_but_not_verified_or_labelled(self):
        result=self.collect(changed=True);self.assertEqual(result['status'],'partial')
        self.assertEqual(result['verified_trash_photos'],0)
        self.assertEqual(handle(self.ws,{'action':'source-stats','case':'qa'})['categories'].get('trash_photos',0),0)
    def test_empty_discovery_is_explicit_and_does_not_pull(self):
        result=self.collect(b'');self.assertEqual(result['status'],'complete')
        self.assertEqual(result['coverage'][0]['state'],'collected_empty')
        self.assertFalse(any('pull' in c for c in self.calls))
    def test_invalid_or_unbounded_listing_fails_before_pull(self):
        for listing in [b'/sdcard/Android/.Trash/../private.jpg\0',b'/data/private.jpg\0',b'/sdcard/Android/.Trash/photo.jpg',b'\xff\0',b'/sdcard/Android/.Trash/a.jpg\0'*1001]:
            self.calls=[];result=self.collect(listing)
            self.assertEqual(result['status'],'failed');self.assertFalse(any('pull' in c for c in self.calls))
