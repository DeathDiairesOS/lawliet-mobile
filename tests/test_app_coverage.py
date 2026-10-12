import tempfile
import unittest
from pathlib import Path
from lawliet_mobile.core import create_case,connect,import_evidence,UserError
from lawliet_mobile.app_coverage import app_coverage
from lawliet_mobile.parsed_import import import_parsed


class AppCoverageTests(unittest.TestCase):
    def test_external_storage_indicators_stay_separate_from_private_data(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);ws=base/'cases';create_case(ws,'qa');source=base/'input'
            paths=['storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/image.jpg',
                   'Android/data/com.whatsapp.w4b/cache/item',
                   'data/user_de/10/com.whatsapp/shared_prefs/settings.xml',
                   'sdcard/Android/media/org.thoughtcrime.securesms/item',
                   'Android/media/com.whatsapp.fake/item',
                   'Android/data/com.discord.apk',
                   'Download/com.discord/image.jpg']
            for name in paths:
                p=source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic')
            with connect(ws,'qa') as (root,db):
                eid=import_evidence(root,db,source,'android')[0]
                items={x['app']:x for x in app_coverage(db,eid)['apps']}
                wa=items['whatsapp']
                self.assertEqual(wa['candidate_files'],3)
                self.assertEqual(wa['candidate_files_by_storage'],{'private':1,'external_data':1,'external_media':1})
                self.assertEqual({x['storage'] for x in wa['path_examples']},{'private','external_data','external_media'})
                self.assertEqual(wa['message_rows'],0)
                self.assertEqual(items['signal']['candidate_files_by_storage']['private'],0)
                self.assertEqual(items['signal']['candidate_files'],1)
                self.assertIn('alternate authorized sources',items['signal']['next_step'])
                self.assertEqual(items['discord']['state'],'no_matching_indicators')

    def test_inventory_is_not_message_or_absence_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);ws=base/'cases';create_case(ws,'qa')
            source=base/'input'
            for name in ['data/user/10/com.discord/files/settings.json',
                         'data/data/com.whatsapp/shared_prefs/settings.xml',
                         'data/data/com.discord.fake/files/one',
                         'data/app/org.thoughtcrime.securesms/base.apk']:
                p=source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic')
            with connect(ws,'qa') as (root,db):
                eid=import_evidence(root,db,source,'android')[0]
                items={x['app']:x for x in app_coverage(db,eid)['apps']}
                self.assertEqual(items['discord']['candidate_files'],1)
                self.assertEqual(items['whatsapp']['state'],'candidate_paths_without_indexed_messages')
                self.assertEqual(items['signal']['state'],'no_matching_indicators')
                self.assertEqual(items['discord']['message_rows'],0)
                self.assertIsNone(items['discord']['first_message_utc'])
                with self.assertRaises(UserError):app_coverage(db,'missing')
                with self.assertRaises(UserError):app_coverage(db,eid,'missing')
                report=base/'discordChats.tsv'
                report.write_text('Timestamp\tDirection\tUsername\tContent\tChannel ID\tSender ID\tID\tAccount ID\n2023-09-20T00:00:00Z\tIncoming\tname\tfixture\t1\t2\t3\t4\n')
                imported=import_parsed(root,db,report,'tsv')
                item=app_coverage(db,imported['evidence_id'])['apps'][0]
                self.assertEqual(item['candidate_files'],0)
                self.assertEqual(item['state'],'indexed_messages')
                self.assertEqual(item['message_rows_by_parser'],{'import/tsv':1})
                self.assertEqual(item['first_message_utc'],'2023-09-20T00:00:00.000000Z')
                self.assertEqual(item['last_message_utc'],item['first_message_utc'])
                self.assertEqual(item['undated_message_rows'],0)
                db.execute('UPDATE artifacts SET timestamp=NULL WHERE evidence_id=?',(imported['evidence_id'],))
                item=app_coverage(db,imported['evidence_id'])['apps'][0]
                self.assertIsNone(item['first_message_utc']);self.assertIsNone(item['last_message_utc'])
                self.assertEqual(item['undated_message_rows'],1)
                with self.assertRaises(UserError):app_coverage(db,eid,imported['run_id'])
