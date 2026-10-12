import base64,struct,unittest
from lawliet_mobile.maps_foreground import decode_preferences,wire_fields
from lawliet_mobile.core import UserError
class MapsForegroundTests(unittest.TestCase):
    def xml(self,lat=123456789,lon=-987654321,version='9.77.5'):
        point=b'\x0d'+struct.pack('<i',lat)+b'\x15'+struct.pack('<i',lon)
        blob=b'\x08\x01\x2a'+bytes([len(point)])+point
        return '<map><string name="app_version">'+version+'</string><string name="last_foreground_location">'+base64.b64encode(blob).decode()+'</string><long name="gmm_last_used" value="1695253830160"/></map>'
    def test_positive_negative_e7_and_separate_app_time(self):
        result=decode_preferences(self.xml());self.assertEqual(result['latitude'],12.3456789);self.assertEqual(result['longitude'],-98.7654321)
        self.assertEqual(result['app_last_used_utc'],'2023-09-20T23:50:30.160000Z');self.assertEqual(result['state'],'limited')
        self.assertNotIn('venue',result);self.assertNotIn('coordinate_time',result)
    def test_unsupported_version_invalid_coordinates_and_duplicate_keys_refused(self):
        for xml in [self.xml(version='new'),self.xml(lat=910000000),self.xml().replace('</map>','<string name="app_version">9.77.5</string></map>'),self.xml().replace('CAEq','!A!?'), '<!DOCTYPE map [<!ENTITY x "bad">]>'+self.xml()]:
            with self.assertRaises((UserError,ValueError)):decode_preferences(xml)
    def test_malformed_wire_refused(self):
        for blob in [b'\0',b'\x08',b'\x2a\xff',b'\x0d\x01',b'\x08\x01\x08\x02',b'x'*257]:
            with self.assertRaises(UserError):wire_fields(blob)
