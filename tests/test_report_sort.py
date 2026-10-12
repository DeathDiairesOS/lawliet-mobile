import csv
import json
from tests.test_desktop import DesktopTests
from lawliet_mobile.report_sort import sort_value


class TypedSortTests(DesktopTests):
    def test_number_and_timestamp_order_preserves_original_values(self):
        values=['10','2','-3','9007199254740993','9007199254740992','1.25','NaN','','1,000']
        report=self.base/'Typed Sort.tsv'
        with report.open('w',newline='') as f:
            writer=csv.writer(f,delimiter='\t');writer.writerow(['Value'])
            writer.writerows([v] for v in values)
        result=self.call('import',path=str(report),format='tsv')
        opts={'evidence':result['evidence_id'],'sort_field':'Value','sort_mode':'number'}
        rows=self.call('records',**opts)['records']
        ordered=[r['data']['_leapp_fields']['Value'] for r in rows]
        self.assertEqual(ordered[:6],['-3','1.25','2','10','9007199254740992','9007199254740993'])
        self.assertEqual(set(ordered[6:]),{'NaN','','1,000'})
        reverse=self.call('records',sort_direction='desc',**opts)['records']
        self.assertEqual([r['data']['_leapp_fields']['Value'] for r in reverse[:6]],list(reversed(ordered[:6])))
        out=self.base/'typed.jsonl';self.call('export',path=str(out),**opts)
        self.assertEqual([json.loads(s)['id'] for s in out.read_text().splitlines()],[r['id'] for r in rows])
        self.assertLess(sort_value('2026-10-11T12:00:00+02:00','timestamp'),sort_value('2026-10-11T11:00:00Z','timestamp'))
        for invalid in ['2026-10-11','2026-10-11 12:00:00','2026-10-11T12:00:00.1234567Z','Time of Extraction','1790000000']:
            self.assertIsNone(sort_value(invalid,'timestamp'))
        self.assertIsNone(sort_value('Infinity','number'))
