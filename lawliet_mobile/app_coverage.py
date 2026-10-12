"""Inventory indicators, kept distinct from parsing and acquisition completeness."""
import re
from collections import Counter
from .core import UserError, iter_artifacts
from .report_sort import sort_value

PACKAGES = {'discord': ('com.discord',), 'whatsapp': ('com.whatsapp', 'com.whatsapp.w4b'),
            'signal': ('org.thoughtcrime.securesms',)}


def app_coverage(db, evidence, run=None):
    if not db.execute('SELECT 1 FROM evidence WHERE id=?', (evidence,)).fetchone():
        raise UserError('Unknown evidence.')
    if run:
        receipt=db.execute('SELECT evidence_id FROM runs WHERE id=?',(run,)).fetchone()
        if not receipt or receipt['evidence_id']!=evidence:
            raise UserError('Run does not belong to selected evidence.')
    result={app:{'app':app,'candidate_files':0,'candidate_files_by_storage':{'private':0,'external_data':0,'external_media':0},'path_examples':[], 'message_rows_by_parser':{},
                 'first_message_utc':None,'last_message_utc':None,'undated_message_rows':0}
            for app in PACKAGES}
    # Match private application directories, not package names in an APK filename,
    # document text, report name or arbitrary filename. Paths remain indicators.
    patterns={}
    for app,packages in PACKAGES.items():
        package='(?:'+'|'.join(re.escape(p) for p in packages)+r')/'
        patterns[app]={
            'private':re.compile(r'(?:^|/)data/(?:data|user(?:_de)?/[0-9]+)/'+package),
            'external_data':re.compile(r'(?:^|/)Android/data/'+package),
            'external_media':re.compile(r'(?:^|/)Android/media/'+package)}
    for file in db.execute('SELECT logical_path,sha256 FROM files WHERE evidence_id=?',(evidence,)):
        path=file['logical_path'].replace('\\','/')
        for app,storage_patterns in patterns.items():
            for storage,pattern in storage_patterns.items():
                if not pattern.search(path):continue
                item=result[app];item['candidate_files']+=1
                item['candidate_files_by_storage'][storage]+=1
                if len(item['path_examples'])<10:
                    item['path_examples'].append({'path':file['logical_path'],'sha256':file['sha256'],'storage':storage})
                break
    counts={app:Counter() for app in PACKAGES}
    for row in iter_artifacts(db,evidence=evidence,run=run,category='messages',limit=None):
        message=row['data'].get('message')
        if isinstance(message,dict) and message.get('app') in counts:
            counts[message['app']][row['parser']]+=1
            item=result[message['app']]
            when=sort_value(row['timestamp'],'timestamp')
            if when is None:
                item['undated_message_rows']+=1
            else:
                when=when.replace('+00:00','Z')
                item['first_message_utc']=min(item['first_message_utc'] or when,when)
                item['last_message_utc']=max(item['last_message_utc'] or when,when)
    for app,item in result.items():
        item['message_rows_by_parser']=dict(counts[app])
        item['message_rows']=sum(counts[app].values())
        item['state']=('indexed_messages' if item['message_rows'] else
                       'candidate_paths_without_indexed_messages' if item['candidate_files'] else
                       'no_matching_indicators')
        item['next_step']=('Review report provenance, date range, duplicates and attachments.' if item['message_rows'] else
                           'Review acquired external files; private message databases are not indicated by these paths. Assess alternate authorized sources.' if item['candidate_files'] and not item['candidate_files_by_storage']['private'] else
                           'Review processing logs and file formats; assess unsupported schemas or encryption.' if item['candidate_files'] else
                           'Check acquisition scope and alternate authorized sources; do not infer absence on the phone.')
    return {'evidence_id':evidence,'run':run,'apps':list(result.values()),
            'limitations':['Path detection covers listed Android private-app and Android/data or Android/media package layouts; iOS backup domains, opaque archives and renamed files are not assessed.',
                           'External data/media paths are separate indicators, not evidence that private app databases were acquired. Directory names alone do not authenticate file origin or message ownership.',
                           'Candidate files may be settings or cache, not readable message databases. No decryption or new collection is performed.',
                           'Message counts are indexed rows, not unique messages or complete history. Without --run, overlapping parser runs are included.',
                           'Observed message dates describe indexed records only; they do not establish complete history, retention periods or absence outside that range. Undated rows are excluded from the range.',
                           'Inventory hashes are stored acquisition values, not a fresh integrity check; use verify.',
                           'No matching indicators does not establish that an app was unused or that messages never existed.']}
