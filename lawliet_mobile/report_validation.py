"""Reconcile indexed LEAPP fields with retained report rows, not phone databases."""
import csv
from .tsv import report_reader
import json
from collections import defaultdict
from pathlib import Path

from .core import digest
from .leapp_reports import leapp_artifact, MAPPING_VERSION


def reconcile_reports(root, db, evidence_id, rows, parser=None, run=None):
    supported={'aleapp','ileapp','import/leapp','import/tsv'}
    catalog={}
    files={file['id']:file['path'] for file in db.execute('SELECT id,path FROM files WHERE evidence_id=?',(evidence_id,))}
    for receipt in db.execute("SELECT * FROM runs WHERE evidence_id=? AND status='complete'",(evidence_id,)):
        engine=receipt['engine']
        if engine not in supported or (parser and parser!=engine) or (run and run!=receipt['id']):
            continue
        detail=json.loads(receipt['detail'] or '{}')
        for report in detail.get('reports',[]):
            relative=report['path']
            base=root/'runs'/receipt['id']/'output' if engine in {'aleapp','ileapp'} else root/'evidence'/evidence_id
            path=base/relative
            catalog[(engine,str(path))]={'path':path,'base':base,'sha256':report['sha256'],'rows':[]}
    # Also cover older records that predate report inventories.
    unresolved=0
    for row in rows:
        engine=row['parser']
        if engine not in supported: continue
        data=row['data']
        if engine in {'aleapp','ileapp'}:
            provenance=data.get('_ancalor_report',{})
            reference,separator,number=row['source_ref'].rpartition(':line=')
            path=root/reference; base=root/'runs'
        else:
            provenance=data.get('_import_report',{})
            relative=files.get(row['file_id'])
            if relative is None:
                unresolved+=1;continue
            base=root/'evidence'/evidence_id;path=base/relative
            number=provenance.get('record');separator=True
        try:
            number=int(number)
            if not separator or number<2: raise ValueError()
        except (ValueError,TypeError):
            unresolved+=1;continue
        item=catalog.setdefault((engine,str(path)),{'path':path,'base':base,'sha256':provenance.get('sha256'),'rows':[]})
        item['rows'].append((number,row['id']))
    checked=0;failures=unresolved;legacy=0;examples=[];tables=[]
    mapping_review=0;display_mismatches=0;mapping_examples=[]
    def label(path):
        return str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    def fail(path,number,reason):
        nonlocal failures
        failures+=1
        if len(examples)<50: examples.append({'report':label(path),'record':number,'reason':reason})
    for (engine,_),item in sorted(catalog.items()):
        path=item['path'];indexed=defaultdict(list)
        for number,identifier in item['rows']:indexed[number].append(identifier)
        report_rows=0;before=failures;legacy_before=legacy
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(item['base'].resolve()) or not path.is_file():
                raise ValueError('Missing or unsafe retained report path')
            if not item['sha256'] or digest(path)!=item['sha256']:
                raise ValueError('Retained report hash mismatch')
            with path.open(encoding='utf-8-sig',newline='') as stream:
                reader=report_reader(stream)
                if not reader.fieldnames or len(set(reader.fieldnames))!=len(reader.fieldnames):
                    raise ValueError('Invalid report headers')
                for number,original in enumerate(reader,2):
                    if None in original or any(v is None for v in original.values()):raise ValueError('Invalid report row width')
                    report_rows+=1
                    matches=indexed.pop(number,[])
                    if len(matches)!=1:
                        fail(path,number,'Missing indexed row' if not matches else 'Duplicate indexed row')
                        continue
                    row=dict(db.execute('SELECT category,timestamp,title,body,data FROM artifacts WHERE id=?',(matches[0],)).fetchone())
                    row['data']=json.loads(row['data'])
                    fields=row['data'].get('_leapp_fields')
                    if fields is None:
                        legacy+=1
                    elif fields!=original:
                        fail(path,number,'Original field values differ')
                    else:
                        checked+=1
                    columns=row['data'].get('_leapp_columns')
                    if columns is not None and columns!=reader.fieldnames:
                        fail(path,number,'Retained column order differs from report headers')
                    # Replay only our report adapter; this does not independently
                    # verify LEAPP's extraction from the device database.
                    category,when,raw,title,body,_=leapp_artifact(path.stem,original,evidence_id)
                    differing=[key for key,expected in [('category',category),('timestamp',when),('title',title),('body',body)] if row[key]!=expected]
                    if row['data'].get('_leapp_report_name')!=path.stem:
                        differing.append('_leapp_report_name')
                    if differing:
                        stored_version=row['data'].get('_ancalor_mapping_version')
                        # A version mismatch cannot prove that an upgrade caused
                        # the difference. Keep needs_review, with a precise reason.
                        review=stored_version!=MAPPING_VERSION and fields==original
                        if review:
                            mapping_review+=1
                            reason='Original fields match; display differs under a different or unrecorded mapping version'
                        else:
                            display_mismatches+=1
                            reason='Displayed fields differ from current report adapter'
                        fail(path,number,reason)
                        if len(mapping_examples)<50:
                            mapping_examples.append({'report':label(path),'record':number,'fields':differing,
                                'stored_mapping_version':stored_version,'current_mapping_version':MAPPING_VERSION,
                                'classification':'mapping_review' if review else 'display_mismatch'})
            for number in indexed:fail(path,number,'Indexed row has no matching report row')
        except (OSError,ValueError,csv.Error) as exc:
            fail(path,None,str(exc))
        tables.append({'report':label(path),'report_rows':report_rows,'indexed_rows':len(item['rows']),'status':'needs_review' if failures>before else ('not_checked' if legacy>legacy_before else 'pass')})
    return {'check':'leapp_report_reconciliation','status':'needs_review' if failures else ('not_checked' if legacy else ('pass' if catalog else 'not_available')),
            'reports_checked':len(catalog),'exact_field_rows':checked,'legacy_rows_without_original_fields':legacy,
            'failure_count':failures,'unresolved_references':unresolved,'examples':examples,'reports':tables,
            'mapping_review_rows':mapping_review,'display_mismatch_rows':display_mismatches,
            'mapping_examples':mapping_examples,'current_mapping_version':MAPPING_VERSION,
            'note':'Original-field and report-hash checks are separate from display mapping replay. A different or unrecorded mapping version requires review when displayed values differ; this alone proves neither tampering nor an upgrade as the cause. This does not authenticate or validate the original phone databases.'}
