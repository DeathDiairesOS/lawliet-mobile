"""JSON-over-stdio bridge for the native desktop app. No network listener."""
import json
import sys
import stat
from pathlib import Path

from .acquisition import case_coverage
from .app_coverage import app_coverage
from .discovery import preview as analysis_preview
from .findings import add_finding, list_findings, export_findings
from .core import UserError, audit, connect, create_case, has_run_index, iter_artifacts, run_scope, select_artifacts, verify
from .messages import conversations
from .parsed_import import import_parsed
from .leapp_reports import report_review_note
from .report import safe_output
from .core import import_evidence
from .parsers import native_analyze, timestamp
from .tools import devices, doctor, collect
from .acquisition import collect_android
from .messages import import_chat
from .discord_package import import_discord_package
from .media import preview
from .signal_backup import decrypt_signal, signal_backup_preflight
from .android_backup import import_backup
from .private_apps import collect_private_apps
from .validation import preflight, validate_case
from .phone_assessment import assess_android
from .pipeline import process_evidence
from . import case_management
from .adapters import analyze_file as adapter_analyze_file, analyze as adapter_analyze
import shutil
from datetime import datetime, timedelta, timezone


def filters(request):
    result = {key: request[key] for key in ('evidence', 'parser', 'run', 'query', 'app', 'conversation', 'category', 'since', 'until', 'report', 'sort_field', 'sort_direction', 'sort_mode', 'phone_query', 'view_group') if request.get(key)}
    if request.get('category') == 'media':
        result['media_items'] = True
        if request.get('media_state'):
            result['media_state'] = request['media_state']
    for key in ('since','until'):
        if key in result:
            value=str(result[key]);converted=timestamp(value+'T00:00:00Z' if len(value)==10 else value)
            if not converted: raise UserError('Use YYYY-MM-DD or an ISO timestamp with timezone.')
            result[key]=converted
    return result


def report_inventory(db, request, clause, args):
    """Indexed counts plus retained zero-row reports from completed scoped runs."""
    counts = dict(db.execute("SELECT json_extract(data,'$._leapp_report_name'),COUNT(*) FROM artifacts WHERE "+clause+" AND json_extract(data,'$._leapp_report_name') IS NOT NULL GROUP BY 1", args))
    conditions, values = ["status='complete'"], []
    for key, column in [('run','id'),('evidence','evidence_id'),('parser','engine')]:
        value=request.get(key)
        if value and not (key=='parser' and value=='unparsed'):
            conditions.append(column+'=?');values.append(value)
    if request.get('parser')=='unparsed':
        conditions.append('records=0')
    for run in db.execute('SELECT detail FROM runs WHERE '+' AND '.join(conditions),values):
        for report in json.loads(run['detail'] or '{}').get('reports',[]):
            # Only an explicitly empty, successfully processed table establishes
            # zero rows. Never turn missing or failed parsing into an empty report.
            if report.get('records',report.get('rows')) != 0:
                continue
            name=report.get('name') or Path(report['path']).stem
            counts.setdefault(name,0)
    categories = {}
    for name,category in db.execute("SELECT DISTINCT json_extract(data,'$._leapp_report_name'),category FROM artifacts WHERE "+clause+" AND json_extract(data,'$._leapp_report_name') IS NOT NULL",args):
        categories.setdefault(name,[]).append(category)
    from .review_groups import evidence_group
    return [{'name':name,'records':count,'categories':sorted(categories.get(name,[])),
             'view_group':evidence_group(categories.get(name,['external'])[0],name)} for name,count in sorted(counts.items())]


def handle(workspace, request):
    workspace = Path(workspace).expanduser().resolve()
    action = request.get('action')
    if action and action.startswith('engine-'):
        from .engines import engine
        from .mulder_engine import job_path, read_json, TERMINAL
        adapter = engine(workspace, request['case'], request.get('engine', 'mulder'))
        if action == 'engine-check': return adapter.check_availability(request.get('config', {}))
        if action == 'engine-start': return adapter.start_investigation(request['config'])
        if action == 'engine-list': return adapter.list_runs()
        if action == 'engine-status': return adapter.get_status(request['job_id'])
        if action == 'engine-cancel': return adapter.cancel_investigation(request['job_id'])
        if action == 'engine-logs': return adapter.get_logs(request['job_id'])
        if action == 'engine-import-output':
            from .mulder_import import import_outputs
            return import_outputs(workspace, request['case'], request['path'],
                                  request['upstream_case_id'], request['version'])
        with connect(workspace, request['case']) as (root, db):
            if action == 'engine-import':
                eid, *_ = import_evidence(root, db, request['path'], 'auto')
                return {'evidence_id': eid}
            if action == 'engine-findings':
                rows = select_artifacts(db, run=request['job_id'], category='agent_findings',
                                        query=request.get('query') or None, limit=101, offset=int(request.get('offset', 0)))
                has_reviews = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='engine_reviews'").fetchone()
                for row in rows:
                    review = db.execute('SELECT decision,reviewer,at FROM engine_reviews WHERE artifact_id=? ORDER BY id DESC LIMIT 1', (row['id'],)).fetchone() if has_reviews else None
                    row['examiner_review'] = dict(review) if review else {'decision': 'unreviewed'}
                return {'records': rows[:100], 'has_more': len(rows)>100}
            if action == 'engine-review':
                decision = request.get('decision')
                reviewer = request.get('reviewer', '').strip()
                if decision not in ('approved','rejected','needs_follow_up') or not reviewer or len(reviewer)>200:
                    raise UserError('Select a review decision and enter an examiner name.')
                row = db.execute("SELECT id FROM artifacts WHERE id=? AND category='agent_findings'", (request['artifact_id'],)).fetchone()
                if not row: raise UserError('Select an imported engine finding in this case.')
                saved = add_finding(db, row['id'], 'Engine finding review: '+decision+'\n'+request.get('note',''), reviewer)
                db.execute('''CREATE TABLE IF NOT EXISTS engine_reviews(id INTEGER PRIMARY KEY, artifact_id TEXT,
                              finding_id TEXT, decision TEXT, reviewer TEXT, at TEXT)''')
                from .core import now
                db.execute('INSERT INTO engine_reviews(artifact_id,finding_id,decision,reviewer,at) VALUES(?,?,?,?,?)',
                           (row['id'], saved['id'], decision, reviewer, now()))
                audit(db, 'engine.finding_reviewed', {'artifact_id':row['id'], 'saved_finding_id':saved['id'], 'decision':decision, 'reviewer':reviewer})
                return {'decision':decision, 'saved_finding_id':saved['id']}
            if action == 'engine-export-report':
                # Verify the captured Markdown before copying; never regenerate or execute HTML.
                verified = handle(workspace, {**request, 'action':'engine-report'})
                destination = safe_output(root, db, request['path'])
                with destination.open('xb') as out, Path(verified['path']).open('rb') as source:
                    shutil.copyfileobj(source, out)
                from .core import digest
                if digest(destination) != verified['sha256']:
                    destination.unlink()
                    raise UserError('Report changed during export.')
                audit(db, 'engine.report_exported', {'job_id':request['job_id'], 'path':str(destination), 'sha256':verified['sha256'], 'review_status':'unreviewed'})
                return {'path':str(destination), 'sha256':verified['sha256'], 'review_status':'unreviewed'}
            if action == 'engine-report':
                jid = request['job_id'];state = adapter.get_status(jid)
                if state['status'] not in TERMINAL: raise UserError('Report viewing is available when the investigation stops.')
                path = job_path(root, jid)
                from .mulder_results import output_case_id
                report = path / 'outputs' / (output_case_id(state.get('upstream_case_id', jid)) + '.report.md')
                if not report.is_file() or report.is_symlink(): raise UserError('No safe Markdown report is available for this investigation.')
                from .core import digest
                from .engine_integrity import captured_manifest
                manifest = captured_manifest(root, db, jid)
                expected = next((r['sha256'] for r in manifest if r['path']=='outputs/'+report.name), None)
                if not expected or digest(report) != expected: raise UserError('Report integrity does not match the captured output manifest.')
                with report.open('rb') as stream: content = stream.read(2*1024**2+1)
                return {'text': content[:2*1024**2].decode('utf-8', errors='replace'), 'truncated': len(content)>2*1024**2,
                        'path': str(report), 'sha256': expected, 'review_status': 'unreviewed'}
        raise UserError('Unknown engine action.')
    if action == 'devices':
        return {'devices': devices(workspace), 'free_gib': round(shutil.disk_usage(workspace).free/1024**3, 1), 'tools': doctor(workspace)['tools']}
    if action == 'cases':
        result = []
        # Path.glob suppresses directory access errors on supported Python
        # versions. An inaccessible workspace must not look like an empty one.
        try:
            folders = list(workspace.iterdir())
        except OSError as exc:
            raise UserError('Cannot list the case workspace. Check that the folder is available and that Lawliet has access, then use Change workspace to select it again. '+str(exc)) from exc
        for folder in folders:
            path = folder / 'case.sqlite'
            try:
                if not stat.S_ISDIR(folder.stat().st_mode):
                    continue
                path.stat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise UserError('Cannot read case inventory at '+str(path)+': '+str(exc)) from exc
            with connect(workspace, folder.name) as (_, db):
                meta = dict(db.execute('SELECT key,value FROM meta'))
                # Queue navigation only needs case metadata. Counting a large
                # artifact table can read hundreds of MB from removable disks.
                records = db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0] if request.get('include_records', True) else None
                result.append({'id': folder.name, 'name': meta['name'], 'created': meta['created_at'], 'records': records, **case_management.summary(db)})
        return sorted(result, key=lambda r: r['created'], reverse=True)
    if action == 'create':
        create_case(workspace, request['id'], request.get('name'), request.get('examiner'))
        return {'id': request['id']}
    with connect(workspace, request['case']) as (root, db):
        if action in {'agent-collection-create', 'agent-collection-list', 'agent-collection-status'}:
            from .agent_collection import create_plan, list_plans, get_plan
            from .agent_collection_handoff import present
            if action == 'agent-collection-list':
                return list_plans(root, db)
            plan = (create_plan(root, db, request.get('config', {})) if action == 'agent-collection-create'
                    else get_plan(root, db, request.get('plan_id')))
            return present(plan, workspace)
        if action == 'file-inventory':
            from .file_inventory import inventory
            return inventory(db,request.get('query',''),request.get('evidence'),request.get('offset',0),request.get('limit',100))
        if action == 'file-preview':
            from .file_inventory import preview_file
            return preview_file(root,db,request.get('file_id'))
        if action == 'investigation-from-findings':
            from .report_preparation import from_findings
            return from_findings(root, db, request.get('objective'), request.get('finding_ids'))
        if action == 'investigation-from-examination':
            from .examination_report import prepare
            return prepare(root, db, request.get('objective'), request.get('evidence_ids'),
                           request.get('outcome'), request.get('examiner'), request.get('examination_scope'),
                           request.get('limitations'), request.get('queries', []))
        if action == 'evidence-inspect':
            from .evidence_viewer import inspect_file
            return inspect_file(root, db, request.get('file_id'), request.get('offset', 0), request.get('length', 4096), request.get('encoding', 'utf-8'), request.get('format'))
        if action == 'competency-record':
            from .competency import record
            return record(db, request.get('event'))
        if action == 'competency-history':
            from .competency import history
            return history(db, request.get('after', 0), request.get('limit', 100), request.get('examiner'), request.get('method'))
        if action == 'identity-record':
            from .identity_associations import record
            return record(db, request.get('event'))
        if action == 'identity-history':
            from .identity_associations import list_records
            return list_records(db, request.get('after', 0), request.get('limit', 100))
        if action == 'identity-groups':
            from .identity_associations import groups
            return groups(db)
        if action == 'remediation-record':
            from .remediation import record
            return record(db, request.get('event'))
        if action == 'remediation-history':
            from .remediation import history
            return history(db, request.get('after', 0), request.get('limit', 100), request.get('action_id'))
        if action in {'sqlite-query', 'sqlite-schema'}:
            from .sqlite_workspace import query, schema
            limits = {key: request[key] for key in ('row_limit', 'max_output_bytes', 'timeout_seconds') if key in request}
            if action == 'sqlite-schema':
                return schema(root, db, request.get('file_id'), **limits)
            return query(root, db, request.get('file_id'), request.get('sql'), request.get('parameters', []), **limits)
        if action == 'sqlite-query-result':
            from .sqlite_workspace import read_result
            return read_result(root, db, request.get('run_id'), request.get('offset', 0), request.get('limit', 100))
        if action == 'custody-record':
            from .custody import record
            return record(root, db, request.get('event'))
        if action == 'custody-list':
            from .custody import list_records
            return list_records(db, request.get('after', 0), request.get('limit', 100), request.get('item_id'))
        if action == 'device-state-record':
            from .device_state import record
            return record(db, request.get('worksheet'))
        if action == 'device-state-list':
            from .device_state import list_records
            return list_records(db, request.get('after', 0), request.get('limit', 100))
        if action == 'customer-report-review':
            from .report_review import review_bundle
            return review_bundle(root, db, request.get('bundle_id'), request.get('kind'), request.get('expected_manifest_sha256'))
        if action in {'customer-report-approve', 'customer-report-release', 'customer-report-redacted-draft',
                      'customer-report-redacted-approve', 'customer-report-redacted-release'} and 'expected_manifest_sha256' in request:
            from .report_review import checked_binding
            redacted = action in {'customer-report-redacted-approve', 'customer-report-redacted-release'}
            checked_binding(root, db, request.get('derivative_id' if redacted else 'draft_id'),
                            'redacted' if redacted else 'original', request['expected_manifest_sha256'])
        if action == 'mvt-preview':
            from .mvt_review import inspect_bundle
            return inspect_bundle(request.get('path'))
        if action == 'mvt-import':
            from .mvt_review import import_bundle
            return import_bundle(root, db, request.get('path'), request.get('expected_manifest_sha256'), request.get('expected_upstream_case_id'))
        if action == 'mvt-list':
            from .mvt_review import list_bundles
            return list_bundles(root, db)
        if action == 'mvt-review':
            from .mvt_review import review
            return review(root, db, request.get('evidence'), request.get('query', ''), request.get('offset', 0), request.get('limit', 50))
        if action == 'mvt-record':
            from .mvt_review import record
            return record(root, db, request.get('evidence'), request.get('artifact_id'))
        if action == 'customer-report-draft':
            from .investigation_report import build_customer_draft
            return build_customer_draft(root,db,request['investigation_id'],request.get('redactions'))
        if action == 'customer-report-masking-preview':
            from .masking_preview import create
            return create(root,db,request.get('draft_id'),request.get('literals'))
        if action == 'customer-report-redacted-draft':
            from .investigation_report import create_redacted_customer_draft
            return create_redacted_customer_draft(root,db,request.get('draft_id'),request.get('literals'))
        if action == 'customer-report-redacted-check':
            from .investigation_report import _checked_redacted_customer_draft
            folder,manifest,checksum=_checked_redacted_customer_draft(root,db,request.get('derivative_id'))
            return {'path':str(folder),'manifest':manifest,'manifest_sha256':checksum}
        if action == 'customer-report-redacted-approve':
            from .investigation_report import approve_redacted_customer_draft
            return approve_redacted_customer_draft(root,db,request.get('derivative_id'),request.get('reviewer'),request.get('declaration'))
        if action == 'customer-report-redacted-release':
            from .investigation_report import release_redacted_customer_draft
            return release_redacted_customer_draft(root,db,request.get('derivative_id'),request.get('path'))
        if action == 'customer-report-approve':
            from .investigation_report import approve_customer_draft
            return approve_customer_draft(root,db,request['draft_id'],request.get('reviewer'),request.get('declaration'))
        if action == 'customer-report-release':
            from .investigation_report import release_customer_draft
            return release_customer_draft(root,db,request['draft_id'],request['path'],request.get('redactions'))
        if action == 'coverage-ledger':
            return case_coverage(root,db,ledger_options={
                'offset':request.get('offset',0),'limit':request.get('limit',100),
                'filters':request.get('filters')})['ledger']
        if action == 'scenario-assessment':
            from .scenario_assessment import assess
            return assess(root, db, request.get('evidence'), request.get('scenario', 'messages'), request.get('run'))
        if action == 'coverage-record':
            from .coverage_ledger import record_observation
            return record_observation(db,request.get('observation'))
        if action == 'case-management':
            return case_management.details(db, request.get('offset', 0))
        if action == 'case-update':
            return case_management.update(db, request.get('values'), request.get('revision'))
        if action == 'case-task-add':
            return case_management.add_task(db, request.get('text'))
        if action == 'case-task-update':
            return case_management.set_task(db, request.get('task_id'), request.get('completed'), request.get('revision'))
        if action == 'finding-add':
            return add_finding(db,request['artifact_id'],request['note'],request.get('examiner',''))
        if action == 'findings':
            return list_findings(db,100,int(request.get('offset',0)))
        if action == 'findings-export':
            return export_findings(root,db,request['path'],request.get('format','jsonl'))
        if action == 'overview':
            evidence = [dict(r) for r in db.execute('SELECT * FROM evidence ORDER BY imported_at DESC,rowid DESC')]
            sources = []
            for e in evidence:
                runs = list(db.execute("SELECT * FROM runs WHERE evidence_id=? ORDER BY started_at DESC,rowid DESC", (e['id'],)))
                for run in runs:
                    if run['status'] != 'complete' and not (run['status']=='partial' and (run['engine']=='mulder' or has_run_index(db,run['id']))):
                        continue
                    if run['engine'] not in {'ileapp','aleapp','sqlite-dissect'} and not has_run_index(db,run['id']):continue
                    clause, args = run_scope(db, run['id'])
                    count = db.execute('SELECT COUNT(*) FROM artifacts WHERE '+clause, args).fetchone()[0]
                    normalized_parsers = [r[0] for r in db.execute('SELECT DISTINCT parser FROM artifacts WHERE '+clause+' LIMIT 2', args)]
                    parser_filter = normalized_parsers[0] if len(normalized_parsers)==1 else ''
                    sources.append({'id': run['id'], 'evidence': e['id'], 'parser': parser_filter, 'run': run['id'], 'label': e['label'] + ' · ' + run['engine'] + (' · partial' if run['status']=='partial' else '') + ' · ' + run['id'], 'records': count, 'status':run['status']})
                for row in db.execute("SELECT parser,COUNT(*) AS n FROM artifacts WHERE evidence_id=? AND parser NOT IN ('ileapp','aleapp','sqlite-dissect') GROUP BY parser", (e['id'],)):
                    sources.append({'id': e['id']+':'+row['parser'], 'evidence': e['id'], 'parser': row['parser'], 'label': e['label']+' · '+row['parser'], 'records': row['n']})
            for e in evidence:
                if not any(s['evidence']==e['id'] for s in sources):
                    completed=db.execute("SELECT 1 FROM runs WHERE evidence_id=? AND status='complete' LIMIT 1",(e['id'],)).fetchone()
                    state='processed · 0 indexed rows' if completed else 'not yet indexed'
                    sources.append({'id':e['id']+':unparsed','evidence':e['id'],'parser':'','label':e['label']+' · '+state,'records':0})
            return {'name': dict(db.execute('SELECT key,value FROM meta'))['name'], 'sources': sources,
                    'evidence': evidence, 'coverage': case_coverage(root, db, ledger_options={'limit':0})}
        if action == 'import-evidence':
            path=Path(request['path'])
            if path.suffix.lower()=='.ab':
                result=import_backup(root,db,path)
                eid=result['evidence_id']
            else:
                eid,_,_=import_evidence(root,db,path,request.get('platform','auto'))
            if request.get('engine'):
                return process_evidence(root,db,workspace,eid,request['engine'])
            analysis=native_analyze(root,db,eid)
            return {'evidence_id':eid,'analysis':analysis}
        if action == 'analyze':
            engine=request.get('engine','native')
            if engine=='auto':return process_evidence(root,db,workspace,request['evidence'],engine)
            if engine not in {'native','ileapp','aleapp','exiftool'}: raise UserError('Unknown engine.')
            return adapter_analyze(root,db,workspace,request['evidence'],engine)
        if action == 'import-chat':
            return import_chat(root,db,request['path'],request['date_order'],request.get('timezone') or None,year_century=request.get('year_century'),chat_path=request.get('chat_path') or None,reuse=True)
        if action == 'import-discord':
            return import_discord_package(root,db,request['path'],timezone_name=request.get('timezone') or None)
        if action == 'signal-preflight':
            try:
                result=signal_backup_preflight(request['path'],workspace)
                result['ready']=result.get('tool',{}).get('available',False)
                return result
            except UserError as exc:
                return {'ready':False,'format_verified':False,'reason':str(exc)}
        if action == 'decrypt-signal':
            result=decrypt_signal(root,db,workspace,request['path'],request['passphrase'])
            result['decode_status']=result['status']
            result['analysis']=native_analyze(root,db,result['evidence_id'])
            if result['analysis'].get('status')!='complete':result['status']='partial'
            result['message_records']=db.execute("SELECT COUNT(*) FROM artifacts WHERE evidence_id=? AND category='messages' AND json_extract(data,'$.message.app')='signal'",(result['evidence_id'],)).fetchone()[0]
            return result
        if action == 'sqlite-files':
            rows=[]
            for r in db.execute('SELECT * FROM files WHERE evidence_id=?',(request['evidence'],)):
                with (root/'evidence'/r['evidence_id']/r['path']).open('rb') as f:
                    if f.read(16)==b'SQLite format 3\x00': rows.append(dict(r))
            return rows
        if action == 'recover':
            engine=request.get('engine','sqlite-dissect')
            if engine not in {'sqlite-dissect','sqlite4n6'}:raise UserError('Choose a supported SQLite recovery engine.')
            return adapter_analyze_file(root,db,workspace,request['file_id'],engine)
        if action == 'related-attachments':
            artifact=db.execute('SELECT * FROM artifacts WHERE id=?',(request['artifact_id'],)).fetchone()
            if not artifact or artifact['category']!='messages': return []
            data=json.loads(artifact['data'])
            if artifact['parser'].startswith('whatsapp-export/'):
                attachment=data.get('attachment',{})
                if attachment.get('status')!='available' or type(attachment.get('file_id')) is not int:return []
                linked=[]
                for row in db.execute("SELECT a.*, f.sha256 AS source_sha256, f.logical_path FROM artifacts a JOIN files f ON f.id=a.file_id WHERE a.evidence_id=? AND a.file_id=? AND a.category='media' AND a.parser='native/whatsapp-export/3' LIMIT 100",(artifact['evidence_id'],attachment['file_id'])):
                    record=dict(row);record['data']=json.loads(record['data']);linked.append(record)
                return linked
            if artifact['parser'].startswith('native/'):
                row_id=data.get('__rowid__');file_id=artifact['file_id']
            elif artifact['parser']=='ileapp':
                row_id=data.get('message',{}).get('source_row_id')
                files=list(db.execute("SELECT id FROM files WHERE evidence_id=? AND logical_path LIKE '%/SMS/sms.db'",(artifact['evidence_id'],)))
                file_id=files[0]['id'] if len(files)==1 else None
            else: return []
            if row_id is None or file_id is None: return []
            ids=[r[0] for r in db.execute("SELECT id FROM artifacts WHERE category='attachments' AND file_id=? AND EXISTS (SELECT 1 FROM json_each(artifacts.data,'$.attachment.message_row_ids') WHERE value=?)",(file_id,str(row_id)))]
            result=[]
            for identifier in ids:
                row=dict(db.execute('SELECT * FROM artifacts WHERE id=?',(identifier,)).fetchone());row['data']=json.loads(row['data']);result.append(row)
            return result
        if action == 'preview':
            return preview(root,db,request['artifact_id'])
        if action == 'assess-android':
            return assess_android(root,db,workspace,request['serial'])
        if action == 'preflight':
            budget=int(request.get('max_gib',20))*1024**3
            if request['platform']=='android' and request.get('profile') in {'contacts-provider','sms-provider'}:budget=min(budget,64*1024**2)
            return preflight(workspace,request['platform'],budget)
        if action == 'app-coverage':
            return app_coverage(db,request['evidence'],request.get('run'))
        if action == 'analysis-plan':
            return analysis_preview(root,db,workspace,request['evidence'],request.get('profile','standard'),request.get('tools',[]))
        if action == 'validate':
            return validate_case(root,db,workspace,request['evidence'],request.get('parser'),request.get('run'))
        if action == 'collect':
            platform=request['platform'];budget=int(request.get('max_gib',20))*1024**3
            if platform=='android' and request.get('profile') in {'contacts-provider','sms-provider'}:budget=min(budget,64*1024**2)
            readiness=preflight(workspace,platform,budget)
            if not readiness['ready']: raise UserError('Acquisition preflight failed: reserve twice the collection budget plus 1 GiB, and configure required tools. Choose another workspace or adjust the budget deliberately.')
            if platform=='android' and request.get('profile')=='private-apps':
                result=collect_private_apps(root,db,workspace,request['serial'],3600,budget)
            elif platform=='android':
                profile=request.get('profile','messages')
                timeout=900 if profile in {'contacts-provider','sms-provider'} else 3600
                result=collect_android(root,db,workspace,request['serial'],profile,request.get('pulls',[]),timeout,budget,
                                       request.get('max_sms',1000),request.get('android_user'),request.get('sms_prefix'))
            elif platform=='ios': result=collect(root,db,workspace,platform,request['serial'],3600,budget)
            else: raise UserError('Choose Android or iOS.')
            result['collection_status']=result['status']
            # Only the Android SMS provider indexes its own result. A stale
            # Android dialog selection must not suppress iPhone parsing.
            if result.get('evidence_id') and not (platform=='android' and request.get('profile')=='sms-provider'):
                result['analysis']=native_analyze(root,db,result['evidence_id'])
                if result['analysis'].get('status')!='complete' and result['status']=='complete':
                    result['status']='partial'
            return result
        if action == 'record-media-trash-source':
            from .media_sources import record_trash
            return record_trash(root,db,request['file_id'],request['receipt_file_id'])
        if action in {'source-stats', 'date-range'}:
            clause, args = '1=1', []
            if request.get('run'):
                clause, args = run_scope(db, request['run'])
            for key in ('evidence', 'parser'):
                if request.get(key):
                    clause += ' AND '+('evidence_id' if key=='evidence' else key)+'=?'
                    args.append(request[key])
            dates = db.execute('SELECT MIN(timestamp),MAX(timestamp),SUM(timestamp IS NULL),COUNT(*) FROM artifacts WHERE '+clause,args).fetchone()
            if action=='date-range':
                days=int(request.get('days',0))
                if days not in {7,30,60,90}: raise UserError('Choose 7, 30, 60 or 90 days.')
                anchor=request.get('anchor','latest')
                if anchor not in {'latest','now'}: raise UserError('Unknown date anchor.')
                if anchor=='latest' and not dates[1]: raise UserError('This source has no dated records. Use All time to include undated artifacts.')
                end=datetime.fromisoformat(dates[1].replace('Z','+00:00')) if anchor=='latest' else datetime.now(timezone.utc)
                return {'since':timestamp((end-timedelta(days=days)).isoformat()),'until':timestamp(end.isoformat()),'anchor':anchor}
            categories = dict(db.execute('SELECT category,COUNT(*) FROM artifacts WHERE '+clause+' GROUP BY category',args))
            from .review_groups import evidence_group
            db.create_function('evidence_group',2,evidence_group,deterministic=True)
            browser_count = db.execute("SELECT COUNT(*) FROM artifacts WHERE "+clause+" AND evidence_group(category,json_extract(data,'$._leapp_report_name'))='browser'",args).fetchone()[0]
            media_observation_count = categories.get('media', 0)
            if 'media' in categories:
                from .core import media_group_key
                scoped_clause = clause.replace('evidence_id', 'a.evidence_id').replace('parser', 'a.parser')
                # run_scope uses an unqualified id; qualify it before joining files.
                if request.get('run'):
                    scoped_clause = scoped_clause.replace('id IN (', 'a.id IN (').replace('source_ref', 'a.source_ref')
                categories['media'] = db.execute('SELECT COUNT(DISTINCT '+media_group_key()+') '
                    'FROM artifacts a LEFT JOIN files f ON f.id=a.file_id WHERE '+scoped_clause+" AND a.category='media'",args).fetchone()[0]
                from .media_sources import available
                categories['trash_photos'] = (db.execute('SELECT COUNT(DISTINCT '+media_group_key()+') '
                    'FROM artifacts a LEFT JOIN files f ON f.id=a.file_id WHERE '+scoped_clause+
                    " AND a.category='media' AND a.file_id IN (SELECT file_id FROM media_acquisition_sources WHERE source_kind='trash')",args).fetchone()[0]
                    if available(db) else 0)
            from .investigator_view import contact_counts
            return {'categories': categories,
                    'contact_entries': contact_counts(db,clause,args),
                    'view_groups': {'browser': browser_count},
                    'media_observation_count': media_observation_count,
                    'media_count_meaning': 'Byte-backed media items; original parser/source observations remain in the index.',
                    'reports': report_inventory(db,request,clause,args),
                    'first':dates[0],'last':dates[1],'undated':dates[2] or 0,'total':dates[3]}
        if action == 'records':
            offset = request.get('offset', 0)
            if type(offset) is not int or not 0 <= offset <= 2**63-1:
                raise UserError('Record offset must be a nonnegative SQLite-range integer; booleans, strings and fractions are not accepted.')
            if request.get('presentation')=='investigator':
                from .investigator_view import investigator_records
                result=investigator_records(db,filters(request),offset,100,request.get('contact_basis','auto'))
                for row in result['records']:
                    row['review_note']=report_review_note(row['data'])
                return result
            rows = select_artifacts(db, limit=101, offset=offset, **filters(request))
            for row in rows[:100]:
                row['review_note']=report_review_note(row['data'])
            return {'records': rows[:100], 'has_more': len(rows)>100, 'offset': offset}
        if action == 'conversations':
            return conversations(db, evidence=request.get('evidence'), parser=request.get('parser'), run=request.get('run'))
        if action == 'import':
            result=import_parsed(root, db, request['path'], request['format'], request.get('label'))
            eid=result['evidence_id']
            row=db.execute('SELECT parser FROM artifacts WHERE evidence_id=? LIMIT 1',(eid,)).fetchone()
            return {**result,'source_id':eid+':'+(row['parser'] if row else 'unparsed')}
        if action == 'verify':
            return verify(root, db)
        if action == 'export':
            from .report import write_jsonl_export
            for key in ('evidence','run'):
                if key in request and (not isinstance(request[key],str) or not request[key].strip()):
                    raise UserError('An explicitly supplied evidence/run scope must be nonempty.')
            selection=filters(request)
            return write_jsonl_export(root,db,request['path'],iter_artifacts(db,limit=None,**selection),selection)
        raise UserError('Unknown desktop operation.')


def main():
    try:
        request = json.load(sys.stdin)
        result = handle(request.pop('workspace'), request)
        print(json.dumps({'ok': True, 'result': result}, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
