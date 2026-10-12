"""Read-only investigator projections. Stored artifacts and claims stay unchanged."""
import json
import re
from decimal import Decimal
from .report_sort import sort_value
from .core import UserError, select_artifacts
from .phone_search import phone_digits

VERSION = 'investigator-view/1'
MAX_RECORDS = 100000
MAX_BYTES = 128 * 1024**2


def text(value):
    return str(value) if value is not None and not isinstance(value, (dict,list)) else ''


def supplied(fields, *keys):
    return next((text(fields[k]) for k in keys if text(fields.get(k))), '')


def observation(row):
    return dict(row)


def project(row, kind, title, fields, note=''):
    result=dict(row)
    result['display_title']=title or row['title']
    result['display_body']=' · '.join(f'{key}: {value}' for key,value in fields if value)
    result['display_fields']=[{'name':key,'value':value} for key,value in fields if value]
    result['investigator_view']={'version':VERSION,'kind':kind,'note':note,
                                'observations':[observation(row)]}
    return result


def contact_fields(row):
    data=row['data'];fields=data.get('_leapp_fields',data)
    properties=data.get('properties',{})
    if properties:
        names=properties.get('FN',[]) or properties.get('N',[])
        return list(names),list(properties.get('TEL',[])),list(properties.get('EMAIL',[]))
    if row['source_ref'].startswith('ABPerson:'):
        return [' '.join(filter(None,[text(data.get('First')),text(data.get('Last'))]))],[],[]
    if data.get('_leapp_report_name') in {'Contacts','Address Book'}:
        name=supplied(fields,'Display Name') or ' '.join(filter(None,[supplied(fields,'First Name'),supplied(fields,'Last Name')]))
        phone=supplied(fields,'Phone Number','Phone Numbers')
        email=supplied(fields,'Email Address','Email addresses')
        if not phone and fields.get('Mimetype')=='vnd.android.cursor.item/phone_v2':phone=supplied(fields,'Data 1')
        if not email and fields.get('Mimetype')=='vnd.android.cursor.item/email_v2':email=supplied(fields,'Data 1')
        return [name] if name else [],[phone] if phone else [],[email] if email else []
    return [],[],[]


def contact_key(row):
    data=row['data']
    match=re.fullmatch(r'Contact (\d+) · (name|phone_v2|email_v2|organization)',row['title'])
    identifier=data.get('raw_contact_id')
    if (row['parser'].startswith('native/') and row['source_ref'].startswith('data:') and
            match and type(identifier) is int and identifier>0 and str(identifier)==match[1] and row['file_id'] is not None):
        return ('android-contact',row['evidence_id'],row['file_id'],identifier),match[2]
    return ('record',row['id']),None


def contact_counts(db, clause, args):
    def key(identifier,evidence,file_id,parser,title,reference,raw_id):
        row={'id':identifier,'evidence_id':evidence,'file_id':file_id,'parser':parser,
             'title':title,'source_ref':reference,'data':{'raw_contact_id':raw_id}}
        return json.dumps(contact_key(row)[0])
    db.create_function('contact_entry_key',7,key,deterministic=True)
    scoped=clause+" AND category='contacts'"
    source_entries=db.execute("SELECT COUNT(DISTINCT contact_entry_key(id,evidence_id,file_id,parser,title,source_ref,json_extract(data,'$.raw_contact_id'))) FROM artifacts WHERE "+scoped+" AND parser LIKE 'native/%'",args).fetchone()[0]
    reports=db.execute("SELECT COUNT(*) FROM artifacts WHERE "+scoped+" AND parser NOT LIKE 'native/%'",args).fetchone()[0]
    return {'source_entries':source_entries,'report_entries':reports,'default_entries':source_entries or reports}


def contacts(rows, basis='auto'):
    if basis not in {'auto','source','reports','all'}:raise UserError('Choose source contacts, report entries or all source entries.')
    groups={}
    for row in rows:
        key,kind=contact_key(row);groups.setdefault(key,[]).append((row,kind))
    native=[];reports=[]
    for key,members in groups.items():
        names=[];phones=[];emails=[]
        for row,kind in members:
            if kind:
                value=text(row['data'].get('data1'))
                target=names if kind=='name' else phones if kind=='phone_v2' else emails if kind=='email_v2' else None
                if target is not None and value:target.append(value)
            else:
                a,b,c=contact_fields(row);names+=a;phones+=b;emails+=c
        names=list(dict.fromkeys(names));phones=list(dict.fromkeys(phones));emails=list(dict.fromkeys(emails))
        representative=next((r for r,k in members if k=='name'),members[0][0])
        source_kind='source' if representative['parser'].startswith('native/') else 'report'
        display=project(representative,'contact-entry',' / '.join(names) or ('Unnamed source contact' if key[0]=='android-contact' else representative['title']),
                        [('Name',' / '.join(names)),('Phone number','\n'.join(phones)),('Email','\n'.join(emails)),
                         ('Representation','Source contact' if source_kind=='source' else 'Imported report entry')],
                        'Source-local entry, not an independently verified person. Fields are joined only within the same evidence file and raw contact ID.' if key[0]=='android-contact' else 'Supplied contact representation; no cross-source identity merge.')
        display['investigator_view'].update(observations=[observation(r) for r,k in members],
                source_kind=source_kind,phones=phones,names=names,conflicting_names=len(names)>1)
        (native if source_kind=='source' else reports).append(display)
    selected='source' if basis=='auto' and native else 'reports' if basis=='auto' else basis
    entries=native if selected=='source' else reports if selected=='reports' else native+reports
    entries.sort(key=lambda r:(r['display_title'].casefold(),r['evidence_id'],r['id']))
    summary={'version':VERSION,'kind':'contacts','basis':selected,'source_entries':len(native),
             'report_entries':len(reports),'source_records':len(rows),
             'meaning':'Source entries are not unique people across devices or accounts. Report entries are kept separately; no identity is inferred from matching names or numbers.'}
    return entries,summary


def message_review_key(row):
    data=row['data'];message=data.get('message',{});fields=data.get('_leapp_fields',{})
    if row['parser']!='import/leapp' or data.get('_leapp_report_name') not in {'discordChats','Discord - Cached Messages (API cache)'}:
        return ('record',row['id'])
    identifiers=[text(message.get(k)) for k in ('account_ids','channel_id','source_row_id','sender')]
    if not all(re.fullmatch(r'[1-9][0-9]*',value) for value in identifiers) or not row['timestamp']:
        return ('record',row['id'])
    # Same retained report bundle and explicit app IDs; changed content/time,
    # edits, direction or attachment representations remain separate entries.
    attachments=tuple(supplied(fields,*keys) for keys in [
        ('Attachment',),('Attachment URL','Attachment URLs'),
        ('Attachment Filename','Attachment Filenames'),('Attachment Proxy URL',)])
    return ('discord-message',row['evidence_id'],*identifiers,row['timestamp'],row['body'],
            text(message.get('direction')),supplied(fields,'Edited Timestamp'),attachments)


def message_entries(rows):
    grouped={}
    for row in rows:grouped.setdefault(message_review_key(row),[]).append(row)
    entries=[]
    for key,members in grouped.items():
        entry=display_record(members[0])
        if len(members)>1:
            entry['investigator_view']['observations']=[observation(r) for r in members]
            entry['investigator_view']['note']='Matching Discord message representations in this retained evidence bundle; account, channel, message ID, sender, content and time agree. Every report observation remains available. This does not establish complete conversation history.'
        entries.append(entry)
    return entries


def display_record(row):
    data=row['data'];fields=data.get('_leapp_fields',data);name=data.get('_leapp_report_name','')
    if row['category']=='contacts':
        names,phones,emails=contact_fields(row);_,kind=contact_key(row)
        if kind=='name':names=[text(data.get('data1'))]
        elif kind=='phone_v2':phones=[text(data.get('data1'))]
        elif kind=='email_v2':emails=[text(data.get('data1'))]
        return project(row,'contact-observation',' / '.join(names) or row['title'],
                       [('Name',' / '.join(names)),('Phone number','\n'.join(phones)),('Email','\n'.join(emails))],
                       'Search result is a source observation. Open Contacts to assemble source-local contact fields.')
    if row['category']=='messages':
        m=data.get('message',{});app=text(m.get('app')) or 'Unknown app'
        peer=supplied(m,'label','conversation');sender=supplied(m,'sender_label','sender')
        result=project(row,'message',peer or row['title'],[('App',app),('Direction',text(m.get('direction'))),('Sender',sender)])
        result['display_body']=row['body'];return result
    if row['category']=='calls':
        partner=supplied(fields,'number','Phone Number','Partner');kind=supplied(fields,'Call Type','call_type','Type','type')
        # ALEAPP decorates call labels with Feather icons; keep markup in provenance.
        kind=re.sub(r'\s*<i\s+data-feather="[^"]*"[^>]*>\s*</i>', '', kind, flags=re.I).strip()
        duration=supplied(fields,'duration','Duration in Secs','Call Duration')
        return project(row,'call',partner or row['title'],[('Number',partner),('Call type (source)',kind),('Duration (source)',duration)],'A call record does not by itself establish that a conversation occurred.')
    if row['category']=='browser' or name in {'Web History','Web Visits','Safari Browser - History'} or name.startswith('Browser Data - History'):
        role='URL summary' if data.get('browser',{}).get('record_kind')=='url_summary' or name=='Web History' else 'Visit record'
        url=supplied(fields,'URL','url')
        if row['parser'].startswith('native/'):
            url=row['body']
        return project(row,'browser-'+role.lower().replace(' ','-'),supplied(fields,'Title','title') or row['title'],
                       [('Record type',role),('URL',url),('Recorded time',supplied(fields,'visit time')),('Timezone','Not established' if not row['timestamp'] and supplied(fields,'visit time') else '')],
                       'URL summaries and visit records remain distinct. A recorded navigation is not proof of deliberate human browsing.')
    if name=='Cookies':
        return project(row,'browser-cookie',supplied(fields,'Name','name') or 'Cookie',
                       [('Record type','Cookie'),('Host',supplied(fields,'Host','host_key','Host Key','Domain')),('Name',supplied(fields,'Name','name'))],
                       'A stored cookie is not an individual browser visit.')
    if name=='Chrome Browser Cache' or 'localstorage' in name.lower() or 'sessionstorage' in name.lower():
        return project(row,'browser-storage','Browser cache' if name=='Chrome Browser Cache' else 'Browser storage',
                       [('Record type',name),('URL / origin',supplied(fields,'URL','url','Origin','origin')),('Key',supplied(fields,'Key','key'))],
                       'Stored/cache content does not by itself establish an intentional visit.')
    if name in {'package_info','Installed Applications'}:
        package=supplied(fields,'Name','Bundle ID','Package Name','Bundle Identifier')
        return project(row,'app-inventory',package or row['title'],[('Package / bundle',package),('Installed (source)',supplied(fields,'Install Time','Install Date')),('Updated (source)',supplied(fields,'Update Time','Updated Date')),('Path',supplied(fields,'Code Path'))])
    if name=='installedappsGass':
        package=supplied(fields,'Bundle ID')
        return project(row,'apk',package or row['title'],[('Package',package),('Version code',supplied(fields,'Version Code')),('APK SHA-256',supplied(fields,'SHA-256 Hash'))],
                       'Collected APK observation; multiple versions do not establish which version was installed or executed.')
    if name=='Usage Stats' and {'Package','Usage Type'} <= fields.keys():
        event=supplied(fields,'Event Type');usage=supplied(fields,'Usage Type')
        return project(row,'app-activity' if usage=='event-log' else 'usage-summary',supplied(fields,'Package'),
                       [('Record type','App activity event' if usage=='event-log' else 'App usage summary'),('Event',event),('Activity',supplied(fields,'Class')),('Active time (ms)',supplied(fields,'Time Active (ms)'))],
                       'Activity events and usage summaries remain distinct; neither alone proves deliberate user action.')
    return row


def investigator_records(db, selection, offset=0, limit=100, contact_basis='auto'):
    selection=dict(selection)
    if selection.get('category')=='messages':
        rows=select_artifacts(db,limit=MAX_RECORDS+1,**selection)
        if len(rows)>MAX_RECORDS or sum(len(json.dumps(r['data'],ensure_ascii=False).encode('utf-8')) for r in rows)>MAX_BYTES:
            raise UserError('Message presentation exceeds the bounded review budget. Narrow the source scope or use Source records.')
        entries=message_entries(rows)
        return {'records':entries[offset:offset+limit],'has_more':offset+limit<len(entries),'offset':offset,
                'summary':{'version':VERSION,'kind':'messages','matching_entries':len(entries),
                           'source_records':len(rows),'meaning':'Matching Discord IDs and content within one evidence bundle share an entry; original report observations remain available. Other sources remain separate.'}}
    if selection.get('category')!='contacts':
        rows=select_artifacts(db,limit=limit+1,offset=offset,**selection)
        return {'records':[display_record(r) for r in rows[:limit]],'has_more':len(rows)>limit,'offset':offset,
                'summary':{'version':VERSION,'meaning':'Readable projections preserve all original source fields. Record counts are not unique-event counts.'}}
    query=selection.pop('query',None);phone=selection.pop('phone_query',None)
    since=selection.pop('since',None);until=selection.pop('until',None)
    sort_field=selection.pop('sort_field',None);direction=selection.pop('sort_direction','asc');sort_mode=selection.pop('sort_mode','text')
    if sort_mode not in {'text','number','timestamp'} or direction not in {'asc','desc'}:raise UserError('Choose a supported sort interpretation and direction.')
    rows=select_artifacts(db,limit=MAX_RECORDS+1,**selection)
    if len(rows)>MAX_RECORDS or sum(len(json.dumps(r['data'],ensure_ascii=False).encode('utf-8')) for r in rows)>MAX_BYTES:
        raise UserError('Contact projection exceeds the bounded review budget. Narrow the evidence scope or use Source records.')
    entries,summary=contacts(rows,contact_basis)
    digits=phone_digits(phone) if phone else None
    if phone and digits is None:raise UserError('Enter one complete phone number; country codes and extensions are not inferred.')
    by_id={r['id']:r for r in rows}
    def matches(entry):
        observations=[by_id[r['id']] for r in entry['investigator_view']['observations']]
        if query and not any(query.casefold() in json.dumps(r,ensure_ascii=False).casefold() for r in observations):return False
        if digits and not any(phone_digits(value)==digits for value in entry['investigator_view']['phones']):return False
        if since or until:
            if not any(r['timestamp'] and (not since or r['timestamp']>=since) and (not until or r['timestamp']<=until) for r in observations):return False
        return True
    entries=[r for r in entries if matches(r)]
    if sort_field:
        def ordered_value(row):
            value=next((f['value'] for f in row['display_fields'] if f['name']==sort_field),None)
            value=sort_value(value,sort_mode)
            return Decimal(value) if value is not None and sort_mode=='number' else value
        valid=[r for r in entries if ordered_value(r) is not None]
        invalid=[r for r in entries if ordered_value(r) is None]
        valid.sort(key=lambda r:(ordered_value(r),r['id']),reverse=direction=='desc')
        entries=valid+invalid
    summary['matching_entries']=len(entries)
    return {'records':entries[offset:offset+limit],'has_more':offset+limit<len(entries),'offset':offset,'summary':summary}
