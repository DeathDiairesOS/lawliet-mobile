"""Read documented SMS Backup & Restore XML exports without executing stylesheets."""
import hashlib
import xml.etree.ElementTree as ET
from .messages import metadata
from .parsers import timestamp


def xml_backup_records(path):
    if path.stat().st_size>128*1024**2:raise ValueError('XML export exceeds 128 MiB; split the export.')
    raw=path.read_bytes()
    # Only UTF-8 input is supported; decoding first also rejects UTF-16 tricks.
    text=raw.decode('utf-8-sig')
    if '\x00' in text or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():raise ValueError('DTD/entity declarations and non-UTF-8 XML are not accepted.')
    try:root=ET.fromstring(text)
    except ET.ParseError as exc:raise ValueError(f'Malformed XML export: {exc}') from exc
    if root.tag not in {'smses','calls'}:return []  # Unrelated XML remains an unparsed file.
    declared=root.get('count')
    if declared is not None and (not declared.isdigit() or int(declared)!=len(root)):
        raise ValueError('Declared XML record count differs from the supplied records; file retained for review.')
    output=[]
    if len(root)>100000:raise ValueError('XML export exceeds 100,000 records.')
    for index,node in enumerate(root,1):
        attrs=dict(node.attrib);when=timestamp(attrs.get('date'),unit='milliseconds')
        data={'original':attrs,'export':dict(root.attrib),'format':'SMS Backup & Restore XML',
              'note':'Supplied export, not an independent guarantee of phone-wide history.'}
        if root.tag=='calls' and node.tag=='call':
            if not {'number','date','duration','type'}<=attrs.keys():raise ValueError('Call export record lacks required fields.')
            kind={'1':'incoming','2':'outgoing','3':'missed'}.get(attrs['type'],'type '+attrs['type'])
            output.append(('calls',when,attrs['date'],f'Call · {kind} · {attrs["number"]}',f'Duration: {attrs["duration"]} seconds',f'xml:call={index}',data));continue
        if root.tag!='smses' or node.tag not in {'sms','mms'}:raise ValueError('Unexpected record in XML export.')
        required={'date','type','body','address'} if node.tag=='sms' else {'date','msg_box'}
        if not required<=attrs.keys():raise ValueError('Message export record lacks required fields.')
        kind=attrs.get('type' if node.tag=='sms' else 'msg_box','')
        direction={'1':'incoming','2':'outgoing','3':'draft','4':'outbox','5':'failed','6':'queued'}.get(kind,'unknown')
        participants=[dict(a.attrib) for a in node.findall('./addrs/addr')]
        usable=[p.get('address','') for p in participants if p.get('address') not in {None,'','insert-address-token'}]
        address=attrs.get('address') or '~'.join(usable)
        app='rcs' if attrs.get('s_chat')=='1' or '@rcs.google.com' in address or '@bot.rcs.google.com' in address else node.tag
        if node.tag=='sms':body=attrs['body'];parts=[]
        else:
            parts=[];bodies=[]
            for part in node.findall('./parts/part'):
                p=dict(part.attrib);encoded=p.pop('data',None)
                if encoded is not None:p['embedded_payload']={'base64_characters':len(encoded),'encoded_sha256':hashlib.sha256(encoded.encode()).hexdigest(),'status':'retained_in_original_xml_not_decoded'}
                if p.get('ct')=='text/plain' and p.get('text') not in {None,'null'}:bodies.append(p['text'])
                parts.append(p)
            body='\n'.join(bodies)
        sender=next((p['address'] for p in participants if p.get('type')=='137' and p.get('address') not in {None,'insert-address-token'}),'')
        if not sender and direction=='incoming' and node.tag=='sms':sender=address
        data.update(parts=parts,addresses=participants,message=metadata(app,address or f'unlinked:{index}',sender,address if direction=='outgoing' else '',direction,
            label=attrs.get('contact_name') or address,participants=usable,attachment_status='payloads_retained_in_original_xml' if any(p.get('embedded_payload') for p in parts) else 'not_established'))
        output.append(('messages',when,attrs.get('date'),f'{app.upper()} · {direction} · {address}',body,f'xml:{node.tag}={index}',data))
    return output
