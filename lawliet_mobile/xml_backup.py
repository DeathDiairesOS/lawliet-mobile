"""Read documented SMS Backup & Restore XML exports without executing stylesheets."""
import hashlib
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat
from .messages import metadata
from .parsers import timestamp

VERSION = 'sms-backup-xml/0.2'
MAX_BYTES = 128*1024**2
MAX_RECORDS = 100000
MAX_ELEMENTS = 250000
MAX_DEPTH = 32


class _XMLRecords(list):
    def __init__(self, supported_root):
        super().__init__();self.supported_root=supported_root


class _BoundedTree(ET.TreeBuilder):
    """Check structure before building each element; never execute XML directives."""
    def __init__(self):
        super().__init__();self.depth=0;self.elements=0;self.records=0;self.stylesheet=None

    def start(self, tag, attrs):
        self.depth+=1;self.elements+=1
        if self.depth>MAX_DEPTH or self.elements>MAX_ELEMENTS:
            raise ValueError('XML element/depth bound exceeded; source retained, no records indexed.')
        if self.depth==2:
            self.records+=1
            if self.records>MAX_RECORDS:raise ValueError('XML export exceeds 100,000 records.')
        return super().start(tag,attrs)

    def end(self, tag):
        result=super().end(tag);self.depth-=1;return result

    def pi(self, target, text=None):
        # SyncTech optionally writes one stylesheet declaration. Preserve it as
        # inert source metadata; no path resolution, stylesheet load or rendering.
        if target=='xml-stylesheet' and self.stylesheet is None and len((text or '').encode())<=2048:
            self.stylesheet={'declaration':text or '', 'state':'ignored_not_loaded_or_executed'}
            return
        raise ValueError('XML processing instructions are refused; no stylesheet or external action executed.')


def xml_backup_records(path):
    if path.stat().st_size>MAX_BYTES:raise ValueError('XML export exceeds 128 MiB; split the export.')
    with path.open('rb') as stream:raw=stream.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES:raise ValueError('XML export exceeds 128 MiB; split the export.')
    # Only UTF-8 input is supported; decoding first also rejects UTF-16 tricks.
    text=raw.decode('utf-8-sig')
    if '\x00' in text or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():raise ValueError('DTD/entity declarations and non-UTF-8 XML are not accepted.')
    version=tuple(int(x) for x in re.findall(r'\d+',expat.EXPAT_VERSION)[:3])
    if version<(2,7,2):raise ValueError('XML backup parsing requires Expat >= 2.7.2.')
    builder=_BoundedTree()
    try:root=ET.fromstring(text,parser=ET.XMLParser(target=builder))
    except ET.ParseError as exc:raise ValueError(f'Malformed XML export: {exc}') from exc
    output=_XMLRecords(root.tag in {'smses','calls'})
    if not output.supported_root:return output
    declared=root.get('count')
    if declared is not None and (not declared.isdigit() or int(declared)!=len(root)):
        raise ValueError('Declared XML record count differs from the supplied records; file retained for review.')
    if len(root)>100000:raise ValueError('XML export exceeds 100,000 records.')
    for index,node in enumerate(root,1):
        attrs=dict(node.attrib);when=timestamp(attrs.get('date'),unit='milliseconds')
        data={'original':attrs,'export':dict(root.attrib),'format':'SMS Backup & Restore XML',
              'xml_parser_version':VERSION,
              'note':'Supplied export, not an independent guarantee of phone-wide history.'}
        if builder.stylesheet is not None:data['stylesheet']=builder.stylesheet
        if root.tag=='calls' and node.tag=='call':
            if not {'number','date','duration','type'}<=attrs.keys():raise ValueError('Call export record lacks required fields.')
            kind={'1':'incoming','2':'outgoing','3':'missed'}.get(attrs['type'],'type '+attrs['type'])
            output.append(('calls',when,attrs['date'],f'Call · {kind} · {attrs["number"]}',f'Duration: {attrs["duration"]} seconds',f'xml:call={index}',data));continue
        if root.tag!='smses' or node.tag not in {'sms','mms'}:raise ValueError('Unexpected record in XML export.')
        required={'date','type','body','address'} if node.tag=='sms' else {'date','msg_box'}
        if not required<=attrs.keys():raise ValueError('Message export record lacks required fields.')
        kind=attrs.get('type' if node.tag=='sms' else 'msg_box','')
        boxes={'1':'incoming','2':'outgoing','3':'draft','4':'outbox','5':'failed'}
        if node.tag=='sms':boxes['6']='queued'
        direction=boxes.get(kind,'unknown')
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
            absent_payloads=sum(1 for p in parts if p.get('ct') not in {'text/plain','application/smil'} and not p.get('embedded_payload'))
            data['mms_coverage']={'parts_state':'present_in_export' if parts else 'absent_from_export',
                'parts_observed':len(parts),'nontext_parts_without_embedded_payload':absent_payloads,
                'payload_decoding':'not_performed','limitation':'Part attributes and encoded bytes are export observations; no attachment file acquisition or RCS protocol validation is established.'}
        sender=next((p['address'] for p in participants if p.get('type')=='137' and p.get('address') not in {None,'insert-address-token'}),'')
        if not sender and direction=='incoming' and node.tag=='sms':sender=address
        data.update(parts=parts,addresses=participants,message=metadata(app,address or f'unlinked:{index}',sender,address if direction=='outgoing' else '',direction,
            label=attrs.get('contact_name') or address,participants=usable,attachment_status='payloads_retained_in_original_xml' if any(p.get('embedded_payload') for p in parts) else 'not_established'))
        output.append(('messages',when,attrs.get('date'),f'{app.upper()} · {direction} · {address}',body,f'xml:{node.tag}={index}',data))
    return output


def xml_coverage(records, logical_path):
    if not records:
        supported=getattr(records,'supported_root',False)
        yield {'source':logical_path,'state':'parsed-empty' if supported else 'unsupported',
               'category':'XML backup records','records':0,'rows_observed':0 if supported else None,
               'reason':'Recognized SMS/calls export contains zero supplied records; not a device-wide absence conclusion.' if supported
               else 'XML root is not a supported SMS/calls export; no message absence or complete XML examination claimed.'}
    for record in records:
        reference=record[-2];data=record[-1];coverage=data.get('mms_coverage')
        if not coverage:continue
        if coverage['parts_state']=='absent_from_export':
            yield {'source':logical_path+'#'+reference,'state':'unresolved','category':'MMS parts',
                   'reason':'No MMS part records are supplied in this export; body and attachment completeness cannot be determined.'}
        elif coverage['nontext_parts_without_embedded_payload']:
            yield {'source':logical_path+'#'+reference,'state':'unresolved','category':'MMS payloads',
                   'reason':'Nontext MMS part records lack embedded payloads; referenced filenames/URLs are not opened or fetched.'}
        if any(p.get('embedded_payload') for p in data.get('parts',[])):
            yield {'source':logical_path+'#'+reference,'state':'unsupported','category':'MMS payload decoding',
                   'reason':'Encoded MMS payloads are retained in original XML but are not decoded, verified as media or linked to acquired files.'}
