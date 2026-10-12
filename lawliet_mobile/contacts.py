"""Conservative UTF-8 vCard 3/4 import for customer-supplied contact exports."""
from .parsers import timestamp


def unescape(value):
    result=[];i=0
    while i<len(value):
        if value[i]=='\\' and i+1<len(value):
            i+=1;result.append('\n' if value[i] in 'nN' else value[i])
        else:result.append(value[i])
        i+=1
    return ''.join(result)


def vcard_records(path):
    if path.stat().st_size>64*1024**2:raise ValueError('vCard export exceeds 64 MiB.')
    # Folded lines begin with a space or tab; their continuation marker is removed.
    lines=[]
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        if line.startswith((' ','\t')) and lines:lines[-1]+=line[1:]
        else:lines.append(line)
    card=None;number=0
    for line in lines:
        if line.upper()=='BEGIN:VCARD':
            if card is not None:raise ValueError('Nested vCard record.')
            card=[]
        elif line.upper()=='END:VCARD':
            if card is None:raise ValueError('vCard end without beginning.')
            number+=1;fields={};versions=[]
            for key,value in card:
                property_name=key.split(';',1)[0].rsplit('.',1)[-1].upper()
                if property_name=='VERSION':versions.append(value)
                if property_name in {'FN','N','TEL','EMAIL','ORG','ADR','NOTE','UID','REV'}:
                    if 'ENCODING=' in key.upper() or ('CHARSET=' in key.upper() and 'CHARSET=UTF-8' not in key.upper()):raise ValueError('Encoded vCard text is unsupported; supply a UTF-8 vCard 3.0/4.0 export.')
                    fields.setdefault(property_name,[]).append(unescape(value))
            if versions not in [['3.0'],['4.0']]:raise ValueError('Only UTF-8 vCard 3.0/4.0 exports are supported.')
            title=next(iter(fields.get('FN',[])),None) or next(iter(fields.get('N',[])),'Unnamed contact')
            raw=next(iter(fields.get('REV',[])),None)
            yield 'contacts',timestamp(raw),raw,title,' · '.join(f'{k}: {v}' for k,values in fields.items() for v in values),f'vcard:record={number}',{'vcard_version':versions[0],'properties':fields,'note':'Supplied contact export; labels and authorship are not independently authenticated.'}
            card=None
        elif card is not None:
            if ':' not in line:raise ValueError('Malformed vCard property.')
            card.append(tuple(line.split(':',1)))
    if card is not None:raise ValueError('Unterminated vCard record.')
    if number==0:raise ValueError('No vCard records found.')
