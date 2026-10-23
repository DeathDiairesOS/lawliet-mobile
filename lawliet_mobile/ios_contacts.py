"""Source-local AddressBook phone/email joins; no person or account inference."""
import json
import sqlite3

SCHEMA = 'ios-addressbook-contact/1'
MAX_VALUES_PER_CONTACT = 4096
MAX_VALUE_BYTES_PER_CONTACT = 4 * 1024**2
PROPERTY_KINDS = {3: 'phone', 4: 'email'}
PROPERTY_NOTE = ('Observed AddressBook schema: property 3 is interpreted as phone and 4 as email. '
                 'Other properties are retained in the source database, not decoded here.')


def _shape(db, table):
    columns = {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')}
    lower = {name.lower() for name in columns}
    identifier = next((name for name in ('rowid', '_rowid_', 'oid') if name not in lower), None)
    if identifier:
        try:
            db.execute(f'SELECT {identifier} FROM "{table}" LIMIT 0')
        except sqlite3.DatabaseError:
            identifier = None
    return columns, identifier


def _schema(db):
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    person = _shape(db, 'ABPerson') if 'ABPerson' in tables else (set(), None)
    multi = _shape(db, 'ABMultiValue') if 'ABMultiValue' in tables else (set(), None)
    label = _shape(db, 'ABMultiValueLabel') if 'ABMultiValueLabel' in tables else (set(), None)
    valid = bool(person[1] and multi[1] and {'record_id', 'property', 'value'} <= multi[0])
    labels = bool(label[1] and 'value' in label[0] and 'label' in multi[0])
    return tables, person, multi, label, valid, labels


def _rows(db, sql):
    cursor = db.execute(sql)
    names = [item[0] for item in cursor.description]
    for row in cursor:
        yield {key: {'blob_bytes': len(value)} if isinstance(value, bytes) else value
               for key, value in zip(names, row)}


def person_records(db):
    """Yield ABPerson dictionaries with bounded, separately referenced values.

    Both cursors stream in source-record order; no complete contacts database is
    loaded into Python. Call contact_coverage separately for file-level gaps.
    The caller owns the read-only working copy, SQLite resource limits and hashes.
    """
    _, person, multi, label, valid, labels = _schema(db)
    if not person[1]:
        return
    if {'__rowid__', 'ios_contact', 'timestamp_semantics'} & person[0] or '__rowid__' in multi[0]:
        raise ValueError('AddressBook source columns collide with the retained row identifier; contacts not decoded.')
    values = iter(())
    if valid:
        # These internal aliases must not replace an original multivalue column.
        reserved = {'__label_rowid__', '__label_value__'}
        if reserved & multi[0]:
            raise ValueError('AddressBook source columns collide with label reference fields; contacts not decoded.')
        label_fields = (f', l.{label[1]} AS __label_rowid__, l.value AS __label_value__' if labels else '')
        label_join = (f' LEFT JOIN ABMultiValueLabel l ON typeof(m.label)=\'integer\' AND m.label=l.{label[1]}' if labels else '')
        values = _rows(db, f'SELECT m.{multi[1]} AS __rowid__, m.*{label_fields} '
            f'FROM ABMultiValue m{label_join} WHERE typeof(m.record_id)=\'integer\' '
            f'AND typeof(m.property)=\'integer\' AND m.property IN (3,4) '
            f'ORDER BY m.record_id,m.{multi[1]}')
    current = next(values, None)
    for row in _rows(db, f'SELECT {person[1]} AS __rowid__, * FROM ABPerson ORDER BY {person[1]}'):
        identifier = row['__rowid__']
        while current is not None and current['record_id'] < identifier:
            current = next(values, None)  # Orphans are counted by contact_coverage.
        observations = []
        byte_count = 0
        while current is not None and current['record_id'] == identifier:
            original = dict(current)
            label_rowid = original.pop('__label_rowid__', None)
            label_value = original.pop('__label_value__', None)
            value = original['value']
            item = {'kind': PROPERTY_KINDS[original['property']], 'property': original['property'],
                    'value': value, 'source_ref': f"ABMultiValue:ROWID={original['__rowid__']}",
                    'person_ref': f'ABPerson:ROWID={identifier}', 'original': original,
                    'value_state': 'supplied-text' if isinstance(value, str) and value else 'unsupported-or-empty'}
            raw_label = original.get('label')
            item['label'] = {'identifier': raw_label, 'value': label_value,
                'source_ref': f'ABMultiValueLabel:ROWID={label_rowid}' if label_rowid is not None else None,
                'state': ('linked' if label_rowid is not None else 'not_supplied' if raw_label is None
                          else 'unresolved')}
            byte_count += len(json.dumps(item, ensure_ascii=False).encode('utf-8'))
            if len(observations) >= MAX_VALUES_PER_CONTACT or byte_count > MAX_VALUE_BYTES_PER_CONTACT:
                raise ValueError('AddressBook contact values exceed the bounded count/byte limit; contact coverage is incomplete.')
            observations.append(item)
            current = next(values, None)
        row['ios_contact'] = {'schema': SCHEMA, 'person_ref': f'ABPerson:ROWID={identifier}',
            'values': observations, 'values_state': 'examined' if valid else 'unsupported-schema',
            'scope': 'Joined within this source database by ABMultiValue.record_id = ABPerson.ROWID. '
                     'A source contact is not an independently verified person.',
            'property_interpretation': PROPERTY_NOTE}
        row['timestamp_semantics'] = ('ABPerson.ModificationDate in Apple epoch seconds; contact modification time, '
                                      'not the creation time of a phone number or email address.')
        yield row


def contact_coverage(db, logical_path):
    """Return counted limitations without exposing contact values in diagnostics."""
    tables, person, multi, label, valid, labels = _schema(db)
    if not {'ABPerson', 'ABMultiValue'} & tables:
        return []
    result = []

    def add(code, table, reason, count=None):
        item = {'source': logical_path, 'table': table, 'category': 'contacts',
                'state': 'limited', 'code': code, 'reason': reason}
        if count is not None:
            item['rows_observed'] = count
        result.append(item)

    if not person[1]:
        add('ios_contacts_person_schema', 'ABPerson', 'ABPerson with a stable SQLite row identifier is unavailable; contact joins are unsupported.')
        return result
    if not valid:
        add('ios_contacts_values_schema', 'ABMultiValue', 'ABMultiValue with record_id, property, value and a stable row identifier is unavailable; phone/email coverage is not established.')
        return result
    p = person[1]
    orphan = db.execute(f"SELECT COUNT(*) FROM ABMultiValue m WHERE typeof(m.record_id)!='integer' "
                        f'OR NOT EXISTS (SELECT 1 FROM ABPerson p WHERE p.{p}=m.record_id)').fetchone()[0]
    if orphan:
        add('ios_contacts_orphan_values', 'ABMultiValue', 'Values with missing or unsupported person linkage remain in the source database and are not assigned to contacts.', orphan)
    unknown = db.execute("SELECT COUNT(*) FROM ABMultiValue WHERE typeof(property)!='integer' OR property NOT IN (3,4)").fetchone()[0]
    if unknown:
        add('ios_contacts_unsupported_properties', 'ABMultiValue', PROPERTY_NOTE, unknown)
    invalid = db.execute("SELECT COUNT(*) FROM ABMultiValue WHERE typeof(property)='integer' AND property IN (3,4) "
                         "AND (typeof(value)!='text' OR value='')").fetchone()[0]
    if invalid:
        add('ios_contacts_invalid_values', 'ABMultiValue', 'Phone/email rows with empty or non-text values remain in the source database; linked rows retain observations but are not used as phone/email text.', invalid)
    if 'label' in multi[0]:
        clause = "typeof(m.property)='integer' AND m.property IN (3,4) AND m.label IS NOT NULL"
        if labels:
            clause += f" AND (typeof(m.label)!='integer' OR NOT EXISTS (SELECT 1 FROM ABMultiValueLabel l WHERE l.{label[1]}=m.label))"
        count = db.execute('SELECT COUNT(*) FROM ABMultiValue m WHERE ' + clause).fetchone()[0]
        if count:
            add('ios_contacts_unresolved_labels', 'ABMultiValueLabel', 'Some supplied phone/email labels cannot be resolved to a stable label row; values retain the original label identifier.', count)
    else:
        add('ios_contacts_label_schema', 'ABMultiValue', 'The multivalue label column is unavailable; phone/email values have no established source label.')
    return result


def contact_values(data, kind):
    """Return only explicitly typed, linked observations for display/search."""
    contact = data.get('ios_contact')
    if not isinstance(contact, dict) or contact.get('schema') != SCHEMA or kind not in PROPERTY_KINDS.values():
        return []
    values = contact.get('values')
    if not isinstance(values, list):
        return []
    return [item['value'] for item in values if isinstance(item, dict)
            and item.get('kind') == kind and type(item.get('property')) is int
            and PROPERTY_KINDS.get(item.get('property')) == kind
            and item.get('person_ref') == contact.get('person_ref')
            and item.get('value_state') == 'supplied-text' and isinstance(item.get('value'), str)
            and item['value']]
