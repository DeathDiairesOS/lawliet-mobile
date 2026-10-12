"""Create fictional mobile evidence for a runnable, offline demonstration."""
import hashlib
import plistlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

from .core import UserError, connect, create_case, import_evidence
from .parsers import native_analyze
from .report import write_report


@contextmanager
def transaction(connection):
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def create_demo(workspace, case="demo"):
    root = create_case(workspace, case, "Parcel link investigation · SYNTHETIC DEMO", "Demo examiner")
    fixtures = root / "demo-fixtures"
    ios, android = fixtures / "ios-backup", fixtures / "android-extraction"
    ios.mkdir(parents=True)
    android.mkdir(parents=True)
    base = datetime(2026, 10, 10, 14, 0, tzinfo=timezone.utc).timestamp()
    apple = base - datetime(2001, 1, 1, tzinfo=timezone.utc).timestamp()
    manifest = sqlite3.connect(ios / "Manifest.db")
    manifest.execute("CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
    (ios / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False, "Version": "9.1", "Demo": True}))

    def ios_db(relative):
        file_id = hashlib.sha1(f"HomeDomain-{relative}".encode()).hexdigest()
        folder = ios / file_id[:2]
        folder.mkdir(exist_ok=True)
        manifest.execute("INSERT INTO Files VALUES(?,?,?,1)", (file_id, "HomeDomain", relative))
        return sqlite3.connect(folder / file_id)

    with transaction(ios_db("Library/SMS/sms.db")) as db:
        db.executescript("CREATE TABLE handle(id TEXT); CREATE TABLE message(date INTEGER, text TEXT, handle_id INTEGER, is_from_me INTEGER, service TEXT);")
        db.execute("INSERT INTO handle VALUES('+1-202-555-0142')")
        for minutes, body, outgoing in [(2, "Your parcel is on hold. Confirm delivery: https://parcel-review.example/verify", 0), (4, "Did you send me a parcel link?", 1), (6, "No. Please don't enter any details on that page.", 0), (13, "I opened it but closed it before filling anything in.", 1)]:
            db.execute("INSERT INTO message VALUES(?,?,?,?,?)", (int((apple + minutes * 60) * 1e9), body, 1, outgoing, "iMessage"))
    with transaction(ios_db("Library/CallHistoryDB/CallHistory.storedata")) as db:
        db.execute("CREATE TABLE ZCALLRECORD(Z_PK INTEGER, ZDATE REAL, ZADDRESS TEXT, ZDURATION REAL)")
        db.executemany("INSERT INTO ZCALLRECORD VALUES(?,?,?,?)", [(1, apple + 8 * 60, "+1-202-555-0142", 94), (2, apple + 30 * 60, "+1-202-555-0199", 203)])
    with transaction(ios_db("Library/Safari/History.db")) as db:
        db.executescript("CREATE TABLE history_items(id INTEGER, url TEXT); CREATE TABLE history_visits(id INTEGER,history_item INTEGER,visit_time REAL,title TEXT);")
        db.executemany("INSERT INTO history_items VALUES(?,?)", [(1, "https://parcel-review.example/verify"), (2, "https://support.example/security")])
        db.executemany("INSERT INTO history_visits VALUES(?,?,?,?)", [(1, 1, apple + 3 * 60, "Delivery verification"), (2, 2, apple + 14 * 60, "Account security help")])
    with transaction(ios_db("Library/AddressBook/AddressBook.sqlitedb")) as db:
        db.execute("CREATE TABLE ABPerson(First TEXT,Last TEXT,Organization TEXT,ModificationDate REAL)")
        db.executemany("INSERT INTO ABPerson VALUES(?,?,?,?)", [("Alex", "Morgan", "Example Research", apple - 86400), ("Jordan", "Lee", "Example Support", apple - 7200)])
    manifest.commit()
    manifest.close()
    sms_path = android / "data/data/com.android.providers.telephony/databases"
    sms_path.mkdir(parents=True)
    with transaction(sqlite3.connect(sms_path / "mmssms.db")) as db:
        db.execute("CREATE TABLE sms(_id INTEGER,date INTEGER,address TEXT,body TEXT,type INTEGER)")
        db.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", [(1, int((base + 60) * 1000), "+1-202-555-0108", "Package awaiting verification: https://parcel-review.example/verify", 1), (2, int((base + 10 * 60) * 1000), "+1-202-555-0142", "I received the same URL on my Android phone.", 2), (3, int((base + 22 * 60) * 1000), "+1-202-555-0142", "Reported the message to support.", 2)])
    calls_path = android / "data/data/com.android.providers.contacts/databases"
    calls_path.mkdir(parents=True)
    with transaction(sqlite3.connect(calls_path / "contacts2.db")) as db:
        db.executescript("CREATE TABLE calls(_id INTEGER,date INTEGER,number TEXT,duration INTEGER,type INTEGER); CREATE TABLE mimetypes(_id INTEGER,mimetype TEXT); CREATE TABLE data(_id INTEGER,raw_contact_id INTEGER,mimetype_id INTEGER,data1 TEXT);")
        db.execute("INSERT INTO calls VALUES(1,?,?,120,2)", (int((base + 25 * 60) * 1000), "+1-202-555-0199"))
        db.execute("INSERT INTO mimetypes VALUES(1,'vnd.android.cursor.item/phone_v2')")
        db.execute("INSERT INTO data VALUES(1,1,1,'+1-202-555-0142')")
    results = []
    with connect(workspace, case) as (root, db):
        for source, platform, label in [(ios, "ios", "Demo iPhone · logical backup"), (android, "android", "Demo Android · filesystem extraction")]:
            identifier, _, _ = import_evidence(root, db, source, platform, label)
            results.append(native_analyze(root, db, identifier))
        report = write_report(root, db, root / "reports" / "investigation.html")
    return {"case": case, "synthetic": True, "runs": results, "report": report,
            "next": [f"lawliet timeline --case {case}", f"lawliet search parcel-review.example --case {case}", f"lawliet verify --case {case}"]}
