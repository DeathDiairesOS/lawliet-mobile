"""Lawliet Mobile command-line interface. Standard library only."""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .core import UserError, case_dir, connect, create_case, import_evidence, select_artifacts, verify
from .correlate import shared_entities
from .demo import create_demo
from .parsers import native_analyze, timestamp
from .report import write_export, write_report
from .tools import TOOLS, collect, configure, devices, doctor
from .acquisition import collect_android, case_coverage
from .android_backup import import_backup
from .messages import conversations, import_chat
from .discord_package import import_discord_package
from .workflows import SCENARIOS, workflow
from .review import review
from .validation import preflight, validate_case
from .phone_assessment import assess_android
from .pipeline import process_evidence
from .adapters import analyze_file as adapter_analyze_file, analyze as adapter_analyze, catalog as adapter_catalog
from .app_coverage import app_coverage
from .findings import add_finding, list_findings, export_findings
from .discovery import PROFILES, preview as analysis_preview


def clean(value):
    # Evidence text must not emit terminal escape/control sequences.
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value if value is not None else ""))


def table(headers, rows, widths=None):
    rows = [[clean(v) for v in row] for row in rows]
    widths = widths or [min(42, max([len(h)] + [len(row[i]) for row in rows])) for i, h in enumerate(headers)]
    def line(row):
        return "  ".join((v if len(v) <= width else v[:max(width - 1, 0)] + "…").ljust(width) for v, width in zip(row, widths))
    print(line(headers))
    print("  ".join("─" * width for width in widths))
    for row in rows:
        print(line(row))
    if not rows:
        print("No records.")


def emit(value, json_mode=False):
    if json_mode:
        print(json.dumps(value, indent=2, ensure_ascii=False, default=str))
    elif isinstance(value, dict):
        for key, item in value.items():
            print(f"{key.replace('_', ' ').capitalize():20} {clean(json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else item)}")
    else:
        print(clean(value))


def utc_argument(value):
    if len(value) == 10:
        value += "T00:00:00Z"
    result = timestamp(value)
    if not result:
        raise argparse.ArgumentTypeError("Use YYYY-MM-DD or a timezone-aware ISO timestamp.")
    return result


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Must be positive.")
    return number


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("Must be zero or positive.")
    return number


def parser():
    p = argparse.ArgumentParser(prog="lawliet", description="LAWLIET MOBILE · lightweight, local mobile evidence triage",
                                epilog="""GET STARTED
  lawliet demo                           Try fictional evidence without a phone
  lawliet doctor                         Check optional tools
  lawliet case create CASE-001            Create a case
  lawliet process /path/to/extraction --case CASE-001
                                         Preserve evidence and run ALEAPP/iLEAPP
  lawliet timeline --case CASE-001        Review dated and undated artifacts
  lawliet search invoice --case CASE-001  Search parsed records
  lawliet verify --case CASE-001          Check retained evidence integrity

CONNECTED PHONES
  lawliet devices
  lawliet assess-android --case CASE-001 --serial SERIAL
  lawliet collect --help                  Collection profiles and examples
  lawliet workflow messages              Customer workflow and blind spots

MORE HELP
  lawliet COMMAND --help                 Options and examples for a command
  --workspace /path/to/cases              Use the same workspace in the app
  --json                                 Structured output for automation

Collection and parsing are separate: LEAPP cannot parse data absent from the
acquisition. Local by default; optional agent execution has explicit disclosure gates.
Original evidence is copied and hashed.""", formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"Lawliet Mobile {__version__}")
    p.add_argument("--workspace", default=os.environ.get("LAWLIET_WORKSPACE", os.environ.get("ANCALOR_WORKSPACE", "lawliet-cases")), help="case workspace (default: ./lawliet-cases)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)
    state = sub.add_parser('device-state', help='record/list examiner device-state worksheets; never queries a phone')
    state.add_argument('--case', required=True)
    state.add_argument('--record-json', help='worksheet JSON file; omit to list recorded worksheets')
    state.add_argument('--after', type=nonnegative, default=0)
    state.add_argument('--limit', type=positive, default=100)
    custody = sub.add_parser('custody', help='record/list claimed custody events and historical gaps')
    custody.add_argument('--case', required=True)
    custody.add_argument('--record-json', help='event JSON file; omit to list recorded events')
    custody.add_argument('--after', type=nonnegative, default=0)
    custody.add_argument('--limit', type=positive, default=100)
    custody.add_argument('--item-id', help='filter history by case-local custody item ID')
    case = sub.add_parser("case", help="create and inspect cases").add_subparsers(dest="action", required=True)
    create = case.add_parser("create", help="create a private case directory")
    create.add_argument("id")
    create.add_argument("--name")
    create.add_argument("--examiner")
    case.add_parser("list", help="list cases")
    show = case.add_parser("show", help="case summary, evidence inventory, and coverage")
    show.add_argument("id")
    engines = sub.add_parser('engine', help='external investigation engine (Mulder); independent of deterministic parsers')
    agent = sub.add_parser('agent-collection', help='authorize a bounded collection for Mulder; automatically preserve, parse and index results')
    agent_actions = agent.add_subparsers(dest='action', required=True)
    agent_config = agent_actions.add_parser('configure', help='select an existing Mulder launcher; never downloads or starts it')
    agent_config.add_argument('--mulder-launcher', required=True)
    authorize = agent_actions.add_parser('authorize', help='record examiner approval for one exact device and collection scope; does not collect yet')
    authorize.add_argument('--case', required=True)
    authorize.add_argument('--objective', required=True)
    authorize.add_argument('--serial', required=True)
    from .agent_collection import PROFILES
    authorize.add_argument('--profile', action='append', required=True, choices=PROFILES,
                           help='triage collects diagnostics without backup; messages explicitly attempts legacy telephony backup and may require device confirmation')
    authorize.add_argument('--pull', action='append', default=[], help='explicit shared-storage path for files profile')
    authorize.add_argument('--android-user', type=nonnegative)
    authorize.add_argument('--examiner', required=True)
    authorize.add_argument('--authorize-collection', action='store_true', help='explicitly authorize only the selected device/profile reads and local processing')
    authorize.add_argument('--max-records', type=positive, default=1000)
    authorize.add_argument('--max-bytes', type=positive, default=64*1024**2, help='per-profile budget up to 20 GiB; SMS and contacts are capped at 64 MiB')
    authorize.add_argument('--timeout', type=positive, default=60, help='per-command timeout seconds')
    for name in ('list', 'status', 'run'):
        command = agent_actions.add_parser(name, help='execute an already authorized plan locally' if name=='run' else 'read persistent collection state')
        command.add_argument('--case', required=True)
        if name != 'list': command.add_argument('plan_id')
    engine_actions = engines.add_subparsers(dest='action', required=True)
    for name in ('check', 'start', 'list', 'status', 'cancel', 'logs'):
        command = engine_actions.add_parser(name)
        command.add_argument('--case', required=True)
        if name in ('check', 'start'):
            command.add_argument('--config', required=True, help='JSON configuration without credentials; see docs/MULDER.md')
        elif name in ('status', 'cancel', 'logs'):
            command.add_argument('job_id')
    report_import = sub.add_parser('import-report', help='retain one JSONL/TSV derived report; optionally contain decoding with configured existing runtime')
    report_import.add_argument('path')
    report_import.add_argument('--case', required=True)
    report_import.add_argument('--format', choices=('jsonl','tsv'), required=True)
    report_import.add_argument('--label')
    report_import.add_argument('--contained', action='store_true', help='require contained decoder;32MiB input,16MiB normalized output; no host fallback; no folders')
    import_output = engine_actions.add_parser('import-output', help='preserve and review existing Mulder outputs locally; no model or parser execution')
    import_output.add_argument('path', help='completed Mulder output directory')
    import_output.add_argument('--case', required=True, help='destination Lawliet case')
    import_output.add_argument('--upstream-case-id', required=True, help='Mulder case ID used in its output filenames and database')
    import_output.add_argument('--version', required=True, help='examiner-declared Mulder version; currently 1.5.2')
    investigation = sub.add_parser('investigation', help='local investigation scope, retrieval and durable query trace')
    actions = investigation.add_subparsers(dest='action', required=True)
    start = actions.add_parser('create', help='record objective and explicitly authorized imported evidence; no model execution')
    start.add_argument('--case', required=True)
    start.add_argument('--objective', required=True)
    start.add_argument('--evidence', action='append', required=True, help='repeat for each authorized evidence ID')
    for name in ('show', 'trace', 'query', 'note', 'export'):
        command = actions.add_parser(name)
        command.add_argument('investigation_id')
        command.add_argument('--case', required=True)
        if name == 'trace':
            command.add_argument('--after', type=nonnegative, default=0)
            command.add_argument('--limit', type=positive, default=100)
        elif name == 'query':
            command.add_argument('--text', required=True)
            command.add_argument('--action-key', required=True, help='unique request ID; repeat unchanged to replay the saved result')
            command.add_argument('--limit', type=positive, default=20)
        elif name == 'note':
            from .investigation import ENTRY_KINDS
            command.add_argument('--kind', choices=ENTRY_KINDS, required=True)
            command.add_argument('--text', required=True)
            command.add_argument('--artifact', action='append', default=[], help='source artifact ID; repeatable')
        elif name == 'export':
            command.add_argument('--out', required=True, help='new local draft JSON report filename; never uploads or releases')
    for name, help_text in [("import", "copy and hash a backup, folder, ZIP/TAR, or file"),
                            ("process", "preserve acquired evidence, run ALEAPP/iLEAPP, and index all reports")]:
        intake = sub.add_parser(name, help=help_text)
        intake.add_argument("path")
        intake.add_argument("--case", required=True)
        intake.add_argument("--platform", choices=["auto", "ios", "android"], default="auto")
        intake.add_argument("--label")
        intake.add_argument("--max-gib", type=positive, default=20)
        intake.add_argument("--max-files", type=positive, default=100000)
        if name == "process":
            intake.add_argument("--engine", choices=["auto", "aleapp", "ileapp", "native"], default="auto")
            intake.add_argument("--timeout", type=positive, default=900)
    chat = sub.add_parser("import-chat", help="import a WhatsApp text, ZIP or folder export with explicit date interpretation")
    chat.add_argument("path")
    chat.add_argument("--case", required=True)
    chat.add_argument("--date-order", choices=["dmy", "mdy", "ymd"], required=True)
    chat.add_argument("--timezone", help="IANA timezone; omitted means messages remain undated")
    chat.add_argument("--year-century", type=int, help="Explicit century for two-digit export years, e.g. 2000; omitted keeps them undated")
    chat.add_argument("--label")
    chat.add_argument("--chat-path", help="relative transcript path when a bundle contains several chats")
    chat.add_argument("--reuse", action="store_true", help="reuse an intact identical export with the same date interpretation")
    discord = sub.add_parser("import-discord", help="preserve and index a supplied Discord account data package ZIP or folder")
    discord.add_argument("path")
    discord.add_argument("--case", required=True)
    discord.add_argument("--timezone", help="explicit IANA timezone for timestamps lacking an offset; omitted keeps those records undated")
    discord.add_argument("--label")
    discord.add_argument("--max-gib", type=positive, default=20)
    discord.add_argument("--max-files", type=positive, default=100000)
    conv = sub.add_parser("conversations", help="list source-scoped normalized message conversations")
    conv.add_argument("--case", required=True)
    conv.add_argument("--app")
    conv.add_argument("--evidence")
    conv.add_argument("--parser", help="exact parser name, e.g. ileapp")
    conv.add_argument("--run", help="select an indexed analysis run or legacy LEAPP/Dissect report run")
    review_cmd = sub.add_parser("review", help="analyze or reuse evidence and create a complete message export with a bounded HTML preview")
    review_cmd.add_argument("--case", required=True)
    review_cmd.add_argument("--evidence", required=True)
    review_cmd.add_argument("--engine", choices=['native', 'ileapp', 'aleapp'], default='native')
    review_cmd.add_argument("--run", help="reuse this completed LEAPP run")
    review_cmd.add_argument("--reanalyze", action='store_true', help="run the selected engine again instead of reusing its latest completed run")
    review_cmd.add_argument("--preview-limit", type=positive, default=500)
    review_cmd.add_argument("--timeout", type=positive, default=900)
    coverage = sub.add_parser("coverage", help="show collected, missing and unparsed evidence coverage")
    coverage.add_argument("--case", required=True)
    assessment = sub.add_parser('case-assess', help='assess a customer scenario against selected indexed evidence; no collection or analysis',
                                description='Summarize indexed records, source references and recorded gaps for one customer scenario. Reads retained metadata only; does not collect, parse, verify evidence bytes or approve findings.')
    assessment.add_argument('--case', required=True)
    assessment.add_argument('--evidence', required=True, help='one explicit case-local evidence ID')
    assessment.add_argument('--scenario', choices=tuple(SCENARIOS), default='messages')
    assessment.add_argument('--run', help='restrict indexed records and processing context to this evidence run')
    apps = sub.add_parser("app-coverage", help="compare Android app-path indicators with indexed messages; not a completeness verdict")
    apps.add_argument("--case", required=True)
    plan = sub.add_parser('analysis-plan', help='inspect evidence and preview compatible analysis; never executes tools')
    plan.add_argument('--case', required=True)
    plan.add_argument('--evidence', required=True)
    plan.add_argument('--profile', choices=PROFILES, default='standard')
    plan.add_argument('--tool', action='append', default=[], help='implemented adapter for custom profile; repeatable')
    apps.add_argument("--evidence", required=True)
    apps.add_argument("--run", help="limit message rows to one parsing run")
    finding = sub.add_parser("finding", help="save, list or export examiner findings with record snapshots")
    finding_actions = finding.add_subparsers(dest="action", required=True)
    add = finding_actions.add_parser("add", help="append an examiner note; parsed evidence remains unchanged")
    add.add_argument("artifact_id")
    add.add_argument("--case", required=True)
    add.add_argument("--note", required=True)
    add.add_argument("--examiner", default="")
    listing = finding_actions.add_parser("list", help="list saved findings in JSON, oldest first")
    listing.add_argument("--case", required=True)
    listing.add_argument("--limit", type=positive, default=100)
    listing.add_argument("--offset", type=nonnegative, default=0)
    exporting = finding_actions.add_parser("export", help="export all saved findings and snapshots to a new JSONL file")
    exporting.add_argument("--case", required=True)
    exporting.add_argument("--out", required=True)
    exporting.add_argument("--format", choices=["jsonl","text"], default="jsonl", help="complete structured snapshots or a readable findings report; both include a hash receipt")
    plan = sub.add_parser("workflow", help="customer scenarios, acquisition routes, commands and blind spots")
    plan.add_argument("scenario", choices=list(SCENARIOS), nargs="?")
    analyze = sub.add_parser("analyze", help="parse evidence with native or optional CLI engines")
    analyze.add_argument("--case", required=True)
    analyze.add_argument("--evidence", help="evidence ID (default: all in case)")
    analyze.add_argument("--engine", choices=["auto", "native", "ileapp", "aleapp", "exiftool"], default="native")
    analyze.add_argument("--timeout", type=positive, default=900, help="external engine timeout in seconds")
    for name in ("timeline", "search", "messages"):
        cmd = sub.add_parser(name, help="query normalized artifacts" if name == "search" else "chronological case timeline")
        if name == "search":
            cmd.add_argument("query", help="literal case-insensitive text search")
        cmd.add_argument("--case", required=True)
        cmd.add_argument("--category")
        cmd.add_argument("--evidence")
        cmd.add_argument("--since", type=utc_argument)
        cmd.add_argument("--until", type=utc_argument)
        cmd.add_argument("--limit", type=positive, default=100)
        cmd.add_argument("--format", choices=["table", "json", "jsonl", "csv"], default="table")
        cmd.add_argument("--out", help="export path (requires a non-table format)")
        cmd.add_argument("--app", help="normalized app, e.g. sms, mms, whatsapp, signal")
        cmd.add_argument("--conversation", help="exact conversation ID from conversations")
        cmd.add_argument("--participant", help="literal substring in normalized sender, recipient, participants or conversation")
        cmd.add_argument("--parser", help="exact parser name; separates native and external results")
        cmd.add_argument("--run", help="select an indexed analysis run or legacy LEAPP/Dissect report run")
        cmd.add_argument("--offset", type=nonnegative, default=0)
        if name == "messages":
            cmd.add_argument("--query", help="literal keyword search within messages")
    inspect = sub.add_parser("inspect", help="show a record's original fields and provenance")
    inspect.add_argument("id")
    inspect.add_argument("--case", required=True)
    pivot = sub.add_parser("correlate", help="find URLs, domains, and phone-like strings shared across evidence sources")
    pivot.add_argument("--case", required=True)
    pivot.add_argument("--kind", choices=["all", "url", "domain", "phone"], default="all")
    pivot.add_argument("--min-sources", type=positive, default=2)
    evidence = sub.add_parser("evidence", help="list imported evidence files and hashes")
    evidence.add_argument("--case", required=True)
    evidence.add_argument("--evidence")
    integrity = sub.add_parser("verify", help="verify evidence SHA-256 hashes and audit chain")
    integrity.add_argument("--case", required=True)
    audit_cmd = sub.add_parser("audit", help="display case operation history")
    audit_cmd.add_argument("--case", required=True)
    report = sub.add_parser("report", help="generate a standalone searchable HTML investigation report")
    report.add_argument("--case", required=True)
    report.add_argument("--out")
    report.add_argument("--category")
    report.add_argument("--app")
    report.add_argument("--conversation")
    report.add_argument("--evidence")
    report.add_argument("--parser")
    report.add_argument("--run")
    report.add_argument("--query")
    report.add_argument("--since", type=utc_argument)
    report.add_argument("--until", type=utc_argument)
    sub.add_parser("doctor", help="check Python and optional tool availability")
    tool = sub.add_parser("tools", help="manage optional external CLI adapters").add_subparsers(dest="action", required=True)
    tool.add_parser("list")
    tool.add_parser("adapters", help="inspect implemented analysis contracts without executing tools")
    conf = tool.add_parser("configure")
    conf.add_argument("name", choices=list(TOOLS))
    conf.add_argument("path", help="executable or Python entry point (e.g. ileapp.py)")
    conf.add_argument("--python", help="isolated Python interpreter for a .py tool entry point")
    isolated = tool.add_parser('isolate-exiftool', help='opt into the qualified existing local ExifTool container profile; no image pull')
    isolated.add_argument('--image', required=True)
    isolated.add_argument('--tool-root', required=True, help='existing ExifTool Perl package root')
    isolated.add_argument('--socket', required=True, help='existing local Docker Unix socket')
    isolated.add_argument('--docker', required=True, help='existing Docker CLI executable')
    isolated_sql = tool.add_parser('isolate-sqlite', help='opt into the existing pinned Python SQLite container; no image pull or host fallback')
    isolated_sql.add_argument('--image', required=True)
    isolated_sql.add_argument('--socket', required=True, help='existing local Docker Unix socket')
    isolated_sql.add_argument('--docker', required=True, help='existing Docker CLI executable')
    isolated_native = tool.add_parser('isolate-native', help='opt into bounded native parsing in the existing Python container; no host fallback')
    isolated_native.add_argument('--image', required=True)
    isolated_native.add_argument('--socket', required=True, help='existing local Docker Unix socket')
    isolated_native.add_argument('--docker', required=True, help='existing Docker CLI executable')
    reports = tool.add_parser('isolate-reports', help='configure existing pinned stdlib runtime for explicit contained single-report imports; no pull')
    reports.add_argument('--image', required=True)
    reports.add_argument('--socket', required=True)
    reports.add_argument('--docker', required=True)
    binding = tool.add_parser('bind-mulder-review', help='explicitly bind an existing review case to one existing Mulder parent case')
    binding.add_argument('--case', required=True)
    binding.add_argument('--parent-case-db', required=True)
    assess = sub.add_parser("assess-android", help="log device/access observations without root installation or permission changes")
    assess.add_argument("--case", required=True)
    assess.add_argument("--serial", required=True)
    validation = sub.add_parser("validate", help="write scoped source reconciliation and backup-inventory reports")
    validation.add_argument("--case", required=True)
    validation.add_argument("--evidence", required=True)
    validation.add_argument("--parser")
    validation.add_argument("--run")
    check = sub.add_parser("preflight", help="check tools and reserved acquisition storage without starting collection")
    check.add_argument("platform", choices=["android","ios"])
    check.add_argument("--max-gib", type=positive, default=20)
    sub.add_parser("devices", help="list devices through ADB and libimobiledevice")
    acquire = sub.add_parser("collect", help="collect a logical iOS backup or Android triage; live collection changes device state")
    acquire.add_argument("platform", choices=["ios", "android"])
    acquire.add_argument("--case", required=True)
    acquire.add_argument("--serial", required=True, help="explicit Android serial or iOS UDID")
    acquire.add_argument("--timeout", type=positive, default=900)
    acquire.add_argument("--profile", choices=["triage", "messages", "logical", "files", "private-apps", "contacts-provider", "sms-provider", "trash-photos"], default="triage", help="Android collection scope; sms-provider reads permitted SMS observations without a collector app")
    acquire.add_argument('--max-sms',type=positive,default=1000,help='SMS-provider record ceiling (1–20000); excessive ID sets are refused before field reads')
    acquire.add_argument('--android-user',type=int,help='Explicit nonnegative Android user/profile for SMS or contacts provider; otherwise observes the current user')
    acquire.add_argument('--sms-prefix',help='Optional literal body prefix selected by the SMS provider; no MMS/RCS completeness claim')
    acquire.add_argument("--pull", action="append", default=[], help="explicit Android shared-storage path (repeatable)")
    acquire.add_argument("--max-gib", type=positive, default=20)
    recover = sub.add_parser("recover", help="run a supported SQLite recovery engine on an imported database")
    recover.add_argument('--engine',choices=['sqlite-dissect','sqlite4n6'],default='sqlite-dissect')
    recover.add_argument("--case", required=True)
    recover.add_argument("--file-id", required=True, type=positive)
    recover.add_argument("--timeout", type=positive, default=900)
    decrypt = sub.add_parser("decrypt-signal", help="decrypt a supplied legacy Signal backup using its known passphrase")
    decrypt.add_argument("path")
    decrypt.add_argument("--case", required=True)
    decrypt.add_argument("--passphrase-file", help="read passphrase from a local file; otherwise prompt securely")
    signal_check = sub.add_parser("check-signal", help="check a supplied backup format and configured decoder without keys or decryption")
    signal_check.add_argument("path")
    media = sub.add_parser("media-preview", help="verify and create a local preview copy of an indexed media/attachment record")
    media.add_argument("id")
    media.add_argument("--case", required=True)
    demo = sub.add_parser("demo", help="create and analyze a fictional two-device case, offline")
    demo.add_argument("--case", default="demo")
    examples = {
        "process": """Examples:
  lawliet process /path/to/android-extraction.zip --case CASE-001 --platform android
  lawliet process /path/to/iphone-backup --case CASE-001 --platform ios
  lawliet process /path/to/extraction --case CASE-001 --engine aleapp --json

Automatically selects ALEAPP/iLEAPP for recognized inputs. Unknown platforms
remain retained for explicit engine selection. Does not collect from a phone.
Exit 0: completed processing. Exit 1: errors, review warnings, unknown platform,
or no LEAPP records; inspect the returned status and retained logs.
Open this case in Lawliet Mobile using the same workspace to review results.""",
        "collect": """Examples (create a case and run devices first):
  lawliet collect android --case CASE-001 --serial SERIAL --profile messages
  lawliet collect android --case CASE-001 --serial SERIAL --profile contacts-provider
  lawliet collect android --case CASE-001 --serial SERIAL --profile files --pull /sdcard/DCIM
  lawliet preflight ios --max-gib 20
  lawliet collect ios --case CASE-001 --serial UDID --max-gib 20

Android triage gathers device metadata/logs, not private app databases.
Messages requests a device-supported telephony backup; coverage varies.
iOS uses a logical backup, not a full filesystem extraction.
After collection: lawliet analyze --case CASE-001 --evidence EVIDENCE_ID --engine auto""",
        "analyze": """Examples:
  lawliet analyze --case CASE-001 --evidence EVIDENCE_ID --engine auto
  lawliet analyze --case CASE-001 --evidence EVIDENCE_ID --engine ileapp

Default engine: native baseline parser. Use auto for the LEAPP-first workflow.
Omitting --evidence processes every evidence source in the case. Repeated LEAPP
runs remain separate; use --run RUN_ID when searching or exporting results.""",
        "search": """Example:
  lawliet search invoice --case CASE-001 --run RUN_ID --format json

Searches parsed titles, bodies and original fields, not unparsed file bytes.
Use --limit and --offset to page results. --out writes the selected page.
The native app Export JSONL action exports all matching rows.""",
        "assess-android": """Example:
  lawliet assess-android --case CASE-001 --serial SERIAL

Logs read-only device, clock, root-command-presence and ID-only provider probes.
Does not install root, grant permissions or change the device clock.
A readable provider does not establish completeness or access to other apps."""
    }
    for name, example in examples.items():
        sub.choices[name].epilog = example
        sub.choices[name].formatter_class = argparse.RawDescriptionHelpFormatter
    return p


def dispatch(args):
    workspace, json_mode = args.workspace, args.json
    if args.command == "workflow":
        result = workflow(args.scenario)
        if json_mode or not args.scenario:
            emit(result, True)
        else:
            print(clean(result['customer']))
            for name in ('sources', 'steps', 'commands', 'blind_spots'):
                print('\n' + name.replace('_', ' ').capitalize())
                for value in result[name]:
                    print('  ' + clean(value))
        return 0
    if args.command == "case":
        if args.action == "create":
            emit({"case": args.id, "path": str(create_case(workspace, args.id, args.name, args.examiner))}, json_mode)
        elif args.action == "list":
            rows = []
            parent = Path(workspace).expanduser().resolve()
            if parent.exists():
                for path in sorted(parent.iterdir()):
                    if not (path / "case.sqlite").is_file():
                        continue
                    with connect(workspace, path.name) as (_, db):
                        meta = dict(db.execute("SELECT key,value FROM meta"))
                        rows.append({"case": path.name, "name": meta["name"], "created_at": meta["created_at"], "artifacts": db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]})
            if json_mode:
                emit(rows, True)
            else:
                table(["CASE", "NAME", "ARTIFACTS", "CREATED"], [[r["case"], r["name"], r["artifacts"], r["created_at"]] for r in rows])
        else:
            with connect(workspace, args.id) as (root, db):
                result = {"case": dict(db.execute("SELECT key,value FROM meta")), "path": str(root),
                          "evidence": [dict(r) for r in db.execute("SELECT * FROM evidence")],
                          "artifacts": dict(db.execute("SELECT category,COUNT(*) FROM artifacts GROUP BY category")),
                          "runs": [dict(r) for r in db.execute("SELECT * FROM runs ORDER BY started_at")]}
                if json_mode:
                    emit(result, True)
                else:
                    print(f"\nLAWLIET MOBILE / {clean(result['case']['name'])}\n")
                    emit({"case": args.id, "examiner": result["case"]["examiner"] or "Unspecified", "path": str(root), "artifacts": sum(result["artifacts"].values())})
                    print("\nEvidence")
                    table(["ID", "PLATFORM", "LABEL", "ENCRYPTED"], [[r["id"], r["platform"], r["label"], bool(r["encrypted"])] for r in result["evidence"]])
                    print("\nArtifact coverage")
                    table(["CATEGORY", "RECORDS"], list(result["artifacts"].items()))
                    print("\nAnalysis runs")
                    table(["RUN", "ENGINE", "STATUS", "NEW RECORDS"], [[r["id"], r["engine"], r["status"], r["records"]] for r in result["runs"]])
        return 0
    if args.command == "demo":
        result = create_demo(workspace, args.case)
        if json_mode:
            emit(result, True)
        else:
            print("\nLAWLIET MOBILE / SYNTHETIC TWO-DEVICE INVESTIGATION\n")
            emit({"case": result["case"], "artifacts": sum(r["new_records"] for r in result["runs"]), "report": result["report"]["path"]})
            print("\nTry next:")
            for cmd in result["next"]:
                print("  " + cmd)
            print("\nAll demo records are fictional. .example URLs and 555 numbers are test data.")
        return 0
    if args.command in {"doctor", "tools"}:
        if args.command == "tools" and args.action == "configure":
            emit(configure(workspace, args.name, args.path, args.python), json_mode)
        elif args.command == 'tools' and args.action == 'isolate-exiftool':
            from .tools import configure_exiftool_container
            emit(configure_exiftool_container(workspace, args.image, args.tool_root, args.socket, args.docker), json_mode)
        elif args.command == 'tools' and args.action == 'isolate-sqlite':
            from .sqlite_container import configure as configure_sqlite_container
            emit(configure_sqlite_container(workspace,args.image,args.socket,args.docker),json_mode)
        elif args.command == 'tools' and args.action == 'isolate-native':
            from .native_container import configure as configure_native_container
            emit(configure_native_container(workspace,args.image,args.socket,args.docker),json_mode)
        elif args.command == 'tools' and args.action == 'isolate-reports':
            from .report_container import configure as configure_reports
            emit(configure_reports(workspace,args.image,args.socket,args.docker),json_mode)
        elif args.command == 'tools' and args.action == 'bind-mulder-review':
            from .mulder_ownership import bind_review_case
            emit(bind_review_case(case_dir(workspace,args.case),args.parent_case_db),json_mode)
        elif args.command == "tools" and args.action == "adapters":
            emit(adapter_catalog(workspace), True)
        else:
            result = doctor(workspace)
            if json_mode:
                emit(result, True)
            else:
                print(f"\nLAWLIET MOBILE {__version__} / Python {result['python']} / zero required packages\n")
                table(["ENGINE / TOOL", "STATUS", "PURPOSE"], [["native", "READY", "Baseline mobile database parsing"]] + [[r["tool"], "FOUND" if r["available"] else "OPTIONAL / MISSING", r["purpose"]] for r in result["tools"]])
                print("\nCore commands work offline. Tool presence does not establish device compatibility.")
        return 0
    if args.command == "check-signal":
        from .signal_backup import signal_backup_preflight
        result=signal_backup_preflight(args.path,Path(workspace))
        emit(result,True)
        return 0 if result.get('tool',{}).get('available') else 1
    if args.command == "preflight":
        emit(preflight(Path(workspace),args.platform,args.max_gib*1024**3),True)
        return 0
    if args.command == "devices":
        result = devices(workspace)
        if json_mode:
            emit(result, True)
        else:
            table(["PLATFORM", "SERIAL", "STATUS"], [[r["platform"], r.get("serial", "—"), r["status"]] for r in result])
        return 0
    if args.command == 'agent-collection':
        from .app_backend import handle
        if args.action == 'configure':
            emit(configure(workspace, 'mulder', args.mulder_launcher), True)
            return 0
        if args.action == 'run':
            from .agent_collection import execute_plan
            with connect(workspace, args.case) as (root, db):
                result = execute_plan(root, db, workspace, args.plan_id)
        else:
            request = {'case': args.case, 'action': 'agent-collection-'+('create' if args.action=='authorize' else args.action)}
            if args.action == 'authorize':
                request['config'] = {'objective':args.objective,'serial':args.serial,'profiles':args.profile,
                    'pulls':args.pull,'android_user':args.android_user,'examiner':args.examiner,
                    'authorized':args.authorize_collection,'max_records':args.max_records,
                    'max_bytes':args.max_bytes,'timeout':args.timeout}
            elif args.action == 'status': request['plan_id'] = args.plan_id
            result = handle(workspace, request)
        emit(result, True)
        return 1 if args.action=='run' and result.get('status') in {'partial','failed','interrupted'} else 0
    if args.command == 'engine':
        from .app_backend import handle
        request = {'action': 'engine-'+args.action, 'case': args.case}
        if args.action in ('check', 'start'):
            from .mulder_engine import read_json
            request['config'] = read_json(Path(args.config))
        elif args.action in ('status', 'cancel', 'logs'):
            request['job_id'] = args.job_id
        elif args.action == 'import-output':
            request.update(path=args.path, upstream_case_id=args.upstream_case_id, version=args.version)
        result = handle(workspace, request)
        emit(result, True)
        return 1 if args.action == 'import-output' and result.get('status') in ('partial','failed') else 0
    with connect(workspace, args.case) as (root, db):
        if args.command == 'import-report':
            from .parsed_import import import_parsed
            emit(import_parsed(root,db,args.path,args.format,args.label,contained=args.contained),json_mode)
            return 0
        if args.command == 'custody':
            from . import custody
            if args.record_json:
                with open(args.record_json, 'rb') as source:
                    data = source.read(65537)
                if len(data) > 65536:
                    raise UserError('Custody event exceeds 64 KiB.')
                try:
                    value = json.loads(data)
                except (ValueError, UnicodeError) as exc:
                    raise UserError('Custody event must be valid JSON.') from exc
                emit(custody.record(root, db, value), True)
            else:
                emit(custody.list_records(db, args.after, args.limit, args.item_id), True)
            return 0
        if args.command == 'device-state':
            from . import device_state
            if args.record_json:
                with open(args.record_json, 'rb') as source:
                    data = source.read(32769)
                if len(data) > 32768:
                    raise UserError('Device-state worksheet exceeds 32 KiB.')
                try:
                    value = json.loads(data)
                except (ValueError, UnicodeError) as exc:
                    raise UserError('Device-state worksheet must be valid JSON.') from exc
                emit(device_state.record(db, value), True)
            else:
                emit(device_state.list_records(db, args.after, args.limit), True)
            return 0
        if args.command == 'investigation':
            from . import investigation
            if args.action == 'create':
                result = investigation.create(db, args.objective, args.evidence)
            elif args.action == 'show':
                result = investigation.get(db, args.investigation_id)
            elif args.action == 'trace':
                result = investigation.trace(db, args.investigation_id, args.after, args.limit)
            elif args.action == 'note':
                result = investigation.note(db, args.investigation_id, args.kind, args.text, args.artifact)
            elif args.action == 'export':
                from .investigation_report import export as export_investigation
                result = export_investigation(root, db, args.investigation_id, args.out)
            else:
                result = investigation.query(db, args.investigation_id, args.action_key, args.text, args.limit)
            emit(result, True)
        elif args.command == "assess-android":
            emit(assess_android(root,db,workspace,args.serial),True)
        elif args.command == "validate":
            emit(validate_case(root,db,workspace,args.evidence,args.parser,args.run),True)
        elif args.command in {"import", "process"}:
            if Path(args.path).suffix.lower() == ".ab":
                result = import_backup(root, db, args.path, args.label, args.max_gib * 1024**3, args.max_files)
            else:
                identifier, files, size = import_evidence(root, db, args.path, args.platform, args.label, args.max_gib * 1024**3, args.max_files)
                result = {"evidence_id": identifier, "files": files, "bytes": size}
            if args.command == "process":
                result = process_evidence(root, db, workspace, result['evidence_id'], args.engine, args.timeout)
                emit(result, json_mode)
                return 0 if result['status'] == 'complete' else 1
            emit({**result, "next": f"lawliet analyze --case {args.case} --evidence {result['evidence_id']} --engine auto"}, json_mode)
        elif args.command == "import-chat":
            result = import_chat(root, db, args.path, args.date_order, args.timezone, args.label, year_century=args.year_century,chat_path=args.chat_path,reuse=args.reuse)
            emit(result, json_mode)
            return 0 if result["status"] == "complete" else 1
        elif args.command == "import-discord":
            result = import_discord_package(root,db,args.path,args.label,timezone_name=args.timezone,max_bytes=args.max_gib*1024**3,max_files=args.max_files)
            emit(result,True)
            return 0 if result['status'] in {'complete','already_imported'} else 1
        elif args.command == "coverage":
            emit(case_coverage(root, db), True)
        elif args.command == 'case-assess':
            from .scenario_assessment import assess
            emit(assess(root, db, args.evidence, args.scenario, args.run), True)
        elif args.command == "finding":
            if args.action == "add":result=add_finding(db,args.artifact_id,args.note,args.examiner)
            elif args.action == "list":result=list_findings(db,args.limit,args.offset)
            else:result=export_findings(root,db,args.out,args.format)
            emit(result,True)
        elif args.command == "app-coverage":
            emit(app_coverage(db,args.evidence,args.run), True)
        elif args.command == 'analysis-plan':
            emit(analysis_preview(root,db,workspace,args.evidence,args.profile,args.tool),True)
        elif args.command == "conversations":
            result = conversations(db, args.app, args.evidence, args.parser, args.run)
            if json_mode:
                emit(result, True)
            else:
                table(["CONVERSATION ID", "APP", "CONVERSATION", "RECORDS", "UNDATED", "EVIDENCE"], [[r[k] for k in ("conversation_id", "app", "conversation", "records", "undated", "evidence_id")] for r in result])
        elif args.command == "review":
            result = review(root, db, workspace, args.evidence, args.engine, args.run,
                            args.reanalyze, args.preview_limit, args.timeout)
            emit(result, json_mode)
            return 0 if result['status'] == 'ready_for_review' else 1
        elif args.command == "analyze":
            identifiers = [args.evidence] if args.evidence else [r[0] for r in db.execute("SELECT id FROM evidence ORDER BY imported_at")]
            if not identifiers:
                raise UserError("No evidence imported. Use import or collect first.")
            results = []
            for identifier in identifiers:
                if not json_mode:
                    print(f"Analyzing {clean(identifier)} with {args.engine}…", file=sys.stderr)
                try:
                    if args.engine == "auto":
                        result = process_evidence(root, db, workspace, identifier, 'auto', args.timeout)
                    else:
                        result = adapter_analyze(root, db, workspace, identifier, args.engine, args.timeout)
                    results.append({"evidence_id": identifier, **result})
                except (UserError, subprocess.TimeoutExpired, OSError) as exc:
                    results.append({"evidence_id": identifier, "status": "failed", "error": str(exc)})
            emit(results, True) if json_mode else [emit(r) for r in results]
            return 1 if any(r["status"] != "complete" for r in results) else 0
        elif args.command in {"timeline", "search", "messages"}:
            records = select_artifacts(db, getattr(args, "query", None), "messages" if args.command == "messages" else args.category, args.evidence, args.since, args.until, args.limit,
                                       args.app, args.conversation, args.participant, args.offset, args.parser, args.run)
            if args.out:
                if args.format == "table":
                    raise UserError("Use --format json, jsonl, or csv with --out.")
                emit({"path": write_export(root, db, args.out, args.format, records), "records": len(records)}, json_mode)
            elif json_mode or args.format == "json":
                emit(records, True)
            elif args.format == "jsonl":
                for row in records:
                    print(json.dumps(row, ensure_ascii=False))
            elif args.format == "csv":
                raise UserError("CSV export requires --out; JSONL can stream to stdout.")
            elif args.command == "messages":
                for record in records:
                    message = record['data'].get('message', {})
                    print(f"\n{clean(record['timestamp'] or 'Undated')} | {clean(record['title'])}")
                    print(clean(record['body']))
                    print(f"  Record: {clean(record['id'])} | Conversation: {clean(message.get('conversation_id', 'unmapped'))}")
                    print(f"  Source: {clean(record['logical_path'] or record['source_ref'])}")
                print(f"\n{len(records)} records shown (limit {args.limit}, offset {args.offset}). Export JSON/JSONL for exact raw text.")
            else:
                table(["UTC TIME", "CATEGORY", "TITLE", "CONTENT", "RECORD ID"], [[(r["timestamp"] or "undated")[:19].replace("T", " "), r["category"], r["title"], r["body"], r["id"]] for r in records], [19, 10, 32, 48, 24])
                print(f"\n{len(records)} records shown (limit {args.limit}). Full fields: inspect <record-id> --case {args.case}")
        elif args.command == "correlate":
            result = shared_entities(db, args.min_sources, args.kind)
            if json_mode:
                emit(result, True)
            else:
                table(["TYPE", "SHARED ENTITY", "SOURCES", "RECORDS"], [[r["kind"], r["value"], r["evidence_sources"], r["records"]] for r in result], [8, 65, 7, 7])
                print("\nExact textual pivots, not attribution or maliciousness verdicts. --json includes record IDs.")
        elif args.command == "inspect":
            record = db.execute("SELECT a.*,f.logical_path,f.sha256 AS source_sha256 FROM artifacts a LEFT JOIN files f ON f.id=a.file_id WHERE a.id=?", (args.id,)).fetchone()
            if not record:
                raise UserError("Artifact not found. Copy an ID from timeline or search.")
            result = dict(record)
            result["data"] = json.loads(result["data"])
            emit(result, json_mode)
        elif args.command == "evidence":
            query = "SELECT evidence_id,path,logical_path,sha256,size FROM files"
            rows = [dict(r) for r in db.execute(query + (" WHERE evidence_id=?" if args.evidence else "") + " ORDER BY evidence_id,path", (args.evidence,) if args.evidence else ())]
            if json_mode:
                emit(rows, True)
            else:
                table(["EVIDENCE", "LOGICAL PATH", "BYTES", "SHA-256"], [[r["evidence_id"], r["logical_path"], r["size"], r["sha256"]] for r in rows], [12, 65, 10, 64])
        elif args.command == "verify":
            result = verify(root, db)
            emit(result, json_mode)
            return 0 if result["ok"] else 1
        elif args.command == "audit":
            rows = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id")]
            if json_mode:
                emit(rows, True)
            else:
                table(["#", "UTC TIME", "ACTION", "DETAIL"], [[r["id"], r["at"], r["action"], r["detail"]] for r in rows], [4, 25, 24, 90])
        elif args.command == "report":
            filters = {k: getattr(args, k) for k in ("category", "app", "conversation", "evidence", "query", "since", "until", "parser", "run") if getattr(args, k)}
            emit(write_report(root, db, args.out or root / "reports" / "investigation.html", filters), json_mode)
        elif args.command == "recover":
            emit(adapter_analyze_file(root, db, workspace, args.file_id, args.engine, args.timeout), json_mode)
        elif args.command == "decrypt-signal":
            from .signal_backup import decrypt_signal
            import getpass
            secret = Path(args.passphrase_file).read_text().strip() if args.passphrase_file else getpass.getpass('Legacy Signal backup passphrase: ')
            result = decrypt_signal(root, db, workspace, args.path, secret)
            secret = ''
            result['decode_status']=result['status']
            result['analysis'] = native_analyze(root, db, result['evidence_id'])
            if result['analysis'].get('status')!='complete':result['status']='partial'
            result['message_records']=db.execute("SELECT COUNT(*) FROM artifacts WHERE evidence_id=? AND category='messages' AND json_extract(data,'$.message.app')='signal'",(result['evidence_id'],)).fetchone()[0]
            emit(result, json_mode)
            return 0 if result['status']=='complete' else 1
        elif args.command == "media-preview":
            from .media import preview
            emit(preview(root, db, args.id), json_mode)
        elif args.command == "collect":
            if (args.sms_prefix is not None or args.max_sms!=1000) and not (args.platform=='android' and args.profile=='sms-provider'):
                raise UserError('SMS limits/prefix options require Android --profile sms-provider.')
            if args.android_user is not None and not (args.platform=='android' and args.profile in {'sms-provider','contacts-provider'}):
                raise UserError('Android user selection requires an Android SMS or contacts provider profile.')
            if args.platform == "android" and args.profile == "private-apps":
                if args.pull: raise UserError('Private app collection uses fixed package paths, not --pull.')
                from .private_apps import collect_private_apps
                result = collect_private_apps(root, db, workspace, args.serial, args.timeout, args.max_gib * 1024**3)
            elif args.platform == "android" and args.profile != "triage":
                result = collect_android(root, db, workspace, args.serial, args.profile, args.pull, args.timeout, args.max_gib * 1024**3,
                                         args.max_sms,args.android_user,args.sms_prefix)
            else:
                if args.pull or args.profile != "triage":
                    raise UserError("Use an Android messages/logical/files profile with --pull.")
                result = collect(root, db, workspace, args.platform, args.serial, args.timeout, args.max_gib * 1024**3)
            emit(result, json_mode)
            return 0 if result["status"] == "complete" else 1
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Global switches may appear before or after subcommands.
    global_args, other = [], []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--json":
            global_args.append(token)
        elif token == "--workspace" and index + 1 < len(argv):
            global_args.extend(argv[index:index + 2])
            index += 1
        elif token.startswith("--workspace="):
            global_args.append(token)
        else:
            other.append(token)
        index += 1
    args = parser().parse_args(global_args + other)
    try:
        return dispatch(args)
    except KeyboardInterrupt:
        emit({"error": "Interrupted. Any completed records and operation logs were retained."}, args.json)
        return 130
    except (UserError, OSError, sqlite3.DatabaseError, ValueError, subprocess.SubprocessError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        else:
            print("Error: " + clean(str(exc)), file=sys.stderr)
        return 1
