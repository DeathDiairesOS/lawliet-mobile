"""Analysis adapter contracts over existing implementations; no auto-installation.

Selection is explicit. This module does not discover evidence, collect from a
device, start background jobs, or claim that executable presence validates a
tool version. Specialized secret-bearing acquisition/decryption stays separate.
"""
from dataclasses import asdict, dataclass
import math
from typing import Callable

from .core import UserError
from . import parsers, tools


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    contract_version: int
    platforms: tuple[str, ...]
    input_scope: str
    input_types: tuple[str, ...]
    dependencies: tuple[str, ...]
    output_formats: tuple[str, ...]
    output_parser: str
    timeout_policy: str
    failure_policy: str


@dataclass(frozen=True)
class AnalysisRequest:
    evidence_id: str
    timeout: float = 900
    file_id: int | None = None


@dataclass(frozen=True)
class AnalysisAdapter:
    spec: AdapterSpec
    execute: Callable

    def run(self, root, db, workspace, request):
        if isinstance(request.timeout, bool) or not isinstance(request.timeout, (int, float)) or not math.isfinite(request.timeout) or request.timeout <= 0:
            raise UserError('Analysis timeout must be a finite positive number of seconds.')
        evidence=db.execute('SELECT * FROM evidence WHERE id=?',(request.evidence_id,)).fetchone()
        if not evidence:raise UserError('Unknown evidence.')
        if evidence['platform'] not in self.spec.platforms:
            raise UserError(f'{self.spec.name} does not match this evidence platform ({evidence["platform"]}).')
        if self.spec.input_scope == 'file':
            source=db.execute('SELECT evidence_id FROM files WHERE id=?',(request.file_id,)).fetchone()
            if not source or source['evidence_id']!=request.evidence_id:
                raise UserError('Select an imported file belonging to this evidence.')
        elif request.file_id is not None:
            raise UserError(f'{self.spec.name} takes an evidence source, not an individual file ID.')
        return self.execute(root,db,workspace,request)


def _native(root,db,workspace,request):
    return parsers.native_analyze(root,db,request.evidence_id)


def _external(name):
    def run(root,db,workspace,request):
        return tools.external_analyze(root,db,workspace,request.evidence_id,name,request.timeout)
    return run


def _recovery(root,db,workspace,request):
    from .recovery import recover_sqlite
    return recover_sqlite(root,db,workspace,request.file_id,request.timeout)


def _sqlite4n6(root,db,workspace,request):
    from .sqlite4n6 import recover
    return recover(root,db,workspace,request.file_id,request.timeout)


_ALL_PLATFORMS=('android','ios','unknown')
_ADAPTERS={}


def _register(spec, execute):
    if spec.name in _ADAPTERS:raise ValueError('Duplicate adapter: '+spec.name)
    _ADAPTERS[spec.name]=AnalysisAdapter(spec,execute)


_register(AdapterSpec('native',1,_ALL_PLATFORMS,'evidence',
    ('supported SQLite schemas','XML/vCard exports','Android text','media inventory'),(),
    ('Lawliet artifacts',),'parsers.native_analyze','No subprocess deadline; runs in backend process.',
    'Per-file errors retained; inspect native run status and errors.'),_native)
for _name,_platform in [('aleapp','android'),('ileapp','ios')]:
    _register(AdapterSpec(_name,1,(_platform,'unknown'),'evidence',
        ('decrypted extraction',),(_name+' and its runtime dependencies',),('TSV','HTML','logs'),
        'leapp_reports.leapp_artifact; unknown report fields preserved',
        'Subprocess deadline; terminate process group on timeout/interruption.',
        'Failed execution or malformed TSV rolls back indexed rows; outputs/logs retained.'),_external(_name))
_register(AdapterSpec('exiftool',1,_ALL_PLATFORMS,'evidence',('media/files',),('exiftool',),
    ('JSON',),'tools.external_analyze metadata reader',
    'Subprocess deadline; terminate process group on timeout/interruption.',
    'Nonzero exit, malformed/oversized JSON fails; indexed rows rolled back; output retained.'),_external('exiftool'))
_register(AdapterSpec('sqlite-dissect',1,_ALL_PLATFORMS,'file',
    ('plaintext SQLite database with captured sidecars',),('sqlite-dissect and its runtime dependencies',),
    ('CSV','logs'),'recovery.recover_sqlite candidate reader',
    'Subprocess deadline and storage guard; terminate process group on interruption.',
    'Failed run and logs retained; any rows indexed before a later parse failure remain candidates.'),_recovery)
_register(AdapterSpec('sqlite4n6',1,_ALL_PLATFORMS,'file',
    ('plaintext SQLite database with captured sidecars',),('sqlite4n6 0.10.1',),
    ('JSONL','logs'),'sqlite4n6.normalized_record',
    'Version probe up to 20 seconds; carving deadline and storage guard.',
    'Unsupported version, failed execution or malformed records fail transactionally; raw output/logs retained.'),_sqlite4n6)


def get_adapter(name):
    try:return _ADAPTERS[name]
    except KeyError:raise UserError(f'No implemented analysis adapter: {name}') from None


def analyze(root,db,workspace,evidence_id,engine,timeout=900,file_id=None):
    return get_adapter(engine).run(root,db,workspace,AnalysisRequest(evidence_id,timeout,file_id))


def analyze_file(root,db,workspace,file_id,engine,timeout=900):
    source=db.execute('SELECT evidence_id FROM files WHERE id=?',(file_id,)).fetchone()
    if not source:raise UserError('Select an imported file.')
    return analyze(root,db,workspace,source['evidence_id'],engine,timeout,file_id)


def catalog(workspace):
    """Read configuration/presence only. No tool execution or evidence access."""
    rows=[]
    for adapter in _ADAPTERS.values():
        value=asdict(adapter.spec)
        value.update(available=True,availability_error=None,
                     tool_version=parsers.VERSION if adapter.spec.name=='native' else None,
                     version_status='built_in' if adapter.spec.name=='native' else 'not_probed')
        if adapter.spec.name!='native':
            try:tools.command(workspace,adapter.spec.name)
            except UserError as exc:value.update(available=False,availability_error=str(exc))
        rows.append(value)
    return {'contract_version':1,'adapters':rows,
            'note':'Availability is executable presence only, not version compatibility. Input types describe capabilities, not discovery results. Acquisition and secret-bearing decryption remain specialized workflows.'}
