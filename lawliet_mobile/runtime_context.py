"""Recorded local runtime fingerprints, not signatures or tool certification."""
import platform
import sys
from pathlib import Path
from .core import digest


def snapshot():
    package = Path(__file__).resolve().parent
    return {'format': 'ancalor-runtime-context-v1',
        'python_version': sys.version, 'python_executable_sha256': digest(Path(sys.executable).resolve()),
        'host_system': platform.system(), 'host_release': platform.release(),
        'host_architecture': platform.machine(),
        'backend_source_sha256': {p.name: digest(p) for p in sorted(package.glob('*.py'))},
        'limitations': ['Local hashes are not independent signatures or trustworthy timestamps.',
                       'External dependency trees and OS libraries are not fully fingerprinted.',
                       'This records a runtime, not method validation or legal admissibility.']}
