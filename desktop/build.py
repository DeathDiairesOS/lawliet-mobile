"""Build a native macOS .app with the stdlib Python backend bundled as source."""
import plistlib
import hashlib
import json
import platform
import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def native_key(sources, identity, arguments):
    values={'sources':{str(p):digest(p.read_bytes()) for p in sorted(sources)},
            'compiler_sdk':identity, 'arguments':arguments}
    return digest(json.dumps(values, sort_keys=True).encode())


def can_reuse_native(receipt, key, executable):
    return (receipt.get('schema_version')==1 and receipt.get('native_key')==key
            and executable.is_file() and receipt.get('native_sha256')==digest(executable.read_bytes()))


def canonical_output(path):
    """Old build commands must not recreate the retired application."""
    return path.with_name("LAWLIET.app") if path.name.casefold() == "ancalor mobile.app" else path


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=root.parent / 'lawliet-cases')
    parser.add_argument('--output', type=Path, default=root / 'dist' / 'LAWLIET.app')
    parser.add_argument('--bundle-id', default='com.lawliet.mobile')
    parser.add_argument('--backend-source', type=Path, help='Package a previously verified backend source directory instead of the active repository')
    parser.add_argument('--rebuild', action='store_true', help='Force native compilation instead of using a verified cache')
    args = parser.parse_args()
    app = canonical_output(args.output).resolve()
    if args.bundle_id == "com.ancalor.mobile": args.bundle_id = "com.lawliet.mobile"
    contents = app / 'Contents'
    (contents / 'MacOS').mkdir(parents=True, exist_ok=True)
    resources = contents / 'Resources'
    resources.mkdir(exist_ok=True)
    for asset in (root / 'desktop/assets').iterdir():
        shutil.copy2(asset, resources / asset.name)
    backend = resources / 'lawliet_mobile'
    if backend.exists():
        shutil.rmtree(backend)  # Generated bundle only; do not retain removed source modules.
    shutil.copytree(args.backend_source or root / 'lawliet_mobile', backend,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    legacy_backend = resources / 'ancalor_mobile'
    if legacy_backend.is_symlink(): legacy_backend.unlink()
    elif legacy_backend.exists(): shutil.rmtree(legacy_backend)
    legacy_backend.symlink_to('lawliet_mobile', target_is_directory=True)
    shutil.copy2(root / 'desktop/catalog_backend.py', resources / 'catalog_backend.py')
    info = {'CFBundleName': 'LAWLIET', 'CFBundleDisplayName': 'LAWLIET',
            'CFBundleIdentifier': args.bundle_id, 'CFBundleVersion': '1',
            'CFBundleShortVersionString': '0.1.0', 'CFBundleExecutable': 'LawlietMobile',
            'CFBundlePackageType': 'APPL', 'CFBundleIconFile': 'Lawliet.icns', 'LSMinimumSystemVersion': '13.0',
            'NSHighResolutionCapable': True, 'NSCameraUsageDescription': 'LAWLIET displays the selected USB iPhone screen. Preview frames are not recorded or imported as case evidence.', 'LawlietPython': sys.executable,
            'LawlietWorkspace': str(args.workspace.resolve())}
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    native_command = ['swiftc', '-parse-as-library', '-swift-version', '5', '-O', '-target', platform.machine()+'-apple-macos13.0',
                    str(root / 'desktop/LawlietMobile.swift'), str(root / 'desktop/BackendProcess.swift'), str(root / 'desktop/EngineInvestigationView.swift'), str(root / 'desktop/CaseManagementView.swift'), str(root / 'desktop/ReviewContext.swift'), str(root / 'desktop/ReviewContextView.swift'), str(root / 'desktop/CoverageReview.swift'), str(root / 'desktop/CoverageReviewView.swift'), '-o', str(contents / 'MacOS/LawlietMobile'),
                    '-framework', 'SwiftUI', '-framework', 'AppKit', '-framework', 'WebKit']
    native_command[8:8] = [str(root/'desktop/DraftReview.swift'), str(root/'desktop/DraftReviewView.swift'),str(root/'desktop/DraftPreparationView.swift'),str(root/'desktop/SourceScope.swift'),str(root/'desktop/CaseCatalog.swift'),str(root/'desktop/CaseCatalogView.swift'),str(root/'desktop/InlineMediaCache.swift'),str(root/'desktop/InlineMediaView.swift')]
    native_command[8:8] = [str(root/'desktop/DeviceAuditLog.swift'),str(root/'desktop/DeviceAuditLogView.swift'),str(root/'desktop/DeviceInteractionView.swift'),str(root/'desktop/ParsedReportsSidebar.swift'),str(root/'desktop/EvidenceFilesView.swift'),str(root/'desktop/UnifiedEvidenceSidebar.swift')]
    native_command[8:8] = [str(root/'desktop/InvestigatorSourcesView.swift'),str(root/'desktop/LawlietTheme.swift'),str(root/'desktop/CapabilityCoverageView.swift')]
    native_command[8:8] = [str(root/'desktop/IPhoneInteractionView.swift')]
    sources = [Path(arg) for arg in native_command if arg.endswith('.swift')]
    identity = {'compiler': subprocess.check_output(['swiftc', '--version'], text=True),
                'compiler_path': str(Path(shutil.which('swiftc')).resolve()),
                'sdk_path': subprocess.check_output(['xcrun', '--show-sdk-path'], text=True),
                'sdk_version': subprocess.check_output(['xcrun', '--show-sdk-version'], text=True)}
    key = native_key(sources, identity, native_command)
    cache = root / 'build' / ('native-' + digest(str(app).encode())[:16] + '.json')
    try:
        receipt = json.loads(cache.read_text())
        if not isinstance(receipt, dict): receipt = {}
    except (OSError, ValueError):
        receipt = {}
    executable = contents / 'MacOS/LawlietMobile'
    compiled = args.rebuild or not can_reuse_native(receipt, key, executable)
    if compiled:
        subprocess.run(native_command, check=True)
        if native_key(sources, identity, native_command) != key:
            raise RuntimeError('Swift source changed during compilation; rerun the build.')
    print('Native compilation: ' + ('compiled' if compiled else 'reused verified executable'))
    subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(app)], check=True)
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    cache.parent.mkdir(parents=True, exist_ok=True)
    receipt = {'schema_version':1, 'native_key':key, 'native_sha256':digest(executable.read_bytes()),
               'compiler_sdk':identity,
               'catalog_helper_sha256':digest((resources/'catalog_backend.py').read_bytes()),
               'backend_hashes':{str(path.relative_to(backend)):digest(path.read_bytes()) for path in sorted(backend.rglob('*.py'))}}
    cache.write_text(json.dumps(receipt, indent=2)+'\n')
    print(app)


if __name__ == '__main__':
    main()
