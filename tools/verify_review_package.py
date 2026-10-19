#!/usr/bin/env python3
"""Verify a local LAWLIET review package without its originating case database."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lawliet_mobile.package_verification import verify_package, PackageError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--expected-manifest-sha256', help='digest obtained through a separate trusted channel')
    args = parser.parse_args()
    try:
        result = verify_package(args.package, args.expected_manifest_sha256)
    except PackageError as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Evidence-controlled filenames/JSON never enter error logs.
        print(json.dumps({'ok': False, 'error': 'Package verification refused; check format, inventory, integrity and supplied digest.'}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
