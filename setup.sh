#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Apple's bundled Python can run the bootstrap; runtime Python 3.13 is managed separately.
exec python3 tools/bootstrap.py "$@"
