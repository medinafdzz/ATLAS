#!/bin/sh
# Local one-shot offline capture; no privileged or remote access by default.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$ROOT/portable/atlas_portable.py" --manifest "$ROOT/examples/safe-local.json" --output-dir "${ATLAS_OUTPUT_DIR:-$ROOT/results}" "$@"
