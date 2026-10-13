#!/usr/bin/env bash
# run_published.sh : run the PUBLISHED nenrin-verify builds (npm and PyPI) on the three cases in ../records and save
# each raw output and exit code here. It installs nothing; install first, outside this repository:
#
#   mkdir -p "$EXT/npm" && cd "$EXT/npm" && npm init -y && npm install --no-save nenrin-verify@0.5.1
#   python3 -m venv "$EXT/venv" && "$EXT/venv/bin/pip" install nenrin-verify==0.5.3
#
# Run:  runs/run_published.sh "$EXT/npm" "$EXT/venv"      (from vate-s3-v0/)
set -euo pipefail
NPM_DIR="${1:?usage: run_published.sh <npm-install-dir> <venv-dir>}"
VENV="${2:?usage: run_published.sh <npm-install-dir> <venv-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REC="$(cd "$HERE/../records" && pwd)"
NPM_BIN="$NPM_DIR/node_modules/.bin/nenrin-verify"
PY_BIN="$VENV/bin/nenrin-verify"
npm_v=$(node -p "require('$NPM_DIR/node_modules/nenrin-verify/package.json').version")
py_v=$("$PY_BIN" --version | awk '{print $2}')
echo "npm nenrin-verify $npm_v   PyPI nenrin-verify $py_v   node $(node --version)   $("$VENV/bin/python" --version)" | tee "$HERE/ENV.txt"
for c in match target_mismatch missing_receipt; do
  set +e
  (cd "$REC/$c" && "$NPM_BIN" nenrin-bundle.json) > "$HERE/npm-$c.out" 2> "$HERE/npm-$c.err"; ne=$?
  (cd "$REC/$c" && "$PY_BIN" nenrin-bundle.json) > "$HERE/pypi-$c.out" 2> "$HERE/pypi-$c.err"; pe=$?
  (cd "$REC/$c" && "$PY_BIN" --sha nenrin-bundle.json) > "$HERE/pypi-$c.sha.txt" 2>&1
  set -e
  echo "$ne" > "$HERE/npm-$c.exit"; echo "$pe" > "$HERE/pypi-$c.exit"
  same=no; cmp -s "$HERE/npm-$c.out" "$HERE/pypi-$c.out" && same=yes
  echo "$c  npm exit $ne  pypi exit $pe  stdout byte-identical: $same" | tee -a "$HERE/ENV.txt"
done
