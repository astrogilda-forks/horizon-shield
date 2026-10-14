#!/bin/bash
# Regenerates in.json, runs it through the JS reference, the Python port and the Go port, and writes RAW.txt
# (commands, versions, stdout, exit status). Run from anywhere:
#   bash workers/hs-ledger/nenrin/occurrence-cell-v0/run.sh
# Needs python3 with cryptography (for the generator only), node, go. Offline: no network, no clock.
set -u
cd "$(dirname "$0")"
{
  echo "# occurrence-cell-v0 raw run"
  echo "HEAD: $(git rev-parse HEAD 2>/dev/null || echo unknown)  uncommitted files in this directory: $(git status --porcelain -- . 2>/dev/null | wc -l)"
  echo "python: $(python3 --version 2>&1)  cryptography: $(python3 -c 'import cryptography;print(cryptography.__version__)' 2>&1)"
  echo "node: $(node --version)  go: $(go version 2>&1)"
  echo
  echo "\$ python3 -B make_occurrence_cases.py"; python3 -B make_occurrence_cases.py; echo "exit $?"
  echo "in.json sha256: $(sha256sum in.json | cut -d' ' -f1)"
  echo
  echo "\$ node run_occurrence.mjs"; node run_occurrence.mjs; echo "exit $?"
  echo
  echo "\$ python3 -B run_occurrence_py.py"; python3 -B run_occurrence_py.py; echo "exit $?"
  echo
  echo "\$ (cd ../sdk-go && go run ./cmd/nenrin-verify-go --batch <abs>/in.json <abs>/results_go.json)"
  (cd ../sdk-go && go run ./cmd/nenrin-verify-go --batch "$OLDPWD/in.json" "$OLDPWD/results_go.json"); echo "exit $?"
  echo
  echo "\$ compare: every row of results_py.json and results_go.json against results_js.json"
  python3 -B - <<'PY'
import json
js = json.load(open("results_js.json")); py = json.load(open("results_py.json")); go = json.load(open("results_go.json"))
n = lambda v: (v.get("verdict"), sorted(v.get("refusals", [])), sorted(v.get("findings", [])), v.get("lookup_calls"))
bad = [k for k in js if n(py.get(k, {})) != n(js[k])] + [k for k in go if n(dict(go[k], lookup_calls=js[k].get("lookup_calls"))) != n(js[k])]
print("rows js=%d py=%d go=%d, differing: %s" % (len(js), len(py), len(go), bad or "none"))
raise SystemExit(1 if bad else 0)
PY
  echo "exit $?"
} 2>&1 | tee RAW.txt
