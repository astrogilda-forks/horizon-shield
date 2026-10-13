#!/usr/bin/env bash
# priorseal-reader-v0: clone PriorSeal at the pinned v1.0.1 matrix commit, install the pinned Python libraries
# in a fresh venv, run the independent reader, and write report.json next to this script.
#
#   ./run.sh [WORKDIR]            WORKDIR defaults to a new temporary directory
#   OUT=/path/report.json ./run.sh
#   PROBES=1 ./run.sh             also run the mutation probes (each must DISAGREE) on a scratch copy
#
# Needs: git, python3 (3.11 was used), network for the clone and pip. Nothing here signs, pushes or posts.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMMIT=2ff89d86611257b4440232e5c2793926b3d52043
REPO=https://github.com/imokokok/PriorSeal
WORK="${1:-$(mktemp -d)}"
OUT="${OUT:-$HERE/report.json}"
M=examples/open-evidence-lab-exact-call-matrix-v1

mkdir -p "$WORK"
if [ ! -d "$WORK/PriorSeal/.git" ]; then
  git init -q "$WORK/PriorSeal"
  git -C "$WORK/PriorSeal" remote add origin "$REPO"
  git -C "$WORK/PriorSeal" fetch -q --depth 1 origin "$COMMIT"
  git -C "$WORK/PriorSeal" checkout -q --detach FETCH_HEAD
fi
test "$(git -C "$WORK/PriorSeal" rev-parse HEAD)" = "$COMMIT"
echo "clone: $WORK/PriorSeal @ $COMMIT"

if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install -q --disable-pip-version-check -r "$HERE/requirements.txt"
fi
"$WORK/venv/bin/python" --version

# -I: isolated mode, so nothing from the clone or the current directory can shadow a module.
set +e
"$WORK/venv/bin/python" -I "$HERE/reader.py" --clone "$WORK/PriorSeal" --out "$OUT"
rc=$?
set -e
echo "reader exit: $rc"
python3 -c 'import hashlib,sys;print("report sha256:",hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$OUT"

if [ "${PROBES:-0}" = 1 ]; then
  probe() {
    local name="$1" py="$2" mut="$WORK/probe"
    rm -rf "$mut"; mkdir -p "$mut/$M"; cp -r "$WORK/PriorSeal/$M/." "$mut/$M/"
    python3 -I -c "$py" "$mut/$M"
    local res
    # M1 (commit) and M2 (manifest digests) always fail on a mutated copy, so they are left out of the line.
    # The reader exits 1 on any probe (M1/M2), hence "|| true"; the printed line is what matters.
    res=$("$WORK/venv/bin/python" -I "$HERE/reader.py" --clone "$mut" | python3 -c 'import json,sys;d=json.load(sys.stdin);c=[x for x in d["contradictionsExcludingDocConsistency"] if not x.startswith(("M1.","M2."))];print("fieldsDifferent=%d contradicted=%s" % (d["fields"]["different"], ",".join(c) or "none"))') || true
    echo "probe $name: $res"
    rm -rf "$mut"
  }
  SA='import json,sys;p=sys.argv[1]+"/fixture/signed-authorization.json";d=json.load(open(p));'
  OB='import json,sys;p=sys.argv[1]+"/fixture/observed/'
  probe signature-one-hex-digit "$SA"'s=d["authorization"]["signature"];d["authorization"]["signature"]=s[:10]+("0" if s[10]!="0" else "1")+s[11:];json.dump(d,open(p,"w"))'
  probe acceptance-acceptedAt "$SA"'d["acceptance"]["acceptedAt"]=1001;json.dump(d,open(p,"w"))'
  probe authorization-expiresAt "$SA"'d["authorization"]["expiresAt"]=3000;json.dump(d,open(p,"w"))'
  probe case00-nonce "$OB"'case-00-exact-call-observed-match.json";d=json.load(open(p));d["nonce"]=8;json.dump(d,open(p,"w"))'
  probe case04-evidence-available "$OB"'case-04-execution-evidence-unavailable.json";d=json.load(open(p));d["executionDataAvailable"]=True;d["status"]="CONFIRMED";json.dump(d,open(p,"w"))'
  # Control: a case-only change must NOT disagree (contract 4: case-insensitive equality).
  probe control-case00-calldata-uppercase "$OB"'case-00-exact-call-observed-match.json";d=json.load(open(p));d["calldataHash"]="0x"+d["calldataHash"][2:].upper();json.dump(d,open(p,"w"))'
  # Control: numeric nonce 7 equals "7" under String() coercion (contract 4).
  probe control-case00-numeric-nonce "$OB"'case-00-exact-call-observed-match.json";d=json.load(open(p));d["nonce"]=7;json.dump(d,open(p,"w"))'
fi
exit "$rc"
