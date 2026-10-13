#!/usr/bin/env bash
# ops/prod_fix_check.sh: read-only checks that the 2026-10-13 fixes are live in production.
#
# What it does: GET requests only (curl), nothing is written anywhere, no token is sent. Each row compares one
# public answer with the value this repo expects after the deploys of 2026-10-13 (issue #13 read failures, and the
# concurrency audit ops/concurrency_audit_20261013.md, HIGH rows and the MEDIUM rows of the second batch). It prints a
# table and exits 1 if any row does not match. ai-council has no /health, so its fix (AC) has no row here.
#
# Usage:
#   bash ops/prod_fix_check.sh --gate-commit <short sha>
#     --gate-commit SHA   the short sha of the last origin/main commit that changed workers/hs-verify-gate
#                         (git log -1 --format=%h origin/main -- workers/hs-verify-gate). The gate's /health
#                         gate_commit must start with it (or it with gate_commit, whichever is shorter).
#   Optional:
#     --webmcp-version V  expected hs-webmcp version (default 1.0.4, the version the 2026-10-13 fix shipped under)
#     --base URL          send every request to URL instead of the production host, keeping each path
#                         (for a local fake server). The table still names the production host.
#     --skip-new          leave out the rows for the concurrency fixes (use before those are deployed)
#   Environment:
#     CURL                the curl command to run (default: curl). A test can point it at a fake.
#
# Exit: 0 all rows match, 1 at least one mismatch or unreachable, 2 bad arguments.
set -u

GATE_COMMIT=""
WEBMCP_VERSION="1.0.4"
BASE=""
SKIP_NEW=0
CURL="${CURL:-curl}"

while [ $# -gt 0 ]; do
  case "$1" in
    --gate-commit) GATE_COMMIT="${2:-}"; shift 2 ;;
    --webmcp-version) WEBMCP_VERSION="${2:-}"; shift 2 ;;
    --base) BASE="${2:-}"; shift 2 ;;
    --skip-new) SKIP_NEW=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if ! printf '%s' "$GATE_COMMIT" | grep -Eq '^[0-9a-f]{7,40}$'; then
  echo "--gate-commit <short sha> is required (7 to 40 hex). Get it with:" >&2
  echo "  git fetch origin && git log -1 --format=%h origin/main -- workers/hs-verify-gate" >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo "python3 is needed to read the JSON answers" >&2; exit 2; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# Rows: name|url|kind|field|expected
#   kind json_eq      : JSON field equals expected
#   kind json_prefix  : JSON field and expected share a prefix (the shorter is a prefix of the longer)
#   kind status       : HTTP status equals expected
#   kind contains     : body contains expected
ROWS=(
  "hs-kira-line health|https://hs-kira-line.oga-surf-project.workers.dev/health|json_eq|version|v25-lessons-20261013"
  "hs-kira-group health|https://hs-kira-group.oga-surf-project.workers.dev/health|json_eq|version|group-6-readfail2-20261013"
  "hs-webmcp version|https://web.horizonshield.dev/health|json_eq|version|$WEBMCP_VERSION"
  "gate gate_commit|https://gate.horizonshield.dev/health|json_prefix|gate_commit|$GATE_COMMIT"
  "hs-us-report health|https://hs-us-report.oga-surf-project.workers.dev/health|status||200"
  "teardown page marker|https://horizonshield.dev/teardown/|contains||reference_unavailable"
  "ledger head|https://ledger.horizonshield.dev/ledger/head|status||200"
)
if [ "$SKIP_NEW" -eq 0 ]; then
  ROWS+=(
    "ledger sequencer (L1)|https://ledger.horizonshield.dev/health|json_eq|sequencer|do-serialized-20261013"
    "us-report payments (U1)|https://hs-us-report.oga-surf-project.workers.dev/health|json_eq|payments|pay-record-v1-20261013"
    "hearing estimate files (H1)|https://hs-hearing.oga-surf-project.workers.dev/health|json_eq|estimate_files|per-key-20261013"
    "hearing version (readfail3)|https://hs-hearing.oga-surf-project.workers.dev/health|json_eq|version|2.3.2-rmw-20261013"
    "us-report answers (U2)|https://hs-us-report.oga-surf-project.workers.dev/health|json_eq|answers|ans-per-key-20261013"
    "us-report draft claim (U3)|https://hs-us-report.oga-surf-project.workers.dev/health|json_eq|draft_claim|claim-20261013"
    "us-report unpaid delete (U4)|https://hs-us-report.oga-surf-project.workers.dev/health|json_eq|unpaid_delete|two-phase-20261013"
    "us-report board (U5)|https://hs-us-report.oga-surf-project.workers.dev/health|json_eq|board_index|per-key-20261013"
    "gate mould index (G2)|https://gate.horizonshield.dev/health|json_eq|mould_index|per-key-20261013"
    "gate removal stones (G3)|https://gate.horizonshield.dev/health|json_eq|removed_stones|per-key-20261013"
    "gate sweep lease (G4 G5)|https://gate.horizonshield.dev/health|json_eq|sweep|single-flight-20261013"
    "hearing store writes (H2 H3)|https://hs-hearing.oga-surf-project.workers.dev/health|json_eq|store_writes|do-serialized-20261013"
    "kira-line lessons (K1)|https://hs-kira-line.oga-surf-project.workers.dev/health|json_eq|lessons|per-key-20261013"
  )
fi

json_field() {  # $1 file, $2 field; prints the value or <no field>/<not json>
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("<not json>"); sys.exit(0)
v = d.get(sys.argv[2], "<no field>") if isinstance(d, dict) else "<not an object>"
print(v if isinstance(v, str) else json.dumps(v))
PY
}

fails=0
i=0
printf '%-30s %-6s %-28s %-28s %s\n' "CHECK" "HTTP" "EXPECTED" "GOT" "RESULT"
printf '%-30s %-6s %-28s %-28s %s\n' "-----" "----" "--------" "---" "------"
for row in "${ROWS[@]}"; do
  IFS='|' read -r name url kind field expected <<<"$row"
  i=$((i + 1))
  target="$url"
  if [ -n "$BASE" ]; then
    path="/${url#https://*/}"
    [ "$path" = "/$url" ] && path="/"
    target="${BASE%/}${path}"
  fi
  body="$TMPD/body.$i"
  code="$($CURL -sS -m 20 -H 'cache-control: no-cache' -o "$body" -w '%{http_code}' "$target" 2>"$TMPD/err.$i")" || code="000"
  [ -f "$body" ] || : >"$body"
  got=""; ok=0
  case "$kind" in
    status) got="$code"; [ "$code" = "$expected" ] && ok=1 ;;
    contains) if grep -q -- "$expected" "$body"; then got="present"; ok=1; else got="absent"; fi; [ "$code" = "200" ] || ok=0 ;;
    json_eq) got="$(json_field "$body" "$field")"; [ "$code" = "200" ] && [ "$got" = "$expected" ] && ok=1 ;;
    json_prefix)
      got="$(json_field "$body" "$field")"
      if [ "$code" = "200" ] && [ -n "$got" ] && { [ "${got#"$expected"}" != "$got" ] || [ "${expected#"$got"}" != "$expected" ]; }; then ok=1; fi ;;
  esac
  [ "$code" = "000" ] && got="unreachable: $(head -c 60 "$TMPD/err.$i" | tr '\n' ' ')"
  if [ "$ok" -eq 1 ]; then result="OK"; else result="MISMATCH"; fails=$((fails + 1)); fi
  printf '%-30s %-6s %-28s %-28s %s\n' "$name" "$code" "${expected:0:28}" "${got:0:28}" "$result"
done
echo
if [ "$fails" -gt 0 ]; then
  echo "$fails of $i checks did not match. Nothing was written; this script only reads."
  exit 1
fi
echo "all $i checks match"
exit 0
