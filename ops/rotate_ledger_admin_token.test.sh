#!/bin/bash
# ops/rotate_ledger_admin_token.test.sh
#
# ops/rotate_ledger_admin_token.sh を --dry-run で走らせる試験。偽の HOME と偽の鍵ファイルを使い、
# wrangler / gh / curl / openssl は一度も呼ばない。確かめること:
#   - 手順の順番 (rotate: 生成 -> hs-ledger に put -> 新しい値で 200 -> ファイルへ移す -> pdf-gen -> gateway -> Actions)
#   - --sync は 200 を確かめてから配る。受け付けない値は配らない。--include-ledger は hs-ledger を先にやる。
#   - 途中で失敗したら、古い値と新しい値の場所を出し、終了コード 1。
#   - 出力のどこにも 64 桁の 16 進 (値の形) が出ない。偽の鍵そのものも出ない。
#   - dry-run は HOME の鍵ファイルを変えず、.new も作らない。
#
#   bash ops/rotate_ledger_admin_token.test.sh
#
# 終了コード 0 = 全部通った、1 = どれかが落ちた。

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/rotate_ledger_admin_token.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rot_test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAKE_HOME="$WORK/home"
mkdir -p "$FAKE_HOME"
for w in hs-ledger hs-pdf-gen; do
  mkdir -p "$FAKE_HOME/horizon-shield/workers/$w"
  printf '{ "name": "%s" }\n' "$w" > "$FAKE_HOME/horizon-shield/workers/$w/wrangler.jsonc"
done
mkdir -p "$FAKE_HOME/hs-core-private/hs-agreement-intake"
printf '{ "name": "hs-agreement-intake" }\n' > "$FAKE_HOME/hs-core-private/hs-agreement-intake/wrangler.jsonc"
FAKE_TOKEN="$(printf 'a1%.0s' $(seq 32))"   # 64 hex built at run time, so no key-shaped literal sits in the repo
printf '%s\n' "$FAKE_TOKEN" > "$FAKE_HOME/.hs_ledger_token"
chmod 600 "$FAKE_HOME/.hs_ledger_token"
BEFORE_SUM="$(cksum < "$FAKE_HOME/.hs_ledger_token")"

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# run <outfile> [env assignments...] -- <args...>
run() {
  local out="$1"; shift
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  env -i PATH="$PATH" HOME="$FAKE_HOME" TMPDIR="$WORK" "${envs[@]+"${envs[@]}"}" bash "$SCRIPT" --dry-run "$@" > "$out" 2>&1
  echo $? > "$out.rc"
}
rc() { cat "$1.rc"; }
line_of() { grep -n -F -m1 -- "$2" "$1" | cut -d: -f1; }
# in_order <file> <marker1> <marker2> ...: every marker is present and each comes after the previous one
in_order() {
  local f="$1"; shift
  local prev=0 n m
  for m in "$@"; do
    n="$(line_of "$f" "$m")"
    [ -n "$n" ] || { echo "       missing: $m"; return 1; }
    [ "$n" -gt "$prev" ] || { echo "       out of order: $m (line $n, previous at $prev)"; return 1; }
    prev="$n"
  done
  return 0
}
no_secret() { ! grep -Eq '[0-9A-Fa-f]{64}' "$1" && ! grep -qF "$FAKE_TOKEN" "$1"; }

echo "--rotate (dry-run):"
O="$WORK/rotate.out"; run "$O" --  --rotate
check "exit 0" '[ "$(rc "$O")" = 0 ]'
check "order: generate, put hs-ledger, probe new, move, pdf-gen, gateway, Actions" \
  'in_order "$O" "STEP: generate a new value" "STEP: put the new LEDGER_ADMIN_TOKEN to hs-ledger" "STEP: probe hs-ledger with the new value" "STEP: move" "STEP: put LEDGER_ADMIN_TOKEN to hs-pdf-gen" "STEP: put LEDGER_ADMIN_TOKEN to hs-agreement-intake" "STEP: set GitHub Actions secret"'
check "each wrangler put is the printf pipe shape run in the worker dir" \
  '[ "$(grep -c "printf %s \"\$V\" | npx --yes wrangler secret put LEDGER_ADMIN_TOKEN" "$O")" = 3 ]'
check "gh reads the value from a file on stdin" 'grep -qF "gh secret set LEDGER_ADMIN_TOKEN --repo ogasurfproject-jpg/horizon-shield <" "$O"'
check "curl gets the header through --config - (not argv)" 'grep -qF -- "--config - https://ledger.horizonshield.dev/ledger/pending" "$O"'
check "checklist marks all five places done" '[ "$(grep -c "^  \[done  \]" "$O")" = 5 ]'
check "key manager reminder is printed" 'grep -qF "鍵マネージャ" "$O"'
check "no 64-hex string and not the fake token in the output" 'no_secret "$O"'
check "dry-run left the key file unchanged and made no .new" '[ "$(cksum < "$FAKE_HOME/.hs_ledger_token")" = "$BEFORE_SUM" ] && [ ! -e "$FAKE_HOME/.hs_ledger_token.new" ]'

echo "--rotate, hs-agreement-intake put fails:"
O="$WORK/rotate_fail.out"; run "$O" DRYRUN_FAIL=hs-agreement-intake -- --rotate
check "exit 1" '[ "$(rc "$O")" = 1 ]'
check "names where the new value is and where the old value is" \
  'grep -q "新しい値: hs-ledger" "$O" && grep -q "新しい値: keyfile" "$O" && grep -q "新しい値: hs-pdf-gen" "$O" && grep -q "古い値:   hs-agreement-intake" "$O"'
check "says how to finish (--sync)" 'grep -qF "bash ops/rotate_ledger_admin_token.sh --sync" "$O"'
check "Actions is still attempted after a worker fails" 'grep -qF "STEP: set GitHub Actions secret" "$O"'
check "no 64-hex string in the failure output" 'no_secret "$O"'

echo "--rotate, the new value does not authenticate:"
O="$WORK/rotate_401.out"; run "$O" DRYRUN_PROBE_CODE=401 -- --rotate
check "exit 1" '[ "$(rc "$O")" = 1 ]'
check "stops before moving the file and before the other places" \
  '! grep -qF "STEP: move" "$O" && ! grep -qF "to hs-pdf-gen" "$O" && ! grep -qF "STEP: set GitHub Actions secret" "$O"'
check "reports hs-ledger as unknown and the rest as old" 'grep -q "不明:     hs-ledger" "$O" && grep -q "古い値:   keyfile" "$O"'
check "no 64-hex string" 'no_secret "$O"'

echo "--rotate, the hs-ledger put fails:"
O="$WORK/rotate_ledgerfail.out"; run "$O" DRYRUN_FAIL=hs-ledger -- --rotate
check "exit 1, nothing after hs-ledger" '[ "$(rc "$O")" = 1 ] && ! grep -qF "STEP: probe hs-ledger with the new value" "$O" && ! grep -qF "to hs-pdf-gen" "$O"'

echo "--sync (dry-run):"
O="$WORK/sync.out"; run "$O" -- --sync
check "exit 0" '[ "$(rc "$O")" = 0 ]'
check "order: check file, probe, pdf-gen, gateway, Actions" \
  'in_order "$O" "STEP: check" "STEP: probe hs-ledger with" "STEP: put LEDGER_ADMIN_TOKEN to hs-pdf-gen" "STEP: put LEDGER_ADMIN_TOKEN to hs-agreement-intake" "STEP: set GitHub Actions secret"'
check "hs-ledger is not put without --include-ledger" '! grep -qF "to hs-ledger" "$O"'
check "no 64-hex string" 'no_secret "$O"'

echo "--sync (default mode, no flag):"
O="$WORK/default.out"; run "$O" --
check "default is --sync" '[ "$(rc "$O")" = 0 ] && grep -qF "mode=sync" "$O"'

echo "--sync --include-ledger:"
O="$WORK/sync_inc.out"; run "$O" -- --sync --include-ledger
check "exit 0, hs-ledger after the probe and before hs-pdf-gen" \
  '[ "$(rc "$O")" = 0 ] && in_order "$O" "STEP: probe hs-ledger with" "to hs-ledger (--include-ledger" "STEP: put LEDGER_ADMIN_TOKEN to hs-pdf-gen"'

echo "--sync, the file does not authenticate:"
O="$WORK/sync_401.out"; run "$O" DRYRUN_PROBE_CODE=401 -- --sync
check "exit 2 and nothing pushed" '[ "$(rc "$O")" = 2 ] && ! grep -qF "to hs-pdf-gen" "$O" && ! grep -qF "STEP: set GitHub Actions secret" "$O"'
O="$WORK/sync_401_inc.out"; run "$O" DRYRUN_PROBE_CODE=401 -- --sync --include-ledger
check "with --include-ledger: hs-ledger is put first, then no push when 200 never comes" \
  '[ "$(rc "$O")" = 1 ] && grep -qF "it does not accept this value yet" "$O" && ! grep -qF "to hs-pdf-gen" "$O"'

echo "--sync, a bad key file:"
printf 'not-a-token\n' > "$FAKE_HOME/.hs_ledger_token"
O="$WORK/sync_badfile.out"; run "$O" -- --sync
check "exit 2, nothing probed or pushed" '[ "$(rc "$O")" = 2 ] && ! grep -qF "STEP: probe" "$O"'
printf '%s\n' "$FAKE_TOKEN" > "$FAKE_HOME/.hs_ledger_token"; chmod 644 "$FAKE_HOME/.hs_ledger_token"
O="$WORK/sync_mode.out"; run "$O" -- --sync
check "mode 644 is reported as a chmod 600 (dry-run does not change it)" 'grep -qF "chmod 600" "$O" && [ "$(stat -c %a "$FAKE_HOME/.hs_ledger_token" 2>/dev/null || stat -f %Lp "$FAKE_HOME/.hs_ledger_token")" = 644 ]'

echo "missing worker dir:"
rm -rf "$FAKE_HOME/hs-core-private/hs-agreement-intake"
O="$WORK/nodir.out"; run "$O" -- --rotate
check "exit 2 before anything is generated" '[ "$(rc "$O")" = 2 ] && ! grep -qF "STEP: generate" "$O"'

check "hs-gateway is no longer a place (its secret was removed on 2026-10-13)" '! grep -qF "hs-gateway" "$O"'

echo
echo "=== $pass ok, $fail failed ==="
[ "$fail" -eq 0 ]
