#!/bin/bash
# ops/rotate_ledger_admin_token.sh
#
# hs-ledger への書き込み鍵 (header X-Ledger-Key) を、置き場所すべてで同じ値にそろえる。社長の Mac で走らせる。
#
# 同じ値が要る場所 (2026-10-19 時点):
#   1. hs-ledger    の worker secret LEDGER_ADMIN_TOKEN   (鍵を確かめる側)
#   2. hs-pdf-gen   の worker secret LEDGER_ADMIN_TOKEN   (台帳へ追記する)
#   3. hs-agreement-intake の worker secret LEDGER_ADMIN_TOKEN (合意・契約・実行の日次の束ねを台帳へ追記する。
#      private、~/hs-core-private/hs-agreement-intake。HS_INTAKE_DIR で場所を変えられる)
#      2026-10-19: ここが一覧から漏れていた。10-13 の回転でこの worker だけ古い値のまま残り、10-14 から毎日の
#      束ねが 401 で戻され、SEKI の execution が台帳に入らなかった (失敗は worker の中で黙って待ちに戻る作り)。
#   hs-gateway は 2026-10-13 に TOshi が secret を消し、台帳へ書かない状態に戻した。この台本は入れない。
#   4. GitHub Actions secret LEDGER_ADMIN_TOKEN of ogasurfproject-jpg/horizon-shield (.github/workflows/jidec-stamp.yml)
#   5. ~/.hs_ledger_token (64 桁の 16 進、mode 600。ops/run_stamp.sh が毎時読む)
# この台本が触らない場所 (終わりの一覧で思い出させる):
#   - 鍵マネージャ (iCloud メモなど) の行。workers/hs-ledger/append_witness.sh は、そこから貼り付けた値を使う。
#   - GCP の hs-ledger-twin を配備している場合の Secret Manager LEDGER_ADMIN_TOKEN (workers/hs-ledger/gcp/README.md)。
#
# 使い方:
#   bash ops/rotate_ledger_admin_token.sh                     = --sync
#   bash ops/rotate_ledger_admin_token.sh --sync              今の ~/.hs_ledger_token を確かめて、2 3 4 に配る (3 だけ配るなら --sync で全部配って構わない、同じ値の入れ直し)
#   bash ops/rotate_ledger_admin_token.sh --sync --include-ledger
#                                                             1 にも入れる (先に 1 に入れて、200 を確かめてから配る)
#   bash ops/rotate_ledger_admin_token.sh --rotate            新しい値を作り、1 に入れて 200 を確かめてから 5 2 3 4
#   ... --dry-run                                             wrangler / gh / curl / openssl を呼ばず、形だけ出す
#
# 値の扱い (守ること):
#   - 値は画面にも、コマンドの引数 (ps で見える) にも、履歴にも、記録にも出さない。
#   - wrangler には printf %s "$V" | npx wrangler secret put NAME で渡す (printf は bash の組み込みなので引数に出ない)。
#     2026-10-07 に `< file` で put したら何も保存されなかったので、ファイルからの redirect は使わない。
#   - curl には header を --config - (標準入力) で渡す。-H "X-Ledger-Key: ..." は引数に出るので使わない。
#   - gh には gh secret set NAME --repo ... < file で渡す。file は空白・改行を除いた値だけの一時ファイル。
#   - 各 worker で wrangler の "Success" の行を確かめる。無ければ失敗として数える。
#
# 終了コード 0 = 全部の場所が済んだ、1 = どこかが失敗した (終わりの一覧に、古い値と新しい値の場所が出る)、
#            2 = 始める前の確認で止めた (何も変えていない)。

set +o xtrace
set -u -o pipefail
umask 077

NAME="LEDGER_ADMIN_TOKEN"
REPO_SLUG="ogasurfproject-jpg/horizon-shield"
REPO="${HS_REPO:-$HOME/horizon-shield}"
KEYFILE="$HOME/.hs_ledger_token"
NEWFILE="$HOME/.hs_ledger_token.new"
PROBE_URL="https://ledger.horizonshield.dev/ledger/pending"
OTHER_WORKERS="hs-pdf-gen hs-agreement-intake"
INTAKE_DIR="${HS_INTAKE_DIR:-$HOME/hs-core-private/hs-agreement-intake}"
wdir() { case "$1" in hs-agreement-intake) printf '%s' "$INTAKE_DIR" ;; *) printf '%s' "$REPO/workers/$1" ;; esac; }

MODE="sync"; INCLUDE_LEDGER=0; DRY=0
for a in "$@"; do
  case "$a" in
    --sync) MODE="sync" ;;
    --rotate) MODE="rotate" ;;
    --include-ledger) INCLUDE_LEDGER=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (use --sync, --rotate, --include-ledger, --dry-run)"; exit 2 ;;
  esac
done

TMPD="$(mktemp -d "${TMPDIR:-/tmp}/hs_ledger_rot.XXXXXX")" || { echo "mktemp failed"; exit 2; }
chmod 700 "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT
trap 'echo; echo "interrupted"; [ "$MODE" = "rotate" ] && rotate_failure_report; exit 1' INT TERM

# 状態の記録 (値は持たない)。STATE_<place> = old | new | same | failed | skipped | unknown
PLACES="hs-ledger hs-pdf-gen hs-agreement-intake actions keyfile"
setst() { eval "STATE_${1//-/_}=\"\$2\""; }
getst() { eval "printf '%s' \"\${STATE_${1//-/_}:-not-run}\""; }
for p in $PLACES; do setst "$p" "not-run"; done

step() { echo; echo "== STEP: $* =="; }
redact() { sed -E 's/[0-9A-Fa-f]{64}/<redacted>/g'; }

# 値を空白なしで読む (tr はファイルを標準入力で受けるので、値は引数に出ない)。
readval() { tr -d '[:space:]' < "$1"; }
is64hex() { local v; v="$(readval "$1")"; [[ "$v" =~ ^[0-9a-fA-F]{64}$ ]]; }

# 正規化した写し (値だけ、改行なし) を一時ディレクトリに作る。gh に渡すのはこれ。
normcopy() { # $1 = source file, $2 = dest
  local v; v="$(readval "$1")"; printf %s "$v" > "$2"; chmod 600 "$2"; v=
}

# ---------------------------------------------------------------- 外の道具 (dry-run では形だけ)
probe() { # $1 = file with the value, $2 = "old" for the old value. prints the HTTP code
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] printf 'header = \"X-Ledger-Key: %s\"\\n' \"\$V\" | curl -s -o /dev/null -w %{http_code} --config - $PROBE_URL" >&2
    if [ "${2:-}" = "old" ]; then printf '%s' "${DRYRUN_OLD_PROBE_CODE:-401}"; else printf '%s' "${DRYRUN_PROBE_CODE:-200}"; fi
    return 0
  fi
  local v code
  v="$(readval "$1")"
  code="$(printf 'header = "X-Ledger-Key: %s"\n' "$v" | curl -s -o /dev/null -w '%{http_code}' --max-time 20 --config - "$PROBE_URL")"
  v=
  printf '%s' "${code:-000}"
}

gen_new() { # $1 = dest file
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] openssl rand -hex 32 | tr -d '\\n' > $HOME/.hs_ledger_token.new   (mode 600)"
    printf '%064d' 0 > "$1"; chmod 600 "$1"
    return 0
  fi
  ( umask 077; openssl rand -hex 32 | tr -d '\n' > "$1" ) && chmod 600 "$1"
}

wr_put() { # $1 = worker, $2 = file with the value. 0 when wrangler printed Success
  local w="$1" f="$2" log="$TMPD/wrangler_$1.log" v rc
  local d; d="$(wdir "$w")"
  if [ ! -f "$d/wrangler.jsonc" ] && [ ! -f "$d/wrangler.toml" ]; then
    echo "  $w: $d に wrangler の設定が無い。put しない。"
    return 1
  fi
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] (cd $d && printf %s \"\$V\" | npx --yes wrangler secret put $NAME)"
    if [ "${DRYRUN_FAIL:-}" = "$w" ]; then echo "X [ERROR] simulated failure" > "$log"; else echo "Success! Uploaded secret $NAME" > "$log"; fi
  else
    v="$(readval "$f")"
    ( cd "$d" && printf %s "$v" | npx --yes wrangler secret put "$NAME" ) > "$log" 2>&1
    rc=$?
    v=
  fi
  if grep -q "Success" "$log"; then
    echo "  $w: $(grep -m1 "Success" "$log" | redact)"
    return 0
  fi
  echo "  $w: wrangler の Success の行が無い。失敗として数える。wrangler の出力 (末尾):"
  redact < "$log" | tail -n 8 | sed 's/^/      /'
  return 1
}

gh_set() { # $1 = file with the value (normalized, no newline)
  local log="$TMPD/gh.log" rc
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] gh secret set $NAME --repo $REPO_SLUG < <normalized copy of the value>"
    [ "${DRYRUN_FAIL:-}" = "actions" ] && { echo "  actions: gh failed (simulated)"; return 1; }
    echo "  actions: set"
    return 0
  fi
  gh secret set "$NAME" --repo "$REPO_SLUG" < "$1" > "$log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then echo "  actions: $(redact < "$log" | tail -n 1)"; return 0; fi
  echo "  actions: gh が失敗した (exit $rc):"
  redact < "$log" | tail -n 6 | sed 's/^/      /'
  return 1
}

# ---------------------------------------------------------------- 始める前の確認
preflight() {
  step "preflight (mode=$MODE include_ledger=$INCLUDE_LEDGER dry_run=$DRY)"
  local missing=0 w
  if [ "$DRY" = 0 ]; then
    for t in npx gh curl tr; do command -v "$t" >/dev/null 2>&1 || { echo "  missing tool: $t"; missing=1; }; done
    [ "$MODE" = "rotate" ] && { command -v openssl >/dev/null 2>&1 || { echo "  missing tool: openssl"; missing=1; }; }
    if command -v gh >/dev/null 2>&1 && ! gh auth status >/dev/null 2>&1; then echo "  gh is not logged in (gh auth login)"; missing=1; fi
  fi
  for w in hs-ledger $OTHER_WORKERS; do
    [ -d "$(wdir "$w")" ] || { echo "  missing worker dir: $(wdir "$w")"; missing=1; }
  done
  if [ $missing -ne 0 ]; then echo "  始める前の確認で止めた。何も変えていない。"; exit 2; fi
  echo "  ok"
}

# ---------------------------------------------------------------- 配る (2 3 4)
push_others() { # $1 = normalized file, $2 = state word for success (new|same)
  local w
  for w in $OTHER_WORKERS; do
    step "put $NAME to $w"
    if wr_put "$w" "$1"; then setst "$w" "$2"; else setst "$w" "failed"; fi
  done
  step "set GitHub Actions secret $NAME ($REPO_SLUG)"
  if gh_set "$1"; then setst actions "$2"; else setst actions "failed"; fi
}

# ---------------------------------------------------------------- 終わりの一覧
finish() {
  local rc=0 p s
  echo
  echo "== checklist ($MODE) =="
  for p in $PLACES; do
    s="$(getst "$p")"
    case "$s" in
      new|same|verified) mark="done  " ;;
      skipped) mark="skip  " ;;
      not-run) mark="-     " ;;
      *) mark="FAILED"; rc=1 ;;
    esac
    case "$p" in
      hs-ledger) label="hs-ledger worker secret" ;;
      hs-pdf-gen) label="hs-pdf-gen worker secret" ;;
      hs-agreement-intake) label="hs-agreement-intake worker secret" ;;
      actions) label="GitHub Actions secret ($REPO_SLUG)" ;;
      keyfile) label="$KEYFILE" ;;
    esac
    printf '  [%s] %-42s %s\n' "$mark" "$label" "$s"
  done
  echo "  (new = 新しい値が入った、same = 今の値を入れ直した、verified = 今の値で 200 を確かめた (入れ直していない)、"
  echo "   old = 古い値のまま、failed = 失敗、unknown = put は通ったが 200 を確かめられない、- = 走らせていない)"
  echo
  echo "  この台本が触らない場所:"
  echo "   - 鍵マネージャ (iCloud メモなど) の LEDGER_ADMIN_TOKEN の行。$MODE で値が変わったなら、その行を今の値に直す。"
  echo "     値はここには出さない。手元の値は $KEYFILE にある (append_witness.sh は貼り付けた値を使う)。"
  echo "   - GCP の hs-ledger-twin を配備しているなら、その Secret Manager の LEDGER_ADMIN_TOKEN も同じ値にする:"
  echo "       gcloud secrets versions add LEDGER_ADMIN_TOKEN --project tsugi-marketplace --data-file=\"$KEYFILE\""
  return $rc
}

# 失敗したときに、どこが古い値でどこが新しい値かと、続きのやり方を出す (rotate 用)。
rotate_failure_report() {
  echo
  echo "== rotate が途中で止まった: 古い値と新しい値の場所 =="
  local p s
  for p in $PLACES; do
    s="$(getst "$p")"
    case "$s" in
      new) echo "  新しい値: $p" ;;
      not-run|failed) echo "  古い値:   $p ($s)" ;;
      *) echo "  不明:     $p ($s)" ;;
    esac
  done
  echo
  echo "  続きのやり方:"
  if [ "$(getst keyfile)" = "new" ]; then
    echo "   新しい値は $KEYFILE にある (hs-ledger はこの値で 200)。失敗した場所だけ入れ直すには:"
    echo "     bash ops/rotate_ledger_admin_token.sh --sync"
    echo "   (--sync は $KEYFILE が 200 を返すことを確かめてから hs-pdf-gen, hs-agreement-intake, Actions に配る)"
  else
    echo "   新しい値は $NEWFILE にある (mode 600)。"
    echo "   もう一度 --rotate を走らせると、$NEWFILE が hs-ledger で 200 を返すならそれを使って続きをやる。"
    echo "   200 を返さないなら止まって、消してよいかを案内する。"
  fi
}

# ---------------------------------------------------------------- --sync
do_sync() {
  preflight
  step "check $KEYFILE"
  if [ ! -f "$KEYFILE" ]; then echo "  $KEYFILE が無い。--rotate で作るか、鍵マネージャの値をファイルに入れてから走らせる。"; exit 2; fi
  local perm
  perm="$(stat -c '%a' "$KEYFILE" 2>/dev/null || stat -f '%Lp' "$KEYFILE" 2>/dev/null)"   # GNU first; macOS stat rejects -c
  if [ "$perm" != "600" ]; then
    if [ "$DRY" = 1 ]; then echo "[dry-run] chmod 600 $KEYFILE (mode was $perm)"; else chmod 600 "$KEYFILE"; echo "  mode was $perm, set to 600"; fi
  fi
  if ! is64hex "$KEYFILE"; then echo "  $KEYFILE の中身が 64 桁の 16 進ではない。何も配らない。"; exit 2; fi
  echo "  64 hex, mode 600: ok"
  normcopy "$KEYFILE" "$TMPD/norm"
  setst keyfile "same"

  step "probe hs-ledger with $KEYFILE"
  local code
  code="$(probe "$TMPD/norm")"
  echo "  GET /ledger/pending -> HTTP $code"
  if [ "$code" = "200" ]; then
    setst hs-ledger "same"
    if [ "$INCLUDE_LEDGER" = 1 ]; then
      step "put $NAME to hs-ledger (--include-ledger; it already accepts this value)"
      if wr_put hs-ledger "$TMPD/norm"; then setst hs-ledger "same"; else setst hs-ledger "failed"; fi
    else
      setst hs-ledger "verified"
    fi
  else
    if [ "$INCLUDE_LEDGER" != 1 ]; then
      echo "  hs-ledger がこの値を受け付けない (HTTP $code)。受け付けない値を他へ配ると追記が止まるので、何も配らない。"
      echo "  この値を正として hs-ledger にも入れるなら: bash ops/rotate_ledger_admin_token.sh --sync --include-ledger"
      setst hs-ledger "old"
      finish; exit 2
    fi
    step "put $NAME to hs-ledger (--include-ledger; it does not accept this value yet)"
    if ! wr_put hs-ledger "$TMPD/norm"; then setst hs-ledger "failed"; finish; exit 1; fi
    step "probe hs-ledger again"
    code="$(probe_until_200 "$TMPD/norm")"
    echo "  GET /ledger/pending -> HTTP $code"
    if [ "$code" != "200" ]; then
      echo "  put は Success だったが 200 にならない。他へは配らない。少し待って --sync をもう一度。"
      setst hs-ledger "unknown"; finish; exit 1
    fi
    setst hs-ledger "new"
  fi
  push_others "$TMPD/norm" "same"
  finish
}

probe_until_200() { # 反映に数秒かかることがあるので、最大 6 回 (5 秒おき) 試す
  local i code
  for i in 1 2 3 4 5 6; do
    code="$(probe "$1")"
    [ "$code" = "200" ] && break
    [ "$DRY" = 1 ] || sleep 5
  done
  printf '%s' "$code"
}

# ---------------------------------------------------------------- --rotate
do_rotate() {
  preflight
  local code resumed=0 shown="$NEWFILE"
  if [ "$DRY" = 1 ]; then NEWFILE="$TMPD/newgen"; fi   # dry-run は HOME に何も書かない (表示は本来の場所)

  if [ -f "$NEWFILE" ] && [ "$DRY" = 0 ]; then
    step "resume: $NEWFILE exists from an earlier --rotate"
    if ! is64hex "$NEWFILE"; then echo "  $NEWFILE の中身が 64 桁の 16 進ではない。中身を確かめてから消す。何も変えていない。"; exit 2; fi
    normcopy "$NEWFILE" "$TMPD/new"
    code="$(probe "$TMPD/new")"
    echo "  GET /ledger/pending with $NEWFILE -> HTTP $code"
    if [ "$code" != "200" ]; then
      echo "  hs-ledger は $NEWFILE の値を受け付けない。前の --rotate の put は届いていない。"
      echo "  届いていないことに納得できたら、消してから --rotate をやり直す: rm $NEWFILE"
      exit 2
    fi
    echo "  hs-ledger は既にこの値。続きをやる。"
    setst hs-ledger "new"; resumed=1
  fi

  if [ $resumed -eq 0 ]; then
    step "generate a new value into $shown (mode 600)"
    if ! gen_new "$NEWFILE" || ! is64hex "$NEWFILE"; then echo "  新しい値を作れなかった。何も変えていない。"; rm -f "$NEWFILE"; exit 2; fi
    echo "  64 hex: ok (shown nowhere)"
    normcopy "$NEWFILE" "$TMPD/new"

    step "put the new $NAME to hs-ledger"
    if ! wr_put hs-ledger "$TMPD/new"; then
      setst hs-ledger "failed"
      echo "  hs-ledger への put が失敗した。どこも古い値のまま。新しい値は使われていない:"
      echo "    rm $NEWFILE"
      finish; exit 1
    fi

    step "probe hs-ledger with the new value"
    code="$(probe_until_200 "$TMPD/new")"
    echo "  GET /ledger/pending (new value) -> HTTP $code"
    if [ "$code" != "200" ]; then
      setst hs-ledger "unknown"
      echo "  put は Success だったが、新しい値で 200 にならない。ここで止める (他は古い値のまま)。"
      if [ -f "$KEYFILE" ]; then
        normcopy "$KEYFILE" "$TMPD/old"
        echo "  古い値 ($KEYFILE) での応答: HTTP $(probe "$TMPD/old" old)"
      fi
      rotate_failure_report; finish; exit 1
    fi
    setst hs-ledger "new"
    if [ -f "$KEYFILE" ]; then
      normcopy "$KEYFILE" "$TMPD/old"
      echo "  old value now answers HTTP $(probe "$TMPD/old" old) (401 expected)"
    fi
  fi

  step "move $shown to $KEYFILE"
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] mv $shown $KEYFILE && chmod 600 $KEYFILE"
    setst keyfile "new"
  elif mv -f "$NEWFILE" "$KEYFILE" && chmod 600 "$KEYFILE"; then
    setst keyfile "new"; echo "  ok (ops/run_stamp.sh reads it from the next hourly run)"
  else
    setst keyfile "failed"
    echo "  mv に失敗した。新しい値は $NEWFILE に残っている。"
    rotate_failure_report; finish; exit 1
  fi

  push_others "$TMPD/new" "new"
  if ! finish; then rotate_failure_report; exit 1; fi
}

if [ "$MODE" = "rotate" ]; then do_rotate; else do_sync; fi
