#!/bin/bash
# Build the replication archive for the manuscript from one commit, reproducibly.
#   bash papers/nenrin-stack/make_replication_zip.sh [commit] [out.zip]
# The archive holds the manuscript, this directory, and every path NUMBERS.md cites, exactly as committed
# (git archive, so untracked files never enter). The same commit always gives the same file list and contents.
set -euo pipefail
C="${1:-HEAD}"
OUT="${2:-nenrin-stack-replication-$(git rev-parse --short=12 "$C").zip}"
cd "$(git rev-parse --show-toplevel)"
PATHS=(papers/nenrin-stack workers/hs-ledger/nenrin workers/hs-ledger/src workers/hs-ledger/test ops/tsunagi ops/adoption ops/concurrency_audit_20261013.md ops/no_swallowed_read.mjs ops/no_swallowed_read.test.mjs docs/metrics tools/tsunagi tools/adoption)
git archive --format=zip --prefix="nenrin-stack-replication-$(git rev-parse --short=12 "$C")/" -o "$OUT" "$C" -- "${PATHS[@]}"
echo "commit $(git rev-parse "$C")"
echo "archive $OUT"
shasum -a 256 "$OUT" 2>/dev/null || sha256sum "$OUT"
