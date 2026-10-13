#!/usr/bin/env bash
# refresh_upstream.sh <a2a-go commit or branch> : replace go/a2acrypto with upstream a2a-go's a2acrypto at that
# commit, unchanged apart from the one import path (the a2a package is the local JSON-shape stub in go/a2a), keep
# export_canon.go (the only file that is not upstream code), and rewrite UPSTREAM_SHA256.txt. Used by the watch
# workflow so a new a2a-go commit is measured as it is, not as it was copied on 2026-10-01.
# 2026-10-13: a2a-go e85760e (#453) made a2acrypto import its module-internal package internal/utils (ExpectEOF).
# Go does not let another module import an internal package, so for each internal/<pkg> that a2acrypto imports, the
# files of that package that import only the standard library are copied unchanged into go/internal/<pkg> (their
# sha256 in UPSTREAM_SHA256.txt as internal/<pkg>/<file>) and the import path is rewritten to it. A file of that
# package that imports anything outside the standard library is not copied; if a2acrypto needs it, go build fails
# and the watch says so instead of measuring a substitute.
set -euo pipefail
REF="${1:?usage: refresh_upstream.sh <commit|branch>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
git init -q "$T/a2a-go"
git -C "$T/a2a-go" remote add origin https://github.com/a2aproject/a2a-go.git
git -C "$T/a2a-go" fetch -q --depth 1 origin "$REF"
git -C "$T/a2a-go" checkout -q FETCH_HEAD
COMMIT="$(git -C "$T/a2a-go" rev-parse HEAD)"
find "$HERE/a2acrypto" -maxdepth 1 -name '*.go' ! -name export_canon.go -exec rm -f {} +
: > "$HERE/UPSTREAM_SHA256.txt"
REWRITE='s#"github.com/a2aproject/a2a-go(/v[0-9]+)?/a2a"#"hs.local/interop/a2a"#; s#"github.com/a2aproject/a2a-go(/v[0-9]+)?/internal/([a-z0-9_]+)"#"hs.local/interop/internal/\2"#'
for f in "$T"/a2a-go/a2acrypto/*.go; do
  case "$f" in *_test.go) continue ;; esac
  b="$(basename "$f")"
  (cd "$T/a2a-go/a2acrypto" && sha256sum "$b") >> "$HERE/UPSTREAM_SHA256.txt"
  sed -E "$REWRITE" "$f" > "$HERE/a2acrypto/$b"
done
rm -rf "$HERE/internal"
for pkg in $(cat "$T"/a2a-go/a2acrypto/*.go | grep -oE '"github.com/a2aproject/a2a-go(/v[0-9]+)?/internal/[a-z0-9_]+"' | sed -E 's#.*/internal/([a-z0-9_]+)"#\1#' | sort -u); do
  mkdir -p "$HERE/internal/$pkg"
  for f in "$T/a2a-go/internal/$pkg"/*.go; do
    case "$f" in *_test.go) continue ;; esac
    # only files whose imports are all standard library (no dot in the first path element)
    if sed -n '/^import/,/^)/p' "$f" | grep -oE '"[^"]+"' | tr -d '"' | cut -d/ -f1 | grep -q '\.'; then continue; fi
    if grep -qE '^import "[^"]*\.[^"]*"' "$f"; then continue; fi
    b="$(basename "$f")"
    (cd "$T/a2a-go" && sha256sum "internal/$pkg/$b") >> "$HERE/UPSTREAM_SHA256.txt"
    cp "$f" "$HERE/internal/$pkg/$b"
  done
done
cp "$T/a2a-go/LICENSE" "$HERE/UPSTREAM_LICENSE"
echo "$COMMIT"
