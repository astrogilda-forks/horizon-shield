#!/usr/bin/env python3
"""Make the blind copy of one of giskard09's vector files: the same cases with `expected_code` and `note` removed
from each case, written as JSON with two-space indent, non-ASCII kept, and a final newline unless --no-final-newline is given. The sha256 of each blind
copy used here is in rerun-*/BLIND_COPY_SHA256SUMS.

    python3 -I -B make_blind_copy.py <author's vectors.json> <blind copy.json> [--no-final-newline]

The 7125f55d copies were written without the final newline (--no-final-newline); the 4cbf5c8 copies have it.
"""
import json, sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
for c in d["cases"]:
    c.pop("expected_code", None)
    c.pop("note", None)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(json.dumps(d, indent=2, ensure_ascii=False) + ("" if "--no-final-newline" in sys.argv[3:] else "\n"))
