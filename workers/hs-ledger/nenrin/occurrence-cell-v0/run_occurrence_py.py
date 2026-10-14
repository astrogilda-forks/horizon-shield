#!/usr/bin/env python3
"""The same rows as run_occurrence.mjs, through the Python port (../sdk-python/src/nenrin_verify/provenance.py).

  python3 -B run_occurrence_py.py [in.json] [out.json]      (defaults: in.json, results_py.json)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "sdk-python", "src")))
from nenrin_verify import provenance as P  # noqa: E402

inp = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "in.json")
outp = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "results_py.json")


def sig(p):
    return {"verdict": p["verdict"], "refusals": sorted(r["code"] for r in p["refusals"]),
            "findings": sorted(f["code"] for f in p["findings"])}


cases = json.load(open(inp, encoding="utf-8"))
out = {}
for c in cases:
    out[c["name"]] = sig(P.verify_provenance(dict(c["bundle"], resolve=P.did_key_resolver)))
base = next(c for c in cases if c["name"] == "o00_signed_grant_and_provider_receipt")["bundle"]
for name, ext in (("o06_lookup_not_found", {"found": False, "matches": False}),
                  ("o07_lookup_found_not_matching", {"found": True, "matches": False}),
                  ("o08_lookup_found_and_matching", {"found": True, "matches": True})):
    calls = []

    def lookup(ev, ext=ext, calls=calls):
        calls.append(1)
        return ext
    row = sig(P.verify_provenance(dict(base, resolve=P.did_key_resolver, lookup=lookup)))
    row["lookup_calls"] = len(calls)
    out[name] = row
with open(outp, "w", encoding="utf-8", newline="\n") as f:
    json.dump(out, f, indent=2)
    f.write("\n")
for k, v in out.items():
    print(k, json.dumps(v, separators=(",", ":")))
