#!/usr/bin/env python3
"""Write pinned/expected.json from the two reference verifiers (npm and PyPI) on pinned/fixtures/.

Refuses to write when the two disagree on any bundle or either raises: a pinned signature is one both references
already give, so pinning never changes behaviour. Run after make_pinned.mjs, only when adding cases.
  python3 pin_expected.py
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import differential as d  # noqa: E402


def main():
    meta = json.load(open(os.path.join(HERE, "pinned", "cases.json")))
    cases = [{"name": m["name"], "bundle": json.load(open(os.path.join(HERE, "pinned", "fixtures", m["name"] + ".json")))} for m in meta]
    js, py = d.run_js(cases), d.run_py(cases)
    bad = [c["name"] for c in cases if js[c["name"]] != py[c["name"]] or "error" in js[c["name"]]]
    if bad:
        print("NOT WRITTEN, the references disagree or raise on: " + ", ".join(bad))
        return 1
    out = {
        "schema": "nenrin-interop-expected-v0",
        "version": "0.1.0",
        "verifier": "nenrin-provenance-verify-v0 (sdk/nenrin_verify.mjs, npm: nenrin-verify; and the PyPI port)",
        "note": "edge rules pinned from the 2026-10-12 triage (S1 to S12 in VERIFIER.md). Not part of the conformance condition at the top of VERIFIER.md; a check you can run.",
        "cases": {m["name"]: {"intent": m["intent"], "expect": js[m["name"]]} for m in meta},
    }
    with open(os.path.join(HERE, "pinned", "expected.json"), "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote pinned/expected.json, %d cases, npm and PyPI agree on every one" % len(meta))
    return 0


if __name__ == "__main__":
    sys.exit(main())
