#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run the reference implementation (MUSUBI settle_v1_16.py) over every vector in vectors/ and compare the core
fields of SETTLE_CORE_v0.md section 9 with each expected.json. Prints N/N and exits 0 only when all agree.

    python3 run_reference.py                       # reference in the folder above (musubi-v0)
    SETTLE_REF=/path/to/musubi-v0 python3 run_reference.py

It also checks every file against the sha256 recorded in vectors.json, so a vector edited by hand is caught.
The reference is called as a library: settle_v1_16.settle_v1_16(contract, events, view, nenrin_records=...),
binding mode strict, one view (no fork choice). See SETTLE_CORE_v0.md section 2.

core_fields() is the one definition of the core projection; gen_vectors.py imports it from here.
"""
import hashlib, json, os, sys

sys.dont_write_bytecode = True                # never write caches into the reference folder

HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.environ.get("SETTLE_REF", os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))


def core_fields(s):
    """Project a settlement onto the core fields (SETTLE_CORE_v0.md section 9)."""
    disp = {}

    def put(sha, code):
        if sha in disp and disp[sha] != code:
            raise AssertionError("record %s has two dispositions: %s and %s" % (sha, disp[sha], code))
        disp[sha] = code

    b = s.get("binding") or {}
    for x in b.get("foreign") or []:
        put(x["sha256"], "foreign")
    for x in b.get("inconsistent") or []:
        put(x["sha256"], "inconsistent")
    for sha in b.get("unbound") or []:
        put(sha, "unbound")
    for x in s.get("rejected") or []:
        put(x["sha256"], "rejected")
    for x in s.get("ignored") or []:
        put(x["sha256"], "ignored")
    for x in s.get("orphaned") or []:
        put(x["sha256"], "orphaned")
    for x in s.get("predates_contract") or []:
        put(x["sha256"], "predates_contract")
    for x in s.get("duplicate_anchorings") or []:
        for sha in x.get("dropped") or []:
            put(sha, "duplicate_dropped")
    for x in s.get("signed_body_collapse") or []:
        for sha in x.get("dropped") or []:
            put(sha, "duplicate_dropped")
    for x in s.get("underspecified") or []:
        if "sha256" in x:
            put(x["sha256"], x["reason"])
    for x in (s.get("v1_16") or {}).get("refused") or []:
        put(x["sha256"], x["reason"])
    for x in s.get("authoritative_event_set") or []:
        put(x["sha256"], "accepted")
    return {
        "contract_sha256": s.get("contract_sha256"),
        "verdict": s.get("verdict"),
        "status": s.get("status"),
        "bond_outcome": s.get("bond_outcome"),
        "deviation_codes": sorted({d.get("clause") for d in (s.get("deviations") or [])}),
        "underspecified_reasons": sorted({u.get("reason") for u in (s.get("underspecified") or [])}),
        "event_set": [{"kind": e["kind"], "sha256": e["sha256"], "height": e["height"]} for e in (s.get("authoritative_event_set") or [])],
        "dispositions": {k: disp[k] for k in sorted(disp)},
    }


def load_reference(ref=REF):
    sys.path.insert(0, ref)
    import settle_v1_16
    from contract_v0 import parse_strict
    return settle_v1_16.settle_v1_16, parse_strict


def settle_dir(vdir, settle, parse_strict):
    """Read one vector's inputs exactly as stored and settle them with the reference."""
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(os.path.join(vdir, "contract.json"))
    view = rd(os.path.join(vdir, "view.json"))
    ed = os.path.join(vdir, "events")
    events = [rd(os.path.join(ed, f)) for f in sorted(os.listdir(ed))] if os.path.isdir(ed) else []
    nd = os.path.join(vdir, "nenrin")
    nenrin = [rd(os.path.join(nd, f)) for f in sorted(os.listdir(nd))] if os.path.isdir(nd) else None
    pp = os.path.join(vdir, "parent.json")
    parent = rd(pp) if os.path.isfile(pp) else None
    return settle(contract, events, view, parent=parent, nenrin_records=nenrin or None)


def main():
    settle, parse_strict = load_reference()
    idx = json.load(open(os.path.join(HERE, "vectors", "vectors.json"), encoding="utf-8"))
    n = ok = 0
    for v in idx["vectors"]:
        n += 1
        vdir = os.path.join(HERE, "vectors", v["id"])
        problems = []
        for rel, want in sorted(v["files"].items()):
            got = hashlib.sha256(open(os.path.join(vdir, rel), "rb").read()).hexdigest()
            if got != want:
                problems.append("file %s sha256 %s, index says %s" % (rel, got[:12], want[:12]))
        exp = json.load(open(os.path.join(vdir, "expected.json"), encoding="utf-8"))
        got = core_fields(settle_dir(vdir, settle, parse_strict))
        for k in sorted(set(exp) | set(got)):
            if exp.get(k) != got.get(k):
                problems.append("%s: expected %s, got %s" % (k, json.dumps(exp.get(k))[:200], json.dumps(got.get(k))[:200]))
        if problems:
            print("FAIL %s" % v["id"])
            for p in problems:
                print("     " + p)
        else:
            ok += 1
            print("ok   %-44s %-14s %-12s %s" % (v["id"], got["verdict"], got["status"], ",".join(got["deviation_codes"] + got["underspecified_reasons"]) or "-"))
    print("\n%d/%d vectors agree with the reference (settle_v1_16.py at %s)" % (ok, n, REF))
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
