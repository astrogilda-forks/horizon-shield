#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
settle core v0, held-out set blind-01: freeze a challenger's outputs, and compare them with the opened answers.

Before opening (challenger):
    python3 blind_compare.py freeze --outputs OUTDIR
        OUTDIR holds one file per vector, bNN.json, the eight core fields (SETTLE_CORE_v0.md 9.1) as a JSON object.
        A vector the implementation cannot settle still gets a file, e.g. {"error": "..."}; a missing file counts as a
        disagreement. Prints the freeze digest: sha256 of the lines "<sha256 of file bytes>  bNN.json\\n" in id order,
        over b01..bNN exactly. Post that digest, with the code commit, before the opening date.

After opening (anyone):
    python3 blind_compare.py compare --public PUBDIR --expected EXPDIR --salts SALTS.json --outputs OUTDIR \
                                     --frozen <digest> --name <handle>
        1. checks the opening (blind_commit.verify_opening): answers and root match COMMITMENT.txt;
        2. checks that OUTDIR has the frozen digest; stops if not (outputs changed after freezing are not compared);
        3. compares the eight core fields per vector and prints agree / disagree with every differing field.
        deviation_codes and underspecified_reasons are compared as sets (9.1); event_set as a list (8.1 order);
        dispositions as an object; extra top-level keys in an output are listed, not judged.
This script reads only. It changes no file, the answers included.
"""
import argparse, hashlib, json, os, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blind_commit import verify_opening, read_commitment   # noqa: E402

CORE = ["contract_sha256", "verdict", "status", "bond_outcome", "deviation_codes", "underspecified_reasons", "event_set", "dispositions"]
SETS = {"deviation_codes", "underspecified_reasons"}
sha = lambda b: hashlib.sha256(b).hexdigest()


def freeze_digest(outdir, ids):
    lines = []
    for i in ids:
        p = os.path.join(outdir, i + ".json")
        lines.append("%s  %s.json\n" % (sha(open(p, "rb").read()) if os.path.isfile(p) else "missing", i))
    return sha("".join(lines).encode())


def norm(k, v):
    if k in SETS and isinstance(v, list):
        try:
            return sorted(set(v))
        except TypeError:
            return v
    return v


def short(v):
    s = json.dumps(v, sort_keys=True)
    return s if len(s) <= 160 else s[:157] + "..."


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("freeze")
    f.add_argument("--outputs", required=True)
    f.add_argument("--count", type=int, default=48)
    c = sub.add_parser("compare")
    for k in ("--public", "--expected", "--salts", "--outputs", "--frozen", "--name"):
        c.add_argument(k, required=True)
    a = ap.parse_args()

    if a.cmd == "freeze":
        ids = ["b%02d" % i for i in range(1, a.count + 1)]
        missing = [i for i in ids if not os.path.isfile(os.path.join(a.outputs, i + ".json"))]
        print("files: %d of %d present%s" % (len(ids) - len(missing), len(ids), (", missing " + " ".join(missing)) if missing else ""))
        print("freeze digest %s" % freeze_digest(a.outputs, ids))
        return 0

    if not verify_opening(a.public, a.expected, a.salts):
        print("the opening does not match the commitment: nothing compared")
        return 2
    _, _, _, per = read_commitment(a.public)
    ids = sorted(per)
    got_digest = freeze_digest(a.outputs, ids)
    if got_digest != a.frozen:
        print("outputs digest %s is not the frozen %s: nothing compared" % (got_digest, a.frozen))
        return 3
    agree, rows = 0, []
    for i in ids:
        exp = json.load(open(os.path.join(a.expected, i, "expected.json"), encoding="utf-8"))
        p = os.path.join(a.outputs, i + ".json")
        try:
            out = json.load(open(p, encoding="utf-8"))
        except (OSError, ValueError) as e:
            out = {"error": "unreadable output: %s" % e}
        if not isinstance(out, dict):
            out = {"error": "output is not an object"}
        diffs = [(k, exp.get(k), out.get(k, "<absent>")) for k in CORE if norm(k, exp.get(k)) != norm(k, out.get(k, "<absent>"))]
        extra = sorted(set(out) - set(CORE))
        if diffs:
            rows.append("DISAGREE %s" % i)
            for k, e, g in diffs:
                rows.append("    %-22s expected %s" % (k, short(e)))
                rows.append("    %-22s %-8s %s" % ("", a.name, short(g)))
        else:
            agree += 1
            rows.append("agree    %s" % i)
        if extra:
            rows.append("    (extra keys, not judged: %s)" % ", ".join(extra))
    print("settle core v0 blind-01, %s, frozen %s" % (a.name, a.frozen))
    print("\n".join(rows))
    print("%s: %d of %d vectors agree on the eight core fields" % (a.name, agree, len(ids)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
