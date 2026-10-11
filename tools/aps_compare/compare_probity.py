#!/usr/bin/env python3
"""compare_probity: HORIZON SHIELD's APS 2.0 reader output beside Probity's independent reader, case by case.

    python3 tools/aps_compare/compare_probity.py                  # fetches Probity's report at the pinned commit
    python3 tools/aps_compare/compare_probity.py --report r.json  # offline, a copy of that report

Both readers ran on aeoess's frozen vectors (agent-passport-vectors-v2.json, commit 407ca2d5, sha256 9fce76db...).
Ours is closed source; verify-directory/admission/aps-v2/results-407ca2d5.json is its published output. Probity's is
public (probityai/agent-evidence-atlas, experiments/aps-corrected20-2026-10-10/report.json), pinned here by commit and
sha256. For every case this compares the final outcome, proof_of_possession and key_authority where our reader reports
them, and the resolver requests. Three outcomes are declared to differ, and are checked to differ exactly as declared:
did-web-resolver-not-found (ours invalid / key_authority rejected, following the SDK; Probity indeterminate /
unresolved, following draft-04 section 3.5), version-changed and record-type-changed (ours invalid, Probity
unsupported). Exit 0 when everything else agrees and the declared differences are exactly these; 1 otherwise.
It does not run either reader: it compares what each published. Standard library only.
"""
import argparse, hashlib, json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OURS = os.path.join(ROOT, "verify-directory", "admission", "aps-v2", "results-407ca2d5.json")
PROBITY_URL = ("https://raw.githubusercontent.com/probityai/agent-evidence-atlas/82436c01307d425960f3b3353af35a824a1d3b21/"
               "experiments/aps-corrected20-2026-10-10/report.json")
PROBITY_SHA256 = "1598f87559130cb0e7a2e4ca59e5d6a2a584b402149bc28baad30dd9eaa01df1"
VECTORS_SHA256 = "9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5"
DECLARED = {
    "did-web-resolver-not-found": {"ours": ("invalid", "rejected"), "probity": ("indeterminate", "unresolved")},
    "version-changed": {"ours": ("invalid", None), "probity": ("unsupported", None)},
    "record-type-changed": {"ours": ("invalid", None), "probity": ("unsupported", None)},
}


def fetch(url):
    req = urllib.request.Request(url, headers={"user-agent": "hs-aps-compare/0 (+https://github.com/ogasurfproject-jpg/horizon-shield)"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def compare(ours, probity):
    """Returns (rows, problems)."""
    prob = []
    if ours.get("vectors", {}).get("sha256") != VECTORS_SHA256:
        prob.append("our results are not over the 407ca2d5 vectors")
    if probity.get("fixtureSHA256") != VECTORS_SHA256:
        prob.append("Probity's report is not over the 407ca2d5 vectors")
    theirs = {c["name"]: c for c in probity.get("cases", [])}
    rows = []
    for c in ours.get("cases", []):
        name, r = c["name"], c["reader"]
        t = theirs.pop(name, None)
        if t is None:
            prob.append("%s: not in Probity's report" % name)
            continue
        tl = t.get("layers", {})
        diffs = []
        if r.get("state") != t.get("readerOutcome"):
            diffs.append("outcome %s / %s" % (r.get("state"), t.get("readerOutcome")))
        if "proof_of_possession" in r and r["proof_of_possession"] != tl.get("proof_of_possession"):
            diffs.append("proof_of_possession %s / %s" % (r["proof_of_possession"], tl.get("proof_of_possession")))
        if "key_authority" in r and r["key_authority"] != tl.get("key_authority"):
            diffs.append("key_authority %s / %s" % (r["key_authority"], tl.get("key_authority")))
        if (c.get("resolver_requests") or []) != (t.get("resolverRequests") or []):
            diffs.append("resolver requests differ")
        d = DECLARED.get(name)
        if d:
            want = d["ours"][0] == r.get("state") and d["probity"][0] == t.get("readerOutcome") \
                and (d["ours"][1] is None or (r.get("key_authority") == d["ours"][1] and tl.get("key_authority") == d["probity"][1]))
            other = [x for x in diffs if not x.startswith("outcome") and not x.startswith("key_authority")]
            ok = want and not other
            rows.append({"name": name, "status": "declared difference" if ok else "UNEXPECTED", "detail": diffs})
            if not ok:
                prob.append("%s: the declared difference is not what was published: %s" % (name, diffs))
        else:
            rows.append({"name": name, "status": "agree" if not diffs else "DIFFER", "detail": diffs})
            if diffs:
                prob.append("%s: %s" % (name, "; ".join(diffs)))
    for name in theirs:
        prob.append("%s: in Probity's report, not in ours" % name)
    return rows, prob


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--report", help="a local copy of Probity's report.json (else fetched at the pinned commit)")
    ap.add_argument("--ours", default=OURS)
    a = ap.parse_args()
    raw = open(a.report, "rb").read() if a.report else fetch(PROBITY_URL)
    if hashlib.sha256(raw).hexdigest() != PROBITY_SHA256:
        print("Probity's report is not the pinned file (sha256 %s, pinned %s)" % (hashlib.sha256(raw).hexdigest(), PROBITY_SHA256))
        return 1
    rows, prob = compare(json.load(open(a.ours, encoding="utf-8")), json.loads(raw.decode("utf-8")))
    for r in rows:
        print("%-36s %-20s %s" % (r["name"], r["status"], "; ".join(r["detail"])))
    agree = sum(r["status"] == "agree" for r in rows)
    declared = sum(r["status"] == "declared difference" for r in rows)
    print("\n%d agree, %d declared differences as declared, %d problems" % (agree, declared, len(prob)))
    for p in prob:
        print("PROBLEM " + p)
    return 1 if prob else 0


if __name__ == "__main__":
    sys.exit(main())
