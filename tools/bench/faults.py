#!/usr/bin/env python3
"""faults.py: four faults, each tried several ways, counted as detected or missed by the repository's own checkers.

    python3 tools/bench/faults.py [--out /tmp/hs-bench] [--json]

Offline. Every input is a copy made in a temp dir from files committed in this repository: the ledger copy in
workers/hs-ledger/nenrin/survive-v0/kept (mirror-v0 layout) and the synthetic MUSUBI contract and regtest chain of
musubi-v0/settle-core-v0/gen_vectors.py. Nothing under the repository is written. No network: the one checker that
would reach block explorers (survive.check_anchors) gets a stand-in fetcher that refuses, and only the part of it
that runs before any fetch is counted.

Each row says basis "verified" (the count comes from running the checker here) or "expected" (the outcome follows
from the code but was not run, with the reason).

1 truncated ledger copy   the last k entries (k = 1..10) removed from a copy of kept/.
                          a. verify_chain.py with --held-head kept/head.json (a head saved on an earlier day)
                          b. verify_chain.py without a held head
                          c. survive.py drill without a held head: digests and chain are run here; the Bitcoin
                             anchors need two block explorers, so the drill's outcome "rebuilt" is expected, not run
2 forked head.json        entry p of the copy gets different raw bytes (a trailing newline, claim_sha256 updated),
                          the chain is recomputed and a self-consistent head.json is written for the fork, for
                          p in {137, 136, 130, 120, 100}.
                          a. one reader holding only the forked copy and its head (verify_chain --head)
                          b. two readers comparing: the forked head held against the genuine copy (--held-head)
                          c. two mirrors comparing content_sha256 (mirror.py content_digests over the manifest)
3 swapped anchor          a. a record carries the anchor of another record in another block (5 records, 5 tries)
                          b. the same signed body anchored again in a later block, only that copy given (3 tries)
                          c. two .ots proofs of the kept copy swapped (5 pairs), survive.check_anchors
4 shortened header view   one execution, the chain padded so the anchor is exactly final (depth 6, horizon
                          inclusive); a. the top s headers removed (s = 1..8); b. the lowest s headers removed (s = 2..3,
                          so the contract checkpoint, the second header, is gone).
A try is detected when the checker reports a finding or the settlement is not (within_grant, final) with the
record accepted. A control row runs the unchanged input and shows whether it passes clean (false_alarm 0).
"""
import argparse, copy, hashlib, json, os, shutil, sys, tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
NENRIN = os.path.join(REPO, "workers", "hs-ledger", "nenrin")
KEPT = os.path.join(NENRIN, "survive-v0", "kept")
sys.path.insert(0, os.path.join(NENRIN, "survive-v0"))
sys.path.insert(0, os.path.join(NENRIN, "mirror-v0"))

import verify_chain as VC  # noqa: E402
import survive as SV  # noqa: E402
import mirror as MR  # noqa: E402


class NoNetwork(Exception):
    pass


def refuse_fetch(*_a, **_k):
    raise NoNetwork("faults.py does not fetch")


def copy_ledger(dst, upto=None):
    os.makedirs(os.path.join(dst, "ledger"))
    for name in os.listdir(os.path.join(KEPT, "ledger")):
        stem = name.split(".")[0]
        if stem.isdigit() and (upto is None or int(stem) <= upto):
            shutil.copyfile(os.path.join(KEPT, "ledger", name), os.path.join(dst, "ledger", name))
    return dst


def head_doc(n, head):
    return {"schema": VC.HEAD_SCHEMA, "n": n, "head": head, "prev_entry_sha256": head, "entry_sha256": SV.marker_sha(n, head)}


def write_json(p, obj):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return p


def row(fault, case, tries, detected, basis, note, codes=()):
    return {"fault": fault, "case": case, "tries": tries, "detected": detected, "missed": tries - detected, "basis": basis,
            "note": note, "codes": sorted(set(codes))}


def control(fault, case, clean, note):
    """An unchanged input: it must pass. false_alarm is 1 if a checker reported a finding on it."""
    return {"fault": fault, "case": "control: " + case, "control": True, "false_alarm": 0 if clean else 1, "basis": "verified", "note": note}


def fault1(work):
    rows = []
    held = os.path.join(KEPT, "head.json")
    full = VC.run(copy_ledger(os.path.join(work, "f1_full")), held=[held])
    N = full["copy"]["rebuilt_through"]
    rows.append(control(1, "the whole copy, held head", full["ok"], "n = %d" % N))
    det_a, det_b, clean_c, codes = 0, 0, 0, []
    ks = range(1, 11)
    for k in ks:
        d = copy_ledger(os.path.join(work, "f1_k%d" % k), upto=N - k)
        a = VC.run(d, held=[held])
        b = VC.run(d)
        det_a += 0 if a["ok"] else 1
        det_b += 0 if b["ok"] else 1
        codes += [f["what"] for f in a["findings"] + b["findings"]]
        ents = SV.load_entries(d)
        dig, ch = SV.check_digests(d, ents), SV.check_chain(d, ents)
        clean_c += 1 if (not dig["failed"] and ch["broken_at"] is None and all(r["result"] in ("match", "beyond_rebuilt_range") for r in ch["stamped_heads"])) else 0
    rows.append(row(1, "a. truncated, held head given", len(ks), det_a, "verified", "verify_chain.run(held=[kept/head.json])", codes))
    rows.append(row(1, "b. truncated, no held head", len(ks), det_b, "verified", "verify_chain.run() with the copy alone"))
    rows.append(row(1, "c. survive drill, no held head", len(ks), len(ks) - clean_c, "expected",
                    "digests and chain clean on %d of %d copies (run here); the drill would also check Bitcoin anchors through "
                    "two block explorers (not run, no network), and with them passing its outcome is rebuilt" % (clean_c, len(ks))))
    return rows


def fork_copy(dst, p):
    d = copy_ledger(dst)
    rawp, jp = os.path.join(d, "ledger", "%d.raw" % p), os.path.join(d, "ledger", "%d.json" % p)
    raw = open(rawp, "rb").read() + b"\n"
    open(rawp, "wb").write(raw)
    e = json.load(open(jp, encoding="utf-8"))
    e["claim_sha256"] = hashlib.sha256(raw).hexdigest()
    write_json(jp, e)
    return d, e["claim_sha256"]


def fault2(work):
    rows = []
    gen = VC.run(copy_ledger(os.path.join(work, "f2_gen")))
    N, H = gen["copy"]["rebuilt_through"], gen["copy"]["head"]
    gen_head = write_json(os.path.join(work, "f2_gen_head.json"), head_doc(N, H))
    man = json.load(open(os.path.join(KEPT, "manifest.json"), encoding="utf-8"))
    gen_csha = MR.content_digests(man)[0]
    ctl = VC.run(os.path.join(work, "f2_gen"), head=gen_head)
    rows.append(control(2, "genuine copy and its head", ctl["ok"], "verify_chain.run(head=genuine head)"))
    ps = [N, N - 1, N - 7, N - 17, N - 37]
    a = b = c = 0
    ca, cb = [], []
    for p in ps:
        d, claim = fork_copy(os.path.join(work, "f2_p%d" % p), p)
        fr = VC.run(d)
        fhead = write_json(os.path.join(work, "f2_p%d_head.json" % p), head_doc(N, fr["copy"]["head"]))
        ra = VC.run(d, head=fhead)
        a += 0 if ra["ok"] else 1
        ca += [f["what"] for f in ra["findings"]]
        rb = VC.run(os.path.join(work, "f2_gen"), held=[fhead])
        b += 0 if rb["ok"] else 1
        cb += [f["what"] for f in rb["findings"]]
        fm = copy.deepcopy(man)
        for e in fm["entries"]:
            if e.get("n") == p:
                e["claim_sha256"] = claim
        c += 1 if MR.content_digests(fm)[0] != gen_csha else 0
    rows.append(row(2, "a. one reader, forked copy and its own head", len(ps), a, "verified",
                    "verify_chain.run(head=forked head.json); a fork below a head stamped inside a later entry breaks that stamp", ca))
    rows.append(row(2, "b. two readers, forked head held against the genuine copy", len(ps), b, "verified", "verify_chain.run(held=[forked head])", cb))
    rows.append(row(2, "c. two mirrors, content_sha256 compared", len(ps), c, "verified", "mirror.content_digests over kept/manifest.json and the forked manifest"))
    return rows


def settle_env():
    sys.path.insert(0, os.path.join(NENRIN, "musubi-v0", "settle-core-v0"))
    import gen_vectors as G
    return G


def judged(G, events, view):
    s = G.s16.settle_v1_16(G.BASE, events, view)
    c = G.core_fields(s)
    return c, (c["verdict"] == "within_grant" and c["status"] == "final" and len(c["event_set"]) == len(events))


def fault3(G, work):
    rows = []
    ch = G.Chain()
    recs = [ch.put(G.ex(G.BASE, extra={"nenrin_ref": hashlib.sha256(("tools/bench fault anchor %d" % i).encode()).hexdigest()})) for i in range(5)]
    ch.pad(G.DEPTH)
    view = ch.view()
    _, ok = judged(G, recs, view)
    rows.append(control(3, "5 records in 5 blocks, own anchors", ok, "within_grant, final, 5 accepted"))
    det, codes = 0, []
    for i in range(5):
        ev = copy.deepcopy(recs)
        ev[i]["anchor"] = copy.deepcopy(recs[(i + 1) % 5]["anchor"])
        c, ok = judged(G, ev, view)
        det += 0 if ok else 1
        codes += c["underspecified_reasons"] + c["deviation_codes"] + sorted(set(c["dispositions"].values()) - {"accepted"})
    rows.append(row(3, "a. anchor of another record in another block", 5, det, "verified", "settle_v1_16", codes))
    det = 0
    for later in (1, 3, 10):
        ch2 = G.Chain()
        r = G.ex(G.BASE, extra={"nenrin_ref": hashlib.sha256(b"tools/bench fault reanchor").hexdigest()})
        ch2.put(r)
        ch2.pad(later - 1)
        again = ch2.put(r)
        ch2.pad(G.DEPTH)
        _, ok = judged(G, [again], ch2.view())
        det += 0 if ok else 1
    rows.append(row(3, "b. same body anchored again %s blocks later, only the later copy" % "1, 3, 10", 3, det, "verified",
                    "a valid anchor at a later height; by construction nothing in the record says it was anchored earlier"))
    ents = SV.load_entries(KEPT)
    pairs = [(n, n + 1) for n in (1, 30, 60, 90, 120)]
    d = copy_ledger(os.path.join(work, "f3_ots"))
    det, codes, passed_digest = 0, [], 0
    for x, y in pairs:
        px, py = os.path.join(d, "ledger", "%d.ots" % x), os.path.join(d, "ledger", "%d.ots" % y)
        bx, by = open(px, "rb").read(), open(py, "rb").read()
        open(px, "wb").write(by)
        open(py, "wb").write(bx)
        try:
            an = SV.check_anchors(d, {x: ents[x]}, get=refuse_fetch)
            fails = [f["why"] for f in an["failed"]]
            det += 1 if fails else 0
            codes += fails
        except NoNetwork:
            passed_digest += 1
        open(px, "wb").write(bx)
        open(py, "wb").write(by)
    rows.append(row(3, "c. two .ots proofs swapped", len(pairs), det, "verified",
                    "survive.check_anchors with a fetcher that refuses; %d reached the fetch step" % passed_digest, codes))
    return rows


def fault4(G):
    rows = []
    ch = G.Chain()
    r = ch.put(G.ex(G.BASE, extra={"nenrin_ref": hashlib.sha256(b"tools/bench fault view").hexdigest()}))
    ch.pad(G.DEPTH - 1)
    hs = ch.view()["headers"]
    _, ok = judged(G, [r], {"headers": hs})
    rows.append(control(4, "anchor exactly final (tip = anchor + 5)", ok, "within_grant, final; removing only the header below the checkpoint also stays final, so it is not a try"))
    det, codes = 0, []
    for s in range(1, 9):
        c, ok = judged(G, [r], {"headers": hs[:-s]})
        det += 0 if ok else 1
        codes += [c["status"]] + c["underspecified_reasons"]
    rows.append(row(4, "a. top s headers removed, s = 1..8", 8, det, "verified", "status and reasons in codes", codes))
    det, codes = 0, []
    for s in (2, 3):
        c, ok = judged(G, [r], {"headers": hs[s:]})
        det += 0 if ok else 1
        codes += [c["status"]] + c["underspecified_reasons"]
    rows.append(row(4, "b. lowest s headers removed, s = 2..3 (the checkpoint goes)", 2, det, "verified", "the checkpoint is the second header", codes))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "hs-bench"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="faults-", dir=a.out)
    try:
        G = settle_env()
        rows = fault1(work) + fault2(work) + fault3(G, work) + fault4(G)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    text = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    out = {"rows": rows, "rows_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    if a.json:
        print(json.dumps(out, sort_keys=True, indent=1))
    else:
        for r in rows:
            if r.get("control"):
                print("%d  %-62s %s" % (r["fault"], r["case"], "passes clean" if not r["false_alarm"] else "FALSE ALARM"))
                continue
            print("%d  %-62s %2d tries  %2d detected  %2d missed  [%s]  %s" % (r["fault"], r["case"], r["tries"], r["detected"], r["missed"], r["basis"], ",".join(r["codes"])))
        print("rows_sha256 %s" % out["rows_sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
