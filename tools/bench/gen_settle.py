#!/usr/bin/env python3
"""gen_settle.py: one MUSUBI contract with N anchored executions and the header view that holds them, the same bytes on every run.

    python3 tools/bench/gen_settle.py --n 1000 --out /tmp/hs-bench

Built with the helpers of workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/gen_vectors.py, imported as a library
(importing it builds its vectors in memory and writes nothing): the synthetic contract BASE (synthetic parties whose
Ed25519 seeds are sha256 of a fixed label, regtest difficulty, finality depth 6, a bond), ex() for each execution
record, signed by the synthetic contractor, and Chain, which mines regtest headers with a fixed salt.

Execution i performs read (authorized) and cites nenrin_ref sha256("tools/bench settle execution <i>"), so every
record is a different body. Records go into blocks of --per-block (default 100), each anchored by a plain merkle
path, then the chain is padded by 6 empty blocks so every anchor is final.

Writes <out>/settle_<n>/{contract.json, view.json, events.jsonl} (canonical JSON, one record per line) and prints one
JSON line with the sha256 of each file and of the three together (sha256 over the three file sha256 hex strings
joined by newlines, in that order).
"""
import argparse, hashlib, json, os, sys, tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
SETTLE_CORE = os.path.join(REPO, "workers", "hs-ledger", "nenrin", "musubi-v0", "settle-core-v0")


def gv():
    sys.path.insert(0, SETTLE_CORE)
    import gen_vectors
    return gen_vectors


def build(n, per_block=100):
    G = gv()
    ch = G.Chain()
    events = []
    for b in range(0, n, per_block):
        recs = [G.ex(G.BASE, extra={"nenrin_ref": hashlib.sha256(("tools/bench settle execution %d" % i).encode()).hexdigest()})
                for i in range(b, min(n, b + per_block))]
        put = ch.put(*recs)
        events += put if isinstance(put, list) else [put]
    ch.pad(G.DEPTH)
    return G, G.BASE, events, ch.view()


def write(n, out, per_block=100):
    G, contract, events, view = build(n, per_block)
    d = os.path.join(out, "settle_%d" % n)
    os.makedirs(d, exist_ok=True)
    files = {"contract.json": G.canonical(contract), "view.json": G.canonical(view),
             "events.jsonl": "".join(G.canonical(e) + "\n" for e in events)}
    shas = {}
    for name in ("contract.json", "view.json", "events.jsonl"):
        b = files[name].encode("utf-8")
        with open(os.path.join(d, name), "wb") as f:
            f.write(b)
        shas[name] = hashlib.sha256(b).hexdigest()
    combined = hashlib.sha256("\n".join(shas[k] for k in ("contract.json", "view.json", "events.jsonl")).encode("ascii")).hexdigest()
    return {"dir": d, "executions": len(events), "headers": len(view["headers"]), "files_sha256": shas, "input_sha256": combined,
            "bytes": sum(len(v.encode("utf-8")) for v in files.values())}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--per-block", type=int, default=100)
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "hs-bench"))
    a = ap.parse_args(argv)
    print(json.dumps(write(a.n, a.out, a.per_block), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
