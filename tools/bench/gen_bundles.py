#!/usr/bin/env python3
"""gen_bundles.py: write N NENRIN provenance bundles, one per line (JSONL), the same bytes on every run.

    python3 tools/bench/gen_bundles.py --n 10000 --keys reuse7 --out /tmp/hs-bench
    python3 tools/bench/gen_bundles.py --n 10000 --keys per-bundle --out /tmp/hs-bench

Nothing here is random. Every Ed25519 seed is sha256 of a public phrase (the way
workers/hs-ledger/nenrin/sdk-python/tests/fixtures/make_fixtures.mjs derives its keys), every timestamp and nonce
is fixed, and Ed25519 signing is deterministic (RFC 8032), so the file has the same sha256 on any machine.
The seeds are derived in memory and never written; the bundles carry public keys (did:key) and signatures only.

Two key modes, because the verifiers cache the result of the Ed25519 key check (JavaScript and Python keep at most
4,096 keys, Go keeps every key), so the number of distinct keys changes what is being timed:
  reuse7      seven keys (A, B, C, W1, W2, W3, X) shared by every bundle
  per-bundle  every bundle has its own keys (A, B, C, W1, W2, W3 derived from the phrase and the bundle number), so
              no two bundles share a key and the key check runs for every key of every bundle

Ten bundle shapes, by bundle number modulo 10 (each bundle has its own task_id, so no two lines are equal):
  0-6 full     grant, receipt, two witnessed hops (accepted)
  7   tampered receipt outcome changed after the provider signed it (refused)
  8   disagree a third observation by W3 with verdict fail on hop 0 (witness disagreement)
  9   late     receipt executed after the grant window (refused)

Prints one JSON line: path, count, bytes, sha256 of the file.
Run with the repository's own nenrin_verify (sdk-python/src), not an installed copy.
"""
import argparse, base64, hashlib, json, os, sys, tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
NENRIN = os.path.join(REPO, "workers", "hs-ledger", "nenrin")
sys.path.insert(0, os.path.join(NENRIN, "sdk-python", "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from nenrin_verify import provenance as P  # noqa: E402

PHRASE = "horizon-shield tools/bench provenance bundle seed "
NB, NA, IN, LATE = "2026-09-18T00:00:00Z", "2026-09-18T01:00:00Z", "2026-09-18T00:30:00Z", "2026-09-18T02:00:00Z"
REF = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ACTION = {"tool": "a2a.invoke", "target": "/invoices/pay", "args_sha256": "sha_args_ok"}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SHAPES = ["full"] * 7 + ["tampered", "disagree", "late"]


def b58(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


class Signer(object):
    def __init__(self, label):
        self.k = Ed25519PrivateKey.from_private_bytes(hashlib.sha256((PHRASE + label).encode("utf-8")).digest())
        raw = self.k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.did = "did:key:z" + b58(b"\xed\x01" + raw)

    def sign(self, value):
        return base64.b64encode(self.k.sign(P.canonical(value).encode("utf-8"))).decode("ascii")


ROLES = ("A", "B", "C", "W1", "W2", "W3")
_SHARED = {}


def signers(mode, i):
    if mode == "reuse7":
        if not _SHARED:
            for r in ROLES + ("X",):
                _SHARED[r] = Signer(r)
        return _SHARED
    return {r: Signer("%d/%s" % (i, r)) for r in ROLES}


def obs(K, task, seq, frm, to, witness, verdict="pass", prev=None, detail_ref=None):
    o = {"task_id": task, "hop": {"seq": seq, "from": K[frm].did, "to": K[to].did}, "prev_evidence_id": prev,
         "conduct": {"verdict": verdict, "detail_ref": detail_ref}, "witness_id": K[witness].did, "observed_at": IN}
    o["evidence_id"] = P.evidence_id(o)
    o["witness_sig"] = K[witness].sign(P.preimage(o))
    o["edge_sig"] = K[frm].sign({"task_id": o["task_id"], "hop": o["hop"]})
    return o


def bundle(mode, i):
    K = signers(mode, i)
    shape = SHAPES[i % 10]
    task = "task_bench_%07d" % i
    g = {"schema": "task-execution-bind-v0/grant", "task_id": task, "action": dict(ACTION), "caller_id": K["A"].did,
         "provider_id": K["B"].did, "nonce": "n%d" % i, "not_before": NB, "not_after": NA}
    g["grant_ref"] = P.grant_ref(g)
    g["caller_sig"] = K["A"].sign(P.grant_preimage(g))
    r = {"schema": "task-execution-bind-v0/receipt", "task_id": task, "grant_ref": g["grant_ref"], "executed_action": dict(ACTION),
         "outcome": {"status": "completed", "result_sha256": "sha_res_%d" % i, "evidence": {"kind": "ledger_record", "ref": REF, "system": "ledger.horizonshield.dev"}},
         "provider_id": K["B"].did, "executed_at": LATE if shape == "late" else IN}
    r["receipt_id"] = P.receipt_id(r)
    r["provider_sig"] = K["B"].sign(P.receipt_preimage(r))
    if shape == "tampered":
        r["outcome"]["status"] = "failed"
    h0 = obs(K, task, 0, "A", "B", "W1", detail_ref="nenrin-exec://" + r["receipt_id"])
    h1 = obs(K, task, 1, "B", "C", "W2", prev=h0["evidence_id"])
    hops = [h0, h1]
    if shape == "disagree":
        hops = [h0, obs(K, task, 0, "A", "B", "W3", verdict="fail"), h1]
    b = {"task_id": task, "observations": hops, "grant": g, "receipt": r}
    if shape == "tampered":
        b["receipts"] = [r]
    return b


def write(n, mode, out):
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "bundles_%s_%d.jsonl" % (mode, n))
    h, size = hashlib.sha256(), 0
    with open(path, "wb") as f:
        for i in range(n):
            line = (json.dumps(bundle(mode, i), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            h.update(line)
            size += len(line)
            f.write(line)
    return {"path": path, "keys": mode, "count": n, "bytes": size, "sha256": h.hexdigest()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--keys", choices=("reuse7", "per-bundle"), default="reuse7")
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "hs-bench"))
    a = ap.parse_args(argv)
    print(json.dumps(write(a.n, a.keys, a.out), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
