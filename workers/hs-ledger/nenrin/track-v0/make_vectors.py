#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Builds vectors/: small mirror directories of signed admissions, each with the pins to read it under and the report
track.py gives (expected.json). Keys are derived from fixed labels and Ed25519 signatures are deterministic, so the
directory rebuilds byte for byte:  python3 make_vectors.py && git diff --exit-code vectors/"""
import base64, hashlib, json, os, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import track as T                                                    # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey   # noqa: E402
from cryptography.hazmat.primitives import serialization             # noqa: E402

OUT = os.path.join(HERE, "vectors")
A, B = "door-a.example", "door-b.example"
H0 = 972400


def key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"nenrin-track-v0 test key " + label.encode()).digest())


def pub_b64(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


KA, KB, KX = key("a"), key("b"), key("someone else")


def admission(dom, k, seq, prev, height, decision="admit", salt="", ku=None, name="test-door-v1"):
    rec = {"schema": "a2a-admission-v0", "admission_id": "%s:seq=%d:prev=%s" % (name, seq, prev),
           "relying_party": {"domain": dom, "key_url": ku or "https://%s/keys/door.json" % dom},
           "chain_view": {"height": height, "header_sha256": hashlib.sha256(b"h%d" % height).hexdigest()},
           "decision": decision, "reasons": [], "publication": "public"}
    if salt:
        rec["note"] = salt
    msg = T.CONTEXT + T.canonical(rec).encode("utf-8")
    rec["signatures"] = [{"domain": dom, "alg": "ed25519", "sig": base64.b64encode(k.sign(msg)).decode()}]
    return rec, hashlib.sha256(msg).hexdigest()


def chain(dom, k, n, start_h=H0, step=10, ku=None, name="test-door-v1"):
    out, prev = [], T.GENESIS
    for s in range(1, n + 1):
        rec, asha = admission(dom, k, s, prev, start_h + step * s, ku=ku, name=name)
        out.append(rec)
        prev = asha
    return out


class Mirror:
    def __init__(self, name):
        self.d = os.path.join(OUT, name)
        os.makedirs(os.path.join(self.d, "ledger"))
        os.makedirs(os.path.join(self.d, "objects"))
        self.n = 100

    def obj(self, rec=None, raw=None, name=None):
        b = raw if raw is not None else T.canonical(rec).encode("utf-8")
        sha = name or hashlib.sha256(b).hexdigest()
        with open(os.path.join(self.d, "objects", sha), "wb") as f:
            f.write(b)
        return sha

    def batch(self, shas, bitcoin_block, extra=()):
        self.n += 1
        recs = [{"canonical_sha256": s, "record_schema": "a2a-admission-v0", "verdict": "accepted", "verifier_version": "admission-intake 0.3.1"}
                for s in sorted(shas)] + list(extra)
        batch = {"schema": "nenrin-agreement-batch-v1", "anchored_at": "2026-10-21T00:30:00Z", "count": len(recs), "records": recs}
        rc = T.canonical(batch)
        e = {"n": self.n, "claim_sha256": hashlib.sha256(rc.encode()).hexdigest(), "record_canonical": rc,
             "ots_status": "confirmed" if bitcoin_block else "pending", "bitcoin_block": bitcoin_block}
        with open(os.path.join(self.d, "ledger", "%d.json" % self.n), "w", encoding="utf-8") as f:
            f.write(T.canonical(e))

    def pins(self, *doms):
        p = {A: pub_b64(KA), B: pub_b64(KB)}
        with open(os.path.join(self.d, "pins.json"), "w", encoding="utf-8") as f:
            f.write(T.canonical({"https://%s/keys/door.json" % d: p[d] for d in doms}))


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    cases = []

    m = Mirror("01_one_history")                       # four admissions, the last not yet on Bitcoin
    c = chain(A, KA, 4)
    s = [m.obj(r) for r in c]
    m.batch(s[:3], H0 + 60); m.batch(s[3:], None); m.pins(A)
    cases.append(("01_one_history", "one chain, three anchored in time and one waiting for its Bitcoin block"))

    m = Mirror("02_fork")                              # seq 3 signed twice
    c = chain(A, KA, 4)
    other, _ = admission(A, KA, 3, json.loads(json.dumps(c[2]))["admission_id"].split("prev=")[1], H0 + 30, decision="refuse")
    s = [m.obj(r) for r in c] + [m.obj(other)]
    m.batch(s, H0 + 80); m.pins(A)
    cases.append(("02_fork", "the door signed two admissions with seq 3"))

    m = Mirror("03_broken_link")                       # seq 3 names a prev that is not seq 2's
    c = chain(A, KA, 2)
    r3, a3 = admission(A, KA, 3, "ab" * 32, H0 + 30)
    r4, _ = admission(A, KA, 4, a3, H0 + 40)
    s = [m.obj(r) for r in c + [r3, r4]]
    m.batch(s, H0 + 80); m.pins(A)
    cases.append(("03_broken_link", "seq 3 does not follow seq 2"))

    m = Mirror("04_gap")                               # seq 2 never published
    c = chain(A, KA, 4)
    s = [m.obj(r) for i, r in enumerate(c) if i != 1]
    m.batch(s, H0 + 80); m.pins(A)
    cases.append(("04_gap", "seq 2 is not in this copy"))

    m = Mirror("05_anchored_late")                     # seq 4 surfaced long after its chain view
    c = chain(A, KA, 4)
    s = [m.obj(r) for r in c]
    m.batch(s[:3], H0 + 60); m.batch(s[3:], H0 + 40 + T.LATE_BLOCKS + 1); m.pins(A)
    cases.append(("05_anchored_late", "seq 4 was first anchored more than 576 blocks after the height it names"))

    m = Mirror("06_bad_signature")                     # seq 2 signed by another key under door A's name
    c = chain(A, KA, 3)
    forged, _ = admission(A, KX, 2, c[1]["admission_id"].split("prev=")[1], H0 + 20, salt="x")
    s = [m.obj(c[0]), m.obj(forged), m.obj(c[2])]
    m.batch(s, H0 + 80); m.pins(A)
    cases.append(("06_bad_signature", "an admission under door A's name that door A's key did not sign; it is left out and seq 2 is a gap"))

    m = Mirror("07_unpinned_and_unreadable")           # a door nobody pinned, a non-canonical copy, bytes under another name, a batch name with no bytes
    ca, cb = chain(A, KA, 2), chain(B, KB, 2)
    s = [m.obj(r) for r in ca + cb]
    loose = json.dumps(chain(A, KA, 3)[2], indent=1).encode()
    s.append(m.obj(raw=loose))
    s.append(m.obj(raw=b'{"schema":"a2a-admission-v0"}', name="cd" * 32))
    m.batch(s + ["ef" * 32], H0 + 80, extra=[{"canonical_sha256": "aa" * 32, "record_schema": "a2a-agreement-v1", "verdict": "accepted"}])
    m.pins(A)
    cases.append(("07_unpinned_and_unreadable", "door B is not pinned; a copy that is not canonical; bytes that are not what their name says; a name with no bytes"))

    m = Mirror("08_genesis")                           # seq 1 names a previous admission
    r1, a1 = admission(A, KA, 1, "11" * 32, H0 + 10)
    r2, _ = admission(A, KA, 2, a1, H0 + 20)
    s = [m.obj(r1), m.obj(r2)]
    m.batch(s, H0 + 80); m.pins(A, B)
    cases.append(("08_genesis", "seq 1 must name 64 zeros"))

    m = Mirror("09_two_doors_one_domain")             # two doors on one domain, as SHIKEN's and SEKI's: two chains, no fork
    k1, k2 = "https://%s/keys/first-door.json" % A, "https://%s/keys/second-door.json" % A
    s = [m.obj(r) for r in chain(A, KA, 3, ku=k1, name="first-door-v1") + chain(A, KB, 2, ku=k2, name="second-door-v1")]
    m.batch(s, H0 + 80)
    with open(os.path.join(m.d, "pins.json"), "w", encoding="utf-8") as f:
        f.write(T.canonical({k1: pub_b64(KA), k2: pub_b64(KB)}))
    cases.append(("09_two_doors_one_domain", "two doors share a domain with their own keys and names: each is its own chain"))

    m = Mirror("10_unchained")                         # a door whose admission_id is a UUID: counted, and judged for lateness only
    u1, _ = admission(A, KA, 1, T.GENESIS, H0 + 10, name="x")
    u1["admission_id"] = "5902f39a-a22c-4b00-8ee0-1e12efeea0cb"
    del u1["signatures"]
    u1["signatures"] = [{"domain": A, "alg": "ed25519", "sig": base64.b64encode(KA.sign(T.CONTEXT + T.canonical(u1).encode())).decode()}]
    u2 = json.loads(json.dumps(u1)); u2["admission_id"] = "62891158-9e65-4b7f-8df8-f8137342b4ea"; u2["chain_view"]["height"] = H0 + 20
    del u2["signatures"]
    u2["signatures"] = [{"domain": A, "alg": "ed25519", "sig": base64.b64encode(KA.sign(T.CONTEXT + T.canonical(u2).encode())).decode()}]
    s = [m.obj(u1), m.obj(u2)]
    m.batch(s[:1], H0 + 60); m.batch(s[1:], H0 + 20 + T.LATE_BLOCKS + 1); m.pins(A)
    cases.append(("10_unchained", "admission ids with no seq and prev: no chain to judge, and the second was anchored late"))

    index = []
    for name, why in cases:
        d = os.path.join(OUT, name)
        pins = T.parse_pins(["%s@%s" % (v, k) for k, v in sorted(json.load(open(os.path.join(d, "pins.json"))).items())])
        rep = T.track(d, pins)
        with open(os.path.join(d, "expected.json"), "w", encoding="utf-8") as f:
            f.write(T.canonical(rep) + "\n")
        index.append({"case": name, "why": why, "verdict": rep["verdict"], "report_sha256": rep["report_sha256"]})
    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(index, indent=1, ensure_ascii=False) + "\n")
    for x in index:
        print("%-28s %-12s %s" % (x["case"], x["verdict"], x["report_sha256"][:16]))


if __name__ == "__main__":
    main()
