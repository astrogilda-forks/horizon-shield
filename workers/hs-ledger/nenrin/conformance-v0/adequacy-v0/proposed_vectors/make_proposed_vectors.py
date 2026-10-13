#!/usr/bin/env python3
"""PROPOSALS, not part of any frozen corpus: the smallest new vector for each fault the frozen corpora cannot see.

Each vector is a validly signed grant and receipt (no observations, no intent) changed in one place. The intended
verdict signature below is written from VERIFIER.md by hand, not copied from a verifier run; run_adequacy.py then
checks that the unmutated Python port and the published JS reference both give it, and that the fault each vector
targets gives something else.

Keys are derived at run time from public labels (sha256 of a label is the Ed25519 seed), so anyone regenerates the
same bytes and no key material is stored. They are test keys and protect nothing.

  python3 -I -B make_proposed_vectors.py      (writes fixtures/*.json and expected.json next to this file)
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "..", "sdk-python", "src")))
from nenrin_verify import provenance as P  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TASK = "task_adequacy_proposal"
ACTION = {"tool": "a2a.invoke", "target": "/task", "args_sha256": "sha_args_ok"}
REF = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def b58(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


class Party:
    def __init__(self, label):
        seed = hashlib.sha256(("nenrin adequacy-v0 proposal test key: " + label).encode("utf-8")).digest()
        self.priv = Ed25519PrivateKey.from_private_bytes(seed)
        raw = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.id = "did:key:z" + b58(b"\xed\x01" + raw)

    def sign(self, obj):
        return base64.b64encode(self.priv.sign(P.canonical(obj).encode("utf-8"))).decode("ascii")


CALLER, PROVIDER, OTHER = Party("caller"), Party("provider"), Party("other provider")


def grant(**o):
    g = {"schema": "task-execution-bind-v0/grant", "task_id": TASK, "action": ACTION, "caller_id": CALLER.id,
         "provider_id": PROVIDER.id, "nonce": "n1", "not_before": "2026-10-04T00:00:00Z",
         "not_after": "2026-10-04T01:00:00Z"}
    g.update(o)
    g["grant_ref"] = P.grant_ref(g)
    g["caller_sig"] = CALLER.sign(P.grant_preimage(g))
    return g


def receipt(g, signer=PROVIDER, **o):
    r = {"schema": "task-execution-bind-v0/receipt", "task_id": TASK, "grant_ref": g["grant_ref"],
         "executed_action": ACTION,
         "outcome": {"status": "completed", "result_sha256": "sha_res_1",
                     "evidence": {"kind": "ledger_record", "ref": REF, "system": "ledger.horizonshield.dev"}},
         "provider_id": signer.id, "executed_at": "2026-10-04T00:30:00Z"}
    r.update(o)
    r["receipt_id"] = P.receipt_id(r)
    r["provider_sig"] = signer.sign(P.receipt_preimage(r))
    return r


def flip_sig(s):
    """One bit of the signature flipped, written again in canonical standard base64."""
    b = bytearray(base64.b64decode(s))
    b[10] ^= 0x01
    return base64.b64encode(bytes(b)).decode("ascii")


def bundle(g, r):
    return {"task_id": TASK, "grant": g, "receipt": r}


def cases():
    out = []

    def add(name, targets, b, refusals, findings, intent):
        out.append((name, targets, b, {"verdict": "refused" if refusals else "accepted",
                                       "refusals": sorted(refusals), "findings": sorted(findings)}, intent))
    base_find = ["evidence_bound_unchecked", "no_delegation_observations"]

    g = grant()
    add("p00_base", [], bundle(g, receipt(g)), [], base_find,
        "the clean pair every proposal changes in one place: accepted")

    g = grant()
    g["caller_sig"] = flip_sig(g["caller_sig"])
    add("p01_caller_sig_bit_flipped", ["F1"], bundle(g, receipt(g)), ["execution_signature_invalid"], base_find,
        "step 2b: the grant's caller_sig has one bit flipped (still canonical base64), so it does not verify: "
        "execution_signature_invalid (reason caller_sig_invalid). Nothing else changes and the receipt reconciles")

    g = grant()
    g["caller_sig"] = PROVIDER.sign(P.grant_preimage(g))
    add("p02_grant_signed_by_provider_key", ["F1", "F3"], bundle(g, receipt(g)), ["execution_signature_invalid"],
        base_find,
        "step 2b: the grant is signed with the provider's key, not with the key of grant.caller_id: "
        "execution_signature_invalid (caller_sig_invalid). A verifier that tries the keys of every party accepts it")

    g = grant()
    r = receipt(g)
    g["grant_ref"] = "f" * 64
    add("p03_grant_ref_not_recomputing", ["F6a"], bundle(g, r), ["execution_invalid", "execution_unreconciled"],
        base_find,
        "step 2a: grant.grant_ref is not the recomputed id (it is outside the signed preimage, so caller_sig still "
        "verifies): execution_invalid (grant_recompute_mismatch). The receipt names the recomputed id, so 2d finds "
        "no receipt for the stored grant_ref: execution_unreconciled")

    g = grant()
    r = receipt(g)
    r["receipt_id"] = "e" * 64
    add("p04_receipt_id_not_recomputing", ["F6b"], bundle(g, r), ["execution_invalid", "execution_unreconciled"],
        base_find,
        "step 2a: receipt.receipt_id is not the recomputed id (outside the signed preimage, provider_sig still "
        "verifies): execution_invalid (receipt_recompute_mismatch); 2d: the receipt is not authentic without a "
        "recomputing receipt_id: execution_unreconciled")

    g = grant()
    r = receipt(g, grant_ref="d" * 64)
    add("p05_receipt_names_other_grant", ["F6c"], bundle(g, r), ["execution_invalid", "execution_unreconciled"],
        base_find,
        "step 2a: the receipt, validly signed, names a grant_ref other than this grant's: execution_invalid "
        "(receipt_unbound); 2d: no receipt for this grant: execution_unreconciled")

    g = grant()
    add("p06_hour_24_inside_window", ["F7"], bundle(g, receipt(g, executed_at="2026-10-03T24:00:00Z")),
        ["execution_invalid"], base_find,
        "step 2a, section 5: executed_at 2026-10-03T24:00:00Z is not a strict RFC3339 instant (hour 24): "
        "execution_invalid (invalid_timestamp). Date.parse reads it as 2026-10-04T00:00:00Z, which is inside the "
        "window, so a verifier without the strict check accepts")

    g = grant()
    add("p07_executed_after_not_after", ["F4", "F4b"], bundle(g, receipt(g, executed_at="2026-10-04T01:00:01Z")),
        ["execution_invalid"], base_find,
        "step 2a: executed_at is one second after not_after: execution_invalid (outside_authorization_window)")

    g = grant()
    add("p08_receipt_from_unauthorized_provider", ["F10"], bundle(g, receipt(g, signer=OTHER)),
        ["execution_invalid", "execution_unreconciled"], base_find,
        "step 2a: the receipt is validly signed by a provider other than grant.provider_id: execution_invalid "
        "(provider_not_authorized); 2d: no receipt from the authorized provider: execution_unreconciled")
    return out


def main():
    fx = os.path.join(HERE, "fixtures")
    os.makedirs(fx, exist_ok=True)
    exp = {"schema": "nenrin-interop-expected-v0",
           "status": "PROPOSAL: not part of any frozen corpus (not interop-v0*, not conformance-v0/pinned); "
                     "written by the adequacy-v0 measurement to show what would kill each surviving fault",
           "verifier": "nenrin-provenance-verify-v0 (sdk/nenrin_verify.mjs and the PyPI port)",
           "note": "verdict signature: verdict, sorted refusal codes, sorted finding codes. targets names the "
                   "declared faults in ../mutations.json this vector is meant to kill",
           "cases": {}}
    for name, targets, b, expect, intent in cases():
        with open(os.path.join(fx, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(b, f, indent=2, ensure_ascii=False)
            f.write("\n")
        exp["cases"][name] = {"intent": intent, "targets": targets, "task_id": TASK, "expect": expect}
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(exp, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote %d proposed vectors" % len(exp["cases"]))


if __name__ == "__main__":
    main()
