#!/usr/bin/env python3
"""interop-v0.3/own-proto: the vectors that pin preimage coverage for an own "__proto__" wire key.

Each vector is a validly signed grant, receipt and intent (no observations). The base is accepted; the others add
ONE field after signing, without touching any digest or signature, so a conforming verifier (VERIFIER.md section 2:
every non-derived field, unknown fields included, stays in the preimage) recomputes a different id and refuses.
The field is either the own JSON key "__proto__" (which JSON.parse makes an own property, and which
Object.assign({}, rec) silently does not copy: pipavlo82, horizon-shield#29, 2026-10-15) or an ordinary unknown key
"audit_note" as the control. A verifier that keeps every own key gives the same signature for the pair.

Keys are derived at run time from public labels (sha256 of a label is the Ed25519 seed), so anyone regenerates the
same bytes and no key material is stored. They are test keys and protect nothing.

  python3 -I -B make_own_proto_vectors.py      (writes fixtures/*.json, expected.json and SHA256SUMS next to this file)
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "sdk-python", "src")))
from nenrin_verify import provenance as P  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TASK = "task_own_proto"
ACTION = {"tool": "a2a.invoke", "target": "/task", "args_sha256": "sha_args_ok"}
REF = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ADDED = {"audit_note": "not signed"}


def b58(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


class Party:
    def __init__(self, label):
        seed = hashlib.sha256(("nenrin interop-v0.3/own-proto test key: " + label).encode("utf-8")).digest()
        self.priv = Ed25519PrivateKey.from_private_bytes(seed)
        raw = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.id = "did:key:z" + b58(b"\xed\x01" + raw)

    def sign(self, obj):
        return base64.b64encode(self.priv.sign(P.canonical(obj).encode("utf-8"))).decode("ascii")


CALLER, PROVIDER = Party("caller"), Party("provider")


def grant():
    g = {"schema": "task-execution-bind-v0/grant", "task_id": TASK, "action": ACTION, "caller_id": CALLER.id,
         "provider_id": PROVIDER.id, "nonce": "n1", "not_before": "2026-10-15T00:00:00Z",
         "not_after": "2026-10-15T01:00:00Z"}
    g["grant_ref"] = P.grant_ref(g)
    g["caller_sig"] = CALLER.sign(P.grant_preimage(g))
    return g


def receipt(g):
    r = {"schema": "task-execution-bind-v0/receipt", "task_id": TASK, "grant_ref": g["grant_ref"],
         "executed_action": ACTION,
         "outcome": {"status": "completed", "result_sha256": "sha_res_1",
                     "evidence": {"kind": "ledger_record", "ref": REF, "system": "ledger.horizonshield.dev"}},
         "provider_id": PROVIDER.id, "executed_at": "2026-10-15T00:30:00Z"}
    r["receipt_id"] = P.receipt_id(r)
    r["provider_sig"] = PROVIDER.sign(P.receipt_preimage(r))
    return r


def intent(g):
    i = {"schema": "task-execution-bind-v0/intent", "task_id": TASK, "grant_ref": g["grant_ref"],
         "proposed_action": ACTION, "provider_id": PROVIDER.id, "declared_at": "2026-10-15T00:20:00Z"}
    i["intent_id"] = P.intent_id(i)
    i["intent_sig"] = PROVIDER.sign(P.intent_preimage(i))
    return i


def bundle():
    g = grant()
    return {"task_id": TASK, "grant": g, "receipt": receipt(g), "intent": intent(g)}


def added(slot, key):
    """The base bundle with {key: ADDED} appended to one record AFTER signing: no digest or signature changes."""
    b = bundle()
    b[slot] = dict(b[slot])
    b[slot][key] = dict(ADDED)
    return b


def cases():
    find = ["evidence_bound_unchecked", "no_delegation_observations"]
    g_ref = ["execution_invalid", "execution_signature_invalid", "preflight_invalid"]
    r_ref = ["execution_invalid", "execution_signature_invalid", "execution_unreconciled"]
    i_ref = ["preflight_invalid", "preflight_signature_invalid"]
    out = []

    def add(name, b, refusals, findings, intent_text):
        out.append((name, b, {"verdict": "refused" if refusals else "accepted",
                              "refusals": sorted(refusals), "findings": sorted(findings)}, intent_text))

    add("q00_base", bundle(), [], find,
        "the clean grant, receipt and intent every other vector changes by one added field: accepted")
    add("q01_own_proto_in_grant", added("grant", "__proto__"), g_ref, find,
        "the own JSON key \"__proto__\" added to the signed grant after signing. Section 2 keeps every non-derived "
        "field in the preimage, so grant_ref no longer recomputes (execution_invalid, grant_recompute_mismatch) and "
        "caller_sig no longer verifies over the full preimage (execution_signature_invalid); the intent names the "
        "grant by the stored grant_ref, which is no longer this grant's recomputed id (preflight_invalid, "
        "intent_unbound). A verifier whose copy of the record drops an own \"__proto__\" key (Object.assign) accepts")
    add("q02_own_proto_in_receipt", added("receipt", "__proto__"), r_ref, find,
        "the same key added to the signed receipt: receipt_id does not recompute (execution_invalid), provider_sig "
        "does not verify (execution_signature_invalid), and no authentic receipt is left to reconcile "
        "(execution_unreconciled)")
    add("q03_own_proto_in_intent", added("intent", "__proto__"), i_ref, find,
        "the same key added to the signed intent: intent_id does not recompute (preflight_invalid, "
        "intent_recompute_mismatch) and intent_sig does not verify (preflight_signature_invalid); the grant and "
        "receipt are untouched, so the execution step passes")
    add("q04_audit_note_in_grant", added("grant", "audit_note"), g_ref, find,
        "control: an ordinary unknown key \"audit_note\" added to the grant after signing. Same signature as q01; "
        "a verifier must not tell the two apart")
    add("q05_audit_note_in_receipt", added("receipt", "audit_note"), r_ref, find,
        "control: the same ordinary key added to the receipt. Same signature as q02")
    add("q06_audit_note_in_intent", added("intent", "audit_note"), i_ref, find,
        "control: the same ordinary key added to the intent. Same signature as q03")
    return out


def main():
    fx = os.path.join(HERE, "fixtures")
    os.makedirs(fx, exist_ok=True)
    exp = {"schema": "nenrin-interop-expected-v0",
           "version": "0.3.1",
           "frozen_from": "make_own_proto_vectors.py in this directory (deterministic: keys from public labels)",
           "verifier": "nenrin-provenance-verify-v0 (sdk/nenrin_verify.mjs; npm and PyPI nenrin-verify; Go nenrin-verify-go)",
           "note": "the canonical verdict signature each fixture must reproduce: verdict, sorted refusal codes, sorted "
                   "finding codes. q01 to q03 add the own JSON key \"__proto__\" to one signed record after signing; "
                   "q04 to q06 add an ordinary unknown key the same way and must give the same signature",
           "cases": {}}
    sums = []
    for name, b, expect, intent_text in cases():
        path = os.path.join(fx, name + ".json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(b, f, indent=2, ensure_ascii=False)
            f.write("\n")
        exp["cases"][name] = {"intent": intent_text, "task_id": TASK, "expect": expect}
        sums.append((hashlib.sha256(open(path, "rb").read()).hexdigest(), "fixtures/" + name + ".json"))
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(exp, f, indent=2, ensure_ascii=False)
        f.write("\n")
    sums.insert(0, (hashlib.sha256(open(os.path.join(HERE, "expected.json"), "rb").read()).hexdigest(), "expected.json"))
    with open(os.path.join(HERE, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as f:
        for h, n in sums:
            f.write(h + "  " + n + "\n")
    print("wrote %d vectors" % len(exp["cases"]))


if __name__ == "__main__":
    main()
