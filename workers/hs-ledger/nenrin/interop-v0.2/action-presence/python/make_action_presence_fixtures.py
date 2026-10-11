#!/usr/bin/env python3
"""Build the interop-v0.2/action-presence corpus.

Nine fixtures for the rule VERIFIER.md section 5 settles as "a missing, null, false, 0 or
'' action fails E1 on its own" -- one per shape the sentence names (missing, null, false, 0,
''), plus the boundary case where the value is an empty object and is therefore not
degenerate. Three more reach the same rule through the intent's proposed_action (step 3) and
the declared-versus-executed comparison: two with a degenerate value, one with the key
absent.

Every fixture is freshly signed with keys generated here, and is valid except for the value
under test, so only that rule can refuse it. The expected verdict signatures come from
verify_edge.py in this directory (the independent Python implementation, with the section 5
degenerate-action rule applied); see INTEROP.md for the reference's agreement.

usage: make_action_presence_fixtures.py <out_dir>
"""
import base64
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify_edge import (  # noqa: E402
    GRANT_DERIVED, INTENT_DERIVED, OBS_DERIVED, RECEIPT_DERIVED, cbytes, digest,
    verify, without,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TASK = "task_action_presence"
GOOD_EVIDENCE = {"kind": "ledger_record", "ref": "ab" * 32,
                 "system": "action-presence.example"}
ACTION = {"tool": "a2a.invoke", "target": "/task", "args_sha256": "sha_args_ok"}


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


class Party:
    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        raw = self.sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.did = "did:key:z" + b58encode(b"\xed\x01" + raw)

    def sign(self, obj) -> str:
        return base64.b64encode(self.sk.sign(cbytes(obj))).decode("ascii")


class Case:
    """One bundle under construction, with its own parties."""

    def __init__(self, task=TASK):
        self.task = task
        self.caller, self.provider = Party(), Party()
        self.witnesses = [Party() for _ in range(4)]

    def grant(self, action=ACTION):
        g = {"schema": "task-execution-bind-v0/grant", "task_id": self.task,
             "action": copy.deepcopy(action),
             "caller_id": self.caller.did, "provider_id": self.provider.did,
             "nonce": "n-action-presence-1",
             "not_before": "2026-10-04T00:00:00Z",
             "not_after": "2026-10-04T01:00:00Z"}
        g["grant_ref"] = digest(without(g, GRANT_DERIVED))
        g["caller_sig"] = self.caller.sign(without(g, GRANT_DERIVED))
        return g

    def receipt(self, g, executed_action=ACTION):
        r = {"schema": "task-execution-bind-v0/receipt", "task_id": self.task,
             "grant_ref": g["grant_ref"],
             "executed_action": copy.deepcopy(executed_action),
             "outcome": {"status": "completed", "result_sha256": "sha_res_1",
                         "evidence": copy.deepcopy(GOOD_EVIDENCE)},
             "provider_id": self.provider.did,
             "executed_at": "2026-10-04T00:30:00Z"}
        r["receipt_id"] = digest(without(r, RECEIPT_DERIVED))
        r["provider_sig"] = self.provider.sign(without(r, RECEIPT_DERIVED))
        return r

    def intent(self, g, proposed_action):
        i = {"schema": "task-execution-bind-v0/intent", "task_id": self.task,
             "grant_ref": g["grant_ref"],
             "proposed_action": copy.deepcopy(proposed_action),
             "provider_id": self.provider.did,
             "declared_at": "2026-10-04T00:20:00Z"}
        i["intent_id"] = digest(without(i, INTENT_DERIVED))
        i["intent_sig"] = self.provider.sign(without(i, INTENT_DERIVED))
        return i

    def obs(self, seq, prev, witness=0, link=None):
        w = self.witnesses[witness]
        o = {"task_id": self.task,
             "hop": {"seq": seq, "from": self.caller.did, "to": self.provider.did},
             "prev_evidence_id": prev,
             "conduct": {"verdict": "ok"},
             "witness_id": w.did,
             "observed_at": "2026-10-04T00:10:00Z"}
        if link is not None:
            o["conduct"]["detail_ref"] = link
        o["evidence_id"] = digest(without(o, OBS_DERIVED))
        o["witness_sig"] = w.sign(without(o, OBS_DERIVED))
        o["edge_sig"] = self.caller.sign(
            {"task_id": o.get("task_id"), "hop": o["hop"]})
        return o

    def walk(self, r, o0=None):
        link = "nenrin-exec://" + r["receipt_id"]
        o0 = o0 or self.obs(0, None, link=link)
        o1 = self.obs(1, o0["evidence_id"], witness=1, link=link)
        return [o0, o1]


def cases():
    out = {}

    # ---- the five degenerate/control values on E1 -------------------------
    variants = (
        ("action_null", None,
         "grant.action = receipt.executed_action = null: a degenerate value fails E1 on its "
         "own, so agreeing on null is not agreement; refused"),
        ("action_zero", 0,
         "the same with 0 on both sides (0 is in the section's list); refused"),
        ("action_empty_string", "",
         "the same with the empty string on both sides; refused"),
        ("action_false", False,
         "the same with false on both sides; refused"),
        ("action_empty_object_accepted", {},
         "the boundary: {} is not in the section's list, so it is compared like any other "
         "action and {} against {} passes E1; accepted"),
    )
    for name, value, intent in variants:
        c = Case()
        g = c.grant()
        r = c.receipt(g, executed_action=value)
        g["action"] = copy.deepcopy(value)
        g["grant_ref"] = digest(without(g, GRANT_DERIVED))
        g["caller_sig"] = c.caller.sign(without(g, GRANT_DERIVED))
        r["grant_ref"] = g["grant_ref"]
        r["executed_action"] = copy.deepcopy(value)
        r["receipt_id"] = digest(without(r, RECEIPT_DERIVED))
        r["provider_sig"] = c.provider.sign(without(r, RECEIPT_DERIVED))
        out[name] = (intent, {"task_id": TASK, "observations": c.walk(r),
                              "grant": g, "receipt": r})

    # ---- the same degenerate value reaching step 3 and the finding --------
    for name, value, intent in (
        ("intent_action_null", None,
         "grant.action is an action, the intent's proposed_action and the receipt's "
         "executed_action are null: E1 refuses, the preflight action check refuses, and the "
         "declared-versus-executed comparison reports a divergence; refused"),
        ("intent_action_zero", 0,
         "the same with 0 for both; refused"),
    ):
        c = Case()
        g = c.grant()
        r = c.receipt(g, executed_action=value)
        bundle = {"task_id": TASK, "observations": c.walk(r), "grant": g, "receipt": r,
                  "intent": c.intent(g, value)}
        out[name] = (intent, bundle)

    # ---- the shape the section names first: the key is absent ------------
    c = Case()
    g = c.grant()
    r = c.receipt(g)
    del g["action"]
    g["grant_ref"] = digest(without(g, GRANT_DERIVED))
    g["caller_sig"] = c.caller.sign(without(g, GRANT_DERIVED))
    r["grant_ref"] = g["grant_ref"]
    del r["executed_action"]
    r["receipt_id"] = digest(without(r, RECEIPT_DERIVED))
    r["provider_sig"] = c.provider.sign(without(r, RECEIPT_DERIVED))
    out["action_missing"] = (
        "grant.action and receipt.executed_action are both absent (the shape the section "
        "names first): both sides are missing, so equality would hold, but the key's absence "
        "fails E1 on its own; refused",
        {"task_id": TASK, "observations": c.walk(r), "grant": g, "receipt": r})

    c = Case()
    g = c.grant()
    r = c.receipt(g)
    del r["executed_action"]
    r["receipt_id"] = digest(without(r, RECEIPT_DERIVED))
    r["provider_sig"] = c.provider.sign(without(r, RECEIPT_DERIVED))
    i = c.intent(g, ACTION)
    del i["proposed_action"]
    i["intent_id"] = digest(without(i, INTENT_DERIVED))
    i["intent_sig"] = c.provider.sign(without(i, INTENT_DERIVED))
    out["intent_action_missing"] = (
        "grant.action is an action, the intent's proposed_action and the receipt's "
        "executed_action are both absent: E1 refuses, the preflight action check refuses, "
        "and the declared-versus-executed comparison reports a divergence; refused",
        {"task_id": TASK, "observations": c.walk(r), "grant": g, "receipt": r, "intent": i})

    return out


def main():
    out_dir = Path(sys.argv[1]).resolve()
    (out_dir / "fixtures").mkdir(parents=True, exist_ok=True)
    built = cases()
    expected = {
        "schema": "nenrin-interop-expected-v0",
        "version": "0.1.0",
        "verifier": "independent Python implementation (verify_edge.py), written from "
                    "VERIFIER.md; the reference was not read",
        "note": "the canonical verdict signature each fixture must reproduce: verdict, "
                "sorted refusal codes, sorted finding codes.",
        "cases": {},
    }
    for name, (intent, bundle) in built.items():
        (out_dir / "fixtures" / f"{name}.json").write_text(
            json.dumps(bundle, indent=2, sort_keys=False) + "\n")
        sig = verify(bundle).signature()
        expected["cases"][name] = {
            "intent": intent,
            "task_id": bundle.get("task_id"),
            "expect": {"verdict": sig["verdict"],
                       "refusals": sig["refusals"],
                       "findings": sig["findings"]},
        }
        print(f"{name:<30} {sig['verdict']:<9} refusals={sig['refusals']} "
              f"findings={sig['findings']}")
    (out_dir / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(f"\n{len(built)} fixtures -> {out_dir}")


if __name__ == "__main__":
    main()
