#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rebuild vectors/vectors.json byte for byte: python3 gen_vectors.py (needs agentrust-trace==0.11.0).

Every key is derived from a fixed label, every TRACE authorization is signed by agentrust-trace's own
sign_bridge, and the Trust Records are two real ones copied unchanged from agentrust-io/trace-registry
(the summit demo record signed by its registered producer key, and Bernstein 3.20.0's) plus records
agentrust-trace's own sign_record signs here. Every expectation below is written by hand from SPEC.md,
not copied from the evaluator's output.
"""
import base64
import calendar
import copy
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import trace_terms_v0 as T  # noqa: E402
import contract_v0 as C  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from agentrust_trace import intent_bridge as IB  # noqa: E402
from agentrust_trace.sign import sign_record, key_to_jwk, jwk_thumbprint  # noqa: E402

SRC = os.path.join(HERE, "..", "trace-bind-v0", "sources")


def key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("trace-terms-v0 test key: " + label).encode()).digest())


def pub_b64(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)).decode()


def jwk_with_kid(k, kid):
    j = dict(key_to_jwk(k))
    j["kid"] = kid
    return j


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


SUMMIT = load(os.path.join(SRC, "summit-demo-record.json"))
BERNSTEIN = load(os.path.join(SRC, "bernstein-3.20.0-20260920-165918-backend-99365805.json"))["trace"]
SUMMIT_THUMB = jwk_thumbprint(SUMMIT["cnf"]["jwk"])
BERNSTEIN_THUMB = jwk_thumbprint(BERNSTEIN["cnf"]["jwk"])

PRINCIPAL, CONTRACTOR = key("principal"), key("contractor")
AUTHORIZER, STRANGER_AUTH = key("authorizer"), key("an authorizer nobody agreed to")
OUTSIDER = key("someone who is not the contractor")
LIB_PRODUCER = key("a runtime signing with agentrust-trace sign_record")
AUTH_JWK = jwk_with_kid(AUTHORIZER, "auth-1")
STRANGER_JWK = jwk_with_kid(STRANGER_AUTH, "auth-1")  # same kid, other key: the thumbprint decides
P_DOM, C_DOM = "principal.example", "contractor.example"

TOOLS = {"estimate.report": "report", "estimate.audit": "audit", "estimate.compare": "compare",
         "estimate.export": "export"}


AGREED_AT = "2026-08-01T00:00:00Z"  # before every act in the vectors: the summit record is from 2026-08-20


def make_contract(grant_extra=None, requirements=None, contract_id="7e5c0a1d2b3c4d5e6f708192a3b4c5d6",
                  expiry=None, parent=None):
    grant = {"authorized_actions": ["report", "audit"], "prohibited_actions": ["compare"], "conditional": [],
             "delegation": {"allowed": []}, "privacy": "public_record", "revocation": {"effective_at": "anchor"},
             "witnesses": []}
    grant.update(grant_extra or {})
    rec = C.build_contract(
        {"domain": P_DOM, "key_url": "https://principal.example/keys/principal.json",
         "public_key_ed25519_b64": pub_b64(PRINCIPAL)},
        {"domain": C_DOM, "key_url": "https://contractor.example/keys/contractor.json",
         "public_key_ed25519_b64": pub_b64(CONTRACTOR)},
        {"purpose": "trace-terms-v0 test vectors: estimate report and audit calls",
         "payload_digest": hashlib.sha256(b"trace-terms-v0 task").hexdigest()},
        grant,
        ["that both parties signed these grant bytes"],
        ["that anyone enforced any of this at runtime; the terms are proved against the records afterwards",
         "that anyone judges liability or fault; the verdict is a function anyone recomputes",
         "that a deviation was impossible, only that performing one is a provable deviation",
         "that this is a legal contract or determines legal responsibility",
         "that the parties exist: every key here is a test key derived from a fixed label"],
        requirements=requirements or {"evidence": "n/a", "recovery": "n/a"},
        contract_id=contract_id, nonce="0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        agreed_at=AGREED_AT, expiry=expiry, parent_contract=parent)
    C.sign_contract(rec, PRINCIPAL, pub_b64(PRINCIPAL), P_DOM)
    C.sign_contract(rec, CONTRACTOR, pub_b64(CONTRACTOR), C_DOM)
    v = C.verify_contract(rec)
    assert v["verdict"] == "accepted", v
    return rec, v["contract_sha256"]


CONTRACT, CSHA = make_contract()

RUNTIME_SUMMIT = {"producers": [SUMMIT_THUMB], "subjects": [SUMMIT["subject"]],
                  "models": [{"provider": SUMMIT["model"]["provider"], "model_id": SUMMIT["model"]["model_id"]}],
                  "policy_bundle_hashes": [SUMMIT["policy"]["bundle_hash"]], "enforcement_mode": "enforce",
                  "data_classes": ["confidential"], "platforms": [SUMMIT["runtime"]["platform"]],
                  "min_slsa_level": 2, "appraisal_status": ["affirming"], "max_age_seconds": None}


def terms(max_calls=None, total=None, runtime="none", authorizers=None, tools=None, sign=("p", "c"),
          csha=None, extra=None):
    t = {"schema": T.TERMS_SCHEMA, "contract_sha256": csha or CSHA,
         "authorizers": authorizers or [jwk_thumbprint(AUTH_JWK)], "tools": tools or dict(TOOLS),
         "max_calls": max_calls or {}, "max_calls_total": total,
         "runtime": None if runtime == "none" else runtime, "signatures": []}
    if extra:
        t.update(extra)
    if "p" in sign:
        T.sign_terms(t, PRINCIPAL, P_DOM)
    if "c" in sign:
        T.sign_terms(t, CONTRACTOR, C_DOM)
    return t


T0 = SUMMIT["iat"] + 60  # every call in the summit-runtime vectors happens a minute after the record was issued


def call(seq, tool, *, at=None, scope_tools=None, decision="allow", auth_id=None, expires_in=600,
         authorizer=AUTHORIZER, record=SUMMIT, signer=CONTRACTOR, transcript_required=False,
         authorized_tool_call=None, act_bridge=None, act_trace_sha="auto", amount=1, contract_sha=None,
         kid="auth-1"):
    at = T0 + seq * 10 if at is None else at
    tool_call = {"name": tool, "arguments": {"estimate_id": "E-%03d" % seq, "amount": amount}}
    declaration = {"impact": "read", "summary": "estimate call %d" % seq}
    pic_intent = "sha256:" + hashlib.sha256(("intent %d" % seq).encode()).hexdigest()
    pic_args = "sha256:" + hashlib.sha256(("args %d" % seq).encode()).hexdigest()
    auth = {"authorization_id": auth_id or "A-%03d" % seq, "decision": decision, "authorizer": "principal.example",
            "authorizer_key_id": kid, "authorized_at": at - 30, "expires_at": at - 30 + expires_in,
            "scope": {"tools": scope_tools or ["estimate.report", "estimate.audit"], "impacts": ["read"]},
            "pic": {"profile": "PIC-CJSON/1.0", "intent_digest": pic_intent, "args_digest": pic_args},
            "declaration_digest": IB.digest_jcs(declaration),
            "tool_call_digest": IB.digest_jcs(authorized_tool_call or tool_call),
            "transcript_required": transcript_required}
    if transcript_required:
        auth["successor_observation_digest"] = "sha256:" + "ab" * 32
    bridge = IB.sign_bridge(auth, authorizer)
    item = {"bridge": bridge, "declaration": declaration, "pic_intent_digest": pic_intent,
            "pic_args_digest": pic_args, "tool_call": tool_call, "transcript": None, "trust_record": record}
    act = T.make_act(contract_sha or CSHA, seq, item, at, record)
    if act_bridge:
        act["bridge_sha256"] = act_bridge
    if act_trace_sha != "auto":
        act["trace_sha256"] = act_trace_sha
    T.sign_act(act, signer)
    item["act"] = act
    return item


def bundle(t, acts, jwks=None, contract=None):
    return {"contract": contract or CONTRACT, "terms": t, "authorizer_jwks": jwks or [AUTH_JWK], "acts": acts}


def within(i):
    return {"index": i, "status": "within_terms", "codes": []}


def row(i, status, codes):
    return {"index": i, "status": status, "codes": sorted(codes)}


V = []


def add(vid, title, b, verdict, acts, refusals=None):
    V.append({"id": vid, "title": title, "bundle": b,
              "expect": {"verdict": verdict, "refusals": refusals or [], "acts": acts}})


# ---- the scene: every call allowed by TRACE, the contract still decides
add("TT01", "three calls, each allowed by TRACE, inside the grant and the counts, on the agreed runtime",
    bundle(terms(max_calls={"audit": 2}, total=3, runtime=RUNTIME_SUMMIT),
           [call(1, "estimate.report"), call(2, "estimate.audit"), call(3, "estimate.audit")]),
    "within_terms", [within(0), within(1), within(2)])

add("TT02", "the third audit: TRACE allows each call, the parties agreed to two audits",
    bundle(terms(max_calls={"audit": 2}),
           [call(1, "estimate.audit"), call(2, "estimate.audit"), call(3, "estimate.audit")]),
    "outside_terms", [within(0), within(1), row(2, "outside_terms", ["calls_exceed_terms"])])

add("TT03", "the total: two calls agreed, four made, the third and the fourth are over",
    bundle(terms(total=2),
           [call(1, "estimate.report"), call(2, "estimate.audit"), call(3, "estimate.report"),
            call(4, "estimate.audit")]),
    "outside_terms", [within(0), within(1), row(2, "outside_terms", ["calls_exceed_terms"]),
                      row(3, "outside_terms", ["calls_exceed_terms"])])

add("TT04", "the bridge scope includes compare and TRACE allows it; the contract prohibits compare",
    bundle(terms(), [call(1, "estimate.compare",
                          scope_tools=["estimate.report", "estimate.audit", "estimate.compare"])]),
    "outside_terms", [row(0, "outside_terms", ["prohibited_action"])])

add("TT05", "a tool the terms map to an action the grant never authorized",
    bundle(terms(), [call(1, "estimate.export", scope_tools=["estimate.export"])]),
    "outside_terms", [row(0, "outside_terms", ["action_not_granted"])])

add("TT06", "a tool the terms do not name at all",
    bundle(terms(), [call(1, "estimate.delete", scope_tools=["estimate.delete"])]),
    "outside_terms", [row(0, "outside_terms", ["tool_not_in_terms"])])

add("TT07", "TRACE verifies the bridge under the key the relying party supplied; the principal never agreed to it",
    bundle(terms(), [call(1, "estimate.report", authorizer=STRANGER_AUTH)], jwks=[STRANGER_JWK]),
    "outside_terms", [row(0, "outside_terms", ["authorizer_not_agreed", "executed_without_valid_authorization"])])

add("TT08", "the signed decision is deny and the contractor executed the call anyway",
    bundle(terms(), [call(1, "estimate.report", decision="deny")]),
    "outside_terms", [row(0, "outside_terms", ["authorization_denied", "executed_without_valid_authorization"])])

add("TT09", "the contractor states it executed after the authorization expired",
    bundle(terms(), [call(1, "estimate.report", expires_in=20)]),
    "outside_terms", [row(0, "outside_terms", ["authorization_invalid", "executed_without_valid_authorization"])])

add("TT10", "the authorization names one tool call, the contractor executed another",
    bundle(terms(), [call(1, "estimate.audit",
                          authorized_tool_call={"name": "estimate.audit", "arguments": {"estimate_id": "E-999",
                                                                                        "amount": 1}})]),
    "outside_terms", [row(0, "outside_terms", ["authorization_mismatch", "executed_without_valid_authorization"])])

_c11 = call(1, "estimate.report")
_other = call(2, "estimate.report")
_c11["bridge"] = _other["bridge"]
add("TT11", "the bundle carries another bridge than the one the act names: anyone can do that, so undetermined",
    bundle(terms(), [_c11]),
    "undetermined", [row(0, "undetermined", ["evidence_not_as_signed"])])

add("TT12", "one authorization carried two calls",
    bundle(terms(), [call(1, "estimate.audit", auth_id="A-SHARED"), call(2, "estimate.audit", auth_id="A-SHARED")]),
    "outside_terms", [within(0), row(1, "outside_terms", ["authorization_reused"])])

add("TT13", "an act signed by someone other than the contractor is reported and not counted against the total",
    bundle(terms(total=1), [call(1, "estimate.report"), call(2, "estimate.report", signer=OUTSIDER)]),
    "within_terms", [within(0), row(1, "not_attributed", ["act_not_signed_by_contractor"])])

_dup = call(1, "estimate.report")
add("TT14", "the same act bytes presented twice count once",
    bundle(terms(total=1), [_dup, copy.deepcopy(_dup)]),
    "within_terms", [within(0), row(1, "duplicate", ["same_act_again"])])

# ---- the runtime, with real Trust Records
TB = BERNSTEIN["iat"] + 60
add("TT15", "Bernstein 3.20.0's real record under terms that agreed on the summit runtime",
    bundle(terms(runtime=RUNTIME_SUMMIT), [call(1, "estimate.report", at=TB, record=BERNSTEIN)]),
    "outside_terms", [row(0, "outside_terms", ["producer_not_agreed", "subject_not_agreed", "model_not_agreed",
                                               "policy_not_agreed", "platform_not_agreed", "slsa_below_terms",
                                               "appraisal_not_agreed"])])

RUNTIME_BERNSTEIN = {"producers": [BERNSTEIN_THUMB], "subjects": [BERNSTEIN["subject"]],
                     "models": [{"provider": "anthropic", "model_id": "claude-haiku-4-5-20251001"}],
                     "policy_bundle_hashes": [BERNSTEIN["policy"]["bundle_hash"]], "enforcement_mode": "enforce",
                     "data_classes": ["confidential"], "platforms": ["software-only"], "min_slsa_level": 0,
                     "appraisal_status": ["none"], "max_age_seconds": None}
add("TT16", "the same real record under terms that agreed on exactly that software-only runtime",
    bundle(terms(runtime=RUNTIME_BERNSTEIN), [call(1, "estimate.report", at=TB, record=BERNSTEIN)]),
    "within_terms", [within(0)])

add("TT17", "the parties agreed on a runtime and the contractor signed an act that names no Trust Record",
    bundle(terms(runtime=RUNTIME_SUMMIT), [call(1, "estimate.report", record=None)]),
    "outside_terms", [row(0, "outside_terms", ["runtime_evidence_not_named"])])

_tampered = copy.deepcopy(SUMMIT)
_tampered["model"]["model_id"] = "summarizer-v4"
add("TT18", "the summit record with its model changed after signing",
    bundle(terms(runtime=RUNTIME_SUMMIT), [call(1, "estimate.report", record=_tampered)]),
    "outside_terms", [row(0, "outside_terms", ["trace_refused"])])

add("TT19", "the act names one Trust Record, the bundle carries another (the real summit record)",
    bundle(terms(runtime=RUNTIME_SUMMIT), [call(1, "estimate.report", act_trace_sha="00" * 32)]),
    "undetermined", [row(0, "undetermined", ["runtime_evidence_missing"])])

add("TT20", "the call ran two days after the record it names was issued",
    bundle(terms(runtime=RUNTIME_SUMMIT), [call(1, "estimate.report", at=SUMMIT["iat"] + 2 * 86400)]),
    "outside_terms", [row(0, "outside_terms", ["trace_stale_at_act"])])

_rt21 = dict(RUNTIME_SUMMIT, data_classes=["internal"])
add("TT21", "the parties agreed on internal data, the record states confidential",
    bundle(terms(runtime=_rt21), [call(1, "estimate.report")]),
    "outside_terms", [row(0, "outside_terms", ["data_class_not_agreed"])])

_lib = sign_record({"eat_profile": "tag:agentrust-io.com,2026:trace-v0.2", "iat": T0, "subject":
                    "spiffe://contractor.example/agent/estimator",
                    "model": dict(SUMMIT["model"]), "runtime": dict(SUMMIT["runtime"]),
                    "policy": {"bundle_hash": SUMMIT["policy"]["bundle_hash"], "enforcement_mode": "monitor"},
                    "data_class": "confidential", "build_provenance": dict(SUMMIT["build_provenance"]),
                    "appraisal": dict(SUMMIT["appraisal"])}, LIB_PRODUCER)
_rt22 = dict(RUNTIME_SUMMIT, producers=[jwk_thumbprint(_lib["cnf"]["jwk"])], subjects=[_lib["subject"]])
add("TT22", "a record agentrust-trace signs here states monitor where the parties agreed on enforce",
    bundle(terms(runtime=_rt22), [call(1, "estimate.report", at=T0 + 30, record=_lib)]),
    "outside_terms", [row(0, "outside_terms", ["enforcement_not_agreed"])])

add("TT23", "runtime not in the terms: a Trust Record is carried and not read",
    bundle(terms(), [call(1, "estimate.report", record=BERNSTEIN, at=T0 + 10)]),
    "within_terms", [within(0)])

add("TT24", "transcript required by the authorization and not supplied",
    bundle(terms(), [call(1, "estimate.report", transcript_required=True)]),
    "outside_terms", [row(0, "outside_terms", ["authorization_mismatch", "executed_without_valid_authorization"])])

# ---- stage A
add("TT25", "terms signed by the principal only", bundle(terms(sign=("p",)), [call(1, "estimate.report")]),
    "refused", [], refusals=["terms_one_sided"])
add("TT26", "terms naming another contract",
    bundle(terms(csha="11" * 32), [call(1, "estimate.report")]), "refused", [], refusals=["terms_for_other_contract"])
_ct = copy.deepcopy(CONTRACT)
_ct["grant"]["prohibited_actions"] = []
add("TT27", "the contract changed after both signed it (compare no longer prohibited)",
    bundle(terms(), [call(1, "estimate.compare", scope_tools=["estimate.compare"])], contract=_ct),
    "refused", [], refusals=["contract:bad_signature", "contract:one_sided"])
add("TT28", "terms with a member no reader checks",
    bundle(terms(extra={"note": "trust me"}), [call(1, "estimate.report")]), "refused", [],
    refusals=["terms_malformed:members"])
_bad = call(1, "estimate.report")
_bad["act"]["seq"] = 0
add("TT29", "an act altered after signing so it is no longer well formed: nobody's act, reported and not counted",
    bundle(terms(), [_bad, call(2, "estimate.report")]),
    "within_terms", [row(0, "not_attributed", ["act_malformed"]), within(1)])


# ---- the holes a review found, each closed and kept as a vector
_c30 = call(1, "estimate.report")
_c30["trust_record"] = None
add("TT30", "the act names the summit record and the bundle does not carry it",
    bundle(terms(runtime=RUNTIME_SUMMIT), [_c30]),
    "undetermined", [row(0, "undetermined", ["runtime_evidence_missing"])])

_c31 = call(2, "estimate.compare", scope_tools=["estimate.compare"])
_c31["act"]["seq"] = 2.0
T.sign_act(_c31["act"], CONTRACTOR)
add("TT31", "the contractor signs a malformed act for a prohibited call: it cannot drop out of sight as within",
    bundle(terms(), [call(1, "estimate.report"), _c31]),
    "undetermined", [within(0), row(1, "unreadable", ["act_malformed", "signed_by_contractor"])])

_ok32 = call(1, "estimate.report")
_hid32 = call(1, "estimate.compare", scope_tools=["estimate.compare"], auth_id="A-X")
add("TT32", "two different acts the contractor signed with one seq, a report and a prohibited compare",
    bundle(terms(), [_ok32, _hid32]),
    "outside_terms", [row(0, "outside_terms", ["seq_conflict"]),
                      row(1, "outside_terms", ["prohibited_action", "seq_conflict"])])
add("TT33", "the same two acts in the other order: the verdict does not depend on who orders the bundle",
    bundle(terms(), [_hid32, _ok32]),
    "outside_terms", [row(0, "outside_terms", ["prohibited_action", "seq_conflict"]),
                      row(1, "outside_terms", ["seq_conflict"])])

_other_agent = sign_record({"eat_profile": "tag:agentrust-io.com,2026:trace-v0.2", "iat": T0,
                            "subject": "spiffe://someone-else.example/agent/x",
                            "model": dict(SUMMIT["model"]), "runtime": dict(SUMMIT["runtime"]),
                            "policy": dict(SUMMIT["policy"]), "data_class": "confidential",
                            "build_provenance": dict(SUMMIT["build_provenance"]),
                            "appraisal": dict(SUMMIT["appraisal"])}, LIB_PRODUCER)
_rt34 = dict(RUNTIME_SUMMIT, producers=[jwk_thumbprint(_other_agent["cnf"]["jwk"])],
             subjects=["spiffe://contractor.example/agent/estimator"])
add("TT34", "a genuine record from an agreed producer, about another agent",
    bundle(terms(runtime=_rt34), [call(1, "estimate.report", at=T0 + 30, record=_other_agent)]),
    "outside_terms", [row(0, "outside_terms", ["subject_not_agreed"])])

_c35 = call(1, "estimate.report")
_c35["declaration"] = dict(_c35["declaration"], summary="changed by whoever assembled the bundle")
add("TT35", "a third party changes the declaration: undetermined, the contractor is not blamed",
    bundle(terms(), [_c35]), "undetermined", [row(0, "undetermined", ["evidence_not_as_signed"])])

add("TT36", "the agreed authorizer's key is not supplied: undetermined, not authorizer_not_agreed",
    bundle(terms(), [call(1, "estimate.report")], jwks=[STRANGER_JWK]),
    "undetermined", [row(0, "undetermined", ["authorizer_key_not_supplied"])])

_c37 = call(1, "estimate.report")
_c37["bridge"] = dict(_c37["bridge"], z="\ud800")
add("TT37", "an unsigned bridge carrying a lone surrogate: a verdict, not a crash",
    bundle(terms(), [_c37]), "undetermined", [row(0, "unreadable", ["act_malformed", "signed_by_contractor"])])

_ct38 = copy.deepcopy(CONTRACT)
_ct38["parties"][0] = "xxx"
add("TT38", "a contract whose party is not an object: a verdict, not a crash",
    bundle(terms(), [], contract=_ct38), "refused", [], refusals=["contract:unreadable"])

add("TT39", "the contractor signs a prohibited call's act under another contract: not judged here, and not within",
    bundle(terms(), [call(1, "estimate.report"),
                     call(2, "estimate.compare", scope_tools=["estimate.compare"], contract_sha="ee" * 32)]),
    "undetermined", [within(0), row(1, "other_contract", ["contractor_act_for_other_contract"])])

add("TT40", "a cap on a name no tool maps to would never apply: refused",
    bundle(terms(max_calls={"estimate.audit": 1}), [call(1, "estimate.audit")]), "refused", [],
    refusals=["terms_malformed:max_calls_unknown_action"])

add("TT41", "no acts at all: nothing was shown to be within the terms",
    bundle(terms(), []), "undetermined", [])

SECOND_AUTH = key("a second authorizer the principal agreed to")
SECOND_JWK = jwk_with_kid(SECOND_AUTH, "auth-2")
add("TT42", "two agreed authorizers each number their first authorization A-001: not a reuse",
    bundle(terms(authorizers=[jwk_thumbprint(AUTH_JWK), jwk_thumbprint(SECOND_JWK)]),
           [call(1, "estimate.report", auth_id="A-001"),
            call(2, "estimate.report", auth_id="A-001", authorizer=SECOND_AUTH, kid="auth-2")],
           jwks=[AUTH_JWK, SECOND_JWK]),
    "within_terms", [within(0), within(1)])

_c43 = call(2, "estimate.audit")
_c43["tool_call"] = {"name": "estimate.compare", "arguments": {"estimate_id": "E-002", "amount": 1}}
add("TT43", "a third party swaps the tool call for a prohibited one: undetermined, and the audit count is not moved",
    bundle(terms(max_calls={"audit": 1}), [call(1, "estimate.audit"), _c43]),
    "undetermined", [within(0), row(1, "undetermined", ["evidence_not_as_signed"])])


# ---- round two of the review
_c44 = call(2, "estimate.audit")
_a44 = _c44["bridge"]["authorization"]
_a44["expires_at"] = float(_a44["expires_at"])
_a44["authorized_at"] = float(_a44["authorized_at"])
add("TT44", "whoever assembles the bundle writes the bridge's integer times as equal floats: same digest, same verdict",
    bundle(terms(), [call(1, "estimate.report"), _c44]), "within_terms", [within(0), within(1)])

_r45 = copy.deepcopy(SUMMIT)
_r45["build_provenance"]["slsa_level"] = 2.0
add("TT45", "the summit record's slsa_level written as 2.0: the producer signed the same bytes, the verdict is the same",
    bundle(terms(runtime=RUNTIME_SUMMIT), [call(1, "estimate.report", record=_r45)]), "within_terms", [within(0)])

_g46 = call(1, "estimate.report")
_b46 = copy.deepcopy(_g46)
_b46["declaration"] = {"impact": "read", "summary": "not what the act names"}
add("TT46", "the same act twice, the first copy with other evidence: the copy that matches the act is the one read",
    bundle(terms(), [_b46, _g46]), "within_terms",
    [row(0, "duplicate", ["same_act_again"]), within(1)])

_ct47, _cs47 = make_contract({"conditional": [{"action": "report", "requires": "principal_approval"}]},
                             contract_id="7e5c0a1d2b3c4d5e6f708192a3b4c5d7")
add("TT47", "a grant with a conditional clause this profile does not judge: refused, not judged as if it were absent",
    bundle(terms(csha=_cs47), [call(1, "estimate.report", contract_sha=_cs47)], contract=_ct47), "refused", [],
    refusals=["grant_clause_not_judged:conditional"])

_ct48, _cs48 = make_contract({"limits": {"report": {"max_amount": 1, "unit": "JPY"}}},
                             requirements={"evidence": "n/a", "recovery": "n/a",
                                           "admission": "required_before_execution"},
                             contract_id="7e5c0a1d2b3c4d5e6f708192a3b4c5d8")
add("TT48", "a grant with amount limits: refused here, settle judges amounts",
    bundle(terms(csha=_cs48), [call(1, "estimate.report", contract_sha=_cs48, amount=10 ** 6)], contract=_ct48),
    "refused", [], refusals=["contract_clause_not_judged:requirements.admission", "grant_clause_not_judged:limits"])

add("TT49", "a junk item nobody signed is reported and does not move the verdict",
    bundle(terms(), [call(1, "estimate.report"), {}]), "within_terms",
    [within(0), row(1, "not_attributed", ["act_malformed"])])

add("TT50", "more authorizer keys than a bundle may carry",
    bundle(terms(), [call(1, "estimate.report")], jwks=[AUTH_JWK] * 65), "refused", [],
    refusals=["bundle_malformed:authorizer_jwks"])

_g51 = call(1, "estimate.report")
_b51 = copy.deepcopy(_g51)
_b51["trust_record"] = BERNSTEIN
add("TT51", "the same act twice, the first copy carrying another Trust Record: the copy whose record matches is read",
    bundle(terms(runtime=RUNTIME_SUMMIT), [_b51, _g51]), "within_terms",
    [row(0, "duplicate", ["same_act_again"]), within(1)])

# ---- round three of the review: clauses outside the grant that both parties also signed
_ct52, _cs52 = make_contract(contract_id="7e5c0a1d2b3c4d5e6f708192a3b4c5d9",
                             parent={"contract_id": "7e5c0a1d2b3c4d5e6f708192a3b4c5d6", "settlement_url": None})
add("TT52", "a child contract whose parent is not supplied: refused, a parent was never checked",
    bundle(terms(csha=_cs52), [call(1, "estimate.report", contract_sha=_cs52)], contract=_ct52), "refused", [],
    refusals=["contract_clause_not_judged:parent_contract"])

_ct53, _cs53 = make_contract(requirements={"evidence": "nenrin_required", "recovery": "tsugi_required"},
                             contract_id="7e5c0a1d2b3c4d5e6f708192a3b4c5da")
add("TT53", "a contract requiring NENRIN evidence and TSUGI recovery: refused here, settle judges those",
    bundle(terms(csha=_cs53), [call(1, "estimate.report", contract_sha=_cs53)], contract=_ct53), "refused", [],
    refusals=["contract_clause_not_judged:requirements.evidence", "contract_clause_not_judged:requirements.recovery"])

_before = calendar.timegm(time.strptime(AGREED_AT, "%Y-%m-%dT%H:%M:%SZ"))
add("TT54", "the contractor states the call ran an hour before the contract was agreed",
    bundle(terms(), [call(1, "estimate.report", at=_before - 3600)]),
    "outside_terms", [row(0, "outside_terms", ["executed_before_agreed_at"])])

_ct55, _cs55 = make_contract(contract_id="7e5c0a1d2b3c4d5e6f708192a3b4c5db", expiry="2026-08-21T00:00:00Z")
add("TT55", "a call the contractor states ran after the contract expired",
    bundle(terms(csha=_cs55), [call(1, "estimate.report", contract_sha=_cs55),
                               call(2, "estimate.report", contract_sha=_cs55, at=T0 + 2 * 86400)], contract=_ct55),
    "outside_terms", [within(0), row(1, "outside_terms", ["executed_after_expiry"])])


def main():
    doc = {"schema": "musubi-trace-terms-vectors-v0", "generator": "gen_vectors.py",
           "agentrust_trace": T.AGENTRUST_TRACE_PIN,
           "sources": {"summit-demo-record.json": hashlib.sha256(
               open(os.path.join(SRC, "summit-demo-record.json"), "rb").read()).hexdigest(),
               "bernstein-3.20.0-20260920-165918-backend-99365805.json": hashlib.sha256(
                   open(os.path.join(SRC, "bernstein-3.20.0-20260920-165918-backend-99365805.json"),
                        "rb").read()).hexdigest()},
           "vectors": V}
    os.makedirs(os.path.join(HERE, "vectors"), exist_ok=True)
    with open(os.path.join(HERE, "vectors", "vectors.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True, ensure_ascii=True)
        f.write("\n")
    print("wrote %d vectors" % len(V))


if __name__ == "__main__":
    main()
