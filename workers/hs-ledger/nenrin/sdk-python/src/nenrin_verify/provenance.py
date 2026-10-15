"""nenrin-provenance-verify-v0 in Python: a line-for-line port of npm nenrin-verify's nenrin_verify.mjs.

Same input, same report. The JavaScript file is the reference; this port is held to it by tests/test_parity.py,
which runs both on the frozen fixtures and on generated mutations and requires the two reports to be the same
object, key for key (and the CLI output to hash the same under report_sha256). Where the JavaScript would throw
(a property read on null, a value with no canonical form), this port raises.

Layers (each verifies on its own; this file adds the cross-layer checks):
  task-delegation-bind-v0  third-party observation of the delegation chain: R1..R4, witness_sig, edge_sig
  task-execution-bind-v0   caller/gateway action and outcome binding: E1..E3, caller_sig, provider_sig
  outcome_evidence         the outcome's commitment to an independently checkable pointer
  preflight                the provider's pre-execution declaration against the grant

It opens no socket and has no clock. Signatures prove who asserted, not that the assertion is true; every report
says so in does_not_establish, accepted or refused.
"""
import functools as _functools
import hashlib
import re as _re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._js import (UNDEF, JSTypeError, assign, OBJECT_PROTOTYPE_KEYS, CanonicalError, JSMap, and_prop, canonical,
                  date_parse, is_num, is_obj, node_b64decode, nullish, or_, prop, seq, sort_numeric, stringify,
                  truthy, uniq)

VERIFIER_VERSION = "0.1.7"
CONSUME_VERSION = "0.1.1"
CANDIDATE_EVIDENCE_VERSION = "0.1.0"
LINK_PREFIX = "nenrin-exec://"
CANONICALIZATION = "musubi-canonical-v0"
ACTION_PREIMAGE_PROFILE = "task-execution-bind-v0/action"

__all__ = ["verify_provenance", "consume_evidence", "posture_line", "candidate_evidence_set", "preflight_report",
           "public_key_from_did_key", "did_key_resolver", "evidence_id", "grant_ref", "receipt_id", "intent_id",
           "canonical", "VERIFIER_VERSION"]


def sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _without(rec, derived):
    """The record's own keys minus the derived ones; every other own key stays, "__proto__" included. The reference
    used Object.assign({}, rec), which does not copy an own "__proto__" key, so a record carrying that field as an own
    wire key hashed without it (pipavlo82, #29, 2026-10-15); bind.mjs withoutDerived and this port now keep it."""
    items = rec.items() if isinstance(rec, dict) else assign(rec).items()
    return {k: v for k, v in items if k not in derived}


# ---- task-delegation-bind-v0/bind.mjs ----
DERIVED_FIELDS = ("evidence_id", "witness_sig", "edge_sig", "consent")


def preimage(obs):
    return _without(obs, DERIVED_FIELDS)


def evidence_id(obs):
    return sha256hex(canonical(preimage(obs)))


def witness_independent(obs):
    hop = prop(obs, "hop")
    return not seq(prop(obs, "witness_id"), prop(hop, "from")) and not seq(prop(obs, "witness_id"), prop(hop, "to"))


def recompute_ok(obs):
    e = prop(obs, "evidence_id")
    return isinstance(e, str) and e == evidence_id(obs)


def verify_observation(obs):
    if not witness_independent(obs):
        return {"ok": False, "reason": "witness_not_independent"}
    if not recompute_ok(obs):
        return {"ok": False, "reason": "recompute_mismatch"}
    return {"ok": True}


def aggregate_verdict(observations_for_hop):
    verdicts = uniq([prop(prop(o, "conduct"), "verdict") for o in observations_for_hop])
    if len(verdicts) == 0:
        return "no_evidence"
    if len(verdicts) > 1:
        return "disagreement"
    return verdicts[0]


# ---- signatures (sign.mjs, sign_exec.mjs, preflight.mjs) ----
_B64_STD = _re.compile(r"[A-Za-z0-9+/]*={0,2}")


def b64_exact(s, n):
    """The n bytes of a field written in canonical standard base64 (RFC 4648 section 4: the standard alphabet, padding
    present, no whitespace, unused trailing bits zero), else None. One key or signature has exactly one spelling."""
    import base64 as _b64
    if not isinstance(s, str) or len(s) == 0 or len(s) % 4 != 0 or not _B64_STD.fullmatch(s):
        return None
    try:
        b = _b64.b64decode(s, validate=True)
    except Exception:
        return None
    if len(b) != n or _b64.b64encode(b).decode("ascii") != s:
        return None
    return b


_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_D2 = 2 * _ED_D % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_add(P, Q):
    p = _ED_P
    a = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    b = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    c = P[3] * _ED_D2 % p * Q[3] % p
    d = 2 * P[2] * Q[2] % p
    e, f, g, h = (b - a) % p, (d - c) % p, (d + c) % p, (b + a) % p
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _ed_mul(P, n):
    R, Q = (0, 1, 1, 0), P
    while n:
        if n & 1:
            R = _ed_add(R, Q)
        Q = _ed_add(Q, Q)
        n >>= 1
    return R


def _ed_is_identity(P):
    return P[0] % _ED_P == 0 and (P[1] - P[2]) % _ED_P == 0


@_functools.lru_cache(maxsize=4096)
def _ed25519_key_check(raw):
    p = _ED_P
    sign = raw[31] >> 7
    y = int.from_bytes(raw[:31] + bytes([raw[31] & 0x7F]), "little")
    if y >= p:
        return False
    u, v = (y * y - 1) % p, (_ED_D * y * y + 1) % p
    x2 = u * pow(v, p - 2, p) % p
    x = pow(x2, (p + 3) // 8, p)
    if x * x % p != x2:
        x = x * _ED_SQRT_M1 % p
    if x * x % p != x2:
        return False
    if x == 0 and sign == 1:
        return False
    if (x & 1) != sign:
        x = p - x
    P = (x, y, 1, x * y % p)
    if _ed_is_identity(P):
        return False
    return _ed_is_identity(_ed_mul(P, _ED_L))


def ed25519_key_ok(raw):
    """ed25519_key.mjs ed25519KeyOk (nenrin-verify 0.4.2): True only for the canonical encoding of a point P of the
    prime-order subgroup (P != identity, L * P = identity). Refused: small order (R = identity, S = 0 verifies on every
    message with no private key), mixed order A + T (one private key posing as a second key), and non-canonical
    encodings (y >= p, or x = 0 with the sign bit set)."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        return False
    return _ed25519_key_check(bytes(raw))


def sig_bytes(s):
    """bind.mjs sigBytes (0.4.1): the 64 bytes of a signature field written in canonical standard base64, else None."""
    return b64_exact(s, 64)


def _ed25519_verify(pub, message, sig_b64):
    """sigBytes(sig) then nodeVerify(null, Buffer.from(message, "utf8"), pub, bytes) inside try/catch."""
    try:
        sb = sig_bytes(sig_b64)
        if sb is None:
            return False
        key = pub if isinstance(pub, Ed25519PublicKey) else Ed25519PublicKey.from_public_bytes(pub)
        key.verify(sb, message.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _verify_detached(sig, pub, preimage_fn):
    if not isinstance(sig, str) or not truthy(pub):
        return False
    try:
        msg = canonical(preimage_fn())
    except (CanonicalError, JSTypeError):
        return False
    return _ed25519_verify(pub, msg, sig)


def _edge_of(obs):
    return {"task_id": prop(obs, "task_id"), "hop": prop(obs, "hop")}


def verify_witness_sig(obs, pub):
    return _verify_detached(prop(obs, "witness_sig"), pub, lambda: preimage(obs))


def verify_edge_sig(obs, pub):
    return _verify_detached(prop(obs, "edge_sig"), pub, lambda: _edge_of(obs))


def verify_signed(obs, resolve):
    if not verify_witness_sig(obs, resolve(prop(obs, "witness_id"))):
        return {"ok": False, "reason": "witness_sig_invalid"}
    if not verify_edge_sig(obs, resolve(prop(prop(obs, "hop"), "from"))):
        return {"ok": False, "reason": "edge_sig_invalid"}
    return {"ok": True}


# ---- task-execution-bind-v0/bind_exec.mjs ----
GRANT_DERIVED = ("grant_ref", "caller_sig", "action_binding")
RECEIPT_DERIVED = ("receipt_id", "provider_sig", "action_binding")
INTENT_DERIVED = ("intent_id", "intent_sig", "action_binding")


def grant_preimage(g):
    return _without(g, GRANT_DERIVED)


def receipt_preimage(r):
    return _without(r, RECEIPT_DERIVED)


def intent_preimage(i):
    return _without(i, INTENT_DERIVED)


def grant_ref(g):
    return sha256hex(canonical(grant_preimage(g)))


def receipt_id(r):
    return sha256hex(canonical(receipt_preimage(r)))


def intent_id(i):
    return sha256hex(canonical(intent_preimage(i)))


def actions_equal(a, b):
    return truthy(a) and truthy(b) and canonical(a) == canonical(b)


def grant_is_self_authorized(g):
    return not nullish(prop(g, "provider_id")) and seq(prop(g, "caller_id"), prop(g, "provider_id"))


def provider_authorized(g, r):
    return nullish(prop(g, "provider_id")) or seq(prop(r, "provider_id"), prop(g, "provider_id"))


def receipt_binds_grant(g, r):
    gr = prop(r, "grant_ref")
    return isinstance(gr, str) and gr == grant_ref(g)


_RFC3339_CAL = _re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?Z")


def _days_in_month(y, m):
    return [31, 29 if (y % 4 == 0 and y % 100 != 0) or y % 400 == 0 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]


def is_rfc3339_utc(s):
    """bind_exec.mjs isRfc3339Utc (0.4.1): the strict pattern, a real calendar day, hour 0..23, then Date.parse."""
    if not isinstance(s, str):
        return False
    m = _RFC3339_CAL.fullmatch(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if y < 1 or not (1 <= mo <= 12) or d < 1 or d > _days_in_month(y, mo) or h > 23 or mi > 59 or se > 59:
        return False
    return date_parse(s) is not None


def _in_window(g, t_str):
    t = date_parse(t_str)
    if t is None:
        return False
    nb, na = prop(g, "not_before"), prop(g, "not_after")
    if not nullish(nb):
        v = date_parse(nb)
        if v is None or t < v:
            return False
    if not nullish(na):
        v = date_parse(na)
        if v is None or t > v:
            return False
    return True


def within_window(g, r):
    return _in_window(g, prop(r, "executed_at"))


def grant_recompute_ok(g):
    v = prop(g, "grant_ref")
    return isinstance(v, str) and v == grant_ref(g)


def receipt_recompute_ok(r):
    v = prop(r, "receipt_id")
    return isinstance(v, str) and v == receipt_id(r)


def intent_recompute_ok(i):
    v = prop(i, "intent_id")
    return isinstance(v, str) and v == intent_id(i)


def action_digest(action):
    return sha256hex(canonical(action))


def action_binding(action):
    return {"type": "canonical_request_digest", "canonicalization": CANONICALIZATION,
            "preimage_profile": ACTION_PREIMAGE_PROFILE, "digest": {"alg": "sha-256", "value": action_digest(action)}}


def check_action_binding(rec, key):
    b = prop(rec, "action_binding")
    if b is UNDEF:
        return {"status": "absent"}
    if not truthy(b) or not is_obj(b) or not seq(prop(b, "type"), "canonical_request_digest"):
        return {"status": "malformed"}
    d = prop(b, "digest")
    if not truthy(d) or not is_obj(d) or not seq(prop(d, "alg"), "sha-256") or not isinstance(prop(d, "value"), str):
        return {"status": "malformed"}
    if not seq(prop(b, "canonicalization"), CANONICALIZATION) or not seq(prop(b, "preimage_profile"), ACTION_PREIMAGE_PROFILE):
        return {"status": "unknown_profile"}
    if nullish(prop(rec, key)) or prop(d, "value") != action_digest(prop(rec, key)):
        return {"status": "mismatch"}
    return {"status": "recomputed"}


def action_binding_ok(st):
    return st == "absent" or st == "recomputed"


def _timestamps_ok(g, t):
    if not is_rfc3339_utc(t):
        return False
    if not nullish(prop(g, "not_before")) and not is_rfc3339_utc(prop(g, "not_before")):
        return False
    if not nullish(prop(g, "not_after")) and not is_rfc3339_utc(prop(g, "not_after")):
        return False
    return True


OPEN_GRANT_EXEC = ("the grant names no provider_id, so any executor's receipt is accepted; this pair does not establish "
                   "that the executor was the one the caller intended.")
SELF_AUTH_EXEC = ("caller_id equals the grant's provider_id; the caller authorized its own executor. Declared, so recorded "
                  "not refused; this pair does not establish that the authorization came from anyone other than the executor.")


def verify_execution(g, r):
    findings = []
    if not grant_recompute_ok(g):
        return {"ok": False, "reason": "grant_recompute_mismatch", "findings": findings}
    if not receipt_recompute_ok(r):
        return {"ok": False, "reason": "receipt_recompute_mismatch", "findings": findings}
    gb, rb = check_action_binding(g, "action"), check_action_binding(r, "executed_action")
    ab = {"grant": gb["status"], "receipt": rb["status"]}
    if not action_binding_ok(gb["status"]):
        return {"ok": False, "reason": "action_binding_" + gb["status"], "record": "grant", "findings": findings, "action_binding": ab}
    if not action_binding_ok(rb["status"]):
        return {"ok": False, "reason": "action_binding_" + rb["status"], "record": "receipt", "findings": findings, "action_binding": ab}
    if not receipt_binds_grant(g, r):
        return {"ok": False, "reason": "receipt_unbound", "findings": findings, "action_binding": ab}
    if not _timestamps_ok(g, prop(r, "executed_at")):
        return {"ok": False, "reason": "invalid_timestamp", "findings": findings}
    if not provider_authorized(g, r):
        return {"ok": False, "reason": "provider_not_authorized", "findings": findings}
    if not within_window(g, r):
        return {"ok": False, "reason": "outside_authorization_window", "findings": findings}
    if nullish(prop(g, "provider_id")):
        findings.append({"code": "open_grant", "why": OPEN_GRANT_EXEC})
    if grant_is_self_authorized(g):
        findings.append({"code": "self_authorized", "why": SELF_AUTH_EXEC})
    if not actions_equal(prop(g, "action"), prop(r, "executed_action")):
        return {"ok": False, "reason": "action_diverged", "findings": findings, "action_binding": ab}
    return {"ok": True, "reason": "action_bound", "findings": findings, "action_binding": ab}


def reconcile_outcome(receipts, gref):
    for_grant = [r for r in receipts if seq(prop(r, "grant_ref"), gref) and receipt_recompute_ok(r)]
    ids = uniq([prop(r, "receipt_id") for r in for_grant])
    if len(ids) == 0:
        return {"status": "no_receipt"}
    if len(ids) > 1:
        return {"status": "equivocation", "receipt_ids": ids}
    return {"status": "reconciled", "receipt_id": ids[0], "outcome": prop(for_grant[0], "outcome")}


def verify_grant_sig(g, pub):
    return _verify_detached(prop(g, "caller_sig"), pub, lambda: grant_preimage(g))


def verify_receipt_sig(r, pub):
    return _verify_detached(prop(r, "provider_sig"), pub, lambda: receipt_preimage(r))


def verify_intent_sig(i, pub):
    return _verify_detached(prop(i, "intent_sig"), pub, lambda: intent_preimage(i))


def verify_signed_execution(g, r, resolve):
    if not verify_grant_sig(g, resolve(prop(g, "caller_id"))):
        return {"ok": False, "reason": "caller_sig_invalid"}
    if not verify_receipt_sig(r, resolve(prop(r, "provider_id"))):
        return {"ok": False, "reason": "provider_sig_invalid"}
    return {"ok": True}


def reconcile_signed(receipts, gref, authorized_provider, resolve):
    if nullish(authorized_provider):
        return {"status": "no_authorized_provider"}
    authentic = [r for r in receipts
                 if seq(prop(r, "grant_ref"), gref) and seq(prop(r, "provider_id"), authorized_provider)
                 and seq(prop(r, "receipt_id"), receipt_id(r)) and verify_receipt_sig(r, resolve(authorized_provider))]
    ids = uniq([prop(r, "receipt_id") for r in authentic])
    if len(ids) == 0:
        return {"status": "no_authentic_receipt"}
    if len(ids) > 1:
        return {"status": "equivocation", "receipt_ids": ids, "provider_id": authorized_provider}
    return {"status": "reconciled", "receipt_id": ids[0], "outcome": prop(authentic[0], "outcome")}


# ---- task-execution-bind-v0/outcome_evidence.mjs ----

_HEX64 = _re.compile(r"\A[0-9a-f]{64}\Z")
EVIDENCE_KINDS = {
    "bitcoin_tx": {"ref": _HEX64, "means": "a Bitcoin transaction id; a reader checks it on any node or explorer"},
    "ledger_record": {"ref": _HEX64, "means": "a content-addressed ledger record sha256; a reader fetches the bytes and recomputes"},
    "document_sha256": {"ref": _HEX64, "means": "sha256 of a document the reader can obtain and hash"},
    "url_sha256": {"ref": _HEX64, "means": "sha256 of the bytes served at a url the reader can fetch and hash"},
}


def evidence_of(receipt):
    if truthy(receipt) and truthy(prop(receipt, "outcome")) and truthy(prop(prop(receipt, "outcome"), "evidence")):
        return prop(prop(receipt, "outcome"), "evidence")
    return None


def evidence_well_formed(ev):
    if not truthy(ev) or not (is_obj(ev) or isinstance(ev, list)):
        return {"ok": False, "reason": "evidence_not_object"}
    kind = prop(ev, "kind")
    key = kind if isinstance(kind, str) else _key_of(kind)
    ref = prop(ev, "ref")
    if key in OBJECT_PROTOTYPE_KEYS:
        # EVIDENCE_KINDS[key] is an inherited member there: truthy, with no .ref to test against
        if not isinstance(ref, str):
            return {"ok": False, "reason": "evidence_ref_malformed"}
        raise JSTypeError("Cannot read properties of undefined (reading 'test')")
    k = EVIDENCE_KINDS.get(key)
    if not k:
        return {"ok": False, "reason": "evidence_kind_unknown"}
    if not isinstance(ref, str) or not k["ref"].match(ref):
        return {"ok": False, "reason": "evidence_ref_malformed"}
    system = prop(ev, "system")
    if not isinstance(system, str) or len(system) == 0:
        return {"ok": False, "reason": "evidence_system_missing"}
    return {"ok": True}


def _key_of(v):
    """the property key JavaScript would make of a non-string value used as obj[v]"""
    if v is None:
        return "null"
    if v is UNDEF:
        return "undefined"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_num(v):
        from ._js import num_str
        return num_str(v)
    if isinstance(v, list):
        return ",".join("" if (x is None or x is UNDEF) else _key_of(x) if not isinstance(x, str) else x for x in v)
    return "[object Object]"


def verify_evidence(receipt, lookup=None):
    ev = evidence_of(receipt)
    if not truthy(ev):
        return {"ok": True, "reason": "no_evidence_bound", "bound": False, "checked_externally": False}
    w = evidence_well_formed(ev)
    if not w["ok"]:
        return {"ok": False, "reason": w["reason"], "bound": True, "checked_externally": False}
    if not callable(lookup):
        return {"ok": True, "reason": "evidence_bound_unchecked", "bound": True, "checked_externally": False}
    try:
        ext = lookup(ev)
    except Exception as e:
        ext = {"found": False, "matches": False, "error": str(e)}
    found = truthy(ext) and truthy(prop(ext, "found"))
    matches = truthy(ext) and truthy(prop(ext, "matches"))
    external = {"found": found, "matches": matches}
    if not found:
        return {"ok": False, "reason": "evidence_not_found", "bound": True, "checked_externally": True, "external": external}
    if not matches:
        return {"ok": False, "reason": "evidence_does_not_match", "bound": True, "checked_externally": True, "external": external}
    return {"ok": True, "reason": "evidence_confirmed", "bound": True, "checked_externally": True, "external": external}


# ---- task-execution-bind-v0/preflight.mjs ----
def intent_binds_grant(g, i):
    v = prop(i, "grant_ref")
    return isinstance(v, str) and v == grant_ref(g)


def verify_preflight(g, i):
    findings = []
    if not grant_recompute_ok(g):
        return {"ok": False, "reason": "grant_recompute_mismatch", "findings": findings}
    if not intent_recompute_ok(i):
        return {"ok": False, "reason": "intent_recompute_mismatch", "findings": findings}
    ib = check_action_binding(i, "proposed_action")
    if not action_binding_ok(ib["status"]):
        return {"ok": False, "reason": "action_binding_" + ib["status"], "record": "intent", "findings": findings}
    if not intent_binds_grant(g, i):
        return {"ok": False, "reason": "intent_unbound", "findings": findings}
    if not _timestamps_ok(g, prop(i, "declared_at")):
        return {"ok": False, "reason": "invalid_timestamp", "findings": findings}
    if not provider_authorized(g, i):
        return {"ok": False, "reason": "provider_not_authorized", "findings": findings}
    if not _in_window(g, prop(i, "declared_at")):
        return {"ok": False, "reason": "outside_authorization_window", "findings": findings}
    if nullish(prop(g, "provider_id")):
        findings.append({"code": "open_grant", "why": "the grant names no provider_id, so any declaring executor is accepted; this pair does not establish the caller intended this executor."})
    if grant_is_self_authorized(g):
        findings.append({"code": "self_authorized", "why": "caller_id equals the grant's provider_id; the caller authorized its own executor."})
    if not actions_equal(prop(g, "action"), prop(i, "proposed_action")):
        return {"ok": False, "reason": "action_diverged", "findings": findings}
    return {"ok": True, "reason": "preauthorized", "findings": findings}


def intent_matches_receipt(i, r):
    return actions_equal(prop(i, "proposed_action"), prop(r, "executed_action"))


def _json_key(v):
    """JSON.stringify(v) used as a Map key (counterparty_posture)."""
    s = stringify(v)
    return "undefined" if s is None else s


def counterparty_posture(prior_observations, prior_receipts):
    obs = prior_observations if isinstance(prior_observations, list) else []
    rcpts = prior_receipts if isinstance(prior_receipts, list) else []
    by_hop = JSMap()
    for o in obs:
        hop = and_prop(o, "hop")
        k = _json_key([and_prop(o, "task_id"), prop(hop, "seq") if truthy(hop) else None])
        if not by_hop.has(k):
            by_hop.set(k, [])
        by_hop.get(k).append(o)
    unresolved = []
    for k, s in by_hop.items():
        if seq(aggregate_verdict(s), "disagreement"):
            unresolved.append({"at": k, "witnesses": [prop(o, "witness_id") for o in s]})
    by_grant = JSMap()
    for r in rcpts:
        k = and_prop(r, "grant_ref")
        if not by_grant.has(k):
            by_grant.set(k, [])
        by_grant.get(k).append(r)
    equivocations = []
    for k, s in by_grant.items():
        rec = reconcile_outcome(s, k)
        if rec["status"] == "equivocation":
            equivocations.append({"grant_ref": k, "receipt_ids": rec["receipt_ids"]})
    return {
        "prior_observation_hops": by_hop.size(),
        "prior_receipt_grants": by_grant.size(),
        "unresolved_disagreements": unresolved,
        "equivocations": equivocations,
        "note": "material for the caller's own decision, not a score and not a recommendation; absence of conflict here is not evidence of good conduct, only that none was presented",
    }


def preflight_report(inp):
    g, i = prop(inp, "grant"), prop(inp, "intent")
    resolve = prop(inp, "resolve") if callable(prop(inp, "resolve")) else (lambda _id: None)
    require_sig = not seq(prop(inp, "require_signature"), False)
    findings = []
    pf = verify_preflight(g, i)
    findings.extend(pf["findings"])
    sig_ok, sig_reason = True, "signature_not_required"
    if require_sig:
        sig_ok = verify_intent_sig(i, resolve(prop(i, "provider_id")))
        sig_reason = "intent_sig_valid" if sig_ok else "intent_sig_invalid"
    authorized = pf["ok"] and sig_ok
    posture = counterparty_posture(prop(inp, "priorObservations"), prop(inp, "priorReceipts"))
    establishes = []
    if authorized:
        establishes.append("the declared action equals, byte for byte, the action the caller signed in the grant (grant_ref " + _str(prop(g, "grant_ref")) + ")")
        establishes.append("the declaring provider is the executor the grant authorized, and the declaration falls in the grant window")
        if require_sig:
            establishes.append("the intent carries a valid provider signature over its own bytes, attributable to " + _str(prop(i, "provider_id")))
    else:
        establishes.append("nothing about authorization: " + (sig_reason if pf["ok"] else pf["reason"]))
    dne = [
        "this is NOT a decision to proceed: HORIZON SHIELD returns evidence, not allow or deny, and no trust score; the caller's own gateway decides",
        "that the provider will execute the action it declared: the receipt, checked after execution, is what catches a declared-then-diverged action",
        "that the counterparty is trustworthy: the posture surfaces presented conflicts as material, and absence of conflict is not evidence of good conduct",
        "that any action occurred in the world: this is a pre-execution declaration, and no signature has a side-effect oracle",
    ]
    return {"schema": "task-preflight-v0", "task_id": and_prop(g, "task_id"), "authorized": authorized, "status": pf["reason"],
            "signature": sig_reason, "findings": findings, "counterparty_posture": posture, "establishes": establishes,
            "does_not_establish": dne}


def _str(v):
    """String(v) for the concatenations in the report text."""
    if isinstance(v, str):
        return v
    if v is UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_num(v):
        from ._js import num_str
        return num_str(v)
    if isinstance(v, list):
        return ",".join("" if (x is None or x is UNDEF) else _str(x) for x in v)
    return "[object Object]"


# ---- provenance-v0/provenance_verify.mjs ----
def chain_continuous_set(observations):
    by_seq = JSMap()
    for o in observations:
        s = prop(prop(o, "hop"), "seq") if (truthy(o) and truthy(prop(o, "hop"))) else UNDEF
        if not by_seq.has(s):
            by_seq.set(s, [])
        by_seq.get(s).append(o)
    seqs = sort_numeric(by_seq.keys)
    for i, s in enumerate(seqs):
        if not seq(s, i):
            return {"ok": False, "reason": "seq_gap", "at": i}
    for s in seqs:
        for o in by_seq.get(s):
            if seq(s, 0):
                if not seq(prop(o, "prev_evidence_id"), None):
                    return {"ok": False, "reason": "root_prev_not_null", "at": 0}
            else:
                prior = [evidence_id(x) for x in by_seq.get(s - 1)]
                if not any(seq(p, prop(o, "prev_evidence_id")) for p in prior):
                    return {"ok": False, "reason": "broken_link", "at": s}
    return {"ok": True}


DOES_NOT_ESTABLISH = [
    "that any executed action occurred in the world: E1 compares the provider's signed claim to the caller's signed authorization and has no side-effect oracle",
    "that the reconciled outcome is the real-world outcome: E2 proves recoverability and surfaces equivocation, it does not prove truth",
    "that any witness is unaffiliated with the parties: R1 proves structural distinctness, not independence",
    "that bound evidence exists in its system or says what the provider claims, unless layers.evidence.checked_externally is true, and even then only what the injected lookup reported",
    "anything about time beyond the record contents: this verifier has no clock and saw no anchor; a Bitcoin anchor, if one exists, bounds the records separately",
    "that this is the only provenance these parties produced for this task_id",
]


def _hop_seq(o):
    """o.hop && o.hop.seq"""
    return and_prop(prop(o, "hop"), "seq")


def verify_provenance(inp):
    task_id = and_prop(inp, "task_id")
    # 0.1.6: a record slot or list element that is present but not an object (and not null/false) is malformed:
    # refused in its own step with reason record_not_object, otherwise not presented (provenance_verify.mjs).
    raw_observations = prop(inp, "observations") if isinstance(prop(inp, "observations"), list) else []
    malformed_observations = [i for i, o in enumerate(raw_observations) if not is_obj(o)]
    observations = [o for o in raw_observations if is_obj(o)]
    malformed_records = []

    def slot(name):
        v = prop(inp, name)
        if v is UNDEF or v is None or v is False:
            return None
        if is_obj(v):
            return v
        malformed_records.append(name)
        return None
    grant = slot("grant")
    primary_receipt = slot("receipt")
    receipts = []
    seen = set()
    extra = prop(inp, "receipts") if isinstance(prop(inp, "receipts"), list) else []
    for i, r in enumerate(extra):
        if not is_obj(r):
            malformed_records.append("receipts[" + str(i) + "]")
    extra = [r for r in extra if is_obj(r)]
    for r in ([primary_receipt] if truthy(primary_receipt) else []) + list(extra):
        try:
            key = canonical(r)
        except (CanonicalError, JSTypeError):
            key = str(len(receipts))
        if key not in seen:
            seen.add(key)
            receipts.append(r)
    resolve = prop(inp, "resolve") if callable(prop(inp, "resolve")) else (lambda _id: None)
    lookup = prop(inp, "lookup") if callable(prop(inp, "lookup")) else None
    require_sigs = not seq(prop(inp, "require_signatures"), False)
    intent = slot("intent")

    refusals, findings = [], []

    def refuse(code, why, extra=None):
        d = {"code": code, "why": why}
        d.update(extra or {})
        refusals.append(d)

    def note(code, why, extra=None):
        d = {"code": code, "why": why}
        d.update(extra or {})
        findings.append(d)

    for i in malformed_observations:
        refuse("delegation_observation_invalid", "an element of observations is not an object; it is not an observation and contributes nothing to steps 0, R3, R4 or linkage", {"index": i, "reason": "record_not_object"})
    for name in malformed_records:
        refuse("preflight_invalid" if name == "intent" else "execution_invalid", "the record slot " + name + " holds a value that is neither an object nor null/false; it is malformed and otherwise treated as not presented", {"record": name, "reason": "record_not_object"})

    layers = {"identity": None, "delegation": None, "execution": None, "preflight": None, "evidence": None, "linkage": None}

    # ---- 0. task identity across every presented record ----
    if not isinstance(task_id, str) or len(task_id) == 0:
        refuse("task_id_missing", "input.task_id must be a non-empty string")
    id_checks = []
    for i, o in enumerate(observations):
        id_checks.append({"record": "observation[" + str(i) + "]", "id": and_prop(o, "task_id")})
    if truthy(grant):
        id_checks.append({"record": "grant", "id": prop(grant, "task_id")})
    if truthy(intent):
        id_checks.append({"record": "intent", "id": prop(intent, "task_id")})
    for i, r in enumerate(receipts):
        id_checks.append({"record": "receipt[" + str(i) + "]", "id": and_prop(r, "task_id")})
    mismatched = [c["record"] for c in id_checks if not seq(c["id"], task_id)]
    layers["identity"] = {"records": len(id_checks), "mismatched": mismatched}
    if mismatched:
        refuse("task_id_mismatch", "every record must carry the task_id under verification", {"records": mismatched})

    # ---- 1. delegation layer (observation) ----
    if len(raw_observations) == 0:
        layers["delegation"] = {"present": False}
        note("no_delegation_observations", "no third-party observation of the delegation chain was presented; the execution layer is verified on its own")
    else:
        per = []
        for i, o in enumerate(observations):
            v = verify_observation(o)
            s = verify_signed(o, resolve) if require_sigs else {"ok": True, "reason": "signatures_not_required"}
            per.append({"index": i, "seq": _hop_seq(o), "witness_id": prop(o, "witness_id"), "ok": v["ok"] and s["ok"],
                        "reason": (("ok" if s["ok"] else s["reason"]) if v["ok"] else v["reason"])})
        for p in per:
            if not p["ok"]:
                refuse("delegation_observation_invalid", "an observation failed R1/R2 or its signatures", {"index": p["index"], "seq": p["seq"], "reason": p["reason"]})
        chain = chain_continuous_set(observations)
        if not chain["ok"]:
            refuse("delegation_chain_broken", "hop continuity (R3) does not hold over the presented set", {"reason": chain["reason"], "at": chain["at"]})
        by_seq = JSMap()
        for o in observations:
            s = _hop_seq(o)
            if not by_seq.has(s):
                by_seq.set(s, [])
            by_seq.get(s).append(o)
        hop_verdicts = [{"seq": s, "verdict": aggregate_verdict(by_seq.get(s)), "witnesses": [prop(o, "witness_id") for o in by_seq.get(s)]}
                        for s in sort_numeric(by_seq.keys)]
        for h in hop_verdicts:
            if seq(h["verdict"], "disagreement"):
                note("witness_disagreement", "witnesses of one hop disagree; the aggregate is disagreement, not the favorable verdict (R4)", {"seq": h["seq"], "witnesses": h["witnesses"]})
        layers["delegation"] = {"present": True, "observations": per, "chain": chain, "hop_verdicts": hop_verdicts}

    # ---- 2. execution layer (grant + receipt) ----
    reconciled = None
    if not truthy(grant) and len(receipts) == 0:
        layers["execution"] = {"present": False}
        note("no_execution_records", "no grant/receipt pair was presented; the delegation layer is verified on its own")
    elif not truthy(grant) or len(receipts) == 0:
        layers["execution"] = {"present": True, "complete": False}
        refuse("execution_incomplete_pair", "a grant and at least one receipt are both required to verify execution")
    else:
        primary = or_(primary_receipt, receipts[0])
        ve = verify_execution(grant, primary)
        for f in ve["findings"]:
            note(f["code"], f["why"])
        if not ve["ok"]:
            x = {"reason": ve["reason"]}
            if ve.get("record"):
                x["record"] = ve["record"]
            refuse("execution_invalid", "the grant/receipt pair failed recompute, binding, window or E1", x)
        sigs = {"ok": True, "reason": "signatures_not_required"}
        if require_sigs:
            sigs = verify_signed_execution(grant, primary, resolve)
            if not sigs["ok"]:
                refuse("execution_signature_invalid", "caller_sig or provider_sig does not verify", {"reason": sigs.get("reason", UNDEF)})
        for i, r in enumerate(receipts):
            if r is primary:
                continue
            if require_sigs and not verify_signed_execution(grant, r, resolve)["ok"]:
                continue
            vr = verify_execution(grant, r)
            if not vr["ok"]:
                refuse("execution_invalid", "a presented receipt failed recompute, binding, window or E1 against the grant",
                       {"reason": vr["reason"], "receipt_index": i, "receipt_id": and_prop(r, "receipt_id")})
        rec = (reconcile_signed(receipts, prop(grant, "grant_ref"), prop(grant, "provider_id"), resolve) if require_sigs
               else reconcile_outcome(receipts, prop(grant, "grant_ref")))
        if rec["status"] == "equivocation":
            refuse("execution_equivocation", "the authorized provider signed conflicting outcomes for one grant; no single outcome can be established (E2, fail-closed)", {"receipt_ids": rec["receipt_ids"]})
        elif rec["status"] != "reconciled":
            refuse("execution_unreconciled", "no authentic receipt reconciles this grant", {"status": rec["status"]})
        else:
            reconciled = next((r for r in receipts if seq(prop(r, "receipt_id"), rec["receipt_id"])), None) or primary
        layers["execution"] = {"present": True, "complete": True, "pair": ve["reason"], "signatures": sigs.get("reason", UNDEF),
                               "reconciliation": rec["status"], "receipt_id": or_(rec.get("receipt_id", UNDEF), None),
                               "outcome": or_(rec.get("outcome", UNDEF), None),
                               "action_binding": ve.get("action_binding") or {"grant": "absent", "receipt": "absent"}}

    # ---- 2b. preflight layer ----
    if not truthy(intent):
        layers["preflight"] = {"present": False}
    elif not truthy(grant):
        layers["preflight"] = {"present": True, "complete": False}
        refuse("preflight_without_grant", "an intent was presented without a grant; a pre-execution declaration can only be checked against the grant it references")
    else:
        pf = verify_preflight(grant, intent)
        for f in pf["findings"]:
            note(f["code"], f["why"])
        if not pf["ok"]:
            x = {"reason": pf["reason"]}
            if pf.get("record"):
                x["record"] = pf["record"]
            refuse("preflight_invalid", "the pre-execution intent is not authorized by the grant", x)
        isig = {"ok": True, "reason": "signatures_not_required"}
        if require_sigs:
            ok = verify_intent_sig(intent, resolve(prop(intent, "provider_id")))
            isig = {"ok": ok, "reason": "intent_sig_valid" if ok else "intent_sig_invalid"}
            if not ok:
                refuse("preflight_signature_invalid", "the intent signature does not verify", {"reason": isig["reason"]})
        dme = None
        if truthy(reconciled):
            dme = intent_matches_receipt(intent, reconciled)
            if not dme:
                note("declared_executed_divergence", "the pre-execution declaration and the executed action differ; the individual preflight or execution refusal above is the operative one")
        layers["preflight"] = {"present": True, "complete": True, "status": pf["reason"], "signature": isig["reason"], "declared_matches_executed": dme}

    # ---- 3. evidence layer ----
    ev_receipt = or_(or_(or_(reconciled, primary_receipt), receipts[0] if receipts else UNDEF), None)
    if truthy(ev_receipt):
        vev = verify_evidence(ev_receipt, lookup)
        layers["evidence"] = {"bound": vev["bound"], "checked_externally": vev["checked_externally"], "result": vev["reason"], "external": vev.get("external") or None}
        if not vev["ok"]:
            refuse("evidence_invalid", "the outcome's evidence pointer is malformed or was not confirmed by the injected lookup", {"reason": vev["reason"]})
        elif vev["bound"] and not vev["checked_externally"]:
            note("evidence_bound_unchecked", "the provider committed to an evidence pointer but no external lookup ran; a reader must check it in the named system")
        elif not vev["bound"]:
            note("no_evidence_bound", "the outcome carries no independently checkable pointer; it rests on the provider's signed claim alone")
    else:
        layers["evidence"] = {"bound": False, "checked_externally": False, "result": "no_receipt", "external": None}

    # ---- 4. linkage ----
    if len(raw_observations) and truthy(reconciled):
        rid = receipt_id(reconciled)
        links, bad = 0, []
        for i, o in enumerate(observations):
            conduct = and_prop(o, "conduct")
            ref = prop(conduct, "detail_ref") if truthy(conduct) else None
            if isinstance(ref, str) and ref.startswith(LINK_PREFIX):
                links += 1
                named = ref[len(LINK_PREFIX):]
                if named != rid:
                    bad.append({"index": i, "seq": _hop_seq(o), "named": named})
        layers["linkage"] = {"links": links, "mismatched": len(bad)}
        if bad:
            refuse("linkage_receipt_mismatch", "an observation names an execution receipt by digest that is not the reconciled receipt", {"records": bad})
        if links == 0:
            note("no_digest_link", "no observation names the execution receipt by digest; the layers verify independently but are not linked")
    else:
        layers["linkage"] = {"links": 0, "mismatched": 0}

    # ---- 5. verdict and honest scope ----
    verdict = "refused" if refusals else "accepted"
    est = []
    if verdict == "accepted":
        est.append("every presented record carries task_id " + task_id + " (" + str(len(id_checks)) + " records)")
        if layers["delegation"]["present"]:
            est.append("each of " + str(len(observations)) + " observations recomputes (R2) with a witness structurally distinct from both hop parties (R1)")
            est.append("the hop chain is contiguous from seq 0 and every prev_evidence_id resolves to a presented prior-hop observation (R3)")
            est.append("per-hop verdicts are aggregated over the full witness set, fail-closed; any disagreement is surfaced in layers.delegation.hop_verdicts, never collapsed (R4)")
            if require_sigs:
                est.append("each observation carries a valid witness signature and a valid delegator edge signature against the resolved keys")
        if layers["execution"]["present"]:
            est.append("the provider's signed executed_action equals the caller's signed authorization, byte for byte (E1)")
            est.append("the receipt hash-references this grant and comes from the executor the grant authorized (E3)")
            est.append("executed_at is a strict RFC3339 UTC instant inside the grant window")
            est.append("exactly one authentic outcome reconciles for this grant (E2)")
            if require_sigs:
                est.append("caller_sig and provider_sig verify against the resolved keys")
            ab = layers["execution"].get("action_binding") or {}
            carried = [k for k in ("grant", "receipt") if ab.get(k) == "recomputed"]
            if carried:
                est.append("the VATE-shaped action_binding on the " + " and ".join(carried) + " recomputes from the signed action under musubi-canonical-v0 (AB); a recipient reading digest.value as effective_request_hash reads the same bytes E1 compared")
        pfl = layers["preflight"]
        if pfl and pfl["present"] and pfl.get("complete"):
            est.append("the provider declared its action before execution and that declaration equals the caller authorization (preflight): the action was authorized before it ran")
            if pfl.get("declared_matches_executed") is True:
                est.append("declared equals authorized equals executed: the pre-execution intent, the grant and the reconciled receipt carry the same action byte for byte")
        if layers["evidence"]["bound"]:
            ev = prop(prop(ev_receipt, "outcome"), "evidence")
            pointer = _str(prop(ev, "kind")) + ":" + _str(prop(ev, "ref"))
            if layers["evidence"]["checked_externally"]:
                est.append("the outcome's evidence pointer " + pointer + " in " + _str(prop(ev, "system")) + " was confirmed by the injected lookup")
            else:
                est.append("the provider committed, under its signature, to evidence pointer " + pointer + " in " + _str(prop(ev, "system")) + "; a reader can check it there without the provider")
        if layers["linkage"]["links"] > 0:
            est.append(str(layers["linkage"]["links"]) + " observation(s) name the reconciled receipt by digest and the digest recomputes")
    else:
        est.append("nothing: see refusals")

    def uq(xs):
        return uniq([x for x in xs if isinstance(x, str) and len(x)])

    has_pair = truthy(grant) and len(receipts) > 0
    ab_applied = any(truthy(x) and prop(x, "action_binding") is not UNDEF for x in [grant] + receipts + [intent])
    rules = [
        {"id": "ID", "layer": "cross", "applied": True, "statement": "every presented record carries the task_id under verification"},
        {"id": "R1", "layer": "delegation", "applied": len(observations) > 0, "statement": "witness_id differs from hop.from and hop.to (structural independence)"},
        {"id": "R2", "layer": "delegation", "applied": len(observations) > 0, "statement": "evidence_id recomputes from the canonical preimage"},
        {"id": "R3", "layer": "delegation", "applied": len(observations) > 0, "statement": "hops contiguous from seq 0, each prev_evidence_id resolves to a presented prior-hop observation"},
        {"id": "R4", "layer": "delegation", "applied": len(observations) > 0, "statement": "per-hop verdicts aggregate over the full witness set; disagreement is surfaced, never collapsed"},
        {"id": "E1", "layer": "execution", "applied": has_pair, "statement": "the provider's signed executed_action equals the caller's signed authorization, byte for byte"},
        {"id": "E2", "layer": "execution", "applied": has_pair, "statement": "exactly one authentic outcome reconciles for the grant; conflicting outcomes are equivocation"},
        {"id": "E3", "layer": "execution", "applied": has_pair, "statement": "the receipt hash-references the grant and comes from the executor the grant authorized"},
        {"id": "AB", "layer": "execution", "applied": ab_applied, "statement": "an action_binding, when carried, recomputes from the signed action under the named canonicalization (musubi-canonical-v0); it is derived, outside the preimage, and adds no trust; one that does not recompute refuses the record"},
        {"id": "PF", "layer": "preflight", "applied": truthy(intent), "statement": "the declared pre-execution action equals the caller's grant, from the authorized executor, in the window"},
        {"id": "SIG", "layer": "attribution", "applied": require_sigs, "statement": "witness_sig, edge_sig, caller_sig and provider_sig verify against keys resolved from the signer identities"},
    ]
    signers = {
        "signatures_required": require_sigs,
        "witnesses": uq([and_prop(o, "witness_id") for o in observations]),
        "delegators": uq([and_prop(and_prop(o, "hop"), "from") if truthy(o) else o for o in observations]),
        "caller_id": prop(grant, "caller_id") if truthy(grant) and isinstance(prop(grant, "caller_id"), str) else None,
        "provider_id": prop(grant, "provider_id") if truthy(grant) and isinstance(prop(grant, "provider_id"), str) else None,
        "resolution": "identities are did:key or key_url; keys resolve offline from the identifier itself or from the resolve function the caller supplied",
    }
    return {
        "schema": "nenrin-provenance-verify-v0", "verifier_version": VERIFIER_VERSION, "task_id": task_id, "verdict": verdict,
        "refusals": refusals, "findings": findings, "layers": layers, "establishes": est, "does_not_establish": list(DOES_NOT_ESTABLISH),
        "rules": rules, "signers": signers,
        "recompute": {
            "offline": "this verifier opens no socket and has no clock; run it yourself on the same records and do not take this operator's word",
            "layers": ["../task-delegation-bind-v0/bind.mjs + sign.mjs (R1..R4, witness_sig, edge_sig)", "../task-execution-bind-v0/bind_exec.mjs + sign_exec.mjs (E1..E3, caller_sig, provider_sig)", "../task-execution-bind-v0/outcome_evidence.mjs (evidence pointer shape and optional lookup)"],
            "cross_layer": ["every record must carry the same task_id", "an observation's detail_ref nenrin-exec://<receipt_id> must equal receiptId(reconciled receipt)", "if an intent is present, its proposed_action must equal the grant action (preflight) and the reconciled receipt executed_action (declared equals authorized equals executed)", "if a grant, receipt or intent carries action_binding, digest.value must equal sha256(canonical(its action)) under musubi-canonical-v0; the field is outside every preimage and signature"],
        },
    }


# ---- provenance-v0/consume.mjs ----
def consume_evidence(inp):
    p = verify_provenance(inp)
    L = p["layers"]
    ex = L["execution"] if (L["execution"] and L["execution"]["present"] and L["execution"].get("complete")) else None
    pre = L["preflight"] if (L["preflight"] and L["preflight"]["present"] and L["preflight"].get("complete")) else None
    outcome = ex.get("outcome") if ex else None
    facts = {
        "verified": p["verdict"] == "accepted",
        "authorized_before_execution": True if (pre and not any(r["code"].startswith("preflight_") for r in p["refusals"])) else None,
        "executed_matches_authorization": (ex["pair"] == "action_bound") if ex else None,
        "outcome": ({"status": prop(outcome, "status"), "reconciled": ex["reconciliation"] == "reconciled"} if (ex and truthy(outcome)) else None),
        "hops": ([{"seq": h["seq"], "verdict": h["verdict"], "disagreement": seq(h["verdict"], "disagreement")} for h in L["delegation"]["hop_verdicts"]]
                 if (L["delegation"] and L["delegation"]["present"]) else []),
        "evidence_pointer": ({"bound": True, "checked_externally": L["evidence"]["checked_externally"]} if (L["evidence"] and L["evidence"]["bound"])
                             else {"bound": False, "checked_externally": False}),
        "digest_links": L["linkage"]["links"] if L["linkage"] else 0,
    }
    conflicts = {
        "refused": p["verdict"] == "refused",
        "refusal_codes": [r["code"] for r in p["refusals"]],
        "disagreements": [{"seq": f.get("seq", UNDEF), "witnesses": f.get("witnesses", UNDEF)} for f in p["findings"] if f["code"] == "witness_disagreement"],
        "equivocations": [{"receipt_ids": f.get("receipt_ids", UNDEF)} for f in p["refusals"] if f["code"] == "execution_equivocation"],
    }
    g, it = and_prop(inp, "grant"), and_prop(inp, "intent")
    anchors = {
        "grant_ref": prop(g, "grant_ref") if (truthy(inp) and truthy(g)) else None,
        "intent_id": prop(it, "intent_id") if (truthy(inp) and truthy(it)) else None,
        "reconciled_receipt_id": ex["receipt_id"] if (ex and truthy(ex["receipt_id"])) else None,
        "observation_evidence_ids": [and_prop(o, "evidence_id") for o in (prop(inp, "observations") if (truthy(inp) and isinstance(prop(inp, "observations"), list)) else [])],
    }
    return {
        "schema": "nenrin-consume-v0", "consume_version": CONSUME_VERSION, "task_id": p["task_id"],
        "facts": facts, "conflicts": conflicts, "anchors": anchors,
        "does_not_establish": p["does_not_establish"],
        "contract": "NENRIN returns verified evidence and its honest limits. It computes no trust score and makes no allow or deny decision. The consuming engine reads facts and conflicts and decides for itself. Absence of conflict is not evidence of good conduct; it may mean no evidence was presented.",
        "reverify": {
            "how": "re-run nenrin-provenance-verify-v0 on the same records with your own resolve and lookup; every hash and signature recomputes offline, with no clock and no network",
            "provenance": p["recompute"],
        },
        "provenance": p,
    }


def posture_line(consumed):
    f, c = consumed["facts"], consumed["conflicts"]
    return {
        "task_id": consumed["task_id"],
        "verified": f["verified"],
        "hops": len(f["hops"]),
        "disagreement_hops": len([h for h in f["hops"] if h["disagreement"]]),
        "equivocations": len(c["equivocations"]),
        "outcome_status": f["outcome"]["status"] if f["outcome"] else None,
        "evidence_checked_externally": f["evidence_pointer"]["checked_externally"],
        "note": "counts only; not a score, not a verdict, not a recommendation",
    }


def candidate_evidence_set(task_id, candidates):
    evaluated = []
    for c in candidates:
        records = prop(c, "records")
        bundle = consume_evidence(assign(records, {"task_id": task_id}))
        evaluated.append({"candidate_id": prop(c, "candidate_id"), "bundle": bundle, "posture": posture_line(bundle)})
    return {
        "schema": "nenrin-candidate-evidence-v0",
        "version": CANDIDATE_EVIDENCE_VERSION,
        "task_id": task_id,
        "candidates": [{"candidate_id": e["candidate_id"], "verified": e["bundle"]["facts"]["verified"],
                        "disagreement_hops": e["posture"]["disagreement_hops"], "equivocations": e["posture"]["equivocations"],
                        "outcome_status": e["posture"]["outcome_status"], "evidence_checked_externally": e["posture"]["evidence_checked_externally"],
                        "anchors": e["bundle"]["anchors"]} for e in evaluated],
        "contract": "NENRIN supplies verified per-candidate evidence and surfaced conflicts. It does not decide which candidates are permitted, it does not order them, and it computes no trust score. The trust filter decides permitted; the ordering primitive (for example ARBITER) decides order.",
        "run_record": {
            "task_id": task_id,
            "evaluated_candidates": [e["candidate_id"] for e in evaluated],
            "permitted": None,
            "order": None,
            "evidence_anchors": [{"candidate_id": e["candidate_id"], "anchors": e["bundle"]["anchors"]} for e in evaluated],
            "note": "permitted is filled by the trust filter and order by the orderer; NENRIN records them and can anchor this run_record to Bitcoin so a third party recomputes the permitted set and the returned order rather than trusting the operator",
        },
        "does_not_establish": [
            "which candidates are permitted: that is the trust filter's decision, from this evidence and its own policy",
            "the order of the candidates: that is the orderer's output, for example ARBITER, over the permitted set",
            "any trust score: none is computed here, and absence of conflict is not evidence of good conduct",
        ],
        "bundles": [e["bundle"] for e in evaluated],
    }


# ---- did:key resolution (offline) ----
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s):
    b = [0]
    for ch in s:
        carry = _B58.find(ch)
        if carry < 0:
            raise ValueError("bad base58 char")
        for j in range(len(b)):
            carry += b[j] * 58
            b[j] = carry & 0xFF
            carry >>= 8
        while carry > 0:
            b.append(carry & 0xFF)
            carry >>= 8
    zeros = 0
    while zeros < len(s) and s[zeros] == "1":
        zeros += 1
    return bytes([0] * zeros + b[::-1])


def public_key_from_did_key(did):
    """32 raw Ed25519 public key bytes from a did:key (multicodec 0xed01). Raises on anything else."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    payload = _b58decode(did[len("did:key:z"):])
    if len(payload) < 2 or payload[0] != 0xED or payload[1] != 0x01:
        raise ValueError("not an ed25519-pub did:key")
    raw = payload[2:]
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    if not ed25519_key_ok(raw):
        raise ValueError("not a usable Ed25519 key (it must be the canonical encoding of a point in the prime-order subgroup)")
    return raw


def did_key_resolver(identifier):
    try:
        return public_key_from_did_key(identifier)
    except Exception:
        return None
