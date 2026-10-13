#!/usr/bin/env python3
"""Clean-room verifier for nenrin-provenance-verify-v0, written from specs/VERIFIER.md only.

Usage:
  python3 verify.py --vectors               check canonical() against specs/canonical_vectors.json
  python3 verify.py --corpus                run all fixtures, write impl/out.json
  python3 verify.py bundle.json [...]       print verdict signatures

Every place a guess was made is tagged GUESS-<n>; the numbers match GAPS.md.
"""
import base64
import datetime
import hashlib
import json
import os
import re
import sys
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Strict JSON loading
# ---------------------------------------------------------------------------

class CanonError(Exception):
    pass


class BadNumber:
    """A JSON number token with a fraction or exponent. GUESS-1: refused lexically."""
    def __init__(self, text):
        self.text = text

    def __repr__(self):
        return "BadNumber(%s)" % self.text


class DupDict(dict):
    """An object that had a duplicate key in the source. GUESS-2: it cannot be canonicalized."""
    pass


def _pairs(pairs):
    seen = set()
    dup = False
    for k, _ in pairs:
        if k in seen:
            dup = True
        seen.add(k)
    d = DupDict(pairs) if dup else dict(pairs)
    return d


def _bad_constant(name):
    raise ValueError("bad_json: %s" % name)  # NaN / Infinity are not JSON


def load_json_text(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_float=BadNumber,
                      parse_constant=_bad_constant)


def load_json(path):
    with open(path, "rb") as f:
        return load_json_text(f.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Canonical form (musubi-canonical-v0)
# ---------------------------------------------------------------------------

MAX_SAFE = 2 ** 53 - 1
_SHORT = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}


def _canon_str(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _SHORT:
            out.append(_SHORT[c])
        elif c < 0x20:
            out.append("\\u%04x" % c)
        elif 0xD800 <= c <= 0xDFFF:
            out.append("\\u%04x" % c)  # lone surrogate (a paired one never reaches here in Python str)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canon(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if -MAX_SAFE <= v <= MAX_SAFE:
            return str(v)
        raise CanonError("unsafe_number")
    if isinstance(v, (float, BadNumber)):
        raise CanonError("non_integer_number")
    if isinstance(v, str):
        return _canon_str(v)
    if isinstance(v, list):
        return "[" + ",".join(_canon(x) for x in v) + "]"
    if isinstance(v, dict):
        if isinstance(v, DupDict):
            raise CanonError("duplicate_key")
        for k in v:
            if not all(0x20 <= ord(c) <= 0x7E for c in k):
                raise CanonError("key_not_printable_ascii")
        keys = sorted(v.keys())  # printable ASCII: Python str order == code point order
        return "{" + ",".join(_canon_str(k) + ":" + _canon(v[k]) for k in keys) + "}"
    raise CanonError("bad_json")


def canonical(v):
    """UTF-8 bytes. Lone surrogates are already escaped, so plain utf-8 encoding is safe."""
    return _canon(v).encode("utf-8")


def sha256(v):
    return hashlib.sha256(canonical(v)).hexdigest()


def try_sha256(v):
    try:
        return sha256(v)
    except CanonError:
        return None


def canon_eq(a, b):
    try:
        return canonical(a) == canonical(b)
    except CanonError:
        return False  # GUESS-3: an uncanonicalizable value never compares equal


# ---------------------------------------------------------------------------
# did:key, base64, signatures
# ---------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    lead = len(s) - len(s.lstrip("1"))
    return b"\x00" * lead + body


def resolve_did_key(did):
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        return None
    raw = b58decode(did[len("did:key:z"):])
    if raw is None or len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw[2:])
    except Exception:
        return None


_B64 = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")


def b64decode_std(s):
    if not isinstance(s, str) or len(s) % 4 != 0 or not _B64.match(s):
        return None  # GUESS-4: padding required, no whitespace, no url-safe alphabet
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def sig_verifies(sig_b64, signer_did, preimage):
    key = resolve_did_key(signer_did)
    if key is None:
        return False
    sig = b64decode_std(sig_b64)
    if sig is None or len(sig) != 64:
        return False
    try:
        msg = canonical(preimage)
    except CanonError:
        return False
    try:
        key.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Preimages
# ---------------------------------------------------------------------------

DERIVED = {
    "observation": ("evidence_id", "witness_sig", "edge_sig", "consent"),
    "grant": ("grant_ref", "caller_sig", "action_binding"),
    "receipt": ("receipt_id", "provider_sig", "action_binding"),
    "intent": ("intent_id", "intent_sig", "action_binding"),
}


def preimage(rec, kind):
    if not isinstance(rec, dict):
        return None  # GUESS-5: a non-object record has no preimage; every check on it fails
    drop = DERIVED[kind]
    p = {k: v for k, v in rec.items() if k not in drop}
    if isinstance(rec, DupDict):
        p = DupDict(p)
    return p


def recomputed_id(rec, kind):
    p = preimage(rec, kind)
    return None if p is None else try_sha256(p)


def id_recomputes(rec, kind, field):
    rid = recomputed_id(rec, kind)
    return rid is not None and isinstance(rec, dict) and rec.get(field) == rid


def g(rec, key, default=None):
    return rec.get(key, default) if isinstance(rec, dict) else default


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

_TS = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z", re.ASCII)


def parse_ts(s):
    """Return a sortable exact instant (Decimal seconds since epoch) or None."""
    if not isinstance(s, str):
        return None
    m = _TS.fullmatch(s)  # GUESS-6: ASCII digits only, whole string (no trailing newline)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    try:
        # GUESS-7: "a real instant" = valid Gregorian date, hour 0-23, minute 0-59, second 0-59
        dt = datetime.datetime(y, mo, d, h, mi, se, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    frac = Decimal(m.group(7)) if m.group(7) else Decimal(0)
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    whole = (dt - epoch).days * 86400 + (dt - epoch).seconds
    return Decimal(whole) + frac  # GUESS-8: exact comparison, not millisecond-truncated


# ---------------------------------------------------------------------------
# action_binding
# ---------------------------------------------------------------------------

def action_binding_reason(rec, action_field):
    """None if fine (absent or correct), else a reason string."""
    if not isinstance(rec, dict) or "action_binding" not in rec:
        return None  # GUESS-9: only key absence is "absent"; a null value is present and malformed
    ab = rec["action_binding"]
    if not isinstance(ab, dict):
        return "action_binding_malformed"
    if ab.get("type") != "canonical_request_digest":
        return "action_binding_malformed"
    dg = ab.get("digest")
    if not isinstance(dg, dict) or dg.get("alg") != "sha-256" or not isinstance(dg.get("value"), str):
        return "action_binding_malformed"
    if ab.get("canonicalization") != "musubi-canonical-v0" or \
            ab.get("preimage_profile") != "task-execution-bind-v0/action":
        return "action_binding_unknown_profile"
    if action_field not in rec:
        return "action_binding_mismatch"  # GUESS-10
    h = try_sha256(rec[action_field])
    if h is None or dg["value"] != h:  # GUESS-11: exact (lowercase) string compare; extra keys allowed
        return "action_binding_mismatch"
    return None


# ---------------------------------------------------------------------------
# The procedure
# ---------------------------------------------------------------------------

EVIDENCE_KINDS = {"bitcoin_tx", "ledger_record", "document_sha256", "url_sha256"}
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def js_falsy(v):
    # GUESS-12: "falsy" read in the JavaScript sense: undefined, null, false, 0, "" (no NaN in JSON).
    # {} and [] are truthy (present), unlike Python.
    return v is None or v is False or (isinstance(v, int) and not isinstance(v, bool) and v == 0) or v == ""


def is_present(bundle, key):
    # GUESS-13: an optional key whose value is null counts as absent.
    return isinstance(bundle, dict) and bundle.get(key) is not None


def verify(bundle, lookup=None):
    refusals, findings = [], []
    reasons = []  # (code, reason) for readers

    def refuse(code, reason=None):
        refusals.append(code)
        reasons.append((code, reason))

    if not isinstance(bundle, dict):
        bundle = {}  # GUESS-14: non-object bundle treated as empty object
    require_sigs = bundle.get("require_signatures", True)
    require_sigs = require_sigs is not False  # GUESS-15: only literal false turns signatures off

    obs = bundle.get("observations")
    if obs is None:
        obs = []
    if not isinstance(obs, list):
        obs = []  # GUESS-16
    grant = bundle.get("grant") if is_present(bundle, "grant") else None
    intent = bundle.get("intent") if is_present(bundle, "intent") else None

    # receipt set
    rset = []
    seen = []
    cand = []
    if is_present(bundle, "receipt"):
        cand.append(bundle["receipt"])
    rs = bundle.get("receipts")
    if isinstance(rs, list):
        cand.extend(rs)
    for r in cand:
        try:
            cb = canonical(r)
        except CanonError:
            cb = None  # GUESS-17: an uncanonicalizable receipt is never a duplicate, kept
        if cb is not None and cb in seen:
            continue
        if cb is not None:
            seen.append(cb)
        rset.append(r)
    primary = rset[0] if rset else None

    # Step 0, identity
    tid = bundle.get("task_id")
    tid_ok = isinstance(tid, str) and tid != ""
    if not tid_ok:
        refuse("task_id_missing")
    records = list(obs) + ([grant] if grant is not None else []) + \
        ([intent] if intent is not None else []) + list(rset)
    mismatch = False
    for r in records:
        if not tid_ok or g(r, "task_id") != tid:
            mismatch = True
    if mismatch:
        refuse("task_id_mismatch")

    # Step 1, delegation
    rec_ids = [recomputed_id(o, "observation") for o in obs]
    if not obs:
        findings.append("no_delegation_observations")
    else:
        for o, rid in zip(obs, rec_ids):
            hop = g(o, "hop")
            wid = g(o, "witness_id")
            reason = None
            if wid == g(hop, "from") or wid == g(hop, "to"):
                reason = "witness_not_independent"
            elif rid is None or g(o, "evidence_id") != rid:
                reason = "recompute_mismatch"
            elif require_sigs and not sig_verifies(g(o, "witness_sig"), wid, preimage(o, "observation")):
                reason = "witness_sig_invalid"
            elif require_sigs and not sig_verifies(
                    g(o, "edge_sig"), g(hop, "from"),
                    {"task_id": g(o, "task_id"), "hop": hop}):  # GUESS-18: missing fields
                reason = "edge_sig_invalid"
            if reason:
                refuse("delegation_observation_invalid", reason)

        # R3
        by_seq = {}
        bad_seq_type = False
        for o, rid in zip(obs, rec_ids):
            s = g(g(o, "hop"), "seq")
            if not (isinstance(s, int) and not isinstance(s, bool)):
                bad_seq_type = True  # GUESS-19
                continue
            by_seq.setdefault(s, []).append((o, rid))
        r3 = None
        seqs = sorted(by_seq)
        if bad_seq_type or seqs != list(range(len(seqs))):
            r3 = "seq_gap"
        if r3 is None:
            for o, _ in by_seq.get(0, []):
                if g(o, "prev_evidence_id") is not None:
                    r3 = "root_prev_not_null"
                    break
        if r3 is None:
            for s in seqs:
                if s == 0:
                    continue
                prior = {rid for _, rid in by_seq.get(s - 1, []) if rid is not None}
                for o, _ in by_seq[s]:
                    if g(o, "prev_evidence_id") not in prior:
                        r3 = "broken_link"
                        break
                if r3:
                    break
        if r3:
            refuse("delegation_chain_broken", r3)

        # R4
        for s in seqs:
            verdicts = set()
            for o, _ in by_seq[s]:
                v = g(g(o, "conduct"), "verdict")
                try:
                    verdicts.add(canonical(v))  # GUESS-20: distinct by canonical bytes
                except CanonError:
                    verdicts.add(repr(v).encode())
            if len(verdicts) > 1:
                findings.append("witness_disagreement")

    # Step 2, execution
    reconciled = None
    grant_rid = recomputed_id(grant, "grant") if grant is not None else None

    def pair_check(rcpt, with_findings):
        """Returns None on pass, else reason. GUESS-21: E1 is part of the pair check (also in 2c)."""
        if grant_rid is None or g(grant, "grant_ref") != grant_rid:
            return "grant_recompute_mismatch"
        if not id_recomputes(rcpt, "receipt", "receipt_id"):
            return "receipt_recompute_mismatch"
        r = action_binding_reason(grant, "action")
        if r:
            return r
        r = action_binding_reason(rcpt, "executed_action")
        if r:
            return r
        if g(rcpt, "grant_ref") != grant_rid:
            return "receipt_unbound"
        r = window_check(g(rcpt, "executed_at"), "executed_at" in rcpt, g(grant, "provider_id"),
                         g(rcpt, "provider_id"))
        if r:
            return r
        if with_findings:
            add_grant_findings()
        if not canon_eq(g(grant, "action"), g(rcpt, "executed_action")):
            return "action_diverged"
        return None

    def window_check(t, t_present, gprov, rprov):
        nb, na = g(grant, "not_before"), g(grant, "not_after")
        # GUESS-22: "where present" = key present and not null; a missing/null executed_at is
        # invalid_timestamp (it cannot be placed in any window).
        tt = parse_ts(t)
        if tt is None:
            return "invalid_timestamp"
        nbt = None
        nat = None
        if nb is not None:
            nbt = parse_ts(nb)
            if nbt is None:
                return "invalid_timestamp"
        if na is not None:
            nat = parse_ts(na)
            if nat is None:
                return "invalid_timestamp"
        if not (gprov is None or gprov == rprov):
            return "provider_not_authorized"
        if (nbt is not None and tt < nbt) or (nat is not None and tt > nat):
            return "outside_authorization_window"
        return None

    def add_grant_findings():
        gp = g(grant, "provider_id")
        if gp is None:
            findings.append("open_grant")
        elif gp == g(grant, "caller_id"):
            findings.append("self_authorized")

    if grant is None and not rset:
        findings.append("no_execution_records")
    elif grant is None or not rset:
        refuse("execution_incomplete_pair")
    else:
        # a
        r = pair_check(primary, True)
        if r:
            refuse("execution_invalid", r)
        # b
        if require_sigs:
            if not sig_verifies(g(grant, "caller_sig"), g(grant, "caller_id"), preimage(grant, "grant")):
                refuse("execution_signature_invalid", "caller_sig")
            elif not sig_verifies(g(primary, "provider_sig"), g(primary, "provider_id"),
                                  preimage(primary, "receipt")):
                refuse("execution_signature_invalid", "provider_sig")
        # c
        caller_ok = (not require_sigs) or sig_verifies(g(grant, "caller_sig"), g(grant, "caller_id"),
                                                       preimage(grant, "grant"))
        for rc in rset[1:]:
            if require_sigs and (not caller_ok or not sig_verifies(
                    g(rc, "provider_sig"), g(rc, "provider_id"), preimage(rc, "receipt"))):
                continue
            r = pair_check(rc, False)
            if r:
                refuse("execution_invalid", r)
        # d
        gp = g(grant, "provider_id")
        if gp is None:
            refuse("execution_unreconciled", "no_authorized_provider")
        else:
            auth = []
            for rc in rset:
                if g(rc, "grant_ref") != g(grant, "grant_ref"):
                    continue
                if g(rc, "provider_id") != gp:
                    continue
                if not id_recomputes(rc, "receipt", "receipt_id"):
                    continue
                if require_sigs and not sig_verifies(g(rc, "provider_sig"), gp, preimage(rc, "receipt")):
                    continue
                auth.append(rc)
            ids = []
            for rc in auth:
                if rc["receipt_id"] not in ids:
                    ids.append(rc["receipt_id"])
            if not ids:
                refuse("execution_unreconciled")
            elif len(ids) > 1:
                refuse("execution_equivocation")
            else:
                reconciled = next(rc for rc in auth if rc["receipt_id"] == ids[0])

    # Step 3, preflight
    if intent is not None:
        if grant is None:
            refuse("preflight_without_grant")
        else:
            def pre():
                if grant_rid is None or g(grant, "grant_ref") != grant_rid:
                    return "grant_recompute_mismatch"
                if not id_recomputes(intent, "intent", "intent_id"):
                    return "intent_recompute_mismatch"
                r = action_binding_reason(intent, "proposed_action")
                if r:
                    return r
                if g(intent, "grant_ref") != grant_rid:
                    return "intent_unbound"
                r = window_check(g(intent, "declared_at"), True, g(grant, "provider_id"),
                                 g(intent, "provider_id"))
                if r:
                    return r
                add_grant_findings()
                if not canon_eq(g(grant, "action"), g(intent, "proposed_action")):
                    return "action_diverged"
                return None
            r = pre()
            if r:
                refuse("preflight_invalid", r)
            if require_sigs and not sig_verifies(g(intent, "intent_sig"), g(intent, "provider_id"),
                                                 preimage(intent, "intent")):
                refuse("preflight_signature_invalid")
            if reconciled is not None and not canon_eq(g(intent, "proposed_action"),
                                                       g(reconciled, "executed_action")):
                findings.append("declared_executed_divergence")

    # Step 4, evidence
    target = reconciled if reconciled is not None else primary
    if rset:
        outcome = g(target, "outcome")
        E = g(outcome, "evidence")  # GUESS-23: missing/non-object outcome => E absent
        if js_falsy(E):
            findings.append("no_evidence_bound")
        else:
            wf = (isinstance(E, dict) and E.get("kind") in EVIDENCE_KINDS
                  and isinstance(E.get("ref"), str) and _HEX64.fullmatch(E["ref"]) is not None
                  and isinstance(E.get("system"), str) and E["system"] != "")
            if not wf:
                refuse("evidence_invalid", "malformed")
            elif lookup is None:
                findings.append("evidence_bound_unchecked")
            else:
                res = lookup(E)
                if res is not True:
                    refuse("evidence_invalid", "lookup")

    # Step 5, linkage
    if obs and reconciled is not None:
        rid = recomputed_id(reconciled, "receipt")
        links = [o for o in obs if isinstance(g(g(o, "conduct"), "detail_ref"), str)
                 and g(g(o, "conduct"), "detail_ref").startswith("nenrin-exec://")]
        if not links:
            findings.append("no_digest_link")
        elif any(g(g(o, "conduct"), "detail_ref")[len("nenrin-exec://"):] != rid for o in links):
            refuse("linkage_receipt_mismatch")

    # Step 6
    return {
        "verdict": "refused" if refusals else "accepted",
        "refusals": sorted(set(refusals)),
        "findings": sorted(set(findings)),
    }, reasons


def check_vectors():
    d = load_json(os.path.join(ROOT, "specs", "canonical_vectors.json"))
    results = []
    for v in d["vectors"]:
        b = canonical(v["value"])
        h = hashlib.sha256(b).hexdigest()
        ok_h = h == v["sha256"]
        ok_n = len(b) == v.get("bytes")
        results.append((v["name"], ok_h, ok_n, len(b), v.get("bytes")))
    return results


def run_corpus():
    out = {}
    detail = {}
    for tag, sub in (("v0", "v0"), ("v01", "v01")):
        out[tag] = {}
        fx = os.path.join(ROOT, sub, "fixtures")
        for fn in sorted(os.listdir(fx)):
            if not fn.endswith(".json"):
                continue
            sig, reasons = verify(load_json(os.path.join(fx, fn)))
            out[tag][fn[:-5]] = sig
            detail["%s/%s" % (tag, fn[:-5])] = reasons
    with open(os.path.join(ROOT, "impl", "out.json"), "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    return out, detail


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--vectors"]:
        for name, okh, okn, n, en in check_vectors():
            print("%s  sha256:%s bytes:%s(%d/%s)  %s" % ("PASS" if okh and okn else "FAIL",
                  okh, okn, n, en, name))
    elif args == ["--corpus"]:
        out, detail = run_corpus()
        for tag in out:
            for k, v in out[tag].items():
                print(tag, k, json.dumps(v), [r for r in detail["%s/%s" % (tag, k)]])
    else:
        for p in args:
            print(p, json.dumps(verify(load_json(p))[0]))
