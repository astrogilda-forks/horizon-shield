#!/usr/bin/env python3
"""Clean-room verifier for nenrin-provenance-verify-v0 bundles, written from the three spec texts only
(delegation_SPEC.md = task-delegation-bind-v0, execution_SPEC.md = task-execution-bind-v0, PROVENANCE.md).

Output per bundle: {"verdict", "refusals" (sorted codes), "findings" (sorted codes)}.
Reasons are tracked internally (see --reasons) but are not part of the signature (PROVENANCE.md).

Every place where the spec text did not decide the behaviour is a named interpretation flag (INTERP below).
The defaults are the reading documented in GAPS.md; the alternatives can be toggled with --set FLAG=0/1.
"""
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------- interpretation flags (see GAPS.md)
INTERP = {
    # no_digest_link fires whenever no observation names the RECONCILED receipt (literal definition),
    # even if some observation names a different receipt. 0 = only when no observation carries any
    # nenrin-exec:// link at all.
    "no_digest_link_literal": 1,
    # 1 = receipts that fail provider_sig or come from a non-authorized provider are silently dropped
    # from the reconciliation set (reconcileSigned "griefing" reading); a refusal is raised only if that
    # leaves nothing reconciled. 0 = every presented receipt is checked and any failure is a refusal.
    "receipt_set_filter": 0,
    # 1 = also raise execution_unreconciled when zero receipts reconcile although a more specific
    # execution refusal (signature, invalid) already explains it.
    "unreconciled_cascade": 0,
    # 1 = an observation that failed R1/R2/signature is excluded from the R3 set and from linkage.
    "invalid_obs_excluded": 0,
    # 1 = when the bundle task_id is missing, every record with a non-empty task_id is also a mismatch.
    "task_missing_cascade": 0,
    # 1 = a receipt that fails E1/window/timestamp is not eligible to reconcile.
    "reconcile_requires_valid": 0,
    # 0 = a refused report carries no findings.
    "findings_on_refused": 1,
    # 1 = an intent alone counts as an execution record (suppresses no_execution_records).
    "intent_counts_as_execution_record": 0,
    # 1 = R3 additionally requires hop[n].from == hop[n-1].to.
    "r3_party_continuity": 0,
    # 1 = observed_at is held to the strict RFC3339 UTC rule (refusal delegation_observation_invalid).
    "check_observed_at": 1,
}

EVIDENCE_KINDS = {"bitcoin_tx", "ledger_record", "document_sha256", "url_sha256"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$")
MAX_SAFE = 2 ** 53 - 1
EXEC_PREFIX = "nenrin-exec://"

# ---------------------------------------------------------------- strict JSON (delegation_SPEC "Refusals, before anything is hashed")


class StrictJSONError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _pairs_hook(pairs):
    seen = set()
    out = {}
    for k, v in pairs:
        if k in seen:
            raise StrictJSONError("duplicate_key")
        if not all(0x20 <= ord(c) <= 0x7E for c in k):
            raise StrictJSONError("key_not_printable_ascii")
        seen.add(k)
        out[k] = v
    return out


def _parse_float(s):
    raise StrictJSONError("non_integer_number")


def _parse_int(s):
    n = int(s)
    if abs(n) > MAX_SAFE:
        raise StrictJSONError("unsafe_number")
    return n


def _parse_const(s):  # NaN, Infinity
    raise StrictJSONError("bad_json")


def strict_loads(text):
    try:
        return json.loads(text, object_pairs_hook=_pairs_hook, parse_float=_parse_float,
                          parse_int=_parse_int, parse_constant=_parse_const)
    except StrictJSONError:
        raise
    except ValueError:
        raise StrictJSONError("bad_json")


# ---------------------------------------------------------------- canonical form musubi-canonical-v0


def _esc(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c < 0x20:
            out.append({8: "\\b", 12: "\\f", 10: "\\n", 13: "\\r", 9: "\\t"}.get(c, "\\u%04x" % c))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE:
            raise StrictJSONError("unsafe_number")
        return str(v)
    if isinstance(v, float):
        raise StrictJSONError("non_integer_number")
    if isinstance(v, str):
        return _esc(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not all(0x20 <= ord(c) <= 0x7E for c in k):
                raise StrictJSONError("key_not_printable_ascii")
        return "{" + ",".join(_esc(k) + ":" + canonical(v[k]) for k in sorted(v)) + "}"
    raise StrictJSONError("bad_json")


def sha256hex(v):
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()


def without(d, keys):
    return {k: v for k, v in d.items() if k not in keys}


# ---------------------------------------------------------------- did:key (not specified in the texts; W3C did:key Ed25519)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s):
    n = 0
    for c in s:
        i = _B58.find(c)
        if i < 0:
            raise ValueError("bad base58")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def resolve(did):
    """did:key:z<base58btc(0xed 0x01 || 32-byte Ed25519 key)> -> public key, or None."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        return None
    try:
        raw = _b58decode(did[len("did:key:z"):])
    except ValueError:
        return None
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw[2:])
    except Exception:
        return None


def verify_sig(did, message_obj, sig_b64):
    key = resolve(did)
    if key is None or not isinstance(sig_b64, str):
        return False
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    if len(sig) != 64:
        return False
    try:
        key.verify(sig, canonical(message_obj).encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- timestamps


def parse_ts(s):
    if not isinstance(s, str):
        return None
    m = TS_RE.match(s)
    if not m:
        return None
    y, mo, d, hh, mi, ss = (int(x) for x in m.groups()[:6])
    frac = m.group(7)
    us = int((frac[1:] + "000000")[:6]) if frac else 0
    try:
        return datetime(y, mo, d, hh, mi, ss, us, tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------- derived-field sets
OBS_DERIVED = {"evidence_id", "witness_sig", "edge_sig", "consent"}
GRANT_DERIVED = {"grant_ref", "caller_sig", "action_binding"}
RECEIPT_DERIVED = {"receipt_id", "provider_sig", "action_binding"}
INTENT_DERIVED = {"intent_id", "intent_sig", "action_binding"}  # guessed: INTENT_DERIVED is named, never listed


def check_action_binding(rec, action_field):
    """Rule AB. Returns None (absent or ok) or a reason string."""
    if "action_binding" not in rec:
        return None
    ab = rec["action_binding"]
    if not isinstance(ab, dict) or set(ab) != {"type", "canonicalization", "preimage_profile", "digest"}:
        return "action_binding_malformed"
    dg = ab.get("digest")
    if ab.get("type") != "canonical_request_digest" or not isinstance(dg, dict) \
            or set(dg) != {"alg", "value"} or dg.get("alg") != "sha-256" \
            or not isinstance(dg.get("value"), str) or not HEX64.match(dg["value"]):
        return "action_binding_malformed"
    if ab.get("canonicalization") != "musubi-canonical-v0" or \
            ab.get("preimage_profile") != "task-execution-bind-v0/action":
        return "action_binding_unknown_profile"
    if dg["value"] != sha256hex(rec.get(action_field)):
        return "action_binding_mismatch"
    return None


def evidence_well_formed(ev):
    if not isinstance(ev, dict) or set(ev) != {"kind", "ref", "system"}:
        return False
    if ev["kind"] not in EVIDENCE_KINDS:
        return False
    if not isinstance(ev["ref"], str) or not isinstance(ev["system"], str) or not ev["system"]:
        return False
    # ref shape per kind is not specified; all four kinds are hash-like, require 64 lowercase hex.
    return bool(HEX64.match(ev["ref"]))


# ---------------------------------------------------------------- the verifier


def verify_bundle(b, interp=None):
    I = dict(INTERP)
    if interp:
        I.update(interp)
    refusals = []  # (code, reason)
    findings = set()

    def refuse(code, reason=None):
        refusals.append((code, reason))

    task_id = b.get("task_id")
    observations = b.get("observations") or []
    grant = b.get("grant")
    receipts_in = []
    if b.get("receipt") is not None:
        receipts_in.append(b["receipt"])
    receipts_in.extend(b.get("receipts") or [])
    # dedupe identical presentations (same receipt_id and same bytes)
    receipts, seen = [], set()
    for r in receipts_in:
        k = canonical(r)
        if k not in seen:
            seen.add(k)
            receipts.append(r)
    intent = b.get("intent")

    # ---- identity
    task_missing = not isinstance(task_id, str) or task_id == ""
    if task_missing:
        refuse("task_id_missing")
    records = list(observations) + ([grant] if grant else []) + receipts + ([intent] if intent else [])
    for rec in records:
        rt = rec.get("task_id") if isinstance(rec, dict) else None
        if task_missing:
            if I["task_missing_cascade"] and rt:
                refuse("task_id_mismatch")
            if not rt:
                refuse("task_id_missing")
        elif rt != task_id:
            if not rt:
                refuse("task_id_missing")
            else:
                refuse("task_id_mismatch")

    # ---- delegation
    valid_obs = []
    if not observations:
        findings.add("no_delegation_observations")
    for o in observations:
        bad = None
        hop = o.get("hop") or {}
        pre = without(o, OBS_DERIVED)
        if not isinstance(hop, dict) or not isinstance(hop.get("seq"), int) or isinstance(hop.get("seq"), bool):
            bad = "malformed"
        elif sha256hex(pre) != o.get("evidence_id"):
            bad = "evidence_id_mismatch"  # R2
        elif o.get("witness_id") in (hop.get("from"), hop.get("to")):
            bad = "witness_not_independent"  # R1
        elif not verify_sig(o.get("witness_id"), pre, o.get("witness_sig")):
            bad = "witness_sig_invalid"
        elif not verify_sig(hop.get("from"), {"task_id": o.get("task_id"), "hop": hop}, o.get("edge_sig")):
            bad = "edge_sig_invalid"
        elif I["check_observed_at"] and parse_ts(o.get("observed_at")) is None:
            bad = "invalid_timestamp"
        if bad:
            refuse("delegation_observation_invalid", bad)
        else:
            valid_obs.append(o)
    chain_set = valid_obs if I["invalid_obs_excluded"] else [o for o in observations if isinstance(o.get("hop"), dict)]
    if chain_set:
        by_seq = {}
        for o in chain_set:
            by_seq.setdefault(o["hop"].get("seq"), []).append(o)
        seqs = sorted(s for s in by_seq if isinstance(s, int))
        broken = seqs != list(range(len(seqs))) or not seqs
        if not broken:
            for s in seqs:
                for o in by_seq[s]:
                    if s == 0:
                        if o.get("prev_evidence_id") is not None:
                            broken = True
                    else:
                        prior = [p for p in by_seq[s - 1] if p.get("evidence_id") == o.get("prev_evidence_id")]
                        if not prior:
                            broken = True
                        elif I["r3_party_continuity"] and not any(p["hop"].get("to") == o["hop"].get("from") for p in prior):
                            broken = True
        if broken:
            refuse("delegation_chain_broken")
    elif observations:
        refuse("delegation_chain_broken")
    # R4 per {task_id, hop}
    groups = {}
    for o in (valid_obs if I["invalid_obs_excluded"] else observations):
        try:
            k = canonical({"task_id": o.get("task_id"), "hop": o.get("hop")})
        except StrictJSONError:
            continue
        groups.setdefault(k, set()).add(canonical((o.get("conduct") or {}).get("verdict")))
    if any(len(v) > 1 for v in groups.values()):
        findings.add("witness_disagreement")

    # ---- execution
    reconciled = None
    has_exec = grant is not None or bool(receipts)
    if not has_exec and not (I["intent_counts_as_execution_record"] and intent is not None):
        findings.add("no_execution_records")
    grant_ok_ref = None
    if grant is not None:
        gpre = without(grant, GRANT_DERIVED)
        if sha256hex(gpre) != grant.get("grant_ref"):
            refuse("execution_invalid", "grant_ref_mismatch")
        else:
            grant_ok_ref = grant.get("grant_ref")
        if not verify_sig(grant.get("caller_id"), gpre, grant.get("caller_sig")):
            refuse("execution_signature_invalid", "caller_sig")
        ab = check_action_binding(grant, "action")
        if ab:
            refuse("execution_invalid", ab)
        nb, na = parse_ts(grant.get("not_before")), parse_ts(grant.get("not_after"))
        if nb is None or na is None:
            refuse("execution_invalid", "invalid_timestamp")
        elif nb > na:
            refuse("execution_invalid", "empty_window")
        if not grant.get("nonce"):
            refuse("execution_invalid", "nonce_missing")
        if grant.get("provider_id") is None:
            findings.add("open_grant")
        elif grant.get("provider_id") == grant.get("caller_id"):
            findings.add("self_authorized")
    else:
        nb = na = None

    if grant is not None and not receipts:
        refuse("execution_incomplete_pair", "no_receipt")
    if receipts and grant is None:
        refuse("execution_incomplete_pair", "no_grant")

    if grant is not None and receipts:
        authorized = grant.get("provider_id")
        candidates = []
        dropped_sig = False
        for r in receipts:
            rpre = without(r, RECEIPT_DERIVED)
            problems = []  # (code, reason)
            id_ok = sha256hex(rpre) == r.get("receipt_id")
            if not id_ok:
                problems.append(("execution_invalid", "receipt_id_mismatch"))
            sig_ok = verify_sig(r.get("provider_id"), rpre, r.get("provider_sig"))
            if not sig_ok:
                problems.append(("execution_signature_invalid", "provider_sig"))
            if r.get("grant_ref") != grant.get("grant_ref"):
                problems.append(("execution_invalid", "receipt_unbound"))
            prov_ok = authorized is not None and r.get("provider_id") == authorized
            if authorized is not None and not prov_ok:
                problems.append(("execution_invalid", "provider_not_authorized"))
            validity = []
            try:
                if canonical(grant.get("action")) != canonical(r.get("executed_action")):
                    validity.append(("execution_invalid", "action_diverged"))
            except StrictJSONError:
                validity.append(("execution_invalid", "action_diverged"))
            ea = parse_ts(r.get("executed_at"))
            if ea is None:
                validity.append(("execution_invalid", "invalid_timestamp"))
            elif nb is not None and na is not None and not (nb <= ea <= na):
                validity.append(("execution_invalid", "outside_window"))
            ab = check_action_binding(r, "executed_action")
            if ab:
                validity.append(("execution_invalid", ab))

            attributable = id_ok and sig_ok and prov_ok and r.get("grant_ref") == grant.get("grant_ref")
            if I["receipt_set_filter"] and not (sig_ok and prov_ok):
                dropped_sig = dropped_sig or not sig_ok
                for p in problems:
                    if p[1] not in ("provider_sig", "provider_not_authorized"):
                        refuse(*p)
                continue
            for p in problems + validity:
                refuse(*p)
            if attributable and (not I["reconcile_requires_valid"] or not validity):
                candidates.append(r)
        distinct = {r["receipt_id"]: r for r in candidates}
        if authorized is None:
            # open grant: "accepted with an open_grant finding but NOT reconcilable"
            pass
        elif len(distinct) == 1:
            reconciled = next(iter(distinct.values()))
        elif len(distinct) > 1:
            refuse("execution_equivocation")
        else:
            explained = any(c.startswith("execution_") for c, _ in refusals)
            if I["receipt_set_filter"] and dropped_sig and not explained:
                refuse("execution_signature_invalid", "provider_sig")
            elif I["unreconciled_cascade"] or not explained:
                refuse("execution_unreconciled")

    # ---- evidence (reconciled receipt only)
    if reconciled is not None:
        outcome = reconciled.get("outcome") or {}
        if "evidence" in outcome and outcome["evidence"] is not None:
            if evidence_well_formed(outcome["evidence"]):
                findings.add("evidence_bound_unchecked")  # no lookup is ever injected here
            else:
                refuse("evidence_invalid")
        else:
            findings.add("no_evidence_bound")

    # ---- linkage (only when exactly one receipt reconciles)
    if reconciled is not None and observations:
        link_obs = valid_obs if I["invalid_obs_excluded"] else observations
        links = []
        for o in link_obs:
            ref = (o.get("conduct") or {}).get("detail_ref")
            if isinstance(ref, str) and ref.startswith(EXEC_PREFIX):
                links.append(ref[len(EXEC_PREFIX):])
        rid = reconciled.get("receipt_id")
        if any(l != rid for l in links):
            refuse("linkage_receipt_mismatch")
        if I["no_digest_link_literal"]:
            if rid not in links:
                findings.add("no_digest_link")
        elif not links:
            findings.add("no_digest_link")

    # ---- preflight
    if intent is not None:
        if grant is None:
            refuse("preflight_without_grant")
        ipre = without(intent, INTENT_DERIVED)
        if sha256hex(ipre) != intent.get("intent_id"):
            refuse("preflight_invalid", "intent_id_mismatch")
        if not verify_sig(intent.get("provider_id"), ipre, intent.get("intent_sig")):
            refuse("preflight_signature_invalid")
        ab = check_action_binding(intent, "proposed_action")
        if ab:
            refuse("preflight_invalid", ab)
        da = parse_ts(intent.get("declared_at"))
        if da is None:
            refuse("preflight_invalid", "invalid_timestamp")
        if grant is not None:
            if intent.get("grant_ref") != grant.get("grant_ref"):
                refuse("preflight_invalid", "intent_unbound")
            if grant.get("provider_id") is not None and intent.get("provider_id") != grant.get("provider_id"):
                refuse("preflight_invalid", "provider_not_authorized")
            if canonical(intent.get("proposed_action")) != canonical(grant.get("action")):
                refuse("preflight_invalid", "action_outside_grant")
            if da is not None and nb is not None and na is not None and not (nb <= da <= na):
                refuse("preflight_invalid", "outside_window")
        if reconciled is not None and \
                canonical(intent.get("proposed_action")) != canonical(reconciled.get("executed_action")):
            findings.add("declared_executed_divergence")

    codes = sorted({c for c, _ in refusals})
    verdict = "refused" if codes else "accepted"
    fs = sorted(findings) if (I["findings_on_refused"] or verdict == "accepted") else []
    return {"verdict": verdict, "refusals": codes, "findings": fs}, refusals


def verify_text(text, interp=None):
    try:
        b = strict_loads(text)
    except StrictJSONError as e:
        # no provenance refusal code is defined for this; strict_json codes are surfaced as-is
        return {"verdict": "refused", "refusals": [e.code], "findings": []}, [(e.code, None)]
    try:
        return verify_bundle(b, interp)
    except UnicodeEncodeError:  # lone surrogate: not representable as UTF-8; spec silent
        return {"verdict": "refused", "refusals": ["bad_json"], "findings": []}, [("bad_json", None)]
    except StrictJSONError as e:
        return {"verdict": "refused", "refusals": [e.code], "findings": []}, [(e.code, None)]


def main(argv):
    import glob
    import os
    interp = {}
    show_reasons = False
    args = argv[1:]
    out_path = None
    while args:
        a = args.pop(0)
        if a == "--set":
            k, v = args.pop(0).split("=")
            if k not in INTERP:
                raise SystemExit("unknown flag " + k)
            interp[k] = int(v)
        elif a == "--reasons":
            show_reasons = True
        elif a == "--out":
            out_path = args.pop(0)
    result = {}
    for ver in ("v0", "v01"):
        result[ver] = {}
        for f in sorted(glob.glob("/tmp/cleanroom/%s/fixtures/*.json" % ver)):
            name = os.path.basename(f)[:-5]
            sig, reasons = verify_text(open(f, encoding="utf-8").read(), interp)
            result[ver][name] = sig
            if show_reasons:
                print(ver, name, sig["verdict"], reasons, sig["findings"], file=sys.stderr)
    text = json.dumps(result, indent=2, sort_keys=True)
    if out_path:
        open(out_path, "w").write(text + "\n")
    print(text)


if __name__ == "__main__":
    main(sys.argv)
