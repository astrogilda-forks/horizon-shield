#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.16: strict inputs, and the walk check reads accepted records only (a2a-settlement-v1.16).

Why this file exists. On 2026-10-17 we wrote settle down as a specification for a second, independent implementation
(SETTLE_CORE_v0.md). Writing it down showed places where settle v1.10 to v1.15 accept input that a careful second
implementation would refuse or read differently, and one place where a record nobody signed can change the verdict:

  N2  The NENRIN cross check (settle v1.5, called from v1.7) runs over every bound record, also records that failed
      authentication. An unsigned, unanchored record that names the contract can make the verdict a deviation and
      forfeit a bond.
  N1  A trailing line feed passes several checks (Python's "$" and bytes.fromhex skipping whitespace): block hash,
      proof operands, header hex, action names, approval nonces. A JavaScript port reads these differently.
  N3  delegated_to and approvals are iterated without a type check (a string is read character by character).
  N4  Floats, NaN, Infinity and integers above 2^53 - 1 are accepted in records and views. JavaScript reads them
      differently, so record digests and anchors differ by runtime.
  N6  Two inputs stop the reference with an exception: a revocation against a grant with no revocation block, and an
      object inside delegated_to.
  N8  The bond test uses truthiness, so [] and {} mean "no bond" in Python and "a bond" in JavaScript.
  N9  Signature checks call OpenSSL after checking the public key. A signature whose S is not below the group order,
      or whose R is not a point of prime order, is now refused before OpenSSL is asked.
  N11 A record whose anchor claims a height below the contract's lower bound was dropped without a word; a parent
      contract was never checked; requirements.evidence "nenrin_required" was never read; an empty event set read
      as within_grant.

v1.10 to v1.15 are not edited. v1.16 binds the records itself, triages the bound ones, runs v1.15 only on records
strictly signed by a party, and then applies the rules below to v1.15's answer. Settlement is in binding mode strict.

Strict values (rule 1). Every string anywhere in a record, the view or a supplied walk is free of C0 control characters
and DEL. Every object key is ASCII. Every number is an integer from -(2^53 - 1) to 2^53 - 1 (no float, NaN or
Infinity). Nesting is at most 512 levels. Fixed forms are checked whole: anchor.block_hash, nenrin_ref and
contract_ref.contract_sha256 / payload_digest are 64 lowercase hex characters, every proof operand is lowercase hex of
whole bytes (empty allowed); performed_actions and delegated_to are lists of strings, approvals a list of objects. A
header is an integer height and 160 lowercase hex characters.

Strict signatures (rule 2). A signature that decodes to 64 bytes must have S below the group order L and an R that
decodes to a point of prime order (agreement_verify.public_key_problem). A record is "strictly signed" when one of its
signature entries from a role its schema allows (settle v1.2) is strict and verifies.

Binding and triage (rule 3). A record that cannot be digested at all is set aside. The rest are bound by
contract_ref.contract_sha256, exactly as settle v1.5 does (bound, foreign, unbound, inconsistent); only bound records
are triaged. The body is what the signers signed (the record without signatures and anchor); the anchor and the
signatures list are not signed, so anyone holding a copy can change them.
  a. Not strictly signed: set aside (record_not_strict) when the body is not strict; set aside (signature_not_strict)
     when only a lax signature verifies; otherwise rejected with settle v1.2's reason. Such records never reach v1.15:
     no copy collapse, record count or check sees them.
  b. Strictly signed, with a body that is not strict: the record is a party's own statement, so the settlement is
     underspecified (record_not_strict).
  c. Strictly signed, with an anchor that is not strict: set aside (anchor_not_strict) when a strictly signed copy of the
     same body with an anchor that verifies is in the input; otherwise underspecified (anchor_not_strict), as settle
     v1.1 already does for an anchor that does not verify. Problems in the signatures list of a strictly signed record
     are ignored, as before.
  d. A revocation against a grant with no revocation block: set aside (revocation_not_provided_for).
Records set aside are listed in v1_16.refused with their reason, rejected ones in rejected.

The contract, the view and the walks (rule 4). A contract that is not an object, or whose shape stops a lower layer
while the contract door refuses it: contract_not_verified. A contract signature that is not strict
(contract_signature_not_strict), a bond that is not null or an object with a positive integer amount (bond_malformed),
a parent_contract with no parent supplied (parent_not_supplied), or a parent that does not verify or under which the
contract does not verify (parent_narrowing_failed): underspecified. A header that is not strict: view_not_strict. A
supplied walk that is not strict is left out of the NENRIN index (v1_16.walks_set_aside); if an execution v1.15 read
cites it by nenrin_ref, the settlement is underspecified (walk_not_strict). Events that are not a list, or any other
shape that stops a lower layer: input_not_settleable.

Rejected records are read by no check (rule 5). If v1.15 still rejects a record, v1.15 is run again without it, until it
rejects nothing new. Every rejected record is listed.

Anchors below the lower bound (rule 6). A record (strictly signed, since only those reach v1.15) whose anchor claims a
height below the contract's lower bound cannot be honest: its body names the contract, and the contract names the lower
bound's block hash. v1.15 drops it as predates_contract without a word; v1.16 makes the settlement underspecified
(anchor_below_lower_bound).

nenrin_required (rule 7). When requirements.evidence is "nenrin_required", an accepted execution with no nenrin_ref of
64 lowercase hex characters is a deviation (evidence_missing).

Nothing to settle (rule 8). When v1.15 says within_grant over an empty event set, v1.16 says nothing_to_settle: no
record was read, so nothing was found within the grant or outside it. The status and bond outcome are v1.15's.

Where a rule makes the settlement underspecified, the event set and the dispositions are what v1.15 computed over the
records it read. Inputs without any of these problems settle to v1.15's answer; the output then differs only in schema,
settled_under, the v1_16 block and the establishes lines. Admissions (settle v1.14) are passed to v1.15 unchanged.
"""
import argparse, base64, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_15 as v115
import settle_v1_5 as v15
import settle_v1_2 as v12
import settle_v1_1 as v11
import settle_v1_7 as v17
from contract_v0 import canonical, parse_strict, ed25519_verify, contract_sha256, EXEC_SCHEMA
from agreement_verify import public_key_problem

SETTLE_SCHEMA = "a2a-settlement-v1.16"
KINDS = (EXEC_SCHEMA, v1.REVOKE_SCHEMA, v1.ACK_SCHEMA)
SAFE = 2 ** 53 - 1
L_ORDER = 2 ** 252 + 27742317777372353535851937790883648493
CTRL = re.compile(r"[\x00-\x1f\x7f]")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
HEXANY = re.compile(r"\A(?:[0-9a-f]{2})*\Z")
HEADER = re.compile(r"\A[0-9a-f]{160}\Z")
MAX_DEPTH = 512


# --------------------------------------------------------------------------- rule 1: values
def value_problem(x, path="$", ascii_keys=True, depth=0):
    """None when every string, key and number under x is acceptable (rule 1). A short reason otherwise.
    Keys are visited in code point order, so the reason does not depend on the order keys were written in."""
    if depth > MAX_DEPTH:
        return "%s: nested deeper than %d levels" % (path, MAX_DEPTH)
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, int):
        return None if -SAFE <= x <= SAFE else "%s: integer outside the safe range" % path
    if isinstance(x, float):
        return "%s: a number that is not an integer" % path
    if isinstance(x, str):
        return "%s: a control character in a string" % path if CTRL.search(x) else None
    if isinstance(x, list):
        for i, y in enumerate(x):
            p = value_problem(y, "%s[%d]" % (path, i), ascii_keys, depth + 1)
            if p:
                return p
        return None
    if isinstance(x, dict):
        for k in sorted(x, key=lambda k: (not isinstance(k, str), str(k))):
            if not isinstance(k, str) or CTRL.search(k) or (ascii_keys and not k.isascii()):
                return "%s: a key that is not plain ASCII" % path
            p = value_problem(x[k], "%s.%s" % (path, k), ascii_keys, depth + 1)
            if p:
                return p
        return None
    return "%s: a value of type %s" % (path, type(x).__name__)


# --------------------------------------------------------------------------- rule 3: signatures
def sig_problem(sig_b64):
    """None for a signature string that does not decode to 64 bytes (authentication skips it) or that is strict.
    A reason when it decodes to 64 bytes and S >= L or R is not a canonical point of prime order."""
    if not isinstance(sig_b64, str):
        return None
    try:
        raw = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return None
    if len(raw) != 64:
        return None
    if int.from_bytes(raw[32:], "little") >= L_ORDER:
        return "S is not below the group order"
    why = public_key_problem(raw[:32])
    return ("R %s" % why) if why else None


def _sig_strings(entries):
    out = []
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict):
            for k in ("sig_b64", "signature"):
                if isinstance(e.get(k), str):
                    out.append(e[k])
    return out


# --------------------------------------------------------------------------- rule 2: fixed forms
def body_problem(ev):
    """A problem in the part of the record its signers signed (everything but signatures and anchor)."""
    body = {k: v for k, v in ev.items() if k not in ("signatures", "anchor")}
    p = value_problem(body)
    if p:
        return p
    if "nenrin_ref" in ev and ev["nenrin_ref"] is not None and not (isinstance(ev["nenrin_ref"], str) and HEX64.match(ev["nenrin_ref"])):
        return "nenrin_ref is not 64 lowercase hex characters"
    cr = ev.get("contract_ref")
    if isinstance(cr, dict):
        for k in ("contract_sha256", "payload_digest"):
            if k in cr and not (isinstance(cr[k], str) and HEX64.match(cr[k])):
                return "contract_ref.%s is not 64 lowercase hex characters" % k
    if ev.get("schema") == EXEC_SCHEMA:
        for k in ("performed_actions", "delegated_to"):
            if k in ev and not (isinstance(ev[k], list) and all(isinstance(s, str) for s in ev[k])):
                return "%s is not a list of strings" % k
        if "approvals" in ev and not (isinstance(ev["approvals"], list) and all(isinstance(s, dict) for s in ev["approvals"])):
            return "approvals is not a list of objects"
        for ap in ev.get("approvals") or []:
            for k in ("sig_b64", "signature"):
                why = sig_problem(ap.get(k))
                if why:
                    return "an approval signature: " + why
    return None


def anchor_problem(ev):
    """A problem in the anchor, which nobody signed: anyone holding a copy can change it."""
    if "anchor" not in ev:
        return None
    a = ev["anchor"]
    p = value_problem(a, "$.anchor")
    if p:
        return p
    if not isinstance(a, dict):
        return None  # the shape is v1.1's to judge
    if "block_hash" in a and not (isinstance(a["block_hash"], str) and HEX64.match(a["block_hash"])):
        return "anchor.block_hash is not 64 lowercase hex characters"
    proof = a.get("proof")
    for i, op in enumerate(proof if isinstance(proof, list) else []):
        if isinstance(op, dict) and "hex" in op and not (isinstance(op["hex"], str) and HEXANY.match(op["hex"])):
            return "anchor.proof[%d].hex is not lowercase hex of whole bytes" % i
    return None


def strict_signer(ev, contract):
    """True when the record carries a signature that a strict verifier accepts, from a role its schema allows
    (settle v1.2's authenticate, with rule 3 applied to each signature first)."""
    try:
        keys, wit = v12._keys(contract)
        allowed = v12.REQUIRED.get(ev.get("schema"))
        sigs = ev.get("signatures")
        if not allowed or not isinstance(sigs, list):
            return False
        msg = v12.record_signing_bytes(ev)
        for s in sigs:
            if not isinstance(s, dict) or s.get("role") not in allowed or sig_problem(s.get("sig_b64")):
                continue
            if value_problem(s):
                continue
            pub = wit.get(s.get("witness_name")) if s["role"] == "witness" else keys.get(s["role"])
            if isinstance(pub, str) and ed25519_verify(pub, s.get("sig_b64"), msg) is True:
                return True
    except Exception:
        return False
    return False


def signatures_problem(ev):
    for s in _sig_strings(ev.get("signatures")):
        why = sig_problem(s)
        if why:
            return why
    return value_problem(ev.get("signatures"), "$.signatures") if "signatures" in ev else None


def triage(ev, contract):
    """What v1.16 does with one record bound to this contract (by contract_sha256, settle v1.5) before v1.15 sees it:
    ("keep",), ("set_aside", reason, detail), ("rejected", why), ("underspecified", reason, detail) or
    ("anchor", reason, detail). See the module docstring, rule 3."""
    signed = strict_signer(ev, contract)
    bp = body_problem(ev)
    if not signed:
        if bp:
            return ("set_aside", "record_not_strict", bp)
        lax = None
        try:
            lax = v12.authenticate(ev, contract)
        except Exception:
            lax = "the record's shape stops authentication"
        if lax is None:
            return ("set_aside", "signature_not_strict", "the only signature that verifies is not strict")
        return ("rejected", lax)
    if bp:
        return ("underspecified", "record_not_strict", bp)
    ap = anchor_problem(ev)
    if ap:
        return ("anchor", "anchor_not_strict", ap)
    if ev.get("schema") == v1.REVOKE_SCHEMA and not _revocable(contract):
        return ("set_aside", "revocation_not_provided_for", "the grant has no revocation block, so the contract cannot be revoked")
    return ("keep",)


def view_problem(view):
    p = value_problem(view, "$view")
    if p:
        return p
    hs = view.get("headers") if isinstance(view, dict) else None
    if not isinstance(hs, list):
        return None  # the shape is v1.1's to judge
    for i, h in enumerate(hs):
        if not isinstance(h, dict) or not (isinstance(h.get("height"), int) and not isinstance(h.get("height"), bool)) \
                or not (isinstance(h.get("hex"), str) and HEADER.match(h["hex"])):
            return "headers[%d] is not an integer height with 160 lowercase hex characters" % i
    return None


# --------------------------------------------------------------------------- contract-level rules
def contract_problems(contract, parent):
    probs = []
    for s in _sig_strings(contract.get("signatures") if isinstance(contract, dict) else None):
        why = sig_problem(s)
        if why:
            probs.append({"reason": "contract_signature_not_strict", "detail": why})
            break
    bond = contract.get("bond") if isinstance(contract, dict) else None
    if bond is not None:
        amt = bond.get("amount") if isinstance(bond, dict) else None
        if not (isinstance(bond, dict) and isinstance(amt, int) and not isinstance(amt, bool) and 0 < amt <= SAFE):
            probs.append({"reason": "bond_malformed", "detail": "a bond is null, or an object whose amount is a positive integer"})
    pc = contract.get("parent_contract") if isinstance(contract, dict) else None
    if pc is not None:
        if parent is None:
            probs.append({"reason": "parent_not_supplied", "detail": "the contract names a parent_contract; settle it with --parent"})
        else:
            import contract_v0
            ok = isinstance(parent, dict) and contract_v0.verify_contract(parent)["verdict"] == "accepted"
            r = contract_v0.verify_contract(contract, parent=parent) if ok else None
            if not ok:
                probs.append({"reason": "parent_narrowing_failed", "detail": "the supplied parent does not verify on its own"})
            elif r["verdict"] != "accepted" or r["refusals"]:
                probs.append({"reason": "parent_narrowing_failed", "detail": "the child contract does not verify under the supplied parent"})
    return probs


def _revocable(contract):
    g = contract.get("grant") if isinstance(contract, dict) else None
    return isinstance(g, dict) and isinstance(g.get("revocation"), dict)


def _lower_height(contract):
    lb = contract.get("lower_bound") if isinstance(contract, dict) else None
    h = lb.get("height") if isinstance(lb, dict) else None
    return h if isinstance(h, int) and not isinstance(h, bool) else None


# --------------------------------------------------------------------------- settle
def _underspecified(out, contract, reasons, note):
    out["underspecified"] = sorted(list(out.get("underspecified") or []) + reasons, key=canonical)
    out["verdict"], out["status"], out["deviations"] = "underspecified", "undetermined", []
    out["bond_outcome"] = v15._bond_outcome(contract, "underspecified", "undetermined")
    out["establishes"] = list(out.get("establishes") or [])[:1] + [note]
    return out


def _triage(ev, contract):
    try:
        return triage(ev, contract)
    except Exception as e:  # a shape that stops a check is not a strict record
        return ("set_aside", "record_not_strict", "the record's shape stops the checks (%s)" % type(e).__name__)


def _sha(ev):
    try:
        return v1.rec_sha(ev)
    except Exception:
        return None


ESTABLISH = ("that the input was checked against the strict rules of a2a-settlement-v1.16 first (records set aside are listed in "
             "v1_16.refused), and that no check read a record that is not strictly signed by a party or that failed authentication")


def _no_settlement(contract, reasons, refused=(), rejected=(), binding=None):
    """The output when the input cannot be settled at all (not an object, or a shape that stops a lower layer)."""
    csha = None
    try:
        csha = contract_sha256(contract) if isinstance(contract, dict) else None
    except Exception:
        pass
    bond = "n/a"
    try:
        bond = v15._bond_outcome(contract, "underspecified", "undetermined") if isinstance(contract, dict) else "n/a"
    except Exception:
        pass
    return {"schema": SETTLE_SCHEMA, "settled_under": None, "contract_sha256": csha, "binding_mode": "strict",
            "verdict": "underspecified", "status": "undetermined", "bond_outcome": bond, "deviations": [],
            "underspecified": sorted(reasons, key=canonical), "authoritative_event_set": [],
            "rejected": sorted(rejected, key=canonical), "binding": binding or {"bound": [], "unbound": [], "foreign": [], "inconsistent": []},
            "v1_16": {"refused": sorted(refused, key=canonical), "rejected_left_out_of_checks": False},
            "establishes": ["that no verdict is rendered for this input (see underspecified)"],
            "does_not_establish": ["that any record is true or false; nothing was settled"]}


def _door_refuses(contract):
    try:
        import contract_v0
        return contract_v0.verify_contract(contract)["verdict"] != "accepted"
    except Exception:
        return True


def settle_v1_16(contract, events, view, parent=None, **kw):
    kw.pop("mode", None)  # v1.16 settles in strict mode only
    if not isinstance(contract, dict):
        return _no_settlement(contract, [{"reason": "contract_not_verified", "detail": "the contract is not a JSON object"}])
    if not isinstance(events, list):
        return _no_settlement(contract, [{"reason": "input_not_settleable", "detail": "events is not a list"}])

    # a value no runtime can digest (an integer too long to write out, say) is set aside before anything reads it
    refused, readable = [], []
    for ev in events:
        if isinstance(ev, dict) and ev.get("schema") in KINDS and _sha(ev) is None:
            refused.append({"sha256": None, "reason": "record_not_strict", "detail": "the record cannot be digested"})
        else:
            readable.append(ev)

    # binding first, by contract_sha256 (settle v1.5): only records bound to these terms are triaged
    try:
        csha = contract_sha256(contract)
        bound, foreign, unbound, inconsistent = v15.classify_binding(contract, readable, csha)
    except Exception as e:
        return _no_settlement(contract, [{"reason": "contract_not_verified" if _door_refuses(contract) else "input_not_settleable",
                                          "detail": "the input's shape stops binding (%s)" % type(e).__name__}], refused)
    binding = {"bound": sorted(_sha(e) for e in bound), "unbound": sorted(_sha(e) for e in unbound),
               "foreign": sorted(foreign, key=canonical), "inconsistent": sorted(inconsistent, key=canonical)}

    keep, rejected, failed, anchors = [], [], [], []
    for ev in bound:
        t = _triage(ev, contract)
        if t[0] == "keep":
            keep.append(ev)
        elif t[0] == "set_aside":
            refused.append({"sha256": _sha(ev), "reason": t[1], "detail": t[2]})
        elif t[0] == "rejected":
            rejected.append({"sha256": _sha(ev), "schema": ev.get("schema"), "why": t[1]})
        elif t[0] == "underspecified":
            failed.append({"sha256": _sha(ev), "reason": t[1], "detail": t[2]})
        else:
            anchors.append((ev, t))
    cv = None
    try:
        cv, _ = v11.verify_view(view, contract)
    except Exception:
        cv = None
    good_bodies = set()
    for ev in keep:
        try:
            if cv is not None and v17.anchor_valid_v1_7(ev, cv):
                good_bodies.add(v115.signed_digest(ev))
        except Exception:
            pass
    for ev, t in anchors:
        if v115.signed_digest(ev) in good_bodies:
            refused.append({"sha256": _sha(ev), "reason": t[1], "detail": t[2] + "; a strictly signed copy of the same body with an anchor that verifies is in the input"})
        else:
            failed.append({"sha256": _sha(ev), "reason": t[1], "detail": t[2]})

    vp = view_problem(view)
    try:
        cps = contract_problems(contract, parent)
    except Exception as e:
        cps = [{"reason": "parent_narrowing_failed", "detail": "the parent's shape stops the check (%s)" % type(e).__name__}]
    walks_aside = []
    nr = kw.get("nenrin_records")
    if nr is not None and not isinstance(nr, list):
        walks_aside.append({"sha256": None, "detail": "nenrin_records is not a list"})
        kw["nenrin_records"] = None
    elif nr:
        ok_walks = []
        for w in nr:
            why = value_problem(w, "$walk")
            if why:
                walks_aside.append({"sha256": _sha(w), "detail": why})
            else:
                ok_walks.append(w)
        kw["nenrin_records"] = ok_walks or None

    # v1.15 over the strictly signed bound records; again without whatever it rejects, until it rejects nothing new
    try:
        runs, current, seen_rej = 0, list(keep), []
        while True:
            s = dict(v115.settle_v1_15(contract, current, view, **kw))
            runs += 1
            rej = {x.get("sha256") for x in s.get("rejected") or [] if isinstance(x, dict)}
            seen_rej += [x for x in s.get("rejected") or [] if isinstance(x, dict)]
            nxt = [ev for ev in current if _sha(ev) not in rej]
            if len(nxt) == len(current):
                break
            current = nxt
    except Exception as e:
        reason = "contract_not_verified" if _door_refuses(contract) else "input_not_settleable"
        return _no_settlement(contract, [{"reason": reason, "detail": "the input's shape stops a lower layer (%s)" % type(e).__name__}],
                              refused, rejected, binding)

    out = s
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, s.get("schema")
    out["binding"] = binding
    out["rejected"] = sorted({canonical(x): x for x in rejected + seen_rej}.values(), key=canonical)
    refused.sort(key=canonical)
    out["v1_16"] = {"refused": refused, "rejected_left_out_of_checks": runs > 1}
    if walks_aside:
        out["v1_16"]["walks_set_aside"] = sorted(walks_aside, key=canonical)

    # every v1.16 reason is collected; any one of them means no verdict
    reasons = []
    if vp:
        reasons.append({"reason": "view_not_strict", "detail": vp})
    reasons += cps
    cited = {ev.get("nenrin_ref") for ev in current if ev.get("schema") == EXEC_SCHEMA}
    reasons += [{"reason": "walk_not_strict", "walk_sha256": w["sha256"], "detail": w["detail"]}
                for w in walks_aside if w.get("sha256") and w["sha256"] in cited]
    reasons += failed
    below = [x for x in out.get("predates_contract") or [] if isinstance(x, dict)]
    if below and _lower_height(contract) is not None:
        out["predates_contract"] = []
        reasons += [{"reason": "anchor_below_lower_bound", "sha256": x.get("sha256"),
                     "detail": "a record strictly signed by a party carries an anchor below the contract's lower bound, "
                               "which cannot commit to a body that names this contract"} for x in below]
    if reasons:
        return _underspecified(out, contract, sorted(reasons, key=canonical),
                               "that the input cannot be settled under the strict rules of a2a-settlement-v1.16 "
                               "(see underspecified), so no verdict is rendered")

    if out.get("verdict") in ("within_grant", "deviation"):
        req = contract.get("requirements")
        if isinstance(req, dict) and req.get("evidence") == "nenrin_required":
            by_sha = {_sha(ev): ev for ev in current if ev.get("schema") == EXEC_SCHEMA}
            extra = []
            for x in out.get("authoritative_event_set") or []:
                if isinstance(x, dict) and x.get("kind") == "execution":
                    ref = (by_sha.get(x.get("sha256")) or {}).get("nenrin_ref")
                    if not (isinstance(ref, str) and HEX64.match(ref)):
                        extra.append({"clause": "evidence_missing", "observed": None, "height": x.get("height"),
                                      "record_sha256": x.get("sha256"), "evidence_sha": None})
            if extra:
                out["deviations"] = sorted(list(out.get("deviations") or []) + extra, key=canonical)
                out["verdict"] = "deviation"
                out["bond_outcome"] = v15._bond_outcome(contract, "deviation", out.get("status"))

    if out.get("verdict") == "within_grant" and not (out.get("authoritative_event_set") or []):
        out["verdict"] = "nothing_to_settle"

    out["establishes"] = list(out.get("establishes") or []) + [ESTABLISH]
    return out


# --------------------------------------------------------------------------- self test
def _selftest():
    import copy, subprocess
    import settle_v1_1 as v11
    import settle_v1_11 as v111
    import contract_v0 as v0
    import approval_v3 as AV
    from contract_v0 import contract_sha256
    n = 0
    NAMED = ("schema", "settled_under", "establishes", "does_not_establish", "v1_16")
    strip = lambda s: {k: v for k, v in s.items() if k not in NAMED}
    reasons = lambda s: sorted({u.get("reason") for u in s.get("underspecified") or []})
    refused = lambda s: sorted(x["reason"] for x in s["v1_16"]["refused"])
    clauses = lambda s: sorted(d["clause"] for d in s["deviations"])
    dup = lambda x: json.loads(json.dumps(x))

    # [1] inputs without the problems v1.16 names: v1.15's answer, apart from the named fields
    fx = v111.load_fixture()
    contracts, cases, keys = fx
    same = empty = 0
    for k in sorted(cases):
        a = v111.settle_fixture_case(v115.settle_v1_15, k, fx)
        b = v111.settle_fixture_case(settle_v1_16, k, fx)
        if a["verdict"] == "within_grant" and not a["authoritative_event_set"]:
            assert b["verdict"] == "nothing_to_settle" and canonical(dict(strip(b), verdict="within_grant")) == canonical(strip(a)), k
            empty += 1
        else:
            assert canonical(strip(b)) == canonical(strip(a)), k
            same += 1
    rr = os.path.join(HERE, "run0002")
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    r2 = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    a, b = v115.settle_v1_15(*r2, nenrin_records=nr), settle_v1_16(*r2, nenrin_records=nr)
    assert b["verdict"] == "within_grant" and b["status"] == "final" and canonical(strip(b)) == canonical(strip(a))
    assert b["settled_under"] == a["schema"] and b["v1_16"] == {"refused": [], "rejected_left_out_of_checks": False}
    n += 1; print("[1] %d fixture scenarios and run0002 settle to v1.15's answer; %d fixture scenarios with no accepted record read "
                  "nothing_to_settle instead of within_grant" % (same + 1, empty))

    key = AV._key
    ka, pa = key("principal"); kb, pb = key("contractor"); kx, px = key("stranger")
    PDG = "b" * 64
    base = v11._Chain(60, "00" * 32, "v116")
    for _ in range(38):
        base.block()
    lb = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    DNE = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]

    def mk(nonce, revocable=True, bond=None, parent=None, evidence="n/a", grant_actions=("read", "pay")):
        g = {"authorized_actions": list(grant_actions), "prohibited_actions": ["delete"], "conditional": [],
             "delegation": {"allowed": []}, "finality": {"depth": 3, "max_target_bits": "207fffff"}}
        if revocable:
            g["revocation"] = {"effective_at": "anchor"}
        c = v0.build_contract(
            {"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
            {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
            {"purpose": "settle_v1_16_selftest", "payload_digest": PDG, "a2a_task_id": "t16"}, g,
            ["that both parties signed these grant bytes at the stated time"], DNE,
            requirements={"evidence": evidence, "recovery": "n/a"}, bond=bond, lower_bound=lb,
            parent_contract={"contract_id": parent["contract_id"]} if parent else None,
            contract_id=("0123456789abcdef0123456789ab%04x" % int(nonce[:4], 16)), nonce=nonce, agreed_at="2026-10-17T00:00:00Z")
        v0.sign_contract(c, ka, pa, "a.example"); v0.sign_contract(c, kb, pb, "b.example")
        return c

    def ex(c, actions=("read",), signer=kb, role="contractor", sign=True, **extra):
        r = {"schema": EXEC_SCHEMA, "contract_ref": {"contract_id": c["contract_id"], "payload_digest": PDG, "contract_sha256": contract_sha256(c)},
             "performed_actions": list(actions), "approvals": [], "delegated_to": [], "nenrin_ref": "c" * 64}
        r.update(extra)
        return v12.sign_record(r, signer, role) if sign else r

    def rv(c):
        r = {"schema": v1.REVOKE_SCHEMA, "contract_ref": {"contract_id": c["contract_id"], "payload_digest": PDG, "contract_sha256": contract_sha256(c)},
             "revoked_by": "principal"}
        return v12.sign_record(r, ka, "principal")

    def run(c, recs, fork, nenrin=None, parent=None, extra_unanchored=()):
        ch = base.fork(98, fork)
        R = ch.block(list(recs)) if recs else []
        for _ in range(5):
            ch.block()
        return settle_v1_16(c, R + list(extra_unanchored), ch.view(), parent=parent, nenrin_records=nenrin), R, ch.view()

    C = mk("1" * 32)
    assert v0.verify_contract(C)["verdict"] == "accepted"
    s, R, view = run(C, [ex(C)], "b0")
    assert s["verdict"] == "within_grant" and s["status"] == "final", (s["verdict"], reasons(s))
    good = R[0]

    # [2] N2: a record that fails authentication is no longer read by the walk check
    W = {"schema": "synthetic-walk-v0", "context": {"contract_sha256": "ee" * 32}, "note": "a walk made under other terms"}
    bad = ex(C, sign=False, nenrin_ref=v1.rec_sha(W))
    a = v115.settle_v1_15(C, [good, bad], view, nenrin_records=[W])
    b = settle_v1_16(C, [good, bad], view, nenrin_records=[W])
    assert a["verdict"] == "deviation" and "evidence_names_other_contract" in clauses(a), clauses(a)
    assert b["verdict"] == "within_grant" and [x["sha256"] for x in b["rejected"]] == [v1.rec_sha(bad)], b["verdict"]
    CB = mk("2" * 32, bond={"amount": 1000, "currency": "JPY"})
    _, RB, viewB = run(CB, [ex(CB)], "b0b")
    bad = ex(CB, sign=False, nenrin_ref=v1.rec_sha(W))
    assert v115.settle_v1_15(CB, RB + [bad], viewB, nenrin_records=[W])["bond_outcome"] == "forfeited"
    assert settle_v1_16(CB, RB + [bad], viewB, nenrin_records=[W])["bond_outcome"] == "held"
    n += 1; print("[2] N2: an unsigned record citing a walk under other terms: v1.15 deviation and the bond forfeited; v1.16 within_grant, "
                  "the bond held, the record listed as rejected")

    # [3] N1: a trailing line feed. In the signed body: no verdict. In the anchor of the only copy: no verdict. In the anchor
    #     of a copy beside a good one: the copy is set aside and the verdict stands
    s, _, _ = run(C, [ex(C, actions=["read\n"])], "b1")
    assert s["verdict"] == "underspecified" and reasons(s) == ["record_not_strict"], reasons(s)
    _, R3, view3 = run(C, [ex(C), ex(C, nenrin_ref="d" * 64)], "b3")
    g3 = R3[0]
    ap_nl = dup(g3); ap_nl["anchor"]["proof"][0]["hex"] += "\n"
    bh_nl = dup(g3); bh_nl["anchor"]["block_hash"] += "\n"
    assert v115.settle_v1_15(C, [ap_nl], view3)["verdict"] == "within_grant"
    for m in (ap_nl, bh_nl):
        s = settle_v1_16(C, [m], view3)
        assert s["verdict"] == "underspecified" and reasons(s) == ["anchor_not_strict"], reasons(s)
    up = dup(g3); up["anchor"]["block_hash"] = up["anchor"]["block_hash"].upper()
    s = settle_v1_16(C, [g3, up, bh_nl], view3)
    assert s["verdict"] == "within_grant" and refused(s) == ["anchor_not_strict", "anchor_not_strict"], refused(s)
    n += 1; print("[3] N1: an action name ending in a line feed (signed): underspecified record_not_strict; a proof operand or block hash "
                  "ending in a line feed on the only copy: underspecified anchor_not_strict; such copies beside a good copy: set aside, within_grant")

    # [4] N3, N4, N6: values and shapes that a JavaScript reader reads differently, or that stopped the reference
    for i, extra in enumerate(({"delegated_to": [{"to": "x"}]}, {"delegated_to": "abc"}, {"approvals": ["x"]}, {"amount_hint": 1.5},
                               {"amount_hint": 2 ** 53}, {"note": "a\x00b"}, {"xé": 1})):
        s, _, _ = run(C, [ex(C, **extra)], "b4%d" % i)
        assert s["verdict"] == "underspecified" and reasons(s) == ["record_not_strict"], (extra, reasons(s))
        junk = ex(C, sign=False, **extra)
        s = settle_v1_16(C, [good, junk], view)
        assert s["verdict"] == "within_grant" and refused(s) == ["record_not_strict"], (extra, s["verdict"], refused(s))
    CI = mk("3" * 32, revocable=False)
    s, R, view_i = run(CI, [ex(CI), rv(CI)], "b4r")
    try:
        v115.settle_v1_15(CI, R, view_i)
        crashed = False
    except Exception:
        crashed = True
    assert crashed and s["verdict"] == "within_grant" and refused(s) == ["revocation_not_provided_for"]
    n += 1; print("[4] N3, N4, N6: an object or a string in delegated_to, a string in approvals, a float, an integer above 2^53 - 1, a NUL, "
                  "a key outside ASCII: signed, underspecified; unsigned beside a good record, set aside, within_grant. A revocation "
                  "against a grant with no revocation block stops v1.15 with an exception; v1.16 sets it aside")

    # [5] N8: a bond is null or an object with a positive integer amount
    for i, bond in enumerate(([], {}, {"amount": "1000"}, {"amount": 0}, {"amount": True}, {"amount": 1.5})):
        cb = mk("4%03d" % i + "4" * 28, bond=bond)
        s, _, _ = run(cb, [ex(cb)], "b5%d" % i)
        assert s["verdict"] == "underspecified" and "bond_malformed" in reasons(s), (bond, reasons(s))
    n += 1; print("[5] N8: a bond of [], {}, a string amount, 0, true or 1.5: underspecified bond_malformed")

    # [6] N9: a signature with S at or above the group order, or with a small order R, is not a signature
    L = L_ORDER
    def malleate(rec):
        r = dup(rec)
        raw = base64.b64decode(r["signatures"][0]["sig_b64"])
        r["signatures"][0]["sig_b64"] = base64.b64encode(raw[:32] + (int.from_bytes(raw[32:], "little") + L).to_bytes(32, "little")).decode()
        return r
    m = malleate(ex(C))
    assert sig_problem(m["signatures"][0]["sig_b64"]) == "S is not below the group order"
    s, _, _ = run(C, [m], "b6")
    assert s["verdict"] == "nothing_to_settle" and len(s["rejected"]) == 1, (s["rejected"], refused(s), reasons(s))
    two = ex(C); two["signatures"].append(malleate(ex(C))["signatures"][0])
    s, _, _ = run(C, [two], "b6b")
    assert s["verdict"] == "within_grant", (s["verdict"], refused(s))
    small_r = base64.b64encode(bytes([1] + [0] * 31) + bytes(32)).decode()
    assert sig_problem(small_r) and sig_problem(small_r).startswith("R ")
    n += 1; print("[6] N9: S + L in place of S: not strictly signed, rejected, nothing_to_settle; the same entry beside a strict "
                  "signature is ignored; an R of small order is refused before OpenSSL is asked")

    # [7] N11: a parent, nenrin_required, an anchor below the lower bound, an empty event set
    P = mk("5" * 32, grant_actions=("read",))
    K = mk("6" * 32, parent=P, grant_actions=("read",))
    s, R, view_k = run(K, [ex(K)], "b7")
    assert s["verdict"] == "underspecified" and reasons(s) == ["parent_not_supplied"], reasons(s)
    assert settle_v1_16(K, R, view_k, parent=P)["verdict"] == "within_grant"
    Kw = mk("7" * 32, parent=P, grant_actions=("read", "pay"))
    s, R, view_w = run(Kw, [ex(Kw)], "b7w")
    assert settle_v1_16(Kw, R, view_w, parent=P)["verdict"] == "underspecified"
    assert "parent_narrowing_failed" in reasons(settle_v1_16(Kw, R, view_w, parent=P))
    CN = mk("8" * 32, evidence="nenrin_required")
    s, _, _ = run(CN, [ex(CN, nenrin_ref=None)], "b7n")
    assert s["verdict"] == "deviation" and clauses(s) == ["evidence_missing"], (s["verdict"], clauses(s))
    s, _, _ = run(CN, [ex(CN)], "b7n2")
    assert s["verdict"] == "within_grant"
    low = dup(good); low["anchor"] = dict(low["anchor"], height=90, block_hash=base.hashes[90])
    a, b = v115.settle_v1_15(C, [low], view), settle_v1_16(C, [low], view)
    assert a["verdict"] == "within_grant" and a["predates_contract"], a["verdict"]
    assert b["verdict"] == "underspecified" and reasons(b) == ["anchor_below_lower_bound"], reasons(b)
    low_u = dup(ex(C, sign=False)); low_u["anchor"] = low["anchor"]
    assert settle_v1_16(C, [good, low_u], view)["verdict"] == "within_grant"
    s, _, _ = run(C, [], "b7e")
    assert s["verdict"] == "nothing_to_settle" and s["status"] == "final"
    n += 1; print("[7] N11: a parent_contract without --parent: underspecified; with a parent it narrows: within_grant; with a parent it "
                  "widens: underspecified; nenrin_required with no nenrin_ref: deviation evidence_missing; a signed record anchored "
                  "below the lower bound: underspecified (v1.15 dropped it and said within_grant); an unsigned one: no effect; no "
                  "record at all: nothing_to_settle")

    # [8] the view
    vb = dup(view); vb["headers"][0]["hex"] = vb["headers"][0]["hex"].upper()
    assert "view_not_strict" in reasons(settle_v1_16(C, [good], vb))
    vb = dup(view); vb["headers"][0]["hex"] += "\n"
    assert "view_not_strict" in reasons(settle_v1_16(C, [good], vb))
    n += 1; print("[8] a header in upper case (v1.15 already refuses it) or ending in a line feed: underspecified view_not_strict")

    # [9] determinism and mutants
    W2 = {"schema": "synthetic-walk-v0", "context": {"contract_sha256": "ee" * 32}, "note": "a walk made under other terms"}
    bad = ex(C, sign=False, nenrin_ref=v1.rec_sha(W2))
    x = settle_v1_16(C, [good, bad], view, nenrin_records=[W2])
    assert canonical(x) == canonical(settle_v1_16(C, [good, bad], view, nenrin_records=[W2]))
    g = globals()
    saved_t, saved_v = g["triage"], g["v115"]

    class Always:                                                             # the rejected record reaches every run
        SETTLE_SCHEMA = saved_v.SETTLE_SCHEMA
        signed_digest = staticmethod(saved_v.signed_digest)

        @staticmethod
        def settle_v1_15(c, evs, vw, **kw):
            return saved_v.settle_v1_15(c, list(evs) + [bad], vw, **kw)
    try:
        g["triage"] = lambda ev, contract: ("keep",)                          # M1: no triage
        killed2 = settle_v1_16(C, [ap_nl], view3)["verdict"] == "within_grant"
        g["v115"] = Always                                                    # M2: no triage, and no run without rejected records
        killed1 = settle_v1_16(C, [good], view, nenrin_records=[W2])["verdict"] == "deviation"
    finally:
        g["triage"], g["v115"] = saved_t, saved_v
    assert killed1 and killed2
    n += 1; print("[9] the same inputs give the same bytes; a mutant without triage misses the line feed; one that also lets the rejected "
                  "record reach every run brings the N2 deviation back")

    # [10] a third party holding copies of genuine records, the contract and the walks cannot change the verdict or the bond
    G = ex(CB, actions=["delete"])
    U1 = {k: v for k, v in G.items() if k != "signatures"}
    U2 = dict(G, signatures=[])
    ch = base.fork(98, "b10")
    A = ch.block([U1]) + ch.block([U2]) + ch.block([G])
    for _ in range(5):
        ch.block()
    v10 = ch.view()
    assert v115.settle_v1_15(CB, A, v10)["bond_outcome"] == "held"                       # v1.15: the unsigned copy displaces G
    s = settle_v1_16(CB, A, v10)
    assert s["verdict"] == "deviation" and s["bond_outcome"] == "forfeited" and len(s["rejected"]) == 2, (s["verdict"], s["rejected"])
    CO = mk("9" * 32)
    CO2 = dict(dup(CO), contract_id=C["contract_id"])                                  # same label, other terms
    old = ex(CO2, actions=["delete"]); old["anchor"] = dup(good["anchor"]); old["anchor"]["block_hash"] = old["anchor"]["block_hash"].upper()
    assert settle_v1_16(C, [good, old], view)["verdict"] == "within_grant"
    flood = [ex(C, sign=False, nenrin_ref="%064x" % i) for i in range(10001)]
    assert settle_v1_16(C, [good] + flood, view)["verdict"] == "within_grant"
    Wf = {"schema": "synthetic-walk-v0", "context": {"contract_sha256": "ee" * 32}, "x": 0.5}
    s, _, _ = run(C, [ex(C, nenrin_ref=v1.rec_sha(Wf))], "b10w", nenrin=[Wf])
    assert s["verdict"] == "underspecified" and reasons(s) == ["walk_not_strict"], reasons(s)
    assert settle_v1_16(C, [good, {"schema": EXEC_SCHEMA, "n": 10 ** 5000}], view)["verdict"] == "within_grant"
    for bad_in in ((None, [good], view), ([], [good], view), (dict(C, grant=True), [good], view), (C, "x", view), (C, [good], None),
                   (C, [good], {"headers": "x"}), (dict(C, parties=[{}, {}]), [good], view)):
        assert settle_v1_16(*bad_in)["verdict"] == "underspecified"
    assert settle_v1_16(C, [good], view, nenrin_records=True)["verdict"] == "within_grant"
    assert settle_v1_16(dict(C, parent_contract={"contract_id": "x"}), [good], view, parent=True)["verdict"] == "underspecified"
    n += 1; print("[10] third parties: two unsigned copies anchored before the contractor's record (v1.15 lets one displace it and holds "
                  "the bond; v1.16 deviation, forfeited); a record of earlier terms under the same contract_id with a bad anchor; 10001 "
                  "unsigned records; an integer too long to digest: no effect. A cited walk with a float: underspecified walk_not_strict. "
                  "A contract, events, view, walks or parent of the wrong shape: a settlement, never an exception")

    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_15.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[11] settle_v1_15 self test (and every layer it runs) still passes")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.16, %d checks (v1.15's answer where nothing is wrong; N2 the walk check reads accepted "
          "records only; N1 line feeds; N3 N4 N6 values and shapes; N8 bonds; N9 strict signatures; N11 parent, nenrin_required, "
          "anchors below the lower bound, nothing to settle; the view; determinism and mutants; third parties; lower layers unchanged)" % n)


# --------------------------------------------------------------------------- command line
def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.16 (strict inputs; the walk check reads accepted records only)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--view", action="append", default=[])
    ap.add_argument("--nenrin", action="append", default=[])
    ap.add_argument("--admission", action="append", default=[], help="a signed a2a-admission-v0 record with its anchor")
    ap.add_argument("--relying-key", action="append", default=[], metavar="DOMAIN=BASE64", help="the relying party's Ed25519 key, fetched from its key_url")
    ap.add_argument("--parent", metavar="PARENT_CONTRACT.json", help="the parent contract, when the contract names a parent_contract")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    for vw in views:
        why = view_problem(vw)
        if why:
            print(json.dumps({"view_not_strict": why}, indent=2)); return 2
    cmp = v115.v110.v19.v18.v17.v14.compare_views_v1_4(views, contract)
    if cmp["chosen"] is None:
        print(json.dumps({"fork_choice": cmp}, indent=2)); return 2
    keys = dict(x.split("=", 1) for x in a.relying_key)
    s = settle_v1_16(contract, [rd(p) for p in a.event], views[cmp["chosen"]], parent=rd(a.parent) if a.parent else None,
                     admissions=[rd(p) for p in a.admission], relying_keys=keys, nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
