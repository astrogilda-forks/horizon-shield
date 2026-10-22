#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.13: an approval for a limited action must name the amount it covers (a2a-settlement-v1.13).

Why this file exists. settle v1.12 reads each execution's amount against grant.limits, a cap no approval lifts. What it
could not read is the approval's own extent: an a2a-approval-v2 approval carries no amount in its signed bytes, so a
pinned approver who meant "150,000, once" signed bytes that cover any amount up to the cap. On #29 (2026-10-10) the
author of the v2 reference agreed: keep v2 frozen, and put an amount-bound approval here, next to grant.limits, which
is what it binds to. That is a2a-approval-v3 (approval_v3.py, APPROVAL_V3.md).

When the rule applies. Only when grant.limits names an action that a pinned approver gates (grant.approval_policy
.approvers[].actions). For every other contract this file returns settle v1.12's result unchanged, the same bytes:
contracts without limits, contracts whose limited actions no approver gates, run0002, the outside parties' contract
d7118f28 and the 18 scenario corpus settle exactly as before.

What changes when it applies, and nothing else:

  the approver rule        for the length of one call, settle v1.10's pinned approver check and clause_eval_v0's (which
                           settle v1.11 uses to recompute admissions) read approval_v3.verify_approver_any: a v3 entry is
                           verified over the v3 bytes, any other entry by the v2 rule with the nonce read by \\Z, as
                           babyblueviper1's reference reads it since bcf6592 (sha256 72f807a4...). Both names are
                           restored in a finally block. No earlier settle file and no pinned file is edited.
  amount_not_approved      for each gated, limited action in an accepted execution record that the lower layers counted
                           as approved (no conditional and no revoked clause for it), and whose record states an amount,
                           a pinned approver's verifying a2a-approval-v3 for that action must cover the amount: anchored
                           in this record or an earlier one, valid_until_height at or above this record's height, not
                           already spent if single_use, and max_amount at or above the amount. Approvals are taken first
                           fit in (height, record sha256, list) order, the order of settle v1.7's walk. Only the records
                           the walk accepted are read, at the heights it verified (authoritative_event_set): a copy
                           dropped as a duplicate anchoring or a record with an inconsistent binding covers nothing. A v3
                           approval whose nonce another approval entry also carries is not used (the walk spends one
                           nonce across all approvals, so it may already be spent there). When none covers
                           it, the clause is raised with the reason: the approval counted names no amount (v2, or a
                           principal's), the v3 approval covers less than the amount, or no v3 approval was usable then.

An execution that states no amount is v1.12's amount_over_limit and is not named twice. A v3 approval whose unit is not
grant.limits' unit for the action, or for an action with no limit, does not verify, so the walk does not count it.

Stated limits: as v1.12. The amount is the one the execution record states and the admission's digest binds; whether
it is the amount that moved in the world is outside these records. The approver's signature proves it signed that
amount, not that the amount was right. Only approver-gated actions are read: a conditional action the principal
approves is still approved by bytes without an amount (settle v1.6), and the cap of v1.12 is all that bounds it.
"""
import argparse, base64, collections, contextlib, hashlib, json, os, sys, threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_2 as v12
import settle_v1_5 as v15
import settle_v1_10 as v110
import settle_v1_11 as v111
import settle_v1_12 as v112
import clause_eval_v0 as ce
import approval_v3 as AV
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.13"
CLAUSES = ("amount_not_approved",)
NOT_APPROVED = ("conditional", "revoked", "prohibited")


def gated_limited(contract):
    """The actions a pinned approver gates and grant.limits caps: the ones this file reads."""
    return sorted(a for a in ce.gated_actions(contract) if ce.limit_for(contract, a) is not None)


def applies(contract):
    return v112.has_limits(contract) and bool(gated_limited(contract))


_SWAP = threading.RLock()


@contextlib.contextmanager
def _approver_rule():
    """Point settle v1.10's and clause_eval_v0's approver rule at approval_v3.verify_approver_any for one call. The lock
    keeps two threads from saving each other's swapped name; an earlier layer called in another thread during the call
    would still read the swapped rule, so settle layers are not to be run concurrently in one process."""
    with _SWAP:
        saved = (v110.verify_approver_approval, ce.verify_approver_approval)
        v110.verify_approver_approval = AV.verify_approver_any
        ce.verify_approver_approval = AV.verify_approver_any
        try:
            yield
        finally:
            v110.verify_approver_approval, ce.verify_approver_approval = saved


def _accepted(events, settlement):
    """The execution records the lower layers walked, at the heights they verified: settlement["authoritative_event_set"]
    (settle v1.7), matched to the records in hand by record sha256. A copy dropped as a duplicate anchoring, a record
    with an inconsistent binding, or one rejected or orphaned is not in that set and is not read here."""
    by_sha = {}
    for ev in events if isinstance(events, list) else []:
        if isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA:
            by_sha.setdefault(v1.rec_sha(ev), ev)
    recs = []
    for x in settlement.get("authoritative_event_set") or []:
        if not isinstance(x, dict) or x.get("kind") != "execution":
            continue
        ev, h = by_sha.get(x.get("sha256")), x.get("height")
        if ev is not None and isinstance(h, int) and not isinstance(h, bool):
            recs.append((h, x["sha256"], ev))
    recs.sort(key=lambda t: (t[0], t[1]))
    return recs


def _shared_nonces(recs):
    """Nonces that two different approval entries in the walked records carry. settle v1.7's walk spends one nonce
    across every counted approval, v2 and v3 and every action; a v3 approval whose nonce another entry also carries is
    not used here, so its single use cannot be spent once by the walk and again by this rule."""
    seen = {}
    for _h, _s, ev in recs:
        for ap in ev.get("approvals") or []:
            if isinstance(ap, dict) and isinstance(ap.get("nonce"), str):
                seen.setdefault(ap["nonce"], set()).add(canonical(ap))
    return {k for k, v in seen.items() if len(v) > 1}


def amount_approval_deviations(contract, events, settlement):
    """The v1.13 rule over the execution records the lower layers walked. Returns (deviations, read)."""
    G = set(gated_limited(contract))
    recs = _accepted(events, settlement)
    not_approved = collections.Counter((d.get("record_sha256"), d.get("observed")) for d in settlement.get("deviations") or []
                                       if isinstance(d, dict) and d.get("clause") in NOT_APPROVED)
    shared = _shared_nonces(recs)
    carriers = []
    for h, s, ev in recs:
        for ap in ev.get("approvals") or []:
            if AV.is_v3(ap) and ap.get("action") in G and ap.get("nonce") not in shared and AV.verify_approval_v3(contract, ap)[0] == "approved":
                carriers.append((h, s, ap))
    used, devs, read = set(), [], []
    for h, s, ev in recs:
        refs = [r for r in ev.get("admission_ref") if isinstance(r, dict)] if isinstance(ev.get("admission_ref"), list) else []
        taken = set()
        for a in [x for x in (ev.get("performed_actions") or []) if isinstance(x, str)]:
            i = next((i for i, r in enumerate(refs) if i not in taken and r.get("action") == a), None)
            ex = {}
            if i is not None:
                taken.add(i)
                ex = refs[i].get("executed") if isinstance(refs[i].get("executed"), dict) else {}
            if a not in G:
                continue
            if not_approved[(s, a)] > 0:                                   # the walk did not count an approval for this one
                not_approved[(s, a)] -= 1
                continue
            amount = ex.get("amount") if ex.get("action") == a else None
            if not (isinstance(amount, int) and not isinstance(amount, bool) and 0 <= amount <= AV.SAFE):
                continue                                                   # v1.12's amount_over_limit names it
            unit = ce.limit_for(contract, a)[1]
            usable = [(ch, cs, ap) for ch, cs, ap in carriers if ap["action"] == a and (cs == s or ch < h)
                      and h <= ap["valid_until_height"] and not (ap["single_use"] and ap["nonce"] in used)]
            pick = next(((ch, cs, ap) for ch, cs, ap in usable if AV.covers(ap, amount)), None)
            row = {"action": a, "amount": amount, "unit": unit, "record_sha256": s, "covered": pick is not None,
                   "approval_nonce": pick[2]["nonce"] if pick else None, "max_amount": pick[2]["max_amount"] if pick else None,
                   "approval_record_sha256": pick[1] if pick else None}
            read.append(row)
            if pick is not None:
                if pick[2]["single_use"]:
                    used.add(pick[2]["nonce"])
                continue
            if usable:
                top = max(usable, key=lambda t: int(t[2]["max_amount"]))[2]
                why = "the a2a-approval-v3 for %s covers at most %s %s; the execution states %d" % (a, top["max_amount"], unit, amount)
            elif any(ap["action"] == a for _ch, _cs, ap in carriers):
                why = "no a2a-approval-v3 for %s was anchored by then, unexpired and unspent, to cover %d %s" % (a, amount, unit)
            elif any(AV.is_v3(ap) and ap.get("action") == a and ap.get("nonce") in shared
                     for _h, _s, e in recs for ap in (e.get("approvals") or [])):
                why = "the a2a-approval-v3 for %s shares its nonce with another approval entry, so it is not used to cover %d %s" % (a, amount, unit)
            else:
                why = ("the approval counted for %s names no amount (a2a-approval-v2 or the principal's); under grant.limits an approval "
                       "for it must be a2a-approval-v3 naming at least %d %s" % (a, amount, unit))
            devs.append({"clause": "amount_not_approved", "observed": a, "height": h, "record_sha256": s, "why": why})
    return devs, read


def settle_v1_13(contract, events, view, admissions=None, relying_keys=None, mode="strict", nenrin_records=None, spine=None,
                 pool=None, contract_anchor_height=None, history=None):
    kw = dict(admissions=admissions, relying_keys=relying_keys, mode=mode, nenrin_records=nenrin_records, spine=spine, pool=pool,
              contract_anchor_height=contract_anchor_height, history=history)
    if not applies(contract):
        return v112.settle_v1_12(contract, events, view, **kw)
    with _approver_rule():
        s = v112.settle_v1_12(contract, events, view, **kw)
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, s.get("schema")
    devs, read = ([], []) if s.get("verdict") == "underspecified" else amount_approval_deviations(contract, events, s)
    out["deviations"] = list(s.get("deviations") or []) + devs
    if s.get("verdict") != "underspecified":
        out["verdict"] = "deviation" if out["deviations"] else "within_grant"
        out["bond_outcome"] = v15._bond_outcome(contract, out["verdict"], out.get("status"))
    out["amount_approval_gate"] = {"rule": SETTLE_SCHEMA, "approval": AV.APPROVAL, "verifier_sha256": AV.verifier_sha256(),
                                   "actions": gated_limited(contract), "approvals_read": sorted(read, key=canonical),
                                   "counts": {c: sum(1 for d in devs if d["clause"] == c) for c in CLAUSES}}
    out["establishes"] = list(s.get("establishes") or []) + [
        "that an approval counted for %s may be a2a-approval-v3, verified over its own bytes (approval_gate reads a2a-approval-v2 bytes for "
        "the rest), and that a v2 nonce was read with \\Z" % ", ".join(gated_limited(contract)),
        "that every approved execution of %s that states an amount was covered by a pinned approver's a2a-approval-v3 naming at least that "
        "amount in grant.limits' unit, under the rule in a2a-settlement-v1.13" % ", ".join(gated_limited(contract))]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + [
        "that the amount an approval names was the right amount to approve; only that the pinned approver's key signed it",
        "that a settler older than v1.13 reads the amount an approval names, or that a principal's approval names one"]
    return out


# --------------------------------------------------------------------------- self test
def _selftest():
    import subprocess
    import settle_v1_1 as v11
    import settle_v1_6 as v16
    import contract_v0 as v0
    import admission_verify_v0 as A
    n = 0
    key = AV._key
    ka, pa = key("principal"); kb, pb = key("contractor"); _kw, pw = key("witness"); kz, pz = key("approver"); kr, pr = key("relying")
    RK = {"shop.example": pr}
    PDG = "a" * 64
    base = v11._Chain(60, "00" * 32, "v113")
    for _ in range(38):
        base.block()
    lb = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    DNE = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]
    PIN = [{"name": "approver.example", "public_key_ed25519_b64": pz, "actions": ["emit_witness", "pay_large"]}]
    NEED = {"evidence": "nenrin_required", "recovery": "tsugi_required", "admission": "required_before_execution"}

    def mk(limits, approvers_=PIN, nonce="c" * 32):
        g = {"authorized_actions": ["read", "emit_witness", "pay"], "prohibited_actions": ["delete"],
             "conditional": [{"action": "emit_witness", "requires": "approver"}, {"action": "pay_large", "requires": "approver"}],
             "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"}, "finality": {"depth": 3, "max_target_bits": "207fffff"},
             "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}],
             "approval_policy": {"allow_unscoped": False, "approvers": approvers_}}
        if limits is not None:
            g["limits"] = limits
        c = v0.build_contract(
            {"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
            {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
            {"purpose": "settle_v1_13_selftest", "payload_digest": PDG, "a2a_task_id": "t13"}, g,
            ["that both parties signed these grant bytes at the stated time"], DNE, requirements=NEED,
            bond={"amount": 1000, "currency": "JPY"}, lower_bound=lb,
            contract_id="0123456789abcdef0123456789abc113", nonce=nonce, agreed_at="2026-10-10T00:00:00Z")
        v0.sign_contract(c, ka, pa, "a.example"); v0.sign_contract(c, kb, pb, "b.example")
        return c

    LIM = {"pay": {"max_amount": 100000, "unit": "JPY"}, "pay_large": {"max_amount": 1000000, "unit": "JPY"}}
    C = mk(LIM)
    assert v0.verify_contract(C)["verdict"] == "accepted", v0.verify_contract(C)
    seq = [0]

    def admit(c, action, amount, decision="admit", reasons=("within_grant",), clause=None, exp=500):
        seq[0] += 1
        nonce = "%032x" % (0x5a00 + seq[0])
        csha = contract_sha256(c)
        req = {"action": {"action": action, "target": None, "amount": amount}, "nonce": nonce, "expiry_height": exp}
        rec = {"schema": A.SCHEMA, "admission_id": "adm-%d" % seq[0],
               "relying_party": {"domain": "shop.example", "key_url": "https://shop.example/keys/agreement.json"},
               "contract_ref": {"contract_id": c["contract_id"], "contract_sha256": csha},
               "action_ref": {"action_binding_digest": A.action_digest(csha, req), "nonce": nonce},
               "presentation_ref": [{"adapter": "musubi-native", "sha256": "0" * 64, "verified": True}],
               "chain_view": {"height": 97, "header_sha256": "ab" * 32}, "revocations_seen": [],
               "decision": decision, "reasons": list(reasons), "clause": clause or ce.clause_path(c, action),
               "rules": {"admit": A.SCHEMA, "version": A.VERSION, "evaluator_sha256": ce.evaluator_sha256()},
               "establishes": ["that the relying party named here ran admit() over this contract, this action digest and this chain view, and signed the result",
                               "that the decision and reasons are what the shared clause evaluator (rules.evaluator_sha256) returns for those inputs; anyone holding them can recompute it"],
               "does_not_establish": list(A.DOES_NOT_ESTABLISH)}
        rec["signatures"] = [{"domain": "shop.example", "alg": "ed25519", "sig": base64.b64encode(kr.sign(A.admission_signing_bytes(rec))).decode("ascii")}]
        ref = {"action": action, "admission_sha256": A.admission_sha256(rec),
               "executed": {"action": action, "target": None, "amount": amount, "nonce": nonce, "expiry_height": exp}}
        return dict(rec, anchor={"height": 97}), ref

    def ex(c, actions, approvals=(), refs=(), tag="1"):
        r = {"schema": EXEC_SCHEMA, "contract_ref": {"contract_id": c["contract_id"], "payload_digest": PDG, "contract_sha256": contract_sha256(c)},
             "performed_actions": list(actions), "approvals": list(approvals), "delegated_to": [], "nenrin_ref": (tag * 64)[:64],
             "admission_ref": list(refs)}
        return v12.sign_record(r, kb, "contractor")

    def run(c, blocks, tag, settle=None):
        """blocks: a list of lists of (actions, approvals, [(action, amount, decision, reasons)]) per record."""
        ch = base.fork(98, tag)
        recs, adms = [], []
        for bi, blk in enumerate(blocks):
            rows = []
            for ri, (acts, aps, asks) in enumerate(blk):
                refs = []
                for (a, amt, dec, rs) in asks:
                    adm, ref = admit(c, a, amt, dec, rs)
                    adms.append(adm); refs.append(ref)
                rows.append(ex(c, acts, aps, refs, tag="%x" % ((bi * 4 + ri) % 15 + 1)))
            recs += ch.block(rows) if rows else ch.block()
        for _ in range(5):
            ch.block()
        view = ch.view()
        return (settle or settle_v1_13)(c, recs, view, admissions=adms, relying_keys=RK), (c, recs, view, adms)

    v3 = lambda amount, nonce, **k: AV.sign_approval_v3(kz, C, k.pop("action", "pay_large"), str(amount), k.pop("unit", "JPY"),
                                                       k.pop("vu", 500), nonce, "approver.example", pz, **k)
    v2 = lambda nonce, action="pay_large", c=None: ce.sign_approver_approval(kz, c or C, action, 500, nonce, "approver.example", pz)
    clauses = lambda s: sorted(d["clause"] for d in s["deviations"])
    ADM = [("pay_large", 150000, "admit", ["within_grant"])]

    # [1] contracts this file does not read: v1.12's bytes
    s, args = run(mk(None, nonce="d" * 32), [[(["emit_witness"], [v2("11" * 16, "emit_witness", mk(None, nonce="d" * 32))], [("emit_witness", None, "admit", ["within_grant"])])]], "n1")
    assert canonical(s) == canonical(v112.settle_v1_12(*args[:3], admissions=args[3], relying_keys=RK))
    Cpay = mk({"pay": {"max_amount": 100000, "unit": "JPY"}}, nonce="e" * 32)
    assert v112.has_limits(Cpay) and not applies(Cpay)
    s, args = run(Cpay, [[(["pay"], [], [("pay", 80000, "admit", ["within_grant"])])]], "n2")
    assert canonical(s) == canonical(v112.settle_v1_12(*args[:3], admissions=args[3], relying_keys=RK)) and s["verdict"] == "within_grant"
    fx = v111.load_fixture()
    contracts, cases, keys = fx
    same = changed = 0
    for k, c in sorted(cases.items()):
        a = v111.settle_fixture_case(settle_v1_13, k, fx)
        b = v111.settle_fixture_case(v112.settle_v1_12, k, fx)
        if not applies(contracts[c["contract"]]):
            assert canonical(a) == canonical(b), k
            same += 1
            continue
        extra = [d for d in a["deviations"] if d["clause"] == "amount_not_approved"]
        assert clauses(a) == sorted(clauses(b) + ["amount_not_approved"] * len(extra)), k
        changed += bool(extra)
        assert (k in ("v12/pay_large_150000_approved", "v12/pay_large_2000000_approved_admitted_by_mistake")) == bool(extra), (k, extra)
    rr = os.path.join(HERE, "run0002")
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    r2 = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    assert canonical(settle_v1_13(*r2, nenrin_records=nr)) == canonical(v112.settle_v1_12(*r2, nenrin_records=nr))
    n += 1; print("[1] not read here (no limits, or no limited action an approver gates): v1.12 byte for byte, %d fixture scenarios and run0002; "
                  "under the fixture's limits contract only the two cases that carry a v2 approval for pay_large gain amount_not_approved" % same)

    # [2] a v3 approval that covers the amount: within_grant, final; admitted or escalated
    s, _ = run(C, [[(["pay_large"], [v3(150000, "21" * 16)], ADM)]], "a1")
    assert s["schema"] == SETTLE_SCHEMA and s["settled_under"] == v112.SETTLE_SCHEMA and s["verdict"] == "within_grant" and s["status"] == "final", s["deviations"]
    row = s["amount_approval_gate"]["approvals_read"][0]
    assert row["covered"] and row["amount"] == 150000 and row["max_amount"] == "150000" and row["unit"] == "JPY"
    assert s["amount_approval_gate"]["verifier_sha256"] == AV.verifier_sha256() and s["amount_approval_gate"]["actions"] == ["pay_large"]
    s, _ = run(C, [[(["pay_large"], [v3(200000, "22" * 16)], [("pay_large", 150000, "escalate", ["conditional_needs_approval"])])]], "a2")
    assert s["verdict"] == "within_grant", s["deviations"]
    n += 1; print("[2] pay_large 150,000 with the pinned approver's v3 approval for 150,000 (admitted) or 200,000 (escalated, approval carried): within_grant, final")

    # [3] the approval covers less, or names no amount
    s, _ = run(C, [[(["pay_large"], [v3(100000, "23" * 16)], ADM)]], "b1")
    assert clauses(s) == ["amount_not_approved"] and "covers at most 100000 JPY; the execution states 150000" in s["deviations"][0]["why"], s["deviations"]
    s, args = run(C, [[(["pay_large"], [v2("24" * 16)], ADM)]], "b2")
    assert clauses(s) == ["amount_not_approved"] and "names no amount" in s["deviations"][0]["why"]
    assert v112.settle_v1_12(*args[:3], admissions=args[3], relying_keys=RK)["verdict"] == "within_grant"
    n += 1; print("[3] a v3 approval for 100,000 on a 150,000 execution, or a v2 approval (within_grant under v1.12): amount_not_approved, with the reason")

    # [4] a v3 approval the walk does not count is not named twice
    s, _ = run(C, [[(["pay_large"], [v3(150000, "25" * 16, unit="USD")], ADM)]], "c1")
    assert clauses(s) == ["admitted_out_of_grant", "approval_unverified", "conditional"], clauses(s)
    assert next(d for d in s["deviations"] if d["clause"] == "approval_unverified")["reason"] == "unit_differs_from_limit"
    s, _ = run(C, [[(["pay_large"], [v3(150000, "26" * 16, vu=97)], ADM)]], "c2")
    assert "conditional" in clauses(s) and "amount_not_approved" not in clauses(s), clauses(s)
    s, _ = run(C, [[(["emit_witness"], [AV.sign_approval_v3(kz, C, "emit_witness", "1", "JPY", 500, "27" * 16, "approver.example", pz)],
                     [("emit_witness", None, "admit", ["within_grant"])])]], "c3")
    assert next(d for d in s["deviations"] if d["clause"] == "approval_unverified")["reason"] == "action_has_no_limit" and "amount_not_approved" not in clauses(s)
    n += 1; print("[4] a v3 approval in another unit, expired, or for an action with no limit: the walk does not count it (approval_unverified "
                  "with the reason, conditional) and amount_not_approved is not added")

    # [5] carried earlier, reusable or single use, first fit
    R = v3(200000, "28" * 16, single_use=False)
    s, _ = run(C, [[(["pay_large"], [R], [("pay_large", 150000, "admit", ["within_grant"])])],
                   [(["pay_large"], [R], [("pay_large", 300000, "admit", ["within_grant"])])]], "d1")
    assert clauses(s) == ["amount_not_approved"] and "covers at most 200000 JPY; the execution states 300000" in s["deviations"][0]["why"], s["deviations"]
    s, _ = run(C, [[(["pay_large"], [v3(100000, "29" * 16), v3(200000, "2a" * 16)], ADM)]], "d2")
    assert s["verdict"] == "within_grant" and s["amount_approval_gate"]["approvals_read"][0]["approval_nonce"] == "2a" * 16, s["deviations"]
    s, _ = run(C, [[(["pay_large"], [v3(200000, "2b" * 16)], ADM)], [(["pay_large"], [], ADM)]], "d3")
    assert "conditional" in clauses(s) and "amount_not_approved" not in clauses(s), clauses(s)
    n += 1; print("[5] a reusable v3 for 200,000 covers 150,000 and, carried again later, not 300,000; of two v3 approvals the one that covers "
                  "is used; a single use v3 spent once leaves the next execution unapproved (conditional, not named twice)")

    # [5b] only the records the walk accepted, at the heights it verified; nonces shared with another entry are not used
    def chain(tag):
        return base.fork(98, tag)
    ch = chain("g1")
    adm1, ref1 = admit(C, "pay_large", 150000)
    adm2, ref2 = admit(C, "read", None)
    E1 = ch.block([ex(C, ["pay_large"], [v2("41" * 16)], [ref1], tag="4")])
    R = ch.block([ex(C, ["read"], [v3(150000, "42" * 16)], [ref2], tag="5")])
    Rp = json.loads(json.dumps(R[0])); Rp["anchor"] = dict(R[0]["anchor"], height=97, block_hash="11" * 32)
    Rb = json.loads(json.dumps(R[0])); Rb["contract_ref"] = dict(Rb["contract_ref"], payload_digest="b" * 64)
    Rb.pop("anchor"); Rb.pop("signatures"); Rb = v12.sign_record(Rb, kb, "contractor"); Rb["anchor"] = dict(R[0]["anchor"], height=97)
    for _ in range(5):
        ch.block()
    M5 = (E1 + R + [Rp], ch.view(), [adm1, adm2])
    for extra, what in (([Rp], "a copy of a later record with a forged earlier anchor"), ([Rb], "a record with an inconsistent binding claiming an earlier height")):
        s = settle_v1_13(C, E1 + R + extra, ch.view(), admissions=[adm1, adm2], relying_keys=RK)
        d = [x for x in s["deviations"] if x["clause"] == "amount_not_approved"]
        assert len(d) == 1 and d[0]["height"] == 98 and "anchored by then" in d[0]["why"], (what, s["deviations"])
    ch = chain("g2")
    adm1, ref1 = admit(C, "emit_witness", None)
    adm2, ref2 = admit(C, "pay_large", 150000)
    N = "43" * 16
    A1 = ch.block([ex(C, ["emit_witness"], [v2(N, "emit_witness")], [ref1], tag="6")])
    A2 = ch.block([ex(C, ["pay_large"], [v2("44" * 16), v3(150000, N)], [ref2], tag="7")])
    for _ in range(5):
        ch.block()
    s = settle_v1_13(C, A1 + A2, ch.view(), admissions=[adm1, adm2], relying_keys=RK)
    assert clauses(s) == ["amount_not_approved"] and "shares its nonce" in s["deviations"][0]["why"], s["deviations"]
    n += 1; print("[5b] a v3 approval in a dropped copy with a forged earlier anchor, or in a record with an inconsistent binding, covers nothing; "
                  "a v3 approval whose nonce a v2 approval already spent is not used")

    # [6] the v2 nonce is read with \Z here, with $ by v1.12 (the published clause_eval_v0)
    nl = ce.sign_approver_approval(kz, C, "emit_witness", 500, "2c" * 16 + "\n", "approver.example", pz)
    s, args = run(C, [[(["emit_witness"], [nl], [("emit_witness", None, "admit", ["within_grant"])])]], "e1")
    assert v112.settle_v1_12(*args[:3], admissions=args[3], relying_keys=RK)["verdict"] == "within_grant"
    assert next(d for d in s["deviations"] if d["clause"] == "approval_unverified")["reason"] == "malformed", s["deviations"]
    n += 1; print("[6] a v2 approval whose nonce ends in a newline: counted by v1.12, malformed here (babyblueviper1's reference at 72f807a4 reads it the same way)")

    # [7] the swapped names are restored, also when the lower layer raises
    assert v110.verify_approver_approval is ce.verify_approver_approval is AV._V2_RULE
    saved = v112.settle_v1_12
    try:
        v112.settle_v1_12 = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            settle_v1_13(C, [], {"headers": []})
        except RuntimeError:
            pass
    finally:
        v112.settle_v1_12 = saved
    assert v110.verify_approver_approval is ce.verify_approver_approval is AV._V2_RULE
    n += 1; print("[7] settle v1.10's and clause_eval_v0's approver rule are restored after the call, also when it raises")

    # [8] determinism
    a, _ = run(C, [[(["pay_large"], [v3(100000, "2d" * 16)], ADM)]], "f1")
    seq[0] -= 1
    b, _ = run(C, [[(["pay_large"], [v3(100000, "2d" * 16)], ADM)]], "f1")
    assert canonical(a) == canonical(b)
    n += 1; print("[8] the same inputs give the same settlement bytes")

    # [9] mutants: each must change a verdict the checks above expect
    killed, g = 0, globals()
    saved = g["amount_approval_deviations"]
    try:
        g["amount_approval_deviations"] = lambda *a, **k: ([], [])                           # M1: the rule is skipped
        killed += run(C, [[(["pay_large"], [v3(100000, "30" * 16)], ADM)]], "m1")[0]["verdict"] == "within_grant"
    finally:
        g["amount_approval_deviations"] = saved
    real = AV.covers
    try:
        AV.covers = lambda e, amount: AV.is_v3(e)                                           # M2: the amount is not compared
        killed += run(C, [[(["pay_large"], [v3(100000, "31" * 16)], ADM)]], "m2")[0]["verdict"] == "within_grant"
    finally:
        AV.covers = real
    saved_rule = g["_approver_rule"]
    try:
        g["_approver_rule"] = contextlib.nullcontext                                        # M3: v3 is never counted by the walk
        killed += run(C, [[(["pay_large"], [v3(150000, "32" * 16)], ADM)]], "m3")[0]["verdict"] != "within_grant"
    finally:
        g["_approver_rule"] = saved_rule
    real_v3 = AV.verify_approval_v3
    try:
        AV.verify_approval_v3 = lambda c, e: ("approved", None)                              # M4: any v3 entry counts, signed or not
        forged = dict(v3(500000, "33" * 16), sig_b64=base64.b64encode(b"\0" * 64).decode())
        killed += run(C, [[(["pay_large"], [forged], ADM)]], "m4")[0]["verdict"] == "within_grant"
    finally:
        AV.verify_approval_v3 = real_v3
    saved_acc = g["_accepted"]
    try:
        def every_record(events, settlement):                                               # M5: records re-read from the input, not the walk's set
            return sorted((v1.height_of(e), v1.rec_sha(e), e) for e in events if isinstance(e, dict) and e.get("schema") == EXEC_SCHEMA
                          and v1.height_of(e) is not None)
        g["_accepted"] = every_record
        s = settle_v1_13(C, M5[0], M5[1], admissions=M5[2], relying_keys=RK)
        killed += "amount_not_approved" not in clauses(s)
    finally:
        g["_accepted"] = saved_acc
    assert killed == 5, killed
    n += 1; print("[9] 5 mutants (rule skipped, amount not compared, v3 not counted, signature not checked, records not taken from the walk): "
                  "all 5 change a verdict the checks above expect")

    r = subprocess.run([sys.executable, os.path.join(HERE, "approval_v3.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-400:], r.stderr[-400:])
    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_12.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[10] approval_v3 self test (vectors in Python and JavaScript) and settle_v1_12 self test (and every layer it runs) pass")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.13, %d checks (not read here: v1.12 byte for byte; v3 covers: within_grant; covers less or names no "
          "amount: amount_not_approved; uncounted v3 not named twice; reusable, first fit, single use; v2 nonce read with \\Z; names "
          "restored; determinism; 5 mutants; lower layers unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.13 (an approval for a limited action names the amount it covers)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--view", action="append", default=[])
    ap.add_argument("--nenrin", action="append", default=[])
    ap.add_argument("--admission", action="append", default=[], help="a signed a2a-admission-v0 record with its anchor")
    ap.add_argument("--relying-key", action="append", default=[], metavar="DOMAIN=BASE64", help="the relying party's Ed25519 key, fetched from its key_url")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    cmp = v110.v19.v18.v17.v14.compare_views_v1_4(views, contract)
    if cmp["chosen"] is None:
        print(json.dumps({"fork_choice": cmp}, indent=2)); return 2
    keys = dict(x.split("=", 1) for x in a.relying_key)
    s = settle_v1_13(contract, [rd(p) for p in a.event], views[cmp["chosen"]], admissions=[rd(p) for p in a.admission], relying_keys=keys,
                     nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
