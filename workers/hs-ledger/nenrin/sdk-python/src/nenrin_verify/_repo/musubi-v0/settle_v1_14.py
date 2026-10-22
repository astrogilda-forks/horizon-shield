#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.14: the admission and limit rules read only the execution records the walk accepted
(a2a-settlement-v1.14). One change, and nothing else.

Why this file exists. settle v1.11 (admissions) and v1.12 (limits) pick their execution records again from the input,
keeping every record that names these terms and carries the contractor's signature. The walk under them (settle v1.7)
does more: it keeps one copy of a record anchored more than once, checks each anchor against the headers, and sets aside
a record whose binding is inconsistent. The anchor is not covered by the contractor's signature, so anyone holding a
record can add a copy with a different anchor. v1.11 and v1.12 read that copy too, at the height it claims:

  - a copy with a forged earlier anchor uses the record's admission first, and the genuine record is then reported as
    unadmitted_execution ("the admission named was already used by an earlier action");
  - a record anchored twice, both validly, is read twice, and the second reading is unadmitted_execution;
  - a copy whose unsigned signatures list was edited is a second body to the walk, and is read as a second act;
  - a copy of a record with an inconsistent binding is read at whatever height it claims.

Each is a deviation nobody committed, added by whoever submits the copy. Two more came out of the same review: when one
admission is given more than once with different anchors, v1.11 keeps the last copy in the list, so the order decided
whether the execution was admitted in time; and an admission_ref whose admission_sha256 is a list or an object makes
v1.11 raise, so one record stopped every settlement of the contract. Found on 2026-10-10 by independent adversarial
reviews of settle v1.13 and of this file. v1.11 and v1.12 are published and are not edited; settlements made under them
recompute to the same bytes.

When the rule applies. Only when contract.requirements.admission is "required_before_execution", the contracts v1.11
reads. For every other contract this file returns settle v1.13's result unchanged, the same bytes.

What changes when it applies, and nothing else:

  inputs           one copy per admission (the same signed bytes): the one with the lowest stated anchor height. An
                   execution whose admission_ref names an admission_sha256 that is not a string is taken out of the input
                   and charged to its signer as nonconforming_record.
  the records      the admission rule (v1.11), the limit rule (v1.12) and the amount rule (v1.13) read the execution
                   records the walk accepted, each the copy whose anchor it verified (authoritative_event_set), plus a
                   record the walk set aside as an inconsistent binding when a party the schema allows signed it and
                   its anchor verifies (contract_ref is inside the signed bytes, so only that party could have made it).
                   Of records with the same signed bytes, only the one at the lowest (height, record sha256) is read.
  the output       those three rules' deviations, admission_gate.admissions_read and .counts, and limit_gate.amounts_read
                   and .counts are recomputed over those records. The walk's own deviations, its event set, its anchors
                   and everything else are v1.13's. With no extra copies, no repeated admissions and no malformed
                   admission_ref, the result differs from v1.13 only in schema, settled_under, establishes and
                   does_not_establish.

Stated limits: as v1.13. An admission's anchor height is read as stated, as before; it is the caller's to check when it
collects the admissions. The walk itself (settle v1.7) is not changed: it still treats two records with the same signed
bytes and different signatures lists as two bodies, so its own clauses (an approval reused, for one) can count such a
copy twice, and a copy carrying the genuine record's anchor makes the anchor proof fail for the whole settlement. Those
belong to the walk and are for the next layer.
"""
import argparse, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_1 as v11
import settle_v1_2 as v12
import settle_v1_7 as v17
import admission_verify_v0 as A
import settle_v1_5 as v15
import settle_v1_10 as v110
import settle_v1_11 as v111
import settle_v1_12 as v112
import settle_v1_13 as v113
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.14"
LAYER_CLAUSES = frozenset(v111.CLAUSES) | frozenset(v112.CLAUSES) | frozenset(v113.CLAUSES)
SAME_EXCEPT = ("schema", "settled_under", "establishes", "does_not_establish")


def _signed_digest(ev):
    """sha256 of the bytes the record's signers signed (settle v1.2): the record without signatures and anchor. Two
    records with the same signed bytes are one act, however their unsigned parts differ."""
    try:
        return hashlib.sha256(v12.record_signing_bytes(ev)).hexdigest()
    except (KeyError, TypeError):
        return None


def walked_events(contract, events, view, settlement):
    """The execution records the admission, limit and amount rules read, with every other record kept as given:

      - the records in settlement["authoritative_event_set"], the ones the walk accepted, each the copy whose anchor it
        verified;
      - a record the walk set aside as an inconsistent binding (it names these terms by contract_sha256 with another
        contract_id or payload_digest) when a party the schema allows signed it and its anchor verifies: contract_ref
        is inside the signed bytes, so only that party could have made it, and its acts are read as before;
      - of records with the same signed bytes, only the one at the lowest (height, record sha256). A copy whose
        unsigned signatures list was edited is not a second act."""
    keep = {x.get("sha256") for x in settlement.get("authoritative_event_set") or [] if isinstance(x, dict) and x.get("kind") == "execution"}
    odd = {x.get("sha256") for x in (settlement.get("binding") or {}).get("inconsistent") or [] if isinstance(x, dict)}
    cv, _ = v11.verify_view(view, contract) if odd else (None, None)
    chosen = {}
    for ev in events if isinstance(events, list) else []:
        if not (isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA):
            continue
        s = v1.rec_sha(ev)
        if s in keep:
            pass
        elif s in odd and cv is not None and not v12.authenticate(ev, contract) and v17.anchor_valid_v1_7(ev, cv):
            pass
        else:
            continue
        h, d = v1.height_of(ev), _signed_digest(ev)
        if not (isinstance(h, int) and not isinstance(h, bool)) or d is None:
            continue
        if d not in chosen or (h, s) < chosen[d][:2]:
            chosen[d] = (h, s, ev)
    picked = {id(t[2]) for t in chosen.values()}
    return [ev for ev in (events if isinstance(events, list) else [])
            if not (isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA) or id(ev) in picked]


def lowest_admission_copies(admissions):
    """One copy per admission (the same signed bytes), the one with the lowest stated anchor height; a copy with no
    integer height comes after any with one. v1.11 keeps whichever copy comes last in the list, so the order a caller
    happened to pass decided whether an execution was admitted in time."""
    best, order = {}, []
    for rec in admissions if isinstance(admissions, list) else []:
        if not (isinstance(rec, dict) and rec.get("schema") == A.SCHEMA):
            order.append(("other", rec)); continue
        try:
            k = A.admission_sha256({x: y for x, y in rec.items() if x != "anchor"})
        except (TypeError, ValueError):
            order.append(("other", rec)); continue
        a = rec.get("anchor") if isinstance(rec.get("anchor"), dict) else {}
        h = a.get("height")
        rank = (0, h) if isinstance(h, int) and not isinstance(h, bool) else (1, 0)
        if k not in best:
            order.append(("adm", k))
            best[k] = (rank, rec)
        elif rank < best[k][0]:
            best[k] = (rank, rec)
    return [best[x][1] if kind == "adm" else x for kind, x in order]


def _bad_admission_ref(ev):
    """An admission_ref whose admission_sha256 is neither a string nor absent. v1.11 compares it with sets of strings and
    raises on a list or an object, so one such record stopped every settlement of the contract."""
    refs = ev.get("admission_ref")
    return isinstance(refs, list) and any(isinstance(r, dict) and r.get("admission_sha256") is not None
                                          and not isinstance(r.get("admission_sha256"), str) for r in refs)


def settle_v1_14(contract, events, view, admissions=None, relying_keys=None, mode="strict", nenrin_records=None, spine=None,
                 pool=None, contract_anchor_height=None, history=None):
    if not v111.admission_required(contract):
        return v113.settle_v1_13(contract, events, view, admissions=admissions, relying_keys=relying_keys, mode=mode,
                                 nenrin_records=nenrin_records, spine=spine, pool=pool, contract_anchor_height=contract_anchor_height,
                                 history=history)
    events = list(events) if isinstance(events, list) else []
    admissions = lowest_admission_copies(admissions)
    csha = contract_sha256(contract)
    charged = [ev for ev in events if isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA and _bad_admission_ref(ev)
               and (ev.get("contract_ref") or {}).get("contract_sha256") == csha and not v12.authenticate(ev, contract)]
    events = [ev for ev in events if not any(ev is c for c in charged)]
    kw = dict(admissions=admissions, relying_keys=relying_keys, mode=mode, nenrin_records=nenrin_records, spine=spine, pool=pool,
              contract_anchor_height=contract_anchor_height, history=history)
    s = v113.settle_v1_13(contract, events, view, **kw)
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, s.get("schema")
    charges = [{"clause": "nonconforming_record", "record_sha256": v1.rec_sha(ev),
                "why": ["admission_ref names an admission_sha256 that is not a string"]} for ev in charged]
    if s.get("verdict") != "underspecified":
        walked = walked_events(contract, events, view, s)
        if v113.applies(contract):
            with v113._approver_rule():
                adm, adm_read = v111.admission_deviations(contract, walked, admissions, relying_keys)
        else:
            adm, adm_read = v111.admission_deviations(contract, walked, admissions, relying_keys)
        lim, lim_read = [], []
        if v112.has_limits(contract):
            already = {(d.get("record_sha256"), d.get("observed"), d.get("admission_sha256")) for d in adm if d.get("clause") == "admitted_out_of_grant"}
            lim, lim_read = v112.limit_deviations(contract, walked, admissions, relying_keys, already=already)
        amt = [d for d in s.get("deviations") or [] if isinstance(d, dict) and d.get("clause") in v113.CLAUSES]   # v1.13 already reads the walk's set
        base = [d for d in s.get("deviations") or [] if not (isinstance(d, dict) and d.get("clause") in LAYER_CLAUSES)]
        out["deviations"] = base + adm + lim + amt + charges
        out["verdict"] = "deviation" if out["deviations"] else "within_grant"
        out["bond_outcome"] = v15._bond_outcome(contract, out["verdict"], out.get("status"))
        if isinstance(s.get("admission_gate"), dict):
            out["admission_gate"] = dict(s["admission_gate"], admissions_read=sorted(adm_read, key=canonical),
                                         counts={c: sum(1 for d in adm if d["clause"] == c) for c in v111.CLAUSES})
        if isinstance(s.get("limit_gate"), dict):
            out["limit_gate"] = dict(s["limit_gate"], amounts_read=sorted(lim_read, key=canonical),
                                     counts={c: sum(1 for d in lim if d["clause"] == c) for c in v112.CLAUSES})
    elif charges:
        out["deviations"] = list(s.get("deviations") or []) + charges
    out["establishes"] = list(s.get("establishes") or []) + [
        "that the admission, limit and amount rules were read over the execution records the walk accepted, each the copy whose anchor "
        "it verified, plus party-signed records with an inconsistent binding whose anchor verifies, one per signed body, under the rule "
        "in a2a-settlement-v1.14"]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + [
        "that a settler older than v1.14 reads only the walk's records for the admission and limit rules; v1.11 and v1.12 read every signed copy",
        "that the walk itself (settle v1.7) treats two records with the same signed bytes and different signatures lists as one; "
        "its own clauses can still count such a copy twice"]
    return out


# --------------------------------------------------------------------------- self test
def _selftest():
    import base64, hashlib, subprocess
    import settle_v1_1 as v11
    import settle_v1_2 as v12
    import clause_eval_v0 as ce
    import contract_v0 as v0
    import admission_verify_v0 as A
    import approval_v3 as AV
    from contract_v0 import contract_sha256
    n = 0
    strip = lambda s: {k: v for k, v in s.items() if k not in SAME_EXCEPT}
    clauses = lambda s: sorted(d["clause"] for d in s["deviations"])

    # [1] no admission requirement: v1.13's bytes; the fixture scenarios and run0002
    fx = v111.load_fixture()
    contracts, cases, keys = fx
    same = renamed = 0
    for k, c in sorted(cases.items()):
        a = v111.settle_fixture_case(settle_v1_14, k, fx)
        b = v111.settle_fixture_case(v113.settle_v1_13, k, fx)
        if not v111.admission_required(contracts[c["contract"]]):
            assert canonical(a) == canonical(b), k
            same += 1
        else:
            assert a["schema"] == SETTLE_SCHEMA and a["settled_under"] == b["schema"] and canonical(strip(a)) == canonical(strip(b)), k
            renamed += 1
    rr = os.path.join(HERE, "run0002")
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    r2 = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    assert canonical(settle_v1_14(*r2, nenrin_records=nr)) == canonical(v113.settle_v1_13(*r2, nenrin_records=nr))
    n += 1; print("[1] no admission requirement: v1.13 byte for byte (%d fixture scenarios, run0002); with it and no extra copies: the same "
                  "settlement apart from schema, settled_under, establishes and does_not_establish (%d scenarios)" % (same, renamed))

    # a contract that requires admission, with keys from labels
    key = AV._key
    ka, pa = key("principal"); kb, pb = key("contractor"); _kw, pw = key("witness"); kz, pz = key("approver"); kr, pr = key("relying")
    RK = {"shop.example": pr}
    PDG = "a" * 64
    base = v11._Chain(60, "00" * 32, "v114")
    for _ in range(38):
        base.block()
    lb = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    DNE = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]

    def mk(limits, nonce):
        g = {"authorized_actions": ["read", "emit_witness", "pay"], "prohibited_actions": ["delete"],
             "conditional": [{"action": "emit_witness", "requires": "approver"}, {"action": "pay_large", "requires": "approver"}],
             "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"}, "finality": {"depth": 3, "max_target_bits": "207fffff"},
             "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}],
             "approval_policy": {"allow_unscoped": False, "approvers": [{"name": "approver.example", "public_key_ed25519_b64": pz,
                                                                          "actions": ["emit_witness", "pay_large"]}]}}
        if limits:
            g["limits"] = limits
        c = v0.build_contract(
            {"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
            {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
            {"purpose": "settle_v1_14_selftest", "payload_digest": PDG, "a2a_task_id": "t14"}, g,
            ["that both parties signed these grant bytes at the stated time"], DNE,
            requirements={"evidence": "nenrin_required", "recovery": "tsugi_required", "admission": "required_before_execution"},
            bond={"amount": 1000, "currency": "JPY"}, lower_bound=lb,
            contract_id="0123456789abcdef0123456789abc114", nonce=nonce, agreed_at="2026-10-10T00:00:00Z")
        v0.sign_contract(c, ka, pa, "a.example"); v0.sign_contract(c, kb, pb, "b.example")
        return c

    LIM = {"pay": {"max_amount": 100000, "unit": "JPY"}, "pay_large": {"max_amount": 1000000, "unit": "JPY"}}
    CP, CL = mk(None, "1" * 32), mk(LIM, "2" * 32)
    assert v0.verify_contract(CP)["verdict"] == "accepted" and v0.verify_contract(CL)["verdict"] == "accepted"
    seq = [0]

    def admit(c, action, amount, decision="admit", reasons=("within_grant",)):
        seq[0] += 1
        nonce = "%032x" % (0x7a00 + seq[0])
        csha = contract_sha256(c)
        req = {"action": {"action": action, "target": None, "amount": amount}, "nonce": nonce, "expiry_height": 500}
        rec = {"schema": A.SCHEMA, "admission_id": "adm-%d" % seq[0],
               "relying_party": {"domain": "shop.example", "key_url": "https://shop.example/keys/agreement.json"},
               "contract_ref": {"contract_id": c["contract_id"], "contract_sha256": csha},
               "action_ref": {"action_binding_digest": A.action_digest(csha, req), "nonce": nonce},
               "presentation_ref": [{"adapter": "musubi-native", "sha256": "0" * 64, "verified": True}],
               "chain_view": {"height": 97, "header_sha256": "ab" * 32}, "revocations_seen": [],
               "decision": decision, "reasons": list(reasons), "clause": ce.clause_path(c, action),
               "rules": {"admit": A.SCHEMA, "version": A.VERSION, "evaluator_sha256": ce.evaluator_sha256()},
               "establishes": ["that the relying party named here ran admit() over this contract, this action digest and this chain view, and signed the result",
                               "that the decision and reasons are what the shared clause evaluator (rules.evaluator_sha256) returns for those inputs; anyone holding them can recompute it"],
               "does_not_establish": list(A.DOES_NOT_ESTABLISH)}
        rec["signatures"] = [{"domain": "shop.example", "alg": "ed25519", "sig": base64.b64encode(kr.sign(A.admission_signing_bytes(rec))).decode("ascii")}]
        ref = {"action": action, "admission_sha256": A.admission_sha256(rec),
               "executed": {"action": action, "target": None, "amount": amount, "nonce": nonce, "expiry_height": 500}}
        return dict(rec, anchor={"height": 97}), ref

    def ex(c, actions, approvals, refs, tag, pdg=PDG):
        r = {"schema": EXEC_SCHEMA, "contract_ref": {"contract_id": c["contract_id"], "payload_digest": pdg, "contract_sha256": contract_sha256(c)},
             "performed_actions": list(actions), "approvals": list(approvals), "delegated_to": [], "nenrin_ref": (tag * 64)[:64],
             "admission_ref": list(refs)}
        return v12.sign_record(r, kb, "contractor")

    def forged_copy(rec, height):
        r = json.loads(json.dumps(rec))
        r["anchor"] = dict(rec["anchor"], height=height, block_hash="11" * 32)
        return r

    def finish(ch):
        for _ in range(5):
            ch.block()
        return ch.view()

    def both(c, recs, view, adms):
        return (v113.settle_v1_13(c, recs, view, admissions=adms, relying_keys=RK),
                settle_v1_14(c, recs, view, admissions=adms, relying_keys=RK))

    # [2] a copy with a forged earlier anchor
    ch = base.fork(98, "a1")
    adm, ref = admit(CP, "read", None)
    R = ch.block([ex(CP, ["read"], [], [ref], "3")])
    view = finish(ch)
    s13, s14 = both(CP, R + [forged_copy(R[0], 97)], view, [adm])
    assert clauses(s13) == ["unadmitted_execution"] and s13["deviations"][0]["record_sha256"] == v1.rec_sha(R[0]), s13["deviations"]
    assert s14["verdict"] == "within_grant" and s14["status"] == "final" and s14["admission_gate"]["counts"]["unadmitted_execution"] == 0, s14["deviations"]
    assert s14["admission_gate"]["admissions_read"][0]["record_sha256"] == v1.rec_sha(R[0])
    assert s14["duplicate_anchorings"] == s13["duplicate_anchorings"] and s14["authoritative_event_set"] == s13["authoritative_event_set"]
    clean13, clean14 = both(CP, R, view, [adm])
    assert s14["deviations"] == clean14["deviations"] == [] and s14["admission_gate"] == clean14["admission_gate"] and clean13["verdict"] == "within_grant"
    n += 1; print("[2] a copy of the record with a forged earlier anchor: v1.13 (via v1.11) reports the genuine record as unadmitted_execution; "
                  "v1.14: within_grant, final, the admission read against the genuine record")

    # [3] a record anchored twice, both validly
    ch = base.fork(98, "a2")
    adm, ref = admit(CP, "read", None)
    rec = ex(CP, ["read"], [], [ref], "4")
    first = ch.block([rec])
    second = ch.block([rec])
    view = finish(ch)
    s13, s14 = both(CP, first + second, view, [adm])
    assert "unadmitted_execution" in clauses(s13) and s14["verdict"] == "within_grant", (clauses(s13), s14["deviations"])
    assert [x["height"] for x in s14["authoritative_event_set"]] == [98]
    n += 1; print("[3] a record anchored at 98 and again at 99: v1.13 reads both and reports the second as unadmitted_execution; v1.14 reads the copy the walk kept")

    # [4] a record with an inconsistent binding the contractor signed is still read (only it could have made it); a forged copy of it is not
    ch = base.fork(98, "a3")
    odd = ch.block([ex(CL, ["pay"], [], [], "5", pdg="b" * 64)])
    ch.block()
    view = finish(ch)
    s13, s14 = both(CL, odd + [forged_copy(odd[0], 97)], view, [])
    assert v1.rec_sha(odd[0]) in [x["sha256"] for x in s14["binding"]["inconsistent"]] and not s14["authoritative_event_set"]
    assert clauses(s14) == ["amount_over_limit", "unadmitted_execution"] and all(d["record_sha256"] == v1.rec_sha(odd[0]) for d in s14["deviations"]), s14["deviations"]
    assert len(clauses(s13)) > len(clauses(s14))
    n += 1; print("[4] a contractor-signed record with another payload digest (an inconsistent binding) paying 5,000,000 with no admission: "
                  "read, amount_over_limit and unadmitted_execution once; its copy with a forged anchor is not read a second time")

    # [4b] a copy whose unsigned signatures list was edited, anchored validly later
    ch = base.fork(98, "a6")
    adm, ref = admit(CP, "read", None)
    R = ch.block([ex(CP, ["read"], [], [ref], "a")])
    ch.block()
    mal = json.loads(json.dumps(R[0])); del mal["anchor"]
    mal["signatures"] = mal["signatures"] + [{"role": "contractor", "sig_b64": "AAAA"}]
    M = ch.block([mal])
    view = finish(ch)
    s13, s14 = both(CP, R + M, view, [adm])
    assert len(s14["authoritative_event_set"]) == 2 and "unadmitted_execution" in clauses(s13), clauses(s13)
    assert s14["verdict"] == "within_grant" and s14["admission_gate"]["admissions_read"][0]["record_sha256"] == v1.rec_sha(R[0]), s14["deviations"]
    n += 1; print("[4b] a copy with a junk entry appended to its signatures list, anchored validly at 100: the walk accepts both bodies; v1.13 "
                  "reports the copy as unadmitted_execution; v1.14 reads one act per signed body, the one at 98")

    # [4c] copies of one admission: the lowest stated height, whatever the order
    ch = base.fork(98, "a7")
    adm, ref = admit(CP, "read", None)
    R = ch.block([ex(CP, ["read"], [], [ref], "b")])
    view = finish(ch)
    late = dict(adm, anchor={"height": 120})
    for order in ([adm, late], [late, adm]):
        s14 = settle_v1_14(CP, R, view, admissions=order, relying_keys=RK)
        assert s14["verdict"] == "within_grant", (order[0]["anchor"], s14["deviations"])
    assert "admission_after_execution" in clauses(v113.settle_v1_13(CP, R, view, admissions=[adm, late], relying_keys=RK))
    n += 1; print("[4c] the same admission given at 97 and at 120: v1.13 reads the last one in the list (admission_after_execution); v1.14 "
                  "reads 97 in either order")

    # [4d] an admission_sha256 that is not a string: charged to the record, no crash
    ch = base.fork(98, "a8")
    adm, ref = admit(CP, "read", None)
    good = ch.block([ex(CP, ["read"], [], [ref], "c")])
    bad = ch.block([ex(CP, ["read"], [], [{"action": "read", "admission_sha256": ["x"], "executed": {}}], "d")])
    view = finish(ch)
    try:
        v113.settle_v1_13(CP, good + bad, view, admissions=[adm], relying_keys=RK)
        raised = False
    except TypeError:
        raised = True
    s14 = settle_v1_14(CP, good + bad, view, admissions=[adm], relying_keys=RK)
    assert raised and clauses(s14) == ["nonconforming_record"] and s14["deviations"][0]["record_sha256"] == v1.rec_sha(bad[0]), s14["deviations"]
    n += 1; print("[4d] an execution whose admission_sha256 is a list: v1.13 raises (TypeError in v1.11); v1.14 charges nonconforming_record to "
                  "that record and settles the rest")

    # [5] the limit and amount rules: a forged copy does not move an amount reading
    ch = base.fork(98, "a4")
    adm, ref = admit(CL, "pay", 80000)
    adm2, ref2 = admit(CL, "pay_large", 150000)
    ap = AV.sign_approval_v3(kz, CL, "pay_large", "150000", "JPY", 500, "51" * 16, "approver.example", pz)
    R = ch.block([ex(CL, ["pay", "pay_large"], [ap], [ref, ref2], "7")])
    view = finish(ch)
    s13, s14 = both(CL, R + [forged_copy(R[0], 97)], view, [adm, adm2])
    assert "unadmitted_execution" in clauses(s13) and s14["verdict"] == "within_grant", (clauses(s13), s14["deviations"])
    assert len(s14["limit_gate"]["amounts_read"]) == 2 and all(r["record_sha256"] == v1.rec_sha(R[0]) for r in s14["limit_gate"]["amounts_read"])
    assert s14["amount_approval_gate"]["approvals_read"][0]["covered"] is True
    s13c, s14c = both(CL, R, view, [adm, adm2])
    assert s14c["verdict"] == s13c["verdict"] == "within_grant" and canonical(strip(s14c)) == canonical(strip(s13c))
    n += 1; print("[5] under grant.limits with a v3 approval: the forged copy makes v1.13 report unadmitted_execution; v1.14 reads pay 80,000 and "
                  "pay_large 150,000 from the genuine record and settles within_grant; without the copy v1.13 and v1.14 agree")

    # [6] genuine deviations stay: refused and executed, over the limit
    ch = base.fork(98, "a5")
    adm, ref = admit(CL, "pay", 150000, "refuse", ("amount_over_limit",))
    R = ch.block([ex(CL, ["pay"], [], [ref], "8")])
    view = finish(ch)
    s13, s14 = both(CL, R + [forged_copy(R[0], 97)], view, [adm])
    assert clauses(s14) == ["amount_over_limit", "executed_after_refusal"], clauses(s14)
    s13c, s14c = both(CL, R, view, [adm])
    assert clauses(s13c) == clauses(s14c) == clauses(s14)
    n += 1; print("[6] a real deviation (refused at 150,000 and executed) is reported the same with and without the forged copy")

    # [7] determinism, and a mutant that reads every copy again
    a = settle_v1_14(CL, R + [forged_copy(R[0], 97)], view, admissions=[adm], relying_keys=RK)
    assert canonical(a) == canonical(s14)
    g = globals()
    saved = g["walked_events"]
    try:
        g["walked_events"] = lambda contract, events, view, settlement: list(events)                         # M1: every signed copy is read
        ch = base.fork(98, "m1")
        madm, mref = admit(CP, "read", None)
        MR = ch.block([ex(CP, ["read"], [], [mref], "9")])
        mview = finish(ch)
        killed = settle_v1_14(CP, MR + [forged_copy(MR[0], 97)], mview, admissions=[madm], relying_keys=RK)["verdict"] != "within_grant"
    finally:
        g["walked_events"] = saved
    assert killed
    n += 1; print("[7] the same inputs give the same bytes; a mutant that reads every signed copy again brings the false unadmitted_execution back")

    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_13.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[8] settle_v1_13 self test (and every layer it runs) still passes")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.14, %d checks (no admission requirement: v1.13 byte for byte; forged earlier anchor, double "
          "anchoring, edited signatures list and forged copies of an inconsistent binding no longer read; repeated admissions and a malformed admission_ref; limits and v3 amounts read from the genuine record; real deviations kept; "
          "determinism and a mutant; lower layers unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.14 (admission and limit rules read over the walk's records)")
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
    s = settle_v1_14(contract, [rd(p) for p in a.event], views[cmp["chosen"]], admissions=[rd(p) for p in a.admission], relying_keys=keys,
                     nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
