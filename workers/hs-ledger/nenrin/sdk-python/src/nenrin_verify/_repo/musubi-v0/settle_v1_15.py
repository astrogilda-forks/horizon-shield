#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.15: records with the same signed bytes are one record (a2a-settlement-v1.15). One rule, and nothing
else.

Why this file exists. The walk (settle v1.7) tells records apart by commitment_digest, which covers the record's
signatures list. The signers sign the record without signatures and anchor (settle v1.2). So anyone holding a record
can add a copy with a junk entry in its signatures list, or an extra key inside an entry, and the walk sees a second
body:

  - anchored in a later block, the copy is read as a second act: a single use approval it carries is "reused", an
    admission it names is "already used";
  - carrying the genuine record's own anchor, the copy's proof fails and the whole settlement becomes underspecified
    (anchor_proof_invalid): a verdict anyone holding one record can block.

Found on 2026-10-10 by an independent adversarial review of settle v1.14, which closed the same kind of copy for the
admission and limit rules but left the walk as published. v1.7 to v1.14 are not edited.

When the rule applies. To every contract, and only when the input carries two or more records (executions,
revocations, acknowledgements) with the same signed bytes. Any other input settles to v1.14's bytes.

The rule. Before anything else reads the input, the copies of one signed body are reduced to one: of the copies whose
anchor verifies against the view (settle v1.7's anchor validity), the one at the lowest (height, record sha256) is
kept, and every other copy is dropped and listed in signed_body_collapse as {signed_sha256, kept, height, dropped}.
When no copy's anchor verifies, all are left as they are, and the walk reports them as before. Then settle v1.14 runs on
the reduced input.

Stated limits: as v1.14. The kept copy's anchor is evidence that those signed bytes existed by then, whoever submitted
that copy; which copy a submitter sent first is not something the records show.
"""
import argparse, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_1 as v11
import settle_v1_2 as v12
import settle_v1_7 as v17
import settle_v1_10 as v110
import settle_v1_14 as v114
from contract_v0 import canonical, parse_strict, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.15"
KINDS = (EXEC_SCHEMA, v1.REVOKE_SCHEMA, v1.ACK_SCHEMA)


def signed_digest(ev):
    """sha256 of the bytes the record's signers signed: the record without signatures and anchor (settle v1.2)."""
    try:
        return hashlib.sha256(v12.record_signing_bytes(ev)).hexdigest()
    except (KeyError, TypeError, ValueError):
        return None


def collapse_signed_bodies(contract, events, view):
    """(events with one copy per signed body, report). See the module docstring."""
    evs = list(events) if isinstance(events, list) else []
    cv, _ = v11.verify_view(view, contract)
    groups = {}
    for ev in evs:
        if isinstance(ev, dict) and ev.get("schema") in KINDS:
            d = signed_digest(ev)
            if d is not None:
                groups.setdefault(d, {}).setdefault(v1.rec_sha(ev), ev)
    drop, report = set(), []
    for d, copies in sorted(groups.items()):
        if len(copies) < 2 or cv is None:
            continue
        valid = []
        for s, ev in copies.items():
            h = v1.height_of(ev)
            try:
                ok = isinstance(h, int) and not isinstance(h, bool) and v17.anchor_valid_v1_7(ev, cv)
            except Exception:
                ok = False
            if ok:
                valid.append((h, s))
        if not valid:
            continue
        h, keep = min(valid)
        gone = sorted(x for x in copies if x != keep)
        drop.update(gone)
        report.append({"signed_sha256": d, "kept": keep, "height": h, "dropped": gone})
    out = [ev for ev in evs if not (isinstance(ev, dict) and ev.get("schema") in KINDS and v1.rec_sha(ev) in drop)]
    return out, report


def settle_v1_15(contract, events, view, admissions=None, relying_keys=None, mode="strict", nenrin_records=None, spine=None,
                 pool=None, contract_anchor_height=None, history=None):
    kw = dict(admissions=admissions, relying_keys=relying_keys, mode=mode, nenrin_records=nenrin_records, spine=spine, pool=pool,
              contract_anchor_height=contract_anchor_height, history=history)
    reduced, collapse = collapse_signed_bodies(contract, events, view)
    if not collapse:
        return v114.settle_v1_14(contract, events, view, **kw)
    s = v114.settle_v1_14(contract, reduced, view, **kw)
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, s.get("schema")
    out["signed_body_collapse"] = collapse
    out["establishes"] = list(s.get("establishes") or []) + [
        "that records with the same signed bytes were read as one record, the copy at the lowest verified anchor (signed_body_collapse), "
        "under the rule in a2a-settlement-v1.15"]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + [
        "that a settler older than v1.15 reads two copies of one signed body as one; v1.7 to v1.14 treat a copy with another signatures "
        "list as another record"]
    return out


# --------------------------------------------------------------------------- self test
def _selftest():
    import base64, subprocess
    import settle_v1_11 as v111
    import settle_v1_13 as v113
    import clause_eval_v0 as ce
    import contract_v0 as v0
    import admission_verify_v0 as A
    import approval_v3 as AV
    from contract_v0 import contract_sha256
    n = 0
    clauses = lambda s: sorted(d["clause"] for d in s["deviations"])
    NAMED = ("schema", "settled_under", "establishes", "does_not_establish", "signed_body_collapse")
    strip = lambda s: {k: v for k, v in s.items() if k not in NAMED}

    # [1] no copies of one signed body: v1.14's bytes (fixture scenarios, run0002)
    fx = v111.load_fixture()
    contracts, cases, keys = fx
    for k in sorted(cases):
        assert canonical(v111.settle_fixture_case(settle_v1_15, k, fx)) == canonical(v111.settle_fixture_case(v114.settle_v1_14, k, fx)), k
    rr = os.path.join(HERE, "run0002")
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    r2 = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    assert canonical(settle_v1_15(*r2, nenrin_records=nr)) == canonical(v114.settle_v1_14(*r2, nenrin_records=nr))
    n += 1; print("[1] no copies of one signed body: v1.14 byte for byte (%d fixture scenarios and run0002)" % len(cases))

    key = AV._key
    ka, pa = key("principal"); kb, pb = key("contractor"); _kw, pw = key("witness"); kz, pz = key("approver"); kr, pr = key("relying")
    RK = {"shop.example": pr}
    PDG = "a" * 64
    base = v11._Chain(60, "00" * 32, "v115")
    for _ in range(38):
        base.block()
    lb = {"kind": "bitcoin_block", "height": 97, "hash": base.hashes[97]}
    DNE = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]

    def mk(limits, nonce, admission):
        g = {"authorized_actions": ["read", "emit_witness", "pay"], "prohibited_actions": ["delete"],
             "conditional": [{"action": "emit_witness", "requires": "approver"}, {"action": "pay_large", "requires": "approver"}],
             "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"}, "finality": {"depth": 3, "max_target_bits": "207fffff"},
             "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}],
             "approval_policy": {"allow_unscoped": False, "approvers": [{"name": "approver.example", "public_key_ed25519_b64": pz,
                                                                          "actions": ["emit_witness", "pay_large"]}]}}
        if limits:
            g["limits"] = limits
        req = {"evidence": "nenrin_required", "recovery": "tsugi_required"}
        if admission:
            req["admission"] = "required_before_execution"
        c = v0.build_contract(
            {"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
            {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
            {"purpose": "settle_v1_15_selftest", "payload_digest": PDG, "a2a_task_id": "t15"}, g,
            ["that both parties signed these grant bytes at the stated time"], DNE, requirements=req,
            bond={"amount": 1000, "currency": "JPY"}, lower_bound=lb,
            contract_id="0123456789abcdef0123456789abc115", nonce=nonce, agreed_at="2026-10-10T00:00:00Z")
        v0.sign_contract(c, ka, pa, "a.example"); v0.sign_contract(c, kb, pb, "b.example")
        return c

    CN = mk(None, "1" * 32, False)
    CP = mk(None, "2" * 32, True)
    CL = mk({"pay": {"max_amount": 100000, "unit": "JPY"}, "pay_large": {"max_amount": 1000000, "unit": "JPY"}}, "3" * 32, True)
    assert all(v0.verify_contract(c)["verdict"] == "accepted" for c in (CN, CP, CL))
    seq = [0]

    def admit(c, action, amount):
        seq[0] += 1
        nonce = "%032x" % (0x9a00 + seq[0])
        csha = contract_sha256(c)
        req = {"action": {"action": action, "target": None, "amount": amount}, "nonce": nonce, "expiry_height": 500}
        rec = {"schema": A.SCHEMA, "admission_id": "adm-%d" % seq[0],
               "relying_party": {"domain": "shop.example", "key_url": "https://shop.example/keys/agreement.json"},
               "contract_ref": {"contract_id": c["contract_id"], "contract_sha256": csha},
               "action_ref": {"action_binding_digest": A.action_digest(csha, req), "nonce": nonce},
               "presentation_ref": [{"adapter": "musubi-native", "sha256": "0" * 64, "verified": True}],
               "chain_view": {"height": 97, "header_sha256": "ab" * 32}, "revocations_seen": [],
               "decision": "admit", "reasons": ["within_grant"], "clause": ce.clause_path(c, action),
               "rules": {"admit": A.SCHEMA, "version": A.VERSION, "evaluator_sha256": ce.evaluator_sha256()},
               "establishes": ["that the relying party named here ran admit() over this contract, this action digest and this chain view, and signed the result",
                               "that the decision and reasons are what the shared clause evaluator (rules.evaluator_sha256) returns for those inputs; anyone holding them can recompute it"],
               "does_not_establish": list(A.DOES_NOT_ESTABLISH)}
        rec["signatures"] = [{"domain": "shop.example", "alg": "ed25519", "sig": base64.b64encode(kr.sign(A.admission_signing_bytes(rec))).decode("ascii")}]
        ref = {"action": action, "admission_sha256": A.admission_sha256(rec),
               "executed": {"action": action, "target": None, "amount": amount, "nonce": nonce, "expiry_height": 500}}
        return dict(rec, anchor={"height": 97}), ref

    def ex(c, actions, approvals, refs, tag):
        r = {"schema": EXEC_SCHEMA, "contract_ref": {"contract_id": c["contract_id"], "payload_digest": PDG, "contract_sha256": contract_sha256(c)},
             "performed_actions": list(actions), "approvals": list(approvals), "delegated_to": [], "nenrin_ref": (tag * 64)[:64]}
        if refs is not None:
            r["admission_ref"] = list(refs)
        return v12.sign_record(r, kb, "contractor")

    def finish(ch):
        for _ in range(5):
            ch.block()
        return ch.view()

    junk = lambda rec: dict(json.loads(json.dumps(rec)), signatures=rec["signatures"] + [{"role": "contractor", "sig_b64": "AAAA"}])

    # [2] a copy with a junk signatures entry carrying the genuine anchor: no longer blocks a verdict
    ch = base.fork(98, "b1")
    R = ch.block([ex(CN, ["read"], [], None, "1")])
    view = finish(ch)
    s14, s15 = v114.settle_v1_14(CN, R + [junk(R[0])], view), settle_v1_15(CN, R + [junk(R[0])], view)
    assert s14["verdict"] == "underspecified" and any(u["reason"] == "anchor_proof_invalid" for u in s14["underspecified"])
    assert s15["verdict"] == "within_grant" and s15["status"] == "final" and s15["schema"] == SETTLE_SCHEMA
    assert s15["signed_body_collapse"] == [{"signed_sha256": signed_digest(R[0]), "kept": v1.rec_sha(R[0]), "height": 98, "dropped": [v1.rec_sha(junk(R[0]))]}]
    assert canonical(strip(s15)) == canonical(strip(v114.settle_v1_14(CN, R, view)))
    ch = base.fork(98, "b2")
    adm, ref = admit(CP, "read", None)
    R = ch.block([ex(CP, ["read"], [], [ref], "2")])
    view = finish(ch)
    assert v114.settle_v1_14(CP, R + [junk(R[0])], view, admissions=[adm], relying_keys=RK)["verdict"] == "underspecified"
    assert settle_v1_15(CP, R + [junk(R[0])], view, admissions=[adm], relying_keys=RK)["verdict"] == "within_grant"
    n += 1; print("[2] a copy with a junk signatures entry and the genuine anchor: v1.14 underspecified (anchor_proof_invalid, anyone could "
                  "block a verdict); v1.15 within_grant, final, the copy listed in signed_body_collapse; the same with and without admission")

    # [3] the same copy anchored later: not a second act
    ch = base.fork(98, "b3")
    adm, ref = admit(CL, "pay_large", 150000)
    ap = AV.sign_approval_v3(kz, CL, "pay_large", "150000", "JPY", 500, "61" * 16, "approver.example", pz)
    R = ch.block([ex(CL, ["pay_large"], [ap], [ref], "3")])
    ch.block()
    mal = json.loads(json.dumps(R[0])); del mal["anchor"]; mal["signatures"][0] = dict(mal["signatures"][0], x=1)
    M = ch.block([mal])
    view = finish(ch)
    s14 = v114.settle_v1_14(CL, R + M, view, admissions=[adm], relying_keys=RK)
    s15 = settle_v1_15(CL, R + M, view, admissions=[adm], relying_keys=RK)
    assert s14["verdict"] == "deviation" and "conditional" in clauses(s14), clauses(s14)
    assert s15["verdict"] == "within_grant" and s15["signed_body_collapse"][0]["dropped"] == [v1.rec_sha(M[0])], clauses(s15)
    n += 1; print("[3] a copy with an extra key in its signature entry, anchored validly at 100, carrying a single use v3 approval: v1.14's "
                  "walk reads it as a second act (conditional, approval reused); v1.15 keeps the record at 98 and settles within_grant")

    # [4] copies whose anchors do not verify are left for the walk; a different record is not collapsed
    ch = base.fork(98, "b4")
    R = ch.block([ex(CN, ["read"], [], None, "4")])
    view = finish(ch)
    fake = json.loads(json.dumps(R[0])); fake["anchor"] = dict(R[0]["anchor"], height=97, block_hash="11" * 32)
    only_bad = json.loads(json.dumps(fake)); only_bad["signatures"] = only_bad["signatures"] + [{"role": "contractor", "sig_b64": "AAAA"}]
    assert collapse_signed_bodies(CN, [fake, only_bad], view)[1] == []
    other = ex(CN, ["read"], [], None, "5")
    assert collapse_signed_bodies(CN, R + [other], view)[1] == []
    n += 1; print("[4] when no copy's anchor verifies, nothing is collapsed and the walk reports them as before; two records with different "
                  "signed bytes are never collapsed")

    # [5] determinism and a mutant
    a = settle_v1_15(CN, R + [junk(R[0])], view)
    assert canonical(a) == canonical(settle_v1_15(CN, R + [junk(R[0])], view))
    g = globals()
    saved = g["collapse_signed_bodies"]
    try:
        g["collapse_signed_bodies"] = lambda contract, events, view: (list(events), [])          # M1: copies of one signed body kept
        killed = settle_v1_15(CN, R + [junk(R[0])], view)["verdict"] == "underspecified"
    finally:
        g["collapse_signed_bodies"] = saved
    assert killed
    n += 1; print("[5] the same inputs give the same bytes; a mutant that keeps every copy brings the blocked verdict back")

    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_14.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[6] settle_v1_14 self test (and every layer it runs) still passes")

    print("\nSELF-TEST PASSED: MUSUBI settle v1.15, %d checks (no copies: v1.14 byte for byte; a junk signatures entry no longer blocks a "
          "verdict or makes a second act; unverifiable copies left to the walk; determinism and a mutant; lower layers unchanged)" % n)


def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.15 (records with the same signed bytes are one record)")
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
    s = settle_v1_15(contract, [rd(p) for p in a.event], views[cmp["chosen"]], admissions=[rd(p) for p in a.admission], relying_keys=keys,
                     nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
