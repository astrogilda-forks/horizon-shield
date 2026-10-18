#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate vectors/vectors_pilot_v0.json: the pilot on ourselves, with a delegated budget and paid calls.

Same keys and credentials as gen_vectors.py; the spaced test chain of gen_vectors_v0_1.py. Agent B (the leaf of
the chain root -> A -> B) pays responder X per call of the service "estimate-audit"; A, who issued B's credential,
sets the budget.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import gen_vectors as G                # noqa: E402
import gen_vectors_v0_1 as GV          # noqa: E402  (spaced blocks, witnesses, Sc)
import companion_v0 as C               # noqa: E402
import companion_v0_1 as C1            # noqa: E402
import pilot_v0 as P                   # noqa: E402

from ca2a_runtime.delegation.revocation import credential_digest   # noqa: E402

SERVICE = "estimate-audit"
UNIT = "JPY"


def task(amount, n, service=SERVICE, unit=UNIT):
    return {"type": P.T_TASK, "service": service, "amount": amount, "unit": unit, "nonce": C.sha256_hex(("n%d" % n).encode())}


def request(occ, t, responder=G.X_PUB, caller=G.B_PUB, chain=G.CHAIN):
    return {"type": C.T_REQUEST, "caller": caller, "responder": responder, "lineage": G.lin(chain),
            "capability": "pay", "occurrence_id": occ, "task_sha256": P.task_sha256(t)}


def budget(max_total, issuer_k=G.A, issuer=G.A_PUB, target=G.C1, unit=UNIT):
    return C.sign({"type": P.T_BUDGET, "credential_digest": credential_digest(target), "issuer": issuer,
                   "max_total": max_total, "unit": unit}, issuer_k)


def payment(req_sha, amount, seen, payer_k=G.B, payer=G.B_PUB, payee=G.X_PUB, chain=G.CHAIN, unit=UNIT, rail="x402",
            rail_sha=None):
    return C.sign({"type": P.T_PAYMENT, "payer": payer, "payee": payee, "lineage": G.lin(chain), "request_sha256": req_sha,
                   "amount": amount, "unit": unit, "seen_block": seen,
                   "rail": {"kind": rail, "receipt_sha256": rail_sha or C.sha256_hex(("x402:" + req_sha).encode())}},
                  payer_k)


VECTORS = []


def vec(vid, desc, b):
    b = json.loads(json.dumps(b))
    b["profile"] = P.PROFILE
    VECTORS.append({"id": vid, "description": desc, "bundle": b, "expected": json.loads(C.jcs(P.settle(b)))})


def scene(s, n_calls, price, budget_total, seen=None):
    """n paid calls at one price under one budget: tasks, requests, uses, payments, receipts, in log order."""
    seen = seen or s.tip()
    tasks, reqs, items = [], [], [budget(budget_total)]
    for i in range(n_calls):
        t = task(price, i)
        r = request("occ-%d" % i, t)
        rs = C.request_sha256(r)
        tasks.append(t)
        reqs.append(r)
        items += [G.use(rs), payment(rs, price, seen), G.receipt(rs, seen=seen)]
    return items, tasks, reqs


def main():
    # PL01: the scene, within budget
    s = GV.Sc(); s.mine()
    items, tasks, reqs = scene(s, 3, 7000, 30000)
    b = s.finish(items)
    b.update(tasks=tasks, requests=reqs)
    vec("PL01_three_paid_calls_within_budget",
        "B pays X 7,000 per call three times under A's budget of 30,000: every payment counted, every execution paid",
        b)

    # PL02: the fourth call takes the total over the budget
    s = GV.Sc(); s.mine()
    items, tasks, reqs = scene(s, 5, 7000, 30000)
    b = s.finish(items); b.update(tasks=tasks, requests=reqs)
    vec("PL02_budget_exceeded_on_the_fifth_call",
        "five calls at 7,000 under 30,000: the fifth payment (35,000) is budget_exceeded; per-call caps and use counts "
        "would both have passed it",
        b)

    # PL03: the payment does not match the task's price
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 5000, s.tip()), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL03_payment_not_for_task", "the task commits to 7,000, the payment says 5,000", b)

    # PL04: executed without a payment
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL04_executed_without_payment", "a result receipt for a priced request with no payment logged before it", b)

    # PL05: paid, never executed
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL05_paid_not_executed", "a counted payment with no result receipt by the checkpoint: unexecuted", b)

    # PL06: the same payment logged twice counts once
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    p = payment(rs, 7000, s.tip())
    b = s.finish([budget(10000), G.use(rs), p, p, G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL06_duplicate_payment_counts_once", "a retry of the same payment is duplicate_payment, the total is 7,000", b)

    # PL07: the budget delegated onward does not reset
    s = GV.Sc(); s.mine()
    c2 = G.cred("cred-2", G.B, G.B_PUB, G.B2_PUB, {"pay"}, 2, "cred-1")
    ch2 = [G.C0, G.C1, c2]
    t0 = task(7000, 0); r0 = request("occ-0", t0); rs0 = C.request_sha256(r0)
    t1 = task(7000, 1); r1 = request("occ-1", t1, caller=G.B2_PUB, chain=ch2); rs1 = C.request_sha256(r1)
    b = s.finish([budget(10000), G.use(rs0), payment(rs0, 7000, s.tip()), G.receipt(rs0, seen=s.tip()),
                  G.use(rs1, chain=ch2, holder_k=G.B2, holder=G.B2_PUB),
                  payment(rs1, 7000, s.tip(), payer_k=G.B2, payer=G.B2_PUB, chain=ch2),
                  G.receipt(rs1, chain=ch2, caller=G.B2_PUB, seen=s.tip())])
    b.update(tasks=[t0, t1], requests=[r0, r1])
    vec("PL07_delegated_budget_does_not_reset",
        "B delegates to B2; B2's payment under the longer chain counts against A's budget on hop 1: 14,000 over 10,000",
        b)

    # PL08: a budget signed by the wrong key limits nothing
    s = GV.Sc(); s.mine()
    items, tasks, reqs = scene(s, 2, 7000, 30000)
    items[0] = budget(5000, G.B, G.B_PUB)
    b = s.finish(items); b.update(tasks=tasks, requests=reqs)
    vec("PL08_budget_by_non_issuer", "a budget of 5,000 signed by the leaf's own subject is not a limit", b)

    # PL09: the operator refuses the budget; the witnesses carry it
    s = GV.Sc()
    w = s.witness(budget(10000), GV.TWO)                        # witnessed at 96
    s.mine()
    seen = s.tip()                                               # 97
    items, tasks, reqs = scene(s, 2, 7000, 30000, seen=seen)
    items = items[1:]                                            # no budget in the log at all
    b = s.finish(items, [w]); b.update(tasks=tasks, requests=reqs)
    vec("PL09_refused_budget_still_applies",
        "the operator never logs A's budget of 10,000; two witnesses did before the payments' seen block, so the second "
        "payment is budget_exceeded",
        b)

    # PL10: the witnessed budget's order against the payment cannot be fixed
    s = GV.Sc()
    w = s.witness(budget(10000), GV.TWO, seen=G.SEEN)
    s.mine()
    items, tasks, reqs = scene(s, 2, 7000, 30000, seen=G.SEEN)
    items = items[1:]
    b = s.finish(items, [w]); b.update(tasks=tasks, requests=reqs)
    vec("PL10_witnessed_budget_order_unresolved",
        "the payments name block 95, older than the witnessing: budget_order_unresolved, not exceeded and not clean",
        b)

    # PL11: the tightest budget wins, and a budget logged after a payment does not judge it
    s = GV.Sc(); s.mine()
    items, tasks, reqs = scene(s, 2, 7000, 30000)
    items.insert(4, budget(10000))                               # after the first payment, before the second
    b = s.finish(items); b.update(tasks=tasks, requests=reqs)
    vec("PL11_tightest_budget_from_its_logging",
        "30,000 then 10,000 logged between the calls: the second payment runs at 14,000 against 10,000",
        b)

    # PL12: a denial after a payment still counts
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, s.tip()), G.receipt(rs, kind="denial", stage="pre", seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL12_denial_after_payment_still_counts", "the responder denies; the payment stays counted and unexecuted", b)

    # PL13: a payment whose seen block is not in the view
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, {"height": 96, "hash": "33" * 32}), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL13_payment_seen_block_not_in_view", "the payment names a block the view does not hold", b)

    # PL14: the request names another payee than the one paid
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, s.tip(), payee=G.Y_PUB), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL14_paid_the_wrong_responder",
        "the payment goes to Y while the request and the execution name X: the payment does not match, and X executed unpaid",
        b)

    # PL15: no task supplied: the payment is counted on its own word, the execution is priced by the budget alone
    s = GV.Sc(); s.mine()
    items, tasks, reqs = scene(s, 1, 7000, 30000)
    b = s.finish(items); b.update(requests=reqs)
    vec("PL15_no_task_supplied", "without the task the price is the payer's word; the budget still counts it", b)

    # PL16: a budget in another unit does not apply
    s = GV.Sc(); s.mine()
    items, tasks, reqs = scene(s, 2, 7000, 30000)
    items[0] = budget(10, unit="USD")
    b = s.finish(items); b.update(tasks=tasks, requests=reqs)
    vec("PL16_budget_in_another_unit", "a budget of 10 USD does not cap JPY payments; amounts in different units are not compared", b)

    # PL17: a payer names a lineage of its choosing
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    t1 = task(7000, 1); r1 = request("occ-1", t1); rs1 = C.request_sha256(r1)
    fake = payment(rs1, 7000, s.tip())
    fake = C.sign(dict(C.body_of(fake), lineage=["sha256:" + "ee" * 32]), G.B)
    b = s.finish([budget(10000), G.use(rs), payment(rs, 7000, s.tip()), G.receipt(rs, seen=s.tip()),
                  G.use(rs1), fake, G.receipt(rs1, seen=s.tip())])
    b.update(tasks=[t, t1], requests=[r, r1])
    vec("PL17_self_declared_lineage_does_not_escape_the_budget",
        "the second payment names a lineage that is nobody's; the request it names commits to the real one, so the "
        "payment does not match the request, is not counted, and the execution it was meant to cover is unpaid",
        b)

    # PL18: a payment logged before its use still counts; the lineage is verified by the use whenever logged
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), payment(rs, 7000, s.tip()), G.use(rs), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL18_payment_before_its_use", "the use is logged after the payment: counted, lineage verified by that use", b)

    # fifth review, 2026-10-18: the request occurrence is what a payment is judged against
    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 29000, s.tip(), payer_k=G.Z, payer=G.Z_PUB),
                  payment(rs, 7000, s.tip()), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL19_outsider_cannot_spend_or_consume_the_budget",
        "an outsider logs a 29,000 payment for B's request first: it is not the request's caller, so it is not counted "
        "and B's own payment is the one the execution is paid by",
        b)

    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(10000), G.use(rs), payment(rs, 1, s.tip()), payment(rs, 7000, s.tip()), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL20_two_different_payments_for_one_call_both_count",
        "1 then 7,000 for the same request: both count against the budget (7,001), the execution is paid by the one "
        "that is the task's price",
        b)

    s = GV.Sc(); s.mine()
    tasks, reqs, items = [], [], [budget(10000)]
    for i in range(2):
        tt = task(7000, i, unit="jpy"); rr = request("occ-%d" % i, tt); rsx = C.request_sha256(rr)
        tasks.append(tt); reqs.append(rr)
        items += [G.use(rsx), payment(rsx, 7000, s.tip(), unit="jpy"), G.receipt(rsx, seen=s.tip())]
    b = s.finish(items); b.update(tasks=tasks, requests=reqs)
    vec("PL21_unit_spelling_does_not_escape_silently",
        "the payer prices and pays in 'jpy' under a budget in 'JPY': not compared, and every payment says so",
        b)

    s = GV.Sc(); s.mine()
    cb = G.cred("cred-b", G.R, G.R_PUB, G.B_PUB, {"pay"}, 0, None)
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(10000), G.use(rs, chain=[cb]), G.use(rs), payment(rs, 7000, s.tip(), chain=[cb]),
                  G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL22_a_second_credential_does_not_relabel_the_call",
        "B holds a second credential straight from the root and logs a use under it for the same request: the request "
        "commits to the budgeted lineage, so a payment under the other one does not match and the execution is unpaid",
        b)

    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, s.tip()), G.receipt(rs, seen=s.tip())])
    vec("PL23_request_not_supplied",
        "without the request occurrence the payment cannot be matched: reported with its amount, not counted; the "
        "execution is priced by the budget and has no payment to show",
        b)

    s = GV.Sc(); s.mine()
    t = task(0, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    b = s.finish([budget(30000), G.use(rs), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[r])
    vec("PL24_free_call_under_a_budget", "a task priced at zero needs no payment even though the lineage has a budget", b)

    s = GV.Sc()
    w = s.witness(budget(10000), GV.TWO, seen=G.SEEN)
    s.mine()
    r = request("occ-0", task(7000, 0)); rs = C.request_sha256(r)
    b = s.finish([G.use(rs), G.receipt(rs, seen=G.SEEN)], [w]); b.update(requests=[r])
    vec("PL25_unpaid_execution_under_an_unresolved_budget",
        "no task, no payment, and the only budget is witnessed with an unresolved order: the requirement to pay is itself "
        "unresolved, not clean",
        b)

    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    for _ in range(12):
        s.mine()
    late = s.tip()
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, late), G.receipt(rs, seen=late)], depth=6)
    b.update(tasks=[t], requests=[r])
    vec("PL26_payment_logged_before_its_seen_block",
        "the operator dates the payment hours before the block it says it had seen: flagged like a receipt",
        b)

    s = GV.Sc(); s.mine()
    big = C.MAX_SAFE
    t0 = task(big, 0); r0 = request("occ-0", t0); rs0 = C.request_sha256(r0)
    t1 = task(big, 1); r1 = request("occ-1", t1); rs1 = C.request_sha256(r1)
    b = s.finish([G.use(rs0), payment(rs0, big, s.tip()), G.use(rs1), payment(rs1, big, s.tip())])
    b.update(tasks=[t0, t1], requests=[r0, r1])
    vec("PL27_totals_stay_in_range", "two payments of 2^53-1: the running total is clamped and marked, the settlement stays JSON", b)

    s = GV.Sc(); s.mine()
    t = task(7000, 0); r = request("occ-0", t); rs = C.request_sha256(r)
    junk = dict(r, task_sha256=["x"])
    b = s.finish([budget(30000), G.use(rs), payment(rs, 7000, s.tip()), G.receipt(rs, seen=s.tip())])
    b.update(tasks=[t], requests=[junk, r])
    vec("PL28_request_with_a_junk_task_digest", "a supplied request whose task_sha256 is a list is skipped, not raised", b)

    out = {"profile": P.PROFILE, "note": "credentials signed by ca2a_runtime; headers are regtest difficulty, ten minutes apart",
           "vectors": VECTORS}
    with open(os.path.join(HERE, "vectors", "vectors_pilot_v0.json"), "wb") as f:
        f.write(C.jcs(out))
    for v in VECTORS:
        e = v["expected"]
        if "refused" in e:
            print(v["id"], "REFUSED", e["refused"]); continue
        pl = e["pilot"]
        print(v["id"], "pay", [(p["seq"], p["amount"], p["reasons"], p.get("unexecuted", False)) for p in pl["payments"]],
              "exec", [(x["seq"], x["disposition"], x.get("payment_seq"), x.get("reasons", [])) for x in pl["executions"]],
              "rej", [(r["seq"], r["reason"]) for r in e["companion"]["items_rejected"]] or "")


if __name__ == "__main__":
    main()
