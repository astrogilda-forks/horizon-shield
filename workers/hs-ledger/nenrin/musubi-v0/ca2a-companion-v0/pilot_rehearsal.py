#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rehearsal of horizon-shield Issue #51: the three cases of the pilot, end to end, with every role played by test
keys of this repository. Nothing here is the run. It exists so that the other parties can check the bindings
(request occurrence, criteria and checker key fixed before the work, digests of execution receipt and payment
inside the acceptance record) against real bytes before the first call, and so that the MUSUBI side of the run has nothing left to
invent on the day.

Writes rehearsal/ next to this file: for each case the bundle, the settlement, and a short READ_ME line in
rehearsal/INDEX.json. Deterministic: running it twice gives the same bytes.

Roles (test keys from gen_vectors.py and gen_vectors_pilot_v0.py):
  principal (root)      issues the agent's credential            G.R
  agent / payer / buyer B, the leaf of the chain                  G.B
  service / payee       X, HORIZON SHIELD's estimate audit        G.X
  budget issuer         A, who issued B's credential              G.A
  checker               K, named by B in its criteria commitment  GV2.K (stands in for invinoveritas)
  log operator          O                                         G.O
  witnesses             W1, W2 (threshold 2)                      GV.W1, GV.W2 (stand in for #50 volunteers)

The rail is "signed-test-transfer": the payment's rail receipt digest is the SHA-256 of a canonical stub
transfer; on the day it is the x402 commitment receipt's digest, nothing else changes.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import gen_vectors as G                 # noqa: E402
import gen_vectors_v0_1 as GV           # noqa: E402
import gen_vectors_pilot_v0 as GV2      # noqa: E402
import companion_v0 as C                # noqa: E402
import companion_v0_1 as C1             # noqa: E402
import pilot_v0 as P                    # noqa: E402

OUT = os.path.join(HERE, "rehearsal")
FIXTURE = {"type": "horizon-shield.estimate-fixture.v0", "lines": [
    {"item": "外壁塗装 シリコン", "qty": 180, "unit": "㎡", "unit_price": 3200},
    {"item": "足場", "qty": 240, "unit": "㎡", "unit_price": 900},
    {"item": "高圧洗浄", "qty": 180, "unit": "㎡", "unit_price": 250}]}
FIXTURE_SHA = C.sha256_hex(C.jcs(FIXTURE))
CRITERIA = {"type": "horizon-shield.acceptance-criteria.v0", "fixture_sha256": FIXTURE_SHA, "criteria": [
    "every line of the fixture appears in the audit with a JCCDB reference",
    "each unit price is compared against the JCCDB range for the region",
    "the audit's total equals the fixture's total"]}
CRITERIA_SHA = C.sha256_hex(C.jcs(CRITERIA))
PRICE, UNIT = 7000, "JPY-testnet"


def audit_result(fixture):
    """Stand-in for the service: a deterministic digest of what the audit would return for this fixture."""
    return C.sha256_hex(b"audit-of:" + C.jcs(fixture))


def stub_rail_receipt(req_sha, amount, unit):
    return C.sha256_hex(C.jcs({"type": "signed-test-transfer.v0", "request_sha256": req_sha, "amount": amount, "unit": unit}))


def prepare(n):
    """Before the work: the task, the request occurrence, and the buyer's commitment to criteria and checker."""
    t = GV2.task(PRICE, n, unit=UNIT)
    r = GV2.request("pilot-call-%d" % n, t)
    rs = C.request_sha256(r)
    return t, r, rs, GV2.criteria(rs, CRITERIA_SHA, G.SEEN)


def call(s, n, seen, prepared, deliverable_fixture=None):
    """One priced call: use, criteria, payment, execution receipt. Returns the items and the parts."""
    t, r, rs, crit = prepared
    pay = GV2.payment(rs, PRICE, seen, unit=UNIT, rail="signed-test-transfer", rail_sha=stub_rail_receipt(rs, PRICE, UNIT))
    out_fixture = deliverable_fixture or FIXTURE
    rcpt = C.sign({"type": C.T_RECEIPT, "responder": G.X_PUB, "caller": G.B_PUB, "lineage": G.LIN, "capability": "pay",
                   "request_sha256": rs, "seen_block": seen,
                   "outcome": {"kind": "result", "stage": "audited", "response_sha256": audit_result(out_fixture)},
                   "attestation_sha256": None}, G.X)
    items = [G.use(rs), crit, pay, rcpt]
    return items, t, r, rs, pay, rcpt


def bundle_for(items, witnessed, tasks, reqs, s):
    b = s.finish(items, witnessed)
    b.update(tasks=tasks, requests=reqs, profile=P.PROFILE)
    return json.loads(C.jcs(b))


def main():
    os.makedirs(OUT, exist_ok=True)
    index = []

    def emit(case, desc, b):
        settlement = json.loads(C.jcs(P.settle(b)))
        for name, obj in (("bundle", b), ("settlement", settlement)):
            with open(os.path.join(OUT, "case_%s.%s.json" % (case, name)), "wb") as f:
                f.write(C.jcs(obj))
        pl = settlement["pilot"]
        summary = {"case": case, "what": desc,
                   "payments": [(p["seq"], p["amount"], p["unit"], p["reasons"]) for p in pl["payments"]],
                   "executions": [(e["seq"], e["disposition"], e.get("payment_seq"), e.get("payment_reasons", []),
                                   e.get("reasons", []), e.get("accepted")) for e in pl["executions"]],
                   "acceptances": [(a["seq"], a["verdict"], a["counted"], a["reasons"]) for a in pl["acceptances"]],
                   "operator_findings": settlement["companion"]["operator_findings"]}
        index.append(summary)
        print(case, json.dumps(summary["executions"]), json.dumps(summary["acceptances"]))

    # the budget and the criteria commitments go through the witnessed lane as well as the log, so the
    # rehearsal exercises both: an operator that drops or re-sequences them does not change the answer
    budget = GV2.budget(20000, unit=UNIT)

    def before_work(s, prepared):
        ws = [s.witness(budget, GV.TWO)] + [s.witness(p[3], GV.TWO) for p in prepared]
        s.mine()
        return ws, s.tip()

    s = GV.Sc()
    p0 = prepare(0)
    ws, seen = before_work(s, [p0])
    items, t, r, rs, pay, rcpt = call(s, 0, seen, p0)
    items = [budget] + items + [GV2.acceptance(rs, CRITERIA_SHA, rcpt, pay, "pass", seen)]
    emit("A", "within: one call at the task's price, executed, accepted against criteria fixed before the work",
         bundle_for(items, ws, [t], [r], s))

    s = GV.Sc()
    p0 = prepare(0)
    ws, seen = before_work(s, [p0])
    other = dict(FIXTURE, lines=FIXTURE["lines"][:2])          # the audit of a different quote comes back
    items, t, r, rs, pay, rcpt = call(s, 0, seen, p0, deliverable_fixture=other)
    items = [budget] + items + [GV2.acceptance(rs, CRITERIA_SHA, rcpt, pay, "fail", seen)]
    emit("B", "acceptance fails: the deliverable is the audit of another fixture; authority and payment say within and paid, "
              "the checker says fail, and the record cannot be moved to another call",
         bundle_for(items, ws, [t], [r], s))

    s = GV.Sc()
    p0, p1, p2 = prepare(0), prepare(1), prepare(2)
    ws, seen = before_work(s, [p0, p1, p2])
    i0, t0, r0, rs0, pay0, rcpt0 = call(s, 0, seen, p0)
    i1, t1, r1, rs1, pay1, rcpt1 = call(s, 1, seen, p1)
    i2, t2, r2, rs2, pay2, rcpt2 = call(s, 2, seen, p2)
    items = [budget] + i0 + [GV2.acceptance(rs0, CRITERIA_SHA, rcpt0, pay0, "pass", seen)] \
        + i1 + [GV2.acceptance(rs1, CRITERIA_SHA, rcpt1, pay1, "pass", seen)] \
        + i2 + [GV2.acceptance(rs2, CRITERIA_SHA, rcpt2, pay2, "pass", seen)]
    emit("C", "budget exceeded: three calls at 7,000 under a budget of 20,000; the third payment is budget_exceeded, "
              "its execution and acceptance stand on their own and say so",
         bundle_for(items, ws, [t0, t1, t2], [r0, r1, r2], s))

    with open(os.path.join(OUT, "INDEX.json"), "wb") as f:
        f.write(C.jcs({"issue": "ogasurfproject-jpg/horizon-shield#51", "profile": P.PROFILE,
                       "fixture_sha256": FIXTURE_SHA, "criteria_sha256": CRITERIA_SHA, "price": PRICE, "unit": UNIT,
                       "rail": "signed-test-transfer (stand-in for x402)", "cases": index}))
    with open(os.path.join(OUT, "fixture.json"), "wb") as f:
        f.write(C.jcs(FIXTURE))
    with open(os.path.join(OUT, "criteria.json"), "wb") as f:
        f.write(C.jcs(CRITERIA))


if __name__ == "__main__":
    main()
