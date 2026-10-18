#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI pilot profile v0: a delegated budget, paid calls, and what the receipts prove about each other.

The scene (aeoess/agent-governance-vocabulary#177, 2026-10-18): an agent holding a delegated budget pays another
project's service per call; every payment is checked against the budget and leaves a signed receipt; afterwards
anyone recomputes whether the money and the actions stayed within what was granted.

Assembling that from the layers that exist showed two gaps that no layer covered:

  1. nothing summed. settle v1.12's grant.limits caps one execution; the companion's use-policy caps a count of
     calls. A budget is a total: 50,000 per call, a hundred times, passed both.
  2. the request occurrence names no price. A payment receipt could say "7,000 for request R" while R itself
     promised nothing about money, and the responder's execution receipt could not say what it was paid.

This profile adds, on top of the companion (profile v0.1, including its witnessed lane):

  musubi.ca2a.task.v0            the task the request's task_sha256 commits to: service, amount, unit, nonce.
                                 Supplying the task binds the request occurrence to a price without changing the
                                 companion's request type.
  musubi.ca2a.budget-policy.v0   issuer-signed total for a credential: max_total in a unit. A restriction, so the
                                 witnessed lane carries it: an operator that refuses to log it does not escape it.
  musubi.ca2a.payment-receipt.v0 payer-signed: lineage, payee, request_sha256, amount, unit, a Bitcoin block the
                                 payer had seen, and the rail (kind and the digest of the rail's own receipt, for
                                 x402 the salted commitment receipt). The chain settles the money; this record
                                 settles the authorization.

  A fifth gap was named from outside (babyblueviper1, 2026-10-18): after payment and execution, nothing recorded
  whether what came back met what the buyer asked for, by a party that is neither payer nor payee. That is the
  step a dispute weighs. Two items carry it:

  musubi.ca2a.criteria-commitment.v0  buyer-signed, before the work: request_sha256, criteria_sha256, the checker
                                      key, seen_block. A restriction, so the witnessed lane carries it: an operator
                                      that sequences it after the receipt does not unfix it.
  musubi.ca2a.acceptance-record.v0    checker-signed, after it: request_sha256, criteria_sha256, the digest of the
                                      external acceptance record (for invinoveritas, the work-acceptance record of
                                      x402-foundation/tsc#4 profile 1.2.1), the verdict, the digests of the
                                      execution receipt and of the payment it accepts (or null), and a seen block.
  An acceptance counts only when its checker is the key the buyer named in a commitment to the same criteria
  for the same request, that commitment is fixed before the execution receipt (logged before it, or witnessed
  before the block the receipt had seen), the checker is none of the parties (caller, responder, the receipt's
  signer and caller, the operator, any key in a verified chain), the execution receipt digest names a
  companion-accepted result receipt for the request, and the payment digest, when given, names a counted
  payment for the same request and payee logged before the acceptance. One record counts per (execution,
  commitment); whether the buyer named a trustworthy checker is the relying party's reading of the commitment.
  The record itself stays in its own format; this profile binds it to the call and checks who signed it and when.

  Two more gaps appeared while assembling. A payment without a block it had seen cannot be ordered against a
  budget published through the witnessed lane, so a refused budget could never be shown to precede a payment:
  every statement that is ordered against the lane carries a seen block, and the payment receipt now does. And
  a payment's lineage is the payer's own word, where the companion's use item carries the chain cA2A verified:
  a payer naming a lineage of its choosing would escape the budget on its real credential while the execution,
  which finds its payment by request and payee alone, would look paid. So a payment is charged to the lineage
  of the accepted use logged before it for the same request and payee, and its own lineage is only compared.

Rules, in log order, on the entries the companion accepted:

  - A payment is charged to the lineage of the companion-accepted use logged before it for the same request and
    payee (the chain cA2A verified); without one it is charged to its own lineage and marked lineage_unverified,
    and a lineage that differs from the use's is lineage_does_not_match_use. It counts for every credential in
    that lineage, under any chain, whoever the payer, once per (request, payee) pair: the first logged payment
    for a pair is the one, a later one is duplicate_payment. The same counting rule as the companion's uses, so
    delegating the budget onward or re-issuing an ancestor does not reset it.
  - A budget policy counts for a hop when signed by that hop's issuer and logged, or witnessed, before the
    payment. The smallest max_total applies. The running total over counted payments in log order must stay at
    or below it: the first payment that takes it above is budget_exceeded, and so is every later one.
  - When the task is supplied, the payment's amount and unit must equal the task's (payment_not_for_task).
  - A result receipt for a priced request (task amount above zero, or any budget policy on its lineage) needs a
    counted payment logged before it by its caller to its responder: executed_without_payment.
  - A counted payment with no result receipt by the checkpoint is unexecuted: the money left, the work did not
    arrive, or it has not been logged yet. Reported, not judged. A denial after a payment still counts against
    the budget: no refund is modelled in v0.

What this does not prove: that the rail moved the money (the rail's receipt is carried by digest only), that the
amount in the task is the price the service advertised, or that the work was done. It proves who committed to
which price, whether the issuer's total was respected in the order the log fixed, and that each payment and
execution name the same request.

Usage:
  pilot_v0.py --selftest
  pilot_v0.py --settle BUNDLE.json
"""
import argparse, json, os, sys

import companion_v0 as c0
import companion_v0_1 as c1
from companion_v0 import (Bad, jcs, sha256_hex, _nonneg, _is, _need, _fields, check_sig, HEX32, TEXT, DIGEST,
                          load_strict)

PROFILE = "musubi.ca2a.pilot.v0"
T_TASK = "musubi.ca2a.task.v0"
T_BUDGET = "musubi.ca2a.budget-policy.v0"
T_PAYMENT = "musubi.ca2a.payment-receipt.v0"
T_CRITERIA = "musubi.ca2a.criteria-commitment.v0"
T_ACCEPT = "musubi.ca2a.acceptance-record.v0"
VERDICTS = ("pass", "fail", "not_evaluated")
T_SETTLEMENT = "musubi.ca2a.pilot-settlement.v0"
UNIT = TEXT
MAX_AMOUNT = c0.MAX_SAFE


def _budget(item):
    _fields(item, ("type", "credential_digest", "issuer", "max_total", "unit", "signature"), (), T_BUDGET)
    _need(DIGEST, item["credential_digest"], "bad_digest")
    if not (_nonneg(item["max_total"]) and item["max_total"] >= 1):
        raise Bad("bad_max_total")
    _need(UNIT, item["unit"], "bad_unit")
    check_sig(item, "issuer")
    return "budget-policy", item


def _payment(item):
    _fields(item, ("type", "payer", "payee", "lineage", "request_sha256", "amount", "unit", "seen_block", "rail",
                   "signature"), (), T_PAYMENT)
    c0._block(item["seen_block"], "seen_block")
    _need(HEX32, item["payee"], "bad_key")
    c0._lineage(item["lineage"])
    _need(HEX32, item["request_sha256"], "bad_request_sha256")
    if not (_nonneg(item["amount"]) and item["amount"] >= 1):
        raise Bad("bad_amount")
    _need(UNIT, item["unit"], "bad_unit")
    rail = item["rail"]
    _fields(rail, ("kind", "receipt_sha256"), (), "rail")
    _need(TEXT, rail["kind"], "bad_rail_kind")
    if rail["receipt_sha256"] is not None:
        _need(HEX32, rail["receipt_sha256"], "bad_rail_receipt_sha256")
    check_sig(item, "payer")
    return "payment", item


def _criteria(item):
    _fields(item, ("type", "buyer", "request_sha256", "criteria_sha256", "checker", "seen_block", "signature"), (),
            T_CRITERIA)
    _need(HEX32, item["request_sha256"], "bad_request_sha256")
    _need(HEX32, item["criteria_sha256"], "bad_criteria_sha256")
    _need(HEX32, item["checker"], "bad_key")
    c0._block(item["seen_block"], "seen_block")
    check_sig(item, "buyer")
    return "criteria", item


def _acceptance(item):
    _fields(item, ("type", "checker", "request_sha256", "criteria_sha256", "record_sha256", "verdict",
                   "execution_receipt_sha256", "payment_sha256", "seen_block", "signature"), (), T_ACCEPT)
    _need(HEX32, item["request_sha256"], "bad_request_sha256")
    _need(HEX32, item["criteria_sha256"], "bad_criteria_sha256")
    _need(HEX32, item["record_sha256"], "bad_record_sha256")
    if item["verdict"] not in VERDICTS:
        raise Bad("bad_verdict")
    _need(HEX32, item["execution_receipt_sha256"], "bad_execution_receipt_sha256")
    if item["payment_sha256"] is not None:
        _need(HEX32, item["payment_sha256"], "bad_payment_sha256")
    c0._block(item["seen_block"], "seen_block")
    check_sig(item, "checker")
    return "acceptance", item


EXTENSIONS = {T_BUDGET: _budget, T_PAYMENT: _payment, T_CRITERIA: _criteria, T_ACCEPT: _acceptance}
RESTRICTIONS = frozenset(set(c1.RESTRICTIONS) | {"budget-policy", "criteria"})


def task_sha256(task):
    _fields(task, ("type", "service", "amount", "unit", "nonce"), (), "task")
    if task["type"] != T_TASK:
        raise Bad("wrong_type", "task")
    _need(TEXT, task["service"], "bad_service")
    if not _nonneg(task["amount"]):
        raise Bad("bad_amount", "task")
    _need(UNIT, task["unit"], "bad_unit")
    _need(HEX32, task["nonce"], "bad_nonce")
    return sha256_hex(jcs(task))


def settle(bundle):
    """bundle = a companion v0.1 bundle with profile musubi.ca2a.pilot.v0, plus optional tasks: [task, ...].
    Returns the companion's settlement under `companion` and the pilot's under `pilot`. Never raises on input."""
    out = {"type": T_SETTLEMENT, "profile": PROFILE}
    try:
        if not isinstance(bundle, dict) or bundle.get("profile") != PROFILE:
            raise Bad("wrong_profile")
        tasks_raw = bundle.get("tasks", [])
        if not (isinstance(tasks_raw, list) and len(tasks_raw) <= 1024):
            raise Bad("bad_bundle", "tasks")
    except Bad as exc:
        out["refused"] = exc.code
        return out
    inner = {k: v for k, v in bundle.items() if k != "tasks"}
    inner["profile"] = c1.PROFILE
    comp = c1.settle(inner, EXTENSIONS, RESTRICTIONS)
    out["companion"] = comp
    if "refused" in comp:
        out["refused"] = comp["refused"]
        return out
    if not comp["log"]["verified"]:
        return out

    from ca2a_runtime.delegation.credential import DelegationCredential
    from ca2a_runtime.delegation.revocation import credential_digest
    from ca2a_runtime.errors import CA2AError

    tasks = {}
    for t in tasks_raw:
        try:
            tasks.setdefault(task_sha256(t), t)
        except Bad:
            continue
    requests = {}
    for r in bundle.get("requests", []):
        try:
            requests.setdefault(c0.request_sha256(r), r)
        except Bad:
            continue
    entries = bundle["log"]["entries"]
    rejected = {x["seq"] for x in comp["items_rejected"]}
    budgets, payments, uses, criteria, acceptances = [], [], [], [], []
    for e in entries:
        if e["seq"] in rejected:
            continue
        it = e["item"]
        if it.get("type") == T_BUDGET:
            budgets.append((e["seq"], it))
        elif it.get("type") == T_PAYMENT:
            payments.append((e["seq"], it))
        elif it.get("type") == c0.T_USE:
            uses.append((e["seq"], it))
        elif it.get("type") == T_CRITERIA:
            criteria.append((e["seq"], it))
        elif it.get("type") == T_ACCEPT:
            acceptances.append((e["seq"], it))
    wit = {w["item_sha256"]: w for w in comp["witnessed"] if w["kind"] == "budget-policy"}
    wit_crit = {w["item_sha256"]: w for w in comp["witnessed"] if w["kind"] == "criteria"}
    wit_items = {}
    for rec in bundle.get("witnessed", []):
        try:
            d = c1.item_sha256(rec["item"])
        except Exception:
            continue
        if (d in wit or d in wit_crit) and d not in wit_items:
            wit_items[d] = rec["item"]
    A = comp["log"].get("earliest_anchor_height", comp["log"]["anchor_height"])
    pseudo = {"grant": {"finality": {"max_target_bits": bundle["trust"]["max_target_bits"]}},
              "lower_bound": bundle["trust"]["lower_bound"]}
    res, _ = c1.v11.verify_view(bundle["view"], pseudo)      # the companion accepted this view already
    hashes = res["hashes"]
    times = {x["height"]: int.from_bytes(bytes.fromhex(x["hex"])[68:72], "little") for x in bundle["view"]["headers"]}

    # the issuer of each credential, and the lineages that have a verified chain: from the chains the
    # companion used, that is the accepted uses (their chain passed cA2A) and the supplied chains
    issuers, verified_lineages, chain_keys = {}, set(), set()

    def learn(raw_chain, trusted):
        try:
            creds = [DelegationCredential.from_dict(c) for c in raw_chain]
        except (CA2AError, TypeError, ValueError, KeyError):
            return
        try:
            for c in creds:
                c.verify_signature()
        except CA2AError:
            return
        lin = []
        for c in creds:
            d = credential_digest(c)
            issuers.setdefault(d, c.issuer)
            chain_keys.add(c.issuer)
            chain_keys.add(c.subject)
            lin.append(d)
        if trusted:
            verified_lineages.add(tuple(lin))
    for q, u in uses:
        learn(u["chain"], True)
    for raw in bundle.get("chains", []):
        if isinstance(raw, list):
            learn(raw, True)

    def budgets_for(hop_digest, seq, seen_height, unit, any_unit=False):
        """Budgets on this hop in force for the entry at seq: logged before it, or witnessed before the block it
        had seen under the companion's rule. Returns (sure caps in unit, unresolved caps in unit, other units)."""
        iss = issuers.get(hop_digest)
        sure, unresolved, other_units = [], [], set()
        for q, b in budgets:
            if q < seq and b["credential_digest"] == hop_digest and b["issuer"] == iss:
                if any_unit or b["unit"] == unit:
                    sure.append(b["max_total"])
                else:
                    other_units.add(b["unit"])
        for d, w in wit.items():
            b = wit_items.get(d)
            if b is None or b["credential_digest"] != hop_digest or b["issuer"] != iss:
                continue
            o = c1.order({"published": w["published_height"], "earliest": w["earliest_height"]}, seen_height, A) \
                if seen_height is not None else "unresolved"
            if o == "after":
                continue
            if not any_unit and b["unit"] != unit:
                other_units.add(b["unit"])
            elif o == "before":
                sure.append(b["max_total"])
            else:
                unresolved.append(b["max_total"])
        return sure, unresolved, sorted(other_units)

    # payments, in log order: a payment is judged against the request occurrence it names. The request
    # commits to caller, responder and lineage, so that is where the payer, the payee and the charged lineage
    # come from; a payment the relying party cannot match to a request is reported and not counted
    counted = {}                 # credential digest -> {unit: running total}
    seen_bytes = set()
    pairs = {}                   # (request, payee) -> [seq of counted payments]
    rows = []
    for seq, p in payments:
        rs = p["request_sha256"]
        row = {"seq": seq, "request_sha256": rs, "payer": p["payer"], "payee": p["payee"], "amount": p["amount"],
               "unit": p["unit"], "rail": p["rail"]["kind"], "counted": False}
        if p["rail"]["receipt_sha256"] is not None:
            row["rail_receipt_sha256"] = p["rail"]["receipt_sha256"]
        reasons = []
        t = entries[seq]["logged_at"]
        sb = p["seen_block"]
        S = sb["height"] if hashes.get(sb["height"]) == sb["hash"] else None
        if S is None:
            reasons.append("seen_block_not_in_view")
        else:
            if S >= A:
                reasons.append("seen_block_not_before_anchor")
            if t + c0.TIME_SLACK < times[S]:
                reasons.append("logged_before_seen_block")
        digest = sha256_hex(jcs(p))
        if digest in seen_bytes:
            reasons.append("duplicate_payment")             # the same statement logged again is a retry
            row["reasons"] = sorted(set(reasons))
            rows.append(row)
            continue
        seen_bytes.add(digest)
        req = requests.get(rs)
        row["request_known"] = req is not None
        if req is None:
            reasons.append("request_unknown")
            row["reasons"] = sorted(set(reasons))
            rows.append(row)
            continue
        if (req["caller"], req["responder"], req["lineage"]) != (p["payer"], p["payee"], p["lineage"]):
            reasons.append("request_does_not_match_payment")
            row["reasons"] = sorted(set(reasons))
            rows.append(row)
            continue
        ts = req["task_sha256"]
        task = tasks.get(ts) if isinstance(ts, str) else None
        row["task_known"] = task is not None
        row["for_task"] = task is None or (task["amount"], task["unit"]) == (p["amount"], p["unit"])
        if task is not None and not row["for_task"]:
            reasons.append("payment_not_for_task")
        pair = (rs, p["payee"])
        if pair in pairs:
            reasons.append("another_payment_for_request")  # a different statement for the same call: both count
            row["earlier_payment_seqs"] = list(pairs[pair])
        pairs.setdefault(pair, []).append(seq)
        row["counted"] = True
        lineage = req["lineage"]
        if tuple(lineage) not in verified_lineages:
            reasons.append("lineage_unverified")
        limits = []
        for i, d in enumerate(lineage):
            book = counted.setdefault(d, {})
            total = book.get(p["unit"], 0) + p["amount"]
            if total > MAX_AMOUNT:
                total = MAX_AMOUNT
                reasons.append("total_out_of_range")
            book[p["unit"]] = total
            sure, unresolved, other = budgets_for(d, seq, S, p["unit"])
            if sure:
                limit = min(sure)
                limits.append({"hop": i, "limit": limit, "total": total, "unit": p["unit"]})
                if total > limit:
                    reasons.append("budget_exceeded")
            if unresolved:
                reasons.append("budget_order_unresolved")
            if other:
                reasons.append("budget_in_other_unit")
                row.setdefault("budget_units", []).extend(u for u in other if u not in row.get("budget_units", []))
        if limits:
            row["budgets"] = limits
        row["reasons"] = sorted(set(reasons))
        rows.append(row)
    by_seq = {r["seq"]: r for r in rows}

    # executions against payments
    exec_rows, executed = [], set()
    for r in comp["receipts"]:
        seq = r["seq"]
        it = entries[seq]["item"]
        rs = it["request_sha256"]
        e = {"seq": seq, "request_sha256": rs, "disposition": r["disposition"]}
        req = requests.get(rs)
        ts = req["task_sha256"] if req else None
        task = tasks.get(ts) if isinstance(ts, str) else None
        S = it["seen_block"]["height"] if hashes.get(it["seen_block"]["height"]) == it["seen_block"]["hash"] else None
        e["seen_height"] = S
        sure_any = unresolved_any = False
        for d in it["lineage"]:
            # without a task the unit is unknown: a budget on the lineage in any unit prices the call
            sure, unresolved, _ = budgets_for(d, seq, S, task["unit"] if task else "", any_unit=task is None)
            sure_any |= bool(sure)
            unresolved_any |= bool(unresolved)
        priced = (task["amount"] > 0) if task else sure_any
        e["priced"] = priced
        mine = [q for q in pairs.get((rs, it["responder"]), []) if q < seq and by_seq[q]["payer"] == it["caller"]]
        pay = next((q for q in mine if by_seq[q]["for_task"]), None)
        reasons = []
        if pay is None and mine:
            pay = mine[0]
            reasons.append("paid_other_than_task_price")
        if pay is not None:
            e["payment_seq"] = pay
            if by_seq[pay]["reasons"]:
                e["payment_reasons"] = by_seq[pay]["reasons"]
        elif r["outcome"] == "result":
            if priced:
                reasons.append("executed_without_payment")
            elif unresolved_any and not task:
                reasons.append("payment_requirement_unresolved")
        if reasons:
            e["reasons"] = reasons
        if r["outcome"] == "result":
            executed.add((rs, it["responder"]))
        exec_rows.append(e)
    for row in rows:
        if row["counted"] and (row["request_sha256"], row["payee"]) not in executed:
            row["unexecuted"] = True

    # acceptance: the buyer fixes, before the work, what is checked and who checks it (criteria-commitment: the
    # criteria digest and the checker key). An acceptance counts when its checker is the one the buyer named,
    # that commitment is fixed before the execution receipt (logged before it, or witnessed before the block
    # the receipt had seen), the checker is none of the parties, and the execution receipt and payment it
    # names are the companion-accepted ones for this request. One counted record per (execution, commitment).
    receipt_digest = {}            # item digest -> (seq, request, responder, caller, outcome), first logged
    for r in comp["receipts"]:
        it = entries[r["seq"]]["item"]
        receipt_digest.setdefault(c1.item_sha256(it), (r["seq"], it["request_sha256"], it["responder"], it["caller"],
                                                       r["outcome"]))
    payment_digest = {}
    for q in sorted(by_seq):
        if by_seq[q]["counted"]:
            payment_digest.setdefault(c1.item_sha256(entries[q]["item"]), q)
    exec_by_seq = {e["seq"]: e for e in exec_rows}
    operator = bundle["trust"]["operator"]

    def commitment_row(key, c, seq=None, w=None):
        row = {"request_sha256": c["request_sha256"], "buyer": c["buyer"], "criteria_sha256": c["criteria_sha256"],
               "checker": c["checker"], "usable": False}
        reasons = []
        if seq is not None:
            row["seq"] = seq
            t = entries[seq]["logged_at"]
        else:
            row["item_sha256"] = key
            row["published_height"] = w["published_height"]
            t = None
        sb = c["seen_block"]
        S = sb["height"] if hashes.get(sb["height"]) == sb["hash"] else None
        if S is None:
            reasons.append("seen_block_not_in_view")
        else:
            if S >= A:
                reasons.append("seen_block_not_before_anchor")
            if t is not None and t + c0.TIME_SLACK < times[S]:
                reasons.append("logged_before_seen_block")
        req = requests.get(c["request_sha256"])
        if req is None:
            reasons.append("request_unknown")
        elif c["buyer"] != req["caller"]:
            reasons.append("buyer_is_not_caller")
        elif c["checker"] in (req["caller"], req["responder"]):
            reasons.append("checker_is_party")
        row["reasons"] = sorted(set(reasons))
        row["usable"] = not (set(reasons) & {"seen_block_not_in_view", "seen_block_not_before_anchor",
                                               "request_unknown", "buyer_is_not_caller", "checker_is_party"})
        return row
    crows = [commitment_row(None, c, seq=q) for q, c in criteria]
    wcrows = [commitment_row(d, wit_items[d], w=w) for d, w in sorted(wit_crit.items()) if d in wit_items]

    def fixed_before(ex_seq, ex_S, req_sha, crit_sha, checker):
        """The buyer's usable commitments to (criteria, checker) for the request that are fixed before the
        execution at ex_seq, which saw block ex_S. Returns (sure list, unresolved list) of commitment ids."""
        sure, unresolved = [], []
        for row in crows:
            if row["usable"] and (row["request_sha256"], row["criteria_sha256"], row["checker"]) == \
                    (req_sha, crit_sha, checker) and row["seq"] < ex_seq:
                sure.append(row["seq"])
        for row in wcrows:
            if not (row["usable"] and (row["request_sha256"], row["criteria_sha256"], row["checker"]) ==
                    (req_sha, crit_sha, checker)):
                continue
            w = wit_crit[row["item_sha256"]]
            o = c1.order({"published": w["published_height"], "earliest": w["earliest_height"]}, ex_S, A) \
                if ex_S is not None else "unresolved"
            if o == "before":
                sure.append(row["item_sha256"])
            elif o == "unresolved":
                unresolved.append(row["item_sha256"])
        return sure, unresolved

    accepted = {}                  # (execution seq, criteria, checker) -> first counted acceptance seq
    arows = []
    for seq, a in acceptances:
        row = {"seq": seq, "request_sha256": a["request_sha256"], "checker": a["checker"], "verdict": a["verdict"],
               "criteria_sha256": a["criteria_sha256"], "record_sha256": a["record_sha256"], "counted": False}
        reasons = []
        t = entries[seq]["logged_at"]
        sb = a["seen_block"]
        S = sb["height"] if hashes.get(sb["height"]) == sb["hash"] else None
        if S is None:
            reasons.append("seen_block_not_in_view")
        else:
            if S >= A:
                reasons.append("seen_block_not_before_anchor")
            if t + c0.TIME_SLACK < times[S]:
                reasons.append("logged_before_seen_block")
        req = requests.get(a["request_sha256"])
        row["request_known"] = req is not None
        ex = receipt_digest.get(a["execution_receipt_sha256"])
        if ex is None or ex[1] != a["request_sha256"] or ex[0] >= seq:
            reasons.append("execution_receipt_not_found")
            ex = None
        elif ex[4] != "result":
            reasons.append("execution_not_a_result")
        parties = {operator} | chain_keys
        if req is not None:
            parties |= {req["caller"], req["responder"]}
        if ex is not None:
            parties |= {ex[2], ex[3]}
        if req is None:
            reasons.append("request_unknown")
        elif a["checker"] in parties:
            reasons.append("checker_is_party")
        if req is not None and ex is not None:
            ex_S = exec_by_seq[ex[0]].get("seen_height")
            sure, unresolved = fixed_before(ex[0], ex_S, a["request_sha256"], a["criteria_sha256"], a["checker"])
            if sure:
                row["commitment"] = sure[0]
            else:
                named = [r for r in crows + wcrows if r["usable"] and r["request_sha256"] == a["request_sha256"]
                         and r["criteria_sha256"] == a["criteria_sha256"]]
                if not named:
                    reasons.append("criteria_not_committed_by_buyer")
                elif not any(r["checker"] == a["checker"] for r in named):
                    reasons.append("checker_not_named_by_buyer")
                else:
                    reasons.append("criteria_not_fixed_before_work")
                if unresolved:
                    reasons.append("criteria_order_unresolved")
            others = {(r["criteria_sha256"], r["checker"]) for r in crows + wcrows
                      if r["usable"] and r["request_sha256"] == a["request_sha256"]}
            if len(others) > 1:
                reasons.append("multiple_criteria_commitments")
        if a["payment_sha256"] is not None:
            pq = payment_digest.get(a["payment_sha256"])
            if pq is None or by_seq[pq]["request_sha256"] != a["request_sha256"] or \
                    (ex is not None and by_seq[pq]["payee"] != ex[2]):
                reasons.append("payment_not_found")
            elif pq >= seq:
                reasons.append("payment_not_before_acceptance")
            else:
                row["payment_seq"] = pq
                if ex is not None and exec_by_seq[ex[0]].get("payment_seq") != pq:
                    reasons.append("payment_not_the_executions")
        if ex is not None:
            row["execution_seq"] = ex[0]
            k = (ex[0], a["criteria_sha256"], a["checker"])
            if k in accepted:
                reasons.append("another_acceptance_for_execution")
                row["first_acceptance_seq"] = accepted[k]
        hard = {"seen_block_not_in_view", "seen_block_not_before_anchor", "request_unknown", "checker_is_party",
                "execution_receipt_not_found", "execution_not_a_result", "criteria_not_committed_by_buyer",
                "checker_not_named_by_buyer", "criteria_not_fixed_before_work", "payment_not_found",
                "payment_not_before_acceptance", "another_acceptance_for_execution"}
        row["reasons"] = sorted(set(reasons))
        if not (set(reasons) & hard):
            row["counted"] = True
            accepted[(ex[0], a["criteria_sha256"], a["checker"])] = seq
            e = exec_by_seq[ex[0]]
            e.setdefault("acceptance_seqs", []).append(seq)
            verdicts = {ar["verdict"] for ar in arows if ar["counted"] and ar.get("execution_seq") == ex[0]}
            verdicts.add(a["verdict"])
            e["accepted"] = a["verdict"] if len(verdicts) == 1 else "conflicting"
            if reasons:
                e.setdefault("acceptance_reasons", []).extend(x for x in row["reasons"]
                                                             if x not in e.get("acceptance_reasons", []))
        arows.append(row)
    for e in exec_rows:
        e.pop("seen_height", None)
        if "accepted" not in e:
            e["accepted"] = None

    out["pilot"] = {"payments": rows, "executions": exec_rows, "criteria_commitments": crows,
                    "witnessed_criteria_commitments": wcrows, "acceptances": arows,
                    "totals": {d: book for d, book in sorted(counted.items())},
                    "budget_policies": len(budgets), "witnessed_budget_policies": len(wit), "tasks_known": len(tasks)}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--settle")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "vectors", "vectors_pilot_v0.json"), "rb") as f:
            vs = json.loads(f.read())
        bad = 0
        for v in vs["vectors"]:
            if json.loads(jcs(settle(v["bundle"]))) != v["expected"]:
                bad += 1
                print("FAIL", v["id"])
        print("%d/%d vectors agree" % (len(vs["vectors"]) - bad, len(vs["vectors"])))
        sys.exit(1 if bad else 0)
    if a.settle:
        try:
            with open(a.settle, "rb") as f:
                b = load_strict(f.read())
        except (Bad, ValueError, RecursionError, OSError) as exc:
            code = exc.code if isinstance(exc, Bad) else "unreadable_input"
            sys.stdout.write(jcs({"type": T_SETTLEMENT, "profile": PROFILE, "refused": code}).decode("utf-8") + "\n")
            sys.exit(3)
        out = settle(b)
        sys.stdout.write(jcs(out).decode("utf-8") + "\n")
        sys.exit(2 if "refused" in out or not out.get("companion", {}).get("log", {}).get("verified") else 0)
    ap.print_help()


if __name__ == "__main__":
    main()
