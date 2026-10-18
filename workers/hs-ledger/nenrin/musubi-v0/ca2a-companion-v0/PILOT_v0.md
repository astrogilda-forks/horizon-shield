# MUSUBI pilot profile v0: a delegated budget, paid calls, and what the receipts prove about each other

Status: draft, revision 0. Reference verifier `pilot_v0.py`, vectors `vectors/vectors_pilot_v0.json` (28). Built on the companion for cA2A, profile v0.1, which is unchanged; a pilot bundle is a v0.1 bundle plus tasks, and the pilot's settlement carries the companion's settlement whole under `companion`.

## 1. The scene

An agent holds a budget its principal delegated. It pays another project's service per call. Every payment is checked against the budget and leaves a signed receipt. Afterwards anyone, holding no key and trusting no server, recomputes whether the money and the actions stayed within what was granted (aeoess/agent-governance-vocabulary#177, 2026-10-18).

## 2. What assembling it found

Each layer below existed before this profile. Putting them together for this one scene showed four things none of them covered.

1. **Nothing summed.** settle v1.12's `grant.limits` caps one execution. The companion's `use-policy` caps a count of calls. A budget is a total: 50,000 per call, a hundred times, passed both.
2. **The request named no price.** A payment receipt could say "7,000 for request R" while R itself committed to nothing about money, and the responder's execution receipt could not say what it was paid. The request occurrence has a `task_sha256`; a task object with the price under that digest binds the request to the price without changing the companion's request type.
3. **A payment could not be ordered against the witnessed lane.** The execution receipt names a block the responder had seen; a payment receipt without one could never be shown to come after a budget the witnesses published, so a refused budget could never bind a payment. Every statement that is ordered against the lane carries a seen block.
4. **The payer's lineage was its own word.** The companion's use item carries the chain cA2A verified; a payment naming a lineage of the payer's choosing would escape the budget on its real credential, while the execution, which finds its payment by request and payee, would look paid. The first fix charged the payment to the accepted use's lineage; the review of that showed the use itself could be under a second credential the payer holds (PL22), and that the pair (request, payee) let an outsider's payment stand in for the caller's (PL19). What settles all of it is the request occurrence: it already commits to the caller, the responder and the lineage, so a payment is judged against the request it names, and a payment the relying party cannot match to a request is reported and not counted (PL17, PL19, PL22, PL23).

## 3. Objects

All encoded as in the companion (JCS, Ed25519 hex, strict parsing, exact field sets).

**Task** (hashed, not logged): `type` `musubi.ca2a.task.v0`, `service`, `amount` (non-negative integer), `unit`, `nonce` (hex SHA-256). `task_sha256` is the hex SHA-256 of its JCS bytes; the request occurrence commits to it. The bundle carries `tasks` (up to 1024).

**Budget policy** (logged, or witnessed): `type` `musubi.ca2a.budget-policy.v0`, `credential_digest`, `issuer`, `max_total` (at least 1), `unit`, `signature` by `issuer`. A restriction: the witnessed lane carries it under the companion's rules (PL09, PL10).

**Payment receipt** (logged): `type` `musubi.ca2a.payment-receipt.v0`, `payer`, `payee`, `lineage`, `request_sha256`, `amount` (at least 1), `unit`, `seen_block` {`height`, `hash`}, `rail` {`kind`, `receipt_sha256` or null}, `signature` by `payer`. The rail's own receipt is carried by digest: for x402, the salted commitment receipt; the chain settles the money, this record settles the authorization.

## 4. Settlement

The companion settles the bundle first (profile v0.1, handed this profile's item parsers and its one extra restriction kind for that call only; the companion's own CLI and selftest pass none, so what it says about a bundle never depends on which profiles are loaded). On the entries it accepted, in log order:

**Payments.** A payment's `seen_block` must be in the view (`seen_block_not_in_view`, PL13), below the checkpoint's earliest valid anchor, and not hours after the entry's `logged_at` (`logged_before_seen_block`, PL26). The same bytes logged again are `duplicate_payment` and count nothing (PL06).

The request occurrence the payment names must be supplied; otherwise the payment is `request_unknown`, reported with its amount and not counted (PL23). Its caller, responder and lineage must equal the payment's payer, payee and lineage; otherwise `request_does_not_match_payment`, not counted (PL14, PL17, PL19, PL22). The lineage charged is therefore the request's. It is `lineage_unverified` when no accepted use or supplied chain carries that lineage, and still counted. A second, different payment for the same request and payee is `another_payment_for_request` and counts too: money may have moved twice (PL20). With the task supplied, a payment whose amount or unit is not the task's is `payment_not_for_task`, still counted (PL03).

A counted payment counts for every credential in the request's lineage, under any chain, whoever the payer (PL07). Running totals are kept per credential and unit; a total past 2^53 minus 1 is clamped and marked `total_out_of_range` (PL27).

**Budgets.** A budget counts for a hop when its `credential_digest` is that hop, its `issuer` is that hop's issuer as the verified credential states it (PL08), and it was logged before the payment or witnessed before the payment's seen block under the companion's before/after/unresolved rule (PL09, PL10). In the payment's unit, the smallest `max_total` applies: the first payment that takes the running total above it is `budget_exceeded`, and so is every later one (PL02, PL11). A budget on the hop in another unit is not compared, and the payment says so: `budget_in_other_unit` (PL16, PL21). A witnessed budget whose order is unresolved gives `budget_order_unresolved`.

**Executions.** A request is priced when its task is supplied and its amount is above zero (PL24 is free), or, without a task, when any budget counts on its lineage. A result receipt looks for a counted payment logged before it for its request and responder, by its caller: the first that is the task's price (PL20), else the first at all, with `paid_other_than_task_price` (PL03). The execution row carries the payment's reasons (PL11, PL17). A priced execution with none is `executed_without_payment` (PL04, PL14, PL22, PL23); one whose only budget is unresolved is `payment_requirement_unresolved` (PL25). A counted payment with no result receipt by the checkpoint is `unexecuted` (PL05); a denial after a payment leaves it counted and unexecuted (PL12). No refund is modelled.

The settlement adds `pilot`: the payment rows, the execution rows with their payment, the running totals per credential and unit, and counts.

## 5. What this does not prove

That the rail moved the money (the rail's receipt is a digest); that the task's amount is the price the service advertised; that the work was done; or anything the companion's section 8 and v0.1's section 7 already exclude. It proves who committed to which price, whether the issuer's total was respected in the order the log fixed, and that each payment and execution name the same request.

## 6. Vectors

`python pilot_v0.py --selftest` reruns all 28; `python gen_vectors_pilot_v0.py` rebuilds the file byte for byte (SHA-256 in NOTES.md).

| id | what it shows |
|---|---|
| PL01 | three paid calls at 7,000 under 30,000: every payment counted, every execution paid |
| PL02 | the fifth call takes the total to 35,000: `budget_exceeded`; a per-call cap and a use count would both have passed it |
| PL03, PL15, PL23 | the payment is not the task's price; no task supplied; no request supplied |
| PL04, PL05, PL12, PL24, PL25 | executed without payment; paid and not executed; a denial after a payment; a free call; an unresolved requirement to pay |
| PL06, PL20 | the same bytes again count once; a different payment for the same call counts too |
| PL07, PL17, PL18, PL22 | a sub-delegate's payment counts against the ancestor's budget; a self-declared lineage, or a second credential for the same call, does not match the request and leaves the execution unpaid; a payment before its use counts |
| PL08, PL16, PL21 | a budget by a non-issuer limits nothing; a budget in another unit is not compared and is reported |
| PL09, PL10 | a budget the operator refused still applies through the witnesses; when its order cannot be fixed by blocks, unresolved |
| PL11 | a tighter budget logged between two calls judges only the later one |
| PL13, PL26 | a payment naming an unseen block; one dated hours before its seen block |
| PL14, PL19 | a payment to the wrong responder, which leaves the execution unpaid; an outsider's payment, which neither spends nor consumes the budget |
| PL27, PL28 | totals stay in range; a request with a junk task digest is skipped |
