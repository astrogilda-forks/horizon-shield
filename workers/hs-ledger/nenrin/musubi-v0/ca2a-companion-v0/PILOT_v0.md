# MUSUBI pilot profile v0: a delegated budget, paid calls, and what the receipts prove about each other

Status: draft, revision 0. Reference verifier `pilot_v0.py`, vectors `vectors/vectors_pilot_v0.json` (44). Built on the companion for cA2A, profile v0.1, which is unchanged; a pilot bundle is a v0.1 bundle plus tasks, and the pilot's settlement carries the companion's settlement whole under `companion`.

## 1. The scene

An agent holds a budget its principal delegated. It pays another project's service per call. Every payment is checked against the budget and leaves a signed receipt. Afterwards anyone, holding no key and trusting no server, recomputes whether the money and the actions stayed within what was granted (aeoess/agent-governance-vocabulary#177, 2026-10-18).

## 2. What assembling it found

Each layer below existed before this profile. Putting them together for this one scene showed four things none of them covered.

1. **Nothing summed.** settle v1.12's `grant.limits` caps one execution. The companion's `use-policy` caps a count of calls. A budget is a total: 50,000 per call, a hundred times, passed both.
2. **The request named no price.** A payment receipt could say "7,000 for request R" while R itself committed to nothing about money, and the responder's execution receipt could not say what it was paid. The request occurrence has a `task_sha256`; a task object with the price under that digest binds the request to the price without changing the companion's request type.
3. **A payment could not be ordered against the witnessed lane.** The execution receipt names a block the responder had seen; a payment receipt without one could never be shown to come after a budget the witnesses published, so a refused budget could never bind a payment. Every statement that is ordered against the lane carries a seen block.
5. **Nothing recorded whether the result met what the buyer asked for** (named from outside by babyblueviper1, 2026-10-18). Payer and payee can both be honest and the buyer still got the wrong audit; the record of that, by a key that is neither of theirs, is what a dispute reads first. Section 3 adds the buyer's criteria commitment and the checker's acceptance record, bound to the same request occurrence and to the execution receipt and payment by digest.
4. **The payer's lineage was its own word.** The companion's use item carries the chain cA2A verified; a payment naming a lineage of the payer's choosing would escape the budget on its real credential, while the execution, which finds its payment by request and payee, would look paid. The first fix charged the payment to the accepted use's lineage; the review of that showed the use itself could be under a second credential the payer holds (PL22), and that the pair (request, payee) let an outsider's payment stand in for the caller's (PL19). What settles all of it is the request occurrence: it already commits to the caller, the responder and the lineage, so a payment is judged against the request it names, and a payment the relying party cannot match to a request is reported and not counted (PL17, PL19, PL22, PL23).

## 3. Objects

All encoded as in the companion (JCS, Ed25519 hex, strict parsing, exact field sets).

**Task** (hashed, not logged): `type` `musubi.ca2a.task.v0`, `service`, `amount` (non-negative integer), `unit`, `nonce` (hex SHA-256). `task_sha256` is the hex SHA-256 of its JCS bytes; the request occurrence commits to it. The bundle carries `tasks` (up to 1024).

**Budget policy** (logged, or witnessed): `type` `musubi.ca2a.budget-policy.v0`, `credential_digest`, `issuer`, `max_total` (at least 1), `unit`, `signature` by `issuer`. A restriction: the witnessed lane carries it under the companion's rules (PL09, PL10).

**Criteria commitment** (before the work): `type` `musubi.ca2a.criteria-commitment.v0`, `buyer`, `request_sha256`, `criteria_sha256` (the digest of the criteria document, which stays in its own format), `checker` (the key whose acceptance record will count), `seen_block` (a lower bound on when the buyer wrote it, nothing more), `signature` by `buyer`. A restriction: the witnessed lane carries it, so an operator that sequences it after the receipt, or never logs it, does not unfix it. The buyer fixes two things before the work, what is checked and who checks; a checker that was not named is a key anyone could have made up after seeing the result.

**Acceptance record** (logged, after the work): `type` `musubi.ca2a.acceptance-record.v0`, `checker`, `request_sha256`, `criteria_sha256`, `record_sha256` (the digest of the external record, for invinoveritas the work-acceptance record of x402-foundation/tsc#4 profile 1.2.1), `verdict` (`pass`, `fail` or `not_evaluated`), `execution_receipt_sha256`, `payment_sha256` or null, `seen_block`, `signature` by `checker`. The record itself is not re-verified here; this profile binds it to the call and checks who signed it and when.

**Payment receipt** (logged): `type` `musubi.ca2a.payment-receipt.v0`, `payer`, `payee`, `lineage`, `request_sha256`, `amount` (at least 1), `unit`, `seen_block` {`height`, `hash`}, `rail` {`kind`, `receipt_sha256` or null}, `signature` by `payer`. The rail's own receipt is carried by digest: for x402, the salted commitment receipt; the chain settles the money, this record settles the authorization.

## 4. Settlement

The companion settles the bundle first (profile v0.1, handed this profile's item parsers and its one extra restriction kind for that call only; the companion's own CLI and selftest pass none, so what it says about a bundle never depends on which profiles are loaded). On the entries it accepted, in log order:

**Payments.** A payment's `seen_block` must be in the view (`seen_block_not_in_view`, PL13), below the checkpoint's earliest valid anchor, and not hours after the entry's `logged_at` (`logged_before_seen_block`, PL26). The same bytes logged again are `duplicate_payment` and count nothing (PL06).

The request occurrence the payment names must be supplied; otherwise the payment is `request_unknown`, reported with its amount and not counted (PL23). Its caller, responder and lineage must equal the payment's payer, payee and lineage; otherwise `request_does_not_match_payment`, not counted (PL14, PL17, PL19, PL22). The lineage charged is therefore the request's. It is `lineage_unverified` when no accepted use or supplied chain carries that lineage, and still counted. A second, different payment for the same request and payee is `another_payment_for_request` and counts too: money may have moved twice (PL20). With the task supplied, a payment whose amount or unit is not the task's is `payment_not_for_task`, still counted (PL03).

A counted payment counts for every credential in the request's lineage, under any chain, whoever the payer (PL07). Running totals are kept per credential and unit; a total past 2^53 minus 1 is clamped and marked `total_out_of_range` (PL27).

**Budgets.** A budget counts for a hop when its `credential_digest` is that hop, its `issuer` is that hop's issuer as the verified credential states it (PL08), and it was logged before the payment or witnessed before the payment's seen block under the companion's before/after/unresolved rule (PL09, PL10). In the payment's unit, the smallest `max_total` applies: the first payment that takes the running total above it is `budget_exceeded`, and so is every later one (PL02, PL11). A budget on the hop in another unit is not compared, and the payment says so: `budget_in_other_unit` (PL16, PL21). A witnessed budget whose order is unresolved gives `budget_order_unresolved`.

**Executions.** A request is priced when its task is supplied and its amount is above zero (PL24 is free), or, without a task, when any budget counts on its lineage. A result receipt looks for a counted payment logged before it for its request and responder, by its caller: the first that is the task's price (PL20), else the first at all, with `paid_other_than_task_price` (PL03). The execution row carries the payment's reasons (PL11, PL17). A priced execution with none is `executed_without_payment` (PL04, PL14, PL22, PL23); one whose only budget is unresolved is `payment_requirement_unresolved` (PL25). A counted payment with no result receipt by the checkpoint is `unexecuted` (PL05); a denial after a payment leaves it counted and unexecuted (PL12). No refund is modelled.

**Criteria commitments.** Each commitment, logged or witnessed, is usable when its seen block is in the view and before the anchor, its request is supplied, its buyer is that request's caller (`buyer_is_not_caller`) and its checker is neither the caller nor the responder (`checker_is_party`). A commitment is fixed before an execution receipt when it is logged before the receipt, or witnessed with `order` before the block the receipt had seen (the same ordering as for budgets; PL40 witnessed and never logged, PL41 unresolved).

**Acceptance.** An acceptance counts for an execution only when: its request is supplied; the execution receipt it names by digest is a companion-accepted result receipt for the same request, logged before it (`execution_receipt_not_found`, PL35; `execution_not_a_result`; the same bytes logged twice attach to the first, PL39); its checker is the key the buyer named in a usable commitment to the same criteria for the same request, fixed before that receipt (`criteria_not_committed_by_buyer`, PL33; `checker_not_named_by_buyer`, PL37; `criteria_not_fixed_before_work`, PL32, with `criteria_order_unresolved` when a witnessed commitment cannot be ordered, PL41); its checker is none of the parties: the request's caller and responder, the receipt's signer and caller, the operator, any issuer or subject in a verified chain (`checker_is_party`, PL31, PL38, PL44); and, when it names a payment, that payment is a counted one for the same request and payee, logged before the acceptance (`payment_not_found`; `payment_not_before_acceptance`, PL42), `payment_not_the_executions` being reported when it is not the one the execution row found. One acceptance counts per (execution, criteria, checker); a later one by the same checker for the same criteria is `another_acceptance_for_execution` (PL36). When the buyer committed more than one (criteria, checker) pair for the request, every counted acceptance says `multiple_criteria_commitments` (PL43). The execution row carries `acceptance_seqs` and `accepted`: the verdict when all counted acceptances agree (PL29 pass, PL30 fail, PL34 without a payment digest), `conflicting` when they do not (PL43), null when none counts. Whether the key the buyer named deserves trust is the relying party's reading of the commitment, as for witnesses; the profile only makes sure the choice was made before the result was known.

The settlement adds `pilot`: the payment rows, the execution rows with their payment and acceptance, the criteria commitment rows (logged and witnessed), the acceptance rows, the running totals per credential and unit, and counts.

## 5. What this does not prove

That the rail moved the money (the rail's receipt is a digest); that the task's amount is the price the service advertised; that the work was done; or anything the companion's section 8 and v0.1's section 7 already exclude. It proves who committed to which price, whether the issuer's total was respected in the order the log fixed, and that each payment and execution name the same request.

## 6. Vectors

`python pilot_v0.py --selftest` reruns all 44; `python gen_vectors_pilot_v0.py` rebuilds the file byte for byte (SHA-256 in NOTES.md).

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
| PL29, PL30, PL34 | an accepted call; one the checker rejects; an acceptance that names no payment |
| PL31, PL32, PL33, PL35, PL36 | acceptances that do not count: by the payee, criteria fixed after the work, no criteria committed, naming another call's execution, a second one for the same execution |
| PL37, PL38, PL44 | a puppet checker logged first; the key that signed the receipt as checker; the budget issuer as checker |
| PL39, PL40, PL41, PL42, PL43 | a receipt logged twice; a commitment witnessed and never logged; one whose order is unresolved; a payment logged after the acceptance; two commitments with two checkers |

## 7. Rehearsal

`python pilot_rehearsal.py` writes `rehearsal/`: the cases of Issue #51 (A within, B acceptance fails, C budget exceeded, D the same call content under another request occurrence, whose acceptance does not count) as bundles and settlements, every role played by test keys of this repository, the budget and the criteria commitments carried through the witnessed lane as well as the log, the rail a signed test transfer carried by digest. It is not the run; it is the MUSUBI side of the run with nothing left to invent, and real bytes for the other parties to check the bindings against. `hs-pilot` (workers/hs-pilot) is the responder's service for the run: it checks the same bindings before it audits, and signs the execution receipt this profile reads.
