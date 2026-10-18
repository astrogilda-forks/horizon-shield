# Notes: MUSUBI companion for cA2A, profile v0

## Running it

    pip install ca2a-runtime==0.4.0     # brings rfc8785 and cryptography; Python 3.11 or later
    python companion_v0.py --selftest   # 57/57 vectors agree
    python gen_vectors.py               # rebuilds vectors/vectors.json byte for byte
    python companion_v0_1.py --selftest # 33/33 (profile v0.1, the witnessed lane; see COMPANION_v0_1.md)
    python gen_vectors_v0_1.py          # rebuilds vectors/vectors_v0_1.json, then the surrogate checks

The verifier imports `settle_v1_1.py` from the directory above for the Bitcoin header view and the anchor proof, unchanged.

One import is private: the at-execution verdict calls cA2A's `_check_revocation` directly, so that every revocation the log published before a receipt is in force whatever its `issued_at` (CA45). A private function can change without notice, so the profile is pinned to ca2a-runtime 0.4.0 until cA2A offers a public way to say "these statements are in force".

Checked against both cA2A sources on 2026-10-17: agentrust-io/ca2a at 305fedc (editable install) and the PyPI release ca2a-runtime 0.4.0. Both give 57/57.

## Why a companion and not a fork

cA2A's delegation rules are theirs to change. If this profile reimplemented them, every cA2A release could silently split the two. So `settle` only ever asks `ca2a_runtime.delegation.verify_chain` and reports its error code as is (`outside_delegation:SCOPE_ESCALATION` and so on). What this profile adds is ordering, publication, and signed statements that live outside one process.

## Decisions taken in v0

- **Two verdicts on revocation.** cA2A's audit mode goes by the revoker's `issued_at`. The log knows when the statement became public. Both are reported (`ca2a_at_execution`, `ca2a_audit`); a revocation that only the audit sees is `late_revocation_only`, not hidden either way.
- **A revocation dated after its logging is kept and flagged, never dropped, and in force from its log position.** Dropping it let the operator void a valid revocation by logging it a few seconds early (CA33); leaving it to cA2A's `at_time` filter let it lose to its own date (CA45). The at-execution verdict goes by log order; the audit verdict by `issued_at` is reported beside it.
- **Use items carry their whole chain and name their responder.** A use of a credential is a (request, responder) pair under any chain that contains it, so delegating onward, re-issuing an ancestor or fanning one request out to several responders does not reset a limit (CA32, CA43, CA44, CA35).
- **Limits come only from the hop's own issuer, only when logged before the receipt, tightest wins.** Revocation in cA2A is monotonic; a limit behaves the same way.
- **One use per distinct request.** Logging the same use twice is a retry, not a second use.
- **Denials are not executions** for deduplication.
- **Unknown lineage is unassessed.** No chain, no verdict.
- **The evidence functions verify the entries against the checkpoint first.** Otherwise whoever supplies the entries decides the verdict (EV06 to EV10).
- **A receipt names a block it has seen.** That is the only lower bound on time that the operator does not set.
- **The log is a hash chain in v0.** A verifier reads the whole log. Merkle proofs and witnesses are v1.

## Review record

2026-10-17, first round: an adversarial review of the first draft (36 vectors) reported 4 high, 3 medium and 4 low findings. All were fixed; each is a vector (CA32 to CA42, EV06 to EV10).

2026-10-17, second round: 2 high, 2 medium and 2 low. A single-use credential could still run once per responder, and a re-issued ancestor started a fresh count (now counted per credential, at any position, per request and responder: CA43, CA44). A revocation logged early lost to its own later issued_at (now in force by log order, cA2A's audit verdict beside it: CA45). A short checkpoint could hide a promised entry (now operator_withheld: EV11). Use ranks are computed once (1,000 uses and 1,000 receipts settle in about 3 s). Deep nesting is an input error (EV12).

vectors/vectors.json sha256: 4b4e2362ab6dda3743e5ba1cd76285a0872344f40086bc95b18b3bd34490d2a2 (57 vectors).

## Profile v0.1: the witnessed lane (2026-10-18)

v0 could prove that the operator dropped an entry it had signed, not that it refused one. v0.1 (`COMPANION_v0_1.md`, `companion_v0_1.py`) lets revocations and use limits take effect through threshold many independent witnesses, ordered against receipts by Bitcoin blocks, with omission by the operator reported from signatures. v0 is unchanged apart from two hardening fixes below; a v0.1 bundle with no witnessed records settles exactly as v0 on all 45 v0 settlement vectors.

2026-10-18, third round (adversarial review of v0.1 before publishing): 3 high, 1 medium, 3 low.
- The lower bound on publication was taken only from acknowledgements with a deep anchor, so a witness whose acknowledgement was anchored slowly, or a shorter view, turned a possible revocation into a definite absence and a `within` verdict (fixed: the signature and the seen block give the lower bound, the anchor only the upper one; WV31, WV32, and WV10 and WV21 now give unresolved).
- The omission finding compared the checkpoint's anchor height, which anyone can raise by anchoring the signed checkpoint again (fixed: the rule is on the checkpoint's own `as_of` against the due block's time; WV29, WV30; the test chain now spaces blocks ten minutes apart so this can be shown).
- Nothing bound the bundle to what the witnesses published (spec: the verdict is relative to the relying party's own collection, section 7; the settlement names the witnesses counted).
- A lone UTF-16 surrogate in an unsigned request or credential raised out of `settle` in v0 and v0.1 (fixed in v0's `strict_value`, shared: `lone_surrogate`; and `--settle` now refuses an unreadable file with a code instead of a traceback).
- One signed acknowledgement could be repeated 16,384 times with different anchors, each proof run before failing (fixed: a signed acknowledgement is checked once, 512 acknowledgements per bundle; WV33).
- Threshold honesty was described in one direction only (spec section 7 now covers witnesses that sign junk, and a threshold of 1).
- The v0.1 vector digest was not recorded here (below).

2026-10-18, fourth round (adversarial review of the fixes): 2 high, 2 medium, 7 low.
- The one-check rule from the third round was first-copy-wins on the signature, so an unanchored copy of an acknowledgement listed before its anchored copy removed the upper bound, and the verdict depended on the order of honestly collected copies (fixed: identical bytes are checked once, anything else on its own; WV34).
- An acknowledgement whose `signature` was a list or an object raised out of `settle` at that same check (fixed; WV35).
- A seen block the view could not check discarded the whole acknowledgement, anchor included, so two honest witnesses naming a block below the relying party's lower bound made a published revocation vanish (fixed: the lower and the upper bound are counted on their own; WV36, WV11).
- Anyone holding the operator's signed checkpoint could anchor it again later and turn an honest responder's `after` into unresolved (fixed: `log.extra_anchors`, the earliest valid anchor bounds the receipts; WV37).
- Low: a restriction anchored in the block the responder then names is before the receipt (spec: fix S first); the omission rule is on exact bytes (spec: log what the witnesses publish); a view ending before the due block reported nothing (now `omission_check: due_block_not_in_view`, WV38); `revocation_published_late` is not listed beside `revocation_order_unresolved` (information only, unchanged); `--settle` exit codes were inconsistent (now 0, 2, 3 in both profiles); the module docstring still gave the anchor-height rule (fixed); cost is quadratic in receipts and revocations (spec section 7).

vectors/vectors_v0_1.json sha256: 9b4e83e9c1484ce100de67c50f3220aacfb330415393d1d6b48696a64dcda046 (38 vectors).

`witness_ack.py` (2026-10-18): the whole of a witness in one file, keygen, digest, sign, check; the acknowledgement it signs is what `companion_v0_1._ack` reads. Independent witness operators are sought in horizon-shield Issue #50.

## Pilot profile v0: a delegated budget and paid calls (2026-10-18)

`PILOT_v0.md`, `pilot_v0.py`, 28 vectors. Built on v0.1 for the scene aeoess proposed on agent-governance-vocabulary#177 (an agent with a delegated budget paying another project's service per call). Assembling it found four gaps the layers below did not cover (PILOT_v0.md section 2); the companion gained a way to hand a built-on profile its item parsers and restriction kinds for one call (`parse_item(item, extensions)`, `companion_v0_1.settle(bundle, extensions, restrictions)`), with no change to what v0 or v0.1 say on their own.

2026-10-18, fifth round (adversarial review of the pilot before publishing): 3 high, 4 medium, 5 low. The budget could be dodged by a use under a second credential for the same request, by a unit spelled differently, and by a 1 JPY payment logged before the real one; an outsider's or the payee's own payment stood in for the caller's; a supplied request with a list for `task_sha256` raised; two payments of 2^53 minus 1 made the settlement unserialisable; importing the pilot changed what v0.1 said about a bundle; a zero-price task under a budget could never settle clean; an unresolved witnessed budget did not price a call; an execution row hid its payment's problems; a payment dated hours before its seen block passed. All fixed by judging a payment against the request occurrence it names (PL17, PL19, PL20, PL21, PL22, PL23, PL24, PL25, PL26, PL27, PL28) and by passing extensions instead of registering them.

Acceptance (2026-10-18, afternoon): the fifth gap, named by babyblueviper1 on #177: nothing recorded whether the result met what the buyer asked for, by a party that is neither payer nor payee. Two items (criteria commitment before the work, acceptance record after it, both bound to the request occurrence and the latter to the execution receipt and payment by digest), eight vectors (PL29 to PL36), then eight more after review (PL37 to PL44), the rehearsal of Issue #51's three cases (`pilot_rehearsal.py`, `rehearsal/`), and the responder's worker (`workers/hs-pilot`).

2026-10-18, sixth round (adversarial review of the acceptance step): 1 high, 3 medium, 4 low, 2 information.
- "Neither caller nor responder" was the only identity test and the first counted record per execution won, so any party could make a fresh key, sign pass, and get it logged before the real checker's fail (fixed: the buyer's criteria commitment names the checker key before the work and only that key's record counts; first-wins is gone, one record counts per execution, criteria and checker; PL37). The same answer babyblueviper1 gave on #51 the same hour: the checker key is published before the first call and used for nothing else.
- The party test looked at the supplied request only, so the key that signed the receipt, when it was not the request's responder, could accept its own work (fixed: the receipt's signer and caller, the operator, and every issuer and subject in a verified chain are parties; PL38, PL44).
- The receipt digest table was last-wins, so the same receipt logged twice sent the acceptance to the duplicate (fixed: first logged; PL39).
- The commitment was ordered by log sequence only, so an operator could sequence it after the receipt or drop it, and its seen block was shape-checked and never used (fixed: a commitment is a restriction the witnessed lane carries, ordered against the receipt's seen block like a budget; its own seen block is checked against the view and is only a lower bound on when the buyer wrote it; PL40, PL41).
- Low: a payment logged after the acceptance counted (now `payment_not_before_acceptance`, PL42); the acceptance's payment need not be the execution's (reported as `payment_not_the_executions`); result receipts with different bytes for one request are separate executions with separate acceptance slots (unchanged, each is one statement by the responder); the module docstring said the payment was required (fixed).
- Information: a buyer may commit two criteria sets with two checkers (now reported, `multiple_criteria_commitments`, and `accepted` is `conflicting` when the verdicts differ; PL43); the rehearsal index showed the third execution of case C without its payment's `budget_exceeded` (fixed).

vectors/vectors_pilot_v0.json sha256: ff86a70389574fa851884112d01fed1c7bbcff96adc58638379f6c71fe27d0bc (44 vectors).
