# Notes on settle core v0

What a second implementer could read two ways, what the reference does that looks like a defect, and what I could not pin down.
Each item says what the reference does (checked by running it, not by reading alone), why it matters, and which vector pins it, if any.
SETTLE_CORE_v0.md points here by number.

All findings were first checked against settle_v1_10.py. settle_v1_16.py was then written to close them without editing any earlier layer, and SETTLE_CORE_v0.md now describes v1.16. Each item below starts with its status under v1.16.

Two independent adversarial reviews of v1.16 (2026-10-17) then attacked it as a third party holding copies of genuine records, the contract and the walks. The first found six holes (binding by label in triage; unsigned copies reaching the copy collapse; unsigned records counting toward the record limit; an unsigned copy standing in for a good one; about 70 inputs that raised an exception; output depending on key order). All six are closed and pinned by self test check [10] and the vectors `synth_unsigned_copies_anchored_first` and `synth_earlier_terms_record_bad_anchor`. The second review re-ran every proof of concept and both fuzzers against the fixed code (0 crash sites, no verdict or bond change) and found two more: a cited walk that is not strict was left out silently (now `walk_not_strict`, vector `synth_cited_walk_not_strict`), and one record with an integer too long to digest stopped the whole settlement (now set aside on its own).

## Most important first

The four items most likely to split two honest implementations, or to be abused, are N2, N10, N1 and N6.

## N1. A trailing line feed passes five checks (`$` instead of `\Z`)

Status: closed in v1.16 (strict forms, SETTLE_CORE 6.0 and 5.1 rule 9).

Several patterns in the settle layers end with `$`. In Python, `$` also matches just before a final `\n`, so `"abc...\n"` passes `^[0-9a-f]{64}$`. contract_v0.py uses `\Z` and is strict; settle_v1_1.py and settle_v1_4.py are not.

| value | pattern (file) | what happens next | vector |
|---|---|---|---|
| `anchor.block_hash` | `HEX64` (settle_v1_1) | accepted as well formed, then differs from the view's hash: orphaned (excluded, within_grant). A strict reader says anchor_incomplete (no verdict) | real_p31_block_hash_trailing_newline |
| proof operand `hex` | `HEXOPS` (settle_v1_1) | `bytes.fromhex` skips whitespace, so the newline vanishes and the proof verifies | real_p31_proof_operand_trailing_newline |
| header `hex` | inline regex (settle_v1_1.verify_view) | same, the header decodes as if the newline were absent | none |
| action name | `ACTION_RE` (settle_v1_4) | the record conforms; `"delete\n"` is not `"delete"`, so it is unauthorized, not prohibited. A strict reader adds nonconforming_record | synth_action_name_trailing_newline |
| approval nonce | `HEX32` (settle_v1_4) | the approval is counted (the signature covers the newline) | synth_approval_nonce_trailing_newline |

Also affected, without a vector: `lower_bound.hash` (harmless, the later equality fails anyway), grant action names in check_terms (a grant naming `"read\n"` passes), and the operands read by the batch leg rule (anchor_compose uses `bytes.fromhex` too).

A JavaScript reader using `/^...$/` without the `m` flag does NOT accept a trailing newline, and `Buffer.from(x, "hex")` stops at the first non-hex character instead of skipping it. So a straightforward JS port disagrees on all four vectors above.

Recommendation for v1 of the spec: switch these patterns to `\Z` (or `fullmatch`) and refuse whitespace in hex. Until then, the vectors pin the reference.

## N2. The NENRIN cross check reads records that failed authentication

Status: closed in v1.16. Records that are not strictly signed never reach any check; v1.15 is rerun without anything it rejects.

`settle_v1_7.py` line 268 calls `v15._nenrin_deviations(used, ...)` where `used` is every bound record after duplicate collapse, not the accepted ones. So an unsigned, unanchored record that merely carries this contract's `contract_ref` (contract_id, contract_sha256 and payload_digest are all public) and a `nenrin_ref` pointing at a walk whose `context.contract_sha256` names other terms produces `evidence_names_other_contract`. The verdict becomes deviation and a bond is forfeited, although the record is listed as rejected in the same settlement.

Vector synth_nenrin_check_reads_rejected_record pins it (an honest record plus an unsigned one).

Who can do it: anyone who can get a walk record into the settler's `nenrin_records` input. How likely that is depends on how a settler collects walks (for example, fetching every walk cited by any record it was handed). This reads like a defect, not a design: every other rule runs over accepted records only, and the layer that introduced the check (settle_v1_5) passed `used` when `used` was already the bound set. Suggested fix: run the check over accepted executions only. A second implementer must decide whether to copy it; the vector says the reference does.

## N10. Copies that differ only in their `signatures` list are different bodies

Status: closed in v1.15 (copies of one signed body collapse), kept in v1.16.

Duplicate collapse (6.4) groups by body digest, and the body digest is sha256 of the record without `anchor`, which still includes `signatures`. The signers sign the record without both. So anyone holding a record can append a junk entry to `signatures` (it is skipped by authentication, the genuine entry still verifies) and keep the genuine anchor. The copy is a second body; its proof starts from a different digest and fails; the settlement is underspecified (anchor_proof_invalid). Anyone holding one record can block every verdict on the contract.

Vector real_p31_copy_with_junk_signature_entry pins it. settle_v1_15.py was written for exactly this (its docstring cites an independent review on 2026-10-10) and gives within_grant on that vector. So core v0, defined as settle_v1_10, contains a known and fixed defect. If the project wants core v0 to be "v1.15 minus the gates", the scope in section 1 should change and this vector's expectation with it.

## N6. Two inputs crash the reference

Status: closed in v1.16. Both inputs give a settlement; no JSON-shaped input raises.

1. A grant with no `revocation` object, plus one accepted, principal-signed revocation: `TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'` at settle_v1_7.py line 196 (`h + window`). The contract door allows a grant without `revocation`, and check_terms does not require it, so this is a valid contract. The principal can make settlement impossible to compute for such a contract.
2. An accepted execution whose `delegated_to` contains an object: `TypeError: unhashable type: 'dict'` at line 265. Only the contractor or a named witness can sign such a record.

Neither can be a vector (there is no answer to expect). SETTLE_CORE_v0.md 10.1 says case 1 is undefined. Case 2 falls under N3.

## N3. Fields that are read but never type checked

Status: closed in v1.16 (6.0).

Conformance (6.6) checks `performed_actions` and `outcomes` but not:

- `delegated_to`: a string is iterated character by character. `"ab"` gives two delegation deviations, observed `a` and `b`. An object inside the list crashes (N6). A JS port iterating a string gets the same characters for ASCII, but differs for characters outside the BMP (UTF-16 units vs code points).
- `approvals`: an object instead of a list is iterated by its keys. Each key is a string, not an object, so each becomes a forged_approval with observed null.
- `nenrin_ref`, `contract_ref` contents: any type; nested objects may carry any keys, including non-ASCII keys. Canonical key order is by code point in Python and by UTF-16 unit in a naive JS sort; they differ above U+FFFF. The contract door refuses such keys in the contract, but nothing refuses them in records, so record_sha256 and the body digest can differ between runtimes.

A second implementer has to choose. The safest reading of the spec is: reproduce the iteration behaviour for strings and objects as described, and treat a crash input as out of scope.

## N4. Numbers in records, views and batches

Status: closed in v1.16 for records, views and walks. Batches inside proofs are still parsed as the lower layers do.

The contract door refuses floats and unsafe integers in the contract. Nothing refuses them elsewhere, and the Python reader is lenient:

- `json.loads` accepts the tokens `NaN`, `Infinity` and `-Infinity`. JSON.parse rejects them.
- A height written `970480.0` is a Python float: no height, anchor_incomplete. A JS reader sees the integer 970480 and accepts the anchor. The same split applies to header heights in the view (Python: chain_view_rejected), `valid_until_height` and `expiry_height` in records.
- Canonical form writes a Python float with `repr` (`1.0`, `1e+16`); JS writes `1` and `10000000000000000`. Any float inside a record changes its record_sha256 and body digest by runtime, so a proof valid in one fails in the other.
- Integers above 2^53 are exact in Python and rounded in JS.
- In the batch leg rule, `count` is compared with Python `!=`, so `"count": true` equals 1 record and `"count": 1.0` equals 1.

SETTLE_CORE_v0.md 2.2 says inputs carrying such numbers are not defined by core v0. A stricter rule (refuse any record with a non-integer or unsafe number, as the contract door does) would be easy to state for v1.

## N5. Ordering and approval semantics that are easy to get wrong

Status: unchanged. These are semantics, not defects; SETTLE_CORE section 13 lists them.

Checked by running the reference on extra inputs (not all are vectors):

- The set of consumed single use nonces is global, not per action. An approval for `refund` and an approval for `pay_out` that happen to share a nonce: the second is reported approval_reused. Not a vector.
- `requires` in a conditional entry is not read. `{"action": "refund"}` with no `requires` still needs a counted principal approval (the earlier settle_v1.py skipped the check when `requires` was empty). Not a vector.
- A conditional action does not need to be in `authorized_actions`; an approved conditional action is never reported unauthorized. An action that is both conditional and prohibited is prohibited (the door only refuses authorized and prohibited overlapping). Not a vector.
- An expired action is still checked against the other rules, so an expired prohibited act gives two codes. Not a vector, but the rule is short (10.2).
- delivery_ack: an acknowledgement anchored before its revocation (it can name the revocation's body digest before the revocation is anchored) sets the end of authority at the acknowledgement's height, so an act between the two anchors is revoked. Arguably right (the contractor acknowledged), but surprising. Not a vector.
- An approval carried by a record in the same block as the act never counts, even if the record's sha256 sorts first. Vector synth_conditional_approval_same_block_other_record.
- Which of two same-block executions consumes a single use approval depends on record_sha256 order. The deviation codes do not change; which record gets the deviation does (informative).

## N7. Collapse can keep a copy that predates the checkpoint

Status: harmless under v1.16. A kept copy below the checkpoint makes the settlement underspecified (anchor_below_lower_bound), and a third party cannot reach that rule while the genuine anchor verifies.

Duplicate collapse keeps the earliest copy whose anchor verifies, without comparing its height with the checkpoint. A kept copy below the checkpoint is then excluded as predates_contract, and the honest later copy has been dropped. I believe this is unreachable: a record body contains contract_sha256, which commits to the checkpoint hash, so no block at or below the checkpoint can commit to it. A second implementer who adds the comparison will not disagree on any reachable input. Not a vector.

## N8. Bond outcome uses Python truthiness

Status: closed in v1.16 (bond_malformed).

`bond.amount` decides between `n/a` and the other outcomes by truthiness. Python treats `[]`, `{}` and `0.0` as false; JavaScript treats `[]` and `{}` as true. The door does not type check `bond`. Every vector uses either `null` or an integer amount.

## N9. Ed25519 libraries differ on adversarial signatures

Status: closed in v1.16. Only strict signatures count (S below L, R of prime order).

The reference checks the public key itself (canonical encoding, not identity, prime order subgroup) and then calls OpenSSL through the `cryptography` package (50.0.1 here). Libraries differ on signatures crafted against the equation: non-canonical S, small order R, cofactored versus cofactorless verification. Honest signatures verify everywhere. No vector covers adversarial signatures, and I did not test which of these OpenSSL refuses in this version. A follow-up could add vectors from the published Ed25519 edge case sets (for example the "Taming the many EdDSAs" cases) with the reference's answers.

## N11. Other things a reader could take two ways

Status: closed in v1.16 (anchor_below_lower_bound, parent checks, evidence_missing, nothing_to_settle).

- The contract door refuses a contract when any signature entry fails, even if the same party also has a good one (4.1 rule 15). A reader who only asks "did each party sign" accepts it.
- `parent_contract` is not checked during settle: the door only records a finding when no parent is supplied. A delegated child contract settles without its narrowing check.
- `requirements.evidence: "nenrin_required"` (both real contracts carry it) is not read by any settle layer. A settlement without any walk is still final.
- A record whose anchor claims a height below the checkpoint is excluded silently (predates_contract) before its block hash or proof is checked; a claim above the tip makes the whole settlement underspecified. The two are asymmetric: an anchor's claim, which anyone can edit, decides whether a record is dropped quietly or blocks a verdict. Vector real_p31_anchor_below_checkpoint.
- An orphaned record is excluded, but its claimed height still counts for status (8.5).
- Any authenticated, conforming record without a usable anchor makes the whole settlement underspecified (anchor_incomplete). A party can delay a verdict by handing the settler such a record. That is a liveness property of the design, stated here so nobody reads "underspecified" as "the terms are bad".
- Typed batches cannot list revocations or acknowledgements (no kind in anchor_compose.RECORD_KIND), so a revocation anchored through a nenrin-agreement-batch-v1 is refused (anchor_batch_leg_refused) and blocks the verdict.
- In the batch leg rule the raw sha string must be written without escapes; a batch that writes `0` for `0` is refused with the code `internal`.
- With an empty event set and no orphan, the verdict is within_grant and the status final. Vectors real_cross_record_names_other_contract and synth_exec_signed_by_stranger. A reader who expects "nothing to settle" to be its own outcome will disagree.

## N12. Command line versus library

settle_v1_10.py's command line runs fork choice (`compare_views_v1_4`) before settling. For a view that does not verify, it prints `{"fork_choice": ...}`, writes no settlement, and exits 2. The library returns an underspecified settlement with chain_view_rejected. The vectors use the library; run_reference.py calls it directly. The fork choice also refuses a view over 200000 headers before settle sees it.

## N13. Which key carries an approval's signature

Status: closed in revision 0.1 of SETTLE_CORE_v0.md. The reference did not change.

Found by the first separately written implementation (aeoess/musubi-settle-core-check at 7f9a224, horizon-shield Issue #49), which read 6.0's "`sig_b64` (or `signature`)" as two names for one field and accepted `signature` as a fallback in 10.4 too. The reference verifies only `sig_b64` (settle_v1_6 and every layer above it), and its strictness triage (settle_v1_16 body_problem) checks both keys, each on its own. Run on three new vectors, the two readings disagree on two:

- an approval with a valid signature only under `signature`: the reference gives `forged_approval` and `conditional`; the fallback reading gives `within_grant`.
- a strict `sig_b64` beside a malleated `signature`: the reference gives `record_not_strict`; the fallback reading checks only the key it uses and gives `within_grant`.

Both disagreements were in the text, not in that implementation. 6.0 and 10.4 now say what the reference does. Vectors synth_approval_signature_key_only, synth_approval_lax_signature_beside_good_sig_b64 and synth_approval_signature_key_same_value (control).

## N14. Twenty-five implementation notes, answered by the reference

Status: closed in revision 0.2 of SETTLE_CORE_v0.md. The reference did not change.

The same implementation (aeoess/musubi-settle-core-check at 7f9a224) recorded 25 places where the text left it a choice (impl/AMBIGUITIES.md, A1 to A25). Each was settled by building an input with gen_vectors.py and running the reference and that implementation side by side, or, where no input could isolate it, by reading the reference. The answers were posted in horizon-shield Issue #49.

- The implementation's reading was the reference's: A2, A4, A5, A8, A11, A13, A17, A18, A19, A23, A25 (A9 was N13).
- The reference did something the text did not say: A1 (contract_sha256 of a contract that is not an object is null), A3 (an integer over 4300 digits stops the reader), A6 (all whitespace is stripped from a domain), A7 (`delegation: {}` refuses, `ordering: {}` does not), A12 and A15 (`NaN` is a number), A16 (`view_not_strict` needs an object view with a headers list), A20 (what "carries" means), A22 (a copy dropped by 6.4 no longer names its revocation). The last one the text had stated wrongly: it described settle v1.4's intent, which v1.15's collapse of signed bodies changed before v1.4 runs.
- The text matched the reference but no vector showed it: A14, A21. Each now has one.
- A24 cannot apply once 4.1 accepts.
- A10: the text left `grant_subset` to the reference. 4.3.1 now states it, and 25 vectors change one axis each against a parent that sets every axis. Two consequences a reader is unlikely to guess: a child must take at most the parent's `max_hops` minus 1, so a child that copies its parent's grant is not within it when the parent has `max_hops`; and an `ordering` of `{"same_height": null}` counts as set and must be copied.

Before release, 4.3.1 was implemented once more from the text alone, by a reader that saw only 4.3.1, 4.1 rule 10 and 5.2 and none of the code. It agreed with all 27 parent vectors. Its recorded guesses (a child without `requires`, a child without `ack_window`, a child without `max_target_bits`, how witness keys and `ordering` values are compared) were not contradicted by any vector, so each is now written out in 4.3.1.

One practical trap found on the way: that implementation calls `sys.set_int_max_str_digits(0)` when it is imported, which lifts the limit of A3 for every module in the same Python process, the reference included. Run the two in separate processes.

## N15. Ten more implementation notes, answered by the reference

Status: closed in revision 0.3 of SETTLE_CORE_v0.md. The reference did not change.

The same implementation, updated to revision 0.2 (aeoess/musubi-settle-core-check at 4ca508f), agrees with all 117 vectors on the eight core fields with no UNASSESSED field. Its new notes (impl/AMBIGUITIES.md, B1 to B10) were each settled by a probe through the reference and the implementation side by side.

- The implementation's reading was the reference's: B1 (the 4300 digit limit counts digits, not the sign), B3 (`delegation: {"allowed": null}` refuses), B4 (`requires` compared by exact equality, `""` is not null), B9 (strip, then lowercase, then trailing dots), B10 (`{}` is not `{"same_height": null}`).
- B6 (a revocation is named by the copies kept by 6.0 and not dropped by 6.4, itself included) agrees with every vector, including `synth_ack_names_dropped_copy`, but no vector has a copy set aside in 6.0 or rejected in 6.6 naming a revocation, so that part is not separated yet.
- B2 and B8: its spellings were the reference's (`NaN`, `Infinity`, `-Infinity`; `nan` and `+Infinity` stop the reader; `1e400` is an infinity). N4 said floats are written with Python `repr`; that is true of finite floats only. 3.1 now has item 6, and the two infinities have vectors.
- B7: the reference refuses any `approvers` value that is not a well formed list, so `{}`, `""` and `0` refuse in 4.1 rather than making the input out of scope. 4.1 rule 10 now states what well formed means.
- B5: rule 14 is not empty in core v0. A parent may pin approvers; a child without them fails narrowing (the reference compares the two lists as sets of canonical entries, absent as empty). A child with them is out of scope.

## N16. Revision 0.3 rerun: 123 of 123

The same implementation, updated to revision 0.3 (aeoess/musubi-settle-core-check at c0f8f4f), agrees with all 123 vectors on the eight core fields with no UNASSESSED field; the 117 earlier outputs are unchanged, and a fresh-clone rerun reproduced everything byte for byte (horizon-shield Issue #49).

One more note (C3): rule 14 compares canonical approver entries, so the order of `actions` inside an entry matters, and no vector shows it. The reference does exactly that (contract_v0.grant_subset sorts the entries, not the arrays inside them). A child that keeps pinned approvers is out of scope in core v0, so no core input reaches it; 4.3.1 now says so in one sentence. No vector and no code changed.

## N17. Which reasons the vectors actually produce (revision 0.4)

Status: closed in revision 0.4 of SETTLE_CORE_v0.md. The reference did not change.

Prompted by draft-he-agentproto-verifier-evidence-00 (EXR-1 and EXR-2: a rejecting path counts as exercised only when an identified input drove it), the expected results of the 123 vectors were counted against Appendix A. All ten deviation codes are produced by at least one vector. Of the 28 underspecified reasons, 18 were and 10 were not. Each of the ten was then driven through the reference:

- Reachable, no vector: `grant_action_name_invalid`, `too_many_witnesses`, `ack_window_missing`, `finality_policy_missing`. Five vectors added (`synth_witnesses_32` pins the boundary beside 33). The 123 earlier vectors are byte for byte unchanged; 128 in all.
- Reachable, not through the vector layout: `input_not_settleable` (events not a list) and `input_too_large` (more than 10000 records). `exercise_inputs.py` drives them in memory and keeps its lines in `EXERCISE.txt`. Driving them showed that 10001 copies of one record do not trigger the limit: identical bytes are merged first (6.3), which 6.2 did not say. It says so now. The headers branch of `input_too_large` (more than 200000 verified headers) is still not exercised.
- Unreachable: `authorized_actions_missing`, `witness_key_invalid`, `revocation_policy_not_recomputable`, `bad_expiry_height`. Each 4.2 row describes an input that 4.1 rules 9 or 10 already refuse, and 4.2 applies only after 4.1 accepts. `exercise_inputs.py` D1 to D6 run those inputs and get `contract_not_verified`. The rows stay, so that no code changes meaning, and 4.2 and Appendix A now say they cannot fire.

Every unexercised path was on the refusal side. A verifier that never returns `underspecified` for a malformed policy goes on to compute a verdict it has no basis for, so these paths are the ones worth pinning.

## N18. Two wrong statements about the reference (revision 0.5)

Status: closed in revision 0.5 of SETTLE_CORE_v0.md. No rule, reason or vector changed.

Found while carrying revision 0.4 into draft-oga-musubi-settlement-01:

- Section 16 gave agreement_verify.py as `72990326ac4a0a65`. That is the copy vendored into sdk-python. settle_v1_16.py imports `agreement-v0/agreement_verify.py`, whose sha256 begins `fd8c34ce8a11cf42` (the same at 4100d52a and dd64d0e2). The other prefixes match what the reference loads.
- Section 12 said settle_v1_15.py gives the same core fields on every vector section 13 does not list. Run over the 128 vectors of revision 0.4 (called as `settle_v1_15(contract, events, view, nenrin_records=...)`, core fields as in `run_reference.core_fields`, dispositions set aside), v1.15 differs on 51 and raises on 3 (`synth_delegated_to_object` TypeError, `synth_revocation_irrevocable_grant` TypeError, `synth_contract_not_object` AttributeError). 23 of the 51 are not named anywhere in the specification, for example `synth_exec_signed_by_stranger`, `synth_payload_digest_mismatch`, `real_cross_record_names_other_contract`. The sentence now says only that earlier layers do not agree. The bullet on v1.15 under "What I could not pin down" below was written for the vectors of the first draft.

## N19. Revision 0.4 rerun by its author: 128 of 128

The same implementation, updated to revision 0.4 (`dd64d0e2`) by its author (aeoess/musubi-settle-core-check at [53cfafb](https://github.com/aeoess/musubi-settle-core-check/tree/53cfafb4460c06060d44cd7423ace06cc0196dd3)), agrees with all 128 vectors on the eight core fields with no UNASSESSED field. The 123 earlier outputs are byte identical (their vector directories and `inputs/` at the same Git tree hashes as at `aea731eb`), the four newly covered reasons appear in the expected cases, and none of the four reasons revision 0.4 calls unreachable is emitted. Outputs are frozen in `out/FROZEN-r04.txt` (horizon-shield Issue #49).

Two limits, as he stated them: the run is not blind to the new cases, since he read the comment describing them first, and APS is a party to `real_p31_baseline`. We have not rerun it at 53cfafb ourselves. Revision 0.5 (`c2904fa2`) changed no rule, reason or vector, so the result stands for 0.5.

## What I could not pin down

- Whether the project intends core v0 to follow settle_v1_10 or the latest layer. On the vectors, v1.11 to v1.14 give identical core fields; v1.15 differs on one vector (N10) and reports a dropped copy under `signed_body_collapse` instead of `duplicate_anchorings`, which changes the dispositions projection for real_p31_two_anchorings_one_body only.
- Ed25519 edge case behaviour of the installed OpenSSL (N9).
- Behaviour for inputs that crash the reference (N6), and for records with floats or unsafe integers (N4). The spec leaves them undefined rather than guess.
- run0002: settlement_walk2.json names a2a-settlement-v1.6 and settle_v1_6.py reproduces it byte for byte (sha256 11c27fcf...). settle_v1_10 on the same inputs differs only in schema, settled_under, anchor_rule, establishes and the three gate fields. So run0002 is a core v0 vector (real_r2_baseline) but its published settlement file is a v1.6 file, not a v1.10 file.
