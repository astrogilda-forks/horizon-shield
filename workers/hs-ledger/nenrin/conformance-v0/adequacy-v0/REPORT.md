# adequacy-v0: can the NENRIN corpora tell a wrong verifier apart?

Measured 2026-10-13 on horizon-shield `ff59188726319b8a3c00ff8cbf3892ffa1589bdd`. Nothing in the frozen corpora was changed. Everything here can be rerun:

    python3 run_adequacy.py --tool /path/to/corpus-adequacy

## What was measured

The frozen corpora say which verdict signature (verdict, sorted refusal codes, sorted finding codes, VERIFIER.md section 4) each fixture must produce. A verifier that reproduces all of them is called conforming. This run asks the reverse question: if a verifier leaves out one rule on purpose, does any frozen fixture notice?

- Checker: the Python port, `sdk-python/src/nenrin_verify/provenance.py` (sha256 `9bcf6dfd0c534124c955b507eecc32ba14dbac2e59ce47a257cc2c54d473bb8b`, identical to the commit above), driven through `verify_bundle` exactly as `nenrin-verify bundle.json` does, by `verdict_signature.py`.
- Corpora (93 fixtures, every one with an expected signature): interop-v0 (5), interop-v0.1 (13), interop-v0.2/edge (36), interop-v0.2/action-presence (9), conformance-v0/pinned (30). The four interop corpora are byte for byte the ones vendored in `sdk/tsunagi_corpora.json`. Every file's sha256 is in `report.json`.
- Not measured: `gen_edge_bundles.mjs` (fresh keys each run, judged only by difference between verifiers, no frozen expectation), `strict_rules.test.mjs` (assertions on the JS reference, not a corpus), and the TRACE corpora in `tsunagi_corpora.json` (a different checker).
- Faults: 13 declared substitutions in `mutations.json` (F1 to F10, F6 split into three, and F4b, a refinement of F4), plus two controls. Each is one exact text replacement in one function; the anchor occurs exactly once in the file.
- Tool: corpus-adequacy 0.8.0, `github.com/corpus-adequacy/corpus-adequacy` at `4c075bbe59b4f93107804d9b29fe8bef49a11b57` (source state `exact`, content `sha256:2843097d6728e86c8b9d0f57b634d97b957652a084fd942637eb970d85f9cb6d`), the tool Rul1an described in aeoess/agent-governance-vocabulary#177. It was found and run as published, not reimplemented. Process runner, one child per fixture, outcome = the verdict signature, diagnostic channel = the refusal reasons. The exact manifest it measured is `corpus_adequacy.manifest.json`; its output is `tool_report.v0.json`.

Order of the run, each step a gate for the next:

1. The unmutated checker reproduces all 93 expected signatures, and the 6 reasons interop-v0.1 records for readers. (The tool compares every mutant with this baseline, so after this step "moved" means "differs from expected".)
2. Positive control (every refusal dropped, verdict always accepted): killed, 63 fixtures moved. Inert control (`s.encode("utf-8")` written as `bytes(s, "utf-8")` in `sha256hex`, which runs on every fixture): nothing moved. Both controls hold, so the run has a score.
3. corpus-adequacy measured every fault. `run_adequacy.py` applied the same substitutions itself, compared each result with `expected.json` directly and named the fixtures that moved (the tool reports counts, not ids). The tool and this cross check agree on all 15 rows, including the moved counts.

## Result

5 of 13 declared faults killed (corpus-adequacy: score 38.5, adequate false, control_status killed, unproved 0).

| Fault | Declared change (function) | Result | Frozen fixtures that kill it |
|---|---|---|---|
| F1 grant signature check removed | `verify_grant_sig` returns True | survived | none |
| F2 receipt signature check removed | `verify_receipt_sig` returns True | killed | interop-v0.1/linkage_unreconciled, interop-v0.1/provider_sig_invalid, edge/require_signatures_zero, edge/sig_missing_padding, edge/sig_urlsafe_alphabet, edge/sig_whitespace, edge/sig_trailing_newline, edge/sig_noncanonical_trailing_bits, edge/key_identity_small_order, edge/key_identity_noncanonical_signbit, edge/key_order8_small_order, edge/key_mixed_order |
| F3 wrong key accepted | `verify_signed_execution` accepts a pair signature that verifies under the key of any party of the pair | survived | none |
| F4 validity window check removed | `_in_window` returns True | killed | pinned/s04_window_inverted (only) |
| F4b not_after bound ignored | `_in_window` drops `t > not_after` | survived | none |
| F5 action match removed | E1 test in `verify_execution` becomes `if False` | killed | action-presence/action_null, action_zero, action_empty_string, action_false, action_missing, intent_action_null, intent_action_zero, intent_action_missing; pinned/s10_raction_nfd_vs_nfc |
| F6a grant_ref recompute removed | first check of `verify_execution` | survived | none |
| F6b receipt_id recompute removed | `receipt_recompute_ok` test in `verify_execution` | survived | none |
| F6c receipt.grant_ref binding removed | `receipt_binds_grant` test in `verify_execution` | survived | none |
| F7 strict RFC3339 UTC check removed | `_timestamps_ok` returns True | silent (a survivor) | none; 8 fixtures move only their reason |
| F8 incomplete pair accepted | the `execution_incomplete_pair` refusal is dropped | killed | interop-v0.1/incomplete_pair, edge/receipts_element_not_object, edge/grant_key_not_object, pinned/s01_open_grant_intent_only |
| F9 action_binding comparison removed | the digest test in `check_action_binding` | killed | pinned/s03_abind_upper_grant, s03_abind_upper_receipt, s03_abind_upper_intent |
| F10 executor authorization (E3) removed | `provider_authorized` returns True | survived | none |

(edge = interop-v0.2/edge, pinned = conformance-v0/pinned.) The exact anchors and replacements are in `mutations.json` and repeated per row in `report.json`.

Notes on what the kills rest on:

- F2 is killed by one tampered provider_sig (interop-v0.1/provider_sig_invalid), one receipt not signed by the authorized provider (linkage_unreconciled), and otherwise by encoding and key-validity cases.
- F4 rests on a single fixture, which tests the not_before side only; F4b shows the not_after side is not tested.
- F5 is killed by degenerate actions and by one real divergence (NFD versus NFC). No frozen fixture has a receipt whose action differs from the grant's in an ordinary way, but s10 is enough to force the comparison.
- args_sha256 has no check of its own: it is a member of the action and is compared only inside E1 (F5) and inside the action_binding digest (F9).

## How to read this (the claim ceiling)

- A survivor means only this: the frozen corpora cannot tell that fault apart from the conforming verifier. A second implementation could have that fault and still pass every frozen vector. It does not mean the reference verifier is wrong. The reference implements all these rules; the gap is in what the corpora force.
- A kill does not prove correctness. It shows that one fixture's outcome moved under that one substitution. A different way of getting the same rule wrong may survive (F4 is killed, F4b, a smaller version of the same fault, is not).
- 100% here would be 100% of the 13 faults declared in `mutations.json`, written by the same side that wrote the corpora. Rules nobody declared are invisible to this measurement.
- The result belongs to the checker that was mutated. F7 is silent on the Python port because its `date_parse` only reads strings the strict rule already admits, so a timestamp the strict check would refuse is still refused by the window check with the same code. The same fault in the JS reference is killed by interop-v0.1/non_utc_timestamp, edge/ts_lowercase_tz and edge/ts_offset, because V8's `Date.parse` reads those strings as instants inside the window (side probe, `js_probe_F7` in `report.json`; it disables only the step 2a check in a temporary copy of `sdk/nenrin_verify.mjs`). The JS reference was not otherwise mutated.
- Reasons are not part of the verdict signature and no corpus makes them normative (interop-v0.1 records 6 for readers). F7 moves the recorded reason of interop-v0.1/non_utc_timestamp (invalid_timestamp becomes outside_authorization_window); a consumer comparing reasons would catch it, the pinned outcome does not.

## Survivors, and the smallest vector that would kill each

Frozen on 2026-10-13 as `../../interop-v0.3/survivors/` (TSUNAGI `nenrin-interop-v0.3-survivors`; fixtures copied byte for byte, nothing here changed) in the commit that adds that directory; with it among the frozen corpora, `run_adequacy.py --no-tool` kills 13 of 13.

These are proposals in `proposed_vectors/`, not part of any frozen corpus. Each is a validly signed grant and receipt (no observations, no intent), changed in one place from `p00_base`. Keys come from public labels at run time (`make_proposed_vectors.py`); no key material is stored. The intended signature was written from VERIFIER.md before running anything.

| Survivor | Proposed vector | Intended outcome (unmutated) | Under the fault |
|---|---|---|---|
| F1 | p01_caller_sig_bit_flipped: one bit of caller_sig flipped, still canonical base64 | refused: execution_signature_invalid | accepted |
| F3 (and F1) | p02_grant_signed_by_provider_key: the grant signed with the provider's key | refused: execution_signature_invalid | accepted |
| F6a | p03_grant_ref_not_recomputing: grant.grant_ref altered (outside the signed preimage); the receipt names the recomputed id | refused: execution_invalid, execution_unreconciled | refused: execution_unreconciled only |
| F6b | p04_receipt_id_not_recomputing: receipt.receipt_id altered (outside the signed preimage) | refused: execution_invalid, execution_unreconciled | refused: execution_unreconciled only |
| F6c | p05_receipt_names_other_grant: a validly signed receipt whose grant_ref names another grant | refused: execution_invalid, execution_unreconciled | refused: execution_unreconciled only |
| F7 | p06_hour_24_inside_window: executed_at 2026-10-03T24:00:00Z, which Date.parse reads as not_before | refused: execution_invalid | accepted |
| F4b (and F4) | p07_executed_after_not_after: executed_at one second after not_after | refused: execution_invalid | accepted |
| F10 | p08_receipt_from_unauthorized_provider: a validly signed receipt from a provider other than grant.provider_id | refused: execution_invalid, execution_unreconciled | refused: execution_unreconciled only |

All findings are evidence_bound_unchecked and no_delegation_observations; p00_base is accepted with those two.

Verified, all of it in `report.json` under `proposed_vectors`:

- the unmutated Python port gives the intended signature on all 9;
- the published JS reference (`sdk/nenrin_verify.mjs`, through node) gives the same 9 signatures;
- each vector kills every fault it targets (p02 also kills F1, p07 also kills F4), and no vector kills any other fault;
- corpus-adequacy run again with the 9 proposals added to the 93 frozen fixtures: 13 of 13 killed, score 100.0, adequate true, controls hold (`tool_report_with_proposals.v0.json`).

Four of the eight proposals (p03, p04, p05 and p08) refuse with two codes where the fault leaves one: the reconciliation step (2d) refuses on its own for the same receipt, so a vector of this kind kills the fault through the pair check's code (execution_invalid), not through the verdict. That is still an outcome the corpora pin.

## Files

- `mutations.json`: the declared faults and controls (file, function, rule, anchor, replacement).
- `verdict_signature.py`: the checker adapter the tool runs (one bundle in, its verdict signature and reasons out).
- `run_adequacy.py`: the runner (pins, baseline gate, staging, the tool, the cross check, proposals, JS probe).
- `corpus_adequacy.manifest.json`: the manifest bytes corpus-adequacy measured.
- `tool_report.v0.json`, `tool_report_with_proposals.v0.json`: the tool's own output (they carry the temporary path of the staged manifest).
- `report.json`: pins, controls, per-fault results with killing fixture ids, the JS probe, proposal verification.
- `proposed_vectors/`: `make_proposed_vectors.py`, `expected.json` (marked PROPOSAL), `fixtures/`.
