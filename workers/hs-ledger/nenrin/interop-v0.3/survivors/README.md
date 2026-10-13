# interop-v0.3/survivors: the vectors that kill the faults the older corpora let survive

Nine provenance bundles, each with the verdict signature (VERIFIER.md section 4: verdict, sorted refusal codes,
sorted finding codes) a conforming verifier must return. TSUNAGI name: `nenrin-interop-v0.3-survivors`.

## Where they come from

The adequacy-v0 measurement (`../../conformance-v0/adequacy-v0/REPORT.md`, `report.json`) took 13 declared faults
(one exact text substitution each in the Python port, `mutations.json`) and asked which of them any frozen fixture
notices. With the 93 fixtures of interop-v0, interop-v0.1, interop-v0.2/edge, interop-v0.2/action-presence and
conformance-v0/pinned, 5 of 13 were killed; F7 was silent (only a reason moved) and seven survived. The measurement
proposed one small vector per survivor in `../../conformance-v0/adequacy-v0/proposed_vectors/`. This directory
freezes those proposals:

- `fixtures/*.json` are the proposal files copied byte for byte (same names, same sha256, listed in `SHA256SUMS`).
  They were not regenerated for the copy. The generator stays where it is
  (`../../conformance-v0/adequacy-v0/proposed_vectors/make_proposed_vectors.py`); its keys come from public labels
  (sha256 of a label is the Ed25519 seed) and Ed25519 is deterministic, so running it again writes the same bytes.
  No key material is stored. The keys are test keys and protect nothing.
- `expected.json` carries the proposals' cases unchanged (intent, targets, task_id, expect); only the header changed
  from PROPOSAL to a frozen corpus. `targets` names the faults of `mutations.json` the vector kills. It is not part
  of the signature.
- `task_id` inside the fixtures still reads `task_adequacy_proposal`: changing it would change the signed bytes.

Why the name: interop-v0.1 extended interop-v0, and interop-v0.2 holds corpora written against the section 5
rules (edge, action-presence). These nine come from a different source, a mutation-adequacy measurement, and test
steps 2a, 2b and 2d plus the window and timestamp rules, so they open v0.3 instead of joining a v0.2 directory that
was about section 5. `survivors` says what they are for: the faults that survived the older corpora.

## The vectors

Each is a validly signed grant and receipt (no observations, no intent) changed in one place from `p00_base`. All
findings are evidence_bound_unchecked and no_delegation_observations.

| Vector | Changed | Expected (conforming) | Kills | The fault it closes |
|---|---|---|---|---|
| p00_base | nothing | accepted | none | the clean pair the others change in one place: pins that the unchanged pair is accepted, so a refusal elsewhere comes from the one change |
| p01_caller_sig_bit_flipped | one bit of caller_sig, still canonical base64 | refused: execution_signature_invalid | F1 | `verify_grant_sig` returning true (grant signature not checked) |
| p02_grant_signed_by_provider_key | the grant is signed by the provider, not by grant.caller_id | refused: execution_signature_invalid | F1, F3 | a pair signature accepted under the key of any party of the pair |
| p03_grant_ref_not_recomputing | grant.grant_ref altered (outside the signed preimage) | refused: execution_invalid, execution_unreconciled | F6a | grant_ref not recomputed (under the fault only execution_unreconciled remains) |
| p04_receipt_id_not_recomputing | receipt.receipt_id altered (outside the signed preimage) | refused: execution_invalid, execution_unreconciled | F6b | receipt_id not recomputed |
| p05_receipt_names_other_grant | a validly signed receipt names another grant_ref | refused: execution_invalid, execution_unreconciled | F6c | the receipt.grant_ref binding not checked |
| p06_hour_24_inside_window | executed_at 2026-10-03T24:00:00Z | refused: execution_invalid | F7 | the strict RFC3339 UTC check removed (Date.parse reads hour 24 as the next midnight, inside the window) |
| p07_executed_after_not_after | executed_at one second after not_after | refused: execution_invalid | F4, F4b | the window check removed, or its not_after bound ignored |
| p08_receipt_from_unauthorized_provider | the receipt is validly signed by a provider other than grant.provider_id | refused: execution_invalid, execution_unreconciled | F10 | executor authorization (E3) not checked |

In p03, p04, p05 and p08 the reconciliation step (2d) refuses on its own for the same receipt, so the fault is
killed through the pair check's code (execution_invalid disappears), not through the verdict. That code is part of
the pinned signature.

## What was checked before freezing

- The JS reference (`node run_survivors.mjs`, `sdk/nenrin_verify.mjs`), the Python port (`provenance.py`, through
  `nenrin-tsunagi` and pytest) and the Go port (`go test ./...` in `../../sdk-go`, and
  `nenrin-verify-go --corpus ../interop-v0.3/survivors`) each give 9/9 of these signatures. The verifiers were not
  changed for this corpus.
- `run_adequacy.py --no-tool` (its own cross check, offline) with `("interop-v0.3-survivors",
  "interop-v0.3/survivors")` appended to its `CORPORA` list in memory (the script is left as it was measured): 13 of
  13 declared faults killed, both controls hold, the unmutated port reproduces all 102 expected signatures. Without
  this corpus: 5 of 13. corpus-adequacy itself was not rerun for the freeze; with the same nine vectors added as
  proposals it gave 13 of 13 (`tool_report_with_proposals.v0.json`).

## How to read this (the claim ceiling)

- These vectors kill the faults declared in `mutations.json`, nothing more. Those faults were written by the same
  side that wrote the corpora; a rule nobody declared is invisible to this measurement.
- A kill does not prove a verifier correct. It shows that one fixture's outcome moves under one substitution. A
  different way of getting the same rule wrong may still pass every frozen vector.
- The faults were applied to the Python port. That the same vectors separate the same faults in other
  implementations is likely (they pin the outcome of a rule, not of a code path) but was not measured.

## Run

    node run_survivors.mjs                                              # the JS reference
    npx nenrin-tsunagi run nenrin-interop-v0.3-survivors -- "<your verifier> {in} {out}"
    nenrin-tsunagi run nenrin-interop-v0.3-survivors -- "<your verifier> {in} {out}"   # PyPI nenrin-verify
    (cd ../../sdk-go && go run ./cmd/nenrin-verify-go --corpus ../interop-v0.3/survivors)
    sha256sum -c SHA256SUMS
