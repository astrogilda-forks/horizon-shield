# GAPS: decision-bound-output-v1, blind second reading

Sources read: decision_bound.py (docstrings and comments as spec), jcs.py (docstring: RFC 8785), the two vector files. Nothing else.

## A. Points where I had to guess, or two careful readers could differ

1. **Order between the bound check and the legacy check.**
   Text: "in the check order above, `FORGED_DECISION_CITATION` ... comes first, then `UNAUTHORIZED_BINDING` ..., then `COMMITMENT_AFTER_DECISION` ..., then, for a recorded output hash that matches neither the bound nor the legacy form, `BINDING_MISMATCH` ... A recorded output hash that matches the UNBOUND legacy form exactly ... is `ORDERING_UNVERIFIABLE`."
   The legacy result is described after the list, outside the stated order. I check bound first, then legacy. This only changes a verdict if `"sha256:" + content_sha256` equals the bound hash (practically impossible, but a reader that checks legacy first would give `ORDERING_UNVERIFIABLE` on such a collision).

2. **Legacy recorded hash with a citation that does not recompute.**
   Text: "a verifier MUST compare the claimed `decision_id` against the id recomputed from `decision_preimage` FIRST, before doing anything with the output hash." versus "`ORDERING_UNVERIFIABLE` -- not a failure, just a write that never used this mechanism."
   A write that "never used this mechanism" arguably has no citation to forge. I follow the MUST: forged citation wins, so legacy + bad citation = `FORGED_DECISION_CITATION`. Another reader could put the legacy test first. No vector exercises this.

3. **Outcome not `"permit"` when the bound hash does NOT match.**
   Text: "A citation is only accepted if, in addition to recomputing, the cited decision's own `outcome` field is `"permit"`" versus the code list, which defines `UNAUTHORIZED_BINDING` as "citation recomputes, bound hash matches, but `outcome` is not `"permit"`".
   The first sentence could be read as an acceptance test applied right after the citation check (deny + legacy, or deny + mismatch, would then become `UNAUTHORIZED_BINDING`). I follow the code-list definition: outcome is read only after a bound match. So deny + legacy = `ORDERING_UNVERIFIABLE`, deny + neither = `BINDING_MISMATCH`. No vector exercises this.

4. **What "permit" means exactly.** Text quotes `"permit"`. I compare exact, case-sensitive string equality; a missing `outcome` key, `"Permit"`, `" permit"` or a non-string all count as "not permit". Not stated.

5. **Shape of `decision_preimage`.** Text: "decision_preimage has FIVE: action_ref, canonicalization_profile_id, outcome, policy_id, ts_ms -- all five are hashed". It does not say whether a preimage with a sixth field, a missing field, or wrong value types is rejected, or just hashed as given. I hash whatever object is given and do not gate on shape; out.json reports `preimage_has_exactly_the_five_named_fields` (true for all 8 cases). A stricter reader could reject or name a new outcome.

6. **Malformed input.** The contract names no outcome for a case that lacks a required field. Name `MALFORMED_INPUT` is my own choice. Also my own choices: duplicate JSON keys, NaN/Infinity literals, duplicate `case_id`, empty `case_id`, or non-string hash fields make the input malformed (exit 2). Which fields are "required" (`case_id`, `claimed_decision_id`, `content_sha256`, `decision_preimage`, `recorded_output_hash`) I took from the vectors, not from the text.

7. **Format of hash strings.** Text: "`content_sha256` is BARE hex ... `decision_id` already carries the `sha256:` prefix ... Pass each argument exactly as its own producer gives it -- do not strip or add prefixes here." It does not say whether a verifier should validate hex length or case, or normalize case before comparing. I do no validation and compare exact strings. An uppercase-hex `recorded_output_hash` would be `BINDING_MISMATCH` for me; a normalizing reader could say otherwise. A prefixed `content_sha256` is passed through as given (per the quoted sentence), which yields a different bound hash and a `"sha256:sha256:..."` legacy form.

8. **Canonical form beyond the vectors.** jcs.py docstring: "Only the parts exercised by execution-join-ref-v1 preimages (ASCII string keys/values, plain integers, no floats) are used here". RFC 8785 treats every number as an IEEE-754 double, so integers above 2^53 serialize as rounded doubles. I followed RFC 8785 (e.g. 9007199254740993 -> "9007199254740992"). A reader who prints integers verbatim would hash differently for such values. All `ts_ms` in the vectors are about 1.7e12, so no effect here. Lone surrogates: I reject as malformed (RFC 8785 requires I-JSON); not stated in the text.

9. **Fields the mechanism does not read.** Text: "`verify_case()` still returns `COMMITMENT_AFTER_DECISION` for it today, because nothing in this mechanism reads that field." I read none of `prior_unbound_commitment`, `source`, `synthetic`. A cautious reader might cross-check `source.approved_request.content_sha256` against `content_sha256`, or `source.execution_digest` against the suffix of `policy_id` (both agree in the real-run file), or flag `prior_unbound_commitment.recorded_before_bound_commitment: true`. The text does not ask for any of this; I list these names under `fields_present_but_not_read` in out.json only.

10. **File-level `profile` label.** Text: "those are human-readable labels for a FILE, never hashed". It does not say whether a verifier should refuse a file whose `profile` is unexpected (e.g. `"decision-bound-output-v1-real-run"`). I do not gate on it; it is echoed in out.json.

11. **Is `ORDERING_UNVERIFIABLE` a pass or a fail?** Text: "not a failure". It is also not an acceptance. My SUMMARY only counts verdicts and does not sort them into pass/fail.

## B. Settled by the text without a guess

- A check order is prescribed (CHECK ORDER paragraph): citation first; on mismatch `FORGED_DECISION_CITATION`, "full stop, never reached by constructing the bound hash at all" (out.json shows `bound_output_hash: null` for that case).
- All five result names and their conditions for the cases where a bound hash matches or where the citation fails.
- `decision_id = "sha256:" + hex(SHA-256(JCS(decision_preimage)))`, with the `sha256:` prefix.
- `bound_output_hash = "sha256:" + hex(SHA-256(JCS({content_sha256, decision_id, version})))`, `version` = `"decision-bound-output-v1"`, `content_sha256` bare hex, `decision_id` prefixed.
- `legacy_output_hash = "sha256:" + content_sha256`.
- `profile` labels are never hashed.
- Outcome must be `"permit"` for `COMMITMENT_AFTER_DECISION`; `"deny"` and `"defer"` named explicitly as not permitting.
- KNOWN-LIMITATION-COMMITMENT-NOT-WRITE is stated to return `COMMITMENT_AFTER_DECISION`; my reader agrees.
- Canonical form = RFC 8785: UTF-16 code-unit key order, ECMAScript number formatting, minimal string escaping, UTF-8 output.

## C. Observations from recomputation (not guesses)

- DECISION-BOUND-FORGED-CITATION: its `recorded_output_hash` equals the bound hash computed with the claimed all-zero id. A verifier that tested only the bound hash under the claimed id would accept it; the citation-first order catches it.
- DECISION-BOUND-SUBSTITUTED: citation recomputes; recorded hash matches neither bound nor legacy form.
- DECISION-BOUND-DENIED: citation recomputes against the `"deny"` preimage (its own id), bound hash matches, outcome `"deny"`.
