# GAPS: where the contract left the reader guessing

Fence read: decision_bound.py, vectors_decision_bound_real_run.json, jcs.py. Nothing else.

## Interpretation gaps

1. Decision preimage field set.
   Text: "decision_id is a one-way hash of the decision's own fields (action_ref, policy_id, outcome, ts_ms ...)".
   The record's decision_preimage also has `canonicalization_profile_id`. The field list lives in an external spec ("docs/spec/execution-join-ref-v1.md in argentum-core") not in the fence.
   Assumed: hash the preimage object exactly as recorded, all keys. No schema check.
   Other reading: hashing only the four named fields would give a different decision_id and the case would FAIL. A strict schema reading (reject unknown fields) would also FAIL. Verdict changes under either.

2. Which decision_id is folded into the bound hash.
   Text: "folds the covering decision's own decision_id into the output commitment"; code `bound_output_hash(content_sha256, decision_id)` takes it as an argument.
   Assumed: fold the RECOMPUTED decision_id, and separately require it to equal the stated one. Here they are equal, so no verdict change on this record. On a record whose stated decision_id is wrong but self-consistent with the bound hash, the readings would diverge (mine says FAIL_DECISION_ID).

3. Prefix convention inside the bound preimage.
   Text: `output_hash = SHA-256(JCS({content_sha256, decision_id, version}))`; `ref()` returns "sha256:" + hex.
   Not stated whether content_sha256 is bare hex or "sha256:"-prefixed inside the preimage, nor whether decision_id is prefixed there.
   Assumed (from the code shape and the record): content_sha256 bare hex, decision_id prefixed. The record reproduces only under this reading; the reader also tries the other two and reports none match. Another reading changes the verdict to FAIL.

4. Canonical form for non-integers.
   jcs.py says "Only the parts exercised by execution-join-ref-v1 preimages (ASCII string keys/values, plain integers, no floats) are used".
   Assumed: integers, strings, bools, null, objects, arrays only; floats refused. No effect on this record (ts_ms is an integer).

5. "Satisfies the binding property" vs what can be recomputed.
   Text: a verifier has "the final content (or its hash)". The record carries only the hash, not the bytes.
   Assumed: content_sha256 taken as given. A reading that demands the bytes would make every case in this file unverifiable (no verdict possible), not FAIL.

6. Verdict vocabulary.
   The contract names only one non-success state: "the unverifiable-but-not-tampered case" (legacy shape). It defines no verdict strings.
   Assumed: BOUND, UNBOUND_LEGACY_ONLY, FAIL_DECISION_ID, FAIL_BINDING (my own labels).

7. Role of `source` and `note` fields.
   Not covered by the contract. Checked as informational only (approved_request.content_sha256 equals content_sha256; policy_id equals grant_profile + "/" + execution_digest; ts_ms equals grant_issued_at_iso). All equal; they do not feed the verdict. Treating them as required would not change this verdict.

8. `version` string.
   Taken from the code constant VERSION = "decision-bound-output-v1". The record does not carry it; the file's `profile` is "decision-bound-output-v1-real-run", which I did not use. Using the profile string instead would FAIL.

## The mechanism's own declared limits (its words)

- "It does not prove WHEN the decision was made in wall-clock time"; "'Before' here means 'logically / causally prior'".
- "It does not prevent the dispatcher from fabricating BOTH the decision and the bound output at the same time, after the fact"; "it proves dependency, not elapsed time". Independent anchoring is "not built here".
- "It says nothing about whether decision_id is used ONCE or re-used"; replay guard "not designed or built here".
- "It requires the decision's own preimage fields to be available to the verifier from SOME separate channel"; it does not define "how a verifier comes to trust that the cited decision record is the complete, unaltered one".

## Gaps specific to this record

- The decision_preimage comes from the same file as the output hash, not a separate channel, so the fourth limit is fully in force here.
- The record's own note says decision_bound_output_hash is "this session's overlay", computed after the fact over retained values. So the "decision came first" property here is only the hash dependency; nothing in the record shows the bound hash was produced at write time.
