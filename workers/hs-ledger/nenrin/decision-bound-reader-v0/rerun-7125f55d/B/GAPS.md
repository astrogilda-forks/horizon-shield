# GAPS: where the contract text left this reader guessing

Inputs read: decision_bound.py (as text), jcs.py (as text), the two vector files. Nothing else.

## Contract sentences each verdict rule rests on

- **C1** (decision_id convention): "decision_id is itself SHA-256(JCS(decision_preimage))", together with `ref()` / `decision_id_from_preimage`, which returns `"sha256:" + hex`.
- **C2** (bound output hash): "output_hash = SHA-256(JCS({content_sha256, decision_id, version}))", plus the `bound_output_preimage` docstring: `content_sha256` is BARE hex, `decision_id` carries the `sha256:` prefix, `version` is the constant `"decision-bound-output-v1"`, and the result goes through `ref()` (so it is `sha256:`-prefixed).
- **C3** (recomputation is the check): "An independent verifier ... who has only: the final content (or its hash), the claimed decision_id, the decision's own preimage fields ..., and the recorded output_hash -- can confirm this dependency by recomputation alone."
- **C4** (outcome rule): "A citation is only accepted if, in addition to recomputing, the cited decision's own `outcome` field is `"permit"` ... verify_case() ... returns UNAUTHORIZED_BINDING for exactly this case."
- **C5** (legacy): `legacy_output_hash` = `"sha256:" + content_sha256`, "Used here only to recognize the unverifiable-but-not-tampered case."

| Verdict | Name source | Rule |
|---|---|---|
| ACCEPTED | word "accepted" from C4 | claimed decision_id == ref(preimage) (C1), recorded == bound hash (C2, C3), outcome == "permit" (C4) |
| UNAUTHORIZED_BINDING | verbatim from C4 | C1 and C2 recompute, outcome != "permit" |
| UNVERIFIABLE_LEGACY | my name for C5's "unverifiable-but-not-tampered case" | C1 recomputes, recorded is not the bound hash but equals `"sha256:" + content_sha256` |
| DECISION_ID_MISMATCH | my name | claimed decision_id != ref(decision_preimage) (C1, C3) |
| OUTPUT_HASH_MISMATCH | my name | C1 recomputes, recorded matches neither the bound hash (C2) nor the legacy hash (C5) |

## Gaps

1. **Only two of five verdict names are given by the text.** ACCEPTED (from "accepted") and UNAUTHORIZED_BINDING are the contract's words. The legacy, forged-id and no-match states are described or implied but not named; UNVERIFIABLE_LEGACY, DECISION_ID_MISMATCH and OUTPUT_HASH_MISMATCH are my plain names. Changes labels only, not which cases are grouped together.

2. **Is a claimed decision_id that does not recompute its own failure, and is the bound hash computed from the claimed or the recomputed id?** The text says the verifier holds "the claimed decision_id" and "the decision's own preimage fields" but never says in one sentence "reject if they differ", nor which id goes into the bound hash.
   - Reading A (mine): check claimed == ref(preimage) first (follows from C1 + C3: the dependency is on a decision whose id is a one-way hash of its fields); failure is its own verdict.
   - Reading B: compute the bound hash from the recomputed id only, with no separate id check.
   - Reading C: compute the bound hash from the claimed id only and never recompute the id.
   - Effect: DECISION-BOUND-FORGED-CITATION's recorded hash equals the bound hash of the *claimed* (all-zero) id and not of the recomputed one. Under A it is DECISION_ID_MISMATCH; under B it falls into the same bucket as SUBSTITUTED (OUTPUT_HASH_MISMATCH); under C it would be **ACCEPTED** (outcome is permit). Reading C contradicts C1/C3 so I reject it, but A vs B **does change a verdict label** for this one case. Both values are recorded in the out JSON (`recorded_equals_bound_from_claimed_id`, `..._from_recomputed_id`).

3. **Order of checks when several conditions hold at once.** The text does not order them. My precedence: id mismatch, then bound match (then outcome), then legacy match, then no match. No case in either file has two failing conditions at once (e.g. a forged id together with a legacy hash), so the order changes no verdict here.

4. **Does the outcome rule apply outside a bound match?** C4 qualifies an accepted *citation*. I apply it only after the bound hash recomputes; legacy and mismatch cases are not accepted anyway. No verdict changes.

5. **Outcome values other than "permit"/"deny"/"defer".** C4 is phrased as "only accepted if ... is permit", so any other string (or a missing field) yields UNAUTHORIZED_BINDING. Only "permit" and "deny" occur. No verdict changes.

6. **Is UNVERIFIABLE_LEGACY a pass or a fail?** C5 says "unverifiable-but-not-tampered": not accepted (no binding exists), not flagged as tampered. I report it as its own non-accepting verdict. Whether a caller should treat it as failure is not stated. No verdict changes; it would only matter for an exit code, which I keep at 0 for any completed run.

7. **Shape checks on inputs.** The text says decision_preimage has FIVE named fields and gives prefix conventions (bare hex content, prefixed decision_id), but states no rule to reject a case whose shape differs; it says "do not strip or add prefixes". I record these as informational flags only (all true in both files) and do not derive a verdict from them.

8. **Top-level `profile` and per-case `source` / `synthetic`.** The text says file-level `profile` labels are "never hashed". `source` and `synthetic` are not mentioned at all. I ignore both for verdicts. Note that in the real-run file the `source.approved_request.content_sha256` equals the case's `content_sha256`, but the contract gives no rule linking them, so I do not check it.

9. **Canonical JSON beyond what the vectors exercise.** jcs.py's header says only ASCII string keys/values and plain integers are exercised. I implemented full RFC 8785 behaviour (UTF-16 key order, ECMAScript number form) on my own; with the inputs present, floats and non-ASCII never occur, so this changes nothing.

10. **No expected verdicts in the vectors.** Neither file carries an expected result per case, so this reader cannot report agreement or disagreement with the authors; it reports only its own verdicts. Case ids (e.g. "FORGED-CITATION", "LEGACY", "DENIED") hint at intent but are not treated as rules.

11. **References outside the fence.** The text points to verify_decision_bound.py (verify_case), ../verify.py, ../build_vectors.py, PROVENANCE.md and docs/spec/execution-join-ref-v1.md. None were read. The only verdict name taken from one of these references is UNAUTHORIZED_BINDING, which the contract quotes directly. Observation only: decision_bound.py is exactly 8192 bytes; its content ends cleanly after `legacy_output_hash`, so I read it as complete.
