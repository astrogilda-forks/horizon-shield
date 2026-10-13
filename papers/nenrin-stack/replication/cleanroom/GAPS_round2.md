# GAPS: clean-room implementation of nenrin-provenance-verify-v0 from the spec text

Implementer inputs: specs/VERIFIER.md (normative), delegation_SPEC.md, execution_SPEC.md, PROVENANCE.md,
canonical_vectors.json, and the 18 fixture bundles. Nothing else was read. Implementation: impl/verify.py
(guesses are tagged GUESS-n in the code). Output: impl/out.json.

Summary
- canonical(): 9/9 vectors pass (sha256 and byte length). The vectors are positive cases only.
- 18/18 bundles produce a signature. I could NOT compare them with the expected answers, because
  VERIFIER.md section header says a conforming verifier "reproduces every verdict signature in
  ../interop-v0/expected.json and ../interop-v0.1/expected.json" and neither file was provided (gap A1).
- I found no remaining ambiguity in VERIFIER.md that, read the other way, changes one of the 18 signatures,
  except where prose in another spec contradicts VERIFIER.md and only the precedence clause decides (A2 to A4).
- Category (b) is long: the procedure is complete for well-formed, honestly typed records, but it is silent on
  record shape, JSON lexical form, null versus absent, and parser/regex/base64 flavour. Because every id and
  signature covers the whole record, a signer can produce a fully valid (hash-recomputing, signature-verifying)
  record with any of these oddities, so these are reachable by a real bundle, not only by tampering.

---------------------------------------------------------------------------------------------------------

## (a) Gaps that change, or could change, a verdict signature on these 18 bundles

A1. The expected answers are not in the corpus.
- Text (VERIFIER.md, intro): "A conforming verifier follows it in order and reproduces every verdict signature
  in ../interop-v0/expected.json and ../interop-v0.1/expected.json."
- Neither file was supplied. Conformance can only be claimed against my own reading. Other files named but not
  supplied: ../musubi-v0/canonical_vectors.json (I assumed it is specs/canonical_vectors.json), strict_json.mjs,
  bind.mjs, compose.test.mjs, sign_exec_adversarial, outcome_evidence.mjs, preflight.mjs, CONSUME.md,
  boundary_case.test.mjs. None of them is needed by VERIFIER.md's procedure except strict_json.mjs (see B1, B2).
- Effect: unknown for all 18.

A2. Evidence target when nothing reconciles: PROVENANCE.md contradicts VERIFIER.md.
- VERIFIER.md step 4: "The target is the reconciled receipt; if none, the primary receipt ... This step runs
  even when step 2 refused, which is why a refused bundle can carry evidence_bound_unchecked."
- PROVENANCE.md findings: "evidence_bound_unchecked: the reconciled receipt carries outcome.evidence, ..." and
  "no_evidence_bound: the reconciled receipt carries no evidence pointer".
- Guess: VERIFIER.md ("Where this file and prose elsewhere differ, this file is the contract").
- Alternative reading (PROVENANCE literal: no reconciled receipt, no evidence finding) changes 2 signatures:
  v0/equivocation and v01/provider_sig_invalid would lose evidence_bound_unchecked.

A3. open_grant / self_authorized conditions: PROVENANCE.md definitions are unconditional, VERIFIER.md makes
  them conditional on the pair check passing.
- VERIFIER.md 2a: "If all of these pass: add finding open_grant if grant.provider_id is null, and finding
  self_authorized if ...".
- PROVENANCE.md: "self_authorized: the grant's caller_id equals its provider_id ..." with no condition.
- Guess: VERIFIER.md. On the corpus only v01/self_authorized has caller_id == provider_id and its pair check
  passes, so no signature here changes; it would change any bundle where a self-authorized or open grant meets
  a failing receipt (category b, listed here because the two texts directly conflict).

A4. Closed traps (explicit in VERIFIER.md now, but contradicted or unstated elsewhere). Listed because a reader
  who follows the prose specs instead of VERIFIER.md gets a different signature on the corpus.
- "Failing observations are NOT removed: R3, R4 and linkage below run over every presented observation."
  The other reading (drop invalid observations first) changes v0/forged_signature and v01/witness_is_party:
  the only link sits on the invalid seq 0 observation, so both would gain no_digest_link, and dropping seq 0
  would also add delegation_chain_broken (seq_gap).
- Step 2d defines "authentic" without requiring the pair check of 2a to pass. execution_SPEC.md E2
  ("one distinct receipt_id reconciles") does not say either way. Requiring a passing pair check would change
  v01/non_utc_timestamp (adds execution_unreconciled; linkage then not evaluated).
- delegation_SPEC.md R4 "fail-closed" versus VERIFIER.md "R4 never refuses": v0/disagreement must be accepted.
- None of these is a guess for me; they are noted as the places a second implementer is most likely to diverge.

---------------------------------------------------------------------------------------------------------

## (b) Gaps that would change a verdict on a plausible bundle not in this corpus

### JSON input and canonical form

B1. Number lexical form versus value (GUESS-1).
- VERIFIER.md 2: "an integer in [-(2^53-1), 2^53-1] as its shortest decimal form (no leading zeros, no plus
  sign, no fraction, no exponent; negative zero is written 0). Any other number is refused".
- Silent on whether "1.0", "1e2", "-0.0", "100E0" in the JSON text are integers. A JavaScript JSON.parse cannot
  tell 1.0 from 1, so a JS verifier canonicalizes them as "1"; a Python json.loads yields a float. delegation_SPEC
  hints at a lexical pre-check ("Refusals, before anything is hashed (strict_json.mjs ...)") but the file is not
  provided. Guess: any number token with a fraction or exponent is non_integer_number (lexical refusal), so the
  record fails its recompute check. The other reading accepts and hashes it as an integer. Verdict flips
  between refused (delegation_observation_invalid / execution_invalid / preflight_invalid) and accepted.
- Also: "negative zero is written 0" only makes sense for a value model (JS -0); in a lexical model "-0" is an
  integer token, "-0.0" is not. The vectors contain no such case.

B2. Duplicate keys, bad JSON, NaN/Infinity (GUESS-2).
- delegation_SPEC.md: "duplicate_key (the same key twice in one object at any depth; neither first-wins nor
  last-wins is a result) ... A record that fails one of these has no evidence_id".
- VERIFIER.md lists only "non_integer_number, unsafe_number" and "key_not_printable_ascii" as canonical refusals
  and never says how the bundle is parsed. Python and JS parsers silently take the last duplicate.
- Guess: a duplicate inside a record makes that record uncanonicalizable (recompute fails). Undefined: a
  duplicate at bundle level (e.g. two "grant" keys), malformed JSON, and Python's default acceptance of
  NaN/Infinity tokens (I reject them as bad_json). VERIFIER.md has no code or verdict for an unparseable bundle.
  Readings: refuse the whole bundle (no code exists for it), last-wins, or fail the containing record.

B3. Lone surrogates and refusal vectors are untested.
- VERIFIER.md 2: "A lone surrogate is written as \udxxx with lowercase hex". No vector covers it, nor any
  refusal (unsafe_number, non_integer_number, key_not_printable_ascii, duplicate_key). Implementations that
  encode with a strict UTF-8 encoder crash or substitute U+FFFD instead. Guess: implemented as written.

B4. Receipt-set deduplication when a receipt cannot be canonicalized (GUESS-17).
- VERIFIER.md 1: "drop any receipt whose canonical bytes (section 2) equal an earlier one".
- Silent when canonical() refuses. Guess: such a receipt is never a duplicate and is kept. Effect is mostly
  cosmetic (it can never be authentic), but it can be the primary receipt, so it changes which receipt 2a/2b/4
  use if it is the first one.

### Null versus absent, types, required fields

B5. "optional" bundle keys set to null (GUESS-13).
- VERIFIER.md 1: "grant: Grant, optional", "receipt: Receipt, optional", "intent: Intent, optional",
  "receipts: [...] optional", "observations ... optional, default []".
- Silent on {"grant": null}. Guess: null = absent. Other reading: a present but invalid grant. Example:
  grant null plus a receipt gives execution_incomplete_pair (mine) versus execution_invalid +
  execution_signature_invalid + execution_unreconciled. Same for intent null (preflight_without_grant or not).
  Also undefined: observations or receipts that are not arrays, records that are not objects (GUESS-5, GUESS-16).

B6. Record fields that are absent rather than null (JS `=== null` versus `== null`).
- "grant.provider_id is null" (2a, 2d, 3), "A null not_before or not_after is no bound" (2), "Every seq 0
  observation must have prev_evidence_id null" (R3).
- Silent on an absent key. Guess: absent behaves as null (open grant, no bound, root ok). A strict `=== null`
  reading gives the opposite: absent provider_id is not open, so 2a compares undefined with receipt.provider_id
  (provider_not_authorized), 2d does not short-circuit to execution_unreconciled, open_grant is not emitted;
  absent not_before is "present" and invalid; absent prev_evidence_id at seq 0 is root_prev_not_null.
  The record can be validly signed in this shape, so all of these are reachable.

B7. No required-field or schema checks at all.
- VERIFIER.md 2: "Grant, Receipt and Intent carry a schema string (...) inside their preimage." No step checks
  its value or presence. execution_SPEC.md says "the pure verifier checks presence and window" of the nonce;
  VERIFIER.md never checks nonce presence.
- Consequences under a literal reading: a grant with no "action" and a receipt with no "executed_action" pass
  E1 (canonical(null) == canonical(null) in my implementation; in JS canonical(undefined) is unspecified and may
  throw, which flips E1). A record whose schema says "/receipt" is accepted as a grant if it otherwise verifies.
  A grant without nonce is accepted. Guess: no checks (follow VERIFIER.md). Two readings change verdicts.

B8. hop.seq type (GUESS-19).
- R3: "The distinct seqs, sorted, must be exactly 0, 1, 2, ...". Silent on non-integer seq ("0", 0.5, true).
  Python treats True == 1 and sorts it; JS does not. Guess: any non-integer seq is seq_gap.

B9. conduct.verdict absent or non-string in R4 (GUESS-20).
- R4: "if the observations at that seq carry more than one distinct conduct.verdict value". Silent on how
  "distinct" is computed and whether a missing verdict counts. Guess: distinct canonical bytes, missing = null =
  a distinct value. Other reading (skip missing) drops witness_disagreement.

B10. edge_sig preimage with missing task_id or hop (GUESS-18).
- "P = {task_id, hop} taken from the observation". Silent whether a missing key becomes null or is omitted.
  Changes whether such an edge_sig can verify. Guess: null.

B11. Empty bundle task_id and zero records.
- Step 0: "(an empty or missing bundle task_id differs from every record): one refusal task_id_mismatch".
  With no records at all, is task_id_mismatch emitted? Guess: no ("If any differs" over an empty set). The
  parenthesis can be read as "always mismatch when task_id is empty".

### Timestamps

B12. Regex flavour (GUESS-6).
- "matches ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$". In Python (and PCRE) `$` also matches before a
  trailing "\n", and `\d` matches non-ASCII digits (Arabic-Indic, fullwidth), which Python int() then accepts.
  So "2026-10-04T00:30:00Z\n" and "٢٠٢٦-10-04T00:30:00Z" are valid in a naive Python port and invalid in JS.
  Guess: ASCII digits, whole-string match.

B13. "denotes a real instant" (GUESS-7).
- Silent on second 60 (leap second), hour 24 (ECMAScript date-time format allows T24:00:00), year 0000 (valid in
  JS, invalid in Python datetime), and impossible dates such as 2026-02-30 (some JS engines' Date.parse roll it
  over to March 2 instead of failing). Guess: proleptic Gregorian, year 1 to 9999, hour 0 to 23, second 0 to 59.

B14. Fraction precision (GUESS-8).
- "optional fraction" with unlimited digits; the window is "inclusive". A Date-based implementation truncates to
  milliseconds, so 01:00:00.0004Z is inside not_after 01:00:00Z there and outside with exact comparison.
  Guess: exact decimal comparison.

B15. Missing executed_at / declared_at (GUESS-22).
- 2a: "executed_at, not_before and not_after are valid timestamps where present"; then "executed_at is inside
  the window". "where present" makes a missing executed_at pass validation, and then the window check has no
  instant. Guess: missing or null executed_at is invalid_timestamp. Other reading: passes (accepted bundle).

### action_binding

B16. Exact shape (GUESS-9, GUESS-10, GUESS-11).
- VERIFIER.md 2: "When present it must be an object with type ..., canonicalization ..., preimage_profile ...,
  digest {alg "sha-256", value = sha256(...)}". Silent on extra keys in action_binding or digest (I allow them),
  on uppercase hex in value (I refuse: mismatch), and on a null value (VERIFIER says "Absent is fine";
  execution_SPEC.md says null is malformed; I follow execution_SPEC). Each flips accepted/refused.
- The mapping from defect to reason (which of malformed / unknown_profile) is unstated for e.g. a wrong type;
  reasons are not in the signature, so that part is cosmetic.

B17. The grant's action_binding is not checked in step 3.
- Step 3: "the intent's action binding (section 2)". execution_SPEC.md rule AB: "A verifier that finds one
  recomputes it ... and refuses the record". With grant + intent and no receipt, a bad grant binding is caught
  only indirectly (step 2 already refuses with execution_incomplete_pair), so preflight_invalid is or is not in
  the set depending on reading. Guess: literal (not checked in step 3).

### Steps 2 and 3

B18. Is E1 part of "the pair check" re-run in 2c? (GUESS-21)
- 2a: "Pair check on (grant, primary receipt), stop at the first failure: ... If all of these pass: add finding
  ... Then E1 ...". 2c: "run the pair check of (a) on (grant, this receipt) without adding findings".
  Guess: yes (E1 included, run only after the earlier checks pass). Other reading: a secondary authentic
  receipt with a diverging action adds no execution_invalid (it still causes execution_equivocation).

B19. 2c ignores receipts when the GRANT's caller_sig fails.
- "if signatures are required and either the grant's caller_sig or this receipt's provider_sig ... does not
  verify, ignore this receipt here". Implemented literally; noted because it makes all secondary pair checks
  disappear whenever caller_sig is bad (execution_signature_invalid already refuses, so only the code set changes).

B20. 2d keys on the grant's STORED grant_ref, 2a on the RECOMPUTED one.
- Explicit, implemented literally. With a tampered grant (stale grant_ref), receipts that cite the stale value
  still reconcile, so linkage and the evidence target follow a receipt bound to a grant that failed recompute.
  Not a guess; flagged as a likely unintended asymmetry a second implementer may "fix".

B21. declared_executed_divergence when proposed_action cannot be canonicalized.
- Step 3: "canonical(intent.proposed_action) differs from canonical(reconciled.executed_action)". If canonical()
  refuses, "differs" is undefined. Guess: treated as different (finding emitted) (GUESS-3).

### Evidence

B22. "falsy" (GUESS-12).
- Step 4: "E absent, null or otherwise falsy: finding no_evidence_bound". Falsy in which language? In Python {}
  and [] are falsy; in JS they are truthy. E = {} gives no_evidence_bound (Python) versus evidence_invalid (JS).
  Guess: JS semantics (undefined, null, false, 0, ""), so {} and [] are present and malformed.
- Also silent on a missing or non-object outcome (GUESS-23): I treat E as absent.

### Signatures and keys

B23. base64 strictness (GUESS-4).
- "standard base64 (RFC 4648 section 4, with padding)". Silent on non-canonical trailing bits ("QR==" and "QQ=="
  both decode to "A" in Python), embedded whitespace/newlines, url-safe characters, and missing padding. Node's
  Buffer.from(s, "base64") accepts all of these; Python with validate=True rejects some. Guess: reject anything
  but the standard alphabet with correct padding; non-canonical trailing bits accepted (signature malleability:
  two distinct strings verify).

B24. Ed25519 verification rules.
- "a raw 64-byte Ed25519 signature". Not pinned: RFC 8032 strict (cofactorless, canonical S, reject
  small-order A/R) versus ZIP-215 (cofactored, permissive). Libraries differ on edge-case signatures, so a crafted
  signature verifies in one implementation and not the other. Guess: whatever OpenSSL (cryptography 46) does.

B25. Key resolution: did:key only versus injected resolver.
- VERIFIER.md 2: "Anything else does not resolve." PROVENANCE.md: "key resolution (resolve) and evidence
  confirmation (lookup) are injected". delegation_SPEC.md publication consent says hop parties may be https
  origins ("a party that is not a did:key"). Under VERIFIER.md any observation whose hop.from is an https origin
  fails edge_sig, so every such bundle is refused whenever signatures are required. With an injected resolver it
  could verify. Guess: did:key only. Also unstated: did:key with a fragment, whitespace, or another multibase.

B26. require_signatures non-boolean (GUESS-15).
- "require_signatures: boolean, optional, default true". Silent on "false", 0, null. Guess: only literal false
  disables signatures.

### Linkage

B27. Wrong-case or padded links.
- Step 5: "a string beginning with exactly nenrin-exec://"; "the rest of the string must equal the reconciled
  receipt's recomputed receipt_id". Implemented as exact byte equality, so "NENRIN-EXEC://..." is not a link
  (can produce no_digest_link) and an uppercase-hex id is a mismatch. Explicit enough; listed because PROVENANCE
  says "the digest must recompute", which a reader could take as case-insensitive hex comparison.

---------------------------------------------------------------------------------------------------------

## (c) Cosmetic (no effect on any verdict signature)

C1. Order of R3 sub-checks and of pair-check reasons: only one refusal is emitted, and reasons are not in the
  signature ("The first violation adds one refusal", "Reasons ... are not part of the signature").
C2. Reason when witness_id and hop.from are both missing (both null, so equal): I report
  witness_not_independent; recompute_mismatch is equally plausible. Same refusal code.
C3. Which action_binding reason a wrong "type" gets (malformed vs unknown_profile).
C4. "sorted set": sort order not defined (code point vs locale). All codes are lowercase ASCII plus "_", and the
  signature is compared as sets.
C5. Fixture directory "v01" versus the spec's "interop-v0.1"; out.json uses "v01" as instructed.
C6. Unknown top-level bundle keys are ignored (not stated).
C7. UTF-8 BOM / file encoding of bundles not stated (all 18 are plain UTF-8).
C8. Report fields (why, layers, establishes, recompute) in PROVENANCE.md are not needed for the signature and
  were not implemented.

---------------------------------------------------------------------------------------------------------

## Fixture facts observed (for cross-checking against the missing expected.json)

- All ids recompute and all signatures verify in every bundle except: v0/forged_signature (observation 0
  witness_sig), v01/linkage_unreconciled (receipts[1] provider_sig: an impersonation of the authorized provider
  id), v01/preflight_signature_invalid (intent_sig), v01/provider_sig_invalid (receipt provider_sig).
- v0/equivocation: `receipt` and receipts[0] are byte-identical (deduplicated); two authentic receipt_ids remain.
- v01/witness_is_party: witness_id == hop.from, and its witness_sig is genuinely valid; only R1 fires.
- v01/linkage_unreconciled: the link names the unauthentic receipts[1]; receipts[0] reconciles.
