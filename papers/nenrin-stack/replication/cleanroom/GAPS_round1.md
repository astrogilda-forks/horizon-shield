# GAPS: clean-room implementation of nenrin-provenance-verify-v0 from spec text only

Inputs used: specs/delegation_SPEC.md (DEL), specs/execution_SPEC.md (EXE), specs/PROVENANCE.md (PROV), 18 bundles.
Nothing else was opened. Implementation: impl/verify.py (each guess is a named flag in INTERP, toggle with
`--set FLAG=0|1`). impl/altdiff.py re-runs all 18 bundles with each flag flipped and prints which signatures move.

"Impact" below = whether the alternative reading changes any verdict signature on the 18 bundles (measured with
altdiff.py where a flag exists; computed by hand otherwise).

Headline: the crypto core (canonical form, the four content ids, the five signature types, did:key) reproduced on
the first try for every record in all 18 bundles, but only because I filled in did:key decoding, the intent record,
and the bundle format from general knowledge and from the fixtures, not from the text. The report-level semantics
(which codes fire together, which findings appear on refused reports, how receipt and receipts combine) are where
the text is silent, and 11 independent guesses each move at least one of the 18 signatures (12 if the B1 schema
sentence is taken literally; see the table in section K). One reading
(findings on refused reports) moves 11 of 18.

---------------------------------------------------------------------------------------------------------------
## A. Input format and missing normative sources

### A1. The bundle format is not specified anywhere
No spec defines the input object. PROV says only "optional input `intent`". The keys `task_id`, `observations`,
`grant`, `receipt`, `receipts`, `intent` were learned from the fixtures alone. Nothing says whether `observations`
may be absent or null, or whether `grant` may be a list.
Guess: the keys as seen; missing or null means not presented.
Impact: foundational. Without the fixtures a clean-room implementer could not even start.

### A2. `receipt` and `receipts`: the relationship is undefined
EXE: "over the set of receipts for one grant_ref". No text says how a singular `receipt` and a plural `receipts`
combine. v0/equivocation carries BOTH, with `receipt` duplicated byte for byte inside `receipts`.
v01/linkage_unreconciled carries ONLY `receipts`.
Guess: union of `receipt` and `receipts`, with byte-identical duplicates removed. Reconciliation counts distinct
receipt_id values anyway, so the duplicate does not matter for E2.
Alternatives tried by hand: "if `receipt` is present use only it" makes v0/equivocation **accepted**
(findings [evidence_bound_unchecked]) instead of refused [execution_equivocation]. "Use only `receipts`" gives the
same result as my guess. "Use only `receipt`" makes linkage_unreconciled execution_incomplete_pair.
Impact: HIGH. A plausible reading flips a v0 verdict.

### A3. Referenced normative artifacts that are absent
Spec text that defers to files I may not open:
- DEL: "Its name is musubi-canonical-v0, its vectors are ../musubi-v0/canonical_vectors.json". EXE: "reproduced byte
  for byte in Python and Node". The vectors are the actual conformance test for canonicalization. Without them,
  the escaping, non-ASCII, U+2028/U+2029, U+007F and number-limit rules can only be checked against prose. The
  fixtures exercise none of these: every string is ASCII, and the only integers are 0 and 1.
- DEL: "strict_json.mjs, shared by bind.mjs and the ledger face". The refusal behaviour is defined by a file that
  is not available.
- EXE: "canonical() and sha256hex() are imported from ../task-delegation-bind-v0/bind.mjs". Hex case, among other
  details, lives there (see B6).
- PROV/EXE name functions whose behaviour the report depends on but which are never specified: chainContinuousSet,
  chainContinuous, reconcileSigned (including its return value `no_authorized_provider`), verifyEvidence,
  verifyPreflight, intentMatchesReceipt, outcome_evidence.mjs, preflight.mjs, sign_exec.mjs, compose.test.mjs
  ("A composed verifier MUST also check that the observation, grant and receipt share one task_id
  (compose.test.mjs)", a MUST whose definition is a test file), bind_adversarial A5,
  provenance_adversarial, CONSUME.md.
- PROV pins "task-delegation-bind-v0 ... pin 4d7c9c27...", a commit I cannot see.
Guess: implemented from the prose. Impact: none observed on the 18 bundles, because the fixtures never stress these
paths. That is a gap in the fixtures as much as in the text.

### A4. The intent record is never defined
PROV: "the pre-execution intent, a signed declaration of the action a provider is about to run". EXE: "The provider
signs, before running, what it is about to do (proposed_action) referencing the grant by hash". EXE lists
"INTENT_DERIVED" but never says what is in it. No text gives the intent's field list, its schema string, how
intent_id is computed, the name of the signature field (`intent_sig`), who signs it, or what the signature covers.
Guess: intent_id = SHA-256(canonical(intent without intent_id, intent_sig, action_binding)), and intent_sig is the
provider_id's Ed25519 signature over that same preimage. Both are inferred by analogy with grant and receipt.
Result: the guess recomputes intent_id on all 3 intent bundles. The signature verifies on 2 and fails on
preflight_signature_invalid, as that fixture's name suggests.
Impact: without the analogy guess, all three preflight fixtures cannot be verified at all.

---------------------------------------------------------------------------------------------------------------
## B. Canonicalization, hashing, identifiers

### B1. "The record's schema name sits inside the hashed bytes" is false for observations
DEL, Canonical form: "The record's schema name sits inside the hashed bytes. ... this family commits its type
through the schema field instead." No observation in any of the 18 bundles has a `schema` field. The record shape in
DEL ("{ task_id, hop:{seq,from,to}, prev_evidence_id, conduct:{verdict,detail_ref}, witness_id, observed_at,
evidence_id }") also lists no schema.
Guess: hash the record exactly as presented, without adding a schema. Adding any guessed schema
(e.g. "task-delegation-bind-v0/observation") breaks every evidence_id.
Open questions: should a verifier refuse an observation that has no schema? Should it check the grant, receipt and
intent schema VALUES ("task-execution-bind-v0/grant" and so on), which no spec text states? I do not check
schema values.
Impact: a verifier that follows the sentence literally (requires or injects schema) refuses all 18 bundles with
delegation_observation_invalid.

### B2. The preimage exclusion sets
- Observation: DEL "preimage is the record without evidence_id, witness_sig, edge_sig and consent". This
  contradicts DEL Record, which says "evidence_id = SHA-256(canonical(record without evidence_id))". That
  definition would include the sigs, and the evidence_id would then change when a signature is added. The later
  "Signing does not change evidence_id (preimage excludes sigs)" resolves it. I used the 4-key exclusion, which
  reproduces every evidence_id.
- Grant: EXE "grant_ref = SHA-256(canonical(grant without grant_ref and caller_sig))". action_binding is also
  excluded ("excluded from its own record's preimage"), so the formula as written is incomplete. Reproduces.
- Receipt: same pattern: receipt_id, provider_sig, action_binding. Reproduces.
- Intent: see A4.
- Unknown or extra fields (e.g. a future derived field): no rule says whether unknown top-level fields are hashed
  or refused. I hash them.
Impact on the 18 bundles: none, since no bundle carries action_binding or consent.

### B3. edge_sig message
DEL: "the delegating party (hop.from) signs canonical({task_id, hop})". Not stated: whether task_id is the
observation's or the bundle's. Guess: the observation's. It reproduces, and the two are equal wherever it matters.

### B4. Canonical form details the prose leaves open
- Lone surrogates (\ud800 in JSON input) cannot be encoded as UTF-8. The text says "everything else raw". Guess:
  bad_json.
- "-0": Python parses it to 0. JS JSON.parse gives -0, which JSON.stringify renders as "0". Not addressed.
- "1.0": PROV/DEL say "no fraction". JS JSON.parse("1.0") yields the integer 1. Whether strict_json refuses at the
  token level (non_integer_number) or accepts the value 1 is not stated. Guess: refuse at the token level.
- Limit: "within plus or minus 2^53 - 1". Guess: inclusive.
- key_not_printable_ascii applies to "keys". Does that include keys of the bundle wrapper, or only of hashed
  records? Guess: the whole bundle is parsed strictly.
- Strict-JSON refusals have no provenance refusal code. DEL lists duplicate_key, non_integer_number, unsafe_number,
  key_not_printable_ascii, bad_json, and says the record "has no evidence_id and is not stored". The PROV
  vocabulary has no code for them. Should the verifier refuse with delegation_observation_invalid or
  execution_invalid with that reason, or emit the raw strict code? Guess: a bundle-level refusal whose code is the
  raw strict code. This is outside the PROV vocabulary, and PROV says the vocabulary is closed ("The refusal-code
  vocabulary is the list in PROVENANCE.md"). Contradiction.
Impact: none on the 18 bundles, which are all plain.

### B5. Escape rule: "\u00xx lowercase"
Clear for control characters. I applied it only to U+0000..U+001F, excluding the short forms. Unicode
normalization (NFC) is not mentioned. I assumed none. Untested by the fixtures.

### B6. Hex encoding of ids
EXE names "sha256hex". No text says lowercase or uppercase, or whether comparison is case-insensitive. Guess:
lowercase, compared exactly. The fixtures are all lowercase.

### B7. "a decimal is written as an integer at a stated scale"
Where is the scale stated? There is no field for it. Untested.

---------------------------------------------------------------------------------------------------------------
## C. Signatures and did:key

### C1. did:key decoding is not specified
DEL: "DIDs resolve to the key, did:key is self-contained". EXE: "did:key resolves the key, no network". Not stated:
multibase prefix 'z' (base58btc), the multicodec varint 0xed 0x01 for Ed25519, the 32-byte key length, whether
other key types must be rejected, or behaviour on a malformed DID. Guess: W3C did:key Ed25519. Strip "did:key:z",
base58btc-decode, require the 2-byte prefix ed01 plus 32 bytes, and treat anything else as unresolvable, so the
signature fails.
Impact: required to verify anything. The guess reproduces all signatures.

### C2. Signature encoding
DEL/EXE (clarified 2026-10-04): "raw 64-byte Ed25519 signature, standard base64 encoded". Not stated: whether
padding is required, whether url-safe or unpadded input is tolerated, and whether whitespace is allowed. Guess:
strict standard alphabet with padding, exactly 64 bytes.

### C3. Ed25519 verification strictness
Not stated: cofactored vs cofactorless verification, rejection of non-canonical S, small-order or non-canonical
public keys. These are known divergence points between Node (OpenSSL) and other libraries. Guess: whatever OpenSSL
does through `cryptography`. Untested by the fixtures.

### C4. Parties that are not did:key
DEL Publication consent: a party may be "an https origin on a public host". A witness or hop.from could then be an
https origin, and witness_sig or edge_sig cannot be resolved without a network. Neither the provenance report nor
the signature rule says what happens. Guess: unresolvable, so the signature fails. Untested.

### C5. Consent entries
DEL: "A present-but-invalid entry ... is refused with 422". That is ledger (HTTP) behaviour. No text says whether
the offline provenance verifier must verify `consent`, or under which code. Guess: excluded from the preimage, not
verified. Untested.

---------------------------------------------------------------------------------------------------------------
## D. Delegation layer (R1 to R4)

### D1. No refusal code for a bad witness_sig or edge_sig
PROV vocabulary: delegation_observation_invalid and delegation_chain_broken. There is no delegation signature code,
although the execution and preflight layers each have one (execution_signature_invalid,
preflight_signature_invalid). v0/forged_signature has a bad witness_sig on hop 0.
Guess: delegation_observation_invalid. The reason I record internally is witness_sig_invalid, and reason names are
my own invention: PROV lists only witness_not_independent as an example.
Impact: no alternative code exists in the vocabulary, but a reader could argue for execution_signature_invalid.

### D2. Does an invalid observation still count for R3 and linkage? (cascade)
PROV: "every non-root prev_evidence_id must resolve to some presented prior-hop observation". "Presented", not
"valid". Guess (flag invalid_obs_excluded=0): invalid observations still take part in R3, R4 and linkage.
Alternative (=1): exclude them. Then the hop-1 link dangles and the hop-0 detail_ref is lost:
- v0/forged_signature becomes [delegation_chain_broken, delegation_observation_invalid] + findings
  [evidence_bound_unchecked, no_digest_link]
- v01/witness_is_party becomes the same.
Impact: 2 signatures.

### D3. R3 contents
DEL: "hops are contiguous from seq 0 and each links the prior hop's evidence_id". Not stated:
- whether seq 0 must have prev_evidence_id exactly null (guess: yes);
- whether party continuity (hop[n].from == hop[n-1].to) is checked. The A to C example implies so, but only the
  hash link is stated. Flag r3_party_continuity, impact 0;
- forks: two seq-0 observations with different {from,to}. Not addressed;
- empty observations: R3 is vacuous, and the finding no_delegation_observations applies;
- seq type, and negative or non-integer seq.

### D4. R4 grouping key and hop-level outcome
DEL: "the aggregate over the full witness set for a {task_id, hop}". Guess: group by canonical({task_id, hop}),
which includes from and to, not just seq. Unspecified:
- the verdict vocabulary: only "pass" and "fail" appear;
- whether a unanimous "fail" hop affects the task verdict. I do not refuse, since "the observation's verdict stays
  the witness's own";
- whether detail_ref disagreement among witnesses of one hop matters.
Impact: none on the 18. The disagreement clarification ("accepted") was needed and is present.

### D5. Ordering of R1, R2 and the signature checks
I check R2, then R1, then witness_sig, then edge_sig, then observed_at, and stop at the first failure per
observation. Only the code matters for the signature, and all of these map to the same code, so ordering is
invisible. It would matter if reasons were part of the signature (they are not).

### D6. observed_at
EXE's strict RFC3339 rule is stated for the execution layer ("executed_at ... not_before, not_after ...
declared_at"). Nothing says observed_at is held to it, or under which code. Guess: checked, under
delegation_observation_invalid. Flag check_observed_at, impact 0.

---------------------------------------------------------------------------------------------------------------
## E. Execution layer (E1 to E3, window, reconciliation)

### E1. Refusal for a bad provider_sig in a SET of receipts (griefing vs strict)
EXE: "reconcileSigned is scoped to the grant's authorized provider, which closes both griefing paths: a stranger
signing under its own id is not the authorized executor, and a stranger impersonating the executor's id fails the
signature check." PROV: "a link to a presented receipt that did not reconcile (for example one not signed by the
authorized provider) is linkage_receipt_mismatch". Neither says whether the failing receipt ALSO raises
execution_signature_invalid, or execution_invalid with reason provider_not_authorized, or whether it is silently
dropped from the set. Dropping it is the reading that actually "closes the griefing path": a stranger cannot get a
good bundle refused by appending junk.
Guess (receipt_set_filter=0): every presented receipt is fully checked; a bad signature means
execution_signature_invalid.
Alternative (=1): drop it silently from reconciliation.
- v01/linkage_unreconciled: default [execution_signature_invalid, linkage_receipt_mismatch];
  alt [linkage_receipt_mismatch].
Impact: 1 signature, and the fixture is precisely the one meant to pin this case.

### E2. Cascade: execution_unreconciled alongside a more specific refusal
When the only receipt has a bad signature (v01/provider_sig_invalid), nothing reconciles. No text says whether
execution_unreconciled is ALSO raised.
Guess (unreconciled_cascade=0): only the specific code.
Alternative: [execution_signature_invalid, execution_unreconciled].
Impact: 1 signature. PROV never defines execution_unreconciled; it appears only in the list.

### E3. Does a receipt that fails E1, the window or the timestamp rule still "reconcile"?
EXE E2 defines reconciliation only as "one distinct receipt_id" over "the set of receipts for one grant_ref". It
does not say whether an execution_invalid receipt is eligible.
Guess (reconcile_requires_valid=0): reconciliation = for this grant_ref + id recomputes + signed by the authorized
provider. E1, window and timestamp are separate validity refusals.
Alternative: v01/non_utc_timestamp loses its evidence_bound_unchecked finding, because nothing reconciled.
Impact: 1 signature. The alternative would also raise execution_unreconciled under cascade, so 2 readings change.

### E4. Open grant: contradictory text
EXE: "an open grant (provider_id null) is accepted with an open_grant finding but is NOT reconcilable ...
reconcileSigned returns no_authorized_provider otherwise". PROV has a refusal code execution_unreconciled, and
"open_grant: ... nothing reconciles attributably". Is an open grant with a receipt accepted (EXE) or refused with
execution_unreconciled (PROV, by analogy)? Are linkage and evidence evaluated (there is no reconciled receipt)?
Guess: accepted with open_grant, no reconciled receipt, so no linkage and no evidence findings. Untested.

### E5. Reason-to-code mapping beyond the listed examples
EXE/PROV give only: invalid_timestamp, receipt_unbound, action_diverged under execution_invalid. Unmapped:
provider_not_authorized (E3), grant_ref or receipt_id recompute failure ("a tampered grant or receipt fails its own
content hash"), a missing nonce ("checks presence"), outside the window, not_before > not_after, and action_binding
failures ("the refusal names the record (grant, receipt or intent)", but under which provenance code?).
Guess: all of them are execution_invalid, or preflight_invalid for the intent. Untested.

### E6. Window and timestamp rule
EXE: "executed_at must fall in [not_before, not_after]. Timestamps must be strict RFC3339 UTC (a trailing Z, no
offset, no date-only form)". Not stated:
- fractional seconds (allowed? I allow them);
- lowercase 't' or 'z', which RFC3339 permits (I reject them);
- leap second ":60" (rejected by my parser);
- whether "+00:00" counts as "no offset". I reject it, since only Z is allowed.
Interval: closed brackets, read as inclusive at both ends. Every fixture has executed_at strictly inside, so
boundaries are untested.

### E7. "nonce ... the pure verifier checks presence"
What counts as present: empty string? null? Guess: falsy means absent, mapped to execution_invalid. Untested.

### E8. Several execution codes are never defined
PROV defines all nine findings (2026-10-04) but none of the 14 refusal codes. execution_incomplete_pair (I read
it as a grant without a receipt or a receipt without a grant), execution_unreconciled, evidence_invalid and
preflight_without_grant are understood only from their names.
Impact: incomplete_pair is pinned by a fixture name, so it is guessable. Is an intent with a receipt but no grant
also execution_incomplete_pair? Unaddressed.

---------------------------------------------------------------------------------------------------------------
## F. Evidence

### F1. Well-formedness of outcome.evidence is unspecified
EXE: "receipt.outcome.evidence = { kind, ref, system } names an independently checkable pointer (bitcoin_tx,
ledger_record, document_sha256, url_sha256). ... verifyEvidence checks shape". The shape rule per kind is not given:
the ref format (64 hex? txid byte order?), the system format (hostname? free text? required?), and whether extra
keys are allowed.
Guess: exactly the three keys, kind in the 4-value set, ref = 64 lowercase hex, system a non-empty string.
evidence_malformed fails on the kind regardless, so the guess is invisible there. But a stricter or looser
reader of ref or system could flip the pass bundle (ref "0123...ef" plus system "ledger.horizonshield.dev").

### F2. Which receipts' evidence is checked
PROV defines the evidence findings over "the reconciled receipt". Should evidence_invalid fire for a malformed
pointer on a presented but unreconciled receipt? Guess: only the reconciled receipt is checked. Untested.

### F3. Null evidence
Is `evidence: null` absent (no_evidence_bound) or malformed (EXE AB says null is malformed for action_binding, but
says nothing about evidence)? Guess: null means absent.

---------------------------------------------------------------------------------------------------------------
## G. Linkage

### G1. no_digest_link alongside linkage_receipt_mismatch
PROV definition: "no_digest_link: a receipt reconciled and observations were presented, but no observation's
conduct.detail_ref names it as nenrin-exec://<receipt_id>". In linkage_unpresented and linkage_unreconciled an
observation DOES carry a nenrin-exec link, but to the wrong receipt. Read literally the finding fires. The gloss
"the layers verify independently but are not linked" suggests it is meant for the no-link case.
Guess (no_digest_link_literal=1): literal, so it fires.
Alternative: drop it in both bundles.
Impact: 2 signatures.

### G2. Which detail_ref values are links
Not stated: whether only the exact prefix "nenrin-exec://" counts; case; trailing data; whether a non-hex suffix is
a mismatch or ignored; whether other schemes (e.g. https) are ignored. Guess: exact prefix, and anything after it
compared to receipt_id exactly. Also, "the digest must recompute": recompute what? I read it as "the named receipt's
receipt_id recomputes from its bytes", which the execution layer already checks.

### G3. Linkage with multiple linking observations
If two observations link, one correctly and one wrongly, I raise mismatch. Not stated.

---------------------------------------------------------------------------------------------------------------
## H. Preflight

### H1. "inside the caller's signed grant"
EXE: "verifyPreflight establishes that the declared action is inside the caller's signed grant". "Inside" could
mean equality or some containment (e.g. a grant pattern). The text then says "Under a fixed-action grant that
equality is implied", which suggests other grant kinds exist. Guess: canonical equality with grant.action.

### H2. Temporal ordering of declared_at
EXE: "a signed pre-execution promise", "verified BEFORE execution". The only stated check is "in the window". In
preflight_invalid and preflight_signature_invalid, declared_at == executed_at (both 00:30:00Z). A verifier that
enforces declared_at < executed_at (strictly "pre-execution") adds preflight_invalid to preflight_signature_invalid,
and to preflight_invalid as a duplicate.
Guess: window only, no ordering. Impact: 1 signature under the strict alternative (hand-computed).

### H3. Intent field checks and their codes
Not stated: whether intent.grant_ref must equal grant.grant_ref, intent.provider_id must equal grant.provider_id,
declared_at must be in the window, and intent_id must recompute. Also not stated: the code for each failure.
Guess: all of them under preflight_invalid.

### H4. preflight_without_grant and no_execution_records
PROV: "no_execution_records: neither a grant nor a receipt was presented". preflight_without_grant has an intent
but neither of those, so the literal reading emits it. An intent is arguably an execution-layer record.
Guess (intent_counts_as_execution_record=0): literal, so it fires.
Impact: 1 signature (v01/preflight_without_grant).

### H5. declared_executed_divergence when the preflight already failed
PROV says it fires when proposed_action differs from the reconciled receipt's executed_action, "the preflight or
execution refusal raised alongside it is the operative one". Clear enough. It fires in preflight_invalid. Under E3
alternative readings, where nothing reconciles, it would not fire.

---------------------------------------------------------------------------------------------------------------
## I. Identity (task_id)

### I1. What "missing" means, and the cascade
PROV: "every presented record carries the task_id under verification". task_id_missing is never defined. The
fixture uses "" at the bundle level, so empty string counts. Not addressed: null or an absent key; a RECORD with no
task_id (my guess: task_id_missing, not mismatch); and whether, once the bundle task_id is missing, every record
with a non-empty task_id is also task_id_mismatch.
Guess (task_missing_cascade=0): no cascade.
Alternative: v01/task_id_missing becomes [task_id_mismatch, task_id_missing].
Impact: 1 signature.

### I2. Does a task_id mismatch disable the layer it occurs in?
In task_id_mismatch, the grant and receipt are consistent with each other (both "task_other") and the observation
links the receipt. Guess: the layers still run, so the evidence finding still appears. No text addresses it. A
reader who drops mismatched records from the graph would turn this into execution and linkage refusals
(incomplete pair, no reconciled receipt). Untested by flag, but plausible.

### I3. Duplicate codes
The task says "sorted list of refusal codes". PROV gives refusals as a list of objects, so the same code can occur
more than once (task_id_mismatch for grant AND receipt). Is the signature a set or a multiset? Guess: set
(deduplicated). Impact: under a multiset reading v01/task_id_mismatch becomes
[task_id_mismatch, task_id_mismatch]. 1 signature.

---------------------------------------------------------------------------------------------------------------
## J. Report aggregation

### J1. Are findings emitted on refused reports?
PROV: "Fail-closed for readers: a refused report's establishes is exactly ['nothing: see refusals']." Silent on
findings. evidence_bound_unchecked "appears on clean bundles", which says nothing about dirty ones.
Guess (findings_on_refused=1): findings are computed independently of the verdict.
Alternative: empty findings on every refused bundle.
Impact: HIGH. 11 of 18 signatures change.

### J2. Verdict aggregation
Assumed: refused iff at least one refusal code; findings never refuse (stated for witness_disagreement and
self_authorized, assumed for the rest). PROV says "the admission decision stays with the recipient" yet the report
has a verdict field, so the verdict is a status, not a decision. Consistent enough.

### J3. Reasons vs codes
Stated clearly (PROV, EXE): reasons are not codes and not part of the signature. But only 4 reason names are given
(invalid_timestamp, receipt_unbound, action_diverged, witness_not_independent; plus provider_not_authorized and
action_binding_* in EXE prose). Every other reason name in verify.py is invented.

### J4. Layer independence
PROV: "It composes three layers that each stand on their own". This supports running every layer even after
another layer refuses, which is my reading. Nothing says whether a delegation refusal suppresses linkage, or an
identity refusal suppresses everything. Impact: see D2, I2 and J1.

---------------------------------------------------------------------------------------------------------------
## K. Summary of the readings that move signatures on the 18 bundles

| # | gap | default | alt changes |
|---|-----|---------|-------------|
| J1 | findings on refused reports | emitted | 11 |
| A2 | receipt vs receipts precedence | union | 1 (equivocation flips to accepted) |
| D2 | invalid obs excluded from R3/linkage | not excluded | 2 |
| G1 | no_digest_link literal | literal | 2 |
| E1 | bad-sig receipt in set: refuse vs drop | refuse | 1 |
| E2 | execution_unreconciled cascade | no | 1 |
| E3 | invalid receipt can reconcile | yes | 1 |
| I1 | task_id_missing cascade | no | 1 |
| I3 | codes as set vs multiset | set | 1 |
| H2 | declared_at strictly before executed_at | not required | 1 |
| H4 | intent counts as execution record | no | 1 |
| B1 | schema "inside the hashed bytes" taken literally | ignored | 18 (all refused) |

Readings with no effect on these bundles but unresolved by the text: did:key details (C1), base64 strictness (C2),
Ed25519 strictness (C3), the canonical edge cases (B4 to B7), the strict-JSON code mapping (B4), R3 party
continuity (D3), observed_at (D6), open grant (E4), the reason mapping (E5), the timestamp grammar and window
boundaries (E6), nonce (E7), evidence shape (F1 to F3), link parsing (G2, G3), preflight containment (H1),
consent (C5) and non-did parties (C4).
