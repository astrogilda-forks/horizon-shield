# nenrin-provenance-verify-v0: the verifier algorithm (normative)

Written 2026-10-04 after a clean-room test: an implementer given only the specs and the fixtures, with no access to
any NENRIN source, reproduced 13 of 18 verdict signatures and had to guess at every step listed below. This file
closes those guesses. It is the complete procedure. A conforming verifier follows it in order and reproduces every
verdict signature in ../interop-v0/expected.json and ../interop-v0.1/expected.json. Where this file and prose
elsewhere differ, this file is the contract.

## 1. Input: the bundle
A bundle is one JSON object:

    { "task_id": string,
      "observations": [WitnessObservation, ...],   optional, default []
      "grant": Grant,                              optional
      "receipt": Receipt,                          optional
      "receipts": [Receipt, ...],                  optional
      "intent": Intent,                            optional
      "require_signatures": boolean }              optional, default true (the interop corpora use the default)

The receipt set is built once: start with `receipt` (if present), then append each element of `receipts` in order,
and drop any receipt whose canonical bytes (section 2) equal an earlier one. The primary receipt is `receipt` if
present, otherwise the first element of the receipt set. Every later step that says "receipt set" means this list.

## 2. Primitives
**Canonical form (musubi-canonical-v0).** canonical(v) is the UTF-8 encoding of:
- null, true, false as literals;
- an integer in [-(2^53-1), 2^53-1] as its shortest decimal form (no leading zeros, no plus sign, no fraction, no
  exponent; negative zero is written 0). Any other number is refused (non_integer_number, unsafe_number);
- a string as `"` + body + `"`, where `"` becomes `\"`, backslash becomes `\\`, U+0008 `\b`, U+000C `\f`, U+000A
  `\n`, U+000D `\r`, U+0009 `\t`, every other code point below U+0020 becomes `\u00xx` with lowercase hex, and every
  other code point is written raw (non-ASCII, U+007F, U+2028, U+2029 included). A lone surrogate is written as
  `\udxxx` with lowercase hex;
- an array as `[` + canonical elements joined by `,` + `]`;
- an object as `{` + `"key":value` pairs joined by `,` + `}`, keys sorted by code point. Every key must be printable
  ASCII (U+0020..U+007E) or the object is refused (key_not_printable_ascii).
No Unicode normalization is applied, here or in any comparison: a string is its code points as parsed. Two strings
that differ only in normalization form (for example NFC and NFD) are different values with different canonical
bytes and different hashes. No whitespace anywhere. Vectors: ../musubi-v0/canonical_vectors.json. These refusals
belong to the canonical rule, not to the report vocabulary. A record (observation, grant, receipt, intent, or the
evidence inside a receipt) that holds a number the canonical form refuses cannot be checked at all. A conforming
verifier MUST NOT return accepted for such a bundle. The reference (JavaScript and Python) stops with an error that
names the rule and the path (for example non_integer_number at $.hop.seq) and returns no report; a verifier that
instead refuses in that record's step (recompute_mismatch and the step's refusal code) is equally conformant, since
no verdict signature is defined for this input. Such numbers never reach a verdict in the ledger, whose ingress
refuses them before parsing (section 5, Input). Unknown bundle keys are not records and are not canonicalized.

**Hash.** sha256(x) is SHA-256 over canonical(x), written as 64 lowercase hex characters.

**did:key.** An identifier `did:key:z<base58btc>` whose base58btc payload (Bitcoin alphabet, leading `1` = 0x00)
is the two bytes 0xed 0x01 followed by exactly 32 bytes, the raw Ed25519 public key. Anything else does not
resolve. A signature by an identifier that does not resolve does not verify.

**Signature.** A signature field holds standard base64 (RFC 4648 section 4, with padding) of a raw 64-byte
Ed25519 signature over canonical(P), where P is the preimage named below. There is no JWS envelope. Undecodable
base64, a wrong length, or an unresolvable key all mean the signature does not verify.

**Preimages.** Each record's preimage is the record with its derived fields removed. Every other field, including
fields this file does not name, stays in the preimage. That includes a field whose key is `__proto__`: it is an
ordinary JSON member of the record, parsed as an own key, kept in the preimage and hashed like any other. A verifier
whose copy of a record silently drops that one key (JavaScript `Object.assign` and the spread operator run the
`__proto__` setter instead of copying it; the reference did this before nenrin-verify 0.5.3, verifier_version
0.1.7) recomputes the stored id for a record changed after signing and accepts it (pipavlo82, #29, 2026-10-15).
Corpus: ../interop-v0.3/own-proto (the key added to a signed grant, receipt and intent, each refused with the same
signature as an ordinary unknown key added the same way).

| record | derived fields removed | id = sha256(preimage) | signature over canonical(preimage) | signer |
|---|---|---|---|---|
| WitnessObservation | evidence_id, witness_sig, edge_sig, consent | evidence_id | witness_sig | witness_id |
| (edge of an observation) | P = {task_id, hop} taken from the observation | none | edge_sig | hop.from |
| Grant | grant_ref, caller_sig, action_binding | grant_ref | caller_sig | caller_id |
| Receipt | receipt_id, provider_sig, action_binding | receipt_id | provider_sig | the receipt's own provider_id |
| Intent | intent_id, intent_sig, action_binding | intent_id | intent_sig | the intent's provider_id |

WitnessObservation carries no schema field; its type is fixed by the bundle key it appears under. Grant, Receipt
and Intent carry a `schema` string ("task-execution-bind-v0/grant", "/receipt", "/intent") inside their preimage.
Record shapes:

    WitnessObservation { task_id, hop:{seq,from,to}, prev_evidence_id, conduct:{verdict,detail_ref}, witness_id, observed_at, evidence_id, witness_sig, edge_sig }
    Grant   { schema, task_id, action, caller_id, provider_id, nonce, not_before, not_after, grant_ref, caller_sig }
    Receipt { schema, task_id, grant_ref, executed_action, outcome:{status, result_sha256, evidence?}, provider_id, executed_at, receipt_id, provider_sig }
    Intent  { schema, task_id, grant_ref, proposed_action, provider_id, declared_at, intent_id, intent_sig }

**Timestamps.** A timestamp is valid when it matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$` (uppercase T
and Z, optional fraction, no offset, `+00:00` is not accepted) and denotes a real instant. The window is inclusive:
not_before <= t <= not_after. A null not_before or not_after is no bound on that side. observed_at is not checked.

**action_binding** (optional on grant, receipt, intent). Absent (the key not present) is fine; present with the value
null is malformed. When present it must be an object with
type "canonical_request_digest", canonicalization "musubi-canonical-v0", preimage_profile
"task-execution-bind-v0/action", digest {alg "sha-256", value = sha256(the record's action field)}; otherwise the
check fails, with the reason decided in this order. Not an object (or an array), type not "canonical_request_digest",
digest not an object, digest.alg not "sha-256", or digest.value not a string: action_binding_malformed.
canonicalization or preimage_profile not the values above: action_binding_unknown_profile. The record's action field
null or absent, or digest.value not equal to the recomputed digest: action_binding_mismatch. The comparison is exact
on the string: digest.value must be the recomputed digest as 64 lowercase hex characters, and uppercase or mixed
case hex is action_binding_mismatch even when it denotes the same bytes. All three are reasons;
the refusal code is the one the step names (execution_invalid in step 2, preflight_invalid in step 3).

## 3. The procedure
Codes go into two lists, refusals and findings. Run every step, in order, whatever earlier steps found: no step
is skipped because another refused, except where a step says so. In steps 1 to 3, a name in parentheses after a
check is a reason, reported for readers; the refusal code is the one the step names at the end of the bullet or
paragraph (for example, an invalid executed_at in step 2a gives reason invalid_timestamp under refusal
execution_invalid).

**Step 0, identity.** If task_id is not a non-empty string: refusal task_id_missing. Then compare task_id with the
task_id of every observation, the grant, the intent and every receipt in the receipt set. If any differs (an empty
or missing bundle task_id differs from every record): one refusal task_id_mismatch.

**Step 1, delegation.** No observations: finding no_delegation_observations, go to step 2. Otherwise, for each
observation, in order, stop at its first failure:
R1 witness_id differs from hop.from and from hop.to (reason witness_not_independent); R2 evidence_id equals the
recomputed id (recompute_mismatch); if signatures are required, witness_sig verifies (witness_sig_invalid), then
edge_sig verifies (edge_sig_invalid). Each failing observation adds one refusal delegation_observation_invalid.
Failing observations are NOT removed: R3, R4 and linkage below run over every presented observation.
R3 over the set: group observations by hop.seq. The distinct seqs, sorted, must be exactly 0, 1, 2, ... (else
delegation_chain_broken, reason seq_gap). Every seq 0 observation must have prev_evidence_id null (else
root_prev_not_null). Every other observation's prev_evidence_id must equal the recomputed evidence_id of at least
one presented observation with seq one lower (else broken_link). The first violation adds one refusal
delegation_chain_broken.
R4: for each seq, if the observations at that seq carry more than one distinct conduct.verdict value, add one
finding witness_disagreement for that seq. R4 never refuses (fail-closed is the hop-level aggregate, "disagreement").

**Step 2, execution.**
- No grant and an empty receipt set: finding no_execution_records. Go to step 3.
- A grant with an empty receipt set, or a non-empty receipt set with no grant: refusal execution_incomplete_pair.
  Nothing else in this step runs. Go to step 3.
- Otherwise:
  a. Pair check on (grant, primary receipt), stop at the first failure: grant_ref recomputes
     (grant_recompute_mismatch); receipt_id recomputes (receipt_recompute_mismatch); action bindings, grant first
     (section 2); receipt.grant_ref equals the recomputed grant_ref (receipt_unbound); executed_at is a valid
     timestamp (a missing or null executed_at is invalid), and not_before and not_after are valid timestamps unless
     null or absent (invalid_timestamp); grant.provider_id is null or equals
     receipt.provider_id (provider_not_authorized); executed_at is inside the window
     (outside_authorization_window). If all of these pass: add finding open_grant if grant.provider_id is null, and
     finding self_authorized if grant.provider_id is not null and equals grant.caller_id. Then E1: canonical(grant.action)
     equals canonical(receipt.executed_action) (action_diverged). Any failure adds one refusal execution_invalid.
  b. If signatures are required: caller_sig verifies under grant.caller_id, then provider_sig of the primary receipt
     verifies under that receipt's provider_id. The first failure adds one refusal execution_signature_invalid.
  c. Every other receipt in the set, in order: if signatures are required and either the grant's caller_sig or this
     receipt's provider_sig (under its own provider_id) does not verify, ignore this receipt here (no code). Otherwise
     run the pair check of (a) on (grant, this receipt) without adding findings; a failure adds one refusal
     execution_invalid.
  d. Reconciliation. If grant.provider_id is null: refusal execution_unreconciled. Otherwise the authentic receipts
     are those in the set with grant_ref equal to the grant's stored grant_ref, provider_id equal to
     grant.provider_id, receipt_id that recomputes, and (if signatures are required) provider_sig that verifies under
     grant.provider_id. Count distinct receipt_ids among them: none, refusal execution_unreconciled; more than one,
     refusal execution_equivocation; exactly one, that receipt is the reconciled receipt.
     A bundle whose grant has a null or absent provider_id is therefore always refused: with a receipt, by
     execution_unreconciled here; without one, by execution_incomplete_pair. The finding open_grant from step 2a or
     step 3 is reported alongside the refusal and never on an accepted report. Prose elsewhere that calls an open
     grant "accepted" means that it passes the provider check, not the bundle verdict.

**Step 3, preflight.** No intent: nothing. An intent with no grant: refusal preflight_without_grant. Otherwise,
stop at the first failure: grant_ref recomputes (grant_recompute_mismatch); intent_id recomputes
(intent_recompute_mismatch); the intent's action binding (section 2); intent.grant_ref equals the recomputed
grant_ref (intent_unbound); declared_at is a valid timestamp (missing or null is invalid), and not_before and
not_after are valid timestamps unless null or absent (invalid_timestamp); grant.provider_id is null or equals intent.provider_id (provider_not_authorized); declared_at
is inside the window (outside_authorization_window). If all of these pass, add findings open_grant and
self_authorized under the same conditions as step 2a. Then canonical(grant.action) equals
canonical(intent.proposed_action) (action_diverged). Any failure adds one refusal preflight_invalid. Then, if
signatures are required and intent_sig does not verify under intent.provider_id: refusal
preflight_signature_invalid. Finally, if a receipt reconciled in step 2 and canonical(intent.proposed_action) differs
from canonical(reconciled.executed_action): finding declared_executed_divergence. A degenerate action on either side
(section 5, missing fields) counts as differing. Step 3 does not compare declared_at with any receipt's executed_at:
an intent declared after the execution is not refused and adds no finding; that it came first is the producer's
claim, not something this verifier checks.

**Step 4, evidence.** The target is the reconciled receipt; if none, the primary receipt; if the receipt set is
empty, skip this step. Let E be target.outcome.evidence. E absent, null or otherwise falsy: finding
no_evidence_bound. E present: it is well formed when it is an object, E.kind is one of bitcoin_tx, ledger_record,
document_sha256, url_sha256, E.ref is 64 lowercase hex characters, and E.system is a non-empty string (extra keys
are allowed). Not well formed: refusal evidence_invalid. Well formed and no lookup injected (the interop setting):
finding evidence_bound_unchecked. With an injected lookup: not found or not matching is refusal evidence_invalid,
confirmed adds nothing. This step runs even when step 2 refused, which is why a refused bundle can carry
evidence_bound_unchecked.

**Step 5, linkage.** Runs only when observations were presented AND a receipt reconciled in step 2; otherwise
neither code below is emitted. A link is an observation whose conduct.detail_ref is a string beginning with exactly
`nenrin-exec://`. For each link, the rest of the string must equal the reconciled receipt's recomputed receipt_id;
if any link names anything else (an id outside the presented set, or a presented receipt that did not reconcile):
one refusal linkage_receipt_mismatch. Both comparisons are exact on the string. A detail_ref that begins with the
prefix in any other case (for example NENRIN-EXEC://) is not a link. The rest must be the 64 lowercase hex
characters of the recomputed receipt_id; the same id in uppercase names something else and gives
linkage_receipt_mismatch. If there are no links at all: finding no_digest_link. A wrong link is still a
link, so a mismatch and no_digest_link never appear together.

**Step 6, verdict.** refused if the refusal list is non-empty, otherwise accepted. Findings are reported whatever
the verdict.

## 4. The verdict signature
{ verdict, refusals: the sorted set of refusal codes, findings: the sorted set of finding codes }. Codes are
compared as sets; a code that occurs more than once in a report (for example delegation_observation_invalid for
two bad observations) counts once. Reasons are reported for readers and are not part of the signature.
How many times a report lists a code is not part of the signature either. The reference lists a code once per step
that adds it: a self-authorized grant with an intent gives self_authorized from step 2a and again from step 3, and
a report that lists it once is equally conformant (clarified 2026-10-09, reported by @kuangmi-bit).

## 5. Edge rules (outside the corpora, pinned so two implementations agree)
These follow the reference verifier (sdk/nenrin_verify.mjs, a JavaScript runtime). Where the reference has a known
weakness it is said so, with the fix. The rules added on 2026-10-12 (open grant, missing fields in R1, action_binding
case, window edges, intent order, observation order, outcome shape, closed evidence kinds, link case, Unicode
normalization, R4 distinctness) each have a bundle in ../conformance-v0/pinned/, with the signature the reference
gives in its expected.json; reproducing those is a check you can run, not part of the conformance condition at the
top of this file. Non-canonical numbers (section 2) have no bundle there, since no verdict signature is defined for
them.
- **Input.** The verifier receives the bundle as a parsed JSON value (RFC 8259). Numbers are values, so the token 1.0
  is the integer 1 and -0 is 0; a duplicate key keeps the last value. Refusing duplicate keys and non-integer number
  tokens before parsing is the ledger's ingress rule (strict JSON: duplicate_key, non_integer_number, unsafe_number,
  key_not_printable_ascii, bad_json), not part of the offline verdict signature.
- **Null and absent.** A bundle key whose value is null, false or absent is treated as not presented (grant, receipt,
  intent). observations and receipts that are not arrays are treated as empty. grant.provider_id, not_before and
  not_after: null and absent mean the same (no provider named, no bound). prev_evidence_id at seq 0 must be exactly
  null; absent fails root_prev_not_null.
- **Malformed records (settled 2026-10-04, interop-v0.2/edge).** A record slot (grant, receipt, intent) whose value
  is present but neither an object nor null/false, and an element of observations or receipts that is not an
  object, is malformed. It adds one refusal in its own step, with reason record_not_object: an observations element
  adds delegation_observation_invalid; a grant, receipt or receipts element adds execution_invalid; an intent adds
  preflight_invalid. In every other respect it is not presented: it is not consulted by step 0, R3, R4 or linkage,
  it does not enter the receipt set, and the rest of the procedure runs as if the slot were null (so a grant with
  receipts [5] is also execution_incomplete_pair). A list that holds only malformed elements still counts as
  presented for the purposes of step 1's no_delegation_observations finding and step 5's precondition. The rule is
  fail-closed on purpose: malformed input never yields accepted, and a producer that emits receipt: 5 is told so.
  The reference applies this from nenrin-verify 0.4.4 (verifier_version 0.1.6); before, it threw on a non-object
  observation and read a non-object record as a record.
- **Missing fields inside a record.** Any field missing from a record stays missing in its preimage (it is not
  turned into null). If grant.action or the receipt's executed_action (or the intent's proposed_action) is missing,
  null, false, 0 or "", E1 (or the preflight action check) fails with reason action_diverged, so step 2 adds the
  refusal execution_invalid (step 3: preflight_invalid); action_diverged is a reason, not a code in the signature.
  The same rule decides step 3's last comparison: when an intent is present and a receipt reconciled, a degenerate
  intent.proposed_action or reconciled.executed_action makes the two differ, and step 3 adds the finding
  declared_executed_divergence. The reference uses one equality for all three comparisons (actionsEqual).
  This holds even when both sides are the same degenerate value (null against null, 0 against 0). An empty object {}
  is not degenerate: it is an action like any other and is compared canonically, so {} against {} passes E1. An edge whose task_id or hop is
  missing cannot be canonicalized, so edge_sig does not verify. hop.seq must be a JSON integer; any other JSON value
  (a string such as "0", null, a boolean, an object) fails R3 with seq_gap. Since numbers are values, the token 0.0
  is the integer 0 and passes. A non-integer number (1.5) or an integer beyond 2^53-1 cannot be canonicalized, so
  the record cannot be checked (section 2, canonical form).
- **Missing fields in R1.** A missing witness_id, hop.from or hop.to is a value of its own: two missing fields are
  equal, and a missing field differs from every present value, null included. So an observation with neither
  witness_id nor hop.from fails R1 (witness_not_independent), one with witness_id null and hop.from null fails R1,
  and one with witness_id missing and hop.from null passes R1 and is decided by the later checks. With signatures
  required, an observation without a resolvable witness_id never verifies; with require_signatures false, R1 is
  all that stands between it and acceptance, which is a known weakness of v0 (a later version may require
  witness_id to be a non-empty string).
- **Order and repetition of observations.** The order of observations changes no code: R3, R4 and linkage are
  computed over the set, and "in order" in step 1 only fixes the order reasons are listed in. Observations are not
  deduplicated. An observation presented twice is checked twice; being identical, it adds nothing the first did not
  (same evidence_id, same verdict, so no witness_disagreement).
- **R4 distinctness.** conduct.verdict is a string, and two verdicts are distinct when the strings differ. At one
  seq, all missing verdicts together count as one value, which differs from every present verdict, null included:
  two witnesses that both omit conduct.verdict do not disagree, and one that omits it disagrees with one that gives
  "pass" or null. Non-string verdicts are outside the corpora; the reference compares null, booleans and numbers by
  value (1 and 1 agree, 1 and "1" differ) and objects and arrays by identity, so two equal object or array verdicts
  still count as distinct and give witness_disagreement. That last point is a known weakness; the fix, comparing
  canonical forms, would change findings and needs a new verifier_version.
- **Empty task_id.** task_id_mismatch needs at least one record; an empty task_id with no records gives
  task_id_missing only.
- **Evidence presence.** E is absent when it is missing, null, false, 0 or "" (no_evidence_bound). An empty object or
  array is present and not well formed (evidence_invalid). A missing outcome, or an outcome that is not a JSON
  object (an array, string, number, boolean or null), means E is absent; an array has no evidence member in either
  reading. The kind list in step 4 is closed and compared exactly: any other string, including one that differs
  only in case or surrounding spaces, makes E not well formed (evidence_invalid). A new kind needs a new version of
  this file.
- **Timestamps.** The pattern uses ASCII digits only and matches the whole string (no trailing newline). Instants are
  compared at millisecond precision, extra fraction digits truncated. A conforming verifier MUST reject impossible
  calendar dates (proleptic Gregorian, years 0001 to 9999), hour 24 and second 60. The reference applies this rule
  from nenrin-verify 0.4.1; earlier versions read the instant with the runtime's date parser, which accepted some
  impossible values (2026-02-30 rolled to 2026-03-02, hour 24, year 0000) and rejected second 60. No corpus vector
  depends on it. A window with not_before equal to not_after is valid and holds exactly that instant, so t equal to
  both is inside it. A window with not_before later than not_after is not malformed; no instant is inside it, so
  the check fails with outside_authorization_window.
- **Base64.** A conforming verifier MUST accept only canonical standard base64 (RFC 4648 section 4: the standard
  alphabet, padding present, no whitespace, unused trailing bits zero), so one signature has one encoding. The
  reference applies this rule from nenrin-verify 0.4.1; earlier versions decoded leniently (missing padding, - and _,
  ignored characters) and accepted such strings. No corpus vector depends on it.
- **Ed25519.** Verification as performed by OpenSSL (RFC 8032 with OpenSSL's checks), with one rule added on the
  key: a public key resolves only if it is the canonical encoding (y < p, and not x = 0 with the sign bit set) of a
  point P of the prime-order subgroup (P is not the identity and L * P is the identity, L = 2^252 +
  27742317777372353535851937790883648493). Otherwise no signature under it verifies. This refuses small-order keys,
  under which OpenSSL accepts R = the identity point, S = 0 on every message with no private key, and mixed-order
  keys A + T, which A's private key can sign for while the string differs from A, so one key could pose as a second,
  independent party (R1). The agreement verifier (agreement-v0) applies the same subgroup rule. The reference applies
  it from nenrin-verify 0.4.2 (verifier_version 0.1.5). Non-canonical signatures (S >= L, a non-canonical R) are
  refused by OpenSSL. None of these are in the corpora.
- **Key resolution.** In the offline interop setting only did:key resolves, and only to a key the Ed25519 rule above
  accepts. Parties named by an https origin need an injected resolver, which is outside the corpora; without one
  their signatures do not verify.
- **require_signatures.** Only the literal false disables signature checks.
- **Unknown bundle keys** are ignored.

## 6. What this does not cover
Ledger-side behaviour (publication consent, HTTP status codes), stateful nonce uniqueness, and the injected lookup's
own semantics. None of these affects an offline verdict signature.

## 7. How to cite
Oga, T. (2026). NENRIN provenance verifier: normative procedure (VERIFIER.md), interoperability vectors and reference verifiers (nenrin-verify 0.4.4). Zenodo. https://doi.org/10.5281/zenodo.23136978

The deposit fixes this text as of nenrin-verify 0.4.4, the interop-v0 and interop-v0.1 vectors with their expected
verdict signatures, and the npm and PyPI packages byte for byte. An implementation that reproduces the vectors can
name the DOI as what it was checked against. Later versions of this text become new versions of the same record.
