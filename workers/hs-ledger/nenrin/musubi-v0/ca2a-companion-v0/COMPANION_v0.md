# MUSUBI companion for cA2A, profile v0

Status: draft, revision 0. Reference verifier `companion_v0.py`, vectors `vectors/vectors.json` (45 settlement vectors, 12 evidence vectors). Every delegation credential and revocation statement in the vectors is built and signed by cA2A's own library, `ca2a_runtime`. The selftest passes against agentrust-io/ca2a at commit 305fedc and against the PyPI release ca2a-runtime 0.4.0.

## 1. What this is

cA2A verifies a delegation chain at the moment of a call. Its own documents list what it does not do around that check: it does not publish revocations, it keeps no record of credential use across requests, its response authentication is a session MAC that only the live caller can check, and its provenance path can be rewritten by anyone who recomputes the hashes.

This profile is the evidence layer for those gaps. It takes cA2A objects as they are, with no new field in any of them, and adds signed statements that a third party can check offline after the fact, ordered in a log whose checkpoints are anchored in Bitcoin.

The delegation rules stay cA2A's. The verifier never reimplements them: every chain is judged by `ca2a_runtime.delegation.verify_chain` and cA2A's own revocation check, with a snapshot built from the log. The one rule added on top is ordering: a revocation logged before a receipt is in force for it, whatever its `issued_at` says. cA2A's audit verdict, which goes by `issued_at`, is reported beside it.

It is a companion, not a replacement. Nothing here competes with cA2A's attestation, sealed channel or live authorization.

## 2. The gaps, in cA2A's own words

All citations are agentrust-io/ca2a at 305fedc.

| cA2A says | Where | This profile |
|---|---|---|
| "cA2A defines no protocol for publishing or fetching revocation statements." A supplier "can withhold a statement". | docs/spec/delegation-chain.md line 165; LIMITATIONS.md line 42; docs/spec/threat-model.md line 51 | Revocations are log items. Each entry is signed by the operator at submission; a later log that omits or changes it is shown by two operator signatures (section 7). `as_of` is signed and bounded by the anchoring block. |
| "The offline verifier has no global used-credential database, so those checks do not establish single-use credentials across requests." | docs/spec/failure-modes.md line 37 | Credential-use items that carry their whole chain, signed by the holder. An issuer-signed limit on a credential counts every use of it, under any chain that contains it and with any responder. |
| "It does not sign the execution lineage or create third-party-verifiable receipts." | docs/spec/response-authentication.md lines 8 and 9 | Execution receipts signed with an Ed25519 key, naming the full lineage, the capability, the request occurrence and the outcome. |
| "not request-execution deduplication, portable signed receipts or confidential output encryption" | LIMITATIONS.md lines 33 and 34 | Deduplication of results per responder and request occurrence. Portable receipts. Confidential outputs are not in v0. |
| "A successful authorization record does not establish that payload opening or application execution succeeded." | docs/spec/failure-modes.md line 39 | A receipt separates the responder's statement of outcome (result, denial or ack, and the stage) from the authorization. It is still the responder's statement, see section 8. |
| "Hash links alone do not prevent an attacker from rewriting the records ... An authenticated external commitment or signed records are needed" | docs/spec/provenance-dag.md line 41 | The log is signed and its head is anchored; a rewrite after the anchor is detected. |
| Simultaneous attestation "needs a commitment step neither peer can back out of" | ROADMAP.md line 44; docs/spec/mutual-attestation.md line 250 | Commit and reveal items in a session whose identifier binds its participants. |

## 3. Encoding

- Every signed object is a JSON object canonicalized with RFC 8785 (JCS), the scheme cA2A uses.
- Keys are raw Ed25519 public keys in lowercase hex (64 characters); signatures are Ed25519 in lowercase hex (128 characters), as in cA2A.
- A signature covers JCS of the object without its `signature` field and, for a checkpoint, without `anchor`.
- Every object carries a `type` string for domain separation. Types of this profile begin with `musubi.ca2a.`; a revocation keeps cA2A's own type `ca2a.delegation-revocation.v1`.
- Parsing is strict: no duplicate keys, no NaN or Infinity, no floats, integers within plus or minus 2^53 minus 1, exact field sets. Every hex and identifier pattern must match the whole string; a trailing newline is not hex.
- A credential is named by cA2A's `credential_digest`: `sha256:` and the hex SHA-256 of the credential's canonical signed body. A lineage is the list of these digests, root first.

## 4. Objects

**Request occurrence** (hashed, not logged): `type` `musubi.ca2a.request.v0`, `caller`, `responder`, `lineage`, `capability`, `occurrence_id`, `task_sha256`, optional `session_id`. `request_sha256` is the hex SHA-256 of its JCS bytes. Both sides commit to the same bytes, so a record ID alone never stands for a request.

**Log entry**: `type` `musubi.ca2a.log-entry.v0`, `log_id`, `operator`, `seq` (from 0, no gaps), `prev` (hex SHA-256 of the JCS of the previous entry including its signature; null at seq 0), `logged_at` (non decreasing), `item`, `signature` by `operator`.

**Checkpoint**: `type` `musubi.ca2a.checkpoint.v0`, `log_id`, `operator`, `size`, `head` (digest of the last entry, null when empty), `as_of`, `signature` by `operator`, `anchor`. The anchor is the settle v1.1 form: `height`, `block_hash`, `proof`, where the proof takes SHA-256 of the checkpoint's JCS bytes without `anchor` to the merkle root of that header.

**Items**

| type | signed by | fields |
|---|---|---|
| `ca2a.delegation-revocation.v1` | the revoker | cA2A's RevocationStatement, unchanged |
| `musubi.ca2a.use-policy.v0` | `issuer` | `credential_digest`, `max_uses` (at least 1) |
| `musubi.ca2a.credential-use.v0` | `holder` | `chain` (the cA2A credentials, root first, unchanged), `responder`, `request_sha256` |
| `musubi.ca2a.execution-receipt.v0` | `responder` | `caller`, `lineage`, `capability`, `request_sha256`, `seen_block` {`height`, `hash`}, `outcome` {`kind`: result, denial or ack; `stage`; `response_sha256`, required for result}, `attestation_sha256` (digest of the evidence the caller appraised, or null) |
| `musubi.ca2a.commit.v0` | `committer` | `session_id`, `participants` (2 to 16 keys, sorted, unique, the committer among them), `session_nonce`, `commitment` |
| `musubi.ca2a.reveal.v0` | `committer` | `session_id`, `evidence_sha256`, `salt` |

`session_id` is the hex SHA-256 of JCS of {`type`: `musubi.ca2a.session.v0`, `participants`, `nonce`}, so a key outside the participants cannot join a session, and nobody can start a different session under the same identifier.

A commitment is the hex SHA-256 of JCS of {`type`: `musubi.ca2a.commitment-preimage.v0`, `session_id`, `committer`, `evidence_sha256`, `salt`}.

`seen_block` is a Bitcoin block the responder had seen when it signed. It gives the receipt a lower bound in time that does not depend on the operator.

## 5. Accepting a log

The verifier holds a trust configuration: `log_id`, `operator`, `root_issuers` (a non empty list of keys), a Bitcoin `lower_bound` (height and hash), `max_target_bits`, `min_depth` (at least 1), optional `max_depth`. A malformed configuration or bundle is refused with a code (`refused`), never raised.

The log is accepted only if all of these hold, in this order, and the first that fails is named:

1. The checkpoint has exactly its fields, names this log and operator, and its signature verifies.
2. The number of entries equals `size`.
3. Each entry has exactly its fields, names this log and operator, has `seq` equal to its position, `prev` equal to the digest of the entry before, `logged_at` not before the previous entry and not after `as_of`, and a valid operator signature.
4. `head` equals the digest of the last entry.
5. Every header in the view is exactly 160 lowercase hex characters. The view is accepted by settle v1.1's `verify_view` under `lower_bound` and `max_target_bits`; the anchor's block is in it with that hash; the proof reaches that header's merkle root; the block has at least `min_depth` confirmations.
6. `as_of` is not later than the anchoring block's time plus 7200 seconds.

A failure stops the settlement: no receipt is judged on an unaccepted log.

## 6. Settling

Each item is checked on its own (shape and its author's signature). A use item is also checked by cA2A: its chain must verify at the entry's `logged_at` (without revocation), and its holder must be the leaf's subject. An item that fails is listed in `items_rejected` with the reason and ignored.

A revocation whose `issued_at` is later than its entry's `logged_at` is kept and listed in `items_flagged`. It is not dropped: dropping it would let the operator void a valid revocation by logging it a few seconds early.

For each receipt, in log order:

1. Its own use is the first use logged before it with the same lineage, `request_sha256` and `responder`. The chain is that use's chain; without one, a supplied chain with exactly the lineage (a copy whose signatures verify is preferred). Without either, or if `seen_block` is not in the view with that hash, the disposition is `unassessed`. Nothing is guessed.
2. `seen_block` must be below the anchoring block (`seen_block_not_before_anchor`), and the entry's `logged_at` must not be more than 7200 seconds before that block's time (`logged_before_seen_block`).
3. `caller` must be the leaf's subject (`caller_not_leaf_subject`), and `capability` must be in the leaf's scope (`capability_not_in_scope`).
4. If the request occurrence is supplied, its caller, responder, lineage and capability must equal the receipt's (`request_does_not_match_receipt`). Without it, `request_sha256` is an opaque commitment and `request_known` is false.
5. cA2A's `verify_chain` runs at `at_time` = the entry's `logged_at`, and gives two verdicts:
   - `ca2a_at_execution`: the chain's structure and validity windows at that time, then cA2A's own revocation check over the revocations logged before the receipt, every one of them in force whatever its `issued_at` (the log says it was public).
   - `ca2a_audit`: `verify_chain` with every revocation in the log, by cA2A's own audit semantics, which go by the revoker's `issued_at`.

   Any cA2A refusal other than a revocation gives `outside_delegation:<cA2A code>`. A revocation at execution gives `executed_after_published_revocation`. A revocation that only the audit sees gives `revocation_published_late`, and the disposition `late_revocation_only`: the revoker dated it before the execution but did not publish it in time.
6. Use limits. A policy counts for hop i of the lineage when its `credential_digest` is that hop, it is signed by that hop's issuer, and it was logged before the receipt. The smallest `max_uses` applies. A use of a credential is one distinct pair of `request_sha256` and `responder` among the accepted uses whose lineage contains that credential, at any position and under any ancestors, numbered in log order, whoever the holder. Delegating onward, re-issuing an ancestor, or sending one request to several responders does not reset a limit. The receipt needs its own use (`use_not_logged_before_execution`), and its rank must be within the limit (`use_limit_exceeded`).
7. A second `result` receipt from the same responder for the same `request_sha256` gives `duplicate_execution`. A denial is not an execution.

No reason gives `within_delegation`. It means: cA2A accepts the chain at the logged time, the capability is in the leaf's scope, the limits and the revocations published before the receipt allow it, and the times are consistent with the blocks. It does not mean the work was done. Otherwise the disposition is `outside`, with every reason listed.

Sessions: the participants come from the session identifier. Only their first commit and first reveal count; anything else is ignored. The session is `simultaneous` when every participant committed and revealed, every reveal opens its commitment, and every commit was logged before every reveal.

## 7. Proving the operator cheated

The operator signs each entry when it accepts it, and returns that signed entry to the submitter. Two functions turn operator misbehaviour into evidence anyone can check from signed objects alone. Both verify the supplied entries against the checkpoint they are said to belong to before comparing anything, so neither can be steered by whoever supplies the entries; a mismatch gives `invalid_input`, never a verdict.

- `check_promise(signed_entry, entries, checkpoint)`: the signed entry must name the checkpoint's log and operator and carry the operator's signature. A checkpoint covers every entry logged at or before its `as_of`. If the checkpoint should cover the entry but its size does not reach the entry's `seq`, the result is `operator_withheld`; if it holds a different entry at that `seq`, `operator_equivocation`. A revoker who holds its signed entry can show that a later log left out, dropped or changed its revocation.
- `compare_checkpoints(a, b, entries)`: `entries` is the log of the larger checkpoint. Two checkpoints of the same size with different heads, a smaller head that is not a prefix of the larger log, or a newer checkpoint that is smaller, give `operator_equivocation`.

This is what turns cA2A's "a supplier can withhold a statement" from silent into provable: a verifier that holds an anchored checkpoint of size N knows any snapshot built from fewer than N entries is stale, and knows which statements it is missing. It does not stop an operator from refusing an entry in the first place; the submitter then has no signed entry, and must go to another log.

## 8. What this does not give

- **No hardware claim.** It does not show that the responder key lives in a TEE, or that the appraised workload is the one that signed. `attestation_sha256` only carries the digest of the evidence the caller appraised; binding the Ed25519 receipt key into the attestation report data is cA2A's or the deployment's work.
- **No truth of results.** A receipt proves who asserted what, in which order relative to other logged statements, no earlier than its seen block and no later than the anchoring block. It does not prove the work was done or done correctly.
- **Times inside that window are the operator's.** `logged_at` decides validity windows in cA2A's check. It is bounded below by the seen block (within the two hours Bitcoin allows in block times) and above by the anchor, and nothing tighter.
- **Detection, and prevention only through the sequencer.** Single use across requests is prevented only for a relying party that logs the use and waits for the operator's signed entry before acting. Everything else is detected after the fact. The operator is the sequencer; its rewriting is provable (section 7), its refusal to accept is not. Independent witnesses and more than one log are v1.
- **Freshness is the anchor's latency.** A checkpoint is anchored only after the next stamping round and the confirmations required. Until then a verifier relies on the operator's signature alone.
- **The log is public.** Keys, credential chains, request digests, capabilities and outcome kinds are visible to anyone. Do not log what the parties do not want seen.
- **Scale.** v0 is a hash chain; a verifier reads the whole log. A Merkle tree with inclusion and consistency proofs (RFC 9162 style) is planned for v1.
- **Not in v0:** confidential outputs (planned with RFC 9180 HPKE from a standard library, with the ciphertext hash in the receipt) and an A2A interoperability report.

## 9. Against cA2A's response requirements

cA2A's docs/spec/response-binding-requirements.md lists RESP-001 to RESP-014 and leaves open the choice between live-caller and portable authentication. The receipt here is the portable option:

| ID | Status in this profile |
|---|---|
| RESP-001 valid response with bound context | yes: responder, caller, lineage, capability, request occurrence and outcome are signed |
| RESP-002 contents changed | yes, by the relying party comparing the response bytes with `response_sha256` |
| RESP-003 proof from another responder | yes: the use names its responder (CA35), and a supplied request must match (CA15) |
| RESP-004 moved to another request with a reused record ID | yes: `request_sha256` commits to the whole occurrence |
| RESP-005 moved across sessions or recipients | partly: `caller` is bound; `session_id` is optional in v0 and a strict policy should require it |
| RESP-006 missing proof under strict policy | relying party policy, outside the verifier |
| RESP-007 kind or status substituted | yes (CA14) |
| RESP-008 replayed response | yes for results, by log order (CA03) |
| RESP-009 restart or lost replay state | yes: the state is the anchored log, not process memory |
| RESP-010 signed denial against unsigned error | yes: a denial receipt is a signed statement (CA16) |
| RESP-011 timeout after submission | partly: the log shows whether any receipt was ever made; the use ledger blocks a blind second use |
| RESP-012 duplicate fields, ambiguous encoding | yes: strict parsing, exact field sets, whole-string patterns (CA34) |
| RESP-013 key rotation without binding to the workload | no: needs the attestation binding in section 8 |
| RESP-014 confidential output | no: not in v0 |

## 10. Vectors

`python companion_v0.py --selftest` reruns all 57. `python gen_vectors.py` rebuilds the file byte for byte; its SHA-256 is in NOTES.md.

| id | what it shows |
|---|---|
| CA01 | a single-use credential, one logged use, one receipt: within |
| CA02 | the same credential used for a second request: `use_limit_exceeded` (cA2A alone cannot see this) |
| CA03 | two result receipts for one request: `duplicate_execution` |
| CA04, CA28 | a revocation of the leaf, or of an ancestor, logged before the execution |
| CA05 | a revocation dated before the execution but logged after it: `late_revocation_only` |
| CA06 | the leaf's own subject tries to revoke: no authority, within |
| CA07, CA08, CA09, CA29 | cA2A's own refusals: scope escalation, untrusted root, expiry at log time, forged hop signature |
| CA10, CA15 | caller is not the leaf subject; the request names another responder |
| CA11, CA12 | the use was not logged, or logged after the execution |
| CA13 | no use and no chain: unassessed |
| CA14 | the outcome changed after signing: the receipt is rejected |
| CA16 | a denial then a result is not a duplicate |
| CA17 to CA21 | log refusals: rewritten entry, withheld entry, checkpoint re-signed after anchoring, too few confirmations, `as_of` after the anchor |
| CA22, CA33 | a revocation dated after it was logged is kept and flagged; cA2A's `at_time` decides whether it applies |
| CA23 to CA25 | commit and reveal: simultaneous, a reveal before a commit, a reveal that does not open |
| CA26, CA27, CA37 | the tightest policy wins; a policy not signed by the issuer is no limit; a policy does not judge earlier executions |
| CA30, CA31 | an unknown item is rejected by name; the same use logged twice counts once |
| CA32 | a limited credential delegated onward: a use below it still counts against the limit |
| CA34 | a hex field with a trailing newline is rejected |
| CA35 | a second responder cannot execute on a use logged for the first |
| CA36 | a forged copy of a chain does not displace the copy that verifies |
| CA38 | a key outside the session cannot spoil it |
| CA39 | a capability outside the leaf's scope |
| CA40, CA41 | a receipt logged before the block it saw; a seen block the view does not hold |
| CA42 | a malformed trust configuration is refused, not raised |
| CA43 | one request sent to two responders is two uses of a single-use credential |
| CA44 | a re-issued ancestor with the same credential_id does not start a new count |
| CA45 | a revocation logged before the execution is in force by log order even when dated after it; cA2A's audit verdict is reported beside it |
| EV01 to EV05 | consistent checkpoints, equivocation at the same size, a kept and a broken promise, a newer checkpoint that is smaller |
| EV06 to EV10 | the evidence functions cannot be steered: the wrong log supplied, the fork caught in either order, edited entries, an entry signed by another key, entries of another checkpoint |
| EV11 | a checkpoint whose as_of is past a promised entry but whose size stops short of it: `operator_withheld` |
| EV12 | deeply nested input is an input error, not a crash |

CA32 to CA45 and EV06 to EV12 come from two rounds of adversarial review on 2026-10-17. The first found that a single-use limit could be reset by delegating onward, that dropping future-dated revocations let the operator void one, and that the evidence functions trusted the entries they were given. The second found that a limit could still be reset by sending one request to two responders or by re-issuing an ancestor, that a revocation logged early could lose to its own date, and that a short checkpoint could hide a promised entry. Each is now a vector.
