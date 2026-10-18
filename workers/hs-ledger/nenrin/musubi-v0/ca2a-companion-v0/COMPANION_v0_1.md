# MUSUBI companion for cA2A, profile v0.1: publishing around the operator

Status: draft, revision 0. Reference verifier `companion_v0_1.py`, vectors `vectors/vectors_v0_1.json` (38). Profile v0 (`COMPANION_v0.md`) is unchanged; everything below is added to it, and a v0.1 bundle with no witnessed records settles exactly as v0 (all 45 v0 settlement vectors, relabeled, give the same result).

## 1. The problem v0 left open

In v0 the operator is the sequencer. Once it signs an entry, dropping or changing that entry later is provable (v0 section 7). Refusing an entry in the first place is not: the submitter has no signed entry, and the statement never takes effect. For a revocation this is the whole game. cA2A says a supplier "can withhold a statement" (docs/spec/threat-model.md line 51); in v0 the operator could do the same, silently.

v0.1 removes the operator from the path for one class of items, restrictions: revocations (`ca2a.delegation-revocation.v1`) and use limits (`musubi.ca2a.use-policy.v0`). They only narrow what is allowed, so taking them from outside the sequencer can never widen anything. Uses and receipts still need the operator's sequence (WV17).

## 2. Trust configuration

Three fields are added, all or none (WV20):

- `witnesses`: 1 to 32 distinct keys. The operator's key may not be among them (WV07).
- `witness_threshold`: 1 to the number of witnesses.
- `max_merge_blocks`: 1 to 1008. The operator must carry a witnessed restriction in any checkpoint whose `as_of` is at or after the time of the block this many blocks after the restriction's publication block (section 6).

## 3. Acknowledgement

`musubi.ca2a.witness-ack.v0`, signed by `witness`: `log_id`, `witness`, `item_sha256` (hex SHA-256 of the JCS bytes of the item, its own signature included), `seen_block` {`height`, `hash`}, `signature`, and optionally `anchor` in the settle v1.1 form (`height`, `block_hash`, `proof`), where the proof takes SHA-256 of the acknowledgement's JCS bytes without `anchor`. The signature covers the object without `signature` and `anchor`, as for a checkpoint.

A witness signs it when it has received the item and published it where relying parties can read it. Anyone can anchor it; the item's author can do so through public OpenTimestamps calendars. Neither step involves the operator.

The bundle carries `witnessed`: up to 256 records `{item, acks}`, each with 1 to 64 acknowledgements, at most 512 in all. Identical acknowledgement bytes appearing again are checked once; a copy with another anchor, or none, is a different object and is checked on its own, so the order of copies changes nothing (WV33, WV34).

## 4. When a restriction is published

An acknowledgement is ignored altogether, and listed under `ack_problems` with the reason, unless: it has exactly its fields (`anchor` optional, WV35 for a signature that is not a string); `log_id` is this log's (WV09); `witness` is a trusted witness (WV05); `item_sha256` is this item's (WV08); the signature verifies (WV25). One that passes gives up to two things, each counted on its own and each listed under `ack_problems` when it fails:

- a **lower bound**, when `seen_block` is in the view with that hash: the witness signed after that block. A seen block the view cannot check, because it is below the relying party's lower bound or was orphaned, gives none (WV11, WV36);
- an **upper bound**, when the anchor block is in the view with that hash, the proof reaches its merkle root (WV10), the anchor has at least `min_depth` confirmations (WV21) and `seen_block` is below the anchor block: the witness had signed by that block.

The two parts bound different things, and neither is required for the other. Requiring the anchor for the lower bound would let slow anchoring of a witness's acknowledgement, or a shorter view, turn a possible revocation into a certain absence (WV31); requiring a checkable seen block for the upper bound would let an old lower bound, or a reorg at the witness, make a published revocation vanish (WV36).

The item must parse as in v0 and be a restriction (WV17). Acknowledgements are pooled by `item_sha256` across records (WV26), and each witness counts once (WV06). For each witness take its lowest seen height over its acknowledgements with a lower bound and, separately, its lowest anchor height over those with an upper bound. With `t` the threshold:

- `earliest` is the t-th lowest of the seen heights, or null when fewer than t witnesses give one: t witnesses had not all signed before that block was seen.
- `published` is the t-th lowest of the anchor heights, or null when fewer than t witnesses give one: by that block, t witnesses had signed (WV32 has no upper bound; WV36 no lower bound).

Taking both numbers from one acknowledgement per witness would not bound both, because a witness's later acknowledgement can be anchored sooner than its earlier one (WV27). Fewer than t witnesses giving either bound is `too_few_witnesses` (WV04), and the restriction does not exist for this settlement. The settlement lists, per restriction, the witnesses that signed and those whose anchor counted.

A witnessed revocation with a `published` block, dated more than 7200 seconds after that block's time, is kept and flagged `revocation_dated_after_witnessing` (WV22), as v0 does for a revocation dated after its logging.

## 5. Order against a receipt

A receipt that v0 would assess was signed after its `seen_block` (height S) and existed by the block that anchors the checkpoint (height A). A checkpoint can be anchored more than once by anyone who holds it, so the bundle may carry, under `log.extra_anchors`, up to 16 further anchors of the same checkpoint; each that verifies like the main one (block in the view, proof, `min_depth`) lowers A to the earliest valid anchor (WV37). A relying party or responder that saw the checkpoint anchored early keeps that anchor, so that a later re-anchoring by anyone cannot widen the window (finding 4 of the second review). A witnessed restriction is:

- **before** the receipt when `published` is not null and `published` ≤ S;
- **after** it when `earliest` is not null and `earliest` ≥ A;
- **unresolved** otherwise, including every restriction without the bound the case needs (WV32, WV36 against a receipt anchored later).

A responder fixes S before it consults the witnesses. A restriction anchored in the very block it then names is before the receipt; the responder had the chance to see it.

Revocations: those logged before the receipt (v0) and the witnessed ones before it are in force for `ca2a_at_execution`, by cA2A's own revocation check with every one of them in force. If that passes, the check is run again with the unresolved ones added; if that one finds the credential revoked, the reason is `revocation_order_unresolved` (WV12, WV27). `ca2a_audit` uses every revocation, logged and witnessed, by cA2A's audit semantics (WV13, WV14). A witnessed revocation without cA2A authority changes nothing (WV18).

Use limits: a policy counts for a receipt when logged before it (v0) or witnessed before it (WV15). If adding the unresolved policies would add a reason, the reason is `use_policy_order_unresolved` (WV24). A witnessed policy is still only a limit when signed by the hop's issuer (WV16).

Dispositions: `within_delegation` with no reason. `outside` when any reason other than `revocation_published_late`, `revocation_order_unresolved` and `use_policy_order_unresolved` is present. Otherwise `order_unresolved` if either unresolved reason is present, else `late_revocation_only`.

`order_unresolved` is not within. A responder that names an old seen block, or whose receipt is anchored slowly, widens its own unresolved window; it cannot turn a revocation it might have seen into a within verdict (WV12).

## 6. Omission is provable

The operator signs a checkpoint knowing its `as_of`; the block that anchors it is not when it signed, since anyone holding the signed checkpoint can anchor it again later (WV30). So the rule is on `as_of`. For each restriction with a `published` block, let `due` = `published` + `max_merge_blocks`. The settlement reports `omission_check` per restriction: `carried` when the item's exact bytes are an entry of the log (WV03), `due_block_not_in_view` when the view ends before `due` so the check could not be made (WV38), `not_yet_due` when `as_of` is before the due block's time (WV01, WV29), and `omitted` when it is at or after it, which also lists `operator_omitted_witnessed_item` under `operator_findings` with the item digest, the two heights, the due block's time and `as_of` (WV02, WV28, WV34). A restriction without an upper bound charges nothing (WV32).

The comparison is on bytes: the operator discharges the rule by logging what the witnesses published, not a variant of it that a submitter handed it directly. An operator that logs every restriction it receives and every one the witnesses publish is never reported.

The evidence is portable: the acknowledgements are signed by the witnesses and anchored, the checkpoint is signed by the operator with its `as_of`, and the entries are verified against it. The operator cannot answer that it was never told: under this profile the witnesses' publication is the delivery. An operator that keeps `as_of` low to avoid the rule publishes a stale checkpoint, which a relying party can see and refuse.

## 7. What changed, and what did not

v0's refusal case is now covered in two ways. The restriction takes effect at its witnessing height whatever the operator does (WV01, WV15), so refusing gains the operator nothing; and leaving it out past the delay is shown by signatures (WV02).

What remains:

- **The bundle is the relying party's collection.** The verifier judges what it is given. A bundle assembled by the operator, or by anyone who drops witnessed records or single acknowledgements, settles as if those statements did not exist, and a dropped lower bound can turn unresolved into a definite after (WV31 with the third acknowledgement removed). "Whatever the operator does" therefore holds for a relying party that fetches acknowledgements from each trusted witness itself and includes every one it receives. The settlement names the witnesses it counted, so a reader can see which trusted witnesses are absent from a restriction; it cannot see a restriction that is absent altogether.
- **Threshold honesty, both ways.** If every trusted witness sides with the operator, or signs without publishing, a refused restriction is silent again. In the other direction, t witnesses that sign a statement nobody could have read, or a single witness when the threshold is 1, produce a finding the operator cannot avoid, and the lane accepts restrictions that carry no authority (WV16, WV18): they limit nothing, but a carried-or-reported rule applies to them too. A witness is therefore expected to sign only statements it has authenticated and published, and the threshold is expected to be above 1. Choosing witnesses and the threshold is the relying party's decision; the verifier only reports under which configuration it counted.
- **Uses and receipts.** They still need the operator. Refusing a use stops the relying party from acting (denial of service), but cannot make an action look allowed. Refusing a receipt leaves the responder holding its own signed receipt.
- **Block granularity.** Order is decided by block heights, about ten minutes each, plus the anchoring delay. Inside that window the answer is `order_unresolved`, never a guess.
- **No witnesses run today.** This revision specifies the lane, its verifier and its vectors. Witness operators independent of The HORIZONs Co., Ltd. still have to be found.
- **Cost.** Every receipt rebuilds cA2A's revocation snapshot over the revocations before it and, when any is unresolved, once more; cA2A verifies each statement's signature when a snapshot is built. With hundreds of revocations and hundreds of receipts a settlement takes seconds. The counts are bounded by the log and the lane, both of which the relying party chose to read.
- **`--settle` exit codes.** 0 for a settlement with receipts, 2 when the bundle is refused or the log does not verify, 3 when the file cannot be read; the same in `companion_v0.py`.
- Everything in v0 section 8 still applies, including no hardware claim.

## 8. Running a witness

A witness needs no server and no part of this code base beyond one file. `witness_ack.py` (dependencies: `cryptography`, `rfc8785`) makes a key, prints an item's digest, signs an acknowledgement over a block the witness has seen, and checks one. The witness publishes the item and the acknowledgement anywhere public and stable (a git repository is enough); anchoring is anyone's job and can be done later with OpenTimestamps. A relying party that names the witness's key in its trust configuration, with the threshold it wants, then counts that witness.

What is asked of a witness, and nothing more: sign only restrictions it has received and published, name the newest block it has seen, and keep what it signed where it published it. Independent witness operators are sought in horizon-shield Issue #50.

## 9. Vectors

`python companion_v0_1.py --selftest` reruns all 38. `python gen_vectors_v0_1.py` rebuilds the file byte for byte and then checks two inputs no vector file can hold (a lone surrogate in a request and in a credential: refused as `lone_surrogate`, never raised); its SHA-256 is in NOTES.md. The test chain gives each block a time ten minutes after the one before, so `as_of` can fall on either side of a block.

| id | what it shows |
|---|---|
| WV01 | the operator never logs the revocation; witnessed before the receipt's seen block, the execution is after a published revocation |
| WV02, WV28, WV29, WV30 | omission past the merge delay is a finding; WV28 at the exact second, WV29 one second before; WV30 a checkpoint anchored again later is not framed |
| WV03 | a carried witnessed revocation: no finding, log seq reported |
| WV04 to WV06 | below the threshold: one witness, an untrusted key, one witness three times |
| WV07, WV19, WV20 | the operator as a witness is refused; records with no witnesses trusted are rejected; an incomplete lane is refused |
| WV08, WV09, WV25, WV35 | acknowledgements ignored altogether: another item, another log, altered after signing, a signature that is not a string |
| WV10, WV21, WV31, WV32 | anchors that do not count still leave the lower bound: a moved anchor, too shallow, a slow third witness, nothing anchored; each gives unresolved, never within |
| WV11, WV36 | seen blocks the view cannot check still leave the upper bound: the witnesses had signed by their anchor |
| WV33, WV34 | identical copies are checked once; copies in any order give the same bounds |
| WV37 | the earliest valid anchor of the checkpoint bounds the receipts |
| WV38 | a view that ends before the due block: the omission check is reported as not possible |
| WV12 | a stale seen block gives order_unresolved, not within |
| WV13, WV14 | witnessed only after the receipt was anchored: no effect at execution; late_revocation_only when backdated |
| WV15, WV16, WV24 | a refused use limit still applies; a non-issuer's limit does not; an unresolved one is reported |
| WV17, WV18 | only restrictions use the lane; a revocation without cA2A authority changes nothing |
| WV22 | dated hours after its witnessing: kept, flagged, in force by block order |
| WV23, WV26, WV27 | the earliest witnessing counts; acknowledgements pool across records; a later acknowledgement does not hide an earlier one |
