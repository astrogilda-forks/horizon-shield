# MUSUBI reference sampling, profile v0: a spot check of a reference dataset that its provider cannot steer

Status: draft, revision 0. Reference verifier `refsample_v0.py`, tool `refsample_tool.py`, vectors `vectors/vectors_refsample_v0.json` (29 settlements, 8 bounds). Built on the companion for cA2A, profiles v0 and v0.1, which are unchanged. Two adversarial rounds before publishing (NOTES.md, Reference sampling v0).

## 1. Why

The pilot of horizon-shield Issue #51 binds four records to one request occurrence: the buyer's budget, the payment, the responder's execution receipt and an independent checker's acceptance record. The audit the responder returns carries, on every line, the SHA-256 of the dataset its verdict was computed from. An acceptance record can therefore show that the audit agrees with that dataset. Nothing in the chain shows that the dataset agrees with the world, and the provider of the dataset is the one party nobody can simply ask.

Every service that answers from a reference (a price list, a cost database, a sanctions list, a model registry) has the same root. The usual answer is an audit of a sample, and the usual weakness of a sample is that someone chose it.

## 2. What this profile adds

A sample nobody chooses. The provider fixes, before a Bitcoin block it has not seen exists, which dataset is sampled, at what rate and by whom; the block's hash then picks the rows; checkers the relying party accepts check those rows against their sources; a verifier recomputes everything from bytes and states a bound.

Bitcoin does a different job here than in the rest of MUSUBI. It is not a clock. It is a public value that nobody, the provider included, can choose: the provider would have to out-mine the network to steer the sample. A transparency log does not offer that; a randomness beacon such as drand does, and could replace the block hash under the same rules.

## 3. Objects

**Commitment** (signed by `provider`): `type` `musubi.refsample.commitment.v0`, `provider`, `dataset_id` (printable ASCII, no spaces), `dataset_sha256`, `row_count`, `row_rule`, `file_sha256` (null only for the `jcs-sha256` rule), `rate_ppm` (1 to 1,000,000), `draw_height`, `checkers` (1 to 8 distinct keys the provider proposes, not the provider), `seen_block` (a block the provider had seen; `draw_height` must be above it), `signature`.

**Check** (signed by `checker`): `type` `musubi.refsample.check.v0`, `checker`, `commitment_sha256`, `row_sha256`, `verdict` (`match`, `mismatch`, `unreachable`, `not_checkable`), `evidence` {`url`, `sha256` of the source bytes the checker read, `locator` inside them; each may be null}, `seen_block`, `signature`.

**Policy** (the relying party's, never read from the bundle): `type` `musubi.refsample.policy.v0`, `lower_bound` (a block the relying party knows), `max_target_bits` (the easiest difficulty it accepts), `min_depth`, `checkers` (1 to 32 keys it accepts), `quorum` (how many of them must say match), `min_sampled` (the smallest sample it accepts), and, when the commitment is logged, `companion_trust` (its trust in that log, profile v0.1; its chain settings must equal the policy's). The settlement carries the policy's digest and its chain settings, so a reader sees what was assumed.

**Rows.** A row rule turns the published file into rows:

| rule | rows |
|---|---|
| `json-pointer-array:<RFC 6901 pointer>` | the elements of the array at the pointer (the rule is printable ASCII, so the pointer is too). UTF-8, no BOM, no duplicate keys, no NaN or infinities, integers and floats below 2^53 in magnitude |
| `csv-header-rows` | the records as Python's `csv` reader with `strict=True` reads UTF-8 text without BOM, fields up to 131,072 characters; the first record names the fields; each further record is an object of strings; a record with another field count is refused. This is a subset of RFC 4180 with Python's tolerances (a quote inside an unquoted field is kept); a second implementation should prefer JSON files |
| `jcs-sha256` | no file: the bundle supplies the row digests, and the rows themselves for whichever rows a reader needs |

A file may hold at most 200,000 rows. A row's digest is SHA-256 of its RFC 8785 bytes. Numbers are read as IEEE doubles, so two spellings of one double (`0.3`, `0.30000000000000001`) are one value. The dataset digest is SHA-256 of `musubi.refsample.v0.dataset`, a zero byte, the rule's length as two bytes big-endian, the rule, and the sorted, de-duplicated row digests as 32-byte values. Row order and repetition in the file do not change it; `row_count` counts distinct rows; the same rows under another rule give another digest.

## 4. The draw

Let B be the hash of block `draw_height`, as 32 bytes in display order. A row with digest d is sampled when

    SHA-256("musubi.refsample.v0.draw" || 0x00 || B || d), read as a 256-bit big-endian integer, times 10^6
    is below rate_ppm times 2^256.

Each row's fate depends on nothing but its own digest and B. Adding rows cannot push a row out of the sample, and the number of sampled rows is itself random (binomial). The draw block must be in the view at the policy's minimum depth; otherwise there is no draw yet (`draw_block_not_in_view`, `draw_block_too_shallow`).

## 5. The chain the draw is read from

The relying party, not the bundle, decides which chain counts. The bundle carries a header view; the verifier accepts it only if it contains the policy's `lower_bound` and every header meets the policy's `max_target_bits`. A floor easier than Bitcoin's minimum difficulty is marked `floor_note` in the settlement: it is for test chains. That is what stops a provider from grinding a private fork at the draw block until its bad rows fall outside the sample, and from planting an anchor below the draw block for a commitment made after it.

Two things are therefore the relying party's job and are stated here because the code cannot do them: the floor must sit near the real network's difficulty at the time (a floor far below it lets a fork be mined cheaply), and the view should be compared with a header source of the relying party's own (a node, or two explorers, as `header_view_fetch.py` does) before a settlement is relied on. A miner can withhold the draw block; that costs the block reward and only buys another draw.

## 6. Fixed before the draw

A commitment binds only when it is shown to exist before block `draw_height` was mined. Three ways, and the settlement says which held:

- `direct_anchor`: a Bitcoin anchor of the commitment's digest (SHA-256 of its RFC 8785 bytes) in a block below `draw_height`. The provider makes it with OpenTimestamps (`refsample_tool.py stampable`, `ots stamp`, `refsample_tool.py compose`). No log and no witness are needed.
- `log`: the commitment is an entry of a companion log, trusted by the policy, whose checkpoint's earliest valid anchor is below `draw_height`.
- `witnesses`: the commitment was acknowledged by the policy's witnesses (the acknowledgement machinery of profile v0.1; it is not a restriction and puts no duty on the log operator) and its publication height is below `draw_height`.

Otherwise the status is `not_fixed_before_draw` and the sample proves nothing. A logged commitment whose log does not verify under the policy's trust gives `log_not_verified`.

**Several versions.** A provider could commit several versions of a dataset before the draw and show only the one whose sample came out well. The draw rule removes the cheap version (re-ordering or padding the same rows changes nothing). Against the expensive one the verifier can only list what it is shown: `other_commitments` names every other commitment in the bundle that shares the provider, the dataset id, the dataset or the file. `hedging` says `not_excluded` for `direct_anchor` and `log`, and `visible_only_if_every_version_went_through_these_witnesses` for `witnesses`: witnesses see every commitment they acknowledge, and nothing else.

## 7. Checks and the bound

A check counts when: it is for this commitment; its checker is named in the commitment and accepted by the policy (`checker_not_named`, `checker_not_accepted`) and is neither the provider nor the log operator (`checker_is_party`); its row is in the dataset and in the sample (`row_not_in_dataset`, `row_not_sampled`); its seen block is in the view and not below the draw block (`seen_block_not_in_view`, `checked_before_draw`). A malformed check is one problem row; identical check bytes count once.

Per sampled row, over the counted checks: a checker that gave the row two verdicts has `contradicted` itself. The row is `mismatch` if any accepted checker says so; else `contradicted`; else `match` if at least `quorum` accepted checkers say match; else `not_checkable`, `unreachable`, `short_of_quorum` (some match, too few), `unchecked`. Rows where checkers say different things are marked `checkers_disagree`. A mismatch from any checker the policy accepts also blocks the row when the provider did not name that checker, or when it looked before the draw: it is listed under `objections`. Leaving an accepted checker's checks out of a bundle can still make a row match when the quorum is smaller than the accepted checkers the commitment names; the settlement says whether `quorum_covers_every_accepted_checker`, and a relying party that wants omission to fail sets the quorum to all of them or collects the checks from its checkers itself. A quorum larger than the accepted checkers the commitment names gives `quorum_unreachable`.

The bound: for n sampled rows of which m were shown correct, the one-sided 95% Clopper-Pearson upper bound on the fraction of the dataset that would not be shown correct, as the smallest p in parts per million with P(X <= n - m | n, p) <= 1/20. The decision is made with exact integers (a floating-point estimate only chooses where to start). Because the sample is independent of the rows' state, the bound conditional on n is valid. The status is `settled` only with a bound; `no_bound` when n is below the policy's `min_sampled` or above 2,000.

## 8. What this proves and what it does not

It proves that the rows looked at were not chosen by the provider, that the checkers were chosen before anyone knew which rows they would look at, and how much the dataset as a whole can be wrong without the sample having shown it, at 95%.

It does not prove that the accepted checkers are honest or competent; the policy is the relying party's statement of whom it believes. It does not prove that a source read after the draw is the source the row was taken from: a provider that controls its cited sources could edit them once it knows the sample. Rows that carry the digest of their source file close that for themselves. It says nothing about a row outside the sample beyond the bound, and it counts a row nobody could check (`not_checkable`, `unreachable`, `unchecked`, `short_of_quorum`) as not shown correct. That is deliberate: a reference whose rows carry no source is a reference nobody can check, and the bound says so.

## 9. Running it

    python3 refsample_v0.py --selftest                              # 29/29 vectors, 8/8 bounds
    python3 refsample_v0.py --rows FILE RULE                        # file digest, rows, dataset digest
    python3 refsample_v0.py --settle BUNDLE.json --policy POLICY.json
                                                                    # exit 0 settled, 2 not settled, 3 unreadable or no policy

`refsample_tool.py` is the provider's and the checker's side (keygen, commit, stampable, compose, draw, check). `refsample_rehearsal.py` runs it on a real JCCDB observation file with test keys.

## 10. Vectors

`python3 gen_vectors_refsample_v0.py` rebuilds the file byte for byte (SHA-256 in NOTES.md).

| vectors | what they fix |
|---|---|
| RS01, RS02, RS15 | settled through the log, the witnesses, the provider's own anchor |
| RS03, RS04, RS16, RS17 | not fixed before the draw: anchored in the draw block, witnessed after it, stamped in it, a proof for other bytes |
| RS05, RS09, RS12, RS13 | a changed file, a draw block not yet in view, a provider naming itself as checker, a draw block already seen |
| RS06, RS22 | other commitments: a second version of the dataset; the same file under another id and draw height |
| RS07 | checks that do not count and rows that fail |
| RS08 | every sampled row not_checkable: the bound is the whole dataset |
| RS10, RS11 | CSV rows; digests only, with only the sampled rows revealed |
| RS14, RS19 | checks that do not count because of whom they come from: the log operator; a checker the policy does not accept |
| RS18 | a view easier than the policy's floor: refused |
| RS20 | a quorum of two |
| RS21 | an empty sample: no_bound |
| RS23 | a logged commitment and a policy with no trust in any log: refused |
| RS24 | one malformed check among good ones |
| RS25 | a checker the policy accepts but the provider did not name says mismatch: the row is a mismatch |
| RS26 | a quorum the named checkers cannot reach |
| RS27, RS28 | a `witnessed` field that is not a list; a signed object of another type |
| RS29 | a log signed by another operator than the policy trusts |
