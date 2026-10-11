# slot-witness-v0: NENRIN as an outside reader of an issuer's one-receipt-per-request record

invinoveritas decision receipts carry a request slot since 2026-10-10: one receipt per (holder, `decider.request_id`), and
`GET https://api.babyblueviper.com/decision-receipt/slot/{request_slot}` lists the receipt that holds it
([decision-receipt SPEC, uniqueness section](https://github.com/babyblueviper1/invinoveritas/blob/main/examples/decision-receipt/SPEC.md)).
The slot closes the case of a holder who keeps an approve and a deny receipt for one decision and reveals the one that
helps (found 2026-10-10, vectors p7, p8, n13, n14 in that suite). The guarantee rests on the issuer's own record, and its
author keeps the slot log on his side. This intake is a witness of that record, not a second copy of it.

## What the ledger does

1. `POST /evidence/slot` with `{"event": <the receipt's signed NIP-01 event>}`. The ledger recomputes the event id
   (NIP-01), verifies the BIP-340 signature under the issuer key pinned in `ISSUERS`, and reads `request_slot` from the
   signed content. A receipt without `request_slot` makes no uniqueness claim and is refused as `no_request_slot`.
2. The ledger fetches the issuer's slot endpoint itself (no redirects, 10 s, at most 65536 bytes kept; 16384 until
   v0.1), keeps the
   response bytes and their sha256, and records a verdict about this receipt:

   | verdict | the slot endpoint said |
   |---|---|
   | `unique` | taken, and `event_ids` is exactly this receipt's event id |
   | `listed_with_others` | taken, lists this receipt and at least one more (or this one twice) |
   | `not_listed` | taken, does not list this receipt |
   | `not_taken` | `taken` is not true |
   | `slot_mismatch` | answered for another slot |
   | `unreadable` | not 200, not a JSON object, `event_ids` not a list of strings, or over the size cap |
   | `fetch_failed` | no answer |

3. It reads the same (slot, receipt) again about daily for 30 days. Each observation names the previous one
   (`previous_observation`, `changed_since_previous`), so a slot that later lists a different or a second receipt is
   visible next to what it listed before. `GET /evidence/slot/s/{request_slot}` returns every observation of a slot and
   `slot_listing_changed`.
4. From v0.1 (2026-10-11), when the slot is decider-scoped (decision-receipt SPEC v0.4: the slot is
   `sha256('invinoveritas.decision_receipt.slot.decider.v1|' + decider_pubkey + '|' + request_id)`), the observation
   also has a `decider` field read from the same bytes. The slot holds a `decider_claim` with `decider_sig`, and
   `conflicts` lists other claims the decider key signed for the same `request_id`. Each signature is BIP-340 by the
   receipt's `decider_pubkey` over `sha256(JCS(decider_claim))`.

   | field | meaning |
   |---|---|
   | `pubkey` | the decider key the signed receipt names |
   | `holder_claim` | the claim holding the slot: `verifies`, `bad_signature`, `other_key`, `other_slot`, `not_the_receipts_claim` (validly signed by this key for this slot, but not the claim this receipt carries), or `malformed` |
   | `conflicts_listed` | entries in `conflicts` (the first 64 are read) |
   | `conflicts_verified` | entries that name this key and slot, differ from the holder's claim, and verify |
   | `equivocation` | at least two different claims for this slot verify under the key: the holder's, the listed conflicts and the receipt's own |

   `decider` is `null` for an account-scoped slot. A new conflict counts as a change for the watch, and
   `/evidence/slot/s/{request_slot}` reports `decider_equivocation_seen`. Observations written before v0.1 stay
   `nenrin-slot-observation-v0`, with no `decider` field, and are checked by the v0 rule.
5. From v0.2 (2026-10-11), the observation also has an `issuer_log` field read from the same bytes. The issuer stamps a
   daily snapshot of every slot to Bitcoin (SPEC v0.4, slot log: lines sorted by slot, `leaf = sha256(line)`, Merkle
   pairs `sha256(left_hex + right_hex)`, `log_root = sha256(JCS(header))` is what is stamped), and a slot's GET carries
   `log`: its `line`, `leaf`, `merkle_path`, the `header` and `log_root`. The intake recomputes the proof and compares the
   line with the slot bytes beside it.

   | `issuer_log.status` | meaning |
   |---|---|
   | `absent` | no `log` object |
   | `not_yet_in_a_snapshot` | the issuer says so (the snapshot is daily) |
   | `malformed` | a `log` object without the fields the SPEC names, in their forms (at most 64 path steps) |
   | `proof_fails` | `leaf` is not `sha256(JCS(line))`, the path does not reach `header.merkle_root`, or `log_root` is not `sha256(JCS(header))` |
   | `line_disagrees` | the proof holds, but the line says something else than the slot: `disagreements` names it (`event_ids`, `claim_sha256`, `decider_sig`, `conflict_shown_by_slot_missing_from_log`, `conflict_in_log_not_shown_by_slot`, ...) |
   | `included` | the proof holds and the line agrees with the slot bytes |

   A conflict received after the snapshot's `cutoff` may be on the slot and not yet in the log. A change of status counts
   as a change for the watch, and `/evidence/slot/s/{request_slot}` reports `issuer_log_statuses_seen`. The stamp itself is
   not checked at intake: `slot_check.py --log-anchor` reads the issuer's `<date>.ots` and checks it stamps the `log_root`.
6. Observations go oldest first into a daily `nenrin-slot-witness-batch-v0` ledger entry, stamped to Bitcoin with
   OpenTimestamps. `mirror-v0` copies each observation's bytes with the batch.

Reads: `/evidence/slot` (what this is), `/evidence/slot/{sha}` and `?format=raw` (the observation and its exact bytes),
`/evidence/slot/s/{request_slot}` (the history), `/evidence/slot/pending`.

## The outside copy of the issuer's slot log (`slot_log_copy.mjs`, 2026-10-11)

The issuer's SPEC says two divergent slot logs are attributable to it through where they were served and through
outside witnesses that keep copies. Its author asked for this copy. Once a day at 00:30 UTC, before the slot witness
batch (and on `POST /evidence/slot-log/refresh`, at most once an hour), the ledger:

1. reads the issuer's index of snapshots (`/decision-receipt/slots/log`);
2. for a date it does not hold, fetches the day file itself and keeps its exact bytes, after checking it against the
   index (`file_sha256`, `log_root`), on its own by the SPEC's rules (canonical lines, sorted slots, `n_slots`, Merkle
   root, cutoff, `log_root = sha256(JCS(header))`) and against the copy of the day before (`prev_root` chains, every slot
   stays with the same line, only new conflicts appended). Every failure is named in `problems`;
3. writes a `nenrin-slot-log-copy-v0` record into the slot witness pool, so the copy is in that night's batch and
   stamped to Bitcoin by this ledger;
4. if the index later names another file or `log_root` for a date it already holds, keeps the second file too and
   writes a record saying so (`divergent_from_earlier_copy`): two snapshots for one date is what the SPEC calls
   provable divergence;
5. keeps every distinct `.ots` the issuer serves for a held day (pending, then upgraded) until one is kept while the
   index says confirmed.

The copy runs only where `SLOT_LOG_COPY` is `"on"` (set in `wrangler.jsonc`). Without it, the daily run and the
refresh fetch nothing and write nothing (the refresh answers 503 `copy_off`), so tests give the same result on a machine
that can reach the issuer as on one that cannot.

Reads: `/evidence/slot-log` (the copies), `/evidence/slot-log/{date}` (the file, byte for byte; `?file_sha256=` for a
divergent one), `/evidence/slot-log/{date}.ots` (the confirmed `.ots` if kept, else the latest; `?sha256=` for another),
`/evidence/slot-log/{date}.json` (the copy record). The issuer's own checker runs on the copies unchanged
(`slot_log_check.py <date>.jsonl --prev <previous>.jsonl`, then `ots verify -d <log_root> <date>.ots`), and
`slot_check.py --log-copy <date>` checks a copy from here. It keeps what the issuer served this ledger; it does not
judge the slots and shows nothing about what the issuer served anyone else.

## What an observation establishes, and what it does not

It establishes that the receipt verifies under the issuer key and names this slot; that at `observed_at` this ledger got
exactly the kept bytes from the issuer's slot endpoint; that the verdict is what those bytes say; and, once batched and
stamped, that the observation existed before that Bitcoin block.

It does not establish that only one receipt was issued (that is the issuer's record), that the `request_id` behind the
slot is the decider's own id (the SPEC leaves that to the relying party), that the recorded decision was the decider's
real choice, what the endpoint served between observations or to anyone else, or that the issuer key was not
compromised. For `decider`, it does not establish which of two conflicting claims was the real decision, or whose the
decider key is; only that the key signed both.

## Check it yourself

```sh
python3 slot_check.py --sha <observation sha>      # the observation, its batch, its OTS proof (add --headers view.json to check the block)
python3 slot_check.py --slot <request_slot>        # every observation of the slot, and whether the listing changed
python3 slot_check.py --record observation.json    # offline, from the bytes ?format=raw served
python3 slot_check.py --sha <sha> --log-anchor      # also the issuer's .ots for the snapshot the line sits in
```

`slot_check.py` verifies BIP-340 with its own code (`bip340.py`, written separately from `bip340.mjs`) and recomputes the
verdict, and from v0.1 the `decider` field, from the kept bytes. Standard library only.

## Files

- `bip340.mjs`, `bip340.py`: BIP-340 verify (and sign, for fixtures) with no dependency, NIP-01 event checks. Both pass
  the BIP's `test-vectors.csv` (`fixtures/bip340_test_vectors.csv`: the BIP's file, sha256 `34c9d1d9...` with CRLF line ends, stored with LF ends, sha256 `01c8cabb...`) and verify a real invinoveritas
  event (`fixtures/invinoveritas_event.json`, from its repository).
- `slot_witness_v0.mjs`: the intake, the daily watch (`watchSlots`) and the daily batch (`anchorSlotWitnessPool`).
- `slot_check.py`: the reader-side checker.
- `fixtures/gen_fixtures.mjs` and `fixtures/slot_fixtures.json`: v0 observations the JS intake wrote for each verdict,
  recomputed by the Python checker; the test asserts the file regenerates byte for byte. `--v01` writes
  `fixtures/slot_fixtures_v01.json`: v0.1 observations of decider-scoped slots (holder verifies, equivocation, a conflict
  with a bad signature, by another key, for another slot or repeating the holder, a holder with a bad signature, a slot held by the other claim, a holder naming
  another key, an account-scoped slot), with a test decider key.
- `fixtures/slot_fixtures_v02.json` (`--v02`): v0.2 observations whose slot bytes carry a slot log object built by the
  SPEC's rules, with the snapshot file itself where the line is included, so the file, the proof and the slot are
  checked against each other: absent, not yet, included, included with a conflict, a conflict after the cutoff,
  a conflict missing from the log, a logged conflict the slot does not show, another event id, an altered path,
  log_root or header, a header without `cutoff`. The issuer's own `slot_log_check.py` (at 2b0550b7) accepts the
  included proofs and files and refuses the altered ones.
- `fixtures/invinoveritas_slot_log_20261010.json`: the same live slot read after the issuer's first non-empty snapshot
  (2026-10-10, one slot, `log_root` `9214af3a...`): both readers read its `log` as included, as the issuer's own
  `slot_log_check.py --inclusion` does.
- `fixtures/invinoveritas_slot_decider_20261010.json`: the first live decider-scoped slot this ledger observed
  (observation `84a7cb5e...`, 2026-10-10T11:27:56Z): the bytes the ledger kept (sha256 `db1802dd...`), holding one claim
  and listing one conflicting claim. Both readers find both decider signatures valid under the same key.

Tests: `node nenrin/slot-witness-v0/slot_witness_v0.test.mjs` (in `workers/hs-ledger`) and
`python3 nenrin/slot-witness-v0/slot_check_test.py`.

## Limits of v0 and v0.1

- Issuers are pinned by key in `ISSUERS`; v0 reads invinoveritas only.
- The slot format is read as a URL-safe string of 16 to 160 characters until a live receipt fixes it.
- One observation per (slot, receipt) per 6 hours on submission; 200 new observations a day, 20 per network.
- The watch reads at most 50 pairs a run, oldest observation first, for 30 days after the first observation.
- `issuer_log` shows that a line sits under a `log_root` and agrees with the slot. That the root was stamped, and when, is
  `--log-anchor`'s, from the issuer's `.ots`. Neither shows that the issuer kept every claim it was sent.
