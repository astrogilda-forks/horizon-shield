# Concurrency audit: lost updates on shared KV values (2026-10-13)

Scope: every Worker under `workers/*/` (each wrangler `main`), base `origin/main` ff591887. Question: where does a
Worker keep data from several independent writers in ONE KV (or R2) value and update it by read, modify, write?
Cloudflare KV has no compare-and-swap and is eventually consistent (a read can be up to 60 s stale, and two
overlapping writers both read the old value), so `v = get(k); change(v); put(k, v)` drops the other writer's change.
This is separate from issue #13 (read FAILURE handling, fixed earlier today). It answers the external review's
"registry overwrite, lost payment updates, inconsistent stamping state".

Ratings. HIGH: publicly reachable (or cron plus operator) concurrent writers, and the loss is a durable record or
money state. MEDIUM: operator only or low rate, but durable. LOW: counters the code already declares lower bounds,
caches, best effort logs, single writer.

Plan note. The account is on Workers Paid (D1 `hs-jccdb-obs-us` holds 1.6 GB, over the Free 500 MB cap), so KV
list() and per-key reads are within the included quota. If the account ever went back to Free (1,000 list
operations a day), the per-key register reads in G1 would need a short in-isolate cache.

## Findings

| ID | Worker: file:function:line | Key | Writers, rate | Lost on a collision | Existing mitigation | Rating | Status |
|---|---|---|---|---|---|---|---|
| L1 | hs-ledger: src/worker.js `/ledger/append` 1812, anchorWitnessPool 2265, headCheckpoint 2328, anchorAgreementPool 2360; nenrin slot_witness_v0.mjs 495, vouch_pin_v0.mjs 371, trace_pin_v0.mjs 358, task_ledger_v0.mjs 504 | `seq`, `entry:<n>`, `hash:<h>` | 00:30 UTC cron (7 appenders in one run), operator POST /ledger/append, /witness/anchor, /witness/task/anchor, /agreement/anchor | Two appends read the same seq and both write entry:<seq+1>: one answered 201 entry is overwritten, its hash:<h> points at an entry with another claim, a batch's records are marked anchored in an entry that does not list them | AGREEMENT_DEDUPE_DO existed but only for agreement dedupe | HIGH | fixed (serialized in the existing DO) |
| G1 | hs-verify-gate: src/worker.js POST /watch 6001, markDeclined 2741, markDeclared 2755, /register/quarantine 6074, DELETE /watch 6114 | `watch:registry` (one blob, all rows) | anonymous POST /watch (public), daily sweep 18:00Z, operator quarantine and DELETE | A registration answered ok:true vanishes; a quarantine or removal is undone by a writer holding an older copy | none (issue #13 fix only stopped writing back a FAILED read) | HIGH | fixed (one key per row) |
| U1 | hs-us-report: src/index.js handleIpn 224, sweep 498 (metadata repair, unpaid delete) | `order:<id>` status/txn | PayPal IPN (public webhook, retried), hourly sweep, minute draft cron, customer link, operator | A second payment overwrites the first txn_id with no double payment alert; a stale writer puts "paid" back to awaiting_payment (never drafted); the sweep deletes a just paid order and its files | txn:<id> dedupe (get then put, not atomic) | HIGH | fixed (immutable pay:<order>:<txn> key, reconcile, no delete with a payment) |
| H1 | hs-hearing: src/hearing.js estFileSave 281, /admin/estimate-file-read, estimate_files count | `estfiles:<store>` (one list) | LINE webhooks (one request per photo of a multi photo message), form uploads, operator read marks | A photo the store sent drops off the unread list; nobody is asked to read it | none | HIGH | fixed (list built from the files' own keys) |
| U2 | hs-us-report: src/index.js handleAnswer 467 vs generateDraft 280 | `order:<id>` hearing answers | customer answer link vs draft cron (draft takes tens of seconds) | Answers the customer was told "are in" are overwritten by the draft's older copy; the report ships without them | none | MEDIUM | fixed (second batch: `ans:<id>:<ts>` per set, merged at read; approve re-checks the keys) |
| U3 | hs-us-report: src/index.js draftPending 367 | `order:<id>` status via list metadata | minute cron; list metadata lags up to 60 s | Same order drafted twice (double AI cost, two review links, the first link dead) | status set to drafting first | MEDIUM | fixed (second batch: fresh re-read, then write-once claim `draftclaim:<id>`; residual across locations, see below) |
| U4 | hs-us-report: src/index.js sweep 498 unpaid delete | `order:<id>` | hourly sweep vs IPN at the 7 day boundary | Residual after U1: if the IPN lands within the KV visibility window of the delete, the order and files can still be deleted | U1 guard (no delete when a payment key is visible) and orphan alert | MEDIUM | fixed (second batch: `delmark:<id>`, delete an hour or more later after a fresh read; residual covered by the orphan alert) |
| G2 | hs-verify-gate: src/worker.js mouldWrite 1122 | `mould:index` | public POST /mould/from-issue (GitHub workflow, per issue serialized), operator POST /mould | An entry drops off GET /mould (the record itself stays at mould:<id>); a stale "already_recorded" read can rewrite a record | workflow concurrency group per issue | MEDIUM | fixed (second batch: list over mould:*, record read for already_recorded) |
| G3 | hs-verify-gate: src/worker.js DELETE /watch 6133 | `watch:removed` | operator DELETE | A removal stone is lost from the public list (the removal itself now holds, G1) | read failure guard | MEDIUM | fixed (second batch: `watch:removed:<sha256>`) |
| G4 | hs-verify-gate: src/worker.js recordHistory 3955, changes:recent 4019 | `hist:<sha16>`, `changes:recent` | daily sweep, operator POST /sweep | Two overlapping sweeps drop a history entry or a change line | sequential within one sweep | MEDIUM | fixed (second batch: SweepLeaseDO lease) |
| G5 | hs-verify-gate: src/nenrin_instant.js windowStateFor 130, beacon 165, pinWindowRule 239; worker.js fileInstantCommitment 4106 | `nenrin:window:<w>`, `nenrin:beacon:<w>`, `nenrin:rule:<w>`, `nenrin:commitfiled:<w>` | daily sweep, operator POST /sweep | Two sweeps opening a window create two salts: the commitment filed for one, rows derived from the other ("inconsistent stamping state") | read failure guard; create if absent | MEDIUM | fixed (second batch: SweepLeaseDO lease) |
| H2 | hs-hearing: src/autopilot.js putStore 184 | `store:<sid>` | LINE and email webhooks, daily autopilot, operator | A pending question or needs_human flag is overwritten | overwrite detection `_pending_overwritten` (named, not prevented) | MEDIUM | fixed (second batch: DispatchGateDO /rmw, three way merge) |
| H3 | hs-hearing: src/hearing.js 1697, 2305, 2849, 3339 | `hearing:<sid>` profile | form answer, email or LINE reply, estimate update, operator | One channel's answers overwritten by another's older copy | none | MEDIUM | fixed (second batch: same DO, named mutations) |
| K1 | hs-kira-line: src/worker.js kiraLessonsAdd 1920, "おぼえて" 1754 | `kira_lessons:global` | AI auto adds from every group's webhook, owner commands | A lesson silently dropped, or a lesson the owner deleted written back | read failure guard | MEDIUM | fixed (second batch: `kira_lesson:<id>` per lesson, tombstones for the old list) |
| AC | ai-council: src/worker.js 179 | `month_<m>` spend | authorized requests | Spend undercounted, so the $30 cap can be passed | auth | MEDIUM | fixed (second batch: `spend:<month>:<ts>` per charge, paged list, fail closed) |
| U5 | hs-us-report: src/teardown.js handleBoardReview 346 | `board_index` | operator publish links | A published card drops off the index (card stays at board:<id>) | read failure guard | MEDIUM | fixed (second batch: list over board:*, only the shown cards read) |
| L1r | hs-ledger: gcp/firestore_dedupe_do.mjs (GCP twin) | as L1 | as L1, if the twin is ever live | as L1 | the twin builds the DO without env, so appendEntry falls back to the old sequence | MEDIUM | fixed (second batch: /ledger-append in one Firestore transaction) |
| KP | hs-kira-proxy: src/kira-proxy-v2.js | `card_index` and others | unknown | unknown | unknown | n/a | not auditable here: the source is not in this repository (only the test is) |
| G6 | hs-verify-gate: src/worker.js bumpUsage 614, bumpRequests 672 | `usage:<day>`, `usage:req:<day>` | every check | a count | declared in code: "出す数字は常に下限" (line 603) | LOW | accepted (documented lower bound) |
| G7 | hs-verify-gate: src/worker.js netSalt 836, netFreeze 888 | `usage:netsalt:<day>`, `usage:netcount:<day>` | first requests of a day, sweep | one network counted twice at the day boundary | declared in code (line 845) | LOW | accepted |
| L2 | hs-ledger: src/worker.js POST /ledger/{n}/ots 2221 | `entry:<n>` OTS fields | jidec-stamp workflow hourly | a stamp status | workflow `concurrency: jidec-stamp` (single writer) | LOW | accepted |
| L3 | hs-ledger: src/worker.js 349, 1604; response_v0, trace/vouch/slot/task intakes | `agr:count`, `wit:count`, lane and per network caps | public intakes | a cap allows a few more than stated | rate caps only | LOW | accepted (caps are spam control, not records) |
| L4 | hs-ledger: slot_witness_v0.mjs lastKey, slot_log_copy.mjs day record | `slot:last:*`, slot log day | cron, public slot intake | first_observed_at may move | observations are per key | LOW | accepted |
| U6 | hs-us-report: teardown.js bump 58, underCap 71; index.js rateLimited 73 | `stats:<day>`, `rl:*` | public events | a count | declared "Best effort counters (not atomic)" | LOW | accepted |
| U7 | hs-us-report: index.js handleIpn txn check | `txn:<id>` | PayPal resends | a duplicate receipt email and LINE | order first, mark after | LOW | accepted (U1 keeps money state) |
| H4 | hs-hearing: autopilot.js activityAdd 844, refHit 886, dedupRegister 944 | `activity:index`, `ref:<member>`, `dedupe:index` | public feed, referrals, blog dedupe | a feed line, a referral count, a dedupe row | best effort try/catch | LOW | accepted |
| K2 | hs-kira-line: kiraConvAppend 1847, kiraDigestAdd 1944, saveHistory 224; hs-kira-group rememberMessage 160 | `kira_gconv:<gid>`, `kira_digest:<day>`, `chat:<user>`, `grp:<src>` | LINE webhooks | a line of conversation memory (TTL 1 to 30 days) | read failure guard | LOW | accepted (context memory, not a record) |
| PG | hs-pdf-gen: hsDlTokenOk 17220 | `dl_token:<t>` uses | download link | a 6th or 7th use of a 5 use link | orders keyed by txn already | LOW | accepted |
| MS | hs-geo-factory putIndex 180 (admin), hs-monitor addToWatchBatch 128 (cron), hs-outreach putState 46 (cron), hs-price-sync PROPOSAL 247 (monthly cron, admin), hs-souba-pipeline counters (cron), hs-internal-mcp monitor:* (cron) | various | single writer or operator | little | none needed | LOW | accepted |
| OK | hs-gateway TicketLedgerDO, hs-webmcp StatsDO, hs-ledger AgreementDedupeDO, hs-hearing DispatchGateDO | money tickets, shop counters, agreement dedupe, dispatch debounce | | | already serialized in Durable Objects | none | no change |

Not deployed from here: workers/hs-estimate (DEPLOY_MOVED.md). hs-billing writes per key, no read, modify, write.

## Fixes

### L1 hs-ledger: entry numbers assigned in the existing Durable Object

- New `workers/hs-ledger/src/ledger_append.mjs`. `appendEntry(env, h, entry)` sends the entry to the existing class
  `AgreementDedupeDO` (binding AGREEMENT_DEDUPE_DO), instance `ledger:seq`, path `/ledger-append`. Inside
  `blockConcurrencyWhile` it checks `ledger_hash:<h>` in DO storage and `hash:<h>` in KV, takes
  `n = max(KV seq, DO ledger_seq) + 1`, writes entry:n, hash:h, seq, then stores ledger_seq and ledger_hash in DO
  storage. A Durable Object instance runs one such block at a time and its storage is strongly consistent, so two
  appends can no longer share n, and a stale KV read of seq cannot go below the DO's floor.
- All 8 append sites call it (worker.js 4, nenrin pools 4). Entries are built exactly as before (`n` first, same
  keys in the same order); only the source of n changed. A lost race to an identical claim answers as the existing
  dedup answer.
- Fail closed: if the binding is present and the sequencer errors, nothing is appended (POST /ledger/append answers
  503 ledger_append_unavailable; pools stay pending for the next run). If the binding is absent (unit tests) or the
  DO has no LEDGER (GCP twin), the old sequence runs unchanged (residual L1r).
- `AgreementDedupeDO` now takes `(state, env)`; agreement behaviour is unchanged (its tests pass).
- `/health` gains `"sequencer": "do-serialized-20261013"`.
- Migration: none. Same class, binding and `v1` migration already in wrangler.jsonc. The first append after deploy
  seeds the DO counter from KV seq.
- Byte check: a scratch harness ran the same single requests (two POST /ledger/append, one with a lone surrogate in
  the record and an object as work, then POST /witness/anchor, a repeat append, GET /ledger/head) with a fixed clock
  against the old and the new code. Responses and every KV value were identical. Hashing, numbering for a single
  request, record_canonical and the chain recipe are untouched; only who assigns n changed.
- Operator note: never lower KV `seq` by hand after this deploy. The DO keeps the highest number it handed out as a
  floor, so a hand-lowered seq would make the next append skip numbers and leave a hole in the chain walk.
- A failed sequencer call answers 503 and the worker writes nothing itself. If the DO had already written (a lost
  reply), a retry of the same claim is answered as the dedup of that entry from `ledger_hash:<h>`; a pool that threw
  stays pending and is batched again on the next run.

Ledger sequencing verdict (before the fix): NOT serialized. Evidence: each site did
`Number(await env.LEDGER.get("seq")) + 1` then three plain puts (e.g. old worker.js 1829 to 1833, slot_witness_v0.mjs
493 to 497), with no lock, no DO and no conditional write. The chain (jidec-chain-v1, chain_v1.mjs) is derived from
stored entries (`prev_entry_sha256` is computed at walk time, not stored), so a collision does not fork the chain; it
silently replaces entry n, which is worse: the walk stays green. Concurrent appenders exist: the 00:30 UTC cron runs
seven appenders back to back, and four operator routes append on demand. Test 1 of `test/concurrency_seq.test.mjs`
reproduces it on the old code (both told 201 with n 1, seq 1).

### G1 hs-verify-gate: one key per register row

- Rows are written to `watch:reg:<sha256(endpoint)>` as `{ endpoint, row }` (row null hides the endpoint), with the
  row also in the key's metadata when it fits (1,000 bytes), so a full read is one list() plus one get per oversized row.
- `loadRegistry` returns the old blob overlaid by the per-key rows; rows only in per-key form follow in added_at
  order (the blob kept insertion order). All readers keep their shape; writers (POST /watch, markDeclined,
  markDeclared, quarantine, DELETE) read and write their own row only. POST /watch reads the whole register only to
  enforce REGISTRY_MAX for a new row.
- Migration safe: the blob is still read, never rewritten or deleted. No CONFIG.version change, so the signed card
  is untouched (no re-sign). The deploy marker is gate_commit (deploy_gate.sh).
- Rollback note: code before this change does not read `watch:reg:*`. After a rollback, rows registered or changed
  after this deploy are invisible to it (they stay in KV), and its writers would write the blob without them.

### U1 hs-us-report: the payment is its own key

- The IPN writes `pay:<order>:<txn>` (write once, metadata order/txn/at) before touching the order. Responses are
  unchanged.
- The hourly sweep never deletes an unpaid order that has a payment key, and `reconcilePayments` (last 7 days) puts a
  lost "paid" back (LINE: 入金の反映漏れを直した), raises a double payment once per new txn (LINE, mark
  `payalert:<id>`), and raises a payment whose order is gone (mark `payalert:<id>:orphan`). The repair and the orphan
  alert only act on a payment older than 10 minutes (PAY_REPAIR_GRACE): the IPN marks the order paid milliseconds
  after it writes the payment key and a KV write is visible everywhere within about 60 s, so an order still reading
  awaiting_payment after that really lost its "paid". Acting earlier could put a stale copy back over an order the IPN
  or the draft cron is moving. A double payment (two txns) is raised at once. The IPN's own double
  payment branch sets the mark so the sweep does not repeat it. sweep() gains pay_repaired, double_pay_alerts,
  pay_orphans.
- `/health` gains `"payments": "pay-record-v1-20261013"`. Migration: none (no payment keys before; orders untouched).

### H1 hs-hearing: the estimate file list is built from the files

- Every file was already its own key `estfile:<store>:<id>` with name/type/size/at/via in metadata. `estFilesList`
  lists them, overlays the old `estfiles:<store>` index (entries and read flags, read only), adds read marks from
  `estfile_read:<store>:<id>`, and returns the same shape and order as before (oldest first, newest 24).
- Uploads no longer write a shared value; marking read writes one key per file.
- `/health` gains `"estimate_files": "per-key-20261013"`. Migration: none. Rollback note as G1 (old code reads the
  index only).

## Tests

| Worker | New test | On the old code | After | Existing suites before / after |
|---|---|---|---|---|
| hs-ledger | test/concurrency_seq.test.mjs | 9 failures of 20 checks | 20 / 20 | test/*.test.mjs 14 / 14 pass both; nenrin pool tests (slot 98, vouch 73, trace 51, task anchor, task ledger, task trust, agreement intake 63, trust-signal route) pass both; resume_route_selftest R10 fails both (pre-existing, unrelated) |
| hs-verify-gate | test/registry_concurrency.test.mjs | 11 / 17 (6 NG) | 17 / 17 | run_all 37 / 37 before, 38 / 38 after (two storage-reading tests, watch_owner and read_failure_writes_nothing, now read the merged layout) |
| hs-us-report | test/payment_concurrency.test.mjs | 9 failures of 12 | 12 / 12 | 6 / 6 before, 7 / 7 after (added to npm test) |
| hs-hearing | estfiles_race_test.mjs | 3 failures then a crash | 8 / 8 | run_all 21 / 21 before, 22 / 22 after |

Each new test uses an in-memory KV whose reads of the shared key wait at a barrier until two readers are inside (both
read before either writes); the us-report test can also land the stale write last. The ledger test wraps the real
AgreementDedupeDO class in an in-memory state whose blockConcurrencyWhile runs one block at a time.

## Deploy order and checks

1. Run the suites (hs-ledger tests listed above, `node test/run_all.mjs` in hs-verify-gate, `npm test` in
   hs-us-report, `node run_all.mjs` in hs-hearing).
2. Deploys are independent; no wrangler migration is needed anywhere. hs-hearing deploys itself on push
   (deploy-hs-hearing.yml). Deploy hs-ledger outside 00:25 to 00:40 UTC and run no operator append (POST /ledger/append, /witness/anchor,
   /witness/task/anchor, /agreement/anchor) while the new version rolls out: an old instance still appends without the
   sequencer and could collide with a new one during the switch, exactly as two old instances could before.
   Version markers: hs-ledger /health `sequencer`, hs-us-report /health `payments`, hs-hearing /health
   `estimate_files` (its SERVER.version 2.3.1 is left as is: it mirrors server.json, the MCP registry entry). hs-verify-gate is
   identified by gate_commit; CONFIG.version is not bumped because it is inside the signed agent card and would need
   a re-sign.
3. After the deploys: `bash ops/prod_fix_check.sh --gate-commit $(git log -1 --format=%h origin/main -- workers/hs-verify-gate)`.
   It only reads (curl GET), prints a table and exits 1 on any mismatch. `--skip-new` leaves out the three rows for
   these fixes; `--base URL` and `CURL=<fake>` make it testable offline.

## Second batch (2026-10-13, the MEDIUM rows)

Thirteen rows, six commits, one worker each. Same rules as the first batch: old data read and never rewritten or
deleted, public shapes unchanged, fail closed on a failed read or a failed Durable Object call, a test that fails on
the old code. Reviewed by an agent that had not seen the code being written; its findings that led to changes are
marked (review).

### U2, U3, U4, U5 hs-us-report

- U2: every answer set is its own write once key `ans:<order>:<at>-<rand>` (customer link and operator PUT); the
  draft, the review page, the answer form, the admin read and the export `hearingAnswers` merge the sets over the
  order's own answers (oldest first). The draft records which sets it read (`draft.answer_keys`); approve (review page
  and admin) lists the sets again and refuses with 409 when one is missing from that list (the order goes back to
  "answered" and is redrafted), with 503 when the list fails (review: the re-check inside the draft is a KV list and
  can be a minute stale across locations; approve is minutes to hours later). A failed re-check at the end of the
  draft marks the draft failed instead of shipping it (the issue #13 guard caught the first version).
- U3: each candidate is read fresh before drafting and skipped unless it still needs a draft; then a write once claim
  `draftclaim:<id>` (get, put, read own token back, TTL 15 min, released when the draft ends). Residual: KV has no
  compare and swap, so two cron runs in different locations within the propagation window can both claim; the cost is
  one duplicate draft (AI spend, a second review link), not data. No Durable Object exists in this worker and none was
  added for this.
- U4: two phase unpaid delete. The first sweep writes `delmark:<id>`; a later sweep deletes only when the mark is
  older than an hour, a fresh read still says awaiting_payment and no `pay:<order>:*` key is visible. The IPN and the
  reconcile delete the mark. Residual: a payment landing inside the KV visibility window of the second pass can still
  be deleted with its order; the U1 orphan alert (a payment whose order is gone) names it.
- U5: a publish writes only `board:<id>` (published_at in metadata). The board lists the keys, takes the 200 newest by
  metadata plus every card of the old `board_index` (read only), and reads only those (review: the first version read
  every card). Same shape and order.
- /health: answers, draft_claim, unpaid_delete, board_index. No binding, no migration.

### G2, G3, G4, G5 hs-verify-gate

- G2: a mould record's only write is `mould:<id>` with its list line in the metadata; GET /mould lists the prefix and
  overlays the old `mould:index` blob read only. The already_recorded check reads the record itself; a failed read is
  503 mould_read_failed. GET /mould and /mould/<id> answer 503 on a storage error instead of an empty ledger.
- G3: one stone per key `watch:removed:<sha256(endpoint)>`; a re-removal keeps earlier stones under `earlier`,
  flattened on read. The stone is written first, then the row is hidden (a stone without a hidden row is possible when
  the second write fails; the operator repeats the DELETE).
- G4, G5: sweep single flight. New `SweepLeaseDO` (src/sweep_lease.js), one instance "sweep", acquire (TTL 15 min)
  and release inside blockConcurrencyWhile. POST /sweep answers 409 sweep_in_progress when busy, 503
  sweep_lease_unavailable when the lease call fails; the cron skips and logs. `hist:<sha16>` and `changes:recent`
  stay single values (read whole by /history, /changes, /feed.xml); with one sweep at a time their read append put is
  safe. The test also exposed that two sweeps in one isolate shared the module level sweepBudget and the second one
  threw at the end.
- wrangler.jsonc: new binding SWEEP_LEASE_DO and the gate's first migration tag (v1, new_sqlite_classes). deploy_gate.sh
  applies it; the dry run must show the binding. Rollback is safe (old code ignores the keys and the binding).
- /health: mould_index, removed_stones, sweep. CONFIG.version untouched (signed card).

### H2, H3 hs-hearing

- `store:<sid>` and `hearing:<sid>` are written only through the existing DispatchGateDO (binding DISPATCH_DO), new
  path /rmw, one instance per key (`rmw:store:<sid>`, `rmw:hearing:<sid>`, separate from the dispatch marks). Inside
  blockConcurrencyWhile the DO reads KV, uses its own last copy as a floor when KV is older (stamp `_rmw.seq`, within
  120 s), applies a named mutation, writes KV, keeps the last 8 versions. putStore keeps its signature (22 call sites)
  and merges three ways against the version the writer read: untouched fields keep the saved value, pending and
  needs_human keep the newer one, double changes are named in `autopilot._rmw_conflicts`. The five profile writers
  (reply ingest, estimate append, form POST, set-estimates, profile-patch) recompute from the saved record inside the
  DO. Fail closed: a DO error or a reply without the rmw marker throws rmw_failed, nothing written, 503 on routes, skip
  in the daily tick. No new class, binding or migration; the constructor is now (state, env).
- /health: version 2.3.2-rmw-20261013, store_writes.

### K1 hs-kira-line, AC ai-council, L1r hs-ledger GCP twin

- K1: a new global lesson is `kira_lesson:<14 digit ms>-<rand>`; the old `kira_lessons:global` list is read only.
  Deleting a per key lesson deletes the key; deleting a lesson that exists only in the old list writes a tombstone
  `kira_lesson_del:<sha256(text)[0:32]>`. The 40 cap prunes the same way. Read failure guard kept. /health
  v25-lessons-20261013, lessons.
- AC: every charge is `spend:<month>:<ts>-<rand>` (usd in metadata, TTL 100 days); the month total is the old
  `month_<m>` floor plus the listed charges, read page by page with the cursor (review: the first version read one
  page and would have answered 503 for the rest of the month after 1,000 charges). A failed list or more than 50 pages
  is 503 budget_unknown before any AI call. No /health in this worker.
- L1r: the twin serves /ledger-append itself inside one Firestore runTransaction (hash doc and seq doc read, entry,
  hash and seq written in the same transaction) with the same bytes as the Cloudflare side; a failed transaction is
  503 ledger_append_failed and the racy fallback is unreachable from the twin.

### Tests of the second batch

| Worker | New test | On the old code | After | Existing suites before / after |
|---|---|---|---|---|
| hs-us-report | test/order_concurrency.test.mjs | 23 failures of 30 (first version); the review cases 1b, 1c, 10b fail on the agent's version | 42 / 42 | 7 / 7 before, 8 / 8 after; flow and read_failure updated for the two phase delete and the per key board |
| hs-verify-gate | test/mould_removed_perkey.test.mjs, test/sweep_lease_concurrency.test.mjs | 17 / 36 and 10 / 19 | 36 / 36 and 19 / 19 | run_all 38 / 38 before, 40 / 40 after |
| hs-hearing | store_profile_rmw_test.mjs | 14 / 36 | 36 / 36 | run_all 23 / 23 before, 24 / 24 after |
| hs-kira-line | lessons_perkey_test.mjs | 17 of 18 fail | 18 / 18 plus 13 guards | read_fail 40, read_fail2 28 + 7, read_fail3 8 + 5, group_reply 184 to 185 |
| ai-council | test/spend.test.mjs | 10 of 10 fail (0.0184 counted of 0.0367); the paged case fails on the agent's version | 11 / 11 plus 6 guards | none before |
| hs-ledger (gcp) | gcp/firestore_dedupe_do.test.mjs, new cases | 3 of 5 fail (both told n 1) | 9 / 9 | test/*.test.mjs 15 / 15 both |

ops/no_swallowed_read.mjs: 0 new hits on the whole tree (it caught one in the first version of U2).

### Deploy of the second batch

hs-verify-gate: deploy_gate.sh (the dry run must show SWEEP_LEASE_DO and the migration v1). hs-us-report, hs-kira-line,
ai-council: wrangler deploy from a clean checkout of origin/main. hs-hearing: Actions on push. The GCP twin is not
deployed (not live). Then `bash ops/prod_fix_check.sh --gate-commit <sha>`: its rows now expect kira-line
v25-lessons-20261013 and hearing 2.3.2-rmw-20261013 and include the nine new markers.
