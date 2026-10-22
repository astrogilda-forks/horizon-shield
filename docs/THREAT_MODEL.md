# Threat model

As of 2026-10-22 (commit history of this file is its changelog). This file says what we protect, who we assume attacks it, what stops each attack today, and where nothing does. A gap is written as a gap, and stays here until a commit closes it. Paths are in this repository; `nenrin/` is `workers/hs-ledger/nenrin/`.

## What we protect

1. **Verdicts and settlements**: that a reader who has the bytes gets the same answer we published, and that the answer follows from the bytes.
2. **Signed records**: witness records, agreements, receipts, checkpoints. A record must not verify after a covered byte changes, and must not be attributed to a key that did not sign it.
3. **Order and time**: that the ledger's history is not cut, reordered or forked without a reader being able to see it, and that an anchor bounds the time of the bytes it names.
4. **The published tools**: `nenrin-verify` on npm and PyPI, the Go module, and the vendored copies.
5. **Secrets**: no key, token or personal data on a public surface.

## Who we assume attacks it

- An outside party who submits records, walks endpoints, or sends crafted inputs to the verifiers.
- A party to a contract who wants a settlement that the signed terms do not support.
- **The operator itself** (us): the ledger, the gate and most witnesses are run by this company. Several controls below exist only to make our own misbehaviour visible to a reader; they do not prevent it.
- Someone who controls a party's `key_url`, a CI dependency, or a package registry account.

## Threats

### T1. A forged or altered signed record

**Today.** The ledger verifies Ed25519 over the exact canonical bytes at intake, refuses small-order keys (`src/ed25519_point.mjs`), refuses a `key_url` that redirects, is unsigned, or serves a different key. The readers accept one base64 spelling only. Key rotation needs both the old and the new key, chained by `prev_succession_sha256` (`key_succession.py` and its JS twin, with a parity test). Records signed after a declared compromise are refused. The gate publishes its key history at `/.well-known/key-history.json`.

**Gaps.** A compromise handover is signed by the new key alone, by design, so whoever controls a party's `key_url` can take over later attribution; only Bitcoin ordering limits it. Whether the WebCrypto path refuses a non-canonical S (signature malleability) is not tested here.

### T2. A rewritten, cut or forked ledger

**Today.** Every entry binds its predecessor (`src/chain_v1.mjs`); a hole is reported as `broken_at`, never skipped. The export's end marker is bound (`boundHeadRecord`). The head is in the daily batch, stamped with OpenTimestamps. Appends are serialized through a Durable Object. `nenrin/track-v0` reports `fork`, `broken_link`, `gap` and `anchored_late` on a mirror; `nenrin/mirror-v0` compares content and entry hashes.

**Gaps.** There is no gossip and no consistency-proof protocol between readers: a split view shown to two readers is caught only if they compare heads or mirrors. The copies that exist are this company's plus whoever forked. A record we never published is not seen by anyone.

### T3. A substituted anchor

**Today.** `musubi-v0/anchor_compose.py` reads `.ots` without a library, runs only sha256, hexlify, append and prepend, with depth and size limits, and refuses trailing bytes; a record must be listed exactly once in its batch; a pending stamp is never an anchor. `settle_v1_1.verify_view` checks 80-byte headers (linkage, proof of work against nBits, a difficulty floor, the contract checkpoint), picks the fork by cumulative work, requires a finality depth, and marks a settlement `superseded` after a deeper reorganization.

**Gaps.** The ledger SDK, `track-v0` and `mirror-v0` do not verify `.ots` at all. The header view check is not full consensus (no retarget or timestamp rules), and "heaviest" means heaviest among the views compared. Header sources can share an implementation; that has not been audited.

### T4. A false or captured witness

**Today.** A witness key's identity is its host or, on GitHub raw URLs, `github.com/<owner>`; shared hosts and commit-SHA refs are refused. Self-witnessing is refused when the key host equals the walked host or the ledger's host, or the owner is ours. Intake is rate limited per address, per domain and globally. Recovery uses a Bitcoin-seeded draw with commit then reveal and one vote per domain. Since 3252f5ea (TSUGI v2.4, verifier 0.4.0), a draw carries the body of the request its witnesses answered and the number of witnesses requested, and its commitment fixes the subject, the pool and that number together before the beacon block exists. The verifier refuses a request that does not name this draw's subject, pool and beacon, a draw wider or narrower than the policy, a pool other than the committed one, and observations made before the request or before the beacon block. These two holes (an earlier incident's signed observations could be counted again, and the pool could be chosen after the beacon) were found by an internal review on 2026-10-09; draws in the older form still verify and are marked as such (`segment.witness.forms`), and a reader can refuse them (`--require-v24`).

**Gaps.** The self-witness check compares exact host names, so a sibling subdomain or another domain held by the same operator is not refused. The Sybil control (`--min-walked`) defaults to zero. The witness pool for recovery holds two entries in two control clusters (api.babyblueviper.com, admitted 2026-09-23, and a Tencent CloudBase host operated by kuangmi-bit, admitted 2026-10-22, horizon-shield #56), so a quorum of two can be met. Both arrived because we asked them (`operator_outreach_only` in `witness_diversity_report.json`), and two clusters is the minimum a quorum of two needs, with nothing to spare. A witness that signs a lie is not removed by any of this. The list of outside witnesses (`WITNESSES.md`) is kept by hand.

### T5. Two readers that disagree

**Today.** The strict JSON reader refuses duplicate keys, non-integer and unsafe numbers, and non-ASCII keys. `__proto__` is handled the same way in JS, Python and Go (pinned by the `own-proto` corpus). JS and Python are compared on about 25,000 mutations per run in CI; Go against JS on about 27,000 inputs; Python against Go for `track-v0`; the settle core has three implementations on 128 vectors.

**Gaps.** The Go reader keeps the last of two duplicate keys, while the strict reader refuses them; duplicates are refused only on strict paths. The ledger's intake uses plain `JSON.parse`. The differential runners feed inputs re-serialized from parsed objects, so duplicate keys, number spellings and lone surrogates have not reached all three readers as the same raw bytes. Several runners (Go against JS, the conformance differential, the occurrence cells) are run by hand, not in CI. The Python and Go readers are ports by the same author; they are not independent implementations.

### T6. Replay and double use

**Today.** hs-pilot keeps one answer per request occurrence: a repeated `/call` returns the same receipt, a `/call` after `/void` is refused, and `/call` and `/void` for one request are serialized in a Durable Object (283bee47, after a race found by aeoess). Settlement uses single-use nonces, and a receipt logged twice attaches to the first copy.

**Gaps.** The deployed configuration binds the Durable Object (283bee47); a deployment without that binding falls back to the key-value store, which leaves about a minute of race across locations. When two executions share one block, which one a listing blames can depend on bytes outside the signatures; the verdict does not change.

### T7. Spending past a limit

**Today.** Totals are recomputed from counted payments, never taken from a claim; the tightest budget set by the hop's own issuer applies; a self-declared lineage, a second credential, onward delegation or fan-out does not reset a limit (44 vectors, `pilot_v0.py --selftest`). The settlement marks the first payment over the limit `budget_exceeded`; MUSUBI records, it does not stop a call.

**Gaps.** A payment the operator never logs is not counted. Nothing here proves that money moved, at the advertised price, or that the work was done.

### T8. Bending the gate's measurement

**Today.** The gate calls a tool only with consent from the server's own same-origin `/.well-known/mcp-conduct.json` or the operator's list; a requester's claim is ignored and recorded. Register writes use one key per row; quarantine is operator-only with a constant-time token check and a recorded reason. Dishonest test servers must not be marked verified (`test/redteam_gate.mjs`).

**Gaps.** The operator gives consent for its own servers and alone decides a quarantine.

### T9. The supply chain

**Today.** npm and PyPI are published by trusted publishing with provenance and attestations; a Go tag is made only when it equals the port version; vendored copies are pinned and checked in CI; third-party actions are pinned to full commit hashes; a scorecard runs weekly.

The workflow that passes the witness signing key to an action pins that action to a commit (`conduct-witness-dogfood.yml`, since 9f9d972d; it was a moving branch before).

**Gaps.** One workflow uses an action by a moving tag (`mcp-conduct.yml`, `wedjat-check-action@v1`); it is given no key. One earlier PyPI release of a related package was uploaded by hand without an attestation.

### T10. Secrets on a public surface

**Today.** gitleaks scans the full history on every push and pull request; a public-boundary check runs; credentials files are excluded from the repository.

**Gaps.** The gitleaks allow list has not been reviewed line by line. Working files that are not tracked sit in the repository root, so a careless `git add -A` could publish them.

## What this does not claim

It does not claim that the operator is honest, that a witness is independent of us unless it says so with its own key on its own domain, or that a verdict about conduct says anything about the correctness of the business behind an endpoint.
