# Numbers in the manuscript and their sources

Paths are relative to the repository root. "Log" means `replication/log_extracts.md`; "clean room" means `replication/cleanroom/`.

| Number | Where in the manuscript | Source |
|---|---|---|
| 95 entries, chain intact, head 1fda4f12... | 5.1 | Log 1233, 1234 (live service) |
| 88 entries recomputed, chain and end marker match | 5.1 | workers/hs-ledger/nenrin/survive-v0/kept/export.jsonl; workers/hs-ledger/src/chain_v1.mjs |
| first entry 22 Jul 2026, block 959118 | 5.1 | workers/hs-ledger/nenrin/survive-v0/kept/ledger/1.json |
| 28 drill runs: GitHub 14/14, Software Heritage 9 rebuilt, 5 unavailable | 5.1 | workers/hs-ledger/nenrin/survive-v0/drills/history.jsonl |
| outside signed walks: entries 57, 61, 65, 73, 71 to 84 | 5.1 | kept/ledger/<n>.raw; ops/adoption/latest.json |
| 14 refusal codes, 9 finding codes | 3 | workers/hs-ledger/nenrin/provenance-v0/VERIFIER.md; workers/hs-ledger/nenrin/sdk/nenrin_verify.mjs |
| 13/18 then 18/18, 9/9 vectors, 11 guesses, 11 of 18 | 5.2 | clean room GAPS_round1.md, GAPS_round2.md; Log 787 |
| kuangmi-bit 5/5, 21 digests, 5 gaps; 18/18; 8/18 | 5.2 | workers/hs-ledger/nenrin/interop-v0/INTEROP.md; Log 785, 797 |
| babyblueviper1 5/5, 13/13, 36/36, 8 consecutive runs | 5.4 | ops/tsunagi/BOARD.md |
| 13 faults, controls 63 and 0, 5/13 (38.5), 13/13 (100.0) | 5.3 | workers/hs-ledger/nenrin/conformance-v0/adequacy-v0/REPORT.md, report.json; workers/hs-ledger/nenrin/interop-v0.3/survivors/README.md |
| 42/42, 36 cells, 13 outside, 18 outside runs, 10 board-scored, 40 fresh bundles | 5.4 | ops/tsunagi/BOARD.md (run 2026-10-13T00:58:44Z) |
| first fresh-bundle disagreement, 2 of 40 | 5.4 | Log 1018 |
| 31 bundles, 27,062 (2,667 both throw), 98 cases, 69 codes, 29,326 | 5.4 | workers/hs-ledger/nenrin/sdk-python/README.md |
| Go 27,174 (2,352 both throw) | 5.4 | workers/hs-ledger/nenrin/sdk-go/README.md |
| TRACE 8,640 | 5.4 | workers/hs-ledger/nenrin/trace-bind-v0/README.md |
| VATE three cases | 5.4 | workers/hs-ledger/nenrin/vate-s3-v0/README.md |
| PriorSeal 89 / 0 / 13, 8 gaps | 5.4 | workers/hs-ledger/nenrin/priorseal-reader-v0/REPORT.md |
| entries 59, 61, 63, block 969090, 535 headers, settle v1.6 | 5.4 | workers/hs-ledger/nenrin/musubi-v0/run0002/README.md |
| contract with no party from us, block 970543 | 5.4 | ops/adoption/latest.json; docs/metrics/INDICATORS.md |
| 37 services, 16 places | 6 | Log 1205 |
| 28 classified rows (4 / 13 / 11), 9 of 20 | 6 | ops/concurrency_audit_20261013.md |
| 20.5 s to 1.49 s | 6 | Log 1233, 1234; workers/hs-ledger/test/chain_read_speed.test.mjs |
| pool of 1, quorum 2 | 8 | workers/hs-ledger/nenrin/recovery-v0/pool_report.json; ops/adoption/latest.json |
| production use by unaffiliated parties 0 | 8 | docs/metrics/INDICATORS.md |
| about 19 million requests a day from the operator's clients | 8 | docs/metrics/INDICATORS.md section 5 |
