# tools/bench results

Measured on the tree of commit f23867e0 with this folder added (the commit that adds tools/bench has f23867e0 as
its parent). The shas below depend only on the generator, the verifiers and the settlement code; if a later commit
changes one of them, the sha changes and this file says so in a new section.

## The one-line run (10k bundles, 1k executions, the four faults)

```sh
O=$(mktemp -d) && for k in reuse7 per-bundle; do python3 tools/bench/gen_bundles.py --n 10000 --keys $k --out $O && python3 tools/bench/bench_verify.py $O/bundles_${k}_10000.jsonl; done && python3 tools/bench/bench_settle.py --n 1000 --out $O && python3 tools/bench/faults.py --out $O
```

For 100k bundles or 10k executions, change `--n`.

## Expected shas (the same on every machine)

| input | count | bytes | input sha256 |
| --- | ---: | ---: | --- |
| bundles, reuse7 | 10,000 | 29,633,669 | `5bf90962819115f785c65e12aea4a4c6406a74895df63e2ea11f85414da96d39` |
| bundles, per-bundle | 10,000 | 29,633,669 | `7b8a30e155789d70992c07aef168a78f9e71c0796a1cd1e40f66fcabd1bc72b6` |
| bundles, reuse7 | 100,000 | 296,546,669 | `bee4a56afbe9e39e5a3a51022080fc3d0c1490241cda8cee2b9f9ab91de973d7` |
| bundles, per-bundle | 100,000 | 296,546,669 | `5b936b17698d1fd4de6f4565cc85f16b5ebc7d2bd69d46db9563da6252b752d4` |

Verdict sha256, the same from JS, Python and Go and for both key modes (the two modes have the same verdict pattern):

- 10,000 bundles (8,000 accepted, 2,000 refused): `ad4a5549e569b661db52031ed806eb87a2faa4ab89d76a683a41e7f291089e2d`
- 100,000 bundles (80,000 accepted, 20,000 refused): `9992c15dac700a90e2b79ea49ce59e8c048a9eec6ef581e2c87ceaf5f56f9dca`

| settlement input | executions | headers | input sha256 | core_sha256 | result |
| --- | ---: | ---: | --- | --- | --- |
| gen_settle --n 1000 | 1,000 | 18 | `b7b50a501b1e1ec2f9ca6470d70b40335a4c534eaf13eb5ebf9187a8f39923b4` | `6ce7888b658636727218bbaa4b94d3a4e444d7916eb6b5206a16977ebf9efdd1` | within_grant, final, bond held, 1,000 accepted |
| gen_settle --n 10000 | 10,000 | 108 | `db2e43777885f105ee061d872e9716d5448bf3f933960f5d4696f7b42c76c37e` | `b61d816dc3a86e673b3e11563b61b1066516d19cdd301f7c51df146222a2dc8a` | within_grant, final, bond held, 10,000 accepted |

faults.py `rows_sha256`: `e833dc1e0054ec932d11fcc0d8c0b60bcd587cfe582b8c968face530dedb8612`. It depends on
survive-v0/kept/ (137 entries at f23867e0), which grows with the daily commit, and on opentimestamps being
installed (case 3c), so it is pinned to this commit.

## Our machine (The HORIZONs Co., Ltd.)

Apple M3 Pro, macOS 26.3.1 (Darwin 25.3.0, arm64). Node v24.11.1, Python 3.14.7, cryptography 50.0.1, Go 1.27.2,
opentimestamps 0.4.5. 2026-10-23. One verifier at a time; other work on the machine was light but not stopped.
Wall time includes process start-up. RSS is the maximum resident set size from `/usr/bin/time -l`.

### Provenance verifiers

| bundles | keys | JS s | JS µs/bundle | JS RSS MB | Python s | Python µs/bundle | Python RSS MB | Go s | Go µs/bundle | Go RSS MB |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | reuse7 | 6.1 | 611 | 164 | 24.2 | 2,417 | 103 | 4.2 | 425 | 96 |
| 10,000 | per-bundle | 40.8 | 4,084 | 162 | 87.9 | 8,791 | 103 | 35.6 | 3,560 | 96 |
| 100,000 | reuse7 | 62.0 | 620 | 947 | 229.3 | 2,293 | 681 | 39.4 | 394 | 654 |
| 100,000 | per-bundle | 523.3 | 5,233 | 886 | 956.4 | 9,564 | 672 | 376.6 | 3,766 | 642 |

A second run of the 10k rows gave the same input and verdict shas, with times within 12 percent (reuse7: JS 6.4 s,
Python 23.8 s, Go 4.7 s; per-bundle: JS 42.0 s, Python 91.5 s, Go 37.2 s). Generating the bundles took 8.5 s
(10k reuse7) and 13.8 s (10k per-bundle). The whole 100k pass (generation and the three verifiers, both key modes)
took 2,434 s.

All three read the whole input before verifying, so RSS grows with the input size.

### Settlement (settle_v1_16, reference, Python)

| executions | settle s | child wall s | RSS MB | generate s |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 2.37 | 2.59 | 55 | 0.36 |
| 10,000 | 23.9 | 24.6 | 174 | 1.66 |

Linear in the number of executions here: every record is accepted, so settle_v1_16 runs settle_v1_15 once.
Inputs where records are rejected one after another were not measured.

### Faults (faults.py)

| fault | case | tries | detected | missed | basis |
| --- | --- | ---: | ---: | ---: | --- |
| 1 truncated copy | a. held head given (`copy_shorter_than_held_head`) | 10 | 10 | 0 | verified |
| 1 truncated copy | b. no held head (verify_chain.py) | 10 | 0 | 10 | verified |
| 1 truncated copy | c. survive drill, no held head | 10 | 0 | 10 | expected: digests and chain run here and clean; Bitcoin anchors need block explorers, not run |
| 2 forked head | a. one reader, forked copy and its own head | 5 | 3 | 2 | verified: the 3 forks below a head stamped in a later entry break that stamp; the 2 forks of the last two entries pass |
| 2 forked head | b. two readers, forked head held against the genuine copy (`held_head_differs_from_copy`) | 5 | 5 | 0 | verified |
| 2 forked head | c. two mirrors compare content_sha256 | 5 | 5 | 0 | verified |
| 3 swapped anchor | a. anchor of another record (`anchor_proof_invalid`) | 5 | 5 | 0 | verified |
| 3 swapped anchor | b. same body anchored again later, only the later copy given | 3 | 0 | 3 | verified (not detectable by construction) |
| 3 swapped anchor | c. two .ots proofs swapped (`ots_digest_is_not_the_claim`) | 5 | 5 | 0 | verified |
| 4 shortened view | a. top 1 to 8 headers removed (provisional, then `anchor_beyond_observed_chain`, then `chain_view_rejected`) | 8 | 8 | 0 | verified |
| 4 shortened view | b. lowest 2 or 3 headers removed, checkpoint gone (`chain_view_rejected`) | 2 | 2 | 0 | verified |

Each fault also has a control row (the unchanged input); all four pass clean.

## Other machines

Rows from other people's machines, added from issues opened with the [bench result form](https://github.com/ogasurfproject-jpg/horizon-shield/issues/new?template=bench-result.yml). A row is added only when its verdict sha256, and every other sha it reports (input sha256, `core_sha256`, `rows_sha256`), match the expected shas above for the commit it names. A result whose shas do not match is not added here; it stays in its issue, where we look into it as a finding about the generator, a verifier or the settlement code. Rows are credited by GitHub handle.

| handle | commit | OS and CPU | Node / Python / Go | bundles | keys | JS s | Python s | Go s | verdict sha matches | issue |
| --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | --- | --- |

None yet.
