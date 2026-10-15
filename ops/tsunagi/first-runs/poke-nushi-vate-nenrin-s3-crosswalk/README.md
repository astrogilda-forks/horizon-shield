# First run: Poke-nushi's NENRIN and VATE S3 crosswalk on the TSUNAGI board

Run once before the row went on the nightly board, as agreed in [VATE #84](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/issues/84).

- Crosswalk: `Poke-nushi/Verifiable-Agent-Trust-Envelope` at the pinned commit `79a9f91a468be6ef238697baafb5dfe3927a365b`, `reference/nenrin-s3-crosswalk-example`.
- Board: `tools/tsunagi/run_board.py --only poke-nushi-vate-nenrin-s3-crosswalk --no-differential --keep-reports <this folder>`, run from the commit that adds the row, before it was applied upstream (`repository_commit` in `board.json` is that local commit). The board's code, adapter and expectations were exactly the published `tools/tsunagi` (git tree `860ffa67c4c3fdd31bb2bed709f0feefcac4e073`).
- Expectations: `tools/tsunagi/expected/vate-nenrin-s3-crosswalk-v0.json`. A case counts only when all 15 of its findings match.
- Runtime: Linux, Python 3.11.15, Node.js v22.22.2. The rerun row installed jsonschema 4.26.0, nenrin-verify 0.5.3 (PyPI) and nenrin-verify 0.5.1 (npm) into `/tmp/tsunagi-vate-rt-v0`.

| row | file | sha256 | result |
|---|---|---|---|
| saved reports | `poke-nushi-vate-nenrin-s3-crosswalk__saved.json` | `e985653f49510ae80f59ac761aa98a334b38ab7e1773f2fc93fad1a502be137c` | 3/3 |
| checkers run again | `poke-nushi-vate-nenrin-s3-crosswalk__rerun.json` | `cc76265f417c8f10f82d4b8708e31ceae389cf5589ffeba018fd1f7e9c2d1a14` | 3/3 |

Each file is the comparison report `compare_records.py` wrote, byte for byte as the board read it; its sha256 is also in `board.json` (`report_sha256`). Both rows scored: match, target_mismatch and missing_receipt each with all 15 findings as expected.

What this shows: that this crosswalk, at this commit, reproduced its published findings on this run, from the saved reports and with both checkers run again. What it does not: a combined protocol verdict, signer authority, or general compatibility between NENRIN and VATE.
