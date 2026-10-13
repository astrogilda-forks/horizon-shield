# Records Outsiders Can Recheck: replication package

Manuscript: `manuscript_v0.3.tex` (source) and `manuscript_v0.3.pdf`. Prepared for submission to the Journal of Systems and Software (In Practice track, Applied Research Report), in the Elsevier template. Author: Toshikatsu Oga, The HORIZONs Co., Ltd., ORCID 0009-0000-9180-903X. License of this directory: CC BY 4.0 for the text, MIT for the scripts.

Every number in the manuscript traces to this repository at the commit archived on Zenodo (see the manuscript's data availability statement). `make_replication_zip.sh <commit>` rebuilds that archive from the repository: the manuscript, this directory and every path `NUMBERS.md` cites, exactly as committed. `NUMBERS.md` lists each number with its source file. Numbers marked with a dagger in the manuscript come from two private sources, released here:

- `replication/cleanroom/`: the two specification-only reimplementation rounds of 2026-10-04 (section 5.2 of the manuscript). `GAPS_round1.md` and `GAPS_round2.md` are the agents' own gap reports; `verify_round1.py` and `verify_round2.py` are the verifiers they wrote. The agents saw only the specification text, the fixture bundles and (round 2) VERIFIER.md and the canonical vectors; they did not see the reference code or the expected results, and had no network. The operator scored their outputs afterwards against the frozen expectations of interop-v0 and interop-v0.1.
- `replication/log_extracts.md`: the lines of the operator's work log (Japanese) that the manuscript cites.

To rerun the main measurements:

| Measurement | Command (from the repository root) |
|---|---|
| Frozen corpora, reference | `node workers/hs-ledger/nenrin/interop-v0.2/edge/run_edge.mjs` and the runners in each `interop-*` directory |
| Survivors corpus | `node workers/hs-ledger/nenrin/interop-v0.3/survivors/run_survivors.mjs` |
| Mutation analysis | `python3 workers/hs-ledger/nenrin/conformance-v0/adequacy-v0/run_adequacy.py --no-tool` (or `--tool <path to corpus-adequacy 0.8.0>`) |
| Chain recomputation over the snapshot | `workers/hs-ledger/nenrin/survive-v0/kept/export.jsonl` with the recipe in `workers/hs-ledger/src/chain_v1.mjs` |
| Board | `ops/tsunagi/BOARD.md` and `ops/tsunagi/board.json` (nightly, `.github/workflows/tsunagi-board.yml`) |
| Indicators and zeros | `docs/metrics/INDICATORS.md`, `ops/adoption/latest.json` |
| Concurrency audit | `ops/concurrency_audit_20261013.md` |

## Rerun it from outside

The replication package is archived as doi:10.5281/zenodo.23344510 (the commit `1b854544a2b1` built with `make_replication_zip.sh`). The quickest outside check needs no clone and takes a few minutes: in an empty directory,

```
npm init -y && npm install nenrin-verify@0.5.2
npx nenrin-tsunagi run nenrin-interop-v0.3-survivors -- "node node_modules/nenrin-verify/tsunagi_reference_batch.mjs {in} {out}"
```

The last line should read `nenrin-interop-v0.3-survivors: 9/9 verdict signatures reproduced (refereed by nenrin-tsunagi)`. To test a verifier of your own instead of ours, replace the quoted command with yours; `nenrin-tsunagi` writes all nine bundles to `{in}` as a JSON array `[{"name": ..., "bundle": ...}]` and reads `{out}` as a JSON object `{<name>: {"verdict": ..., "refusals": [...], "findings": [...]}}`. If you run it, please post the output in an issue of this repository. A run of your own verifier is recorded, with your permission, in `tools/adoption/registry.json`; the open calls are listed there.
