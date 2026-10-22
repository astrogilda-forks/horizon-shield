# Interop table

Where an implementation, or a run of one, was checked against the same bytes, and what came out. This page counts
agreement and disagreement; it does not certify anything. Rows are split by who ran them:

- **Outside**: someone other than this project wrote the implementation or ran the check, on their own machine, and
  published the result. These are the only rows we count as independent.
- **Ours**: checks this project runs, on code from others or from us. Useful, not independent.

Every row names the commit, the input and where the result is published, so it can be run again. Last updated
2026-10-22.

## Outside

| what was checked | who | against what | result | where |
|---|---|---|---|---|
| MUSUBI settle core v0, a second implementation | aeoess (`aeoess/musubi-settle-core-check` at `53cfafb`) | the 128 settle core vectors at revision 0.4 (`dd64d0e2`), eight core fields | 128 of 128 agree, no unassessed field | [NOTES.md N19](../workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/NOTES.md), Issue #49 |
| MUSUBI settle core v0, a third implementation, written from the text and the vectors only | `kuangmi-bit` (`kuangmi-bit/nenrin-independent-verifiers` at `bbe455c`) | the same 128 vectors | 128 of 128 agree; two places where the text and the vectors pulled apart, stated in revision 0.6 | [NOTES.md N20](../workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/NOTES.md), Issue #49 |
| The #51 set 2 settlement (22 October), recomputed | Poke-nushi | `pilot51/set2/bundle.json` at `b85029de`, `ca2a-runtime` 0.4.0 | the published output sha256 reproduced exactly; signatures and the checkpoint's OpenTimestamps proof checked; with the reader's own headers to block 972564 the verdicts are unchanged and only `anchor_depth` moves from 9 to 14 | [#51 comment](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6332669484) |
| The #51 set 2 audits, compared across two rows | aeoess (APS row) | the A and B audit files of each row | byte identical: A `c2920477…` (1,532 bytes), B `40bc2a46…` (1,101 bytes) | [#51 comment](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6330218168) |
| The Agent Errata node and its part of E6 (agent-governance-vocabulary) | Pico, the AI agent that maintains Agent Errata | `e6-consumer.ts` at `8363d2c` (sha256 `fad87cec…`) on a fresh clone of e6-fixture v1.1.0 (`8d8fc50`) | 12 of 12 agree on verdict, decisive check, all eight claims and every code, the same lines as our record; the consumer is theirs, the fixture is neither theirs nor ours | [#179 comment](https://github.com/aeoess/agent-governance-vocabulary/pull/179#issuecomment-6332546428) |
| The #51 set 2 acceptance records | babyblueviper1 | MUSUBI set 2 A and B, APS A and B, criteria `6d62ca38…` | A passes all four criteria, B fails three (fixture hash, a missing line, the total), as expected; the records are not yet public | [#51 comment](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6331414511) |

Earlier reproductions of our bytes or verdicts by other authors are listed with their sources in
[`tools/adoption/registry.json`](../tools/adoption/registry.json) and summarized in the README.

## Ours

| what was checked | implementations | against what | result | where |
|---|---|---|---|---|
| A2A Agent Card signing across the official SDKs | a2a-python, a2a-js, a2a-go (not ours), measured by our CI on each new SDK version | the signing interop matrix and the signed corpus a2a-card-sign-v01 | per SDK and per group, posted on each run | [Issue #28](https://github.com/ogasurfproject-jpg/horizon-shield/issues/28) |
| NENRIN provenance verifier, three languages | JavaScript (reference), Python, Go, all by this project | every frozen bundle and its mutations, on every push | must agree; the parity workflow fails otherwise | `nenrin-verify (Python) parity` workflow, [`sdk-go/parity/parity.py`](../workers/hs-ledger/nenrin/sdk-go/parity/parity.py) |
| The same three verifiers on text-level rewrites | the same three | 65 inputs: five `interop-v0.2/edge` bundles, each rewritten at the JSON text level 12 ways (duplicate keys, number spellings, -0, 2^53+1, a lone surrogate, a raw U+2028, key order, an escaped hyphen) and sent as the same bytes to all three | 65 of 65 agree (2026-10-22, `a1f31dfe`); rewrites that keep the value give the original verdict, as VERIFIER.md says for a parsed value | [`sdk-go/parity/xlang_step1.py`](../workers/hs-ledger/nenrin/sdk-go/parity/xlang_step1.py) |
| MUSUBI settle core reference | `settle_v1_16.py` | the 128 vectors | 128 of 128 on every revision since 0.4 | `settle-core-v0/run_reference.py` |

## How to add a row

Run an implementation you wrote, or one we did not write, against published bytes, and publish the result where
others can read it: the commit you ran, the input, the output and its sha256. Then tell us in an issue. We add the row
with a link to your result; we do not add a row from a private report.
