# NENRIN witnesses and how they are credited

A witness is anyone outside this project who measured a public agent and filed the record in the NENRIN ledger. A signed witness filed it under a key served from their own domain, or from a repository their GitHub account owns, so the record is counted under that domain (or `github.com/<account>`) rather than under a name anybody can type.

## Credit

A witness whose signed record is in the ledger can be named in the citation metadata of NENRIN:

1. as a contributor (DataCite type `DataCollector`) in the next version of the NENRIN Zenodo record, DOI [10.5281/zenodo.23136978](https://doi.org/10.5281/zenodo.23136978), and
2. in `CITATION.cff` at the root of this repository,

so the name travels with every citation of the work.

Credit is given only with the witness's consent, under the name they choose. A handle is enough. To accept, say so in an issue in this repository or in the thread where you were invited. Withdrawing consent removes the name from the next version. The ledger records themselves cannot be edited or removed by anyone, us included, and each one carries its own date and its Bitcoin anchor.

Credit says that you measured, signed and were counted. It is not an endorsement of this project by you, nor of you by this project. Disagreeing records are credited exactly as agreeing ones are.

## Signed witnesses on the ledger

| signed_domain | ledger entries | credited in citation metadata |
|---|---|---|
| api.babyblueviper.com | 57, 61 | yes, as babyblueviper1 (invinoveritas), 2026-10-05 ([#25](https://github.com/ogasurfproject-jpg/horizon-shield/issues/25#issuecomment-5986324421)). In CITATION.cff now; in the next Zenodo version when it is published. The verifiable reference stays the signing identity api.babyblueviper.com. |
| pipavlo82.github.io | 65 | yes, as pipavlo82, 2026-10-05 ([#27](https://github.com/ogasurfproject-jpg/horizon-shield/issues/27)). In CITATION.cff now; in the next Zenodo version when it is published. Scope: this signed walk only, with the Codex assistance and the collaboration context disclosed in the record; not a member of the re-verification pool. |

The table is kept by hand. `tools/adoption/count_adoption.py` reads the signed domains straight from the ledger export (`https://ledger.horizonshield.dev/ledger/export.jsonl`) and writes them to `ops/adoption/latest.json`; if that and this table disagree, the ledger is right and this table is wrong.

## How to become one

1. One file, no domain and no installer: put your public key in a repository you own and sign with `witness.key_url` set to its raw URL on a branch or tag (`https://raw.githubusercontent.com/<you>/<repo>/main/nenrin-witness-key.json`). You are counted as `github.com/<you>`. A commit SHA as the ref is refused. Details: [a2a-conduct-walk](a2a-conduct-walk/README.md), section 4a.
2. One command, no domain of your own: [conduct-witness-template](https://github.com/ogasurfproject-jpg/conduct-witness-template). Your records are signed under `<you>.github.io`, and once a week your runner recomputes the published evidence with a GitHub attestation under your repository.
3. One signed walk with the reference client and a key on your own domain: [a2a-conduct-walk](a2a-conduct-walk/README.md), section 4a (`--key` and `--key-url`).
4. A standing place in the re-verification pool, answering witness requests from your own A2A agent: [BECOME_A_WITNESS.md](recovery-v0/BECOME_A_WITNESS.md).
