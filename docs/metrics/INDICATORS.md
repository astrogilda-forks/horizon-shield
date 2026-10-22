# HORIZON SHIELD and NENRIN: indicators, kept apart

Prepared 2026-10-13 from repository commit `ff591887` and from public pages read on that day. Machine-readable copy: [`sources.json`](sources.json).

An outside reviewer pointed out that this project was mixing four different things in one breath: GitHub page views, directory impressions, citations in LLM answers, and real use. One sentence in the README had done exactly that: it called one directory's 93,983 listing impressions "AI search results" and set them against a zero that only held for calls made through that one listing. It was corrected in commit [`c2c596c6`](https://github.com/ogasurfproject-jpg/horizon-shield/commit/c2c596c6019e2a404e67c53d2e76fc65164a44ea). This page lists each indicator on its own, so that cannot happen again by accident.

## How to read this page

1. **No indicator is added to another.** There is no total on this page and none should be made from it. The same person or project can appear in several sections; adding the sections would count them twice.
2. **A number appears only where a public source supports it**, one a stranger can open without an account of ours. Where there is no such source, the cell says *not measured publicly*, *not published* or *to confirm*. The two places where this page repeats a figure only we can see are labelled *owner-reported, not checkable*, and they are not used as indicators.
3. **Every number has a source link, the date it was measured, and a line saying what it does not show.**
4. **Verification is not endorsement.** In the words of [aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177): "Verifying another project's artifact should mean exactly that, not endorsement of everything the project does." Someone who reproduced our bytes got the same bytes. They did not thereby adopt, recommend or depend on NENRIN.
5. **"Independent" means the person or project does not work for HORIZON SHIELD and wrote or ran the check themselves.** It does not mean they have no relationship with us. Several have worked with us in public threads; that is noted next to their rows.
6. **"To confirm"** means the source could not be read from where this page was prepared on 2026-10-13. Nothing is inferred from that, in either direction.

## Summary

| # | Indicator | Value | Source | Measured | Confidence |
|---|---|---|---|---|---|
| 1 | Merged contributions to external projects | 4 pull requests whose changes are on the upstream default branch; the merge record itself was read on the PR page for 1 of them. 1 open (a2a-tck#246); 2 to confirm | upstream files and PR pages | 2026-10-13 | high that the content is upstream; merge dates for 3 of 4 to confirm |
| 2a | Independent implementations that reproduced our bytes or verdicts | 14 rows by 7 authors in the weekly count; 2 more implementations on the nightly board since then | [`ops/adoption/latest.json`](../../ops/adoption/latest.json), [`ops/tsunagi/BOARD.md`](../../ops/tsunagi/BOARD.md) | 2026-10-12 (count), 2026-10-13 (board) | high: each row links to the author's own public post or repository |
| 2b | Reproduced with our own tool | 3 (one person, one template repository, one reviewer) | issue and PR comments, GitHub Actions | 2026-10-05 to 2026-10-12 | medium |
| 2c | Outside domains that signed a walk and filed it to our ledger | 3 | ledger entries, read by [`count_adoption.py`](../../tools/adoption/count_adoption.py) | 2026-10-12 | high |
| 3 | External production runs of NENRIN or MUSUBI by unaffiliated parties | 0 shown | see section 3 | 2026-10-13 | high that none is shown |
| 4 | Citations in LLM answers | not measured publicly | see section 4 | | |
| 5 | Directory listings | listing and grading data only; no directory shows a usage figure we can check | directory pages | 2026-10-13 | medium |
| 6 | Paid usage and retention | not published (owner decision) | | | |

## 1. Merged contributions to external projects

A pull request we wrote that the other project took into its default branch.

### Merged

| Project and PR | Date | What it changed | How it was checked (2026-10-13) |
|---|---|---|---|
| [a2aproject/a2a-python#1286](https://github.com/a2aproject/a2a-python/pull/1286) | 2026-10-07 by our records (README); to confirm on the PR page | Adds `tests/utils/signing_interop_vectors.json` and `tests/utils/test_signing_interop.py` to the official A2A Python SDK: one Agent Card signed by a2a-sdk, @a2a-js/sdk, a2a-go and a reference signer must verify, and the same card edited after signing must be rejected. Test files only, no library code | Both files are on `main` ([vectors](https://raw.githubusercontent.com/a2aproject/a2a-python/main/tests/utils/signing_interop_vectors.json), [tests](https://raw.githubusercontent.com/a2aproject/a2a-python/main/tests/utils/test_signing_interop.py)). The TSUNAGI board ran them from a fresh clone at a2a-python commit `0ee47d7b`: 10 of 10. The PR page, as our fetch returned it, still showed "Open", which conflicts with the files being on `main`; the merge date and the merger are therefore marked to confirm |
| [agentrust-io/trace-spec#480](https://github.com/agentrust-io/trace-spec/pull/480) | 2026-10-08 by our records ([trace-pin-v0/README.md](../../workers/hs-ledger/nenrin/trace-pin-v0/README.md)); to confirm on the PR page | Adds the informative page `docs/verifying-after-the-freshness-window.md` (how a relying party can check a TRACE record after its 24 hour window, naming no service) and one link each in `mkdocs.yml`, `verification.md` and `verification-outcome-statements.md` | [The page is on `main`](https://raw.githubusercontent.com/agentrust-io/trace-spec/main/docs/verifying-after-the-freshness-window.md). The PR page as fetched showed "Open"; same conflict as above |
| [aeoess/agent-governance-vocabulary#192](https://github.com/aeoess/agent-governance-vocabulary/pull/192) | 2026-10-05, merged by aeoess | Adds `crosswalk/nenrin.yaml` (how NENRIN's records map to the shared vocabulary) and the regenerated `docs/generated/crosswalk-matrix.md`. The maintainer's review checked the cited lines at commit `a2c1c0b` and recomputed the run0002 MUSUBI settlement offline | PR page shows "Merged" and "aeoess merged 3 commits"; [the file is on `main`](https://raw.githubusercontent.com/aeoess/agent-governance-vocabulary/main/crosswalk/nenrin.yaml) |
| [aeoess/agent-governance-vocabulary#195](https://github.com/aeoess/agent-governance-vocabulary/pull/195) | to confirm | Restores the `governance_attestation` row of `crosswalk/nenrin.yaml` as a partial match resting on a signed witness record a reader can verify | The restored row is in the file on `main`. The PR page as fetched showed "Open"; merge date to confirm |

**What this does not show.** That any of these projects uses NENRIN, depends on it or endorses it. Test vectors in an SDK's test suite test the SDK. A crosswalk maps names between vocabularies; it says nothing about quality. An informative documentation page is not normative.

### Open, not merged

| Project and PR | Opened | State on 2026-10-13 |
|---|---|---|
| [a2aproject/a2a-tck#246](https://github.com/a2aproject/a2a-tck/pull/246) | 2026-09-30 | Open, no review. Adds the a2a-card-sign-v01 corpus, an offline runner and a CI workflow to the A2A test kit |
| bernstein #6442 | to confirm | Not read: the PR could not be located from here (the project's repository appears to be `sipyourdrink-ltd/bernstein`, also to confirm) |

### To confirm

- **perma-id/w3id.org#6653**, recorded in [CONDUCT_EXT_v1.md](../../workers/hs-verify-gate/ext/CONDUCT_EXT_v1.md) as merged on 2026-09-09 (a permanent identifier `https://w3id.org/horizonshield/conduct/v1`). On 2026-10-13 the path `horizonshield/` did not resolve on the repository's `master` branch through raw.githubusercontent.com, and w3id.org itself was not reachable from here. Not counted until confirmed.

## 2. Independent verifiers

People or projects that ran one of our artifacts themselves. Split by whether they wrote their own reader.

### 2a. Independent implementation: their own reader, without our code

Count: **14 rows by 7 authors**, from the weekly count of 2026-10-12 ([`ops/adoption/latest.json`](../../ops/adoption/latest.json), rows in [`tools/adoption/registry.json`](../../tools/adoption/registry.json); the script checks that every link still answers). One link (the Probity atlas) answered 503 during that count and 200 when read again on 2026-10-13.

| Who | Artifact | What they ran | Date | Link | Rerun nightly on TSUNAGI |
|---|---|---|---|---|---|
| `kuangmi-bit` | pinned gate Agent Card | own Go implementation of the @a2a-js/sdk canonical form, 6410 bytes, byte for byte | 2026-09-28 | [a2a-go#445](https://github.com/a2aproject/a2a-go/issues/445#issuecomment-5879965988) | no |
| `kuangmi-bit` | a2a-card-sign-v01, 24 signed vectors | own ES256 harness against the published test key | 2026-10-01 | [A2A#2122](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5937659218) | no |
| `kuangmi-bit` | NENRIN interop-v0, then v0.1 and v0.2/edge | two separate provenance verifiers written from the specification text alone | 2026-10-04 | [#1631 (1)](https://github.com/a2aproject/A2A/discussions/1631#discussioncomment-18738206), [#1631 (2)](https://github.com/a2aproject/A2A/discussions/1631#discussioncomment-18739314) | yes, [kuangmi-bit/nenrin-independent-verifiers](https://github.com/kuangmi-bit/nenrin-independent-verifiers) |
| Sankalp Gilda (`astrogilda`), Probity AI | a2a-card-sign-v01 | verifier written from A2A section 8.4.1 only; then the 13 unknown-field and 5 dual-name cases | 2026-10-01, 2026-10-02 | [A2A#2122](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5936546281), [agent-evidence-vectors#34](https://github.com/probityai/agent-evidence-vectors/pull/34), [#42](https://github.com/probityai/agent-evidence-vectors/pull/42) | yes, self-scored |
| Sankalp Gilda, Probity AI | signed NENRIN witness records | a second reader written from the record format; checks two outside walks (ledger entry 73) | 2026-10-09 | [agent-evidence-atlas](https://github.com/probityai/agent-evidence-atlas/blob/2bff38d8c13f7038d8d773bc77e44ab4f160751a/examples/nenrin-witness-pair/README.md) | no |
| `aeoess` | a2a-card-sign-v01 | own harness for the s3 cases; then a served-scope verifier entry point for a2a-python | 2026-10-01, 2026-10-02 | [A2A#2122 (1)](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5940903881), [A2A#2122 (2)](https://github.com/a2aproject/A2A/issues/2122#issuecomment-5946262435) | no |
| Agenstry (agent directory) | the gate's Agent Card signature | own verifier, 10 of 10 | 2026-09-28 | [agenstry.com listing](https://agenstry.com/agents/gate.horizonshield.dev) | no |
| Federico Blanco Sánchez-Llanos (`babyblueviper1`) | MUSUBI approval-v2 | own reference verifier and 9 vectors; our settle v1.10 agrees 9 of 9 | 2026-10-05 | [issue #29](https://github.com/ogasurfproject-jpg/horizon-shield/issues/29#issuecomment-5987427704) | yes |
| `luiksksk` | TRACE intake (trace-intake-v0) | clean-room Node.js verifier from the SPEC text, 28 cases | 2026-10-09 | [PR #38](https://github.com/ogasurfproject-jpg/horizon-shield/pull/38) | yes |
| a2aproject/a2a-python | a2a-card-sign-v01 s0-control | the SDK's own canonicalizer and verifier, run on our vectors in its CI | 2026-10-07 (to confirm, see section 1) | [#1286](https://github.com/a2aproject/a2a-python/pull/1286) | yes, self-scored |

On the [TSUNAGI board](../../ops/tsunagi/BOARD.md) of 2026-10-13 but not yet in the weekly count: `babyblueviper1-nenrin-cleanroom` (NENRIN interop v0, v0.1 and v0.2/edge, passing since 2026-10-09) and `agent-evidence-atlas-action-presence` by Probity (9 of 9, first run 2026-10-13).

**Relationships, stated plainly.** `babyblueviper1` operates `api.babyblueviper.com`, which is our counterparty in two MUSUBI contracts and one agreement record, and is credited in `CITATION.cff`. `kuangmi-bit` contributed PR #30 to this repository and is a party to a MUSUBI contract (section 3). The a2a-python vectors were written and contributed by us; what they exercise is the SDK's own code. `aeoess` maintains the vocabulary that merged our crosswalk.

**What this does not show.** Use. Each row says one implementation produced the same bytes or verdicts as ours on a published corpus, on that day (and, where marked, again each night). It does not say the author adopted or approves of anything, and seven authors is a small number.

### 2b. Reproduced with our own tool

| Who | What they ran | Date | Link |
|---|---|---|---|
| Pavlo Tvardovskyi (`pipavlo82`) | installed `nenrin-verify` 0.4.5 from PyPI on his own runner and ran the full suite; later the 0.4.7 suite on Windows 11. In his words, a reproduction of published synthetic tests and fixtures, not a security audit or a live two-party contract | 2026-10-05 | [issue #29](https://github.com/ogasurfproject-jpg/horizon-shield/issues/29#issuecomment-5994495262), [his run](https://github.com/pipavlo82/conduct-witness/actions/runs/37309427202) |
| `kuangmi-bit/conduct-witness` | a repository created from our `conduct-witness-template`; its weekly reproduce workflow succeeded, last on 2026-10-06 | counted 2026-10-12 | [kuangmi-bit/conduct-witness](https://github.com/kuangmi-bit/conduct-witness) |
| `aeoess` | recomputed the run0002 MUSUBI settlement byte for byte offline, with the published settle code, while reviewing #192 | 2026-10-05 | [review comment](https://github.com/aeoess/agent-governance-vocabulary/pull/192#issuecomment-5999460575) |

**What this does not show.** That our tool is correct. Running our tool and getting our answer checks that the published files and the tool agree; it is weaker evidence than an independent reader.

### 2c. Outside domains that signed a walk and filed it to our ledger

Count: **3** signed domains, read from every `nenrin-witness-batch-v1` entry of the JIDEC ledger (88 entries) on 2026-10-12: `api.babyblueviper.com` (entries 57, 61), `kuangmi-bit.github.io` (71, 73, 75, 77, 79, 84), `pipavlo82.github.io` (65, 73). Three unsigned walks are listed by name and not counted. Source: [`ops/adoption/latest.json`](../../ops/adoption/latest.json). How to recount: `python3 tools/adoption/count_adoption.py` reads `https://ledger.horizonshield.dev/ledger/<n>` for each entry.

**What this does not show.** A walk is an observation of one of our own endpoints. It says who observed and when, under their key; it is not use of NENRIN in their own systems. The re-verification pool still has one member in one control cluster, short of its quorum of two.

### Not counted here

- **VLC-1.** The README lists [VLC-1](https://github.com/MattyIceMatrix/vlc-1) among outside evidence. VLC-1's own `THIRD-PARTY.md` labels the JIDEC rows "scored by its own operator", that is, by us with their checker; their CI rescores the committed export. That is an outside specification applied to our ledger, not an outside verifier.
- **The A2A interop matrix** ([`workers/a2a-card-sign/interop-matrix`](../../workers/a2a-card-sign/interop-matrix/README.md), results of 2026-10-01) is our own measurement of three SDKs.
- **TSUNAGI rows marked "this project"** are our own implementations.

## 3. External production runs of NENRIN or MUSUBI

**0 shown.**

What exists, and why none of it counts as production use by an unaffiliated party:

| What | Detail | Why it is not counted |
|---|---|---|
| 1 MUSUBI contract with no party from this project | `agent-passport.org` (principal) and `kuangmi-bit.github.io` (contractor), agreed 2026-10-06, settled `final`, verdict `within_grant`, final at Bitcoin block 970543; the settlement recomputes here byte for byte. [Their repository](https://github.com/kuangmi-bit/musubi-peer-contract) | The task in the signed contract is "independent reproduction of the NENRIN interop-v0.2/edge corpus". The parties met in our issue #31 and built it with our `peer_kit.py`. It is a demonstration whose subject is our own artifact |
| 2 MUSUBI contracts and 1 agreement record | with `api.babyblueviper.com` | HORIZON SHIELD is a party to each |
| Outside hosts that used our hosted gate | README: 5 real hosts in the 30 days to 2026-10-02, from `https://gate.horizonshield.dev/usage` | Use of a service we run, not their running of NENRIN. To confirm: the endpoint was not reachable from here |
| Rows on the public conduct register that are not ours | README: 2 of 10 (one pending, one added anonymously and not yet measured), from `https://gate.horizonshield.dev/register` | Registrations, not runs. To confirm, as above |
| Outside TRACE signing keys pinned with trace-pin-v0 | 0, on 2026-10-12 ([`latest.json`](../../ops/adoption/latest.json)) | |

**What would count.** A party with no affiliation to HORIZON SHIELD, running NENRIN records or MUSUBI contracts in its own service, for work whose subject is not one of our artifacts, on its own schedule, leaving public records a stranger can recompute: for example a settled MUSUBI contract between two outside parties for their own work, or recurring ledger filings by an outside system that our calls did not prompt.

## 4. Citations in LLM answers

**Not measured publicly.** No raw measurement output is published in this repository, so this page carries no citation figure.

What exists:

- `ops/llm_visibility_monitor.py` asks one model (Claude Sonnet 4.6 with web search) 17 fixed questions in Japanese and records whether the answer cites our site. The last committed summary, [`ops/visibility_last_run.txt`](../../ops/visibility_last_run.txt), dated 2026-09-14, reads 0 of 17. *Owner-reported, not checkable*: the answers themselves are not published. One model, one day, Japanese questions only.
- A note in Japanese, [`ops/citation_instrument_20260915.md`](../../ops/citation_instrument_20260915.md), summarises the AI Performance report of Bing Webmaster Tools, a dashboard only the site owner can see. The exports are not committed, so its figures are not repeated here.

These two instruments measure different engines and must never be combined. The same note records that calling both of them "citations" was itself an earlier mistake.

**What this does not show.** The 93,983 figure is not an LLM citation count (see section 5).

## 5. Directory listings and their own statistics

Everything in this section is **listing, grading or impression data. None of it is usage.** Pages read on 2026-10-13.

| Directory | Listing | What the page shows | Usage figure on the page |
|---|---|---|---|
| Glama, server page | [HORIZON SHIELD KIRA](https://glama.ai/mcp/servers/ogasurfproject-jpg/horizon-shield) | listed, 15 tools; the score is shown only as a badge image (to confirm) | none |
| Glama, connector | [HORIZON SHIELD YAKUMO](https://glama.ai/mcp/connectors/io.github.ogasurfproject-jpg/hs-hearing) | Healthy; uptime 100.0% over 56 days; tool definition quality A, 4.4 of 5 across 6 tools (scored 2026-08-20); last tested 2026-10-13 07:11 | none |
| Glama, connector | [HORIZON SHIELD WebMCP Intake](https://uncloud.glama.ai/mcp/connectors/io.github.ogasurfproject-jpg/horizon-shield-webmcp) | "Unhealthy" (Glama could not connect); tool definition quality average 4.3 of 5 across 5 tools | none |
| Glama, connector | `dev.workers.oga-surf-project.hs-mcp/horizon-shield` | marked Deprecated (old namespace) | none |
| mcp.so | [horizon-shield](https://mcp.so/zh/servers/horizon-shield) | listed; shows "No tools detected" and transport "stdio" although the server is Streamable HTTP; its description still says 14 tools | none |
| Official MCP Registry | `io.github.ogasurfproject-jpg/horizon-shield` (1.1.0) and `io.github.ogasurfproject-jpg/horizon-shield-webmcp` (1.0.4), per [`server.json`](../../server.json) and [`server-webmcp.json`](../../server-webmcp.json) | to confirm: the registry API was not reachable from here. The registry publishes metadata, not usage | none |
| Agenstry | [gate.horizonshield.dev](https://agenstry.com/agents/gate.horizonshield.dev) | listing with their own signature check (section 2a) | none |
| Smithery, the Claude directory, the ChatGPT app directory | | not read for this page; to confirm | |

**Owner-reported, not checkable.** The README (after `c2c596c6`) and [`verify-directory/index.html`](../../verify-directory/index.html) quote one directory's own dashboard: in the thirty days to 2026-08-14, the listing was shown 93,983 times, with 24 clicks, 421 profile views and zero tool calls made through the listing. Only the listing owner can see that dashboard, and the directory is not named in the repository. These are impressions on one directory. They are not search results, not AI citations, not visitors and not users, and the zero covers only calls made through that listing.

**What this does not show.** Being listed, graded or healthy says nothing about whether anyone calls the server. A tool definition grade rates how tools are described, not whether their answers are right. Uptime is the directory's own probe.

### Other counters this page does not use

- **GitHub traffic** (views, clones): visible only to repository admins. Not shown.
- **Package downloads** (npm, PyPI) and **Zenodo views**: public, but not read for this page; they count downloads and page views, not use.
- **The servers' own usage counter**: it deliberately stores no IP addresses, so it cannot separate our own scheduled checks from outside calls. Not used as a usage figure.

## 6. Paid usage and retention

**Not published (owner decision).** No figures.

## Discrepancies found while preparing this page

- Glama's copy of the README, as read on 2026-10-13, still carried the withdrawn sentence calling the 93,983 "AI search results". Glama refreshes its copy from the repository; recheck after its next sync.
- [`WITNESSES.md`](../../workers/hs-ledger/nenrin/WITNESSES.md) lists two signed witness domains; the ledger count of 2026-10-12 has three (`kuangmi-bit.github.io` is missing from the table). The file itself says the ledger is right when they disagree.
- The README's VLC-1 row reads as if VLC-1's maintainers scored our ledger; VLC-1 labels those rows as scored by their own operator (section 2, "Not counted here").
- The open call in `tools/adoption/registry.json` says the NENRIN provenance verifiers so far are "two, both by kuangmi-bit"; the TSUNAGI board has run `babyblueviper1-nenrin-cleanroom` on the same corpora since 2026-10-09.
- The mcp.so listing shows "No tools detected", transport "stdio" and an old tool count.
