# 神奈川県知事許可 第033529号, observed 2026-10-16 with the detail page

The second lookup of Yakumo member No.002, ミネオトーヨー住器株式会社 of Hiratsuka, now with `kyoka-observe` 0.2.0,
which also reads the register's detail page for the licence. Run
[38836053603](https://github.com/ogasurfproject-jpg/horizon-shield/actions/runs/38836053603) of `kyoka-observe.yml` at commit `cc966d2d`, dispatched by hand.
It answers the question the [first lookup](../kanagawa-033529-2026-10-16) left open.

| | |
| --- | --- |
| list page | one row: ミネオトーヨー住器（株）, 主たる営業所 (32614 bytes) |
| trades | ガラス工事 (一般), 建具工事 (一般) |
| period of validity | 2026-11-24 to 2031-11-23 (the register prints R08年11月24日からR13年11月23日まで) |
| detail page | 12232 bytes, sha256 `34890695380966c7fe2da998fd79e4d019601cd5fd9a0fb169fd15d0c6f3ba0c` |
| observation_id | `55eef15f8031b84acee04bd92fbe3f115d4fb20f570fb61488d3d6b34f9f4642` |

The period shown starts after the day observed, so the reader also reports `validity_starts_after_observation`: the
register already shows the renewed licence (its 許可年月 on the page is R08/11/24), and the period before it, which
the hearing answer's 般-3 points to, is not on the page.

No representative's name and no telephone number are in these files. Both pages were re-read by the run and deleted
on the runner.

| file | what |
| --- | --- |
| `observation.json` | the signed record: query, both fixed requests, sha256 of both responses, the row, the trades and the period |
| `binding.json` | the observer key bound to this run's GitHub Actions OIDC identity (`repo:ogasurfproject-jpg/horizon-shield:environment:nenrin-observer`). The token inside expired at 2026-10-16T01:42:15Z, before it was uploaded |
| `jwks.json` | GitHub Actions' JWKS as the run fetched it, pinned by sha256 |
| `SHA256SUMS` | the three files |

## Recheck

```
cd workers/hs-ledger/nenrin
node issuer-keys-v0/check.mjs --binding kyoka-observe-v0/observed/kanagawa-033529-2026-10-16-detail/binding.json \
                              --jwks    kyoka-observe-v0/observed/kanagawa-033529-2026-10-16-detail/jwks.json
node kyoka-observe-v0/observe.mjs --verify kyoka-observe-v0/observed/kanagawa-033529-2026-10-16-detail \
     --trust https://token.actions.githubusercontent.com=5f8164c9696c27837ad18c5fe7c7022a433bd5390183e8ff15c74d82233270f4
```

The second reports `accepted` with the findings `response_not_supplied`, `detail_response_not_supplied`,
`validity_starts_after_observation` and `observer_bound`.

## What it establishes, and what it does not

Established: the key bound to that public GitHub Actions run signed that at 2026-10-16T01:37:15Z it asked the register about
神奈川県知事許可 第033529号, read one row for that licence on the list page, and read on the detail page the trades
ガラス工事 and 建具工事, both 一般, and the period of validity above.

Not established: that the register served those bytes (TLS does not sign content, and the bytes are not published
because both pages show a person's name); that the licence covers a particular job (the register lists trades, not
jobs, and 一般 is about subcontracting amounts, not quality); that it was in force before 2026-11-24 (that period is
not on the page); and anything about the quality of the work.
