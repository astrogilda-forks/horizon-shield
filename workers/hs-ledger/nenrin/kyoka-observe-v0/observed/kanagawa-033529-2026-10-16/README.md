# 神奈川県知事許可 第033529号, observed 2026-10-16

The first lookup of a real licence with `kyoka-observe-v0`: Yakumo member No.002, ミネオトーヨー住器株式会社 of
Hiratsuka, whose licence number came from its own hearing answer (ガラス工事業・建具工事業, 般-3). Run
[38829262688](https://github.com/ogasurfproject-jpg/horizon-shield/actions/runs/38829262688) of `kyoka-observe.yml` at
commit `40ff550a`, dispatched by hand.

The register answered with one row for that number under 神奈川県: ミネオトーヨー住器（株）, 主たる営業所, at the
address the register publishes. No representative's name is in these files; the register's page that shows it was
re-read by the run and left on the runner.

| file | what |
| --- | --- |
| `observation.json` | the signed record: query, fixed request, sha256 of the 32,614 bytes received, the row |
| `binding.json` | the observer key bound to this run's GitHub Actions OIDC identity (`repo:ogasurfproject-jpg/horizon-shield:environment:nenrin-observer`). The token inside expired at 2026-10-16T00:29:28Z, before it was uploaded |
| `jwks.json` | GitHub Actions' JWKS as the run fetched it, pinned by sha256 |
| `SHA256SUMS` | the three files |

## Recheck

```
cd workers/hs-ledger/nenrin
node issuer-keys-v0/check.mjs --binding kyoka-observe-v0/observed/kanagawa-033529-2026-10-16/binding.json \
                              --jwks    kyoka-observe-v0/observed/kanagawa-033529-2026-10-16/jwks.json
node kyoka-observe-v0/observe.mjs --verify kyoka-observe-v0/observed/kanagawa-033529-2026-10-16 \
     --trust https://token.actions.githubusercontent.com=5f8164c9696c27837ad18c5fe7c7022a433bd5390183e8ff15c74d82233270f4
```

The first says every key in that JWKS was one GitHub Actions served on 2026-10-16 according to
[`issuer-keys-v0`](../../../issuer-keys-v0) and prints the `--trust` above. The second then reports
`accepted ["response_not_supplied","observer_bound"]`: the record names the GitHub Actions run as the observer. Without
`--trust` the same record is `observer_self_pinned`.

## What it establishes, and what it does not

Established: the key bound to that public GitHub Actions run signed that it asked the register about 神奈川県知事許可
第033529号 at 2026-10-16T00:24:28Z, received 32,614 bytes with that sha256, and read one row for that licence.

Not established: that the register served those bytes (TLS does not sign content, and the bytes are not published here
because the page shows a person's name); which trades the licence covers or when it expires (the list page does not
carry them; the hearing answer says ガラス工事業・建具工事業, and "般-3" suggests a licence granted in 令和3年, which
would make 2026 its renewal year, a question for the detail page in v0.2); and anything about the quality of the work.
