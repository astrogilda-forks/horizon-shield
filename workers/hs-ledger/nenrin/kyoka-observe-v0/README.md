# kyoka-observe-v0

A signed record that an observer asked Japan's public register of licensed construction businesses (国土交通省
建設業者・宅建業者等企業情報検索システム, `etsuran2.mlit.go.jp`) about one licence number (建設業許可番号) and what
the register answered that day. Checkable offline. Bound to an identity with [`idp-bind-v0`](../idp-bind-v0), "who
asked" can be a public GitHub Actions run at a public commit, not a statement by HORIZON SHIELD, for a reader who
trusts GitHub's signing keys (see "Who asked" below).

Version 0.1.0 (2026-10-15). Reference: `kyoka_observe.mjs`. Test: `node kyoka_observe.test.mjs` (59 checks). No
dependency outside `node:crypto` and the NENRIN modules next to it.

## Why

"Are you licensed?" is the first question a homeowner should ask a contractor, and it is usually answered by the
contractor. The register is public, but a screenshot proves nothing and a link shows today's answer, not the answer
on the day the contract was signed. This record pins the day's answer.

## The record

    {
      "schema":      "kyoka-observe-v0/observation",
      "observer_id": "did:key:z6Mk...",
      "query":       { "kind": "minister" | "governor", "license_no": "011915", "prefecture": "富山県" (governor only) },
      "request":     { "url": "https://etsuran2.mlit.go.jp/TAKKEN/kensetuKensaku.do", "method": "POST",
                       "body": requestBody(query), "body_sha256": "<sha256 of body>" },
      "response":    { "sha256": "<sha256 of the bytes received>", "length": 29505, "charset": "Shift_JIS",
                       "extractor": "mlit-etsuran-list-v0" },
      "result":      { "status": "listed" | "not_listed" | "unreadable",
                       "rows": [ { "authority", "license_no", "trade_name", "office", "address" } ],
                       "register_message": "" | "該当するデータが存在しません。" },
      "observed_at": "2026-10-15T15:00:00Z",
      "nonce":       "<caller chosen>",
      "observation_id": "<sha256 of canonical(preimage)>",
      "observer_sig":   "<Ed25519 over canonical(preimage), base64>"
    }

Canonical form and preimage as in `provenance-v0/VERIFIER.md` section 2 (the preimage is every own key except
`observation_id` and `observer_sig`).

`requestBody(query)` is fixed: the register's search form with only the licence class and number set (and, for a
governor's licence, the prefecture as kenCode), the number without leading zeros, 50 rows per page. A governor's
licence number repeats across prefectures (第011915号 exists in several), so the extractor keeps only rows whose
許可行政庁 is the queried prefecture; a minister's licence keeps the rows under a regional bureau (関東地方整備局 and
so on), one row per office. The register states how many rows matched in total; when that is more than the page
holds, the record says `rows_truncated: true`, and an empty first page is `unreadable`, never `not_listed`. The form
and the extractor's reading were checked against the live register on 2026-10-15: a minister's licence with 43
offices came back as one page with the seven columns exactly, 43 rows and `resultCount` 43.

The extractor (`mlit-etsuran-list-v0`) decodes Shift_JIS strictly, requires the result table's seven columns exactly
(`No.`, 許可行政庁, 許可番号, 商号又は名称, 代表者名, 営業所名, 所在地), and refuses anything else rather than
guessing (`unexpected_columns`, `unexpected_row`, `no_result_table`). A refused page is recorded as `unreadable`,
never as `not_listed`.

## Verification (offline)

Input: `{ observation, response_bytes?, binding?, jwks? }`.

1. The record is what its id says and the observer signed it: `observation_recompute_mismatch`,
   `observer_id_unresolvable`, `observer_sig_malformed`, `observer_sig_invalid`, `canonical_refused`.
2. The request is the one the query maps to: `request_target_mismatch`, `request_body_mismatch`,
   `request_digest_mismatch`; the query itself: `license_no_malformed`, `prefecture_unknown`, `query_kind_unknown`,
   `prefecture_on_minister`, `query_extra_fields`; the rest: `bad_response_descriptor`, `bad_result`,
   `status_rows_disagree`, `row_fields`, `row_not_for_query` (a row for another number or authority),
`bad_observed_at`, `bad_nonce`, `bad_schema`.
3. With the response bytes: they are the bytes named (`response_digest_mismatch`) and re-extracting them gives the
   recorded result exactly (`extraction_mismatch`; finding `extraction_reproduced`). Without them: finding
   `response_not_supplied`, and the rows are the observer's reading, not rechecked.
4. With an identity binding: it verifies (`binding_refused`), binds `observer_id` (`binding_other_key`), and is
   for the audience `nenrin-kyoka-observe` (`binding_other_audience`). The identity is named (finding
   `observer_bound`) only when the JWKS sha256 is one the reader trusts for that issuer (`trusted`, `--trust`).
   Otherwise the finding is `observer_self_pinned` and no identity is stated: a JWKS shipped in the same folder as
   the binding is the bundle vouching for itself, and anyone can mint a key and a token naming any issuer.

## Who asked

To trust GitHub as the issuer, fetch `https://token.actions.githubusercontent.com/.well-known/jwks` yourself around
the time of the run and compare its sha256 with the one the run printed, then pass
`--trust https://token.actions.githubusercontent.com=<sha256>`. GitHub rotates these keys, so a fetch long after the
run may differ; the run's own summary and the public run log are the other half of the evidence. The token is a
bearer credential for a few minutes; the workflow uploads the binding only after it has expired.

## What it establishes, and what it does not

Accepted means: the holder of `observer_id` (and, when bound under trusted keys, the issuer's subject, for example
`repo:ogasurfproject-jpg/horizon-shield:environment:nenrin-observer`) signed that it sent that exact request to the
register at `observed_at` and received bytes with that sha256. With the bytes, the reader re-reads the rows itself;
without them, the rows are what the observer records.

It does not establish:

- that the register served those bytes. TLS does not sign content; this is what the observer says it received. Two
  independent observers sending the same request and getting the same sha256 is how that is approached, and the
  fixed request and extractor are there so they can be compared.
- that the person or company at your door is the business on the register.
- the licensed trades or the expiry. The list page does not carry them; v0.2 reads the detail page.
- that the register is current. MLIT updates it about twice a month.

## Privacy

The list page shows a representative's name (代表者名). It is never copied into the record (`row_fields` refuses a row
with any other field); it stays inside the hashed response bytes. The workflow re-reads `response.bin` in its own
reader and does not upload it, so a third party can recheck the sha256 only against bytes it obtains itself. For a sole
proprietor the trade name (商号) is usually a person's name as well; it is in the record because it is the answer to
the question, and it is what the register itself publishes. An artifact of a public repository can be downloaded by
any signed-in GitHub user, so a lookup run is a publication of that answer; lookups are dispatched by hand, one at a
time.

## Making one

    node observe.mjs --kind minister --license-no 003000 --out out/
    node observe.mjs --kind governor --prefecture 神奈川県 --license-no 012345 --out out/
    node observe.mjs --verify out/

One query per run, on demand, with a User-Agent that names us. The workflow
[`kyoka-observe.yml`](../../../../.github/workflows/kyoka-observe.yml) runs it with `id-token: write`, binds the
observer key to the run's OIDC identity, re-reads everything with the JWKS it fetched trusted, waits until the token
has expired, and uploads `observation.json`, `binding.json` and `jwks.json`.

## Fixtures

`fixtures/*.bin` are written by `make_fixtures.py` in the register's own shape (Shift_JIS, the `re_disp` table, the
seven columns as served on 2026-10-15). The businesses, people and addresses in them are invented; nothing was copied
from the register.
