# live_smoke: the bytes behind the expected case A audit

One call to the deployed responder (https://hs-pilot.oga-surf-project.workers.dev, responder key `7b1ada68cd366c70a79544b6d719d685fd37e01f26549e08bf388768cc7d0ffe`) on 2026-10-18, made to fix the expected case A audit for ogasurfproject-jpg/horizon-shield#51. **It is not the pilot record.** The caller, payer and lineage are test keys, the payment is a signed test transfer with a placeholder `seen_block`, and nothing was logged or anchored.

- `call.json`: the body that was posted to `POST /call` (task, request, fixture, payment), JCS. The request digest is `69546501c86296c2029de4f2325f6e561b66efa89fe27fdbfe9f4510104d3d01`; its `occurrence_id` is `live-smoke-0`. The fixture is `../fixture.json` (`c2ed811e…`).
- `receipt.json`: the responder's signed execution receipt, JCS, digest `1c01ea21e78690a2e2066849bf143c7c3e4e4463cb4f439668b65abb7e6014d1`. `seen_block` is 971984. The Ed25519 signature is over the JCS of the receipt without `signature`.
- `audit.json`: the audit the receipt names, JCS bytes, sha256 `c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5` (= `outcome.response_sha256`). Every line comes from the public MCP server's `audit_estimate` against souba-db 2.3.0 (`dataset_sha256` `7b16600e…`), with no region.

To recompute the audit, run `auditFixture` from `workers/hs-pilot/src/pilot.mjs` on the fixture against the public MCP server: it gives these 1400 bytes again for as long as the dataset is 2.3.0. The pilot's own record is issued only on the first logged call.
