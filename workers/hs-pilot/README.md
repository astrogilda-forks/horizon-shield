# hs-pilot

The responder side of [horizon-shield Issue #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51): one metered call of HORIZON SHIELD's estimate audit, on a testnet, for the pilot proposed on aeoess/agent-governance-vocabulary#177.

- `GET /.well-known/pilot.json`: the responder key, the price and unit, the service name.
- `POST /call` with `{request, task, fixture, payment}`: checks that the task is this service at this price, that the request occurrence commits to the task and names this responder, that the payment is payer-signed by the request's caller, to this responder, for this request, at the task's price; audits every line of the fixture through the public MCP server's `audit_estimate`; returns the audit and a `musubi.ca2a.execution-receipt.v0` signed with the responder key, naming the block the worker had just seen. The audit names its input by digest (`fixture_sha256`) and is a function of the inputs and of the dataset version (each line carries `dataset_sha256` and the ruleset), so the acceptance criteria of #51 can check it by hash equality: the audit of a different fixture fails the first criterion, it is not left unevaluated. Each line carries the quoted amount, the matched work, the fair range, the reference amount (quantity times the range's average), and a finding `within`, `above`, `below` or `unmatched`; the audit carries the quote total and the reference total (null when any line is unmatched). No region multiplier is applied unless the call names a region.

It logs nothing (the caller logs the use, the payment and the receipt with the log operator), settles no rail (the payment receipt is checked for shape and binding and carried by digest), decides no budget (`pilot_v0.py` does, afterwards) and keeps no state.

`node --test test/pilot.test.mjs` runs it against a mocked MCP server and block source. A receipt it signs parses and verifies under `musubi-v0/ca2a-companion-v0/companion_v0.py`, and its RFC 8785 bytes equal the Python reference's.

Deploy: `wrangler secret put RESPONDER_SEED` (64 hex, a fresh Ed25519 seed, kept in the key manager) then `wrangler deploy`. Post the key from `/.well-known/pilot.json` in #51.
