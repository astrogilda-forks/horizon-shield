# External findings against conduct-v1

Findings made by people outside this project, what they found, what changed, and how the change was checked.
A finding is recorded here when it moved the specification, a reference server or the reference client. Each
entry names the evidence by sha256 so it can be recomputed without asking anyone. Records a finding rests on are
never edited after the fact; the fix is a new record beside them.

## EXT-001 (2026-09-27): `/endpoint` named a URL that did not serve the request

**Found by** [@pipavlo82](https://github.com/pipavlo82), answering the public call for a second
independent witness ([issue #27](https://github.com/ogasurfproject-jpg/horizon-shield/issues/27)). Walk taken from a
Windows PC that pipavlo82 controls, with Codex assistance, using the reference client pinned at fb3339f3.

**The walk.** `POST https://gate.horizonshield.dev/a2a`, walked_at 2026-09-27T14:40:46Z, 5 of 5 applicable
assertions true, unsigned. Ledger record
[`eea3be5b34f46e4fb6c6eee89b9f5f1019e2b8b19c6106f2b660705550cbd2b4`](https://ledger.horizonshield.dev/witness/eea3be5b34f46e4fb6c6eee89b9f5f1019e2b8b19c6106f2b660705550cbd2b4).

**The finding, as a question.** The response metadata said `.../conduct/v1/endpoint =
https://gate.horizonshield.dev/mcp` for a request served by `/a2a`. pipavlo82 asked whether that was intentional.

**What was wrong.** Two things. Section 3 defined `.../endpoint` as "the entry of measured_endpoints that served this
request", and the gate, the ledger and the JIDEC agent answer A2A at `/a2a` while being measured elsewhere, so each
wrote a URL that did not serve the request (a hardcoded constant). The reference client read only the
`A2A-Extensions` header and never the metadata, so it passed the mismatch 5 of 5; its fixtures carried no metadata
at all, and one fixture agent answered with `.../endpoint = "x"` and passed.

**What changed.** Commit [18d83151](https://github.com/ogasurfproject-jpg/horizon-shield/commit/18d83151), deployed
2026-09-28 (gate 0.4.16, ledger, JIDEC, KIRA):

- Specification v1.4, section 14 of `CONDUCT_EXT_v1.md`: `.../endpoint` narrowed to the measured endpoint whose record
  applies; a new `.../served_by` carries the URL the request arrived at, taken from the request, never a constant.
- Servers: all four write `.../served_by` from the request.
- Client: `metadata_echoed` and `endpoint_bound`. A `served_by` that names another URL is false even when `.../endpoint`
  equals the walked URL, one step stricter than the rule first announced on #27; section 14.4 records the difference.
- `walk_reference_servers.py`: the unchanged client against the four real servers, locally, both wires. Against the
  code as it was at the time of the walk, it reproduces the finding (gate, ledger, JIDEC false; KIRA true).

**Independent verification, by the finder.** From the same vantage, with the client pinned at 18d83151:
76/76 self-tests; a live A2A 1.0 walk of `/a2a` at 7 of 7 applicable, `metadata_echoed` and `endpoint_bound` true;
the originally captured response replayed through the new client at 6 of 7 with `endpoint_bound=false`; a copy with
only `served_by` changed to `/wrong` at 6 of 7, FAIL. Ledger record
[`8cde797444d329971b91c924a57df1171a31e5cf81ba51d61724122d71ed6a3e`](https://ledger.horizonshield.dev/witness/8cde797444d329971b91c924a57df1171a31e5cf81ba51d61724122d71ed6a3e)
(walked_at 2026-09-27T16:21:17Z, stored, not counted: same witness, same endpoint, same day). The finder's own scope, kept as
pipavlo82 stated it: this confirms the gate `/a2a` binding fix on the 1.0 wire from one vantage; it does not reverify the
other servers, the 0.3 wire, card signatures, or witness-pool admission, and it is not a second counted witness.

**The exchange** is public on issue #27: the question, the answer and fix plan before the fix was written, the
report after deploy (with two corrections to the first answer), the finder's verification, and the reply.

**What this does not establish.** That the other servers behave correctly from that vantage; that a second
independent witness exists in the counted pool (the pool admits only domain-signed witnesses that declare
reciprocity, and pipavlo82 is not counted there on pipavlo82's behalf).

## EXT-000 (2026-09-11): an endpoint that charges was recorded as an endpoint that failed

Found by walking a real agent that charges for calls, `api.babyblueviper.com` (babyblueviper1),
walk sha256 `9e058efa16789bb1911eb237a160f7c3bcebc520ba3ee4d74f6d469d02648eb8`. The client recorded 402 Payment
Required the same as a broken endpoint, and answered a question about the compensation declaration with a reason
about the extension. Fixed in specification v1.3, section 13 (`payment_required_as_declared`, 402 as an answer, a walk
never pays) and in the client; details there. Numbered EXT-000 because it predates this file.
