# Where NENRIN sits next to Entra Agent ID, SINT and TRACE

Short version: Entra says who an agent is, SINT decides what it may do and writes its own receipts, TRACE describes
what ran. Each of those records is issued by a party with a stake in it. NENRIN is the layer that lets someone who is
none of those parties recheck such a record later: it pins the exact bytes in time (Bitcoin), binds them to an
identity the reader chooses to trust, and keeps second implementations honest. It is not a replacement for any of
the three, and it does not compete with them for the same job.

Written 2026-10-16. Every claim about NENRIN below links to code or a record in this repository; claims about the
other systems link to their own documents. Where NENRIN does not yet connect to one of them, this page says so.

## The question each one answers

| | answers | who issues the record | who can recheck it, and when |
| --- | --- | --- | --- |
| Microsoft Entra Agent ID | which agent identity this is, in which tenant | Microsoft, for the tenant | whoever trusts the tenant's signing keys, while the token is valid (minutes) |
| [SINT Protocol](https://github.com/sint-ai/sint-protocol) | what an agent is permitted to do inside a Work Cell, with hash-chained receipts of compliance | the operator running the policy layer | whoever holds the receipt chain and trusts that operator |
| [TRACE](https://github.com/agentrust-io/trace-spec) | what ran, where, under which policy | the producer, signing with the key in `cnf.jwk` | a conformant verifier, within 24 hours of `iat` by default (spec section 3.2.2) |
| NENRIN (this repository) | that these exact bytes existed by a time no party controls, bound to an identity, and read the same way by independent code | the observer or witness, under its own key; time from Bitcoin | anyone, offline, with no account and no trust in HORIZON SHIELD, at any later date |

The [agent-governance-vocabulary crosswalks](https://github.com/aeoess/agent-governance-vocabulary/tree/main/crosswalk)
map SINT, TRACE (`agentrust-trace.yaml`) and NENRIN (`nenrin.yaml`) term by term, side by side with equal standing.

## How NENRIN connects to each

**Entra Agent ID and other identity providers.** [`idp-bind-v0`](idp-bind-v0) binds a token from a real identity
provider to a NENRIN key and pins the issuer's JWKS by sha256, so the binding stays checkable after the token expires.
On 2026-10-15 it ran with real Microsoft Entra ID v2.0 access tokens (tenant `defcf0d5-...`, two app identities
from the client credentials flow, not yet the Entra Agent ID agent identity type) and real Google ID tokens: agent
A signed a grant, agent B signed a receipt, and a reader with no credential from either issuer verified all four
records in JavaScript and in Python ([`real-issuers`](idp-bind-v0/real-issuers)). [`issuer-keys-v0`](issuer-keys-v0)
records the keys Google, that Entra tenant and GitHub Actions serve, every day, by RFC 7638 thumbprint, stamped to
Bitcoin, so a JWKS pinned in a binding can later be shown to have been the issuer's own. Limits: the Entra bindings
themselves are withheld from the public copy (GitHub treats an Entra access token as a secret even after it expires;
`SHA256SUMS` pins them), and nothing here proves the subject behind a tenant is who it claims to be.

**TRACE.** [`trace-pin-v0`](trace-pin-v0) checks a TRACE record's signature at intake, keeps its RFC 8785 bytes and
anchors their sha256 to Bitcoin. That gives the "second, independent bound" described in TRACE's own informative page
[Verifying a record after the freshness window](https://github.com/agentrust-io/trace-spec/blob/main/docs/verifying-after-the-freshness-window.md),
proposed from here and merged by the TRACE maintainers in
[trace-spec#480](https://github.com/agentrust-io/trace-spec/pull/480). The page names no service. All 33 vectors of
`trace-tests` run through the intake.

**SINT.** No connection yet. A SINT receipt is a hash-chained record its operator issues; pinning the head of that
chain in NENRIN would bound when the chain existed in that form, from outside the operator. That is the same pattern
as TRACE and has not been built or offered to SINT.

## What NENRIN adds that none of them claims

- **Time from outside.** A daily batch of record hashes is stamped with OpenTimestamps to a Bitcoin block. The time
  comes from neither the issuer nor HORIZON SHIELD.
- **Second implementations.** [TSUNAGI](../../../tools/tsunagi) pulls outside readers from their authors' own
  repositories every night and runs them against this corpus. On 2026-10-15 two readers written from the spec alone
  refused an own `__proto__` key that all three reference implementations had accepted; the references were fixed to
  match. Signed outside witnesses are listed in [`WITNESSES.md`](WITNESSES.md).
- **Records about the physical world.** The same record shape is used outside agent protocols, for example
  [`kyoka-observe-v0`](kyoka-observe-v0): a GitHub Actions run asks Japan's register of licensed construction
  businesses about one licence, and signs what the register answered.

## What NENRIN does not do

It does not issue identities, enforce policy, decide whether an action was allowed, or score agents. A signature
says who asserted something, not that it is true, and an absent record is not a negative finding. TLS does not sign
content, so a record of what an observer received is the observer's word until another observer gets the same bytes.
