# idp-bind-v0: binding a provider-issued identity to a NENRIN actor key

Version 0.1.0 (2026-10-15). Reference: `idp_bind.mjs`. Fixtures: `fixtures/`, `expected.json`, `SHA256SUMS`.

## The problem it solves

A NENRIN record is signed by a key and names the key (`did:key`). An enterprise does not know its agents by keys;
it knows them by the identity its identity provider issued (Microsoft Entra Agent ID, Entra ID, Okta, Google, any
OIDC issuer). The two have to meet somewhere a third party can check, or "agent X did this" is a claim only the
tenant's own logs can support. This record is where they meet, and it is checkable outside the tenant.

## The record

    {
      "schema":       "idp-bind-v0/binding",
      "actor_id":     "did:key:z6Mk...",                          the NENRIN actor key (Ed25519)
      "idp": {
        "issuer":     "https://login.microsoftonline.com/<tenant>/v2.0",
        "subject":    "<the provider's subject for the agent>",
        "audience":   "<the relying party the token was issued for>",
        "kid":        "<the provider key that signed the token>",
        "alg":        "RS256" | "ES256"
      },
      "token_sha256": "<sha256 of the compact JWT, ASCII>",
      "token":        "<the compact JWT>",
      "bound_at":     "2026-10-15T00:30:00Z",                    strict RFC3339 UTC
      "nonce":        "<caller chosen>",
      "binding_id":   "<sha256 of canonical(preimage)>",         derived
      "actor_sig":    "<Ed25519 over canonical(preimage), base64>"   derived, by actor_id
    }

Canonical form and preimage: as `provenance-v0/VERIFIER.md` section 2 (musubi-canonical-v0; the preimage is every
own key except `binding_id` and `actor_sig`, an own `__proto__` key included).

## Verification (offline)

Input: `{ "binding": <record>, "jwks": { "sha256": "<hex>", "document": "<the issuer's JWKS text>" } }`. The relying
party fetched the JWKS when it accepted the binding and pinned its sha256; a later reader checks the same bytes. No
step here reaches the network.

1. **The binding is what its id says, and the actor signed it.** `binding_id` recomputes; `actor_sig` verifies
   under `actor_id` over the canonical preimage. Refusals: `binding_recompute_mismatch`, `actor_id_unresolvable`,
   `actor_sig_malformed`, `actor_sig_invalid`, `canonical_refused`.
2. **The token is the one the binding names and is well formed.** `token_sha256` = sha256(token); three
   base64url segments, JSON header and payload, a signature segment that round-trips. Refusals:
   `token_digest_mismatch`, `token_malformed`.
3. **The token says what `idp` says.** header `alg` and `kid` equal `idp.alg` and `idp.kid`; `iss` = issuer;
   `sub` = subject; `aud` contains audience (string or array); `exp` is an integer; `bound_at` lies in
   `[nbf (or iat), exp]`. Refusals: `header_mismatch`, `alg_unsupported`, `issuer_mismatch`, `subject_mismatch`,
   `audience_mismatch`, `token_without_exp`, `bad_nbf`, `outside_token_window`. If the payload carries `cnf`
   (RFC 7800), its `kid` or `did` must equal `actor_id`: `cnf_mismatch`; otherwise finding `cnf_bound`. Without
   `cnf`: finding `bearer_only`.
4. **The issuer signed the token under a key in the pinned JWKS.** sha256(document) = `jwks.sha256`; exactly one
   key with that `kid`, `use` absent or `sig`, `alg` absent or equal, key type matching the algorithm; RS256 is
   RSASSA-PKCS1-v1_5 with SHA-256, ES256 is ECDSA P-256 with SHA-256 and a raw r||s signature. Refusals:
   `jwks_missing`, `jwks_digest_mismatch`, `jwks_not_json`, `jwks_without_keys`, `key_not_in_jwks`, `kid_ambiguous`,
   `key_not_for_signing`, `key_alg_mismatch`, `key_type_mismatch`, `key_unusable`, `idp_signature_invalid`.

Verdict `accepted` only with no refusal. The report lists `establishes` and `does_not_establish` in words.

## What it establishes, and what it does not

Accepted means: the holder of the private key of `actor_id` signed this binding (possession of the NENRIN key), and
the issuer signed a token for `subject`, for `audience`, that was live at `bound_at`, under a key in the pinned
JWKS. After it, a NENRIN grant, receipt, intent or observation signed by `actor_id` is attributable to
`issuer`/`subject` by anyone holding the binding and the pinned JWKS bytes.

It does not establish that the subject did anything (that is what the NENRIN records are for), that the provider's
statement about the subject is true (only that it made it), or, without `cnf`, possession of the provider identity
beyond holding a live bearer token: a JWT is a bearer credential, and whoever holds a live one can bind it to any
key. Two things bound that: the audience (a token for one relying party does not bind at another) and the lifetime
(Entra access tokens live about an hour). A token with `cnf` naming the actor key is possession-proven on both
sides, and the report says so (`cnf_bound`).

A key the issuer rotates out of its JWKS does not make an old binding false: the binding carries the JWKS digest
it was checked against, and the bytes are kept by whoever pinned them. It does mean a reader without those bytes
cannot recheck it (`key_not_in_jwks` against the current document), which is the same situation as any signature
under a retired key and is why the relying party keeps the pinned JWKS next to the binding.

## Entra Agent ID, concretely

An Entra agent identity obtains a token for a relying party's app (`aud` = the app's identifier URI) through the
client-credentials flow. The relying party, on the first request, asks the agent to present the binding record
signed by its NENRIN key over that token, verifies it as above with the tenant's JWKS
(`https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`) pinned by digest, and stores the binding with
the bytes. Every later NENRIN record from that key is attributable to the Entra subject (`oid`) outside Microsoft's
tenant, by anyone with the three things: the binding, the pinned JWKS bytes, the records. That is the demonstration
this layer is written for: two agents with Entra identities, a delegation between them recorded as a NENRIN grant
and receipt, verified by a reader that has no Microsoft credentials. The fixtures here use a mock issuer in Entra's
token and JWKS shape; nothing in this directory was issued by Microsoft, and no claim about Entra's behaviour is
made beyond the published token format.
