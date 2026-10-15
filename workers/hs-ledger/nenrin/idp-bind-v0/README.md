# idp-bind-v0

The hinge between an identity provider's subject (Microsoft Entra Agent ID, Entra ID, any OIDC issuer with a JWKS)
and the Ed25519 key a NENRIN actor signs with: one record, signed by the actor key over a live provider token,
checkable offline by a reader outside the provider's tenant with the issuer's JWKS pinned by digest. `SPEC.md` has
the record, the checks, the codes and the honest line (a bearer token binds whoever held it; `cnf` makes it
possession-proven on both sides).

    node idp_bind.test.mjs            32 checks: the 14 frozen fixtures, RS256 in Entra's JWKS shape, confusion
                                      and malformed inputs, composition with a NENRIN grant
    node make_fixtures.mjs --check    the fixtures are the pinned bytes and the reference reproduces 14/14

`verify(input)` and `makeBinding(...)` are the API; `parseJwt`, `jwkFromJwks` and `signJwt` are the pieces. No
dependency outside `node:crypto`.

    python3 -I idp_bind.py --fixtures  the Python port (needs ../sdk-python and cryptography): 14/14
    python3 -I parity.py               both runtimes over the 14 fixtures and 1,232 one-field mutations: 0 differences

## The demonstration

    cd demo && node entra_delegation_demo.mjs      two agents with provider identities (a mock issuer in Entra ID
                                                   v2.0 shape, RS256) bind their NENRIN keys; A delegates to B as a
                                                   NENRIN grant, B signs the receipt; writes out/
    node entra_delegation_demo.mjs --verify out    the reader alone, JavaScript
    python3 -I reader.py out                       the same reader in Python

The reader holds four files (two bindings, the pinned JWKS bytes, the grant + receipt) and no credential, and
prints what is established: which provider subject authorized which action, which provider subject executed it,
that the executed action equals the authorized one and the receipt commits to the grant by hash; and what is not
(that the action happened in the world, that the subjects are who the tenant says, and, without `cnf`, possession
of the identity beyond holding a live token). With a real tenant, `--token-a`, `--token-b` and `--jwks` take the
two client-credentials tokens and the tenant's JWKS document; nothing else changes.

## Real issuers

[`real-issuers/`](real-issuers) holds two runs with real tokens: Google
(`https://accounts.google.com`, service-account ID tokens) and Microsoft Entra ID (a v2.0 tenant, client-credentials
access tokens). Both were established by the same reader in both runtimes. The Google run is published in full (tokens expired); the Entra bindings are withheld because GitHub push protection treats Entra tokens as secrets even after expiry, and are pinned by digest. `node real-issuers/check.mjs` rechecks
them offline, with no credential from either issuer.
