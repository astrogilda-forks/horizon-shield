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

Status: a reference and a frozen corpus, no port yet, no live tenant run yet. The next step is the demonstration the
spec ends with: two Entra agent identities, a delegation recorded as a NENRIN grant and receipt, verified with no
Microsoft credential.
