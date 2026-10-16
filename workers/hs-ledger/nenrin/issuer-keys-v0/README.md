# issuer-keys-v0

A dated record, kept outside the identity providers, of which signing keys they served. It answers the question
`trusted_identity.mjs` (idp-bind-v0) leaves to the reader: is the JWKS shipped next to a binding the issuer's, or a
key someone minted and named the issuer in?

Once a day, [`issuer-keys.yml`](../../../../.github/workflows/issuer-keys.yml) fetches `<issuer>/.well-known/openid-configuration`
for each issuer in [`ISSUERS.json`](ISSUERS.json) (Google, the Microsoft Entra tenant of the 2026-10-15 run, GitHub
Actions), requires the document to name the issuer exactly, fetches its `jwks_uri`, and records each key by its
RFC 7638 thumbprint. `log/observations/<day>.json` is that day's fetch, stamped with OpenTimestamps
(`<day>.json.ots`); `log/keys.json` holds every key per issuer with the first and last day it was seen; `log/jwks/`
keeps the raw bytes under their sha256.

Keys, not bytes, because the bytes move while the keys do not: Google served the same two keys on 2026-10-15 and
2026-10-16 with different JWKS digests (`5488d26f...` and `c863d760...`), the order of keys and members changing
between fetches.

## Checking a binding

```
node check.mjs --binding ../idp-bind-v0/real-issuers/google-2026-10-15/binding_a.json \
               --jwks    ../idp-bind-v0/real-issuers/google-2026-10-15/jwks.json
```

It says whether every key in that JWKS (all of them, not only the one that signed: trust is given to a document digest,
and one extra key would let its holder through under the same trust) was observed at that issuer within seven days of
the binding's `bound_at` (`--window-days` to change it), and if so prints `--trust <issuer>=<sha256>` for
`trusted_identity.mjs`. Offline; it reads `log/keys.json`.

    node issuer_keys.test.mjs    18 checks, no network (the fake issuer serves the real 2026-10-15 Google keys, reordered)

## What a record establishes, and what it does not

Established: on that UTC day, a GitHub Actions runner fetching the issuer's discovery document over TLS got one that
names the issuer exactly, and its `jwks_uri` served keys with these thumbprints; the stamp shows the file existed by the
time Bitcoin confirmed it.

Not established: that the runner's network was not intercepted beyond what TLS checks; that a key was not compromised;
anything on a day nobody fetched; and independence from this project, since the workflow runs in this project's
repository. A second observer running the same `observe.mjs` from their own account is the way to the last one.
