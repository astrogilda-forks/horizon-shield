# idp-bind-v0 with real issuers

Two runs of the delegation demonstration in [`../demo`](../demo), with tokens issued by real identity providers instead of the mock. A run is four files: the two bindings, the pinned JWKS bytes, and the NENRIN grant and receipt. The Google run is here in full. The Entra run is here without its two bindings (see below), and `SHA256SUMS` pins all eight files, so the withheld two can be checked byte for byte when shared.

| run | issuer | token | subjects |
| --- | --- | --- | --- |
| [`google-2026-10-15`](google-2026-10-15) | `https://accounts.google.com` | Google ID tokens for two service accounts, RS256, audience `api://nenrin-relying-party` | `113892689306592625656`, `115692724741532430986` |
| [`entra-2026-10-15`](entra-2026-10-15) | `https://login.microsoftonline.com/defcf0d5-8cff-40af-a160-a0aa1bb6a912/v2.0` | Microsoft Entra ID v2.0 access tokens from the client credentials flow, RS256, audience the relying party's app id | `44c8852b-5bbe-4e71-8694-2914d784edda`, `919ea16d-707b-4c2c-adce-82e29a663a75` |

In both runs agent A (bound to the first subject) signs a grant for `a2a.invoke /invoices/pay`, agent B (bound to the second) signs a receipt for executing it, and the reader, holding only the four files, verified all four records in JavaScript and in Python on 2026-10-15.

## Recheck

```
node check.mjs                                    # SHA256SUMS, the Google run in full, the Entra grant and receipt
node ../demo/entra_delegation_demo.mjs --verify ../real-issuers/google-2026-10-15
python3 -I ../demo/reader.py google-2026-10-15    # the same reader in Python (run from this folder)
```

No network, no clock, no credential from either issuer. A binding is checked against its token's own `nbf`/`exp` window at `bound_at`, so the runs stay checkable after the tokens expire.

## What these runs establish, and what they do not

Established, by anyone holding the files: the issuer named in each binding signed a token for that subject and audience under a key in the pinned JWKS; the holder of a NENRIN key bound itself to that token inside the token's lifetime; the subject bound to A authorized the action, and the subject bound to B reported executing exactly that action, with the receipt committing to the grant by hash.

Not established: that any payment happened (a signature proves who asserted); whether the subjects are who the issuer says (only that the issuer said so); possession of the provider identity beyond holding a live token, because neither issuer put a `cnf` claim in these tokens (finding `bearer_only`). The Entra tokens carry no `roles` claim; the run did not depend on one.

## About the tokens

The Google tokens are real bearer tokens, published only after they expired (2026-10-15T12:20:50Z); the service accounts they were issued to were deleted at the end of the run.

The Entra bindings are withheld. GitHub push protection classifies the Entra access tokens inside them as secrets, and it does so regardless of expiry (2026-10-15T14:03:06Z) or of the app registrations having been deleted at the end of the run. We did not override that check. The two files are pinned in `SHA256SUMS` (`entra-2026-10-15/binding_a.json`, `binding_b.json`); ask in an issue and we will send them, and `node check.mjs` then verifies the Entra run in full. The JWKS files are the issuers' public keys as fetched at the time of each run, pinned by `jwks.sha256`; a later fetch may differ because issuers rotate keys.
