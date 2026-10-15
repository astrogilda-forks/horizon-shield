# interop-v0.3/own-proto: an own `__proto__` key is part of the preimage

Seven provenance bundles, each with the verdict signature (VERIFIER.md section 4: verdict, sorted refusal codes,
sorted finding codes) a conforming verifier must return. TSUNAGI name: `nenrin-interop-v0.3-own-proto`.

## Where they come from

pipavlo82 (horizon-shield #29, 2026-10-15) started from validly signed records and added the JSON member
`"__proto__": {"audit_note": "not signed"}` to the grant, the receipt and the intent, each after signing, without
touching any digest or signature. The JS reference and the Python port accepted all three; the same member under the
name `audit_note` was refused. A direct Ed25519 check showed the stored signatures do not cover the added field.
The cause: the preimage copy was `Object.assign({}, rec)`, which runs the `__proto__` setter instead of copying that
one own key, so the record hashed without it (the Python and Go ports emulated that copy on purpose). VERIFIER.md
section 2 says every non-derived field stays in the preimage, unknown fields included. The reference keeps every own
key from nenrin-verify 0.5.3 (verifier_version 0.1.7); this corpus pins that.

## The vectors

`make_own_proto_vectors.py` writes them (keys from public labels, Ed25519 is deterministic, so the bytes regenerate;
`SHA256SUMS` lists them). The base is a validly signed grant, receipt and intent for `task_own_proto`; each other
vector adds ONE member to ONE record after signing.

| Vector | Added after signing | Expected (conforming) |
|---|---|---|
| q00_base | nothing | accepted |
| q01_own_proto_in_grant | `"__proto__"` in the grant | refused: execution_invalid, execution_signature_invalid, preflight_invalid |
| q02_own_proto_in_receipt | `"__proto__"` in the receipt | refused: execution_invalid, execution_signature_invalid, execution_unreconciled |
| q03_own_proto_in_intent | `"__proto__"` in the intent | refused: preflight_invalid, preflight_signature_invalid |
| q04_audit_note_in_grant | `"audit_note"` in the grant (control) | the signature of q01 |
| q05_audit_note_in_receipt | `"audit_note"` in the receipt (control) | the signature of q02 |
| q06_audit_note_in_intent | `"audit_note"` in the intent (control) | the signature of q03 |

All findings are evidence_bound_unchecked and no_delegation_observations. q01 carries preflight_invalid because the
intent names the grant by its stored grant_ref, which is no longer the grant's recomputed id (intent_unbound).

A verifier that keeps every own key gives 7/7. One whose copy drops an own `__proto__` key (Object.assign, the
spread operator, or a port that emulates them) gives 4/7: it accepts q01 to q03 and refuses the controls.

## What was checked before freezing

- The JS reference (`node run_own_proto.mjs`, `sdk/nenrin_verify.mjs` at 0.5.3), the Python port (0.5.5, pytest and
  `nenrin-tsunagi`) and the Go port (v0.2.2, `go test ./...`, `nenrin-verify-go --corpus`) each give 7/7.
- The reference at 0.5.2 gives 4/7 (q01 to q03 accepted), which is the finding.
- The 93 + 9 frozen fixtures of the older corpora and the 31 parity bundles give the same signatures before and after.
