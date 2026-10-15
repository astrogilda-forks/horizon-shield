# payee-confirm-v0

The third signature on a delegated payment. Agent A authorizes "pay this invoice" (a NENRIN grant), agent B reports
executing it (a NENRIN receipt), and the payee, a party neither controls, signs that it received exactly the invoiced
amount for exactly that grant and receipt. Each party's key can be bound to an identity its own provider issued
([`idp-bind-v0`](../idp-bind-v0)). A reader with no credential checks all of it, offline.

Version 0.1.0 (2026-10-15). Reference: `payee_confirm.mjs`. Test: `node payee_confirm.test.mjs` (25 checks).
Demonstration: `node three_party_demo.mjs --out out/` (mock issuer in GitHub Actions' token shape) and
`node three_party_demo.mjs --verify out/` (the reader alone).

## Why

A receipt from the executor says "I paid", and the executor is the party with the most reason to say so. The payee is
the one who can say "I was paid", and that is only worth something if it commits to the same task, grant, receipt and
amount the payer authorized. Here the payee discloses the invoice terms, and they must hash to the `args_sha256` the
payer's grant already signed, so the payee cannot confirm a different amount than the one authorized without the
check refusing it.

## The record

    {
      "schema":      "payee-confirm-v0/confirmation",
      "payee_id":    "did:key:z6Mk...",
      "task_id":     "...", "grant_ref": "<grant.grant_ref>", "receipt_id": "<receipt.receipt_id>",
      "invoice":     { "invoice": "INV-2026-1015", "amount_jpy": 120000 },   sha256(canonical(invoice)) = grant.action.args_sha256
      "received":    { "currency": "JPY", "amount": 120000 },
      "rail":        "bank_transfer" | "card" | "bitcoin" | "other",
      "evidence":    { "kind", "ref", "system" }    optional, an outcome-evidence pointer (bitcoin_tx, ledger_record, document_sha256, url_sha256)
      "received_at": "2026-10-15T15:30:04Z",          not before receipt.executed_at
      "nonce":       "...",
      "confirmation_id": "<sha256 of canonical(preimage)>",
      "payee_sig":       "<Ed25519 over canonical(preimage), base64>"
    }

## Verification

Input: `{ confirmation, grant, receipt, bindings?: { payer, executor, payee }, jwks?, lookup? }`.

1. Id and signature: `confirmation_recompute_mismatch`, `payee_id_unresolvable`, `payee_sig_malformed`, `payee_sig_invalid`.
2. The grant and receipt verify on their own (the NENRIN provenance verifier), are the ones named, and the receipt
   reports a completed execution: `grant_receipt_refused`, `names_other_records`, `receipt_not_completed`. The
   granted action (tool and target) is quoted in the report as it is, not interpreted.
3. The invoice is the granted one and the amount is that amount: `invoice_not_granted`, `bad_received`,
   `amount_mismatch`, `received_before_execution`.
4. The payee is a third key: `payee_is_party`.
5. A rail pointer: finding `no_rail_evidence`, `rail_evidence_unchecked`, or, with an injected lookup,
   `rail_evidence_confirmed` / refusal `rail_evidence_not_found`, `rail_evidence_does_not_match`; a malformed pointer
   is refused with the outcome-evidence code. The lookup is asked about the whole payment (`evidence`, `amount`,
   `currency`, `payee_id`, `invoice`, `received_at`), so "matches" can be about this amount to this payee.
6. Bindings, per role: `binding_refused_<role>`, `binding_other_key_<role>`, `binding_other_audience_<role>` (the
   audience is `nenrin-payee-confirm`); two roles on one provider subject: `one_identity_two_roles`. A role's
   identity is named (findings `payer_bound`, `executor_bound`, `payee_bound`) only when its JWKS sha256 is one the
   reader trusts for that issuer (`trusted`, `--trust`); otherwise `<role>_self_pinned` and no identity is stated,
   because a JWKS in the same bundle as the binding only vouches for itself.

## What it establishes, and what it does not

Accepted means: the payer's key (and identity) authorized that invoice, the executor's reported executing it, and a
third key (and identity) confirmed receiving that amount for that grant and receipt, after the execution.

It does not establish that money moved. Three agreeing signatures are three statements. A payment-rail pointer and a
lookup the reader runs are how that is approached, and the report says whether one ran ("that money moved" leaves
`does_not_establish` only when it did). It does not establish that the parties are who their providers say, only that
the providers said so, and only for roles that carry a binding; nor that the invoice was owed or the price fair.

## With real identities

The workflow [`nenrin-github-oidc.yml`](../../../../.github/workflows/nenrin-github-oidc.yml) runs this with GitHub
Actions as the identity provider: three jobs in three environments (`nenrin-payer`, `nenrin-executor`,
`nenrin-payee`) get three tokens with three different subjects, and the reader checks the six files the run writes,
trusting the JWKS the run fetched. The tokens are never printed; they cross between jobs as one-day artifacts that the
last job deletes as soon as it has them, and the bindings are uploaded only after every token has expired. In the few
seconds the token artifacts exist, a signed-in user who knew to look could download one and bind it to their own key;
that is the bearer-token limit `idp-bind-v0` states, and it is why a binding of these demo subjects counts only if
its `binding_id` is listed in a run summary of this workflow.
