# nenrin-provenance-verify-v0 (番人 draft, 2026-09-17)

One verifier over the whole provenance graph of one A2A task. The normative step-by-step procedure, which a
second implementation follows to reproduce the interop corpora, is VERIFIER.md. It composes three layers that each stand on
their own, imports their pinned primitives unchanged, and adds only the cross-layer checks no single layer can
make. It opens no socket and has no clock; key resolution (resolve) and evidence confirmation (lookup) are
injected, exactly like the layers below it.

## What it composes
- task-delegation-bind-v0 (../task-delegation-bind-v0, pin 4d7c9c270c2846465fafdea9833869c5660c4ae2):
  third-party OBSERVATION of the delegation chain. R1 independence, R2 recompute, R3 continuity,
  R4 non-suppression; witness_sig and edge_sig.
- task-execution-bind-v0 (../task-execution-bind-v0): caller/gateway ACTION + OUTCOME binding.
  E1 authorized-action match, E2 outcome reconciliation, E3 grant binding; caller_sig and provider_sig.
- outcome_evidence (../task-execution-bind-v0/outcome_evidence.mjs): the outcome's commitment to an
  independently checkable pointer (bitcoin_tx, ledger_record, document_sha256, url_sha256).
- preflight (../task-execution-bind-v0/preflight.mjs): the pre-execution intent, a signed declaration of the
  action a provider is about to run, verified against the grant before execution (optional input `intent`).

## What only this layer checks
- task identity: every presented record carries the task_id under verification.
- digest-bound linkage: an observation whose conduct.detail_ref is nenrin-exec://<receipt_id> must name the
  RECONCILED receipt, and the digest must recompute. Linkage, not authority: the observation's verdict never
  inherits the receipt's outcome, and the receipt's outcome never inherits the verdict.
  Clarified 2026-10-04: naming a receipt that was merely PRESENTED is not enough; a link to a presented receipt
  that did not reconcile (for example one not signed by the authorized provider) is linkage_receipt_mismatch.
  Linkage is evaluated only when exactly one receipt reconciles. Under equivocation, or when nothing reconciles,
  there is no reconciled receipt, linkage is not evaluated, and neither linkage_receipt_mismatch nor no_digest_link
  is emitted; the execution refusal is the operative one. interop-v0.1 fixtures linkage_unpresented and
  linkage_unreconciled pin both cases.
- R3 over a SET: chainContinuousSet generalizes the pinned chainContinuous to several witnesses per hop
  (every non-root prev_evidence_id must resolve to some presented prior-hop observation). With one witness per
  hop it is the pinned check; provenance_adversarial asserts the two agree on valid, forged and hidden-hop cases.

## Report
    { schema: "nenrin-provenance-verify-v0", verifier_version, task_id, verdict: accepted|refused,
      refusals: [{code, why, ...}], findings: [{code, why, ...}],
      layers: { identity, delegation, execution, evidence, linkage },
      establishes: [...], does_not_establish: [...], recompute: {...} }
Same shape as a2a-agreement-verify-v0. Fail-closed for readers: a refused report's establishes is exactly
["nothing: see refusals"]. Witness disagreement is a finding with hop verdict "disagreement", never collapsed to
the favorable verdict. Provider equivocation is a refusal: no single outcome can be established.

## Refusal codes
task_id_missing, task_id_mismatch, delegation_observation_invalid, delegation_chain_broken,
execution_incomplete_pair, execution_invalid, execution_signature_invalid, execution_equivocation,
execution_unreconciled, evidence_invalid, linkage_receipt_mismatch, preflight_without_grant, preflight_invalid,
preflight_signature_invalid.

Refusals carry an optional reason (for example execution_invalid with reason invalid_timestamp, receipt_unbound or
action_diverged; delegation_observation_invalid with reason witness_not_independent). Reasons explain; they are not
part of the verdict signature and are not refusal codes.

## Finding codes (declared, non-fatal)
no_delegation_observations, no_execution_records, witness_disagreement, self_authorized, open_grant,
evidence_bound_unchecked, no_evidence_bound, no_digest_link, declared_executed_divergence.

What each finding means (defined 2026-10-04; until then four of these were listed but not defined):
- no_delegation_observations: no observation was presented; the execution layer is verified on its own.
- no_execution_records: neither a grant nor a receipt was presented; the delegation layer is verified on its own.
- witness_disagreement: the witnesses of one hop returned different verdicts; that hop's aggregate is
  "disagreement" (R4). Surfaced, not refused.
- self_authorized: the grant's caller_id equals its provider_id; the caller authorized its own executor (emitted when
  the pair or preflight check reaches that point, VERIFIER.md step 2a and step 3). Declared,
  so recorded and not refused. This is the execution-layer self path; the delegation-layer one (a witness that is
  a party to its own hop) is an R1 refusal, delegation_observation_invalid with reason witness_not_independent.
- open_grant: the grant names no provider_id, so the provider check passes for any executor, and no receipt
  reconciles attributably. It is emitted when the pair or preflight check reaches that point (the same condition
  as self_authorized), and it always comes with a refusal: execution_unreconciled when a receipt is presented
  (VERIFIER.md step 2d), execution_incomplete_pair when only an intent is. It explains that refusal; it does not
  replace it. An accepted report never carries open_grant in v0.
- evidence_bound_unchecked: the evidence target (the reconciled receipt, or the primary receipt when nothing
  reconciled, VERIFIER.md step 4) carries outcome.evidence, the pointer is well formed, and no
  external lookup was injected. Read it as "bound, not confirmed": it is the normal state of an offline run and
  appears on clean bundles, including interop-v0 pass. It is not an anomaly.
- no_evidence_bound: the evidence target carries no evidence pointer; the outcome rests on the provider's
  signed claim alone.
- no_digest_link: a receipt reconciled and observations were presented, but no observation's conduct.detail_ref
  names it as nenrin-exec://<receipt_id>; the layers verify independently but are not linked.
- declared_executed_divergence: an intent was presented and its proposed_action differs from the reconciled
  receipt's executed_action; the preflight or execution refusal raised alongside it is the operative one.

## The wall (written into every report)
No signature can cross it, and no report from this verifier claims to:
- that any executed action occurred in the world: E1 compares the provider's signed claim to the caller's
  signed authorization and has no side-effect oracle;
- that the reconciled outcome is the real-world outcome: E2 proves recoverability and surfaces
  equivocation, it does not prove truth;
- that any witness is unaffiliated with the parties: R1 proves structural distinctness, not independence;
- that bound evidence exists in its system or says what the provider claims, unless
  layers.evidence.checked_externally is true, and even then only what the injected lookup reported;
- anything about time beyond the record contents: no clock, no anchor seen here;
- that this is the only provenance these parties produced for this task_id.
The honest way to get closer to the wall is not to claim more, but to bind outcomes to pointers a reader can
check in a system that is already independently verifiable (outcome_evidence). That moves "the provider
claims X" to "the provider committed to E in S, go check S", without any trusted oracle.

## Consuming NENRIN evidence from a trust engine
consume.mjs (nenrin-consume-v0) projects a verified provenance into a compact, stable bundle a reputation or
policy engine reads in one call and re-verifies itself: facts, conflicts, anchors, honest limits, and the
recompute steps. It returns no trust score and no allow or deny decision. See CONSUME.md for the contract.

## Run
    node provenance_adversarial.test.mjs
    node consume.test.mjs
    node ../task-execution-bind-v0/bind_exec_adversarial.test.mjs
    node ../task-execution-bind-v0/sign_exec_adversarial.test.mjs
    node ../task-execution-bind-v0/compose.test.mjs
    node ../task-execution-bind-v0/outcome_evidence.test.mjs
    node ../task-execution-bind-v0/exec_cross_lang_test.mjs   (runs exec_witness_emit.py via python3)

## Honest scope
v0 is a draft, not outsider-validated. Signatures and digests prove who asserted and the linkage, not that any
assertion is true. The execution boundary already has an artifact of record (Poke-nushi's VATE, a2aproject/A2A
#1769); task-execution-bind-v0 is a minimal, swappable reference implementation so the composition seam can be
tested end to end, and this verifier is what tests it. Neither claims ownership of that boundary.
