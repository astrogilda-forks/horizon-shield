# musubi-trace-terms-v0

Status: draft, revision 0. Reference evaluator `trace_terms_v0.py`, vectors `vectors/vectors.json` (55), rebuilt byte for byte by `gen_vectors.py`.

## 1. The question

TRACE ([agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec) v0.2) gives two kinds of signed evidence about an agent's calls:

- a **PIC/TRACE authorization** (profile `tag:agentrust-io.com,2026:pic-trace-bridge-v1`, `agentrust_trace.intent_bridge`): one authorizer's signed `allow` or `deny` for one tool call, with a tool and impact scope and a validity window. TRACE's verifier checks one call against one authorization. Its own text says a matching binding establishes integrity, not sufficiency.
- a **Trust Record**: a runtime's signed statement of what ran the agent (subject, model, policy bundle and enforcement mode, platform, data class, build provenance, appraisal status).

Neither says what two parties agreed, and neither adds anything up. Every call can be allowed and the fifth still be one more than the parties agreed; a bridge scope can be wider than the contract; a runtime can be honestly described and still not be the one the parties agreed to.

For the acts the contractor signed as executed under an `a2a-contract-v0` both parties signed, this profile answers:

1. Was each call authorized, under a decision TRACE's own verifier accepts, by an authorizer the principal agreed to?
2. Was each tool, mapped to the contract's actions, inside the grant?
3. Did the calls together stay within the counts both parties agreed?
4. When the parties agreed on a runtime, does the Trust Record each act names come from an agreed producer, about an agreed agent, and state that runtime?

It is a pure function of the bundle. It never fetches and runs nothing. It judges only the acts presented (section 8).

## 2. Who can make what true

The rule every code below follows: **an act is outside the terms only on what the contractor signed and on signatures nobody else can forge.** The contractor's act commits by digest to every piece of evidence the verdict reads. Whoever assembles a bundle can leave evidence out, swap it, or withhold a key; each of those makes the act `undetermined`, never `outside_terms`. And no act the contractor did not sign is counted.

## 3. Encodings

Objects that belong to MUSUBI (the contract, the terms, the act) are signed over the musubi canonical form (`musubi-canonical-v0`, `agreement-v0/agreement_verify.py canonical`) with a context line, as `a2a-contract-v0` is. Objects that belong to TRACE (authorizations, tool calls, declarations, transcripts, Trust Records) are digested as TRACE digests them: RFC 8785 with `sha256:<hex>` for bridge digests (`intent_bridge.digest_jcs`), hex sha256 of RFC 8785 for the whole bridge, and the NENRIN trace intake's `sha(R)` for a Trust Record (`trace-bind-v0/SPEC.md` section 2). Nothing TRACE signed is re-encoded. A TRACE object with no RFC 8785 form (a lone surrogate, a non-finite number, an integer past 2^53 - 1, nesting past 64) makes its act `unreadable`.

Every TRACE object is read in the form its digest names: `json.loads(RFC8785(x))`. `1790000030.0` and `1790000030` have one RFC 8785 form, so one digest and one signature; without this rule, whoever assembles a bundle could rewrite an integer as an equal float, keep every digest and signature valid, and make TRACE's strict readers reject what was signed (TT44, TT45).

## 4. The terms

Both contract parties sign the terms with the keys the contract pins, over `"musubi-trace-terms-v0\n" + canonical(terms without signatures)`. Exactly these members:

```json
{
  "schema": "musubi-trace-terms-v0",
  "contract_sha256": "<the contract's contract_sha256>",
  "authorizers": ["<RFC 7638 thumbprint of an authorizer key the principal accepts>"],
  "tools": {"<TRACE tool name>": "<contract action>"},
  "max_calls": {"<contract action>": 2},
  "max_calls_total": 3,
  "runtime": null,
  "signatures": [{"domain": "<party domain>", "alg": "ed25519", "signature": "<base64>"}]
}
```

`max_calls` may be empty; every key must be an action some tool maps to (a cap that could never apply is refused). `max_calls_total` may be null. `runtime` is null or exactly:

```json
{
  "producers": ["<thumbprint of a Trust Record key both accept>"],
  "subjects": ["spiffe://contractor.example/agent/estimator"],
  "models": [{"provider": "...", "model_id": "..."}],
  "policy_bundle_hashes": ["sha256:..."],
  "enforcement_mode": "enforce",
  "data_classes": ["confidential"],
  "platforms": ["azure-cvm-sev-snp"],
  "min_slsa_level": 2,
  "appraisal_status": ["affirming"],
  "max_age_seconds": null
}
```

`producers` and `subjects` are required and non-empty; every other member may be null, meaning the parties did not agree on it. `max_age_seconds` null is 86400 (TRACE 3.2.2's default record age). The terms add to the contract; they cannot widen it.

## 5. The act

The contractor signs one act per executed call, with the contractor key the contract pins, over `"musubi-trace-act-v0\n" + canonical(act without signatures)`. Exactly these members:

```json
{
  "schema": "musubi-trace-act-v0",
  "contract_sha256": "<hex>",
  "seq": 1,
  "bridge_sha256": "<hex sha256 of the RFC 8785 bytes of the whole signed bridge>",
  "tool_call_digest": "sha256:<hex>",
  "declaration_digest": "sha256:<hex>",
  "pic_intent_digest": "<as the bridge carries it>",
  "pic_args_digest": "<as the bridge carries it>",
  "transcript_digest": "sha256:<hex> or null",
  "trace_sha256": "<the Trust Record's pin identity, or null>",
  "executed_at": 1790000000,
  "signatures": [{"role": "contractor", "sig_b64": "<base64>"}]
}
```

`seq` is the contractor's numbering, an integer from 1. `executed_at` is the contractor's statement of when the call ran. `trace_sha256` null is the contractor's statement that it names no Trust Record for the call.

## 6. Stage A

The whole bundle `{"contract", "terms", "authorizer_jwks", "acts"}` is refused, and no act is read, when its members are not exactly these (`bundle_malformed`); the contract does not verify under `contract_v0.verify_contract` (`contract:<code>` for every code, `contract:unreadable` when it cannot be read at all); the grant carries a clause this profile does not judge, `conditional`, `limits`, `approval_policy`, `data_access` or `expiry_height`, non-empty (`grant_clause_not_judged:<clause>`; settle judges those, and judging the rest as if the clause were absent would be a false green, TT47, TT48); the contract names a parent (`contract_clause_not_judged:parent_contract`, no parent is checked here, TT52), carries a requirement other than `evidence: "n/a"` and `recovery: "n/a"` (`contract_clause_not_judged:requirements.<key>`, TT53), or an `agreed_at` or non-null `expiry` that is not `YYYY-MM-DDTHH:MM:SSZ` (`contract_clause_not_judged:agreed_at`, `...:expiry`); `authorizer_jwks` is not a list of at most 64 objects or `acts` not a list of at most 1024 (`bundle_malformed:authorizer_jwks`, `bundle_malformed:acts`); the terms are malformed (`terms_schema`, `terms_malformed:<member>`, `terms_malformed:max_calls_unknown_action`); the terms name another contract (`terms_for_other_contract`); or both parties did not sign them by the pinned keys (`terms_one_sided`, `terms_bad_signature`, `terms_stranger_signature`, `terms_signature_malformed`).

## 7. Each act

Every item gets a row with one status.

- `unreadable` (`act_malformed`): not exactly an item `{act, bridge, declaration, pic_intent_digest, pic_args_digest, tool_call, transcript, trust_record}` with a well-formed act, or a TRACE object without an RFC 8785 form. Only when the act still carries a valid contractor signature (`signed_by_contractor` is added): nothing about it is counted, and it keeps the verdict from being `within_terms`. An unreadable item nobody signed is `not_attributed` with `act_malformed`, reported only (TT49).
- `not_attributed` (`act_not_signed_by_contractor`): reported, never counted. A third party cannot push the contractor over a count.
- `other_contract` (`contractor_act_for_other_contract`): signed by the contractor under another contract; not judged here, and it keeps the verdict from being `within_terms`.
- `duplicate` (`same_act_again`): the same act bytes (signatures excluded) as an act already read. Counts once. Among identical copies, the one whose evidence matches what the act names is read (TT46).

The remaining acts are read in `seq` order (ties by act bytes, so the order of the list does not matter). For each, every code that applies is listed:

- `seq_conflict`: the contractor signed two different acts with this `seq`. Both are read and counted, and both carry it.
- `executed_before_agreed_at`, `executed_after_expiry`: the contractor states the call ran before the contract's `agreed_at`, or at or after its `expiry` (TT54, TT55).
- `evidence_not_as_signed` (undetermined): the bridge, tool call, declaration, PIC digests or transcript in the bundle are not the ones the act names; `why` lists which. The authorization and the tool are then not judged, and the call counts toward the total only.
- The authorizer: the supplied key with the bridge's `authorizer_key_id` as `kid` under which the bridge's signature verifies. When it is a key the terms list, TRACE decides. When only a key the terms do not list verifies it, `authorizer_not_agreed` and `executed_without_valid_authorization` (the bridge really was signed by that key). When no supplied key verifies it, `authorizer_key_not_supplied` (undetermined).
- TRACE's own `verify_bridge` (agentrust-trace 0.11.0) with that key, at `now = executed_at`: `AuthorizationDenied` is `authorization_denied`, `AuthorizationMismatch` is `authorization_mismatch`, any other error is `authorization_invalid`, each with `executed_without_valid_authorization`.
- `authorization_reused`: an earlier act in this order used the same `authorization_id` from the same authorizer key.
- `tool_not_in_terms`, else `prohibited_action` when the grant prohibits the mapped action, else `action_not_granted` when the grant does not authorize it.
- `calls_exceed_terms`: counting every act read here (valid or not: the contractor signed that it ran), the act takes its action past `max_calls` or the total past `max_calls_total`. The first act over and every later one carry it. An act with `evidence_not_as_signed` counts toward the total only.
- When `runtime` is not null: `runtime_evidence_not_named` when the act's `trace_sha256` is null; `runtime_evidence_missing` (undetermined) when the bundle does not carry the record the act names; otherwise the record is checked as the NENRIN ledger's trace intake checks it at `now = executed_at` (`trace_refused`, the intake code in `why`), then `producer_not_agreed`, `subject_not_agreed`, `model_not_agreed`, `policy_not_agreed`, `enforcement_not_agreed`, `data_class_not_agreed`, `platform_not_agreed`, `slsa_below_terms`, `appraisal_not_agreed` by equality with the terms, and `trace_stale_at_act` when `executed_at - iat` exceeds the agreed maximum age.

An act with any code other than `evidence_not_as_signed`, `authorizer_key_not_supplied` and `runtime_evidence_missing` is `outside_terms`; with only those, `undetermined`; with none, `within_terms`.

The verdict is `refused` (stage A); otherwise `outside_terms` when any act is outside; otherwise `undetermined` when any act is undetermined, unreadable or under another contract, or when no act was read; otherwise `within_terms`.

## 8. What a verdict establishes, and what it does not

Establishes, for anyone holding the bundle:

- that both parties signed the contract and the terms, and the contractor signed each act counted;
- for each such act, whether TRACE's own verifier accepts its authorization under a key the principal agreed to, at the time the contractor states;
- whether those acts, taken together, stay inside the grant and the agreed counts;
- whether each named Trust Record verifies, comes from an agreed producer, is about an agreed subject, and states what the parties agreed.

Does not establish:

- **Anything about acts that were not presented.** An act the contractor never signed, or signed and withheld, is not counted; `seq` is not required to be gap free. Completeness needs the acts on a log the contractor cannot rewrite (the NENRIN ledger with a Bitcoin anchor), or the authorizer's own record of the authorizations it issued.
- That `executed_at` is true. The contractor chooses it, within the bridge's window and the record's age (a record may be issued up to 300 seconds after the stated act, as the NENRIN intake and TRACE allow, so a record that hashes a transcript of the call can follow it); anchor the act to bound it.
- That the grant or an authorizer key was not revoked. Revocations are separate records this profile does not read.
- Anything about anchoring. The acts are not anchored here, so the contract's `lower_bound` and finality are not read; `agreed_at` is the contract's declared time and `executed_at` the contractor's, compared as stated.
- That the runtime which actually ran the call is the one in the Trust Record the contractor names. The record must be about an agreed subject from an agreed producer; that the call ran there is the contractor's statement.
- That any Trust Record claim is true. Its claims are its producer's statements; nothing here appraises a hardware attestation, as TRACE v0.2's own verifier does not.
- That the PIC intent and argument digests are what PIC would compute; they are compared as given.
- What the authorizer key would allow. The terms pin the key; what it signs is the authorizer's.
- Liability, fault, or that this is a legal agreement.

## 9. Relation to other layers

The evaluator imports, and does not reimplement: `contract_v0.verify_contract` (MUSUBI), `nenrin_verify.trace` (the ledger's TRACE intake and RFC 8785), and `agentrust_trace.intent_bridge.verify_bridge` (TRACE). It checks a bridge's signature itself only to tell which supplied key signed it (Ed25519 over RFC 8785 of `{profile, authorization}`, the bytes `sign_bridge` signs). No published settle layer changes, and no field is added to `a2a-execution-v0`: the act is a record of its own, for the reason `trace-bind-v0` section 6 gives.
