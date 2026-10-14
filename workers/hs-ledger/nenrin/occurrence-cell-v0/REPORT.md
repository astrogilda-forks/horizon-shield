# occurrence-cell-v0: NENRIN on the atlas cell "Canonical JSON signature x occurrence"

The cell, as probityai/agent-evidence-atlas#76 states it: a valid signature over a record does not show the run
happened. A passing case refuses a well-signed record that has no independent observation of the run.

This directory asks what the NENRIN provenance verifier (task-execution-bind-v0: a grant signed by the caller, a
receipt signed by the provider the grant names) does with that record. It is verifier behavior on fixtures we wrote,
run by us. It is not an outside run and it is not blind.

## Result

Ten rows. The first seven are the bundles in `in.json`, run offline with no lookup. The last three reuse o00 with an
injected evidence lookup that returns a fixed answer (a stub: it shows what the verifier does with each answer, not
that any system was queried). JS reference (`../sdk/nenrin_verify.mjs`, the same bytes as npm nenrin-verify@0.5.2),
Python port (`../sdk-python`) and Go port (`../sdk-go`, the seven offline rows) give the same signature on every row
(`RAW.txt`).

| Row | Record | Verdict | Refusals | Findings (besides no_delegation_observations) |
|---|---|---|---|---|
| o00 | caller-signed grant, receipt signed by the named provider | accepted | | evidence_bound_unchecked |
| o01 | caller-signed grant, no receipt member | refused | execution_incomplete_pair | |
| o02 | caller-signed grant, receipt null | refused | execution_incomplete_pair | |
| o03 | receipt names the provider but is signed with the caller's key | refused | execution_signature_invalid, execution_unreconciled | evidence_bound_unchecked |
| o04 | grant names the caller as provider; the caller signs grant and receipt | accepted | | evidence_bound_unchecked, self_authorized |
| o05 | provider signs that the run failed | accepted | | evidence_bound_unchecked |
| o09 | provider receipt with no evidence pointer | accepted | | no_evidence_bound |
| o06 | o00, lookup: pointer not found | refused | evidence_invalid | |
| o07 | o00, lookup: found, does not match | refused | evidence_invalid | |
| o08 | o00, lookup: found and matches | accepted | | |

Two frozen vectors of `../interop-v0.3/survivors` belong to the same question and are already on the TSUNAGI board:
p02 (grant signed with the provider's key) and p08 (receipt validly signed by a provider the grant did not name),
both refused.

## What this shows, and where it stops

1. A validly signed authorization with nothing that says the run happened is refused (o01, o02). That is the cell's
   passing case, for this record format.
2. An occurrence signed by anyone other than the provider the authorization names is refused (o03, and p08).
3. **o04 is not refused.** When the caller names itself as provider and signs both halves, the verdict is accepted
   and the verifier only discloses `self_authorized`. On the verdict alone, o04 fails the cell: one party signed the
   authorization and the occurrence. A relying party that requires a separate party has to refuse on that finding
   itself. VERIFIER.md (step 2a) and task-execution-bind-v0/EXTENSION.md list self_authorized as a declared,
   non-fatal disclosure; we did not change that for this run.
4. In o00 the occurrence is a signature by a second party (the provider), not an observation by someone outside
   the pair. Offline the verifier says so (`evidence_bound_unchecked`, or `no_evidence_bound` in o09). Only an
   injected lookup against the system the pointer names moves it to a refusal (o06, o07) or a confirmation (o08),
   and the stub here proves nothing about any real system.
5. The verifier checks the record of the occurrence, not the outcome: a signed failure is accepted (o05).

## Exposure

We wrote the verifier, the base vectors and these cases. The outcomes in the table were observed by running the
verifiers first and written down afterwards; no expected signatures were fixed in advance. Nothing here is blind.

## Roles

- Verifier, cases, run and report: HORIZON SHIELD (ogasurfproject-jpg).
- Keys: test keys derived from public labels in
  `../conformance-v0/adequacy-v0/proposed_vectors/make_proposed_vectors.py` (sha256 of a label is the Ed25519
  seed). Anyone regenerates the same bytes; they protect nothing. Keys are resolved from the did:key strings.

## Run it

    bash workers/hs-ledger/nenrin/occurrence-cell-v0/run.sh      # regenerates in.json, runs JS, Python, Go, writes RAW.txt

or, with only node and the npm package:

    npm init -y && npm install nenrin-verify@0.5.2
    node <this dir>/run_occurrence.mjs node_modules/nenrin-verify <this dir>/in.json out.json

`RAW.txt` was written before the commit, on its parent; the committed bytes of every file here are the ones that
run used (`SHA256SUMS`).
