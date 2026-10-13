# Independent reader for the PriorSeal exact-call matrix v1.0.1

Result: **AGREES.** A separately written Python reader, built from PriorSeal's published contract,
fixture and docs without opening any PriorSeal verifier code, reproduces every comparable field of the
committed `report.json` at `imokokok/PriorSeal@2ff89d86611257b4440232e5c2793926b3d52043` (contract 1.0.1):
89 fields equal, 0 different, 13 not comparable. Of 91 claims, 78 are ESTABLISHED, 0 are contradicted by the
computation, 12 are NOT_ESTABLISHED (no input or no spec), and 1 documentation inconsistency was found (the
README case table, see G7).

This is a different project's reader (HORIZON SHIELD / NENRIN), not PriorSeal's and not the Open Evidence
Lab's. It is answer-exposed: the expected results are published with the fixture and were read before the
reader was written.

## Pins

| Item | Value |
| --- | --- |
| Repository | https://github.com/imokokok/PriorSeal |
| Matrix commit | `2ff89d86611257b4440232e5c2793926b3d52043` (shallow fetch of that SHA) |
| Matrix | `examples/open-evidence-lab-exact-call-matrix-v1/`, contract `1.0.1` |
| Cold-run packet / template commit | `d90e5d3aaccc7e83e19ca39d2e785290a480801a` |
| Committed `report.json` sha256 | `223db1554639f242eae559b1f010dcabe3e9466e610cfa95aefe2e1ce564a363` (matches MANIFEST and the packet) |
| `signed-authorization.json` sha256 | `38cebf301c47a63fd3f308b6b7e7e6b6bd0fd166c81857276059650f828fdccb` |
| Python | CPython 3.11.15 |
| Libraries | pycryptodome 3.21.0 (keccak), eth-keys 0.6.0 (secp256k1 recovery), cryptography 43.0.3 (Ed25519), eth-account 0.13.4 (second-path cross-check only); full pins in `requirements.txt` |
| Our `report.json` sha256 | `1be82ce82e6e185b7cce78b5ddd8beb5019d07043e55960567615f54d2338f66` (deterministic: two runs, identical bytes) |

Every file's sha256 and byte length is recorded in `report.json` under `pins.files`, with the reader's own
sha256 under `pins.self`.

## Run

    ./run.sh /some/empty/dir          # clone at the pin, fresh venv, run, write report.json here
    PROBES=1 ./run.sh /some/empty/dir # also run the mutation probes below

`reader.py` exits 0 only when nothing is contradicted (the README-table finding excepted) and every
comparable field equals the published report.

## What was independently checked

Authorization level (one signed authorization shared by all six cases):

| Id | Check | Rule source | Result |
| --- | --- | --- | --- |
| A5 | EIP-712 digest, hand-rolled: type string from contract 2.1, values from the 2.3 path map, domain `{PriorSeal, 2, 8453}` | INPUT-CONTRACT 2.1, 2.3; EIP-712 | `0x9e404bfc...92cf5b1`, equal |
| A6 | Signer recovery from `(digest, signature)` equals `authorization.authorizer.address` | INPUT-CONTRACT 2.1 | `0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A`, equal; v=27, low-s |
| A7 | Second path through eth-account `encode_typed_data` + `recover_message` | library, not PriorSeal | same digest, same signer |
| A8 | Ed25519 acceptance signature over UTF-8 canonical JSON of the acceptance without `signature` | INPUT-CONTRACT 2.2; canonical form from the APS signing-bytes doc | valid |
| A9, A10 | Acceptance issuer, keyId, algorithm match the key file; ACCEPTED, sequence 1, `previousEntryHash` null | INPUT-CONTRACT 2.2; APS doc | ESTABLISHED |
| A1 | `intentHash = H(intent without intentHash)`; intent, authorization and acceptance copies agree | APS doc | `a18ebfbf...b08c0ae6`, equal |
| A2 | `authorizationId = "auth_" + H(authorization without authorizationId, signature)[:32]`; acceptance carries it | APS doc | `auth_50e35155...`, equal |
| A3 | `acceptance.authorizationHash = H(full authorization)` (binds the acceptance to this exact signed authorization) | APS doc | equal |
| A4 | `acceptance.entryHash = H({sequence, authorizationHash, acceptedAt, previousEntryHash})` | APS doc | equal |
| A11 | Authorization window at reference time `tRef = notBefore = 1000`: `issuedAt <= notBefore <= tRef <= expiresAt`, acceptance inside the window, `maxUses >= 1`, eip712 EOA with `principal.account == authorizer.address`, v2 schema and profile | d90e5d3 packet README; INPUT-CONTRACT 2 | ESTABLISHED |
| A12 | The published TEST seed and TEST secp256k1 value derive the published Ed25519 key and address | key file | consistent (informational) |

Per case:

| Id | Check | Rule source |
| --- | --- | --- |
| C2 | Authorization to observation binding: chain, delegated executor (`delegate.executor` vs observed `sender`) and nonce correlate | lifecycle.md |
| C3 | `acceptance.acceptedAt` not later than observed execution time (else `AUTHORIZATION_AFTER_EXECUTION`) | lifecycle.md |
| C5, C6, C7 | Section 4 mismatch set, section 5 availability set, `bound = mismatch set empty`, with `String()` coercion and ASCII case folding | INPUT-CONTRACT 4, 5 |
| C8, C9 | Compliance status / reason codes and outcome, from a rule inferred from lifecycle prose | lifecycle.md (inferred, G3) |
| C10 | The shipped profile's raw binding as mismatch set UNION availability set | INPUT-CONTRACT changelog note |
| C12 | Case class derived from the result | INPUT-CONTRACT 5 |
| C4, C11 | Decision-evidence binding; `receiptClaimsValid` | NOT_ESTABLISHED (no input; no definition) |

Matrix level: M1 commit pin, M2 all 18 MANIFEST digests and byte lengths (verifier files hashed as bytes
only), M3 contract version in three files, M4 report sha256 equals the packet value, M5 report embeds
expected.json unchanged, M6 README table vs expected.json (CONTRADICTED, G7).

## Results compared with their report.json

| Case | bound (ours / theirs) | mismatch codes | availability | raw profile binding | compliance | outcome | fields equal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| case-00 exact match | true / true | none | none | true | COMPLIANT | COMPLETED | 13/13 |
| case-01 call target | false / false | CALL_TARGET_MISMATCH | none | false | NON_COMPLIANT | COMPLETED | 13/13 |
| case-02 calldata | false / false | CALLDATA_MISMATCH | none | false | NON_COMPLIANT | COMPLETED | 13/13 |
| case-03 native value | false / false | TRANSACTION_VALUE_MISMATCH | none | false | NON_COMPLIANT | COMPLETED | 13/13 |
| case-04 evidence unavailable | true / true | none | EXECUTION_UNAVAILABLE | false (EXECUTION_UNAVAILABLE) | NOT_ASSESSABLE (EXECUTION_UNAVAILABLE) | UNDETERMINED | 13/13 |
| case-05 late execution | false / false | OUTSIDE_AUTHORIZATION_WINDOW, OUTSIDE_TIME_WINDOW | none | false | NON_COMPLIANT | COMPLETED | 13/13 |

Compared per case (13): `reader.bound`, `reader.mismatchCodes`, `reader.availabilityCodes`,
`profile.partitionedBinding.{bound, mismatchCodes, availabilityCodes}`, `profile.rawBinding.{bound,
reasonCodes}`, `profile.complianceStatus`, `profile.complianceReasonCodes`, `profile.outcome`, `className`,
`pass`. Signature block (8): `declaredAuthorizer`, `recoveredAuthorizer` (exact EIP-55 string),
`authorizerMatches`, `eip712Digest`, `acceptanceIssuer`, `acceptanceKeyId`, `acceptanceSignatureValid`,
`authorizationValidAtNotBefore`. Summary (3): case counts by class. Total 89 equal, 0 different. Codes compare
as sorted sets, as the contract requires.

Not comparable (13): `signature.authorizationCode` ("OK"; its vocabulary is unpublished), and per case
`profile.receiptClaimsValid` (no receipt object, no definition) and the `agreement.*` flags (their internal
cross-implementation flags; replaced by our own comparison rows).

Mutation probes (`PROBES=1`), each run on a scratch copy; every real change is caught and both controls stay
clean:

| Probe | Caught by |
| --- | --- |
| one hex digit of the EIP-712 signature | A3, A6, A13; 8 fields differ |
| `acceptance.acceptedAt` 1000 to 1001 | A4, A8; 7 fields differ |
| `authorization.expiresAt` 2000 to 3000 | A2, A3, A5, A6, case-05 codes; 13 fields differ |
| case-00 observed nonce to 8 | C2, C5, C7, C8, C10 |
| case-04 evidence made available and CONFIRMED | C6, C8, C9, C10, C12 |
| control: case-00 calldataHash upper-cased | nothing (case-insensitive, as specified) |
| control: case-00 nonce as JSON number 7 | nothing (`String()` coercion, as specified) |

## Spec gaps found

G1. **Hash identities are not in the contract.** INPUT-CONTRACT 1.0.1 does not define `intentHash`,
`authorizationId`, `authorizationHash` or `entryHash`, nor the exact canonical JSON (2.2 calls it
"the producer's RFC 8785-style canonical form" and says the reader does not have to re-derive it). We used
`docs/architecture/aps-priorseal-signing-bytes-v0.4.0.md`, which was written for the APS fixture at
`d749d269`. All four identities and the acceptance signature reproduced byte for byte, so the rules carry
over, but the matrix contract should cite or restate them; without that page, A1 to A4 and A8 would stop at
"signature verifies over bytes we cannot independently derive the meaning of".

G2. **Reference time for the authorization check.** At `2ff89d8` the contract does not say at what time the
authorization is evaluated, nor what `authorizationCode: "OK"` covers (audience, maxUses, policy?). The
reference time `notBefore` is visible only in the report key `authorizationValidAtNotBefore` and in the later
d90e5d3 packet ("the authorization check at `notBefore` passes"). Policy admission cannot be checked:
`policyHash` is the zero hash and no policy document is published.

G3. **No general rule for compliance and outcome.** The contract gives `COMPLIANT` / `NON_COMPLIANT` /
`NOT_ASSESSABLE`, `complianceReasonCodes` and `COMPLETED` / `UNDETERMINED` only per case (section 7,
expected.json). We inferred the rule from lifecycle.md: availability codes give `NOT_ASSESSABLE` with those
codes; a correlated final execution with mismatches gives `NON_COMPLIANT` with the mismatch codes;
`CONFIRMED` gives `COMPLETED`; `NOT_FOUND`, `PENDING`, `RPC_*` or unavailable evidence give `UNDETERMINED`.
It reproduces all six, but case 04 sets both `executionDataAvailable: false` and `status: NOT_FOUND`, so the
fixture cannot tell which of the two produces `UNDETERMINED`. The outcome label for `REVERTED` is not
published for this profile.

G4. **Correlation mismatches vs compliance (untested).** lifecycle.md says an uncorrelated transaction (chain,
delegated executor, nonce) "remains not assessable", while section 4 lists `CHAIN_MISMATCH`,
`SENDER_MISMATCH` and `NONCE_MISMATCH` as ordinary mismatch codes. No case moves those fields, so whether
such a case is `NON_COMPLIANT` or `NOT_ASSESSABLE` is unspecified. Section 4 also compares `intent.sender`
while lifecycle correlates on `delegate.executor`; they are equal in this fixture.

G5. **The observation does not name the authorization.** The observed envelopes carry no `authorizationId`,
`intentHash` or other link; the pairing is by fixture layout. The live API takes `authorizationId` on
observe (signed-authorization.md), but in the matrix that binding is outside the bytes.

G6. **Comparison wording.** "Only when present in the signed intent" does not say whether `null` or `""`
counts as present. Section 4 says "equality of decimal-string forms" for nonce and value while expected.json
says `strict-string-equality`; whether `"007"` equals `"7"` is not settled (we follow the `String()`
paragraph: not equal). chainId is "strict equality of the integer values" while the semantics paragraph says
all values compare after `String()`; `8453` vs `"8453"` is not exercised. The availability rule says only
`false` yields the code; a missing `executionDataAvailable` is unspecified. Whether time-window checks apply
when evidence is unavailable is unspecified (case 04 is inside both windows, so it makes no difference here).

G7. **README case table disagrees with expected.json on case 05.** The matrix README lists case 05 as
`NON_COMPLIANT, UNDETERMINED`; expected.json, report.json and lifecycle.md (a confirmed late execution is
completed but non-compliant) all say `COMPLETED`. Documentation only; no computed result is affected.

G8. **Undefined report fields.** `receiptClaimsValid` and `authorizationCode` are not defined and the
receipt they refer to is not published, so they cannot be reproduced from outside.

## What could not be established

- Binding to separate decision evidence (C4): the matrix contains none, and the intent has no
  `contextCommitments`. The only pre-execution evidence is the issuer acceptance, which is checked.
- `receiptClaimsValid` and `authorizationCode` (G8).
- Policy admission (G2) and anything about ERC-1271, RFC 3161, witness quorum or anchoring: not in this
  fixture.
- Which observation field drives case 04's `UNDETERMINED` (G3).
- Anything about real chains: the observations are synthetic and nothing was fetched from an RPC.

## Independence statement

The reader was written in Python from the files listed under "Read". No PriorSeal verifier, reader, runner,
generator, SDK or application source was opened, imported, copied or executed by the author of this reader
while writing it. The six producer files in the matrix directory were only hashed as bytes for the MANIFEST
check. The external v1.0.0 Python reader in the Open Evidence Lab record was not opened either.

Read (at `2ff89d8` unless noted):

- `examples/open-evidence-lab-exact-call-matrix-v1/`: `README.md`, `INPUT-CONTRACT.md`, `MANIFEST.json`,
  `expected.json`, `report.json`, `fixture/signed-authorization.json`, `fixture/public-test-keys.json`,
  `fixture/observed/case-00` to `case-05` (6 files)
- `docs/architecture/`: `signed-authorization.md`, `lifecycle.md`, `evidence-relationship-levels.md`,
  `temporal-finality.md`, `aps-priorseal-signing-bytes-v0.4.0.md`
- `docs/case-studies/open-evidence-lab-priorseal-exact-call-reproduction-2026-10.md`
- `README.md` (repository root)
- `sdk/README.md`: a keyword search for compliance and outcome terms, and the exact-call prose section
  (lines 185 to 213); no source under `sdk/src/`
- At `d90e5d3`: `docs/runs/priorseal-exact-call-matrix-v1.0.1-cold-run/README.md`, `RESULT-TEMPLATE.md`,
  `OEL-INVITATION.md`
- File names only (`git ls-files`) to locate the above

Not opened: `verify.mjs`, `verify.mts`, `reader.mjs`, `reader.mts`, `generate-fixture.mjs`,
`generate-fixture.mts` (hashed only); everything under `src/`, `sdk/src/`, `test/`, `scripts/`; all other
examples' code.

Disclosure: earlier on the same day, the same project ran PriorSeal's `verify.mjs` from a fresh clone as a
reproduction (executed, source not read). Its output equals the committed `report.json`, which this reader
read as the comparison target anyway.

## Limits

- Synthetic, offline fixtures: no chain observation, no RPC, no real execution or finality.
- Answer-exposed conformance check, not a blind replication: expected values were public and read first.
- Compliance and outcome rules are inferred (G3); hash identities rest on a doc written for another fixture
  (G1). Both reproduce every published value here, which supports but does not prove the readings.
- One authorization and six envelopes, one field moved at a time; not a corpus, not adversarial encodings.
- Not adoption, endorsement, integration or pilot by PriorSeal, the Open Evidence Lab or HORIZON SHIELD.
  Written by a different project (HORIZON SHIELD / NENRIN).

## Cold-run result (PriorSeal RESULT-TEMPLATE.md at d90e5d3)

Operator and independence

- Operator: HORIZON SHIELD / NENRIN (GitHub `ogasurfproject-jpg`)
- Relationship to PriorSeal / fixture author: none; a separate project
- Separate machine or environment from the author: yes
- Fresh clone at the commit below: yes (shallow fetch of the exact SHA)
- Expected output visible before the run: yes (it is published)
- Runner used: other, the independent Python reader in this directory (`reader.py`), not `verify.mjs`
- Independent reader implementation used: yes. Python 3.11, reader sha256 in `report.json` `pins.self`.
  Scope: EIP-712 digest and recovery, Ed25519 acceptance, intent / authorization / entry hash links,
  authorization window at `notBefore`, sections 4 and 5, correlation and acceptance-before-execution,
  compliance and outcome (inferred rule), raw profile binding

Pinned input and environment

- Repository commit: `2ff89d86611257b4440232e5c2793926b3d52043`
- Contract version: `1.0.1`
- `git rev-parse HEAD`: `2ff89d86611257b4440232e5c2793926b3d52043`
- OS and architecture: Linux x86_64
- Node.js / npm: not used
- Commands: `./run.sh <workdir>` (clone, venv from `requirements.txt`, `python -I reader.py --clone ... --out report.json`)
- `npm ci` result: not applicable

Observed result

- Reader exit code: 0
- Result: AGREES (89 fields equal, 0 different, 13 not comparable)
- Cases agreeing / total: 6 / 6
- Authorizer recovery matched declared signer: yes
- Acceptance signature valid: yes
- Authorization check passed: yes (at `notBefore`, see A11 for the individual checks)
- Output byte-identical to committed `report.json`: not applicable (different program and schema); field by
  field comparison above
- SHA-256 of our output: `1be82ce82e6e185b7cce78b5ddd8beb5019d07043e55960567615f54d2338f66`
- Case 04: `bound: true`, mismatch codes none, availability `EXECUTION_UNAVAILABLE`, raw profile binding
  `false`, `NOT_ASSESSABLE`, `UNDETERMINED`
- Case 05: `OUTSIDE_AUTHORIZATION_WINDOW` and `OUTSIDE_TIME_WINDOW`, `NON_COMPLIANT`, `COMPLETED`
- Differences: none in computed fields; README case table states case 05 as `UNDETERMINED` (G7)

Disclosure and limits

- Local changes: none to the PriorSeal checkout
- Limits on reproducing: `run.sh` needs network for the clone and pip; the reader itself is offline
