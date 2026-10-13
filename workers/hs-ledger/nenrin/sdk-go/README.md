# nenrin-verify-go: the NENRIN provenance verifier in Go

A Go port of the provenance verifier in npm and PyPI `nenrin-verify` (verifier_version 0.1.6). Standard library
only, no network, no clock. It reads a NENRIN provenance bundle and returns the verdict signature the reference
returns: the verdict, the set of refusal codes and the set of finding codes, with each refusal's reason.

```sh
go install github.com/ogasurfproject-jpg/horizon-shield/workers/hs-ledger/nenrin/sdk-go/cmd/nenrin-verify-go@latest

nenrin-verify-go bundle.json                      # report; exit 0 accepted, 1 refused, 2 input error
nenrin-verify-go --corpus ../interop-v0           # reproduce a frozen corpus
```

As a library:

```go
import nv "github.com/ogasurfproject-jpg/horizon-shield/workers/hs-ledger/nenrin/sdk-go/nenrinverify"

v, err := nv.ParseJSON(raw)        // JSON.parse semantics: every number a double, duplicate keys last-wins
rep, err := nv.VerifyBundle(v)     // did:key identities resolve offline; err means the reference throws here
sig := rep.Signature()             // {verdict, refusals, findings}
```

## How it is held to the reference

| check | result |
|---|---|
| interop-v0, interop-v0.1, interop-v0.2/edge, interop-v0.2/action-presence, interop-v0.3/survivors (`go test ./...`, `--corpus`) | 5/5, 13/13, 36/36, 9/9, 9/9 |
| musubi-canonical-v0 shared vectors (`../musubi-v0/canonical_vectors.json`) | 9/9, byte for byte |
| `parity/parity.py`: the 31 frozen parity bundles and their mutations (the same set the Python port is held to), the five interop corpora and 40 signed edge bundles from `../conformance-v0/gen_edge_bundles.mjs`, each parsed by JavaScript and Go from the same text | 27,174 inputs, 0 differences (2,352 on which both throw) against `../sdk/nenrin_verify.mjs` on Node 22 (0.2.1; 27,156 with three corpora at 0.2.0) |
| TSUNAGI, every night from this repository (`ops/tsunagi/BOARD.md`) | one row: the five provenance corpora above and the three TRACE corpora |

The pass condition in `parity.py` is strict: both throw, or the same verdict signature and the same refusals as
(code, reason) in the same order.

```sh
go build -o nenrin-verify-go ./cmd/nenrin-verify-go
node ../conformance-v0/gen_edge_bundles.mjs /tmp/edge.json
python3 parity/parity.py ./nenrin-verify-go --edge /tmp/edge.json
```

## Where the claim stops

- **Same author.** This is a second language written from the reference, not an independent implementation. The
  independent ones are listed in `../interop-v0/INTEROP.md`.
- **Verdict signature only.** The reference report also carries `layers`, `establishes`, `does_not_establish`,
  `rules` and `signers`. This port does not reproduce those texts. The verdict and the codes are what
  `../provenance-v0/VERIFIER.md` section 4 defines as the verdict signature.
- **JavaScript semantics are copied, including the odd ones**, because the reference is the contract: a record
  with an own `__proto__` key loses it from its preimage (Object.assign), `hop.seq` keys that are not numbers are
  ordered the way V8's sort orders them, and an input on which the reference throws returns an error here. Fewer
  than 64 non-numeric `hop.seq` keys are reproduced; 64 or more return `ErrNotReproduced` instead of a guess.
- **Ed25519** is Go's `crypto/ed25519` (RFC 8032, cofactorless, S < L), behind the key rule of VERIFIER.md
  section 5 (canonical encoding of a point of the prime-order subgroup). Within that rule it agrees with OpenSSL
  on every corpus and parity input.
- Raw input bytes that are not valid UTF-8 are decoded per maximal subpart, as Node's `readFileSync(path, "utf8")`
  does.

Cite what it was checked against: Oga, T. (2026). NENRIN provenance verifier: normative procedure (VERIFIER.md),
interoperability vectors and reference verifiers. Zenodo. https://doi.org/10.5281/zenodo.23136978

## TRACE (2026-10-09)

`nenrinverify/trace.go` ports the TRACE intake rule, the `nenrin-trace-bind-v0` verifier and the span check of
`../sdk/trace_verify.mjs` (normative text `../trace-bind-v0/SPEC.md`): `CheckTraceRecord`, `VerifyTraceIntake`,
`VerifyTraceBind`, `SpanAttributes`, `CheckSpanAttributes`. `nenrin-verify-go --trace-batch intake|bind|span in out`
is the TSUNAGI batch form. `go test ./...` runs the three corpora (28, 28, 16); the board referees them nightly.

## 0.2.1 (2026-10-13)

`go test ./...` and the CI's `--corpus` loop now also read interop-v0.2/action-presence (9/9) and
interop-v0.3/survivors (9/9). The second is new: nine vectors frozen from the adequacy-v0 measurement
(`../conformance-v0/adequacy-v0/REPORT.md`), each killing a declared verifier fault the older corpora let survive.
The verifier code is unchanged; only `PortVersion` moved.
