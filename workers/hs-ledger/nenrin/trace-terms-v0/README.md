# musubi-trace-terms-v0

TRACE says each call was allowed and what ran it. This says whether all the calls together kept the contract both parties signed.

A TRACE authorization ([pic-trace-bridge-v1](https://github.com/agentrust-io/trace-spec/blob/main/docs/integration/pic-trace-bridge-v1.md)) is one authorizer's signed decision for one tool call, and TRACE's verifier checks one call against it. A TRACE Trust Record is one runtime's statement of what ran. Neither adds anything up, and neither knows what two parties agreed. This profile takes both as evidence, unchanged, under an `a2a-contract-v0` and a terms annex both parties signed, and answers per call and overall: `within_terms`, `outside_terms`, `undetermined` or `refused`. The normative text is [SPEC.md](SPEC.md).

What it adds that a per-call check cannot see, each shown by a vector:

| | |
|---|---|
| TT02, TT03 | every call allowed, the third one more than the parties agreed (`calls_exceed_terms`) |
| TT04 | the bridge scope includes `compare` and TRACE allows it; the contract prohibits it (`prohibited_action`) |
| TT07 | TRACE verifies the bridge under the key the relying party supplied; the principal never agreed to that authorizer (`authorizer_not_agreed`) |
| TT12 | one authorization carried two calls (`authorization_reused`) |
| TT13 | an act signed by someone other than the contractor is reported and cannot push the contractor over a count |
| TT15, TT16 | a real Trust Record (Bernstein 3.20.0, from trace-registry) outside the runtime the parties agreed, and inside terms that agreed on exactly that software-only runtime |
| TT32, TT33 | two different acts the contractor signed with one number cannot hide a prohibited call, in either order |
| TT11, TT35, TT36, TT43, TT44, TT45 | whoever assembles a bundle can swap the evidence or withhold a key; that makes the act undetermined, never outside the terms |

## Run it

    pip install agentrust-trace==0.11.0
    python3 trace_terms_v0.py --selftest          # 55 / 55
    python3 trace_terms_v0.py check bundle.json   # exit 0 within, 1 outside, 2 refused, 3 undetermined
    python3 gen_vectors.py                        # rebuilds vectors/vectors.json byte for byte

The evaluator imports and does not reimplement TRACE's `verify_bridge` (agentrust-trace 0.11.0), MUSUBI's `verify_contract`, and the NENRIN ledger's TRACE intake (`nenrin_verify.trace`).

## Where the records come from

Every authorization in the vectors is signed by agentrust-trace's own `sign_bridge`. The Trust Records are the summit demo record signed by its producer key registered in [agentrust-io/trace-registry](https://github.com/agentrust-io/trace-registry) and Bernstein 3.20.0's record from the same registry, both copied unchanged into [`../trace-bind-v0/sources`](../trace-bind-v0/sources) (CC BY 4.0, commit and digests there), plus records agentrust-trace's `sign_record` signs here. Every other key is a test key derived from a fixed label; the parties are `principal.example` and `contractor.example`.

## Where it stops

Written by the same author as the rest of NENRIN and MUSUBI; not an independent implementation. Three rounds of adversarial review by a separate agent (2026-10-19) found 11 holes in the first draft, 7 in the second and 1 class in the third; each is closed and kept as a vector (TT30 to TT55). It cannot know about an act the contractor never signed or withheld: completeness needs the acts on a log the contractor cannot rewrite. A Trust Record's claims are its producer's statements and nothing here appraises an attestation. The full list is SPEC.md section 8; who can make which code true is section 2.
