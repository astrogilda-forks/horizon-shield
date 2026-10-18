# Sidecar-swap control (horizon-shield #51), by Poke-nushi

A negative control for the acceptance row of the #51 comparison, prepared and published by Poke-nushi (Takao Sato, VATE) in [Poke-nushi/Verifiable-Agent-Trust-Envelope at `f8fa1478d6ac4bb454bb9bbf0bc46f941d316e36`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/f8fa1478d6ac4bb454bb9bbf0bc46f941d316e36/examples/interop/horizon51-sidecar-swap), and frozen here byte for byte as he offered on #51. It is a derived rehearsal control, not a pilot record.

The two rehearsal acceptance records Federico (babyblueviper1, invinoveritas) issued on `rehearsal/live_smoke` ([preaction-governance-conformance at `a77ff8fa`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/a77ff8fabe46a30aaf3e50d10c8c3a9f003713f9/examples/work-acceptance-issuer)) each carry a signed `bindings_sidecar`. In each file here, only that complete top-level value was exchanged with the other record's, signature included. Every signature still verifies; only the join from each sidecar to the acceptance receipt it sits beside fails.

| File | SHA-256 of the file bytes |
|---|---|
| `hs51-rehearsal-caseA-audit-only.swapped-sidecar.json` | `32744cfc7104dcb5bb59daf7305f9b7fe4887ce4da81886040003f73ef836ada` |
| `hs51-rehearsal-caseA-with-fixture.swapped-sidecar.json` | `561ce33bad29cac89261ae1a7d06a7c71a9d118103667e9ef940d04083846860` |

`control-manifest.json`, `SHA256SUMS` and `UPSTREAM-LICENSE.txt` are his, unchanged (the source records are MIT).

## Checked here, independently

`check_swap.py` is ours. It does not read the checker key from the files: it uses the invinoveritas key Federico posted on #51 (`invinoveritas-checker-a4cecab2`, `pY0UINp9HP6CVUTRBcOeKo5MPbhqRlEsuiAAw3JR3WU=`). It verifies both signatures in each file, computes the JCS SHA-256 of the inner acceptance receipt, and compares the sidecar's execution and occurrence digests with the bytes in `../live_smoke/` (`receipt.json` 1c01ea21…, JCS of `call.json` `request` 69546501…). Its lines are kept in `CHECK.txt`:

```
python3 check_swap.py --check     # CHECK.txt agrees, CONTROL_OK: 2 files
shasum -a 256 -c SHA256SUMS
```

Before freezing, the swap itself was also checked against the two originals at `a77ff8fa`: every top-level value other than `bindings_sidecar` is equal to its own original, and each `bindings_sidecar` is equal to the other original's.

Result, as Poke-nushi stated: acceptance signature valid, sidecar signature valid, the receipt join false, the execution and occurrence joins true, in both files. A reader that checks signatures and verdicts only (the original `war_check.py`) accepts both files; a reader that checks the join reports both mismatches.

Not checked: TSA signatures and trust chains (only digests and parsed times are in the files), and the model judgment behind the criterion results.
