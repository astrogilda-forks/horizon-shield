# Leg 1 regression vectors from babyblueviper1 (CC0-1.0)

Vendored byte for byte from the canonical copy:
https://github.com/babyblueviper1/preaction-governance-conformance/tree/bc02683/examples/musubi-leg1-fixtures

`leg1_vectors.json`, sha256 `3f9408a0a6292196adf13a217be937139260a309c055227369195203f18e243d` (pinned in SHA256SUMS here and in the source).
Author: babyblueviper1, from babyblueviper1's finding in horizon-shield#25. License: CC0-1.0.

Five vectors, every batch derived byte-wise from the real stamped batch `entry63.raw` (JIDEC entry 63, 368f3196...) with the real
execution 19c44a79 (`../../run0002/exec_19c44a79.json`) as the record. Only the control is accepted.

`python3 ../../anchor_compose.py --selftest` runs them in check [10c]: the sha pin first, then every vector through `batch_ops`
(the composer) and through `batch_leg_check` (the verifier, on a proof spliced at the digest's first occurrence), expecting the
reason codes in the file. Do not edit this copy. A change goes through the canonical copy and a new pin.
