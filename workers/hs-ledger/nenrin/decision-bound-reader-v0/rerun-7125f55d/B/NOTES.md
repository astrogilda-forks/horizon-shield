# NOTES

- Python: 3.11.15 (`python3 --version`), standard library only (hashlib, json, math, sys). Run with `-I -B`.
- reader.py sha256: `5c0a685b328c6755a353e2cf4fea6fa347c96221968552809e6075285abee9ca`

## How it was built

1. Read decision_bound.py and jcs.py as text only. Neither is imported or copied.
2. Wrote an independent RFC 8785 canonicalizer: object keys sorted by UTF-16 code units, no whitespace, minimal string escaping (short forms for `" \ \b \f \n \r \t`, `\u00XX` for other control characters, non-ASCII kept as UTF-8), integers as decimal, floats in ECMAScript Number-to-String form from Python's shortest round-trip repr, booleans and null as literals. Spot-checked number formatting (1e21, 1e20, 1e-6, 1e-7, 5e-324, 100.0) and supplementary-plane key ordering.
3. `ref(x) = "sha256:" + sha256(JCS(x))`. Per case: recomputed decision_id = ref(decision_preimage); bound hash = ref({content_sha256 (bare, as given), decision_id, version: "decision-bound-output-v1"}), computed from both the claimed and the recomputed id; legacy hash = "sha256:" + content_sha256.
4. Verdict precedence: DECISION_ID_MISMATCH, then (bound match) ACCEPTED / UNAUTHORIZED_BINDING by outcome, then UNVERIFIABLE_LEGACY, else OUTPUT_HASH_MISMATCH. Rule sources and the open choices are in GAPS.md.
5. Output: one line `<case_id> <VERDICT>` per case plus `SUMMARY`; a JSON file with every recomputed value and comparison flag. Exit 0 when all cases were evaluated, 2 on unreadable or malformed input.

Files: reader.py, RAW.txt (both runs, exit codes, Python version), out_vectors_decision_bound.json, out_vectors_decision_bound_real_run.json, GAPS.md, NOTES.md.
