# tools/bench

Recompute, on your own machine, how fast the NENRIN verifiers and the MUSUBI settlement run, and check that you get
the same answers: the same input sha256 and the same verdict sha256 as in [RESULTS.md](RESULTS.md).
Everything runs offline from this repository. No live service is called, and nothing is written under the
repository: generated files go to a temp directory (default `$TMPDIR/hs-bench`, or `--out`).

Needs: Python 3.9 or later with `cryptography` (CI pins 46.0.7), Node 22 or later, Go 1.21 or later. `faults.py`
also uses `opentimestamps` for one case (3c); without it that case is not counted.

## The one-line run

```sh
O=$(mktemp -d) && for k in reuse7 per-bundle; do python3 tools/bench/gen_bundles.py --n 10000 --keys $k --out $O && python3 tools/bench/bench_verify.py $O/bundles_${k}_10000.jsonl; done && python3 tools/bench/bench_settle.py --n 1000 --out $O && python3 tools/bench/faults.py --out $O
```

Each command prints one JSON line (faults.py prints a table and `rows_sha256`). Compare `sha256` (input),
`verdict_sha256`, `core_sha256` and `rows_sha256` with RESULTS.md. Times and memory are yours; the shas must match.

## The files

| file | what it does |
| --- | --- |
| `gen_bundles.py` | N provenance bundles as JSONL, deterministic. Keys are Ed25519 seeds = sha256 of a public phrase, derived in memory, never written. Two key modes: `reuse7` (seven keys shared by every bundle) and `per-bundle` (no key is shared between bundles). Ten shapes by bundle number mod 10: 7 accepted, 1 tampered receipt, 1 witness disagreement, 1 receipt outside the grant window. |
| `bench_verify.py` | Feeds the same JSONL to the JavaScript (`sdk/nenrin_verify.mjs` through `sdk-go/parity/js_sig_runner.mjs`), Python (`sdk-python/src`, in process) and Go (`nenrin-verify-go --lines`, built locally) verifiers, one process each. Reports wall time, time per bundle, max RSS (`/usr/bin/time -l` on macOS, `-v` on Linux) and the verdict sha256. Exit 1 if the three verdict shas differ. |
| `gen_settle.py` | One synthetic MUSUBI contract with N executions anchored on a regtest header chain, from the helpers of `musubi-v0/settle-core-v0/gen_vectors.py` (`BASE`, `ex`, `Chain`). |
| `bench_settle.py` | Settles that input with the reference `settle_v1_16` and reports time, max RSS and `core_sha256`, the sha256 of `run_reference.core_fields` written as settle-core-v0 writes `expected.json`. |
| `faults.py` | Four faults (truncated ledger copy, forked head.json, swapped anchor, shortened header view), each tried several ways; counts detected and missed and marks each count verified (run here) or expected (not run, with the reason). |

## What the numbers mean

- The verdict sha256 is over one canonical JSON line per bundle, in input order: `{"threw":true}` if the verifier
  threw, else `{"threw":false,"signature":{verdict,refusals,findings},"codes":[{code,reason}]}`. It is the agreement
  rule of `sdk-go/parity/parity.py`, written as a hash so two machines can compare without exchanging the rows.
- The JavaScript and Python verifiers cache at most 4,096 Ed25519 key checks; Go caches every key. `reuse7` measures
  the verifiers with the cache warm, `per-bundle` with every key new. The key check is a scalar multiplication
  written in each language (pure Python in the Python port), so `per-bundle` is the slow case.
- Wall time includes process start-up and reading stdin. For small N the first run of a freshly built Go binary on
  macOS can take a few hundred milliseconds more.
- The settlement time is the reference implementation in Python; it says nothing about other implementations.

## A row from your machine

Run the one-line command above at the commit named in RESULTS.md and keep the JSON lines, the output of `uname -srm`,
your CPU model and the versions of Node, Python, Go and cryptography. Rows from other machines go in their own table
in RESULTS.md, apart from ours.

To send it, open an issue with the [bench result form](https://github.com/ogasurfproject-jpg/horizon-shield/issues/new?template=bench-result.yml):
the commit you ran, your OS and CPU, the version of each verifier, your numbers in the same table as RESULTS.md, and
the shas. Your row is added to the "Other machines" table in RESULTS.md only when the verdict sha256 (and every other
sha you report) matches RESULTS.md. A result that does not match stays in its issue, and we look into it there: a
mismatch is a finding about the code, not about your machine. Please do not paste a host name or your real name
(`uname -a` prints the host name; `uname -srm` does not).
