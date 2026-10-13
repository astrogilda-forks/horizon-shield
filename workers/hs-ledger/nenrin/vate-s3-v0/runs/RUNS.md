# RUNS: the three cases through the published nenrin-verify builds

Run on 2026-10-13. Every file named here is the raw output of that run, kept unchanged.

## Versions

| build | package | version | how it was installed | where it came from |
|---|---|---|---|---|
| npm | `nenrin-verify` | 0.5.1 (`npm view nenrin-verify version` printed `0.5.1`) | `npm install --no-save nenrin-verify@0.5.1` in a scratch directory outside the repository | `https://registry.npmjs.org/nenrin-verify/-/nenrin-verify-0.5.1.tgz`, integrity `sha512-OrQZLd7hQnF8X6ROW7ZvhhHrux5DjRZYOFHeP5qP2jhncsI2rb4u1Pa505ud3Uv187OsXrKQWiFENvX0za4H+w==` |
| PyPI | `nenrin-verify` | 0.5.3 (`pip index versions nenrin-verify` listed 0.5.3 as the latest) | `pip install nenrin-verify==0.5.3` into a fresh venv outside the repository | PyPI index (no `direct_url.json`, so not a local or VCS install) |

Runtime: node v22.22.2, Python 3.11.15 (also in `ENV.txt`).

## Exact commands

```sh
EXT=/path/outside/the/repo
mkdir -p "$EXT/npm" && cd "$EXT/npm" && npm init -y && npm install --no-save nenrin-verify@0.5.1
python3 -m venv "$EXT/venv" && "$EXT/venv/bin/pip" install nenrin-verify==0.5.3

cd workers/hs-ledger/nenrin/vate-s3-v0
runs/run_published.sh "$EXT/npm" "$EXT/venv"
```

`run_published.sh` runs, for each case `C` in `match`, `target_mismatch`, `missing_receipt`, from inside `records/C/`:

```sh
"$EXT/npm/node_modules/.bin/nenrin-verify" nenrin-bundle.json   > runs/npm-C.out  2> runs/npm-C.err   # exit code in runs/npm-C.exit
"$EXT/venv/bin/nenrin-verify"              nenrin-bundle.json   > runs/pypi-C.out 2> runs/pypi-C.err  # exit code in runs/pypi-C.exit
"$EXT/venv/bin/nenrin-verify" --sha        nenrin-bundle.json   > runs/pypi-C.sha.txt                 # verdict and report_sha256
```

The npm CLI has no `--sha` option (it reads its first argument as the bundle path), so only the PyPI build has a `.sha.txt`.

## Results

| case | prediction | npm 0.5.1 verdict / refusal codes / exit | PyPI 0.5.3 verdict / refusal codes / exit | equal? |
|---|---|---|---|---|
| match | accepted | accepted / none / 0 | accepted / none / 0 | yes, stdout byte-identical |
| target_mismatch | refused, `execution_invalid`, reason `action_diverged` | refused / `execution_invalid` reason `action_diverged` / 1 | refused / `execution_invalid` reason `action_diverged` / 1 | yes, stdout byte-identical |
| missing_receipt | refused, `execution_incomplete_pair` | refused / `execution_incomplete_pair` / 1 | refused / `execution_incomplete_pair` / 1 | yes, stdout byte-identical |

Findings (not refusals) in both builds:

- match: `no_delegation_observations`, `evidence_bound_unchecked`
- target_mismatch: `no_delegation_observations`, `evidence_bound_unchecked`
- missing_receipt: `no_delegation_observations`

Other layer values worth reading: in `target_mismatch` both signatures verify, `layers.execution.pair` is `action_diverged`, `reconciliation` is `reconciled` and both action bindings are `recomputed`; the refusal comes from E1 alone. In `missing_receipt`, `layers.execution` is `{"present": true, "complete": false}`.

All three predictions held. No case differs between the builds, so no case is marked unconfirmed.

## Output digests

| file | sha256 |
|---|---|
| npm-match.out, pypi-match.out | 609009ef1a7e0c3e5f833496f4afa71ddaa9a572174141dff98e0d53c536ba55 |
| npm-target_mismatch.out, pypi-target_mismatch.out | 5f2ecffd45107d373db9fe980375804d2c72cb5707a91283af16438ce3e85abd |
| npm-missing_receipt.out, pypi-missing_receipt.out | 720843c8668a5fd0991ad555a482ed3593eadcdc0df90e02f489b5545d81f35a |

PyPI `--sha` lines (report_sha256):

| case | line |
|---|---|
| match | `accepted 948866db75847303fae0cf6f150aa65f221421ddae83a10fd8cad3b362f2121f` |
| target_mismatch | `refused 6cd9b9ac69b4960014e4e31693f84bb27452a479f62c89a8481ae8728103673e` |
| missing_receipt | `refused a8bbd14f50a882df38ee155d2af6c3c4e23925755551fb6a1f49ada1605cc898` |

All six `.err` files are empty.

`vate_s3_v0.test.mjs` also checks that each of these six `.out` files equals the report the in-repo `sdk/nenrin_verify.mjs` prints for the same bundle.
