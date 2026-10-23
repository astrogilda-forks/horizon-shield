# settle core v0 differential fuzzing

`settle_core_fuzz.py` generates inputs for MUSUBI settle core v0
(`workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md`), runs each one through every implementation
pinned in `implementations.json`, projects every output onto the eight core fields of section 9.1 and compares them.
The first crash, timeout or disagreement stops the run and is written down for the owner of the specification.
It judges nobody: a disagreement means the text, the reference or an implementation is wrong, and section 15 says how
to report it.

## Implementations

| name | language | source | how it is called |
|---|---|---|---|
| `reference` | Python | this repository, `musubi-v0/settle_v1_16.py` | `settle_v1_16(contract, events, view, parent=..., nenrin_records=...)` on the files read as `run_reference.settle_dir` reads them, projected by `run_reference.core_fields` |
| `aeoess` | Python | `aeoess/musubi-settle-core-check` at `53cfafb4` | `impl/run_all.py` `run_one(<id>)`, projected as `run_all.main` writes `out/<id>.json` |
| `kuangmi-bit/cryptography` | Python | `kuangmi-bit/nenrin-independent-verifiers` at `bbe455c0`, `settle-core-v0/` | `load_vector(dir)` then `settle(...)`, as its `main()` does for one vector, Ed25519 through `cryptography` |
| `kuangmi-bit/rfc8032` | Python | the same file | the same, with the module's `HAVE_CRYPTO` set to False, so Ed25519 runs on its own RFC 8032 verifier |

There is no JavaScript or Go implementation of settle core v0 in this repository (`sdk/`, `sdk-go/` and
`workers/hs-ledger/nenrin/` were searched). When one appears, add an adapter and a line to `implementations.json`.

`implementations.json` pins each outside implementation by repository, commit, tree hash and the sha256 of every
file that is run, and pins the reference files (`settle_v1_16.py`, `run_reference.py`, `gen_vectors.py`) by sha256.
`run` refuses to start when a pin does not match. No outside code is copied into this repository: `setup` clones it
into `impls/` (ignored by git) and never modifies it.

## Use

Python 3.13 or later (the aeoess implementation requires it) and `cryptography`. A local virtual environment is enough:

```
python3 -m venv .venv && .venv/bin/pip install cryptography==50.0.1
.venv/bin/python settle_core_fuzz.py setup       # the only network step: clone the two outside repositories at their pins
.venv/bin/python settle_core_fuzz.py verify      # offline: commit, tree and sha256 of every pinned file
.venv/bin/python settle_core_fuzz.py selftest    # proves the oracle can fail; prints SELFTEST_OK
.venv/bin/python settle_core_fuzz.py run --count 3000 --seed 1
.venv/bin/python settle_core_fuzz.py run --minutes 20 --seed 2 --max-findings 30
.venv/bin/python settle_core_fuzz.py gen --seed 1 --index 17 --out /tmp/case   # rebuild one input
```

After `setup` everything runs offline. `run` first replays the 128 public vectors unchanged (`--no-replay` skips it),
then generated inputs. Each implementation runs in its own worker process (`python -I -B`), so a crash or a hang
cannot take the harness down; the timeout is 20 seconds per input (`--timeout`).

Exit codes: 0 no finding, 2 disagreement, 3 crash, 4 timeout. By default the first finding stops the run.
`--max-findings N` keeps going, saves up to three examples of each kind of finding and stops after N saved findings;
the exit code is still non-zero.

## Inputs

Inputs are deterministic in `(seed, index)`. About 40 percent are built fresh with the helpers of
`settle-core-v0/gen_vectors.py` (`seedkey`, `Chain`, `synth_contract`, `ex`, `revocation`, approvals, batch legs,
the parent narrowing axes); the rest start from one of the 128 public vectors. Then:

- body mutations (signed content): performed actions, approvals (height, nonce, single use, action, by, binding,
  extra keys, duplicates), delegations, extra keys, contract_ref fields, non-integer and unsafe numbers (0.5, NaN,
  Infinity, 2^53, -0.0, true), inserted revocations, revoked_by, the grant (expiry, conditional, actions, finality,
  revocation and ack window, witnesses, approval policy, ordering, max_hops, delegation, limits), the contract
  (bond, lower bound, contract_id and nonce lengths, parties, extra keys, requirements), and the parent's grant
  (narrowing and widening);
- repair, for inputs on the synthetic keys and in about 60 percent of cases: the contract and parent are re-signed,
  records are rebound to the new contract_sha256 and re-signed with the fixed test keys, and re-anchored on a fresh
  synthetic chain, so the input gets past the signature and anchor doors;
- unsigned mutations: anchor heights and types, swapped, removed or extended anchors, block hashes of the wrong
  length or case, proof operations, dropped, duplicated, reordered and junk events, signature entries (truncated,
  S + L, roles, padding, non-canonical base64), the header view (truncated, checkpoint removed, duplicated,
  swapped, edited, wrong types), contract and parent signatures, nenrin walks;
- byte level mutations of one file in about 12 percent of inputs: non-strict number tokens (`1.0`, `1e0`, `01`,
  `-0`, `1E400`, `NaN`, `nan`, `+1`, 4301 digits, 2^53 + 1), duplicate keys, a BOM, trailing bytes, invalid UTF-8,
  lone surrogates, escaped keys, deep nesting.

Any path containing `blind` is refused, for reading, seeding and writing alike: held-out sets are never used.
Generated inputs are written under `work/` and are not committed.

## Oracle

Every implementation's output is reduced to `{contract_sha256, verdict, status, bond_outcome, deviation_codes,
underspecified_reasons, event_set, dispositions}`. `deviation_codes` and `underspecified_reasons` are compared as sets
(section 9.1); everything else exactly, as canonical JSON. A reader error (section 2.2) is "no settlement", and a
settlement against no settlement is a disagreement. An input whose contract carries a key that section 1 puts out of
scope is run (a crash or a hang still stops) but not compared. An implementation that answers `UNASSESSED` for a
field is counted and not compared.

A finding is written to `findings/<input sha256>/`: `input/` (the files as run), `raw/<implementation>.json` (each
raw result), `diff.json` (each differing field, the section of SETTLE_CORE_v0.md that defines it, and every
implementation's value) and `meta.json` (seed, index, origin and the list of mutations). The input sha256 is the
sha256 over the sorted lines `<sha256 of file> <relative path>`.

`selftest` checks that the oracle fails when it should: a shim that flips `verdict` from `within_grant` to
`deviation` must be caught on the first input where the reference says `within_grant`; a shim that raises and one
that hangs must stop the run on the first input; the finding folder must carry the input's sha256; sets must compare
as sets; the reference adapter must reproduce `expected.json` on all 128 public vectors; inputs must be deterministic;
paths containing `blind` must be refused.
