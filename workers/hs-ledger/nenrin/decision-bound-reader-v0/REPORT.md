# decision-bound-reader-v0: a blind second reader for giskard09's decision-bound-output-v1

For the atlas cell "Policy decision point x effect" (probityai/agent-evidence-atlas#76), giskard09 bound a file-write
output to its covering decision (`decision-bound-output-v1`, github.com/giskard09/execution-join-ref-remora-bridge at
`301b1dc9b7bffdde1a52ef5ba46da9e48214de90`) and accepted our offer of a blind reader: one that writes its check
from the mechanism text and the records only, without his verifier or any expected answer. This directory is that
reader.

## How it was written

- Fence: three files copied from the pinned commit, nothing else readable, no network (`FENCE_SHA256SUMS`):
  `decision-bound-output-v1/decision_bound.py` (the mechanism and its declared limits, read as the contract),
  `decision-bound-output-v1/vectors_decision_bound_real_run.json` (the real AR-00 record) and `jcs.py` (read only to
  learn which canonical form is meant). The author's `verify_decision_bound.py`, the generators and the synthetic
  vectors were not in the fence.
- A separate agent session wrote `blind/reader.py` from the fence: its own canonical JSON and hashing, Python
  standard library only, without importing or copying `decision_bound.py` or `jcs.py`. Its guesses are in
  `blind/GAPS.md`, what its verdict covers in `blind/NOTES.md`.
- `blind/RAW.txt` and `blind/out.json` are its run on the real record. That raw output was posted on #76 before the
  author's verifier was opened.

## Result on the real record (blind)

`AR-00-REAL BOUND`, 6 checks equal, 0 different. `decision_id`, `decision_bound_output_hash` and
`legacy_output_hash` recompute to the stated values; three `source` fields also agree but are not in the mechanism
and do not feed the verdict.

The record reproduces only under one reading of three places the text leaves open (`blind/GAPS.md` 1, 3, 8): the
preimage is hashed with its fifth key `canonicalization_profile_id`, inside the bound preimage `content_sha256` is
bare hex and `decision_id` carries `sha256:`, and `version` is the code constant `decision-bound-output-v1`, not the
file's `profile` string. Each other reading gives FAIL.

## Comparison with the author's verifier (after the blind post)

1. `verify_decision_bound.py vectors_decision_bound_real_run.json` stops with `KeyError: 'claimed_decision_id'`: the
   real record names the field `decision_id`, the synthetic vectors `claimed_decision_id`. With only the two field
   names mapped (`decision_id` to `claimed_decision_id`, `decision_bound_output_hash` to `recorded_output_hash`), its
   `verify_case` gives `ORDERING_ESTABLISHED` for AR-00-REAL, the same as BOUND; given the legacy hash instead, it
   gives `ORDERING_UNVERIFIABLE`.
2. The author's verifier refuses a correctly bound output whose decision outcome is not `permit`
   (`UNAUTHORIZED_BINDING`). `decision_bound.py` names `outcome` only as a hashed field, so the blind reader has no
   such rule and would call a deny decision BOUND. The rule lives in the verifier, not in the mechanism text.

## v1: two labelled changes, made after the comparison

`v1/reader_v1.py` is `blind/reader.py` plus V1-A (outcome not `permit` gives `BOUND_NOT_PERMIT`) and V1-B (the
synthetic field names are read as aliases). It is no longer blind. On the real record it still gives BOUND; on the
author's five synthetic vectors (`vectors_decision_bound.json` at the same commit, sha256
`e0aab8ca436ea19f478015a7e7f06643bda1662888ea47aa45c5d106bbe6470c`) it gives the author's code on all five:

| Vector | Author's code | reader_v1 |
|---|---|---|
| DECISION-BOUND-OK | ORDERING_ESTABLISHED | BOUND |
| DECISION-BOUND-LEGACY | ORDERING_UNVERIFIABLE | UNBOUND_LEGACY_ONLY |
| DECISION-BOUND-FORGED-CITATION | FORGED_DECISION_CITATION | FAIL_DECISION_ID |
| DECISION-BOUND-SUBSTITUTED | BINDING_MISMATCH | FAIL_BINDING |
| DECISION-BOUND-DENIED | UNAUTHORIZED_BINDING | BOUND_NOT_PERMIT |

`v1/RAW_v1.txt` holds both runs.

## What BOUND does and does not establish

It shows that the stated output hash depends on this decision's content. In the mechanism's own words it does not
show wall-clock order, single use of a decision_id, or that the decision and the output were not produced together
afterwards, and it needs the decision record from a separate channel. In this record the decision preimage comes from
the same file, the written bytes are not present (`content_sha256` is taken as given), and the record's own note calls
the bound hash an overlay computed later from retained values.

## Run it

    git clone https://github.com/giskard09/execution-join-ref-remora-bridge && cd execution-join-ref-remora-bridge
    git checkout 301b1dc9b7bffdde1a52ef5ba46da9e48214de90
    python3 -I -B <this dir>/blind/reader.py decision-bound-output-v1/vectors_decision_bound_real_run.json out.json
    python3 -I -B <this dir>/v1/reader_v1.py decision-bound-output-v1/vectors_decision_bound.json out_v1.json

Python 3.11.15 here. No file from the author's repository is copied into this directory; `FENCE_SHA256SUMS` pins the
three fence files by hash.

## Re-runs after the author's fixes

Each re-run follows the same order: the raw output was posted on #76 before the author's verifier or its diff was
opened, and the comparison came after. The blind copies of the vectors drop `expected_code` and `note` from each case
(`tools/make_blind_copy.py` reproduces every copy's sha256 in `BLIND_COPY_SHA256SUMS`). No file from the author's
repository is copied here; each `FENCE_SHA256SUMS` pins the fence by hash.

### `rerun-7125f55d/` (author's commit `7125f55d117961fde33bb50a8b7ef7683c4240f9`)

- `A/`: the first blind reader (`blind/reader.py`, unchanged) on the new records. It fails every case only because the
  records renamed `decision_id` and `decision_bound_output_hash` to `claimed_decision_id` and
  `recorded_output_hash`; its recomputed values still equal the ones the records state.
- `B/`: a new blind reader written in a separate session from the four fence files only (`B/reader.py`, its guesses
  in `B/GAPS.md`). 7 of 7 cases fall in the same groups as the author's `expected_code`, under its own names. The one
  gap left that could flip a verdict: the text did not say to reject a `claimed_decision_id` that does not recompute
  before the output hash is checked (FORGED-CITATION). The `input` field of `B/out_*.json` was rewritten from the
  local fence path to `../fence/...` after the run; nothing else was changed.

### `rerun-4cbf5c8/` (author's commit `4cbf5c85a22659ebd13bb5aa2f4fb7e924b3c207`)

- `B/`: reader B from `rerun-7125f55d/B/reader.py`, unchanged. Same groups on all 8 cases, including the new
  KNOWN-LIMITATION-COMMITMENT-NOT-WRITE, which it accepts.
- `C/`: another new blind reader, written in a separate session from the four fence files only, told to use the
  text's result names where the text gives them and to follow a check order only if the text prescribes one. It found
  the order in the text and gives the author's `expected_code` on all 8 cases, name for name. Its two remaining
  guesses are in `C/GAPS.md` (A.2 and A.3).
- `extra/`: three cases built by `tools/make_extra_cases.py` that swap only `recorded_output_hash`, to test those two
  guesses. The author's `verify_case()`, reader C and reader B all agree on all three (`extra/RAW_extra.txt`). The text
  still allows the other reading on those three; a sentence and three vectors would pin it.

Run a re-run:

    git clone https://github.com/giskard09/execution-join-ref-remora-bridge && cd execution-join-ref-remora-bridge
    git checkout 4cbf5c85a22659ebd13bb5aa2f4fb7e924b3c207
    python3 -I -B <this dir>/tools/make_blind_copy.py decision-bound-output-v1/vectors_decision_bound.json blind.json
    python3 -I -B <this dir>/rerun-4cbf5c8/C/reader.py blind.json out.json
