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
