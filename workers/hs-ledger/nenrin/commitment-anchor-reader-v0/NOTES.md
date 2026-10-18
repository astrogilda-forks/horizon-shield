# commitment-anchor-reader-v0

A blind second reader for babyblueviper1's draft OBS-06 text (`commitment_anchor`, the latest-bound counterpart to `issuance_time_basis`), and three control vectors for it. Discussion: probityai/agent-evidence#32.

## blind/

`reader.py` was written in a separate session from three files only: the draft README with its table of expected results cut out, the vectors with every `expect` and `note` removed, and `38.ots` (`BLIND_COPY_SHA256SUMS`). It uses the Python standard library only, used no network, and never saw `check.py`. Upstream files at the pinned commit: `FENCE_SHA256SUMS`.

    python3 -I -B blind/reader.py <blind copy of vectors.json>

`RAW.txt` is its output exactly as it ran, posted on #32 before any comparison. `GAPS.md` lists every place the text left a choice (17 notes), and for each one whether the other reading would flip a verdict on these vectors.

Comparison with the draft's `check.py` (done after the raw output was posted): `precedence_established` agrees on 11 of 11. The verdicts group the same way on 10 of 11; the result names are the reader's own, because the text names none. The eleventh is the digest-mismatch control. There, `check.py` returns a separate result, and the reader reports "no anchor" followed by the two MUSTs.

## backdated/

Three vectors, each the draft's `anchor-before-outcome` with only the anchor time, the rule and the outcome changed (outcome_time 1782658282, asserts_precedence true):

- `control-backdated-header-moves-the-ceiling`: anchor_time 1782651081, synthetic. This is the earliest time Bitcoin consensus lets the miner of block 955810 write: the median time of blocks 955799 to 955809 is 1782651080, plus one second. The real header says 1782654639. Under `header_time_plus_tolerance` (7200 s) precedence is established.
- `control-honest-header-same-outcome`: the real header time, the same outcome. Not established.
- `later-median-independent-of-the-header-field`: the same outcome under `later_median` (ceiling 1782657732, the median time of blocks 955811 to 955821). Established, whatever the anchor block's own time field says.

So under `header_time_plus_tolerance` the verdict turns on a field the miner chose, within consensus, and it moves by 3558 s. The draft's own `check.py` gives 14 of 14 with the three added (`CHECK_14.txt`; combined file sha256 in `COMBINED_SHA256`). The header times were read from mempool.space and blockstream.info, which agree; block 955810's header hashes to the hash the vectors name, and its merkle root is the result of the Bitcoin leg of `38.ots`.
