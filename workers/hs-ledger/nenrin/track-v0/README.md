# nenrin-track-v0: is a door's signed history one?

A door that admits or refuses an agent's actions signs one admission per decision (`a2a-admission-v0`). SHIKEN's door
chains them: each `admission_id` is `<name>:seq=<n>:prev=<sha256 of the previous admission's signed bytes>`. The ledger
stores each public admission and anchors it in a daily batch; a [mirror](../mirror-v0) copies the batches and the
bytes they name to a place the operator does not control.

This tool reads such a copy, offline, under keys you pin yourself, and answers what a copy alone can answer:

| finding | what it means |
|---|---|
| `fork` | two different admissions, both signed by the pinned key, with the same seq: the door signed two histories |
| `broken_link` | an admission whose `prev` is not the one admission held at the seq before it (seq 1 must name 64 zeros) |
| `anchored_late` | first anchored (the Bitcoin block of the batch entry that names it) more than 576 blocks, about four days, after the chain height it says it was decided at: a record that surfaced after the fact |
| `gap` | a seq below the highest one held that this copy does not hold |
| `unchained` | admissions signed by the pinned key whose id carries no seq and prev (SEKI's door uses a UUID): counted and judged for `anchored_late` only |

The first three are findings (exit 1). A gap, a record that cannot be read as signed, or a name with no bytes makes the
verdict `incomplete` (exit 0): the copy says less, not that the door lied.

```sh
python3 ../mirror-v0/mirror.py pull --dir ./nenrin-mirror
python3 track.py --dir ./nenrin-mirror \
  --pin n4/0R5SQLGINGBwrA7agyMOd2819OcYTvao1Un0lwQ4=@https://shield.the-horizons-innovation.com/keys/shiken-door.json \
  --pin wbWKQTE9F1A2ixJzzhqfpITrU7GhDr9G2ri5YYGvCTE=@https://shield.the-horizons-innovation.com/keys/seki-door.json
```

The same from PyPI (`pip install nenrin-verify`, 0.5.7 or later: `nenrin-track`) and from Go
(`go install github.com/ogasurfproject-jpg/horizon-shield/workers/hs-ledger/nenrin/sdk-go/cmd/nenrin-track-go@latest`).
All three print the same report, byte for byte (`--json`, canonical JSON with its own `report_sha256`).

## Why pins and not fetched keys

A key fetched from the operator's site would make the check depend on the operator. Pin each key once, from the site
and from `keys/` in this repository, and compare them. A chain is one `key_url` and one `admission_id` name, so two
doors on one domain (SHIKEN's and SEKI's) are two chains.

## Run it where we are not

[`github-action/nenrin-track.yml`](github-action/nenrin-track.yml) runs after every run of the mirror workflow in your
own repository, installs `nenrin-verify` at a pinned version, reads your copy and fails the run when a finding appears.
Two holders of the same copy share `report_sha256`.

## How the two implementations are held together

| check | result |
|---|---|
| `vectors/` (10 small mirrors: one history, fork, broken link, gap, late anchor, forged signature, unpinned and unreadable records, seq 1, two doors on one domain, unchained ids), rebuilt byte for byte by `make_vectors.py` | Python and Go give `expected.json` exactly |
| `parity.py`: the vectors and 1,500 mutations of them (a byte flipped, a value replaced by a float, an exponent, a huge integer, a lone surrogate, a key outside ASCII, a moved Bitcoin block, a removed or renamed file) | 0 differences between `track.py` and `nenrin-track-go` |
| a real mirror (`ogasurfproject-jpg/nenrin-mirror-selftest`, branch `nenrin-mirror`, entries 1 to 127, 2026-10-20) | SEKI's 33 public admissions all verify under the pinned key and none was anchored late; both implementations print report `17642abb…` |

Both read numbers the way `JSON.parse` does, and refuse to read a record where two canonical forms could differ (a key
outside printable ASCII, a lone surrogate, a number that is not an integer within 2^53).

## What it does not establish

- That any decision was right. `admission_verify_v0` and the settlement recompute that.
- That the copy holds every admission the door made. A gap is named; an admission nobody published is not seen.
- That a ledger entry's `bitcoin_block` is true. Verify the entry's `.ots` against Bitcoin headers.
- That the door and its operator are independent of each other or of this repository. Same author, two languages:
  this is not an independent implementation. An independent one is welcome.
