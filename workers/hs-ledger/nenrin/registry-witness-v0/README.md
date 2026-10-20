# nenrin-registry-witness-v0

An independent witness for the [TRACE registry](https://github.com/agentrust-io/trace-registry) checkpoint chain, operated by HORIZON SHIELD (The HORIZONs Co., Ltd.), which also holds a registered mirror of that registry.

For each checkpoint it has not seen, the witness verifies the whole chain, signs the checkpoint into an append-only log of its own, and returns a COSE receipt. The receipt uses the stage-1 profile that the registry's own verifier reads, so a reader checks it with the registry's command and this witness's public key:

```
pip install "trace-verify[witness]"
trace-verify receipt --checkpoint state/checkpoints/<entry_hash>.json \
  --response state/receipts/<entry_hash>.post.json \
  --expected-log-id trace-registry/v1 \
  --registry-key bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90 \
  --witness-key <the key in WITNESS_KEY.json>
```

## What a run does

`python3 witness.py run --registry <clone> --state state --key <pem> --published-head <sha256> --source-commit <sha>`

`--published-head` is the SHA-256 of the last line of the published `state/tree_heads.ndjson` (the copy on GitHub). The first run of a new witness log takes `--init` instead. An empty state without `--init`, or a state whose last tree head is not the published one, is refused.

1. It reads every `registry/YYYY/MM/DD.ndjson` in path order.
2. A malformed line, a duplicate JSON key, or an `.ndjson` file anywhere else under `registry/` is a refusal, not something to skip. It runs both of trace-verify's chain checks over the files. First, every checkpoint extends the one before it by a genuine MMR consistency proof and carries a valid registry signature. Second, rebuilding the MMR from the raw entries reproduces every checkpoint. It also requires the key the checkpoints name to be the key pinned here for `trace-registry/v1`. If anything fails, nothing is signed and the run exits 3.
3. It requires continuity with everything it published before. Every checkpoint already in the witness log must still be in the registry as the same bytes on the same line, and checkpoint timestamps may not go backwards. A registry that dropped, replaced or forked a witnessed checkpoint is refused, so the witness never vouches for two incompatible histories of one log.
4. For each checkpoint not already in the witness log, it appends the entry hash to the log. The entry hash is SHA-256 of the nine-field signing-body digest, the same value the registry's verifier recomputes.
5. It mints the receipt with these protected headers:
   - `{1: -8, 395: 1}`.
   - The grade `mmr-verified` under `-65537`.
   - While the checkpoint is less than 30 days old (with an hour to spare), a CWT `iat` under `15`. trace-verify refuses an `iat` more than 30 days after the checkpoint.
6. It checks the minted receipt with `trace_verify._witness.verify` before writing it.
7. It signs a tree head for the witness log, with an RFC 9162 consistency proof from the previous tree head.

Everything new is written into a staging copy of the state, verified there in full, and published by one directory swap. A crash leaves the previous state; the next run discards the staging copy or finishes the swap. Each run holds an OS lock on `state.lock` for its whole length. A refusal writes nothing and exits 3. `--now` and `--enroll` exist only for the self test.

`python3 witness.py verify --registry <clone> --state state --witness-key <hex>` rechecks everything offline:
- every receipt, with the registry's verifier;
- every tree head signature;
- every consistency proof;
- that the log's leaves are the stored receipts.

## Promises

- **Receipts are final.** A checkpoint already witnessed is never witnessed again, and a stored receipt is never overwritten with different bytes. This is the property the registry's LIMITATIONS.md asks of a witness.
- **The grade means what was checked.** `mmr-verified` here means the witness verified the registry's consistency proofs and rebuilt the MMR from the raw entries before signing. It does not mean anything about the claims the registry anchors.
- **`iat` is this witness's clock when the run started,** inside the signature. On its own it is still this witness's assertion. The tree heads are anchored to Bitcoin through the JIDEC ledger, which gives each receipt an upper bound on time from a clock this witness does not control.

## Does not establish

- That the key holder could not sign a second history. No code can stop a key holder. What makes it detectable is publication: every tree head is published and its digest is anchored, so two heads under this key that no consistency proof joins are proof of misbehaviour.

- That any claim anchored in the registry is true.
- That every observer saw the same registry. That needs more than one witness and someone comparing them. The registry has one other witness, for checkpoint 1.
- The June 2026 entry, which predates checkpointing and is outside every checkpoint, as the registry itself states.

## Files

| file | what it is |
|---|---|
| `witness.py` | the witness (run, verify) |
| `witness_test.py` | self test over the real checkpoints in `fixture/`, using the registry's own `trace-verify receipt` |
| `fixture/registry/` | the registry's files at the commit in `fixture/SOURCE_COMMIT`, unmodified (CC BY 4.0, see `fixture/NOTICE`) |
| `fixture/forks/` | a log, a genuine extension of it and a fork of it, made with the registry's own aggregator under a throwaway key (`make_fork_fixture.py`) |
| `requirements.txt` | exact versions with hashes: `pip install --require-hashes -r requirements.txt` |
| `state/` | the witness log, receipts, checkpoints and signed tree heads (public) |
| `WITNESS_KEY.json` | the witness public key |

The private key never enters this repository.
