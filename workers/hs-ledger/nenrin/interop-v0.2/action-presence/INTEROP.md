# interop-v0.2/action-presence: the degenerate-action rule, with vectors

`VERIFIER.md` section 5, *Missing fields inside a record*, says an action that is **missing, `null`,
`false`, `0` or `""` fails E1 on its own**. `interop-v0.2/edge` freezes a vector for most of what
section 5 pins, but none for this sentence — so a reader that implements only the equality half of it
(`null` against `null`, `0` against `0`) passes both corpora while disagreeing with the reference on the
value shapes the sentence names. This corpus gives each of the five shapes a fixture, plus the boundary
where the value is an empty object and is therefore *not* degenerate.

The shapes were found by the nightly differential (the adversary in `conformance-v0` signs a fresh
batch with new keys every run and every batch-capable verifier reads it); `gaction=null` and
`gaction missing both` were the first bundles on which two implementations disagreed, and the rule was
settled in `VERIFIER.md` at `ddc9c3f` (both sides of a
degenerate comparison agreeing is not agreement; `action_diverged` is the check's reason, the refusal
that reaches the signature is `execution_invalid`, and `{}` is compared like any other action).

## Run it

```sh
cd workers/hs-ledger/nenrin/interop-v0.2/action-presence
python3 python/run_action_presence.py
```

Requires Python 3.10+ and `cryptography` (Ed25519 through OpenSSL, as section 5 pins). The runner exits
non-zero on any verdict-signature mismatch and prints the reasons. `python/make_action_presence_fixtures.py .`
regenerates the fixtures and `expected.json` with fresh keys.

## The vectors, one value shape each

| fixture | value on both sides | expected |
|---|---|---|
| `action_missing` | the key is absent on both sides | refused `execution_invalid` |
| `action_null` | `null` | refused `execution_invalid` |
| `action_zero` | `0` | refused `execution_invalid` |
| `action_empty_string` | `""` | refused `execution_invalid` |
| `action_false` | `false` | refused `execution_invalid` |
| `action_empty_object_accepted` | `{}` | **accepted** — not in the section's list, so it is compared like any other action |
| `intent_action_null` | the intent's `proposed_action` and the receipt's `executed_action` are `null` while the grant's action is an action | refused `execution_invalid` + `preflight_invalid`, findings include `declared_executed_divergence` |
| `intent_action_zero` | the same with `0` | the same |
| `intent_action_missing` | the same with the key absent on both sides | the same |

Every fixture is freshly signed with keys generated for it and is valid except for the value under
test, so only that rule can refuse it. The three intent fixtures exist because the same rule is reached
twice more: the preflight action check (step 3, `preflight_invalid`) and the declared-versus-executed
comparison (a finding, not a refusal). `action_missing` is the shape the sentence names first, and the
one equality cannot see at all: two missing keys compare equal.

## Provenance and discriminating power

- The expectations are the verdict signatures of `python/verify_edge.py` here — the independent Python
  implementation written from the normative text, sha256 `0f851a46b5999ec75580f99b02864c4d7264ab98c61f90f348fce1fc14d74ddc`
  (`kuangmi-bit/nenrin-independent-verifiers` @ `1c33429`). The reference implementation was not read.
- The project's reference (`nenrin-verify` 0.4.9, `sdk-python/`) reproduces all nine, checked by handing
  it the same batch through `tools/tsunagi/adapters/py_module_batch.py --nenrin-verify`.
- **They are discriminating**: the copy merged with `interop-v0.2/edge` (sha256
  `98792ec77c1b12195b0e01f2f91940bd2ef246c9b96982d11fe0ace7118b4f7c`, the reader before the section 5
  decision) accepts the five action fixtures (`null`, `0`, `""`, `false`, and missing) and drops
  `declared_executed_divergence` on the three intent fixtures — it agrees on 1 of 9. A corpus that only
  restated the rule would pass both builds.
- **Licence**: this corpus is contributed under the repository's MIT licence. `python/verify_edge.py` is
  byte-identical to `verifiers/nenrin_verify_v02_edge.py` in `kuangmi-bit/nenrin-independent-verifiers`
  @ `1c33429`, also MIT.

## What this does not establish

Not that the verdicts are the only defensible ones (`{}` in particular is a boundary the text draws by
omission, which is why it is a fixture and not a sentence here), not that `interop-v0.2/edge`'s 36
vectors move, and nothing about any implementation's behaviour beyond these nine inputs.
