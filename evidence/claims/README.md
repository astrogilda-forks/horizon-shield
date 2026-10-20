# Claims index: how to check a claim back to Bitcoin

`index.json` lists the claim objects HORIZON SHIELD publishes for its price pages. Each claim pins
`source.dataset_sha256`, the SHA-256 of the dataset bytes it was computed from, and names the ledger entry
that anchors those bytes (`anchor`).

The chain is one hop: the ledger entry's own record carries `dataset_sha256`. The index only points at the
entry, so a verifier does not need to trust the index.

For souba-db 2.3.0 (ledger entry 114, Bitcoin block 972015):

1. Fetch the dataset and hash it:

       curl -s https://shield.the-horizons-innovation.com/data/souba-db.json | shasum -a 256

   The result is `7b16600e50ed73b844ff5b2718f04a6dd4d9ace0367982fb8d139db509d023fd`.
2. Fetch the entry's record bytes, find the same value after `dataset_sha256` in them, and hash them:

       curl -s 'https://ledger.horizonshield.dev/ledger/114?format=raw' > claim_114.txt
       grep dataset_sha256 claim_114.txt
       shasum -a 256 claim_114.txt

   The hash is the entry's `claim_sha256`, `6904baea00067a206d04f7344d50717fe0e12aa2e45905951596b7f172b6e786`.
3. Check that `claim_sha256` is in Bitcoin:

       curl -s https://ledger.horizonshield.dev/ledger/114/ots > claim_114.txt.ots
       ots info claim_114.txt.ots       # no node needed
       ots verify claim_114.txt.ots     # with a Bitcoin node

4. Recompute a claim from the bytes: `regen_claims.py` rebuilds each claim object from the dataset and
   refuses unless it is given the sha256 the anchor carries. Each claim's `object_sha256` must match.

What this establishes: the claim was computed from bytes that existed, unchanged, no later than block 972015.
What it does not: that the prices in the dataset are right. That rests on the public sources named per row
in `souba-db.basis.json`, which entry 114 also binds (`basis_sha256`).

Raised by kuangmi-bit on issue #52 (2026-10-20), who verified the chain end to end.
