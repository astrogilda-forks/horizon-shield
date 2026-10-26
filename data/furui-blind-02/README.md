# FURUI blind-02: the salt and the selection, published at opening

- salt.hex: the 32 byte salt. Its SHA-256 was anchored before the draw in JIDEC ledger entry 158 (the plan).
- manifest.json: the strata, the drawn keys and the root. The root was anchored in entry 164 before anyone read the drawn set; the pin is entry 165; the score digests are in the entry that cites this commit.

Anyone can recompute the seed, the selection and the root from these two files, the block hash at height 973171 and the public datasets: python3 draw_blind02.py verify <salt.hex> <block hash> <MEASURE split dir> manifest.json <blind02.jsonl>.
The row texts are the public datasets' own; the per-row flags and the raw model answers are not published (their SHA-256 are in the score record).
