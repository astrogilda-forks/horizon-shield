# FURUI blind-02: the salt, the selection and the draw tool, published at opening

- salt.hex: the 32 byte salt. Its SHA-256 was anchored before the draw in JIDEC ledger entry 158 (the plan).
- manifest.json: the strata, the drawn keys and the root. The root was anchored in entry 164 before anyone read the drawn set; the pin is entry 165; the score digests are in entry 167, which names commit e8ca10f, where these two files were first published.
- draw_blind02.py: the draw tool, byte for byte the one named in the plan (entry 158, sha256 98ee499d61daaea623b9c5edcc244e00e15625cd179c46db2684aa9f551d7db6). It uses the Python standard library only and holds no FURUI rule, classifier or prompt.
- pubprep.py: the split tool, byte for byte the one named in the plans (entries 158 and 177, sha256 4f51b7ba488373573c2bb155503b59264abc252783551f16ce21df0682d65ed4). It reads the dataset files pinned in PINS.txt and writes the BUILD and MEASURE halves. It needs pyarrow, and it reads from and writes to the two paths fixed in its first lines (RAW and OUT); put the files there or change those two lines. It holds no FURUI rule, classifier or prompt.
- PINS.txt: the dataset pins named in the plans (sha256 feab498d394e0c303faa4100036bdf26e265951be8540f3c4a51b654689f46ec): each dataset's Hugging Face revision, licence, file and file SHA-256.
- RESULT.md: the result.

Anyone can recompute the seed, the selection and the root. Fetch the files listed in PINS.txt at those revisions, check their SHA-256, run pubprep.py, and check that the four MEASURE files have the SHA-256 named in the plan record. Then, with the block hash at height 973171 (00000000000000000001a698f6259782125a20740a53b9fa4b36b763154decd8):

    python3 -I draw_blind02.py verify salt.hex 00000000000000000001a698f6259782125a20740a53b9fa4b36b763154decd8 <dir of the four MEASURE files> manifest.json <blind02.jsonl>

blind02.jsonl holds the drawn rows: the manifest's keys, taken from those four files.
The row texts are the public datasets' own; the per-row flags and the raw model answers are not published (their SHA-256 are in the score record).
