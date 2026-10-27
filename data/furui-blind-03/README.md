# FURUI blind-03: the draw tool, published before the draw

- draw_blind03.py: the draw tool, byte for byte the one named in the plan (JIDEC ledger entry 177, sha256 ac2bda3f71e2ad1dd0345e76ce81e9df2e5f5d3a45ca29c79f93b2c367b578d3). It uses the Python standard library only and holds no FURUI rule, classifier or prompt.
- The split tool and the dataset pins named in the plan are in ../furui-blind-02/ (pubprep.py and PINS.txt). The population is the four MEASURE files with the rows drawn into blind-02 removed (../furui-blind-02/manifest.json); the plan names the four files that remain by their SHA-256.

The seed is sha256("furui-blind-03|" + salt + "|" + the hash of the block at the plan's height H). The salt stays sealed until opening; its SHA-256 is in the plan. The salt and the selection are published here at opening.
