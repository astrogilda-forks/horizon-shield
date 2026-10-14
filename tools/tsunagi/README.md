# TSUNAGI: put your verifier on the board

TSUNAGI (繋, "to connect") runs every registered implementation every night, each cloned from its author's own
repository at the default branch head, against the corpora in this repository. The result is
[`ops/tsunagi/BOARD.md`](../../ops/tsunagi/BOARD.md), with the whole run in `board.json` (sha256 inside),
streaks in `history.json` and a badge per implementation in `badges/`.

What a green cell establishes: that this code, at this commit, reproduced this corpus on this run. What it does not:
that the corpus is right, that the code is correct elsewhere, or anything about who wrote it. A green cell is not an
endorsement, and a red one is written down, never hidden.

## Three ways a cell is scored

- **Refereed by the board** (`"parse": "batch_referee"`, NENRIN corpora). The board writes the fixtures to one batch
  file, your command writes one verdict signature per fixture, and the board compares each with the frozen
  `expected.json` itself. Your own count is not read. This is the form to use for a new NENRIN verifier.
- **Refereed by the board, approvals** (`"parse": "batch_approval_referee"`, the a2a-approval-v2 vectors). The board
  writes `[{"name", "contract", "approval"}]` without the expected values, your command writes
  `{"<name>": {"result", "reason"}}`, and the board compares each answer exactly with this repository's pinned copy of
  the vectors (`workers/hs-ledger/nenrin/musubi-v0/fixtures/babyblueviper1_approver_v2/vectors.json`, sha256 pinned in
  `run_board.py`), not with the copy in your repository. Self-reported rows for the same corpus stay beside them.
- **Refereed by the board, crosswalks** (`"parse": "crosswalk_findings"`). For a tool that compares two checkers'
  reports rather than verifying a corpus itself. The command writes one comparison report to `@out`; the board reads it
  and compares every finding with an expectations file pinned in this repository
  (`tools/tsunagi/expected/<corpus>.json`, sha256 pinned in `run_board.py`). A case counts only when all of its findings
  match, and the tool's exit code is recorded but is not the result. The first is Poke-nushi's NENRIN and VATE S3
  crosswalk (VATE #84): per case, the NENRIN records it compares must be byte for byte the ones published in
  `workers/hs-ledger/nenrin/vate-s3-v0/records`, CW-01 to CW-11 must have their expected status, each NENRIN verifier
  (npm, PyPI) its expected verdict and refusals, and VATE its expected assessment and `record_linkage` with `retry_authorized: false`. The board records the sha256 of every report it scored. It has
  two rows, `"mode": "saved"` (the saved reports compared) and `"mode": "rerun"` (the VATE assessor and both NENRIN
  verifiers run again at the versions the crosswalk names), and the board shows which one each cell did.
- **Self-reported** (`count_line`, `all_pass`, `approval_lines`, `json_results`, `pytest`). The board reads the count
  your command prints. Kept for implementations that registered that way; the board says so in the "scored by" column.
- **Tonight's fresh bundles.** The adversary in `workers/hs-ledger/nenrin/conformance-v0` signs a new set of edge
  bundles with new keys on every run. Every implementation listed under `differential` reads the same batch, and the
  board lists each bundle on which any two of them disagree. There is no frozen answer; a disagreement is a finding
  about the spec, the reference or an implementation, and a person triages it.

## What refereeing does and does not stop

The board loads every corpus before any outside code runs, and after each run it checks that the corpora, the
generator and its own tools are byte for byte what they were; a run that changed them is restored and marked not a
pass. That stops a verifier from reporting a count it did not earn. It does not stop a verifier written to the
answers: `expected.json` is public. Tonight's fresh bundles are the check for that, since they are new every run and
have no published answer.

## The batch contract (any language)

    input  @in   a JSON array      [{"name": "<case>", "bundle": {...}}, ...]
    output @out  a JSON object     {"<case>": {"verdict": "accepted", "refusals": [...], "findings": [...]}, ...}
                                   or {"<case>": {"error": "..."}} for a case you could not evaluate

Codes are compared as sets, as `workers/hs-ledger/nenrin/provenance-v0/VERIFIER.md` section 4 defines the verdict
signature. A missing case, an extra case, an error or any difference counts against you. Exit 0.

## Check yourself first, offline

    pip install nenrin-verify
    nenrin-tsunagi run nenrin-interop-v0.2-edge -- "python3 my_verifier.py {in} {out}"
    nenrin-tsunagi row nenrin-interop-v0.2-edge -- "python3 my_verifier.py {in} {out}"

`run` is the board's referee with the corpora inside the package, so the number you see is the number the board will
show. `row` prints the entry to paste into `implementations.json`. If your verifier is a Python module with
`verify(bundle)`, the board's adapter `tools/tsunagi/adapters/py_module_batch.py <module> @in @out` calls it as is.

With a clone of this repository you can also run the board itself against your working copy, before you push:

    python3 tools/tsunagi/run_board.py --out /tmp/board --only <your-id> --local <your-id>=/path/to/your/checkout

## Join

Open one pull request that adds your row to `implementations.json`: your public `https` repository, its licence,
the command, the corpus. The pull request runs your row at once (workflow `tsunagi-preview`, read-only token, no
secrets) and shows the result in the job summary. After merge your row is on the next night's board, at your own
commit, in your own repository. To list yourself under tonight's fresh bundles, add an entry under `differential`.

Your badge, for your own README:

    ![TSUNAGI](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/ogasurfproject-jpg/horizon-shield/main/ops/tsunagi/badges/<your-id>.json)

To change your command, rename your row or leave the board, open an issue or a pull request; it is done the same
day. The board runs your default branch head, unless your row sets `"pin"` to a full 40-hex commit sha agreed with you: then it runs exactly that commit, a pin that cannot be fetched is reported as not run (never replaced by the head), and the commit cell is marked pinned. Moving a pin is a separate change you approve. Each run row may also set `"mode"`: `rerun` (the default, the board runs your checker) or `saved` (the board compares reports you saved); board.json records which one each cell did. The board never runs outside code with a write token or a secret.
