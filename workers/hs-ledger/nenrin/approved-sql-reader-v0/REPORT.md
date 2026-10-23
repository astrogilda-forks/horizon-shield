# approved-sql-reader-v0: a second reader for oel-approved-sql-illustration/v1

A reader for the approved-SQL case of the Open Evidence Lab (probityai/agent-evidence-atlas#52), written from the
case's input contract only, then compared with the author's reader. It answers the case's invitation to "bring
another reader". It is not part of NENRIN and changes nothing in this repository's verifiers.

## How it was written

- Inputs given to the implementer: `docs/INPUT-CONTRACT.md` and the 16 fixture inputs of
  `examples/approved-sql/` at agent-evidence-atlas `042d9ba4936db003c5a6941a49f84716ea0e777b`, nothing else.
  Not given: the author's reader (`sql_illustration/`), its tests, `fixtures/manifest.json` (the expected answers),
  `qualification/`, or network access. The implementer was a separate AI agent working in a fenced folder;
  the comparison was made afterwards by the operator.
- Python 3 standard library only. `reader.py` sha256 `fc87a6ece18c71d839f6e6b08cfb2d66b56e0dda47e2b5535d5e686bc0fa0b86`.
- `GAPS.md` is the implementer's own list of 25 places where the contract did not decide, each with the
  contract text and whether another reading changes a result or an exit code.

## Result against the author's manifest (16 fixtures)

| Compared | Agreement |
|---|---|
| Exit code (0 match, 1 other assessment, 2 invalid input) | 16 of 16 |
| `result` string, exactly | 4 of 16 (the two `recorded_commit_matches`, `no_match_in_declared_complete_scope`, `approval_not_granted`) |
| `later_state` string, exactly | 15 of 16 (`changed` here, `supplied_state_differs` there) |
| Partition of the fixtures into results | consistent: every pair of fixtures this reader separates, the author's reader separates too. The author splits two of this reader's groups further: the three outcome cases (`transaction_rolled_back`, `statement_failed`, `commit_not_established`) and `insufficient_audit_evidence` versus `application_record_missing`. |

The contract names two result values exactly (`recorded_commit_matches`, `no_match_in_declared_complete_scope`).
The author's reader uses eleven. The other result strings here are the implementer's, so the string mismatches
say that the vocabulary is not in the contract, not that either reader is wrong.

## The two gaps that could change an exit code

- G3 `approval.granted: false`: the contract's definition of `recorded_commit_matches` lists record agreement
  and outcome but not `granted`. A reader that follows that definition literally exits 0 on
  `approval-not-granted.json`. Both readers here exit 1.
- G7 `application: null`: "those supplied records agree" can be read as "whatever was supplied agrees". On that
  reading `application-record-missing.json` exits 0. Both readers here exit 1.

Suggested contract lines: the full list of result values with one line each, and two sentences saying that
`granted: false` and an absent application record each prevent `recorded_commit_matches`.

## Rerun

```
git clone https://github.com/probityai/agent-evidence-atlas && cd agent-evidence-atlas
git checkout 042d9ba4936db003c5a6941a49f84716ea0e777b && cd examples/approved-sql
for f in fixtures/*.json; do [ "$(basename $f)" = manifest.json ] || { python3 <path>/reader.py "$f" > /dev/null; e=$?; echo "$(basename $f) $e"; }; done
```

`results.json` holds this reader's result, later_state and exit for every fixture. The inputs it read
(sha256, at the pin above):

```
292ee4d68d470514d287cd0c3909c410c221277147a29a1e796ae9e5528ed3f5  docs/INPUT-CONTRACT.md
6c92b6f7d151889f84a823993af596f5076d9e5f44c13e26a4827d1a541cee37  fixtures/ambiguous-execution.json
da3260fa876a5ef88dbef58126641020de2e11827030b34ad076f5076ccbaab1  fixtures/application-record-missing.json
a995bcd7ca6e956a51419986e301f9cd4013e3527bf1e526beb5725a9892606b  fixtures/approval-not-granted.json
79a1c3eb9002f9899851961fd13deda8090da8d18365d3819b59040d2d9ed506  fixtures/approved-audit-incomplete.json
5cd9b94f7a72339d12bef109607434b13b2edc845786e6b4522040dc29e49888  fixtures/approved-no-match-declared-scope.json
527368d951fdc5d9c6bc42c526da7d204d92dea63a06d049a453121cdc4cd26a  fixtures/commit-unknown.json
5134ebfbe5581c0c4deadaddde17577da9c28f0feea1d55c6ad14efc0cd7ce89  fixtures/different-database.json
e1d96d3f07742de5f8923307bbf517b1e9b731a7d65ccca846c7860306d1d2ff  fixtures/different-parameters.json
74c87a05241d9abe99210223a05cbe492edcc68a8331ef8ed10a17afab2eb357  fixtures/different-principal.json
6fdf3a69ba1b78a0556ee3ac642dc9ed6373b917e0bfecfe89d12bf555c4afd9  fixtures/different-schema.json
6422a2144b77ae841a962dfb2ee3921db140f05a4bc5c474168a08349740223f  fixtures/different-sql.json
9fe21153ec212f1825452ecc931d51d9700f8bf55d777f85c7b8c026cee78d68  fixtures/matching-commit-later-change.json
6894fd1212b9e3bdf7af47213768edbaa21ddf60952ea0493059adf85ce999bd  fixtures/matching-commit.json
9897ff0c4976afccb6fb50aa7d7bdab03af03ae2e58355a73d59c703ab4ec556  fixtures/outcome-disagreement.json
0dfba3c606df2d85bbc55d19ce181be2563ae693e470ccb04c13cd7ad596aded  fixtures/rolled-back.json
8736af34200fab34a098df933a77755872862196e7f57f2455015c0f6d8b9dd8  fixtures/statement-failed.json
```

## Revision to the contract at agent-evidence c4780c28 (2026-10-24)

After this comparison the author's input contract
([`INPUT-CONTRACT.md` at c4780c28](https://github.com/probityai/agent-evidence/blob/c4780c28f6a6e5836a629cbc09fbe7473a4b68dc/site/examples/approved-sql/docs/INPUT-CONTRACT.md))
listed all eleven results, the order they are checked in, and the four `later_state` values. `reader.py` now
follows that text: the audit join first (lines 26 to 28, 44 to 46), then, with one matching record, the rows from
`approval_not_granted` down, first that applies (line 56). Each check names the contract line it follows.

This revision is not clean-room. It was made by the operator's AI agent, which had seen the manifest; it read no
other reader's code. The clean-room reader stays at `5037ecf8` and the comparison above is of that version.

| Compared over the 16 fixtures | 5037ecf8 | this revision |
|---|---|---|
| Exit code | 16 of 16 | 16 of 16 |
| `result` string, exactly | 4 of 16 | 16 of 16 |
| `later_state` string, exactly | 15 of 16 | 16 of 16 |

The contract exposed one case no fixture covers: `approval.granted: false` with no matching audit record in a
declared complete, matching scope. `contract-c4780c28/approval-not-granted-no-match.json` is
`approval-not-granted.json` with its one audit record removed. `5037ecf8` gives `approval_not_granted`; this
revision gives `no_match_in_declared_complete_scope`, as the contract's order does. Both exit 1.
`contract-c4780c28/results.json` holds this revision's output for all 17.
