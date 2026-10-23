# settle core v0, held-out set blind-01

48 settlement inputs for MUSUBI settle core v0 whose expected outputs are not published yet. The answers were computed by the reference before publication, and only a commitment to them is here. The question is simple: does an implementation written from `SETTLE_CORE_v0.md` get the same eight core fields as the reference on inputs it has never seen answers for?

aeoess proposed this procedure (agent-errata#16): a new implementation written from a pinned text and the inputs, without the notes or the reference code, its code frozen and hashed before anything is compared.

## The pinned text

`../settle-core-v0/SETTLE_CORE_v0.md`, revision 0.8, last changed in commit `d7f5a91ed5565a4b1079f0e627d5d75eeb4a8367`, sha256 `3382374416254f85eec0c4f03699161748db5999794e75b68a00e7a4b7cf27c2`. The same line is in `COMMITMENT.txt`. Later revisions of the text do not apply to blind-01.

## What is here

| path | what |
|---|---|
| `inputs/bNN/` | one folder per input, laid out like `../settle-core-v0/vectors/` (section 16) but without `expected.json`: `contract.json`, `view.json`, `events/eNN.json`, and `nenrin/nNN.json` or `parent.json` where the input has them |
| `SHA256SUMS` | the sha256 of every file under `inputs/` |
| `COMMITMENT.txt` | a salted commitment to each answer, and a root over all of them |
| `COMMITMENT.txt.ots` | an OpenTimestamps proof for `COMMITMENT.txt` |
| `blind_compare.py` | `freeze` computes your freeze digest; `compare` runs the comparison at opening |
| `blind_commit.py` | checks `inputs/` against `SHA256SUMS`, and checks the opening against `COMMITMENT.txt` |

The ids b01 to b48 are in no particular order and say nothing about the input. All 48 inputs are synthetic: the four synthetic public keys and the regtest-difficulty header chain of the public vectors, with contracts of their own. None of them is byte-identical to a public vector, and no input file equals a file of a public vector.

Settle each input as section 16 describes: the contract, the events (file order carries no meaning, 2.1), the view, the walks when `nenrin/` exists, the parent when `parent.json` exists. Binding mode strict, one view.

## What is withheld until opening

- the expected core fields of each input (9.1),
- the 48 salts and the root salt,
- the script that built the inputs, its seed, and the list of what each input tests.

Why salts: most core fields can be computed from the inputs, and the rest come from short lists of values, so a bare hash of an answer could be found by trying candidates. Each answer is hashed with its own 256-bit random salt (`blind_commit.py` explains the construction).

## Two tracks

Say which track you are in when you freeze. Results are reported per track.

**Track T (text only).** You may read: `SETTLE_CORE_v0.md` at the pinned commit; this folder; the inputs of the 128 public vectors (`contract.json`, `view.json`, `events/`, `nenrin/`, `parent.json`); and general references (RFC 8032, RFC 8785, the Bitcoin header format, your language's documentation). You may not read: `NOTES.md`, `gen_vectors.py`, `run_reference.py`, `exercise_inputs.py`, `EXERCISE.txt`, any `expected.json` or `vectors.json`, the reference code in `musubi-v0`, or any other implementation of settle core v0.

**Track V (text and public vectors).** As Track T, and you may also read and test against the 128 public vectors with their `expected.json` and `vectors.json`. Still not `NOTES.md`, the reference code, `gen_vectors.py`, `run_reference.py` or another implementation.

Whatever writes your code, a person or a tool, should be shown only what your track allows. If you have read something outside your track before (for example, you wrote an earlier implementation), you can still take part: say what you read, and the result is reported with that statement.

Nothing here can enforce these rules. The result is as strong as the statement that comes with it, and the statement is published next to it.

## Freeze, then open

1. Write your implementation. Run it on every input and write one file per input, `out/bNN.json`, holding the eight core fields as a JSON object. If it cannot settle an input, write a file anyway (for example `{"error": "..."}`); a missing file counts as a disagreement.
2. Commit the code. Run `python3 blind_compare.py freeze --outputs out` and note the freeze digest.
3. Before `2026-11-20` (23:59 UTC), post one comment on the blind-01 issue with: your handle, the track, the repository URL (it may stay private until opening), the full commit hash and `git rev-parse <commit>^{tree}`, the freeze digest, your language and runtime, and what you read. An OpenTimestamps proof of the same text is welcome but not required; the comment's timestamp is the freeze proof. Do not post your outputs yet, and do not edit the comment afterwards (an edited comment shows its history; we quote the original).
4. On `2026-11-21` we publish, in this folder: the salts, every `expected.json`, the generator, its seed and the list of what each input tests. Anyone can then check the opening with `python3 blind_commit.py open`.
5. You publish your code at the frozen commit and your `out/`. We run `blind_compare.py compare` with your freeze digest. It refuses outputs whose digest is not the frozen one.

The opening date is fixed. It does not move earlier when some number of people have frozen. If nobody has frozen by `2026-11-20`, we may move both dates once, announced on the issue before the deadline. Implementations frozen after the opening are welcome too; they are reported as not blind.

## How results are reported

For each implementation: the handle, the track and the reading statement, the commit and freeze digest, and the count of inputs that agree on all eight core fields (`deviation_codes` and `underspecified_reasons` compared as sets, `event_set` as a list, `dispositions` as an object). Every disagreement is listed with the field and both values.

Every disagreement is then judged against the pinned text, not against the reference: either the reference is right by the text, or the implementation is, or the text allows both. If the reference or our answers are wrong, that is reported as plainly as any other result. A place where the text allows both readings becomes a finding and leads to a revision of the text. The committed answers are never changed after opening, including when they turn out to be wrong; a correction goes into a later revision and a new set.

## Credit

Each participant is credited by handle in this folder's results and in `../settle-core-v0/NOTES.md`. Nobody is paid, on either side.
