# vate-s3-v0: NENRIN records reconstructed from the VATE S3 example capture

Label: **a retrospective synthetic reconstruction; the signatures do not establish that a NENRIN grant existed before the original PUT, and they add no independent observation of it.** The label is outside the signed bytes: it appears in this README and in MANIFEST.json, never in a grant or receipt preimage.

## Purpose

Poke-nushi/Verifiable-Agent-Trust-Envelope#84 agreed a field mapping between the VATE S3 observation example and a NENRIN task-execution grant and receipt (our confirmation posted 2026-10-13). This directory turns that mapping into a generator anyone can rerun offline, writes three cases from it, and records what the two published nenrin-verify builds (npm and PyPI) actually return for each case.

It shows that the agreed relations hold on the pinned capture and that both published verifiers read the resulting records the same way. It does not show that anything happened in the world beyond what the VATE capture already records.

## Pins

| what | value |
|---|---|
| VATE repository | https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope |
| VATE commit | b3b6d4f9610e159e92d3b41b66e72fc7251758dc |
| capture | `reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported/` (18 files) plus `.../instance/receiver-policy.json` |
| capture license | Apache-2.0 (repository root LICENSE at that commit; no NOTICE file there) |
| NENRIN side | this repository at origin/main ff591887 when written; schema `task-execution-bind-v0`, signing helpers `../task-execution-bind-v0/sign_exec.mjs` and `bind_exec.mjs`, did:key helpers `../task-delegation-bind-v0/verify_fixture.mjs`, strict JSON `../task-delegation-bind-v0/strict_json.mjs` |
| npm nenrin-verify | 0.5.1 |
| PyPI nenrin-verify | 0.5.3 |

`vate-capture-b3b6d4f/` is an unchanged copy of those 19 files plus the VATE LICENSE, redistributed under Apache-2.0. Every sha256 is pinned in `gen.mjs` (`CAPTURE_SHA256`, `RECEIVER_POLICY`) and repeated in MANIFEST.json; the generator refuses a capture that differs. `.gitattributes` turns off end-of-line conversion for the copy, because the two `*-headers.txt` files hold CRLF bytes whose sha256 is pinned.

## Files

| path | what |
|---|---|
| `gen.mjs` | the generator: checks the capture, prints every field relation, writes `records/` and `MANIFEST.json` |
| `records/<case>/nenrin-bundle.json` | the three cases, in the bundle format the nenrin-verify CLI takes (`task_id`, `grant`, optional `receipt`) |
| `MANIFEST.json` | sha256 of every record file and of gen.mjs, VATE commit and capture sha256s, key phrases, public keys and did:keys, the window, the label, every field-relation check with both values, predictions |
| `runs/` | raw output of the published builds per case, `run_published.sh`, `ENV.txt`, `RUNS.md` |
| `vate_s3_v0.test.mjs` | offline test: regenerate into a temp dir and compare byte for byte, check the MANIFEST sha256s, confirm the three outcomes with the in-repo `../sdk/nenrin_verify.mjs` |
| `vate-capture-b3b6d4f/` | the unchanged capture copy and LICENSE |

Digests at the time of writing:

| file | sha256 |
|---|---|
| MANIFEST.json | c2689c92050bec2285466282eeccff3549e9d72e8869e6b4906c017775664ea7 |
| records/match/nenrin-bundle.json | 8cc480c66682a0393f03d8101d3afc65399963579fc6f72d30416bbdc37eadfe |
| records/target_mismatch/nenrin-bundle.json | c54228f0e43b3ec7d2bc5a83f7c38ddb3b8c990da8e11888a9aa1df6d432a52e |
| records/missing_receipt/nenrin-bundle.json | 25157161133671c10ffa4cd116bb19c3bf1bc185a4742f885f962ce00c5fe45b |

## Regenerate and rerun

```sh
cd workers/hs-ledger/nenrin/vate-s3-v0

# regenerate in place from the copy (offline, no clock; a rerun is byte-identical)
node gen.mjs vate-capture-b3b6d4f

# or straight from a VATE checkout at the pinned commit
git clone --filter=blob:none --no-checkout https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope vate
git -C vate checkout b3b6d4f9610e159e92d3b41b66e72fc7251758dc
node gen.mjs vate/reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported /tmp/vate-s3-out

# the test (offline)
node vate_s3_v0.test.mjs

# the published builds (install outside the repository first; see runs/RUNS.md)
runs/run_published.sh "$EXT/npm" "$EXT/venv"
```

`gen.mjs` exits 1 and writes nothing if any relation below does not hold.

## Field relations (agreed in #84), with the values on the pinned capture

All hold. `gen.mjs` prints each one with both sides; MANIFEST.json `field_relations` keeps them.

| NENRIN field | relation | value | check |
|---|---|---|---|
| `task_id` (grant and receipt) | effective-request.json `operation_id` | `operation-674feb36f4e0bc34b461` | equals attempt.json `operation_id` |
| `action.tool` | effective-request.json `action` | `s3.put_object` | equals admission.json `request.action` |
| `action.target` | `endpoint_profile_id + "/" + bucket + "/" + key`, exact string join | `local-seaweed-effa0477bd68/vate-linkage-b119eb3183/result.txt` | profile and bucket equal receiver-policy.json; the GET read the same profile, bucket and key |
| `action.args_sha256` | SHA-256 of the full effective-request.json object: sorted keys, compact, ASCII-escaped, UTF-8, lowercase hex | `2e4dce64ddc0f6b44386144ed675006e43f5e18d9214ee45de49da5d991ba98c` | equals admission.json `request.input_hash` minus `sha-256:`; equals post.json `execution.effective_request_hash` minus `sha-256:`; the file bytes are already the basis bytes, so this is also the file's sha256 (cross-checked with Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`) |
| `outcome.version_id` | put-transport.json `returned_version_id` | `6722359d3cd3b17f8cff11460862171e` | equals get-request.json `requested_version_id` and get-transport.json `returned_version_id` |
| `outcome.result_sha256` and `outcome.evidence` (`kind: document_sha256`, `ref`) | SHA-256 of raw get-body.bin (47 bytes) | `6a639f0771bfe86b9e4dd4c0ea0b020d360308a55f34d8b0064d9f2d1d3c150c` | equals get-transport.json `body_ref` digest |
| (separate PUT check) | effective-request.json `body_digest.value` = SHA-256 of put-body.bin | `6a639f0771bfe86b9e4dd4c0ea0b020d360308a55f34d8b0064d9f2d1d3c150c` | holds; `byte_length` 47 = length of put-body.bin |
| `executed_at` | put-transport.json `finished_at`, verbatim, six fractional digits | `2026-10-12T13:12:32.500049Z` | equals post.json `execution.finished_at` |
| `not_before`, `not_after` | must contain PUT `started_at` `2026-10-12T13:12:32.274653Z` and `finished_at` | `2026-10-12T13:12:31.274653Z` to `2026-10-12T13:12:33.500049Z` | contains both at microsecond and at millisecond precision |
| `caller_id`, `provider_id` | did:key Ed25519, TEST-ONLY, seed = SHA-256 of a public phrase | see Keys | signatures verify in both builds |

Kept distinct, never equated (all three pairs differ, as expected):

| pair | values |
|---|---|
| NENRIN outer `action_binding.digest.value` (SHA-256 of musubi-canonical-v0 of the action) vs `args_sha256` | `c4d5438d4413ed896a3733d7798efcfecb93afc982f4eee09e7d181fd255aa24` vs `2e4dce64...a98c` |
| VATE post.json `result.output_hash` vs `outcome.result_sha256` | `4e575f903230c3a11dd11841c41348c008a51e55c8001e7887dcd321bd3efd67` vs `6a639f07...150c` |
| VATE `result.output_hash` vs NENRIN outer `action_binding` | `4e575f90...fd67` vs `c4d5438d...aa24` |

The capture's own manifest.json digests are also checked against every listed file (17 artifacts, all equal).

### The window

`not_before` = PUT `started_at` minus 1 second, `not_after` = PUT `finished_at` plus 1 second, computed in integer microseconds and written with six fractional digits. The verifier checks only `executed_at` against the window; the containment of `started_at` is checked by the generator.

Comparison precision: the npm build (and the in-repo `sdk/nenrin_verify.mjs`) compares with JavaScript `Date.parse`, which keeps milliseconds. The PyPI build's `date_parse` in `nenrin_verify/_js.py` takes the first three fraction digits and drops the rest, so it also compares in milliseconds, truncating. The records keep all six digits; the 1 second margins are far larger than either precision.

### Keys (TEST-ONLY)

The phrases are public, so anyone can derive the private keys. These keys establish nothing about who signed; they only make reruns byte-identical (Ed25519 signing is deterministic). The derivation was cross-checked with Python `cryptography`.

| role | phrase | public key (hex) and did:key |
|---|---|---|
| caller | `NENRIN VATE S3 example caller key v0 (public, test only)` | eb0481e7cd0eb60ff17a6924df8e14f78eb8a85b6c6b57c105bf23bf0f09c770 did:key:z6MkvGfqiuLzzhVKPqLc1kzPYmi6ZtSn4Avqf3LCxc5J7toR |
| provider | `NENRIN VATE S3 example provider key v0 (public, test only)` | 0be1dfc164ed6e22d4b646ed32680f96788bff8ea59d93c7c5ef7dc13f7dda74 did:key:z6MkfFeJ2J6se1SNeo5djxi57JX1WBzm7Z9nCbD1bF1DAjT1 |

Other choices the mapping left open: grant `nonce` = `"vate-s3-v0:" + task_id`; `outcome.evidence.system` names the VATE commit and the get-body.bin path; `outcome.status` is omitted because no agreed relation maps VATE `result.outcome` to it. No preflight intent and no witness observations are written.

## Cases and results

| case | what changes | prediction | npm 0.5.1 | PyPI 0.5.3 | equal? |
|---|---|---|---|---|---|
| match | grant and receipt as derived | accepted | accepted, exit 0 | accepted, exit 0 | yes, byte-identical stdout |
| target_mismatch | receipt `executed_action.target` key `result.txt` changed to `result-other.txt`; `receipt_id` and the receipt's `action_binding` regenerated; re-signed by the provider key; grant unchanged | refused, `execution_invalid`, reason `action_diverged` | refused, `execution_invalid` / `action_diverged`, exit 1 | same | yes, byte-identical stdout |
| missing_receipt | the grant alone | refused, `execution_incomplete_pair` | refused, `execution_incomplete_pair`, exit 1 | same | yes, byte-identical stdout |

All three predictions held in both builds, and the in-repo verifier prints the same reports. Details, commands and output digests: `runs/RUNS.md`.

## Limits

- Synthetic reconstruction. The grant and receipt were written on 2026-10-13 from a capture made on 2026-10-12. The signatures do not establish that a NENRIN grant existed before the original PUT and add no independent observation of it. The keys are test keys derived from public phrases.
- No new S3 capture. Everything here derives from the pinned VATE files; nothing was sent to any S3 endpoint.
- No sub-millisecond boundary tests. Both verifiers compare in milliseconds and the window margins are 1 second, so these cases say nothing about behaviour at a boundary closer than a millisecond.
- `evidence_bound_unchecked` stays a finding in both builds: no external lookup ran, so the verifier does not confirm that get-body.bin exists where `evidence.system` says.
- The verifiers check that the provider's signed claim matches the caller's signed authorization; they have no side-effect oracle.
