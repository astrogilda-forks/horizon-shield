# Reviewing mirror.py before you vendor it

For an organisation that holds a copy of the NENRIN ledger with `github-action/nenrin-mirror-vendored.yml`. The point of the vendored variant is that you review this file once, commit it into your own repository, and pin its sha256 in the workflow. No code is fetched at run time, and a change upstream changes nothing on your side until you commit a new copy and a new pin.

File: `mirror.py`, 462 lines, Python 3 standard library only (`argparse, hashlib, json, os, sys, time, urllib`). No subprocess, no `eval`/`exec`, no dynamic import, no third-party package. sha256 at the time of writing: `7de4bd1d8fca8efef1e29a91ae400ff11207f8825532984760fe86afd70173ba` (2026-10-13: an entry the ledger reports as unstamped is listed as awaiting its first stamp, not as a problem; the six kinds of GET request and the only write location are unchanged).

## Every network call (all HTTP GET, through one function, `fetch`, line 54)

| Line | URL | What is kept |
|---|---|---|
| 190 | `<base>/ledger?format=json` | the entry count |
| 204 | `<base>/ledger/<n>?format=json` | the entry as served |
| 220 | `<base>/ledger/<n>?format=raw` | the claim bytes, kept only if their sha256 equals the entry's `claim_sha256` |
| 237 | `<base>/ledger/<n>/ots` | the OpenTimestamps proof bytes |
| 250 | the `bytes_url` a batch entry names for each record it carries | the bytes, kept only if they hash to the digest the batch names them by (`object_ok`, line 100) |
| 269 | for a record a known batch names by digest without a `bytes_url` (`NAMED_KINDS`, line 122): `<base>/witness/<sha>`, `<base>/evidence/trace/<sha>?format=raw`, `<base>/evidence/vouch/<sha>?format=raw`, `<base>/evidence/slot/<sha>?format=raw` or `<base>/agreement/<sha>` | the record's own bytes (`record_bytes`, line 150), kept only if they hash to that digest, and the signature, key and domain served with them in `<sha>.sig.json` |

`<base>` is `https://ledger.horizonshield.dev` unless `--base` says otherwise. Plain `http://` is refused except for a loopback address in the self test (`_url_ok`, line 85). Nothing is ever sent: there is no POST, no upload and no credential.

## Every write

Only under the directory given by `--dir`, through `_write` (line 65), which writes `<path>.part` and renames it. Layout: `ledger/<n>.json`, `ledger/<n>.raw`, `ledger/<n>.ots`, `objects/<sha256>`, `objects/<sha256>.sig.json`, `manifest.json`. In the workflow that directory is `work/mirror` on the mirror branch, and the job's token can push only to the repository it runs in.

## What a copy establishes, and what it does not

It establishes that these bytes, with these digests, were obtainable from the ledger at `mirrored_at`, and that anyone holding the branch can recompute every digest offline (`python3 mirror.py verify --dir mirror`). It does not establish that any claim in the ledger is true, or that an anchor is valid; check the `.ots` files against Bitcoin headers with any OpenTimestamps client.

## Updating

When you want a newer `mirror.py`, read the diff, commit the file, and change `MIRROR_PY_SHA256` in the workflow in the same commit. Until you do, the workflow refuses any other bytes at that path.
