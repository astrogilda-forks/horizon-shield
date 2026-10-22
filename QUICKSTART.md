# Quickstart: recompute it yourself in five minutes

Everything below runs on your machine, from published bytes, with no account and no key. Each step says what you
should see. If you see something else, that is a finding: open an issue with the command and the output.

You need Python 3.11 or later and [pipx](https://pipx.pypa.io/) (or a virtual environment; see the end). The package
itself is tested on Python 3.9, 3.11 and 3.13; step 4 needs `ca2a-runtime`, which needs 3.11.

## 1. Install (about 30 seconds)

    pipx install 'nenrin-verify[ca2a]==0.7.0'

This installs the verifiers and, through the `ca2a` extra, `ca2a-runtime` 0.4.0, which the cA2A companion needs.
Nothing is fetched from our servers.

## 2. A contract settled in public (a few seconds)

    musubi-verify --run0002

You should see:

    run0002 recomputes: anchored b13a3869..., settlement 11c27fcf... (as published in run0002/README.md)

This is the first MUSUBI contract settled with a party from outside this project: the anchor is composed from the
ledger batch and its OpenTimestamps proof, and the settlement is recomputed from the signed contract, the record and
the header view.

## 3. The specification's 128 test vectors (about 30 seconds)

    musubi-verify --settle-core

You should see:

    settle core v0: 128/128 vectors agree with the reference; EXERCISE.txt agrees; vectors.json sha256 7e139f0e...

These are the vectors of [draft-oga-musubi-settlement](https://datatracker.ietf.org/doc/draft-oga-musubi-settlement/),
22 from real records and 106 synthetic. Two implementations written by other authors agree with all 128
([docs/INTEROP_TABLE.md](docs/INTEROP_TABLE.md)).

## 4. A live run with outside parties (a few seconds)

    musubi-verify --pilot51-set2

You should see:

    #51 set 2 recomputes: settlement output sha256 18a19f8a... (as published in pilot51/set2/README.md)

This is the run of 22 October 2026 (Issue #51): three calls, thirteen log entries, a checkpoint anchored in Bitcoin
block 972551. The third payment carries `budget_exceeded`. Someone outside this project recomputed the same hash on
their own machine.

## 5. Use your own headers

Steps 2 to 4 use the header views that were published with the runs. To take nothing from us, rebuild the view from
your own Bitcoin node, or from two public explorers, and settle again. The verdicts should not change; only the depth
of the anchor grows as new blocks arrive. When a reader outside this project did this for #51 set 2, the depth went
from 9 to 14 and nothing else moved.

## 6. Add your own row

If you write a verifier of your own, or run ours somewhere we have not, publish the commit, the input, the output and
its sha256, and tell us in an issue. See "How to add a row" in [docs/INTEROP_TABLE.md](docs/INTEROP_TABLE.md).

## Without pipx

    python3 -m venv /tmp/nv && /tmp/nv/bin/pip install 'nenrin-verify[ca2a]==0.7.0' && /tmp/nv/bin/musubi-verify --settle-core

Without the `ca2a` extra, steps 2 and 3 work and step 4 says what is missing and exits 3.

## What this does not show

A signature proves who asserted something, not that it is true. A recomputed verdict shows that the published bytes
give the published answer under the published rules; it does not show that the records describe what happened in
the world. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
