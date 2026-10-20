#!/usr/bin/env python3
"""Developer tool, not run by the test: regenerates fixture/forks/ with the TRACE registry's own
aggregator (agentrust-io/trace-registry, aggregator/_mmr_log.py), under a throwaway registry key
whose private half is discarded. Only the public key is kept, in fixture/forks/REGISTRY_KEY.

    python3 make_fork_fixture.py /path/to/trace-registry

a      two checkpoints
a_ext  a, plus a third entry that genuinely extends it
b      the same key and log_id, different content, three checkpoints: a fork of a
a_back a, plus a third checkpoint dated before the second (filed under a later day)
"""
import json, shutil, sys, tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

src = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(src))
from aggregator._mmr_log import CheckpointLog, Ed25519CheckpointSigner  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE / "fixture" / "forks"
pem = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def build(name, tag, times, days=None):
    log = CheckpointLog(None, signer=Ed25519CheckpointSigner(None, pem=pem), replay_entries=[])
    for i, ts in enumerate(times):
        e = {"ts": ts, "batch_id": f"{tag}-{i}", "merkle_root": "sha256:" + (tag * 64)[:64], "leaf_count": 1, "producer": "fork-fixture/0.0.0"}
        e["mmr_checkpoint"] = log.append_entry(e, timestamp=ts).to_dict()
        y, m, d = ts[:10].split("-")
        if days:
            d = days[i]
        p = OUT / name / "registry" / y / m / f"{d}.ndjson"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")


if OUT.exists():
    shutil.rmtree(OUT)
T = ["2026-10-10T00:00:00Z", "2026-10-11T00:00:00Z", "2026-10-12T00:00:00Z"]
build("a", "a", T[:2])
build("a_ext", "a", T)
build("b", "b", T)
build("a_back", "a", T[:2] + ["2026-10-05T00:00:00Z"], days=["10", "11", "21"])
(OUT / "REGISTRY_KEY").write_text(Ed25519CheckpointSigner(None, pem=pem).key_id + "\n")
print("wrote", OUT)
