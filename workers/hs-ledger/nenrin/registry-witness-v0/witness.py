#!/usr/bin/env python3
"""nenrin-registry-witness-v0: an independent witness for the TRACE registry checkpoint chain.

    python3 witness.py run    --registry DIR --state DIR --key PEM --init                 (first run only)
    python3 witness.py run    --registry DIR --state DIR --key PEM --published-head SHA256 [--source-commit SHA]
    python3 witness.py verify --registry DIR --state DIR --witness-key HEX

run   1. Reads every registry/YYYY/MM/DD.ndjson under DIR in path order. A malformed line, a
         duplicate JSON key, an .ndjson file anywhere else under registry/, or an entry without a
         checkpoint after the first checkpointed one is a refusal.
      2. Verifies the whole checkpoint chain with trace-verify's own two checks (consistency proofs
         and signatures between checkpoints; the MMR rebuilt from the raw entries), with the key
         pinned here for each log_id, and checkpoint timestamps that never go backwards.
      3. Requires continuity with what this witness published before. A state with no leaves is
         accepted only with --init. Otherwise the SHA-256 of the state's last tree head line must
         equal --published-head, the value read from the public copy of the witness log, so a
         second or reset state under the same key is refused rather than extended. Every
         witnessed checkpoint must still be in the registry as the same bytes on the same line.
      4. Only then witnesses each checkpoint it has not seen, in chain order: appends its entry
         hash to this witness's own RFC 9162 log, mints a COSE receipt in the stage-1 profile
         trace-verify reads (grade mmr-verified signed under -65537; a signed CWT iat, the run's
         start time, while the checkpoint is less than 30 days old with an hour to spare), and
         signs a tree head with an RFC 9162 consistency proof from the previous one.
      The run holds an OS lock on STATE.lock throughout. New files are written into a uniquely
      named staging copy, checked there against the log just built, and published by a directory
      swap. A refusal writes nothing and exits 3. A witnessed checkpoint's receipt is final.

verify checks a state offline against a registry, recomputing every field of the log from the
      checkpoints and receipts it names.

A key holder can always sign; no code stops that. What makes a second history under this key
detectable is that every tree head is published, and a reader holding two heads of one witness key
that no consistency proof joins holds proof of misbehaviour. See README for what this establishes.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from scitt_cose import merkle
from scitt_cose.receipt import build_receipt
from trace_verify._checkpoint import CheckpointRecord, verify_chain_against_entries, verify_checkpoint_chain
from trace_verify._witness import signing_body, signing_body_digest, verify as verify_receipt_trace

WITNESS_LOG_ID = "nenrin-registry-witness/v1"
GRADE = "mmr-verified"
# trace-verify refuses a signed iat more than 30 days after the checkpoint (MAX_REGISTRATION_DELAY_SECONDS).
IAT_WINDOW_SECONDS = 30 * 86400 - 3600
ENROLLED = {
    # log_id -> the registry key accepted for it, pinned here rather than read from the checkpoint.
    "trace-registry/v1": "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90",
}
# --now and --enroll exist for the self test only and are refused unless this is set.
TEST_ENV = "NENRIN_WITNESS_TEST"
REGISTRY_FILE = re.compile(r"^registry/\d{4}/\d{2}/\d{2}\.ndjson$")
LOG_KEYS = {"v", "log_id", "witness_key", "leaves"}
LEAF_KEYS = {"index", "entry_hash", "checkpoint_signing_digest", "log_id", "mmr_size", "checkpoint_timestamp",
             "source", "line_sha256", "source_commit", "witnessed_at", "iat_signed", "grade", "receipt_sha256",
             "timestamp_before_previous_run"}
STATE_NAMES = {"log.json", "tree_heads.ndjson", "checkpoints", "receipts"}


class Refusal(Exception):
    pass


def jcs(value) -> bytes:
    return rfc8785.dumps(value)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_unique(text):
    def hook(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate JSON key: " + k)
            out[k] = v
        return out
    return json.loads(text, object_pairs_hook=hook)


def read_registry(root: Path):
    """Return [(entry, source 'path:line', raw line bytes)] in registry order."""
    regdir = root / "registry"
    if not regdir.is_dir():
        raise Refusal(f"{root} has no registry/ directory")
    out = []
    for p in sorted(regdir.rglob("*.ndjson")):
        rel = p.relative_to(root).as_posix()
        if not REGISTRY_FILE.match(rel):
            raise Refusal(f"{rel}: an .ndjson file outside registry/YYYY/MM/DD.ndjson; refusing rather than skipping it")
        for n, raw in enumerate(p.read_bytes().split(b"\n"), 1):
            if not raw.strip():
                continue
            try:
                e = load_unique(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise Refusal(f"{rel}:{n}: {exc}")
            if not isinstance(e, dict):
                raise Refusal(f"{rel}:{n}: entry is not an object")
            out.append((e, f"{rel}:{n}", raw))
    seen_cp = False
    for e, src, _ in out:
        has = isinstance(e.get("mmr_checkpoint"), dict)
        if seen_cp and not has:
            raise Refusal(f"{src}: an entry without a checkpoint after checkpointing began")
        seen_cp = seen_cp or has
    return out


def check_chain(rows, enrolled):
    entries = [e for e, _, _ in rows]
    cps = [(e["mmr_checkpoint"], src, raw) for e, src, raw in rows if isinstance(e.get("mmr_checkpoint"), dict)]
    errors = []
    try:
        records = [CheckpointRecord.from_dict(c) for c, _, _ in cps]
    except ValueError as exc:
        return cps, [f"malformed mmr_checkpoint: {exc}"]
    _, errs = verify_checkpoint_chain(records)
    errors += errs
    prev_t = None
    for i, (c, src, _) in enumerate(cps):
        want = enrolled.get(c.get("log_id"))
        if want is None:
            errors.append(f"checkpoint {i}: log_id {c.get('log_id')!r} is not enrolled with this witness")
        elif c.get("key_id") != want:
            errors.append(f"checkpoint {i}: key_id does not match the key pinned for {c.get('log_id')}")
        try:
            t = epoch_of(c["timestamp"])
        except (Refusal, ValueError, TypeError) as exc:
            errors.append(f"checkpoint {i}: timestamp: {exc}")
            continue
        if prev_t is not None and t < prev_t:
            errors.append(f"checkpoint {i} ({src}): timestamp earlier than the checkpoint before it")
        prev_t = t
    errors += verify_chain_against_entries(entries)
    return cps, errors


def entry_hash_of(cp) -> tuple[str, str]:
    digest = signing_body_digest(signing_body(cp))
    return digest.hex(), hashlib.sha256(digest).hexdigest()


def epoch_of(ts: str) -> int:
    t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise Refusal("checkpoint timestamp must carry a timezone")
    return int(t.timestamp())


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_log(state: Path):
    p = state / "log.json"
    if not p.exists():
        return {"v": 1, "log_id": WITNESS_LOG_ID, "leaves": []}
    return load_unique(p.read_text(encoding="utf-8"))


def head_lines(state: Path):
    p = state / "tree_heads.ndjson"
    return [x for x in p.read_bytes().split(b"\n") if x.strip()] if p.exists() else []


def pub_hex(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def tree_head_body(size, root, prev_size, prev_root, proof, ts, key_hex):
    return {"v": 1, "kind": "witness_tree_head", "log_id": WITNESS_LOG_ID, "tree_size": size,
            "root": root, "prev_size": prev_size, "prev_root": prev_root,
            "consistency_proof": proof, "witness_key": key_hex, "timestamp": ts}


def verify_state(reg: Path, state: Path, me: str, enrolled, expect_log=None) -> list[str]:
    bad = []
    if not state.is_dir():
        return [f"{state} is not a directory (an interrupted publish leaves {state.name}.old; run again to restore it)"]
    if state.with_name(state.name + ".old").exists():
        bad.append(f"{state.name}.old exists: a publish was interrupted; run again to finish it")
    try:
        rows = read_registry(reg)
    except Refusal as exc:
        return [f"registry: {exc}"]
    cps, errors = check_chain(rows, enrolled)
    bad += [f"registry chain: {e}" for e in errors]
    by_source = {src: (cp, raw) for cp, src, raw in cps}
    try:
        log = load_log(state)
    except ValueError as exc:
        return bad + [f"log.json: {exc}"]
    if expect_log is not None and jcs(log) != jcs(expect_log):
        bad.append("the state on disk is not the log this run built")
    if set(log) - LOG_KEYS or log.get("log_id") != WITNESS_LOG_ID or log.get("v") != 1 or not isinstance(log.get("leaves"), list):
        bad.append("log.json is not a nenrin-registry-witness/v1 log")
        return bad
    leaves = log["leaves"]
    if leaves and log.get("witness_key") != me:
        bad.append("log.json names a different witness key")
    tree, last = [], {}
    prev_witnessed = None
    for i, l in enumerate(leaves):
        tag = f"leaf {i}"
        if not isinstance(l, dict) or set(l) != LEAF_KEYS:
            bad.append(f"{tag}: fields are not exactly {sorted(LEAF_KEYS)}")
            continue
        eh = l["entry_hash"]
        tree.append(eh)
        if l["index"] != i:
            bad.append(f"{tag}: index {l['index']} out of sequence")
        try:
            cp = load_unique((state / "checkpoints" / f"{eh}.json").read_text(encoding="utf-8"))
            resp = load_unique((state / "receipts" / f"{eh}.post.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            bad.append(f"{tag}: {exc}")
            continue
        digest_hex, h = entry_hash_of(cp)
        if h != eh:
            bad.append(f"{tag}: stored checkpoint does not hash to its entry")
        reg_cp = by_source.get(l["source"])
        if reg_cp is None or entry_hash_of(reg_cp[0])[1] != eh:
            bad.append(f"{tag}: the registry no longer holds this checkpoint at {l['source']} (dropped, moved, replaced or forked)")
        elif sha(reg_cp[1]) != l["line_sha256"] or jcs(reg_cp[0]) != jcs(cp):
            bad.append(f"{tag}: the registry line at {l['source']} is not the bytes that were witnessed")
        want = {"checkpoint_signing_digest": digest_hex, "log_id": cp.get("log_id"), "mmr_size": cp.get("mmr_size"),
                "checkpoint_timestamp": cp.get("timestamp"), "grade": GRADE}
        for k, v in want.items():
            if l[k] != v:
                bad.append(f"{tag}: {k} is not what the checkpoint says")
        lid = cp.get("log_id")
        if lid in last and not cp.get("mmr_size", -1) > last[lid]:
            bad.append(f"{tag}: mmr_size does not increase for {lid}")
        last[lid] = cp.get("mmr_size", -1)
        try:
            receipt = base64.b64decode(resp["receipt_b64"], validate=True)
        except (KeyError, ValueError, TypeError):
            bad.append(f"{tag}: receipt is not base64")
            continue
        if sha(receipt) != l["receipt_sha256"]:
            bad.append(f"{tag}: receipt bytes are not the ones the log recorded")
        if lid not in enrolled:
            bad.append(f"{tag}: log_id {lid!r} is not enrolled")
            continue
        r = verify_receipt_trace(cp, resp, registry_key=enrolled[lid], witness_key=me, expected_log_id=lid)
        if not r["verified"]:
            bad.append(f"{tag}: receipt does not verify under trace-verify: {r.get('error')}")
            continue
        if r["leaf_index"] != i or r["tree_size"] != i + 1:
            bad.append(f"{tag}: receipt sits at leaf {r['leaf_index']} of {r['tree_size']}, not {i} of {i + 1}")
        if r["root"] != merkle.merkle_root(tree):
            bad.append(f"{tag}: receipt root is not the witness log's root at size {i + 1}")
        if not r["limits"]["grade_cryptographically_bound"]:
            bad.append(f"{tag}: grade is not bound")
        if r["limits"]["witness_time_established"] != l["iat_signed"]:
            bad.append(f"{tag}: iat_signed disagrees with the receipt")
        try:
            w = epoch_of(l["witnessed_at"])
        except (Refusal, ValueError, TypeError, AttributeError):
            bad.append(f"{tag}: witnessed_at is not a time")
            continue
        if l["iat_signed"] and r["signed_iat"] != w:
            bad.append(f"{tag}: witnessed_at is not the signed iat")
        if w < epoch_of(cp["timestamp"]):
            bad.append(f"{tag}: witnessed before the checkpoint's own timestamp")
        if l["iat_signed"] != (w <= epoch_of(cp["timestamp"]) + IAT_WINDOW_SECONDS):
            bad.append(f"{tag}: iat_signed is not what the 30-day window gives")
        if prev_witnessed is not None and w < prev_witnessed:
            bad.append(f"{tag}: witnessed_at goes backwards")
        if l["timestamp_before_previous_run"] != (prev_witnessed is not None and epoch_of(cp["timestamp"]) < prev_witnessed and w > prev_witnessed):
            bad.append(f"{tag}: timestamp_before_previous_run is not what the times give")
        prev_witnessed = w
    for sub, want_names in (("checkpoints", {f"{e}.json" for e in tree}), ("receipts", {f"{e}.post.json" for e in tree})):
        have = {p.name for p in (state / sub).iterdir()} if (state / sub).is_dir() else set()
        if have != want_names:
            bad.append(f"{sub}/ holds {sorted(have ^ want_names)} beyond or short of what the log names")
    extra = {p.name for p in state.iterdir()} - STATE_NAMES
    if extra:
        bad.append(f"unexpected files in the state: {sorted(extra)}")
    lines = head_lines(state)
    if tree and not lines:
        bad.append("the log has leaves and no signed tree head")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(me))
    except ValueError:
        return bad + ["witness key is not a 32-byte hex key"]
    prev = None
    for raw in lines:
        try:
            h = load_unique(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            bad.append(f"tree head: {exc}")
            continue
        tag = f"tree head {h.get('tree_size')}"
        body = {k: v for k, v in h.items() if k != "signature"}
        if raw != jcs(h):
            bad.append(f"{tag}: not stored as its canonical bytes")
        if set(h) != {"v", "kind", "log_id", "tree_size", "root", "prev_size", "prev_root", "consistency_proof", "witness_key", "timestamp", "signature"}:
            bad.append(f"{tag}: unexpected fields")
        if body.get("kind") != "witness_tree_head" or body.get("log_id") != WITNESS_LOG_ID or body.get("witness_key") != me:
            bad.append(f"{tag}: not a tree head of this witness")
        try:
            pub.verify(bytes.fromhex(h["signature"]), jcs(body))
        except Exception:
            bad.append(f"{tag}: signature does not verify")
        size = h.get("tree_size")
        if not isinstance(size, int) or not 0 < size <= len(tree):
            bad.append(f"{tag}: size outside the log")
            prev = h
            continue
        if h.get("root") != merkle.merkle_root(tree[:size]):
            bad.append(f"{tag}: root is not the root of the first {size} leaves")
        if prev is None:
            if (h.get("prev_size"), h.get("prev_root"), h.get("consistency_proof")) != (0, "", []):
                bad.append(f"{tag}: the first tree head must start from size 0")
        else:
            if not size > prev.get("tree_size", 0):
                bad.append(f"{tag}: size does not increase")
            elif (h.get("prev_size"), h.get("prev_root")) != (prev.get("tree_size"), prev.get("root")):
                bad.append(f"{tag}: does not name the previous head")
            elif not merkle.verify_consistency(prev["root"], h["root"], prev["tree_size"], size, h.get("consistency_proof", [])):
                bad.append(f"{tag}: consistency proof from {prev['tree_size']} fails")
        prev = h
    if lines and (prev or {}).get("tree_size") != len(tree):
        bad.append("the last tree head does not cover every leaf")
    return bad


def parse_enroll(a):
    if not getattr(a, "enroll", None):
        return dict(ENROLLED)
    out = {}
    for item in a.enroll:
        lid, sep, key = item.partition("=")
        if not sep or len(key) != 64:
            raise SystemExit("--enroll takes LOG_ID=64-hex")
        out[lid] = key
    return out


def guard_test_flags(a):
    if (getattr(a, "now", None) or getattr(a, "enroll", None)) and os.environ.get(TEST_ENV) != "1":
        raise SystemExit(f"--now and --enroll are for the self test only ({TEST_ENV}=1)")


def recover(state: Path):
    """Under the lock: finish or undo what a crashed run left. Nothing outside `state` was ever published."""
    old = state.with_name(state.name + ".old")
    for p in state.parent.glob(state.name + ".staging-*"):
        shutil.rmtree(p)
    if old.exists():
        if state.exists():
            shutil.rmtree(old)
        else:
            os.rename(old, state)


def publish(stage: Path, state: Path):
    old = state.with_name(state.name + ".old")
    if state.exists():
        os.rename(state, old)
    os.rename(stage, state)
    if old.exists():
        shutil.rmtree(old)


def cmd_run(a) -> int:
    guard_test_flags(a)
    state = Path(a.state)
    state.parent.mkdir(parents=True, exist_ok=True)
    with open(state.with_name(state.name + ".lock"), "a") as lockf:
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"REFUSED: another run holds {lockf.name}; nothing was witnessed.")
            return 3
        return _run_locked(a, state)


def _run_locked(a, state: Path) -> int:
    reg = Path(a.registry)
    enrolled = parse_enroll(a)
    pem = Path(a.key).read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("the witness key must be Ed25519")
    me = pub_hex(key)
    now = int(a.now) if a.now else int(time.time())
    recover(state)
    try:
        rows = read_registry(reg)
        cps, errors = check_chain(rows, enrolled)
        if not cps:
            raise Refusal("no checkpoint in the registry")
        if errors:
            raise Refusal("the checkpoint chain does not verify: " + "; ".join(errors))
        log = load_log(state) if state.exists() else {"v": 1, "log_id": WITNESS_LOG_ID, "leaves": []}
        if not log["leaves"]:
            if not a.init:
                raise Refusal("this state has no leaves; start a witness log only with --init")
            if a.published_head:
                raise Refusal("--init starts a new log; it takes no --published-head")
        else:
            if a.init:
                raise Refusal("--init on a state that already has leaves")
            if log.get("witness_key") != me:
                raise Refusal("this state was written under a different witness key")
            lines = head_lines(state)
            if not a.published_head or not lines or sha(lines[-1]) != a.published_head.lower():
                raise Refusal("the last tree head here is not the published one (--published-head); push the state, or fetch the published one, first")
            problems = verify_state(reg, state, me, enrolled)
            if problems:
                raise Refusal("the registry is not continuous with what this witness signed before: " + "; ".join(problems))
        seen = {l["entry_hash"] for l in log["leaves"]}
        last = {}
        prev_run = None
        for l in log["leaves"]:
            last[l["log_id"]] = l["mmr_size"]
            prev_run = epoch_of(l["witnessed_at"])
        new = []
        for cp, src, raw in cps:
            digest_hex, eh = entry_hash_of(cp)
            if eh in seen:
                continue
            if cp["mmr_size"] <= last.get(cp["log_id"], 0):
                raise Refusal(f"checkpoint mmr_size {cp['mmr_size']} is not after the last one witnessed for {cp['log_id']}")
            if now < epoch_of(cp["timestamp"]):
                raise Refusal(f"this clock is before checkpoint mmr_size {cp['mmr_size']}'s own timestamp")
            if prev_run is not None and now < prev_run:
                raise Refusal("this clock is before the previous run")
            last[cp["log_id"]] = cp["mmr_size"]
            new.append((cp, src, raw, digest_hex, eh))
    except Refusal as exc:
        print("REFUSED: nothing was witnessed. " + str(exc))
        return 3
    if not new:
        print(f"OK: chain verified ({len(cps)} checkpoints), nothing new, witness log size {len(log['leaves'])}")
        return 0
    stage = Path(tempfile.mkdtemp(prefix=state.name + ".staging-", dir=state.parent))
    os.rmdir(stage)
    if state.exists():
        shutil.copytree(state, stage)
    else:
        stage.mkdir()
    (stage / "checkpoints").mkdir(exist_ok=True)
    (stage / "receipts").mkdir(exist_ok=True)
    log["witness_key"] = me
    leaves = log["leaves"]
    for cp, src, raw, digest_hex, eh in new:
        iat = now if now <= epoch_of(cp["timestamp"]) + IAT_WINDOW_SECONDS else None
        tree = [l["entry_hash"] for l in leaves] + [eh]
        idx = len(tree) - 1
        receipt = build_receipt(leaf_entry_hex=eh, leaf_index=idx, tree_entries_hex=tree, alg="EdDSA",
                                log_private_key_pem=pem, iat=iat, grade=GRADE)
        response = {"receipt_b64": base64.b64encode(receipt).decode("ascii"), "entry_hash": eh,
                    "entry_hash_scheme": "legacy", "leaf_index": idx, "tree_size": len(tree), "grade": GRADE}
        (stage / "checkpoints" / f"{eh}.json").write_bytes(jcs(cp))
        (stage / "receipts" / f"{eh}.post.json").write_bytes(jcs(response))
        leaves.append({"index": idx, "entry_hash": eh, "checkpoint_signing_digest": digest_hex,
                       "log_id": cp["log_id"], "mmr_size": cp["mmr_size"], "checkpoint_timestamp": cp["timestamp"],
                       "source": src, "line_sha256": sha(raw), "source_commit": a.source_commit,
                       "witnessed_at": iso(now), "iat_signed": iat is not None, "grade": GRADE,
                       "receipt_sha256": sha(receipt),
                       "timestamp_before_previous_run": prev_run is not None and epoch_of(cp["timestamp"]) < prev_run and now > prev_run})
    lines = head_lines(stage)
    prev = load_unique(lines[-1].decode("utf-8")) if lines else None
    tree = [l["entry_hash"] for l in leaves]
    prev_size = prev["tree_size"] if prev else 0
    prev_root = prev["root"] if prev else ""
    proof = merkle.consistency_proof(tree, prev_size, len(tree)) if prev_size else []
    body = tree_head_body(len(tree), merkle.merkle_root(tree), prev_size, prev_root, proof, iso(now), me)
    with open(stage / "tree_heads.ndjson", "ab") as fh:
        fh.write(jcs(dict(body, signature=key.sign(jcs(body)).hex())) + b"\n")
    (stage / "log.json").write_bytes(jcs(log))
    problems = verify_state(reg, stage, me, enrolled, expect_log=log)
    if problems:
        shutil.rmtree(stage)
        print("REFUSED: the new state does not verify, nothing was published. " + "; ".join(problems))
        return 3
    publish(stage, state)
    for cp, _, _, _, eh in new:
        leaf = next(l for l in leaves if l["entry_hash"] == eh)
        print(f"WITNESSED: {cp['log_id']} checkpoint mmr_size {cp['mmr_size']}, entry {eh[:16]}..., iat {'signed' if leaf['iat_signed'] else 'not signed (over 30 days)'}")
    print(f"OK: chain verified ({len(cps)} checkpoints), {len(new)} new receipt(s), witness log size {len(leaves)}, key {me}")
    print(f"published-head {sha(head_lines(state)[-1])}")
    return 0


def cmd_verify(a) -> int:
    guard_test_flags(a)
    state = Path(a.state)
    bad = verify_state(Path(a.registry), state, a.witness_key, parse_enroll(a))
    for b in bad:
        print("FAIL: " + b)
    if not bad:
        lines = head_lines(state)
        print(f"OK: {len(load_log(state)['leaves'])} receipt(s) verify under trace-verify, {len(lines)} tree head(s) signed and consistent")
        if lines:
            print(f"published-head {sha(lines[-1])}")
    return 1 if bad else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="witness.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--registry", required=True)
    r.add_argument("--state", required=True)
    r.add_argument("--key", required=True)
    r.add_argument("--init", action="store_true", help="start a new witness log (state with no leaves)")
    r.add_argument("--published-head", help="SHA-256 of the last line of the published tree_heads.ndjson")
    r.add_argument("--source-commit")
    r.add_argument("--now", help=f"epoch seconds; self test only ({TEST_ENV}=1)")
    r.add_argument("--enroll", action="append", help=f"LOG_ID=HEX in place of the pinned set; self test only ({TEST_ENV}=1)")
    v = sub.add_parser("verify")
    v.add_argument("--registry", required=True)
    v.add_argument("--state", required=True)
    v.add_argument("--witness-key", required=True)
    v.add_argument("--enroll", action="append", help=f"LOG_ID=HEX in place of the pinned set; self test only ({TEST_ENV}=1)")
    a = p.parse_args(argv)
    return cmd_run(a) if a.cmd == "run" else cmd_verify(a)


if __name__ == "__main__":
    sys.exit(main())
