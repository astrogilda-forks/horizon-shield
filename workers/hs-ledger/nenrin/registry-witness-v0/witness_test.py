#!/usr/bin/env python3
"""Self test for nenrin-registry-witness-v0.

fixture/registry: the real TRACE registry checkpoints. fixture/forks: a log, a genuine extension
of it, and a fork of it under one throwaway registry key (make_fork_fixture.py). Every receipt is
also checked with the registry's own command, trace-verify receipt, as a reader would run it.
Witness keys are generated per run in a temporary directory. No network."""
import base64, fcntl, hashlib, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from witness import ENROLLED, TEST_ENV  # noqa: E402

W = [sys.executable, str(HERE / "witness.py")]
FIX = HERE / "fixture"
FORKS = FIX / "forks"
REGKEY = ENROLLED["trace-registry/v1"]
FORKKEY = (FORKS / "REGISTRY_KEY").read_text().strip()
NOW = 1792465200               # 2026-10-20T03:00:00Z: checkpoint 1 is 48 days old, checkpoint 2 is 24
LATE = NOW + 6 * 86400         # 2026-10-26: checkpoint 2 is past the 30-day iat window
ENV = dict(os.environ, **{TEST_ENV: "1"})
fails = 0


def ok(cond, what):
    global fails
    print(("  ok   " if cond else "  FAIL ") + what)
    fails += 0 if cond else 1


def run(*args, env=ENV):
    return subprocess.run(W + list(args), capture_output=True, text=True, env=env)


def published_head(st):
    p = st / "tree_heads.ndjson"
    lines = [x for x in p.read_bytes().split(b"\n") if x.strip()] if p.exists() else []
    return hashlib.sha256(lines[-1]).hexdigest() if lines else None


def wit(reg, st, pem, now=NOW, extra=(), head="auto"):
    """A run as the operator does it: --init on an empty state, else the published head (here: the state's own)."""
    h = published_head(st) if head == "auto" else head
    pos = ["--init"] if h is None and head == "auto" else (["--published-head", h] if h else [])
    return run("run", "--registry", str(reg), "--state", str(st), "--key", str(pem), "--now", str(now), *pos, *extra)


def ver(reg, st, pub, extra=()):
    return run("verify", "--registry", str(reg), "--state", str(st), "--witness-key", pub, *extra)


def tv_receipt(state, eh, pub, regkey=REGKEY, log_id="trace-registry/v1"):
    r = subprocess.run(["trace-verify", "receipt", "--checkpoint", str(state / "checkpoints" / f"{eh}.json"),
                        "--response", str(state / "receipts" / f"{eh}.post.json"), "--expected-log-id",
                        log_id, "--registry-key", regkey, "--witness-key", pub], capture_output=True, text=True)
    return r.returncode, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else {})


def snapshot(d):
    return {p.relative_to(d).as_posix(): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()} if d.exists() else {}


def leaves(st):
    return json.loads((st / "log.json").read_text())["leaves"]


with tempfile.TemporaryDirectory() as t:
    t = Path(t)
    k = Ed25519PrivateKey.generate()
    pem = t / "w.pem"
    pem.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    fork_enroll = ("--enroll", f"trace-registry/v1={FORKKEY}")  # the aggregator names its log trace-registry/v1

    print("[1] the real registry, witnessed as it grew (as of 2026-09-01, then 2026-09-25)")
    early = t / "early"; shutil.copytree(FIX, early, ignore=shutil.ignore_patterns("forks"))
    (early / "registry/2026/09/25.ndjson").unlink()
    st = t / "state"
    r = wit(early, st, pem)
    ok(r.returncode == 0 and "1 new receipt" in r.stdout, "first run witnesses checkpoint 1")
    r = wit(FIX, st, pem)
    ok(r.returncode == 0 and "1 new receipt" in r.stdout and "log size 2" in r.stdout, "second run witnesses checkpoint 2 only")
    L = leaves(st)
    ok([l["mmr_size"] for l in L] == [1, 3], "leaves are checkpoints 1 and 2, in order")
    ok([l["iat_signed"] for l in L] == [False, True], "iat signed for checkpoint 2 only (checkpoint 1 is past 30 days)")

    print("[2] the registry's own verifier accepts each receipt")
    for l in L:
        code, res = tv_receipt(st, l["entry_hash"], pub)
        ok(code == 0 and res.get("verified") is True, f"trace-verify receipt: checkpoint mmr_size {l['mmr_size']} verified")
        ok(res.get("limits", {}).get("grade_cryptographically_bound") is True, "  grade mmr-verified is signed and bound")
        ok(res.get("limits", {}).get("witness_time_established") is l["iat_signed"], f"  witness_time_established = {l['iat_signed']}")

    print("[3] receipts are final")
    before = snapshot(st)
    r = wit(FIX, st, pem, NOW + 3600)
    ok(r.returncode == 0 and "nothing new" in r.stdout and snapshot(st) == before, "a rerun adds nothing and changes no byte")

    print("[4] offline verify")
    v = ver(FIX, st, pub)
    ok(v.returncode == 0 and "2 receipt(s)" in v.stdout and "2 tree head(s)" in v.stdout, "receipts verify, tree heads signed and consistent")
    ok(ver(FIX, st, "00" * 32).returncode == 1, "the wrong witness key is refused")

    print("[5] a registry that is not the one witnessed")
    rb = t / "rollback"; shutil.copytree(FIX, rb, ignore=shutil.ignore_patterns("forks")); (rb / "registry/2026/09/25.ndjson").unlink()
    before = snapshot(st)
    r = wit(rb, st, pem, NOW + 7200)
    ok(r.returncode == 3 and "REFUSED" in r.stdout and snapshot(st) == before, "a registry that dropped a witnessed checkpoint: refused, state untouched")
    ok(ver(rb, st, pub).returncode == 1, "verify against it fails too")
    bad = t / "edited"; shutil.copytree(FIX, bad, ignore=shutil.ignore_patterns("forks"))
    p = bad / "registry/2026/09/01.ndjson"
    e = json.loads(p.read_text()); e["leaf_count"] += 1; p.write_text(json.dumps(e) + "\n")
    st2 = t / "state2"
    r = wit(bad, st2, pem)
    ok(r.returncode == 3 and not st2.exists(), "a quiet edit to a checkpointed entry: refused before anything is written")
    dup = t / "dup"; shutil.copytree(FIX, dup, ignore=shutil.ignore_patterns("forks"))
    p = dup / "registry/2026/09/25.ndjson"; p.write_text(p.read_text().replace('{"ts"', '{"leaf_count":9,"ts"', 1))
    r = wit(dup, t / "state_dup", pem)
    ok(r.returncode == 3 and "duplicate JSON key" in r.stdout, "a duplicate JSON key: refused (exit 3)")
    deep = t / "deep"; shutil.copytree(FIX, deep, ignore=shutil.ignore_patterns("forks"))
    (deep / "registry/2026/10/20").mkdir(parents=True); shutil.copy(FIX / "registry/2026/09/25.ndjson", deep / "registry/2026/10/20/x.ndjson")
    r = wit(deep, t / "state_deep", pem)
    ok(r.returncode == 3 and "outside registry/YYYY/MM/DD.ndjson" in r.stdout, "an .ndjson the layout does not allow: refused, not skipped")

    print("[6] a fork: one log, two histories under the same key")
    sf = t / "state_fork"
    r = wit(FORKS / "a", sf, pem, extra=fork_enroll)
    ok(r.returncode == 0 and "2 new receipt" in r.stdout, "log a: two checkpoints witnessed")
    before = snapshot(sf)
    r = wit(FORKS / "b", sf, pem, extra=fork_enroll)
    ok(r.returncode == 3 and snapshot(sf) == before, "fork b (valid on its own): refused, state untouched")
    sf2 = t / "state_fork2"
    r = wit(FORKS / "b", sf2, pem, extra=fork_enroll, head=None)
    ok(r.returncode == 3 and "only with --init" in r.stdout and not sf2.exists(), "a second, empty state under the same key without --init: refused")
    r = wit(FORKS / "a_ext", sf, pem, extra=fork_enroll, head="00" * 32)
    ok(r.returncode == 3 and "not the published one" in r.stdout, "a state whose last head is not the published one: refused")
    r = run("run", "--registry", str(FORKS / "a_ext"), "--state", str(sf), "--key", str(pem), "--now", str(NOW), "--init", *fork_enroll)
    ok(r.returncode == 3 and "--init on a state that already has leaves" in r.stdout, "--init on a state with leaves: refused")
    r = wit(FORKS / "a_back", t / "state_back", pem, extra=fork_enroll)
    ok(r.returncode == 3 and "earlier than the checkpoint before it" in r.stdout, "a checkpoint dated before the one it extends: refused")
    r = wit(FORKS / "a_ext", sf, pem, extra=fork_enroll)
    ok(r.returncode == 0 and "1 new receipt" in r.stdout and "log size 3" in r.stdout, "a genuine extension of a: its new checkpoint is witnessed")
    ok(ver(FORKS / "a_ext", sf, pub, fork_enroll).returncode == 0, "verify against the extension passes")
    ok(ver(FORKS / "b", sf, pub, fork_enroll).returncode == 1, "verify against the fork fails")
    for l in leaves(sf):
        code, res = tv_receipt(sf, l["entry_hash"], pub, FORKKEY)
        ok(code == 0 and res.get("verified") is True, f"  trace-verify receipt mmr_size {l['mmr_size']} verified")

    print("[7] crashes leave the previous state")
    sc = t / "state_crash"
    r = wit(FIX, sc, pem, 1757000000)  # 2026-09-04: after checkpoint 1, before checkpoint 2
    ok(r.returncode == 3 and not sc.exists(), "a clock before a checkpoint: refused before anything is written")
    r = wit(early, sc, pem)
    ok(r.returncode == 0, "a run that ended")
    before = snapshot(sc)
    stage = sc.with_name(sc.name + ".staging-crashed"); shutil.copytree(sc, stage); (stage / "junk").write_text("x")
    old = sc.with_name(sc.name + ".old")
    r = wit(early, sc, pem)
    ok(r.returncode == 0 and not stage.exists() and snapshot(sc) == before, "a leftover staging copy is discarded, the state is as it was")
    head_before = published_head(sc)
    os.rename(sc, old)
    ok(ver(early, sc, pub).returncode == 1, "verify on a state cut mid-swap fails, it does not read as empty")
    r = wit(early, sc, pem, head=head_before)
    ok(r.returncode == 0 and sc.exists() and not old.exists() and snapshot(sc) == before, "a swap cut between its two renames is restored")
    r = wit(FIX, sc, pem)
    ok(r.returncode == 0 and "1 new receipt" in r.stdout and ver(FIX, sc, pub).returncode == 0, "and the next run carries on")

    before = snapshot(sc)
    with open(sc.with_name(sc.name + ".lock"), "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        r = wit(FIX, sc, pem)
    ok(r.returncode == 3 and "another run holds" in r.stdout and snapshot(sc) == before, "a run while another holds the lock: refused, nothing touched")

    print("[8] verify catches what a run would never write")
    def tampered(name, mutate):
        s2 = t / f"tamper_{name}"; shutil.copytree(st, s2); mutate(s2)
        ok(ver(FIX, s2, pub).returncode == 1, name)
    L = leaves(st)
    eh2 = L[1]["entry_hash"]
    def swap_iat(s2):
        from scitt_cose.receipt import build_receipt
        tree = [l["entry_hash"] for l in L]
        rc = build_receipt(leaf_entry_hex=eh2, leaf_index=1, tree_entries_hex=tree, alg="EdDSA", log_private_key_pem=pem.read_bytes(), iat=NOW + 60, grade="mmr-verified")
        f = s2 / "receipts" / f"{eh2}.post.json"; d = json.loads(f.read_text()); d["receipt_b64"] = base64.b64encode(rc).decode(); f.write_text(json.dumps(d))
    tampered("a second, different receipt for a witnessed checkpoint", swap_iat)
    def other_tree(s2):
        from scitt_cose.receipt import build_receipt
        tree = [L[0]["entry_hash"], eh2, "00" * 32]
        rc = build_receipt(leaf_entry_hex=eh2, leaf_index=1, tree_entries_hex=tree, alg="EdDSA", log_private_key_pem=pem.read_bytes(), iat=NOW, grade="mmr-verified")
        f = s2 / "receipts" / f"{eh2}.post.json"; d = json.loads(f.read_text()); d.update(receipt_b64=base64.b64encode(rc).decode(), tree_size=3); f.write_text(json.dumps(d))
    tampered("a receipt over a tree that is not the witness log", other_tree)
    tampered("tree heads removed", lambda s2: (s2 / "tree_heads.ndjson").unlink())
    def truncate(s2):
        lg = json.loads((s2 / "log.json").read_text()); lg["leaves"] = lg["leaves"][:1]; (s2 / "log.json").write_text(json.dumps(lg))
        hs = (s2 / "tree_heads.ndjson").read_text().splitlines()[:1]; (s2 / "tree_heads.ndjson").write_text("\n".join(hs) + "\n")
    tampered("the log and its heads cut back by one leaf", truncate)
    tampered("an extra receipt file", lambda s2: (s2 / "receipts" / "0000.post.json").write_text("{}"))
    def head_edit(s2):
        f = s2 / "tree_heads.ndjson"; hs = f.read_text().splitlines(); h = json.loads(hs[-1]); h["timestamp"] = "2026-10-21T00:00:00Z"; hs[-1] = json.dumps(h); f.write_text("\n".join(hs) + "\n")
    tampered("a tree head edited", head_edit)
    def coord(s2):
        f = s2 / "receipts" / f"{eh2}.post.json"; d = json.loads(f.read_text()); d["tree_size"] = 3; f.write_text(json.dumps(d))
    tampered("receipt coordinates edited", coord)
    def meta(s2):
        lg = json.loads((s2 / "log.json").read_text()); lg["leaves"][1]["mmr_size"] = 999; (s2 / "log.json").write_text(json.dumps(lg))
    tampered("leaf metadata that the checkpoint does not say", meta)
    def extra_key(s2):
        lg = json.loads((s2 / "log.json").read_text()); lg["leaves"][1]["note"] = "x"; (s2 / "log.json").write_text(json.dumps(lg))
    tampered("an extra field in a leaf", extra_key)
    def when(s2):
        lg = json.loads((s2 / "log.json").read_text()); lg["leaves"][1]["witnessed_at"] = "2030-01-01T00:00:00Z"; (s2 / "log.json").write_text(json.dumps(lg))
    tampered("witnessed_at that is not the signed iat", when)
    moved = t / "moved"; shutil.copytree(FIX, moved, ignore=shutil.ignore_patterns("forks"))
    line = (moved / "registry/2026/09/25.ndjson").read_text()
    e = json.loads(line)
    (moved / "registry/2026/09/25.ndjson").write_text(json.dumps(dict(reversed(list(e.items())))) + "\n")
    ok(ver(moved, st, pub).returncode == 1, "a witnessed registry line re-encoded (same checkpoint): verify fails")
    r = wit(moved, st, pem, NOW + 60)
    ok(r.returncode == 3, "  and a run refuses it")
    ok(ver(FIX, st, pub).returncode == 0, "the untouched state still verifies")

    print("[9] late checkpoints and test-only flags")
    s3 = t / "state_late"
    r = wit(FIX, s3, pem, LATE)
    ok(r.returncode == 0 and [l["iat_signed"] for l in leaves(s3)] == [False, False], "past 30 days: receipts without iat")
    code, res = tv_receipt(s3, leaves(s3)[1]["entry_hash"], pub)
    ok(code == 0 and res["limits"]["witness_time_established"] is False, "  and still verify under trace-verify")
    env = {k: v for k, v in os.environ.items() if k != TEST_ENV}
    r = run("run", "--registry", str(FIX), "--state", str(t / "s_now"), "--key", str(pem), "--now", str(NOW), env=env)
    ok(r.returncode != 0 and not (t / "s_now").exists(), "--now outside the self test is refused")
    r = run("verify", "--registry", str(FIX), "--state", str(st), "--witness-key", pub, *fork_enroll, env=env)
    ok(r.returncode != 0, "--enroll outside the self test is refused")

print(f"\nregistry-witness selftest: {'PASS' if fails == 0 else 'FAIL'} ({fails} failure(s))")
sys.exit(1 if fails else 0)
