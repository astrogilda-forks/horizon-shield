#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Differential fuzzing for MUSUBI settle core v0 (workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md).

Every generated input is run through every implementation pinned in implementations.json. The outputs are projected
onto the eight core fields of section 9.1 and compared canonically. The first crash, timeout or disagreement stops
the run: the input directory, each implementation's raw output and the diff are written to findings/<input sha256>/
and the process exits non-zero.

    python3 settle_core_fuzz.py setup                     # the only step that uses the network: clone the pinned outside implementations
    python3 settle_core_fuzz.py verify                    # offline: check every pin (commit, tree, sha256 of the files run)
    python3 settle_core_fuzz.py selftest                  # proves the oracle can fail (flipped field, crash, timeout), and more
    python3 settle_core_fuzz.py run --count 3000          # or --minutes 20; --seed picks the stream
    python3 settle_core_fuzz.py gen --seed 1 --index 17 --out /tmp/case   # rebuild one input of a stream

Inputs are deterministic in (seed, index). The generator mutates the inputs of the public vectors in
settle-core-v0/vectors/ and builds new ones with the helpers of settle-core-v0/gen_vectors.py (seedkey, Chain,
synth_contract, ex, ...), re-signing part of them with the fixed synthetic test keys so they get past the signature
door. Any path containing "blind" is refused: held-out sets are never read, seeded from or written to.
"""
import argparse, base64, copy, hashlib, importlib.util, json, os, random, re, select, shutil, subprocess, sys, time, traceback

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
CONFIG = os.path.join(HERE, "implementations.json")
CORE = ["contract_sha256", "verdict", "status", "bond_outcome", "deviation_codes", "underspecified_reasons", "event_set", "dispositions"]
SETS = {"deviation_codes", "underspecified_reasons"}
SECTION = {"contract_sha256": "3.3, 9.1", "verdict": "12, 9.1", "status": "8.5", "bond_outcome": "9.3",
           "deviation_codes": "9.1, 10, 11, Appendix A", "underspecified_reasons": "9.1, Appendix A",
           "event_set": "8.1, 9.1", "dispositions": "9.2", "settlement_produced": "2.2"}
MISSING = "<missing>"


# ----------------------------------------------------------------------------------------------- small helpers
def refuse_blind(path):
    """Held-out sets are never read, seeded from or written to."""
    for p in (path, os.path.realpath(path)):
        if "blind" in p.lower():
            raise SystemExit("refused: the path %r contains 'blind'. This tool never touches held-out sets." % path)
    return path


def sha256_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr)


def tree_sha256(d):
    """sha256 over 'sha256 relpath' lines of every file under d, sorted by path: the name of an input."""
    lines = []
    for root, _, files in os.walk(d):
        for f in files:
            p = os.path.join(root, f)
            lines.append("%s %s" % (sha256_file(p), os.path.relpath(p, d).replace(os.sep, "/")))
    return hashlib.sha256("\n".join(sorted(lines, key=lambda l: l.split(" ", 1)[1])).encode()).hexdigest()


def git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def load_config(path=CONFIG):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def impl_dir(impl, impl_root):
    if impl["repo"] == "self":
        return REPO
    return os.path.join(impl_root, impl["dir"])


def check_pins(cfg, impl_root, names=None, quiet=False):
    """Every implementation: commit and tree (outside repos), sha256 of every file run. Returns a list of problems."""
    problems, facts = [], []
    for impl in cfg["implementations"]:
        if names and impl["name"] not in names:
            continue
        d = impl_dir(impl, impl_root)
        if not os.path.isdir(d):
            problems.append("%s: %s is missing (run setup)" % (impl["name"], d))
            continue
        if impl["repo"] != "self":
            try:
                head, tree = git(["rev-parse", "HEAD"], d), git(["rev-parse", "HEAD^{tree}"], d)
            except Exception as e:                                            # noqa: BLE001
                problems.append("%s: not a git checkout (%s)" % (impl["name"], e))
                continue
            if head != impl["commit"]:
                problems.append("%s: HEAD %s, pinned %s" % (impl["name"], head, impl["commit"]))
            if tree != impl["tree"]:
                problems.append("%s: tree %s, pinned %s" % (impl["name"], tree, impl["tree"]))
            dirty = git(["status", "--porcelain", "--untracked-files=no"], d)
            if dirty:
                problems.append("%s: tracked files modified:\n%s" % (impl["name"], dirty))
        for rel, want in sorted(impl["files_sha256"].items()):
            p = os.path.join(d, impl.get("subdir", ""), rel)
            got = sha256_file(p) if os.path.isfile(p) else None
            if got != want:
                problems.append("%s: %s sha256 %s, pinned %s" % (impl["name"], rel, got, want))
            facts.append("%-26s %s %s" % (impl["name"], want[:16], rel))
    if not quiet:
        for f in facts:
            print("pin ok? " + f if problems else "pin ok  " + f)
    return problems


# ----------------------------------------------------------------------------------------------- adapters (worker side)
def adapter_reference(impl, impl_root, opts):
    """settle_v1_16.settle_v1_16 as a library, read exactly as run_reference.settle_dir reads, projected by run_reference.core_fields."""
    base = os.path.join(REPO, impl["subdir"])
    scv0 = os.path.join(base, "settle-core-v0")
    sys.path.insert(0, base)
    sys.path.insert(0, scv0)
    import run_reference                                                      # noqa: E402
    settle, parse_strict = run_reference.load_reference(base)

    def run(vdir):
        rd = lambda p: parse_strict(open(p, encoding="utf-8").read())        # noqa: E731
        try:
            contract = rd(os.path.join(vdir, "contract.json"))
            view = rd(os.path.join(vdir, "view.json"))
            ed = os.path.join(vdir, "events")
            events = [rd(os.path.join(ed, f)) for f in sorted(os.listdir(ed))] if os.path.isdir(ed) else []
            nd = os.path.join(vdir, "nenrin")
            nenrin = [rd(os.path.join(nd, f)) for f in sorted(os.listdir(nd))] if os.path.isdir(nd) else None
            pp = os.path.join(vdir, "parent.json")
            parent = rd(pp) if os.path.isfile(pp) else None
        except Exception as e:                                                # noqa: BLE001  (2.2: no settlement)
            return {"kind": "no_settlement", "why": "%s: %s" % (type(e).__name__, str(e)[:300])}
        s = settle(contract, events, view, parent=parent, nenrin_records=nenrin or None)
        return {"kind": "settled", "core": run_reference.core_fields(s)}
    return run


def adapter_aeoess(impl, impl_root, opts):
    """impl/run_all.py run_one(<vector id>) with VEC pointed at the input's parent; projected as run_all.main writes out/<id>.json."""
    d = os.path.join(impl_dir(impl, impl_root), "impl")
    sys.path.insert(0, d)
    import run_all                                                            # noqa: E402

    def run(vdir):
        run_all.VEC = os.path.dirname(vdir)
        res = run_all.run_one(os.path.basename(vdir))
        proj = json.loads(run_all.sc.canonical({k: res[k] for k in run_all.FIELDS}))
        un = [k for k in CORE if isinstance(proj.get(k), str) and proj[k].startswith("UNASSESSED")]
        if un and all(isinstance(proj.get(k), str) and proj[k].startswith("UNASSESSED: input not readable") for k in CORE):
            return {"kind": "no_settlement", "why": proj["verdict"]}
        if un:
            return {"kind": "unassessed", "fields": un, "core": proj}
        return {"kind": "settled", "core": proj}
    return run


def adapter_kuangmi(impl, impl_root, opts):
    """settle-core-v0/settle_core_v0.py: load_vector(dir) then settle(contract, events, view, nenrin, parent), as its main() does."""
    p = os.path.join(impl_dir(impl, impl_root), "settle-core-v0", "settle_core_v0.py")
    spec = importlib.util.spec_from_file_location("settle_core_v0_kuangmi", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    want = bool(opts.get("have_crypto"))
    if want and not mod.HAVE_CRYPTO:
        raise SystemExit("kuangmi-bit with cryptography requested, but cryptography is not importable")
    mod.HAVE_CRYPTO = want                                                    # False: its RFC 8032 verifier on group arithmetic

    def run(vdir):
        try:
            contract, events, view, nenrin, parent = mod.load_vector(vdir)
        except Exception as e:                                                # noqa: BLE001
            return {"kind": "no_settlement", "why": "%s: %s" % (type(e).__name__, str(e)[:300])}
        got = mod.settle(contract, events, view, nenrin, parent)
        return {"kind": "settled", "core": json.loads(canon({k: got.get(k, MISSING) for k in CORE}))}
    return run


def adapter_selftest(kind):
    """Deliberately wrong shims around the reference, used only by selftest to prove that the oracle fails."""
    def make(impl, impl_root, opts):
        ref = adapter_reference(impl, impl_root, opts)

        def run(vdir):
            out = ref(vdir)
            if kind == "flip" and out["kind"] == "settled" and out["core"]["verdict"] == "within_grant":
                out["core"]["verdict"] = "deviation"                       # one field flipped
            if kind == "crash":
                raise RuntimeError("selftest shim: deliberate crash")
            if kind == "sleep":
                time.sleep(3600)
            return out
        return run
    return make


ADAPTERS = {"reference": adapter_reference, "aeoess": adapter_aeoess, "kuangmi": adapter_kuangmi,
            "selftest-flip": adapter_selftest("flip"), "selftest-crash": adapter_selftest("crash"),
            "selftest-sleep": adapter_selftest("sleep")}


def find_impl(cfg, name):
    for impl in cfg["implementations"]:
        if impl["name"] == name:
            return impl
    if name.startswith("selftest-"):
        ref = dict(find_impl(cfg, "reference"))
        ref.update(name=name, adapter=name)
        return ref
    raise SystemExit("no implementation named %r in %s" % (name, CONFIG))


def worker_main(a):
    cfg = load_config(a.config)
    impl = find_impl(cfg, a.worker)
    proto = os.fdopen(os.dup(1), "w", encoding="utf-8")
    os.dup2(2, 1)                                     # anything an implementation prints goes to stderr, never into the protocol
    sys.stdout = sys.stderr
    run = ADAPTERS[impl["adapter"]](impl, a.impl_root, impl.get("options") or {})
    proto.write(json.dumps({"kind": "ready", "python": sys.version.split()[0]}) + "\n")
    proto.flush()
    for line in sys.stdin:
        vdir = json.loads(line)["dir"]
        try:
            res = run(vdir)
        except BaseException:                                                 # noqa: BLE001
            res = {"kind": "crash", "error": traceback.format_exc()[-6000:]}
        try:
            text = json.dumps(res, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            text = json.dumps({"kind": "crash", "error": "output not serialisable: " + repr(res)[:2000]})
        proto.write(text + "\n")
        proto.flush()


# ----------------------------------------------------------------------------------------------- workers (harness side)
class Worker(object):
    def __init__(self, name, a, logdir):
        self.name, self.a, self.logdir, self.p, self.buf = name, a, logdir, None, b""
        self.start()

    def start(self):
        os.makedirs(self.logdir, exist_ok=True)
        err = open(os.path.join(self.logdir, self.name.replace("/", "_") + ".stderr"), "ab")
        cmd = [sys.executable, "-I", "-B", os.path.abspath(__file__), "--worker", self.name,
               "--config", self.a.config, "--impl-root", self.a.impl_root]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, cwd=self.logdir)
        self.buf = b""
        r = self.recv(time.time() + 120)
        if r.get("kind") != "ready":
            raise SystemExit("worker %s did not start: %s" % (self.name, r))
        self.python = r.get("python")

    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.kill()
            self.p.wait()

    def send(self, vdir):
        self.p.stdin.write((json.dumps({"dir": vdir}) + "\n").encode())
        self.p.stdin.flush()

    def recv(self, deadline):
        return recv_all({self.name: self}, deadline)[0][self.name]


def recv_all(workers, deadline):
    """Wait for one answer from each worker at once. Returns ({name: result}, {name: seconds until it answered})."""
    t0, out, secs = time.time(), {}, {}
    pending = dict(workers)
    for n, w in list(pending.items()):
        if b"\n" in w.buf:
            line, w.buf = w.buf.split(b"\n", 1)
            out[n], secs[n] = json.loads(line.decode("utf-8")), 0.0
            del pending[n]
    while pending:
        left = deadline - time.time()
        if left <= 0:
            for n, w in pending.items():
                w.stop()
                out[n], secs[n] = {"kind": "timeout"}, round(time.time() - t0, 3)
            break
        fds = {w.p.stdout.fileno(): n for n, w in pending.items()}
        r, _, _ = select.select(list(fds), [], [], left)
        for fd in r:
            n = fds[fd]
            w = pending[n]
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                code = w.p.wait()
                out[n], secs[n] = {"kind": "crash", "error": "worker exited with code %s (see logs/%s.stderr)" % (code, n)}, round(time.time() - t0, 3)
                del pending[n]
                continue
            w.buf += chunk
            if b"\n" in w.buf:
                line, w.buf = w.buf.split(b"\n", 1)
                out[n], secs[n] = json.loads(line.decode("utf-8")), round(time.time() - t0, 3)
                del pending[n]
    return out, secs


# ----------------------------------------------------------------------------------------------- the generator
class Gen(object):
    """Inputs deterministic in (seed, index). Uses gen_vectors.py helpers; never writes into the reference folder."""

    def __init__(self, cfg, vectors):
        refuse_blind(vectors)
        ref = find_impl(cfg, "reference")
        base = os.path.join(REPO, ref["subdir"])
        sys.path.insert(0, base)
        sys.path.insert(0, os.path.join(base, "settle-core-v0"))
        import gen_vectors as g                                               # noqa: E402
        self.g = g
        self.v0, self.v1, self.v11, self.v12, self.v16 = g.v0, g.v1, g.v11, g.v12, g.v16
        self.parse = g.parse_strict
        self.KEYS = {g.PP: g.KP, g.PC: g.KC, g.PW: g.KW, g.PS: g.KS}
        idx = json.load(open(os.path.join(vectors, "vectors.json"), encoding="utf-8"))
        self.seeds = []
        for v in idx["vectors"]:
            d = os.path.join(vectors, v["id"])
            self.seeds.append((v["id"], v["family"], d))
        self.vectors = vectors

    # --- reading a public vector into a case
    def load_case(self, vid, family, d):
        rd = lambda p: self.parse(open(p, encoding="utf-8").read())          # noqa: E731
        ed, nd, pp = os.path.join(d, "events"), os.path.join(d, "nenrin"), os.path.join(d, "parent.json")
        case = {"origin": "vector:" + vid, "family": family, "log": [],
                "contract": rd(os.path.join(d, "contract.json")), "view": rd(os.path.join(d, "view.json")),
                "events": [rd(os.path.join(ed, f)) for f in sorted(os.listdir(ed))] if os.path.isdir(ed) else [],
                "nenrin": [rd(os.path.join(nd, f)) for f in sorted(os.listdir(nd))] if os.path.isdir(nd) else None,
                "parent": rd(pp) if os.path.isfile(pp) else None, "has_parent": os.path.isfile(pp), "raw": {}}
        return case

    def synthkeys(self, case):
        c = case["contract"]
        if not isinstance(c, dict) or not isinstance(c.get("parties"), list):
            return False
        pubs = [p.get("public_key_ed25519_b64") for p in c["parties"] if isinstance(p, dict)]
        return self.g.PP in pubs and self.g.PC in pubs

    # --- signer bookkeeping: which fixed test key made each signature entry, recorded before any body mutation
    def mark_signers(self, case):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        for r in case["events"]:
            if not isinstance(r, dict) or r.get("schema") not in self.v12.RECORD_CONTEXT or not isinstance(r.get("signatures"), list):
                continue
            try:
                msg = self.v12.record_signing_bytes(r)
            except Exception:                                                 # noqa: BLE001
                continue
            marks = []
            for i, e in enumerate(r["signatures"]):
                if not isinstance(e, dict) or not isinstance(e.get("sig_b64"), str):
                    continue
                for pub in sorted(self.KEYS):
                    try:
                        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(e["sig_b64"]), msg)
                        marks.append([i, pub])
                        break
                    except (InvalidSignature, ValueError, TypeError):
                        pass
            r["__fuzz_signers"] = marks

    def resign_contract(self, c):
        g = self.g
        c["signatures"] = []
        for key, pub, dom in ((g.KP, g.PP, g.DOM_P), (g.KC, g.PC, g.DOM_C)):
            try:
                self.v0.sign_contract(c, key, pub, dom)
            except BaseException:                                             # noqa: BLE001  (SystemExit when the parties no longer allow it)
                pass
        return c

    def repair(self, case, rng):
        """Re-sign the contract, rebind and re-sign the records with the fixed test keys, re-anchor them on a fresh synthetic chain."""
        g = self.g
        old = case["orig_csha"]
        if isinstance(case["contract"], dict):
            if case.get("parent_touched") and isinstance(case["parent"], dict) and self.synthkeys({"contract": case["parent"]}):
                self.resign_contract(case["parent"])
            self.resign_contract(case["contract"])
            new = self.v0.contract_sha256(case["contract"])
        else:
            new = old
        for r in case["events"]:
            if not isinstance(r, dict):
                continue
            cr = r.get("contract_ref")
            if isinstance(cr, dict) and cr.get("contract_sha256") == old:
                cr["contract_sha256"] = new
            for a in r.get("approvals") if isinstance(r.get("approvals"), list) else []:
                if isinstance(a, dict) and a.get("contract_sha256") == old and isinstance(a.get("sig_b64"), str):
                    for key in (g.KP, g.KC):
                        try:
                            key.public_key().verify(base64.b64decode(a["sig_b64"]), self.v16.approval_v2_bytes(old, a))
                        except Exception:                                     # noqa: BLE001
                            continue
                        a["contract_sha256"] = new
                        a["sig_b64"] = base64.b64encode(key.sign(self.v16.approval_v2_bytes(new, a))).decode()
                        break
            marks = r.get("__fuzz_signers") or []
            if marks and r.get("schema") in self.v12.RECORD_CONTEXT and isinstance(r.get("signatures"), list):
                try:
                    msg = self.v12.record_signing_bytes({k: v for k, v in r.items() if k != "__fuzz_signers"})
                except Exception:                                             # noqa: BLE001
                    msg = None
                if msg is not None:
                    for i, pub in marks:
                        if i < len(r["signatures"]) and isinstance(r["signatures"][i], dict):
                            r["signatures"][i]["sig_b64"] = base64.b64encode(self.KEYS[pub].sign(msg)).decode()
        # re-anchor: keep each record's height where possible, one block per original height
        groups, tip0 = {}, None
        hs = [h.get("height") for h in (case["view"].get("headers") or []) if isinstance(h, dict)] if isinstance(case["view"], dict) and isinstance(case["view"].get("headers"), list) else []
        hs = [h for h in hs if isinstance(h, int) and not isinstance(h, bool)]
        tip0 = max(hs) if hs else None
        for i, r in enumerate(case["events"]):
            an = r.get("anchor") if isinstance(r, dict) else None
            if isinstance(an, dict) and isinstance(an.get("height"), int) and not isinstance(an.get("height"), bool):
                groups.setdefault(an["height"], []).append(i)
        ch = g.Chain()
        maxh = None
        for h in sorted(groups):
            nxt = g.H0 + len(ch.headers)
            if h > nxt:
                ch.pad(min(h - nxt, 40))
            recs = [{k: v for k, v in case["events"][i].items() if k not in ("anchor", "__fuzz_signers")} for i in groups[h]]
            proof0 = case["events"][groups[h][0]]["anchor"].get("proof")
            batch = len(recs) == 1 and isinstance(proof0, list) and proof0 and isinstance(proof0[0], dict) and proof0[0].get("op") == "hexlify"
            if batch:
                out = [ch.put_in_batch(recs[0], *g._batch(None))]
            else:
                out = ch.put(*recs)
                out = out if isinstance(out, list) else [out]
            for i, r in zip(groups[h], out):
                case["events"][i] = r
            maxh = g.H0 + len(ch.headers) - 1
        extra = (tip0 - max(groups)) if (tip0 is not None and groups) else rng.choice([0, 3, g.DEPTH])
        ch.pad(max(0, min(extra, 60)))
        case["view"] = ch.view()
        case["log"].append("repair: contract re-signed, records rebound and re-signed with the fixed test keys, re-anchored on a fresh chain (tip %d)" % (g.H0 + len(ch.headers) - 1))
        case["repaired"] = True

    # --- fresh scenarios built with gen_vectors helpers
    def fresh(self, rng, tag):
        g = self.g
        over, drop, top, log = {}, [], {}, []
        parent = None
        if rng.random() < 0.12:
            name, aover, adrop, atop, _why = rng.choice(g._AXES)
            c = g._child(name, aover, adrop, atop)
            parent = copy.deepcopy(g.PARENT_FULL)
            log.append("fresh child contract, parent axis %s" % name)
        else:
            if rng.random() < 0.4:
                over["conditional"] = copy.deepcopy(rng.choice([g.COND, g.COND + [{"action": "export", "requires": "principal_approval"}]]))
            if rng.random() < 0.25:
                over["expiry_height"] = g.CK + rng.randint(0, 6)
            if rng.random() < 0.3:
                over["witnesses"] = rng.choice([[{"name": "synthetic-witness", "public_key_ed25519_b64": g.PW}],
                                                [{"name": "synthetic-witness", "public_key_ed25519_b64": g.PW},
                                                 {"name": "synthetic-witness-b", "public_key_ed25519_b64": g.PS}],
                                                [{"name": "synthetic-witness", "public_key_ed25519_b64": g.PP}]])
            r = rng.random()
            if r < 0.2:
                over["revocation"] = {"effective_at": "delivery_ack", "ack_window": rng.randint(0, 4)}
            elif r < 0.3:
                over["revocation"] = {"effective_at": "anchor"}
            elif r < 0.35:
                drop.append("revocation")
            if rng.random() < 0.05:
                over["ordering"] = {"same_height": rng.choice(["record_sha256", None, "first_seen"])}
            if rng.random() < 0.2:
                over["authorized_actions"] = rng.choice([["read", "write"], ["read", "refund"], ["read", "Write"], []])
            if rng.random() < 0.15:
                over["delegation"] = {"allowed": ["delegate.synthetic.invalid"]}
                over["max_hops"] = rng.randint(0, 2)
            if rng.random() < 0.08:
                over["approval_policy"] = {"allow_unscoped": rng.choice([True, False])}
            if rng.random() < 0.2:
                over["finality"] = {"depth": rng.randint(1, 8), "max_target_bits": "207fffff"}
            if rng.random() < 0.15:
                top["bond"] = rng.choice([None, {"amount": 0, "currency": "JPY"}, {"amount": "1000", "currency": "JPY"},
                                          {"amount": -5, "currency": "JPY"}, {"amount": True, "currency": "JPY"},
                                          {"amount": 1, "currency": "JPY"}, {}, {"amount": 2 ** 53, "currency": "JPY"}])
            if rng.random() < 0.03:
                over["limits"] = {"max_actions": 3}                          # out of scope (section 1): not compared
            c = g.synth_contract(over, drop, sign=False, top=top, label="settle-core-fuzz " + tag)
            self.resign_contract(c)
            log.append("fresh contract grant %s drop %s top %s" % (sorted(over), drop, sorted(top)))
        ch = g.Chain()
        events, nenrin, revs = [], None, []
        csha = self.v0.contract_sha256(c)
        for b in range(rng.choice([0, 1, 1, 2, 2, 3, 4, 5])):
            ch.pad(rng.choice([0, 0, 0, 1, 2]))
            recs = [self.record(rng, c, ch, revs) for _ in range(rng.choice([1, 1, 1, 2, 3]))]
            if len(recs) == 1 and rng.random() < 0.08:
                put = [ch.put_in_batch(recs[0], *g._batch(None))]
            else:
                put = ch.put(*recs)
                put = put if isinstance(put, list) else [put]
            for r in put:
                if r.get("schema") == self.v1.REVOKE_SCHEMA:
                    revs.append(r)
            events.extend(put)
        if rng.random() < 0.06:
            events.append(self.record(rng, c, ch, revs))                    # bound but never anchored
        if any(isinstance(e, dict) and e.get("nenrin_ref") == g.W_OTHER_SHA for e in events) and rng.random() < 0.8:
            nenrin = [copy.deepcopy(g.W_OTHER)]
        elif rng.random() < 0.05:
            nenrin = [{"schema": "synthetic-walk-v0", "context": {"contract_sha256": csha}, "note": "fuzz walk"}]
        ch.pad(rng.choice([g.DEPTH, g.DEPTH, g.DEPTH, 0, 2, 5, 9]))
        log.append("fresh chain tip %d, %d records" % (g.H0 + len(ch.headers) - 1, len(events)))
        return {"origin": "fresh", "family": "fresh", "log": log, "contract": c, "view": ch.view(), "events": events,
                "nenrin": nenrin, "parent": parent, "has_parent": parent is not None, "raw": {}}

    def record(self, rng, c, ch, revs):
        g = self.g
        r = rng.random()
        if r < 0.1:
            key, role, by = rng.choice([(g.KP, "principal", "principal")] * 3 + [(g.KC, "principal", "principal"), (g.KP, "principal", "contractor")])
            return g.revocation(c, key=key, role=role, revoked_by=by)
        if r < 0.15 and revs:
            return g._ack(self.v1.rec_sha(rng.choice(revs)), c)
        if r < 0.17:
            return rng.choice([{}, {"schema": "a2a-unknown-v0"}, {"schema": g.EXEC_SCHEMA}])
        actions = rng.sample(["read", "read", "write", "delete", "refund", "payment", "export", "Read"], rng.choice([1, 1, 1, 2]))
        actions = list(dict.fromkeys(actions))
        approvals = []
        if "refund" in actions or "export" in actions or rng.random() < 0.1:
            h = g.H0 + len(ch.headers)
            for _ in range(rng.choice([1, 1, 2])):
                kind = rng.random()
                act = rng.choice(["refund", "refund", "export"])
                if kind < 0.6:
                    approvals.append(self.v16.sign_approval_v2(g.KP, c, act, h + rng.choice([-1, 0, 5, 100]), "%032x" % rng.getrandbits(128), rng.random() < 0.8))
                elif kind < 0.7:
                    approvals.append(self.v16.sign_approval_v2(g.KC, c, act, h + 100, "%032x" % rng.getrandbits(128)))
                elif kind < 0.8:
                    approvals.append(self.v12.sign_approval(g.KP, c, act))
                elif kind < 0.9:
                    approvals.append(self.v16.sign_approval_v2(g.KP, c, act, h + 100, g.NONCE(1)))       # a shared nonce: reuse
                else:
                    approvals.append(self.v16.sign_approval_v2(g.KP, g.BASE, act, h + 100, "%032x" % rng.getrandbits(128)))
        delegated = rng.choice([[]] * 8 + [["delegate.synthetic.invalid"], ["other.synthetic.invalid"]])
        extra = {}
        x = rng.random()
        if x < 0.4:
            extra["nenrin_ref"] = "%064x" % rng.getrandbits(256)
        elif x < 0.5:
            extra["nenrin_ref"] = g.W_OTHER_SHA
        if rng.random() < 0.05:
            extra["outcomes"] = {actions[0]: rng.choice(["ok", "error", 0.5, 2 ** 53, float("nan")])}
        signer = rng.choice(["contractor"] * 12 + ["witness", "stranger"])
        sign = rng.random() > 0.05
        return g.ex(c, actions=actions, approvals=approvals, delegated=delegated, extra=extra, signer=signer, sign=sign)

    # --- mutations
    def _recs(self, case, pred=None):
        return [i for i, r in enumerate(case["events"]) if isinstance(r, dict) and (pred is None or pred(r))]

    def body_mutation(self, rng, case):
        """Changes to signed content (records, contract, parent). Repair may re-sign afterwards."""
        g = self.g
        c = case["contract"] if isinstance(case["contract"], dict) else None
        execs = self._recs(case, lambda r: r.get("schema") == g.EXEC_SCHEMA)
        anyrec = self._recs(case)
        ops = []

        def m_actions():
            i = rng.choice(execs); r = case["events"][i]
            v = rng.choice([["read"], ["delete"], ["write"], ["refund"], ["read", "delete"], [], "read", [1], [None], ["read", "read"],
                            ["payment"], ["export"], ["READ"], ["read\t"], ["a" * 65], ["x" * 64]])
            r["performed_actions"] = copy.deepcopy(v)
            return "record %d performed_actions = %s" % (i, canon(v))

        def m_approvals():
            i = rng.choice(execs); r = case["events"][i]
            ap = r.get("approvals")
            if not isinstance(ap, list) or not ap or not isinstance(ap[0], dict):
                r["approvals"] = [self.v16.sign_approval_v2(g.KP, c if c else g.BASE, "refund", g.CK + 100, "%032x" % rng.getrandbits(128))]
                return "record %d gets a principal approval for refund" % i
            a = ap[0]
            k = rng.choice(["valid_until_height", "nonce", "single_use", "action", "by", "binding", "sig_b64", "extra", "dup", "contract_sha256"])
            if k == "valid_until_height":
                a[k] = rng.choice([a.get(k, 0) - 1 if isinstance(a.get(k), int) else 0, g.CK, g.CK + 1, -1, "800100", 1.5, None, 2 ** 53])
            elif k == "nonce":
                a[k] = rng.choice(["ab" * 15, "ab" * 17, "AB" * 16, "", None, g.NONCE(1)])
            elif k == "single_use":
                a[k] = rng.choice([False, True, 1, None, "true"])
            elif k == "action":
                a[k] = rng.choice(["read", "delete", "Refund", "export", None])
            elif k == "by":
                a[k] = rng.choice(["contractor", "witness", None])
            elif k == "binding":
                a[k] = rng.choice(["contract_id", None, "CONTRACT_SHA256"])
            elif k == "sig_b64":
                a.pop("sig_b64", None)
            elif k == "extra":
                a["note"] = "extra key"
            elif k == "dup":
                ap.append(copy.deepcopy(a))
            else:
                a[k] = "00" * 32
            return "record %d approvals[0] %s changed" % (i, k)

        def m_delegated():
            i = rng.choice(execs); r = case["events"][i]
            v = rng.choice([["delegate.synthetic.invalid"], ["other.synthetic.invalid"], [{"to": "x"}], "delegate.synthetic.invalid", [""], ["Delegate.Synthetic.Invalid"]])
            r["delegated_to"] = copy.deepcopy(v)
            return "record %d delegated_to = %s" % (i, canon(v))

        def m_extra_key():
            i = rng.choice(anyrec); r = case["events"][i]
            k = rng.choice(["failed_actions", "note", "outcomes", "x", "anchor_hint", "nenrin_ref", "schema", "signatures"])
            v = rng.choice([["delete"], "n", {"read": "ok"}, 1, None, [], {}])
            if k == "schema":
                v = rng.choice([g.EXEC_SCHEMA, self.v1.REVOKE_SCHEMA, self.v1.ACK_SCHEMA, "a2a-execution-v1", None])
            if k == "signatures":
                return None
            r[k] = copy.deepcopy(v)
            return "record %d key %s = %s" % (i, k, canon(v))

        def m_contract_ref():
            i = rng.choice(anyrec); r = case["events"][i]
            cr = r.get("contract_ref")
            if not isinstance(cr, dict):
                r["contract_ref"] = {"contract_id": "ab" * 16}
                return "record %d contract_ref replaced" % i
            k = rng.choice(["contract_id", "payload_digest", "contract_sha256", "drop_sha", "extra", "upper"])
            if k == "drop_sha":
                cr.pop("contract_sha256", None)
            elif k == "extra":
                cr["settlement_url"] = None
            elif k == "upper" and isinstance(cr.get("contract_sha256"), str):
                cr["contract_sha256"] = cr["contract_sha256"].upper()
            else:
                cr[k] = rng.choice(["00" * 32, "ab" * 16, "ab" * 31, "", None, ("ab" * 32) + "\n"])
            return "record %d contract_ref %s changed" % (i, k)

        def m_numbers():
            i = rng.choice(anyrec); r = case["events"][i]
            v = rng.choice([0.5, float("nan"), float("inf"), float("-inf"), 2 ** 53, -(2 ** 53), 2 ** 53 - 1, -0.0, 1e300, True, 1.0])
            r[rng.choice(["outcomes", "score"])] = {"read": v} if rng.random() < 0.5 else v
            return "record %d carries the number %r" % (i, v)

        def m_revoke():
            cc = c if c else g.BASE
            key, role, by = rng.choice([(g.KP, "principal", "principal")] * 3 + [(g.KC, "principal", "principal"), (g.KP, "principal", "contractor")])
            rv = g.revocation(cc, key=key, role=role, revoked_by=by)
            if anyrec and rng.random() < 0.8:
                src = case["events"][rng.choice(anyrec)]
                if isinstance(src.get("anchor"), dict):
                    rv["anchor"] = copy.deepcopy(src["anchor"])
            self.mark_signers({"events": [rv]})
            case["events"].insert(rng.randint(0, len(case["events"])), rv)
            return "revocation inserted (key %s, revoked_by %s)" % ("principal" if key is g.KP else "contractor", by)

        def m_revoked_by():
            rs = self._recs(case, lambda r: r.get("schema") == self.v1.REVOKE_SCHEMA)
            if not rs:
                return None
            i = rng.choice(rs)
            case["events"][i]["revoked_by"] = rng.choice(["contractor", "witness", None, "Principal"])
            return "record %d revoked_by changed" % i

        def m_grant():
            gr = c.get("grant") if c else None
            if not isinstance(gr, dict):
                return None
            k = rng.choice(["expiry_height", "conditional", "authorized_actions", "prohibited_actions", "finality", "ack_window",
                            "witnesses", "approval_policy", "ordering", "max_hops", "delegation", "data_access", "privacy",
                            "limits", "extra", "float"])
            if k == "expiry_height":
                gr[k] = rng.choice([g.CK, g.CK + 1, g.CK + 2, 0, -1, None, "800002", 1.5, 2 ** 53])
            elif k == "conditional":
                gr[k] = copy.deepcopy(rng.choice([[], g.COND, [{"action": "refund", "requires": "witness_approval"}], [{"action": "read", "requires": "principal_approval"}], {}, None]))
            elif k in ("authorized_actions", "prohibited_actions"):
                gr[k] = copy.deepcopy(rng.choice([["read"], ["read", "write"], [], ["delete"], ["read", "delete"], ["read", ""], "read", None]))
            elif k == "finality":
                gr[k] = copy.deepcopy(rng.choice([{"depth": 1, "max_target_bits": "207fffff"}, {"depth": 0, "max_target_bits": "207fffff"},
                                                  {"depth": "6", "max_target_bits": "207fffff"}, {"depth": 6, "max_target_bits": "1d00ffff"},
                                                  {"depth": 6, "max_target_bits": "207FFFFF"}, {"depth": 6}, {"depth": 9, "max_target_bits": "207fffff"},
                                                  {"depth": 6, "max_target_bits": "207fffff", "extra": 1}]))
            elif k == "ack_window":
                gr["revocation"] = copy.deepcopy(rng.choice([{"effective_at": "delivery_ack", "ack_window": rng.randint(0, 5)}, {"effective_at": "delivery_ack"},
                                                             {"effective_at": "anchor"}, {"effective_at": "never"}, {"effective_at": "delivery_ack", "ack_window": -1}]))
            elif k == "witnesses":
                gr[k] = copy.deepcopy(rng.choice([[], [{"name": "synthetic-witness", "public_key_ed25519_b64": g.PW}],
                                                  [{"name": "w", "public_key_ed25519_b64": g.PW}, {"name": "w", "public_key_ed25519_b64": g.PS}],
                                                  [{"name": "w", "public_key_ed25519_b64": g.PC}], [{"name": "w", "public_key_ed25519_b64": g.PW[:-4]}]]))
            elif k == "approval_policy":
                gr[k] = copy.deepcopy(rng.choice([{"allow_unscoped": True}, {"allow_unscoped": False}, {}, None,
                                                  {"allow_unscoped": False, "approvers": [{"name": "a", "public_key_ed25519_b64": g.PW, "actions": ["refund"]}]}]))
            elif k == "ordering":
                gr[k] = copy.deepcopy(rng.choice([{"same_height": "record_sha256"}, {"same_height": None}, {}, None]))
            elif k == "max_hops":
                gr[k] = rng.choice([0, 1, 2, -1, None, 1.0])
            elif k == "delegation":
                gr[k] = copy.deepcopy(rng.choice([{"allowed": ["delegate.synthetic.invalid"]}, {"allowed": []}, {}, None, {"allowed": "x"}]))
            elif k == "data_access":
                gr[k] = copy.deepcopy(rng.choice([["public_endpoint"], [], None]))
            elif k == "privacy":
                gr[k] = rng.choice(["no_external_retention", "external_retention_allowed", None])
            elif k == "limits":
                gr[k] = rng.choice([{"max_actions": 1}, None])                  # carried only when not null (section 1)
            elif k == "extra":
                gr["budget"] = {"amount": rng.choice([0, 100, -1])}
            else:
                gr["max_hops"] = rng.choice([float("nan"), 0.5, 2 ** 53])
            return "contract grant %s changed" % k

        def m_contract_top():
            if not c:
                return None
            k = rng.choice(["bond", "lower_bound", "contract_id", "nonce", "payload_digest", "parties", "extra", "requirements", "agreed_at", "parent_ref"])
            if k == "bond":
                c["bond"] = copy.deepcopy(rng.choice([None, {"amount": 0}, {"amount": "1000"}, {"amount": -1}, {"amount": True}, {"amount": 1.5},
                                                      {}, {"amount": 1}, [], 5, {"amount": 2 ** 53 - 1, "currency": "JPY"}]))
            elif k == "lower_bound" and isinstance(c.get("lower_bound"), dict):
                lb = c["lower_bound"]
                j = rng.choice(["height", "hash", "kind"])
                lb[j] = rng.choice({"height": [lb.get("height", 0) + 1 if isinstance(lb.get("height"), int) else 1, 0, "800001", None],
                                    "hash": ["00" * 32, "00" * 31, None, (lb.get("hash") or "").upper()],
                                    "kind": ["bitcoin_header", None]}[j])
            elif k in ("contract_id", "nonce"):
                c[k] = rng.choice(["ab" * 16, "ab" * 15 + "a", "ab" * 32, "AB" * 16, "", None])
            elif k == "payload_digest" and isinstance(c.get("task"), dict):
                c["task"]["payload_digest"] = rng.choice(["00" * 32, "00" * 16, None])
            elif k == "parties" and isinstance(c.get("parties"), list) and len(c["parties"]) == 2:
                j = rng.choice(["swap_roles", "extra", "key"])
                if j == "swap_roles":
                    a, b = c["parties"]
                    if isinstance(a, dict) and isinstance(b, dict):
                        a["role"], b["role"] = b.get("role"), a.get("role")
                elif j == "extra" and isinstance(c["parties"][0], dict):
                    c["parties"][0]["note"] = "x"
                elif isinstance(c["parties"][1], dict):
                    c["parties"][1]["public_key_ed25519_b64"] = g.PS
            elif k == "extra":
                c["memo"] = "extra top-level key"
            elif k == "requirements":
                c["requirements"] = copy.deepcopy(rng.choice([{}, {"admission": None}, {"admission": {"x": 1}}, None, {"spine": None}]))
            elif k == "agreed_at":
                c["agreed_at"] = rng.choice(["2026-10-17T00:00:00+00:00", "", None, 0])
            else:
                c["parent_contract"] = {"contract_id": c.get("contract_id"), "settlement_url": None}
            return "contract %s changed" % k

        def m_parent():
            p = case["parent"]
            if not isinstance(p, dict) or not isinstance(p.get("grant"), dict):
                return None
            gr = p["grant"]
            k = rng.choice(["prohibited_actions", "expiry_height", "max_hops", "witnesses", "authorized_actions", "revocation"])
            gr[k] = copy.deepcopy(rng.choice({"prohibited_actions": [["delete"], ["delete", "payment", "write"], []],
                                              "expiry_height": [999999, 1000001, None], "max_hops": [1, 3, 0],
                                              "witnesses": [[]], "authorized_actions": [["read", "write"], []],
                                              "revocation": [{"effective_at": "anchor"}, {"effective_at": "delivery_ack", "ack_window": 9}]}[k]))
            case["parent_touched"] = True
            return "parent grant %s changed (narrowing or widening)" % k

        if execs:
            ops += [m_actions] * 3 + [m_approvals] * 2 + [m_delegated]
        if anyrec:
            ops += [m_extra_key, m_contract_ref, m_numbers]
        ops += [m_revoke, m_revoked_by]
        if c:
            ops += [m_grant] * 3 + [m_contract_top] * 2
        if case["parent"] is not None:
            ops += [m_parent] * 2
        for _ in range(4):
            d = rng.choice(ops)()
            if d:
                return d
        return None

    def post_mutation(self, rng, case):
        """Changes to unsigned parts: anchors, the event list, the view, signatures, the parent and nenrin inputs."""
        g = self.g
        ev = case["events"]
        anch = self._recs(case, lambda r: isinstance(r.get("anchor"), dict))
        signed = self._recs(case, lambda r: isinstance(r.get("signatures"), list) and r["signatures"])
        view = case["view"]
        heads = view.get("headers") if isinstance(view, dict) and isinstance(view.get("headers"), list) else None
        ops = []

        def a_height():
            i = rng.choice(anch); a = ev[i]["anchor"]; h = a.get("height")
            a["height"] = rng.choice([h + d for d in (-2, -1, 1, 2, 10, -100)] if isinstance(h, int) and not isinstance(h, bool) else [800003]
                                     + [str(h), None, -1, 0, True, float(h) if isinstance(h, int) else 1.5, 2 ** 53])
            return "record %d anchor.height = %r" % (i, a["height"])

        def a_swap():
            if len(anch) < 2:
                return None
            i, j = rng.sample(anch, 2)
            ev[i]["anchor"], ev[j]["anchor"] = ev[j]["anchor"], ev[i]["anchor"]
            return "anchors of records %d and %d swapped" % (i, j)

        def a_drop():
            i = rng.choice(anch); ev[i].pop("anchor")
            return "record %d anchor removed" % i

        def a_extra():
            i = rng.choice(anch); ev[i]["anchor"][rng.choice(["note", "tx", "proof_format"])] = rng.choice(["x", 1, None])
            return "record %d anchor extra key" % i

        def a_hash():
            i = rng.choice(anch); a = ev[i]["anchor"]; bh = a.get("block_hash") if isinstance(a.get("block_hash"), str) else "00" * 32
            other = [h.get("hex") for h in heads if isinstance(h, dict)] if heads else []
            v = rng.choice([bh[:-2], bh + "0", bh.upper(), bh + "\n", " " + bh, "00" * 32, None, 5,
                            (hashlib.sha256(bytes.fromhex(rng.choice(other))).digest()[::-1].hex() if other and all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{160}", x) for x in other[:1]) else bh)])
            a["block_hash"] = v
            return "record %d anchor.block_hash = %r" % (i, v if not isinstance(v, str) else v[:20] + "..")

        def a_proof():
            i = rng.choice(anch); a = ev[i]["anchor"]; p = a.get("proof")
            if not isinstance(p, list) or not p:
                a["proof"] = rng.choice([[], None, {}])
                return "record %d anchor.proof replaced" % i
            j = rng.randrange(len(p)); op = p[j]
            k = rng.choice(["flip", "odd", "upper", "unknown_op", "drop", "extra", "dup", "empty", "nonlist"])
            if k == "flip" and isinstance(op, dict) and isinstance(op.get("hex"), str) and op["hex"]:
                op["hex"] = ("0" if op["hex"][0] != "0" else "1") + op["hex"][1:]
            elif k == "odd" and isinstance(op, dict) and isinstance(op.get("hex"), str):
                op["hex"] = op["hex"] + "a"
            elif k == "upper" and isinstance(op, dict) and isinstance(op.get("hex"), str):
                op["hex"] = op["hex"].upper()
            elif k == "unknown_op" and isinstance(op, dict):
                op["op"] = rng.choice(["sha512", "ripemd160", "Sha256", "", None])
            elif k == "drop":
                p.pop(j)
            elif k == "extra" and isinstance(op, dict):
                op["note"] = 1
            elif k == "dup":
                p.insert(j, copy.deepcopy(op))
            elif k == "empty":
                p.insert(j, {"op": rng.choice(["append", "prepend"]), "hex": ""})
            else:
                a["proof"] = {"0": op}
            return "record %d anchor.proof[%d] %s" % (i, j, k)

        def e_drop():
            if not ev:
                return None
            i = rng.randrange(len(ev)); ev.pop(i)
            return "event %d dropped" % i

        def e_dup():
            if not ev:
                return None
            i = rng.randrange(len(ev)); ev.insert(rng.randint(0, len(ev)), copy.deepcopy(ev[i]))
            return "event %d duplicated" % i

        def e_dup_shift():
            if not anch:
                return None
            i = rng.choice(anch); r = copy.deepcopy(ev[i])
            if isinstance(r["anchor"].get("height"), int):
                r["anchor"]["height"] += rng.choice([1, -1, 2])
            ev.append(r)
            return "event %d copied with a shifted anchor height" % i

        def e_order():
            if len(ev) < 2:
                return None
            if rng.random() < 0.5:
                ev.reverse()
                return "events reversed (file order)"
            rng.shuffle(ev)
            return "events shuffled (file order)"

        def e_junk():
            v = rng.choice([{}, [], "x", 7, None, {"schema": g.EXEC_SCHEMA}, {"schema": "a2a-execution-v0", "signatures": "x"}, True])
            ev.insert(rng.randint(0, len(ev)), copy.deepcopy(v))
            return "junk event %s inserted" % canon(v)

        def e_junk_sig():
            if not signed:
                return None
            i = rng.choice(signed); r = copy.deepcopy(ev[i])
            r["signatures"].append(rng.choice([{"role": "observer", "sig_b64": "junk"}, {"role": "contractor", "sig_b64": ""}, "x", None]))
            ev.append(r)
            return "copy of record %d with a junk signature entry appended" % i

        def s_sig():
            i = rng.choice(signed); s = ev[i]["signatures"]; j = rng.randrange(len(s)); e = s[j]
            if not isinstance(e, dict):
                return None
            k = rng.choice(["truncate", "malleate", "role", "extra", "drop_all", "nopad", "lastchar", "witness_name", "key_name"])
            sb = e.get("sig_b64") if isinstance(e.get("sig_b64"), str) else ""
            if k == "truncate":
                e["sig_b64"] = sb[:-4]
            elif k == "malleate" and len(sb) == 88:
                try:
                    e["sig_b64"] = g.malleate(sb)
                except Exception:                                             # noqa: BLE001
                    return None
            elif k == "role":
                e["role"] = rng.choice(["principal", "witness", "contractor", "Contractor", None])
            elif k == "extra":
                e["note"] = "x"
            elif k == "drop_all":
                ev[i]["signatures"] = []
            elif k == "nopad":
                e["sig_b64"] = sb.rstrip("=")
            elif k == "lastchar" and len(sb) >= 3:
                alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                c0 = sb[-3]
                if c0 in alph:
                    e["sig_b64"] = sb[:-3] + alph[(alph.index(c0) & ~3) | rng.randint(1, 3)] + sb[-2:]
            elif k == "witness_name":
                e["witness_name"] = rng.choice(["synthetic-witness", "nobody", None])
            else:
                e["signature"] = e.pop("sig_b64", "")
            return "record %d signatures[%d] %s" % (i, j, k)

        def v_mut():
            k = rng.choice(["truncate", "drop_ck", "drop_mid", "dup", "swap", "flip", "newline", "upper", "height_str", "extra", "header_extra", "empty", "notlist"])
            if k == "truncate" and len(heads) > 2:
                n = rng.randint(1, min(8, len(heads) - 1)); del heads[-n:]
                return "view: last %d headers dropped" % n
            if k == "drop_ck":
                ck = case["contract"].get("lower_bound", {}).get("height") if isinstance(case["contract"], dict) and isinstance(case["contract"].get("lower_bound"), dict) else None
                view["headers"] = [h for h in heads if not (isinstance(h, dict) and h.get("height") == ck)]
                return "view: checkpoint header removed"
            if k == "drop_mid" and len(heads) > 3:
                heads.pop(rng.randrange(1, len(heads) - 1)); return "view: a middle header removed"
            if k == "dup" and heads:
                j = rng.randrange(len(heads)); heads.insert(j, copy.deepcopy(heads[j])); return "view: header %d duplicated" % j
            if k == "swap" and len(heads) > 2:
                j = rng.randrange(len(heads) - 1); heads[j], heads[j + 1] = heads[j + 1], heads[j]; return "view: headers %d and %d swapped" % (j, j + 1)
            hd = rng.choice(heads) if heads else None
            if not isinstance(hd, dict):
                return None
            hx = hd.get("hex") if isinstance(hd.get("hex"), str) else ""
            if k == "flip" and hx:
                p = rng.randrange(len(hx)); hd["hex"] = hx[:p] + ("0" if hx[p] != "0" else "1") + hx[p + 1:]; return "view: one header hex digit changed"
            if k == "newline":
                hd["hex"] = hx + "\n"; return "view: header hex trailing newline"
            if k == "upper":
                hd["hex"] = hx.upper(); return "view: header hex uppercase"
            if k == "height_str":
                hd["height"] = rng.choice([str(hd.get("height")), None, -1, (hd.get("height") or 0) + 1 if isinstance(hd.get("height"), int) else 0]); return "view: header height changed to %r" % hd["height"]
            if k == "extra":
                view["note"] = "x"; return "view: extra top-level key"
            if k == "header_extra":
                hd["hash"] = "00" * 32; return "view: header extra key"
            if k == "empty":
                view["headers"] = []; return "view: no headers"
            if k == "notlist":
                view["headers"] = {"0": hd}; return "view: headers not a list"
            return None

        def c_sig():
            c = case["contract"]
            if not isinstance(c, dict) or not isinstance(c.get("signatures"), list) or not c["signatures"]:
                return None
            k = rng.choice(["flip", "drop", "extra_key", "dup", "domain"])
            s = c["signatures"]
            e = s[rng.randrange(len(s))]
            if k == "flip" and isinstance(e, dict) and isinstance(e.get("signature"), str) and e["signature"]:
                e["signature"] = ("A" if e["signature"][0] != "A" else "B") + e["signature"][1:]
            elif k == "drop":
                s.pop()
            elif k == "extra_key" and isinstance(e, dict):
                e["note"] = "x"
            elif k == "dup":
                s.append(copy.deepcopy(e))
            elif isinstance(e, dict):
                e["domain"] = "other.synthetic.invalid"
            return "contract signature %s" % k

        def p_mut():
            k = rng.choice(["drop", "add", "break"])
            if k == "drop" and case["has_parent"]:
                case["parent"], case["has_parent"] = None, False
                return "parent.json removed"
            if k == "add":
                case["parent"], case["has_parent"] = copy.deepcopy(rng.choice([g.PARENT_FULL, g.BASE, case["contract"]])), True
                return "parent.json supplied"
            if k == "break" and isinstance(case["parent"], dict) and isinstance(case["parent"].get("signatures"), list) and case["parent"]["signatures"]:
                e = case["parent"]["signatures"][0]
                if isinstance(e, dict) and isinstance(e.get("signature"), str):
                    e["signature"] = ("A" if e["signature"][0] != "A" else "B") + e["signature"][1:]
                    return "parent signature broken"
            return None

        def n_mut():
            k = rng.choice(["drop", "junk", "dup", "other"])
            if k == "drop" and case["nenrin"]:
                case["nenrin"] = None; return "nenrin removed"
            if k == "junk":
                case["nenrin"] = (case["nenrin"] or []) + [rng.choice([{}, "x", 1, {"schema": "synthetic-walk-v0", "score": 0.5}])]; return "junk nenrin record added"
            if k == "dup" and case["nenrin"]:
                case["nenrin"] = case["nenrin"] + [copy.deepcopy(case["nenrin"][0])]; return "nenrin record duplicated"
            if k == "other":
                case["nenrin"] = (case["nenrin"] or []) + [copy.deepcopy(g.W_OTHER)]; return "nenrin walk under other terms added"
            return None

        if anch:
            ops += [a_height] * 3 + [a_swap, a_drop, a_extra, a_hash] + [a_proof] * 2 + [e_dup_shift]
        ops += [e_drop, e_dup, e_order, e_junk]
        if signed:
            ops += [e_junk_sig] + [s_sig] * 2
        if heads is not None:
            ops += [v_mut] * 3
        ops += [c_sig, p_mut, n_mut]
        for _ in range(4):
            d = rng.choice(ops)()
            if d:
                return d
        return None

    # --- raw (byte level) mutations of one serialised file
    def raw_mutation(self, rng, files):
        names = sorted(files)
        name = rng.choice(names)
        t = files[name]
        k = rng.choice(["int_token", "int_token", "dup_key", "bom", "trailing", "pretty", "bad_utf8", "lone_surrogate",
                        "escaped_key", "nul_escape", "deep", "whitespace_tail"])
        if k == "int_token":
            ms = list(re.finditer(rb"(?<=[:\[,])-?\d+(?=[,\]\}])", t))
            if not ms:
                return None
            m = rng.choice(ms)
            v = m.group(0)
            rep = rng.choice([v + b".0", v + b"e0", b"0" + v, b"-0", b"1E400", b"NaN", b"nan", b"+" + v, b"Infinity", b"-Infinity",
                              b"9" * 4301, b"9007199254740993", b"-9007199254740993", v + b".5", b"1.0e2"])
            files[name] = t[:m.start()] + rep + t[m.end():]
            return "raw %s: number %s -> %s" % (name, v[:20].decode(), rep[:20].decode())
        if k == "dup_key":
            m = re.search(rb'\{"([^"\\]{1,40})":', t)
            if not m:
                return None
            files[name] = t[:m.end() - len(m.group(1)) - 3] + b'"' + m.group(1) + b'":null,' + t[m.end() - len(m.group(1)) - 3:]
            return "raw %s: duplicate key %s" % (name, m.group(1).decode())
        if k == "bom":
            files[name] = b"\xef\xbb\xbf" + t; return "raw %s: UTF-8 BOM" % name
        if k == "trailing":
            files[name] = t + rng.choice([b"x", b"{}", b",", b"]"]); return "raw %s: trailing garbage" % name
        if k == "whitespace_tail":
            files[name] = t + rng.choice([b"\n", b" \r\n", b"\t"]); return "raw %s: trailing whitespace (valid JSON)" % name
        if k == "pretty":
            try:
                files[name] = json.dumps(self.parse(t.decode("utf-8")), indent=2, ensure_ascii=True).encode()
            except Exception:                                                 # noqa: BLE001
                return None
            return "raw %s: pretty printed with ASCII escapes (same values)" % name
        ms = list(re.finditer(rb'"([a-z_]{2,30})":"([^"\\]{1,60})"', t))
        if k in ("bad_utf8", "lone_surrogate", "nul_escape") and ms:
            m = rng.choice(ms)
            ins = {"bad_utf8": b"\xff", "lone_surrogate": b"\\ud800", "nul_escape": b"\\u0000"}[k]
            files[name] = t[:m.end(2)] + ins + t[m.end(2):]
            return "raw %s: %s inside the value of %s" % (name, k, m.group(1).decode())
        if k == "escaped_key" and ms:
            m = rng.choice(ms)
            key = m.group(1)
            files[name] = t[:m.start(1)] + b"\\u%04x" % key[0] + key[1:] + t[m.end(1):]
            return "raw %s: key %s written with a unicode escape (same value)" % (name, key.decode())
        if k == "deep" and name.startswith("events/"):
            n = rng.choice([511, 512, 513, 600])
            files[name] = b"[" * n + b"]" * n
            return "raw %s: replaced by %d nested arrays" % (name, n)
        return None

    # --- one input
    def make(self, seed, index):
        rng = random.Random("settle-core-fuzz:%s:%d" % (seed, index))
        g = self.g
        if rng.random() < 0.4:
            case = self.fresh(rng, "%s/%d" % (seed, index))
        else:
            vid, fam, d = rng.choice(self.seeds)
            case = self.load_case(vid, fam, d)
        case["orig_csha"] = self.v0.contract_sha256(case["contract"]) if isinstance(case["contract"], dict) else None
        self.mark_signers(case)
        nb = rng.choice([0, 1, 1, 1, 2, 3]) if case["origin"] != "fresh" else rng.choice([0, 0, 1, 1, 2])
        npost = rng.choice([0, 0, 1, 1, 2]) if case["origin"] != "fresh" else rng.choice([0, 0, 0, 1, 1, 2])
        if case["origin"] != "fresh" and nb == 0 and npost == 0:
            npost = 1
        for _ in range(nb):
            dsc = self.body_mutation(rng, case)
            if dsc:
                case["log"].append(dsc)
        if self.synthkeys(case) and (case["origin"] != "fresh" or nb) and rng.random() < 0.6:
            self.repair(case, rng)
        for _ in range(npost):
            dsc = self.post_mutation(rng, case)
            if dsc:
                case["log"].append(dsc)
        files = self.serialise(case)
        if rng.random() < 0.12:
            dsc = self.raw_mutation(rng, files)
            if dsc:
                case["log"].append(dsc)
        return case, files

    def serialise(self, case):
        canonical = self.g.canonical

        def clean(o):
            if isinstance(o, dict):
                return {k: clean(v) for k, v in o.items() if k != "__fuzz_signers"}
            if isinstance(o, list):
                return [clean(v) for v in o]
            return o
        out = {"contract.json": canonical(clean(case["contract"])).encode("utf-8"),
               "view.json": canonical(clean(case["view"])).encode("utf-8")}
        for i, e in enumerate(case["events"]):
            out["events/e%02d.json" % i] = canonical(clean(e)).encode("utf-8")
        for i, w in enumerate(case["nenrin"] or []):
            out["nenrin/n%02d.json" % i] = canonical(clean(w)).encode("utf-8")
        if case["has_parent"]:
            out["parent.json"] = canonical(clean(case["parent"])).encode("utf-8")
        return out


def write_input(files, d):
    refuse_blind(d)
    if os.path.isdir(d):
        shutil.rmtree(d)
    for rel, b in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(b)
    os.makedirs(os.path.join(d, "events"), exist_ok=True)        # an empty events/ is the same as none for every reader


def out_of_scope(contract_bytes, parse):
    """Section 1: a contract carrying one of these keys has no defined result; such inputs are run but not compared."""
    try:
        c = parse(contract_bytes.decode("utf-8"))
    except Exception:                                                         # noqa: BLE001
        return False
    if not isinstance(c, dict):
        return False
    req, gr = c.get("requirements"), c.get("grant")
    if isinstance(req, dict) and ("spine" in req or "convergence" in req or req.get("admission") is not None):
        return True
    if isinstance(gr, dict):
        if gr.get("limits") is not None:
            return True
        ap = gr.get("approval_policy")
        if isinstance(ap, dict) and isinstance(ap.get("approvers"), list) and ap["approvers"]:
            ok = all(isinstance(a, dict) and isinstance(a.get("name"), str) and a.get("name") and isinstance(a.get("public_key_ed25519_b64"), str)
                     and isinstance(a.get("actions"), list) and a["actions"] for a in ap["approvers"])
            if ok:
                return True                         # a well formed list is carried (4.1 rule 10 decides the details; a near miss is compared)
    return False


# ----------------------------------------------------------------------------------------------- the oracle
def normalise(core):
    if not isinstance(core, dict):
        return {k: MISSING for k in CORE}
    out = {}
    for k in CORE:
        v = core.get(k, MISSING)
        if k in SETS and isinstance(v, list) and all(isinstance(x, str) for x in v):
            v = sorted(set(v))
        out[k] = v
    return out


def compare(results):
    """results: {impl: raw}. Returns (comparable, diff) where diff lists the fields on which comparable implementations differ."""
    comp = {n: r for n, r in results.items() if r["kind"] in ("settled", "no_settlement")}
    keys = {n: ("no_settlement" if r["kind"] == "no_settlement" else canon(normalise(r["core"]))) for n, r in comp.items()}
    if len(set(keys.values())) <= 1:
        return comp, None
    diff = []
    if len({r["kind"] for r in comp.values()}) > 1:
        diff.append({"field": "settlement_produced", "section": SECTION["settlement_produced"],
                     "values": {n: r["kind"] == "settled" for n, r in comp.items()}})
    settled = {n: normalise(r["core"]) for n, r in comp.items() if r["kind"] == "settled"}
    for f in CORE:
        vals = {n: s[f] for n, s in settled.items()}
        if len({canon(v) for v in vals.values()}) > 1:
            diff.append({"field": f, "section": SECTION[f], "values": vals})
    return comp, diff


def finding_class(why, results, diff):
    """A coarse name for a finding, so a continued run keeps a few examples of each kind instead of thousands of one:
    which implementations side together, and per field what changes between the sides (codes, never record digests)."""
    groups = {}
    for n, r in sorted(results.items()):
        key = r["kind"] if r["kind"] != "settled" else canon(normalise(r["core"]))
        groups.setdefault(key, []).append(n)
    part = sorted(sorted(v) for v in groups.values())
    reps = [g[0] for g in part]
    detail = []
    for d in diff or []:
        f, vals = d["field"], d["values"]
        if f == "dispositions":
            pairs = set()
            for x in reps:
                for y in reps:
                    vx, vy = vals.get(x), vals.get(y)
                    if x < y and isinstance(vx, dict) and isinstance(vy, dict):
                        for k in set(vx) | set(vy):
                            if vx.get(k) != vy.get(k):
                                pairs.add("%s:%s|%s:%s" % (x, vx.get(k), y, vy.get(k)))
            detail.append([f, sorted(pairs)])
        elif f in SETS:
            sd = set()
            for x in reps:
                for y in reps:
                    vx, vy = vals.get(x), vals.get(y)
                    if x < y and isinstance(vx, list) and isinstance(vy, list):
                        sd |= {"%s+%s" % (x, c) for c in set(vx) - set(vy)} | {"%s+%s" % (y, c) for c in set(vy) - set(vx)}
            detail.append([f, sorted(sd)])
        elif f in ("verdict", "status", "bond_outcome", "settlement_produced"):
            detail.append([f, sorted("%s=%s" % (n, canon(vals.get(n))) for n in reps if n in vals)])
        else:
            detail.append([f])
    desc = [why, part, detail]
    return hashlib.sha256(canon(desc).encode()).hexdigest()[:16], desc


def campaign(a, impl_names, gen, log=print):
    """Run inputs until the budget ends or something fails. Returns a summary dict."""
    work = refuse_blind(os.path.abspath(a.work))
    findings = refuse_blind(os.path.abspath(a.findings))
    os.makedirs(work, exist_ok=True)
    workers = {n: Worker(n, a, os.path.join(work, "logs")) for n in impl_names}
    t0 = time.time()
    st = {"seed": a.seed, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "inputs": 0, "compared": 0,
          "out_of_scope": 0, "generator_errors": 0, "replayed_vectors": 0, "repaired": 0, "raw_mutated": 0,
          "per_impl": {n: {"agree_with_reference": 0, "unassessed": 0, "no_settlement": 0} for n in impl_names},
          "reference_verdicts": {}, "reference_reasons": {}, "reference_status": {}, "reference_nonempty_event_set": 0,
          "stopped": None, "python": {n: w.python for n, w in workers.items()}, "findings": [], "finding_classes": {}}
    max_findings = getattr(a, "max_findings", 0) or 0
    queue = []
    if a.replay:
        for vid, fam, d in gen.seeds:
            queue.append(("vector", vid, d))
    idx = a.start

    def budget_left():
        if a.count is not None and st["inputs"] - st["replayed_vectors"] >= a.count:
            return False
        if a.minutes is not None and time.time() - t0 > a.minutes * 60:
            return False
        return True
    try:
        while queue or budget_left():
            if queue:
                kind, vid, src = queue.pop(0)
                files = {}
                for root, _, fs in os.walk(src):
                    for f in fs:
                        if f in ("expected.json",):
                            continue
                        p = os.path.join(root, f)
                        files[os.path.relpath(p, src).replace(os.sep, "/")] = open(p, "rb").read()
                meta = {"origin": "vector:" + vid + " (unchanged)", "log": []}
                st["replayed_vectors"] += 1
            else:
                i = idx
                idx += 1
                try:
                    case, files = gen.make(a.seed, i)
                except Exception:                                             # noqa: BLE001
                    st["generator_errors"] += 1
                    if st["generator_errors"] <= 5:
                        log("generator error at index %d:\n%s" % (i, traceback.format_exc()[-1500:]))
                    continue
                meta = {"seed": a.seed, "index": i, "origin": case["origin"], "log": case["log"]}
                st["repaired"] += 1 if case.get("repaired") else 0
                st["raw_mutated"] += 1 if any(x.startswith("raw ") for x in case["log"]) else 0
            d = os.path.join(work, "cur", "input")
            write_input(files, d)
            sha = tree_sha256(d)
            oos = out_of_scope(files.get("contract.json", b""), gen.parse)
            deadline = time.time() + a.timeout
            for w in workers.values():
                w.send(d)
            results, secs = recv_all(workers, deadline)
            for n, w in workers.items():
                st["per_impl"][n]["seconds"] = round(st["per_impl"][n].get("seconds", 0) + secs[n], 3)
            st["inputs"] += 1
            bad = {n: r for n, r in results.items() if r["kind"] in ("crash", "timeout")}
            comp, diff = (None, None) if oos else compare(results)
            if oos:
                st["out_of_scope"] += 1
            else:
                st["compared"] += 1
            ref = results.get("reference")
            if ref and ref["kind"] == "settled" and not oos:
                core = ref["core"]
                st["reference_verdicts"][core["verdict"]] = st["reference_verdicts"].get(core["verdict"], 0) + 1
                st["reference_status"][core["status"]] = st["reference_status"].get(core["status"], 0) + 1
                for rsn in core["underspecified_reasons"] + core["deviation_codes"]:
                    st["reference_reasons"][rsn] = st["reference_reasons"].get(rsn, 0) + 1
                st["reference_nonempty_event_set"] += 1 if core["event_set"] else 0
            elif ref and ref["kind"] == "no_settlement" and not oos:
                st["reference_verdicts"]["(no settlement)"] = st["reference_verdicts"].get("(no settlement)", 0) + 1
            if not oos:
                for n, r in results.items():
                    p = st["per_impl"][n]
                    if r["kind"] == "unassessed":
                        p["unassessed"] += 1
                    elif r["kind"] == "no_settlement":
                        p["no_settlement"] += 1
                    if ref and r["kind"] in ("settled", "no_settlement") and ref["kind"] in ("settled", "no_settlement"):
                        same = (r["kind"] == ref["kind"] == "no_settlement") or (r["kind"] == ref["kind"] == "settled" and canon(normalise(r["core"])) == canon(normalise(ref["core"])))
                        p["agree_with_reference"] += 1 if same else 0
            if bad or diff:
                why = "crash" if any(r["kind"] == "crash" for r in bad.values()) else ("timeout" if bad else "disagreement")
                cls, cdesc = finding_class(why, results, diff)
                st["finding_classes"][cls] = st["finding_classes"].get(cls, 0) + 1
                for n in bad:
                    workers[n].stop()
                    workers[n].start()
                if max_findings and st["finding_classes"][cls] > 3:
                    continue                                    # this kind is already kept three times
                fd = os.path.join(findings, sha)
                if os.path.isdir(fd):
                    shutil.rmtree(fd)
                shutil.copytree(d, os.path.join(fd, "input"))
                os.makedirs(os.path.join(fd, "raw"))
                for n, r in results.items():
                    with open(os.path.join(fd, "raw", n.replace("/", "_") + ".json"), "w", encoding="utf-8") as f:
                        f.write(json.dumps(r, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
                with open(os.path.join(fd, "diff.json"), "w", encoding="utf-8") as f:
                    f.write(json.dumps({"input_sha256": sha, "why": why, "out_of_scope": oos,
                                        "failed": {n: r["kind"] for n, r in bad.items()}, "diff": diff or []},
                                       indent=1, sort_keys=True, ensure_ascii=False) + "\n")
                meta["finding_class"], meta["finding_class_detail"] = cls, cdesc
                with open(os.path.join(fd, "meta.json"), "w", encoding="utf-8") as f:
                    f.write(json.dumps(meta, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
                rec = {"why": why, "input_sha256": sha, "finding": fd, "meta": meta, "class": cls,
                       "fields": [x["field"] for x in (diff or [])], "failed": {n: r["kind"] for n, r in bad.items()}}
                st["findings"].append(rec)
                if not max_findings or len(st["findings"]) >= max_findings:
                    st["stopped"] = rec
                    log("STOP %s on input %s (%s): %s" % (why, sha[:16], meta.get("origin"), fd))
                    break
                log("finding %d (%s, class %s) on input %s, continuing (--max-findings %d)" % (len(st["findings"]), why, cls, sha[:16], max_findings))
            if st["inputs"] % 250 == 0:
                log("%6d inputs, %d compared, %d out of scope, %.0f s" % (st["inputs"], st["compared"], st["out_of_scope"], time.time() - t0))
    finally:
        for w in workers.values():
            w.stop()
    st["seconds"] = round(time.time() - t0, 1)
    st["next_index"] = idx
    return st


# ----------------------------------------------------------------------------------------------- commands
def cmd_setup(a):
    cfg = load_config(a.config)
    root = refuse_blind(os.path.abspath(a.impl_root))
    os.makedirs(root, exist_ok=True)
    for impl in cfg["implementations"]:
        if impl["repo"] == "self":
            continue
        d = os.path.join(root, impl["dir"])
        if not os.path.isdir(d):
            subprocess.run(["git", "clone", "-q", impl["repo"], d], check=True)
        subprocess.run(["git", "-C", d, "checkout", "-q", impl["commit"]], check=True)
    probs = check_pins(cfg, root)
    if probs:
        print("\n".join(probs))
        return 1
    print("setup ok: every pin matches")
    return 0


def cmd_verify(a):
    probs = check_pins(load_config(a.config), os.path.abspath(a.impl_root))
    print("\n".join(probs) if probs else "verify ok: every pin matches")
    return 1 if probs else 0


def common_prep(a):
    a.config = os.path.abspath(a.config)
    a.impl_root = refuse_blind(os.path.abspath(a.impl_root))
    a.vectors = refuse_blind(os.path.abspath(a.vectors))
    cfg = load_config(a.config)
    return cfg


def cmd_run(a):
    cfg = common_prep(a)
    names = a.impls.split(",") if a.impls else [i["name"] for i in cfg["implementations"]]
    if names[0] != "reference":
        raise SystemExit("the first implementation must be the reference")
    probs = check_pins(cfg, a.impl_root, names=names, quiet=True)
    if probs and not a.allow_unpinned:
        print("\n".join(probs))
        raise SystemExit("pins do not match; refusing to run (setup, or --allow-unpinned to record a drifted run)")
    gen = Gen(cfg, a.vectors)
    st = campaign(a, names, gen)
    st["pins"] = {i["name"]: {"commit": i.get("commit"), "files_sha256": i["files_sha256"]} for i in cfg["implementations"] if i["name"] in names}
    st["pins_ok"] = not probs
    try:
        import cryptography
        st["cryptography"] = cryptography.__version__
    except ImportError:
        st["cryptography"] = None
    st["harness_python"] = sys.version.split()[0]
    os.makedirs(a.work, exist_ok=True)
    with open(os.path.join(a.work, "summary.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(st, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: st[k] for k in ("inputs", "compared", "out_of_scope", "replayed_vectors", "generator_errors", "per_impl", "seconds", "finding_classes")}, indent=1, sort_keys=True))
    for x in st["findings"]:
        print("finding %s %-12s fields %s failed %s class %s" % (x["input_sha256"][:16], x["why"], ",".join(x["fields"]) or "-", x["failed"] or "-", x["class"]))
    first = st["stopped"] or (st["findings"][0] if st["findings"] else None)
    if first:
        return {"disagreement": 2, "crash": 3, "timeout": 4}[first["why"]]
    return 0


def cmd_gen(a):
    cfg = common_prep(a)
    gen = Gen(cfg, a.vectors)
    case, files = gen.make(a.seed, a.index)
    out = refuse_blind(os.path.abspath(a.out))
    write_input(files, out)
    print(json.dumps({"input_sha256": tree_sha256(out), "origin": case["origin"], "log": case["log"]}, indent=1))
    return 0


def cmd_selftest(a):
    cfg = common_prep(a)
    import tempfile
    base = tempfile.mkdtemp(prefix="settle-core-fuzz-selftest-")
    ok = True

    def check(cond, what):
        nonlocal ok
        print(("ok    " if cond else "FAIL  ") + what)
        ok = ok and cond
    # 1. held-out paths are refused
    for p in ("/x/settle-core-blind-01/vectors", "/x/BLIND/y"):
        try:
            refuse_blind(p)
            check(False, "refuses %s" % p)
        except SystemExit:
            check(True, "refuses a path containing 'blind': %s" % p)
    gen = Gen(cfg, a.vectors)
    # 2. determinism in (seed, index)
    same = True
    for i in range(6):
        d1, d2 = os.path.join(base, "d1"), os.path.join(base, "d2")
        write_input(gen.make("selftest", i)[1], d1)
        write_input(Gen(cfg, a.vectors).make("selftest", i)[1], d2) if i == 0 else write_input(gen.make("selftest", i)[1], d2)
        same = same and tree_sha256(d1) == tree_sha256(d2)
    check(same, "inputs are deterministic in (seed, index)")

    def sub(name, impls, **kw):
        b = argparse.Namespace(**vars(a))
        b.work, b.findings = os.path.join(base, name, "work"), os.path.join(base, name, "findings")
        b.seed, b.start, b.count, b.minutes, b.replay = "selftest", 0, kw.get("count", 300), None, kw.get("replay", False)
        b.timeout = kw.get("timeout", a.timeout)
        hist = []
        st = campaign(b, impls, gen, log=lambda m: hist.append(m))
        return st, b
    # 3. the reference agrees with itself, and replays the public vectors
    st, b = sub("replay", ["reference"], count=0, replay=True)
    exp_ok = True
    w = Worker("reference", b, os.path.join(base, "w"))
    for vid, fam, d in gen.seeds:
        w.send(d)
        r = w.recv(time.time() + a.timeout)
        exp = json.load(open(os.path.join(d, "expected.json"), encoding="utf-8"))
        exp_ok = exp_ok and r["kind"] == "settled" and canon(normalise(r["core"])) == canon(normalise(exp))
    w.stop()
    check(exp_ok and st["stopped"] is None, "the reference adapter reproduces expected.json on all %d public vectors" % len(gen.seeds))
    # 4. a flipped field is caught on the first relevant input
    st, b = sub("flip", ["reference", "selftest-flip"], count=400)
    s = st["stopped"]
    first = None
    if s:
        w = Worker("reference", b, os.path.join(base, "w2"))
        for i in range(0, s["meta"]["index"] + 1):
            d = os.path.join(base, "probe")
            write_input(gen.make("selftest", i)[1], d)
            if out_of_scope(open(os.path.join(d, "contract.json"), "rb").read(), gen.parse):
                continue
            w.send(d)
            r = w.recv(time.time() + a.timeout)
            if r["kind"] == "settled" and r["core"]["verdict"] == "within_grant":
                first = i
                break
        w.stop()
    check(bool(s) and s["why"] == "disagreement" and s["fields"] == ["verdict"] and first == s["meta"]["index"],
          "a shim that flips verdict within_grant -> deviation is caught on the first input where the reference says within_grant (index %s)" % (s and s["meta"]["index"]))
    check(bool(s) and os.path.isfile(os.path.join(s["finding"], "diff.json")) and os.path.isdir(os.path.join(s["finding"], "input"))
          and os.path.basename(s["finding"]) == tree_sha256(os.path.join(s["finding"], "input")),
          "the finding folder is named by the input's sha256 and holds input/, raw/ and diff.json")
    # 5. a crash and a timeout stop the run
    st, b = sub("crash", ["reference", "selftest-crash"], count=5)
    check(bool(st["stopped"]) and st["stopped"]["why"] == "crash" and st["inputs"] == 1, "a crashing implementation stops the run on the first input")
    st, b = sub("sleep", ["reference", "selftest-sleep"], count=5, timeout=2)
    check(bool(st["stopped"]) and st["stopped"]["why"] == "timeout" and st["inputs"] == 1, "a hanging implementation is stopped by the timeout")
    # 6. the set fields are compared as sets, the others exactly
    r1 = {"kind": "settled", "core": dict(zip(CORE, [None, "underspecified", "undetermined", "n/a", [], ["b", "a"], [], {}]))}
    r2 = {"kind": "settled", "core": dict(zip(CORE, [None, "underspecified", "undetermined", "n/a", [], ["a", "b", "a"], [], {}]))}
    r3 = {"kind": "settled", "core": dict(zip(CORE, [None, "underspecified", "undetermined", "n/a", [], ["a", "b"], [], {"x": "accepted"}]))}
    check(compare({"x": r1, "y": r2})[1] is None and [d["field"] for d in compare({"x": r1, "y": r3})[1]] == ["dispositions"],
          "deviation_codes and underspecified_reasons compare as sets; dispositions exactly")
    check([d["field"] for d in compare({"x": r1, "y": {"kind": "no_settlement"}})[1]] == ["settlement_produced"],
          "a settlement against no settlement is a disagreement")
    shutil.rmtree(base, ignore_errors=True)
    print("SELFTEST_OK" if ok else "SELFTEST_FAILED")
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--worker", help=argparse.SUPPRESS)
    p.add_argument("--config", default=CONFIG)
    p.add_argument("--impl-root", default=os.path.join(HERE, "impls"), help="where setup clones the outside implementations (default ./impls)")
    p.add_argument("--vectors", default=os.path.join(REPO, "workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/vectors"))
    p.add_argument("--timeout", type=float, default=20.0, help="seconds per input per implementation (default 20)")
    sp = p.add_subparsers(dest="cmd")
    sp.add_parser("setup")
    sp.add_parser("verify")
    sp.add_parser("selftest")
    r = sp.add_parser("run")
    r.add_argument("--seed", default="1")
    r.add_argument("--start", type=int, default=0)
    r.add_argument("--count", type=int)
    r.add_argument("--minutes", type=float)
    r.add_argument("--impls", help="comma separated names from implementations.json, reference first (default all)")
    r.add_argument("--work", default=os.path.join(HERE, "work"))
    r.add_argument("--findings", default=os.path.join(HERE, "findings"))
    r.add_argument("--no-replay", dest="replay", action="store_false", help="skip the unchanged public vectors at the start")
    r.add_argument("--allow-unpinned", action="store_true")
    r.add_argument("--max-findings", type=int, default=0,
                   help="0 (default): stop at the first crash, timeout or disagreement. N: keep up to three examples of each kind and stop after N saved findings")
    gp = sp.add_parser("gen")
    gp.add_argument("--seed", default="1")
    gp.add_argument("--index", type=int, required=True)
    gp.add_argument("--out", required=True)
    a = p.parse_args(argv)
    if a.worker:
        return worker_main(a)
    if a.cmd == "run" and a.count is None and a.minutes is None:
        a.count = 2000
    return {"setup": cmd_setup, "verify": cmd_verify, "selftest": cmd_selftest, "run": cmd_run, "gen": cmd_gen}.get(a.cmd, lambda _a: p.print_help() or 2)(a)


if __name__ == "__main__":
    sys.exit(main())
