#!/usr/bin/env python3
"""bench_verify.py: feed one JSONL of provenance bundles to the JavaScript, Python and Go NENRIN verifiers.

    python3 tools/bench/bench_verify.py /tmp/hs-bench/bundles_reuse7_10000.jsonl [--only js,go] [--go-bin PATH]

Each verifier runs as its own process, one bundle per line on stdin and one result per line on stdout, the way
workers/hs-ledger/nenrin/sdk-go/parity/parity.py and xlang_step1.py feed them:
  js  node sdk-go/parity/js_sig_runner.mjs sdk/nenrin_verify.mjs   (the npm package's own file)
  py  this file with --py-runner: nenrin_verify from sdk-python/src called in process, as xlang_step1.py py_rows does
  go  nenrin-verify-go --lines, built here from sdk-go with the local Go toolchain (no module download)

Measured per verifier: wall time of the whole process (start-up included) and per bundle, the maximum resident set
size from /usr/bin/time (-l on macOS, -v on Linux), and the verdict sha256. The verdict sha256 is sha256 over the
lines, in input order, of the canonical JSON (sorted keys, no spaces) of {threw: true} for a bundle the verifier
threw on, else {threw: false, signature: {verdict, refusals, findings}, codes: [{code, reason}]}: the comparison
rule of parity.py (both threw, or the same signature and the same refusals as (code, reason) in order).
Exit 1 if the verifiers that ran do not all give the same verdict sha256. No network.
"""
import argparse, collections, hashlib, json, os, platform, re, shutil, subprocess, sys, tempfile, time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
NENRIN = os.path.join(REPO, "workers", "hs-ledger", "nenrin")


def py_runner():
    sys.path.insert(0, os.path.join(NENRIN, "sdk-python", "src"))
    import nenrin_verify as nv
    from nenrin_verify._js import loads, assign
    out = sys.stdout
    for raw in sys.stdin.buffer.read().split(b"\n"):
        if not raw:
            continue
        try:
            rep = nv.verify_provenance(assign(loads(raw.decode("utf-8", "surrogatepass")), {"resolve": nv.did_key_resolver}))
            row = {"threw": False,
                   "signature": {"verdict": rep["verdict"], "refusals": sorted({r["code"] for r in rep["refusals"]}),
                                 "findings": sorted({f["code"] for f in rep["findings"]})},
                   "codes": [{"code": r["code"], "reason": r["reason"] if isinstance(r.get("reason"), str) else (r["status"] if isinstance(r.get("status"), str) else "")} for r in rep["refusals"]]}
        except Exception as e:  # noqa: BLE001
            row = {"threw": True, "error": (type(e).__name__ + ": " + str(e))[:200]}
        out.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


def canon_row(r):
    if r.get("threw"):
        v = {"threw": True}
    else:
        s = r.get("signature") or {}
        v = {"threw": False,
             "signature": {"verdict": s.get("verdict"), "refusals": sorted(s.get("refusals") or []), "findings": sorted(s.get("findings") or [])},
             "codes": [{"code": c.get("code"), "reason": c.get("reason", "")} for c in (r.get("codes") or [])]}
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def build_go(dest):
    env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-o", dest, "./cmd/nenrin-verify-go"], cwd=os.path.join(NENRIN, "sdk-go"), env=env, check=True)
    return dest


def timed(cmd, stdin_path, stdout_path):
    """Run cmd under /usr/bin/time; return (wall seconds, max RSS bytes or None, stderr text)."""
    if sys.platform == "darwin":
        pre, rx, unit = ["/usr/bin/time", "-l"], re.compile(r"(\d+)\s+maximum resident set size"), 1
    else:
        pre, rx, unit = ["/usr/bin/time", "-v"], re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)"), 1024
    if not os.path.exists("/usr/bin/time"):
        pre = []
    with open(stdin_path, "rb") as fi, open(stdout_path, "wb") as fo:
        t0 = time.perf_counter()
        p = subprocess.run(pre + cmd, stdin=fi, stdout=fo, stderr=subprocess.PIPE)
        wall = time.perf_counter() - t0
    err = p.stderr.decode("utf-8", "replace")
    if p.returncode != 0:
        sys.exit("verifier failed (%s): %s" % (" ".join(cmd), err[-2000:]))
    m = rx.search(err)
    return wall, (int(m.group(1)) * unit if m else None), err


def versions():
    v = {"python": platform.python_version(), "platform": platform.platform()}
    for k, cmd in (("node", ["node", "-v"]), ("go", ["go", "version"])):
        try:
            v[k] = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        except OSError:
            v[k] = None
    try:
        import cryptography
        v["cryptography"] = cryptography.__version__
    except ImportError:
        v["cryptography"] = None
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("jsonl", nargs="?")
    ap.add_argument("--only", default="js,py,go", help="comma list of js, py, go")
    ap.add_argument("--go-bin", help="a nenrin-verify-go already built from this commit (else built into a temp dir)")
    ap.add_argument("--keep", help="directory to keep each verifier's raw output in")
    ap.add_argument("--py-runner", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.py_runner:
        return py_runner()
    if not a.jsonl:
        ap.error("the JSONL file is required")
    only = [x for x in a.only.split(",") if x]
    work = a.keep or tempfile.mkdtemp(prefix="hs-bench-verify-")
    os.makedirs(work, exist_ok=True)
    data = open(a.jsonl, "rb").read()
    n = sum(1 for l in data.split(b"\n") if l)
    cmds = {"js": ["node", os.path.join(NENRIN, "sdk-go", "parity", "js_sig_runner.mjs"), os.path.join(NENRIN, "sdk", "nenrin_verify.mjs")],
            "py": [sys.executable, "-B", os.path.abspath(__file__), "--py-runner"]}
    if "go" in only:
        cmds["go"] = [os.path.abspath(a.go_bin) if a.go_bin else build_go(os.path.join(work, "nenrin-verify-go")), "--lines"]
    res = {"input": {"path": a.jsonl, "count": n, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
           "versions": versions(), "verifiers": {}}
    del data
    for name in only:
        outp = os.path.join(work, "out_%s.jsonl" % name)
        wall, rss, _ = timed(cmds[name], a.jsonl, outp)
        rows = [json.loads(l) for l in open(outp, "rb").read().decode("utf-8").split("\n") if l]
        if len(rows) != n:
            sys.exit("%s gave %d rows for %d bundles" % (name, len(rows), n))
        h = hashlib.sha256()
        tally = collections.Counter()
        for r in rows:
            h.update((canon_row(r) + "\n").encode("ascii"))
            tally["threw" if r.get("threw") else r["signature"]["verdict"]] += 1
        res["verifiers"][name] = {"wall_s": round(wall, 3), "per_bundle_us": round(wall / n * 1e6, 1) if n else None,
                                  "max_rss_bytes": rss, "verdict_sha256": h.hexdigest(), "verdicts": dict(sorted(tally.items()))}
        print("%-2s %9.3f s  %8.1f us/bundle  rss %s  verdict %s  %s" % (name, wall, wall / n * 1e6, rss, h.hexdigest()[:16], dict(sorted(tally.items()))), file=sys.stderr)
    shas = {v["verdict_sha256"] for v in res["verifiers"].values()}
    res["agree"] = len(shas) == 1
    print(json.dumps(res, sort_keys=True))
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if res["agree"] else 1


if __name__ == "__main__":
    sys.exit(main())
