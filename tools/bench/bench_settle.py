#!/usr/bin/env python3
"""bench_settle.py: settle one MUSUBI contract with N executions through the reference settle_v1_16 and time it.

    python3 tools/bench/bench_settle.py --n 1000 [--out /tmp/hs-bench]

Writes the input with gen_settle.py, then settles it in a child process run under /usr/bin/time (-l on macOS, -v
on Linux) for the maximum resident set size. The child reads the three files with contract_v0.parse_strict and calls
settle_v1_16.settle_v1_16(contract, events, view) as settle-core-v0/run_reference.py does (strict binding, one view,
no parent, no nenrin records), then projects the settlement with run_reference.core_fields.

Prints one JSON line: the input sha256 (gen_settle.py), the time to read the files, the time to settle, the maximum
RSS, verdict, status, bond outcome, accepted count, and core_sha256 = sha256 of the core fields written as
expected.json is written in settle-core-v0 (json.dumps(core, indent=1, sort_keys=True) + "\\n"). No network.
"""
import argparse, hashlib, json, os, re, subprocess, sys, tempfile, time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
MUSUBI = os.path.join(REPO, "workers", "hs-ledger", "nenrin", "musubi-v0")


def settle_child(d):
    sys.path.insert(0, MUSUBI)
    sys.path.insert(0, os.path.join(MUSUBI, "settle-core-v0"))
    import settle_v1_16
    from contract_v0 import parse_strict
    from run_reference import core_fields
    t0 = time.perf_counter()
    contract = parse_strict(open(os.path.join(d, "contract.json"), encoding="utf-8").read())
    view = parse_strict(open(os.path.join(d, "view.json"), encoding="utf-8").read())
    events = [parse_strict(l) for l in open(os.path.join(d, "events.jsonl"), encoding="utf-8").read().split("\n") if l]
    t1 = time.perf_counter()
    s = settle_v1_16.settle_v1_16(contract, events, view)
    t2 = time.perf_counter()
    core = core_fields(s)
    text = json.dumps(core, indent=1, sort_keys=True) + "\n"
    print(json.dumps({"read_s": round(t1 - t0, 3), "settle_s": round(t2 - t1, 3), "verdict": core["verdict"], "status": core["status"],
                      "bond_outcome": core["bond_outcome"], "accepted": len(core["event_set"]),
                      "deviation_codes": core["deviation_codes"], "underspecified_reasons": core["underspecified_reasons"],
                      "core_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}, sort_keys=True))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "hs-bench"))
    ap.add_argument("--settle-dir", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.settle_dir:
        return settle_child(a.settle_dir)
    sys.path.insert(0, HERE)
    import gen_settle
    t0 = time.perf_counter()
    gen = gen_settle.write(a.n, a.out)
    gen_s = time.perf_counter() - t0
    if sys.platform == "darwin":
        pre, rx, unit = ["/usr/bin/time", "-l"], re.compile(r"(\d+)\s+maximum resident set size"), 1
    else:
        pre, rx, unit = ["/usr/bin/time", "-v"], re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)"), 1024
    if not os.path.exists("/usr/bin/time"):
        pre = []
    t0 = time.perf_counter()
    p = subprocess.run(pre + [sys.executable, "-B", os.path.abspath(__file__), "--settle-dir", gen["dir"]], capture_output=True, text=True)
    wall = time.perf_counter() - t0
    if p.returncode != 0:
        sys.exit(p.stderr[-2000:])
    res = json.loads(p.stdout.strip().split("\n")[-1])
    m = rx.search(p.stderr)
    res.update({"executions": gen["executions"], "headers": gen["headers"], "input_sha256": gen["input_sha256"],
                "files_sha256": gen["files_sha256"], "gen_s": round(gen_s, 3), "child_wall_s": round(wall, 3),
                "max_rss_bytes": int(m.group(1)) * unit if m else None})
    print(json.dumps(res, sort_keys=True))
    return 0 if res["verdict"] == "within_grant" and res["status"] == "final" and res["accepted"] == a.n else 1


if __name__ == "__main__":
    sys.exit(main())
