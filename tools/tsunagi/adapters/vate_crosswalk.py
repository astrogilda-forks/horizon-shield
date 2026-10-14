#!/usr/bin/env python3
"""TSUNAGI adapter for Poke-nushi's NENRIN and VATE S3 crosswalk (reference/nenrin-s3-crosswalk-example in
Poke-nushi/Verifiable-Agent-Trust-Envelope). It runs the crosswalk's own scripts exactly as its README documents them
and leaves one comparison report at --out. It scores nothing: the board reads that report and compares every finding
with tools/tsunagi/expected/vate-nenrin-s3-crosswalk-v0.json itself.

    vate_crosswalk.py setup                                    install the pinned runtimes the rerun mode needs
    vate_crosswalk.py run --impl DIR --mode saved  --out FILE  compare the saved NENRIN and VATE reports
    vate_crosswalk.py run --impl DIR --mode rerun  --out FILE  run the VATE assessor and both NENRIN verifiers again,
                                                               then compare those fresh runs

The runtimes are the ones the crosswalk's README names: jsonschema 4.26.0 for the VATE replay, nenrin-verify 0.5.1
from npm and 0.5.3 from PyPI for the NENRIN replay, Node.js 20 or later from PATH. They are installed once into a
cache directory outside every checkout (TSUNAGI_VATE_RT, default <tmp>/tsunagi-vate-rt-v0). The crosswalk's
replay_native.py checks the installed distributions against its own NATIVE-PINS.json before using them; this adapter
never calls npx and never lets the crosswalk install anything.
"""
import argparse, json, os, shutil, subprocess, sys, tempfile

EXAMPLE = "reference/nenrin-s3-crosswalk-example"
PINS = {"jsonschema": "4.26.0", "nenrin-verify-pypi": "0.5.3", "nenrin-verify-npm": "0.5.1"}
RT = os.environ.get("TSUNAGI_VATE_RT") or os.path.join(tempfile.gettempdir(), "tsunagi-vate-rt-v0")
MARK = os.path.join(RT, "PINS.json")


def say(msg):
    print("vate-crosswalk: " + msg, flush=True)


def run(argv, cwd=None):
    r = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout).strip()[-600:]
        say("exit %d from %s\n%s" % (r.returncode, " ".join(os.path.basename(a) if i == 0 else a for i, a in enumerate(argv)), tail))
    return r.returncode


def paths():
    bin_ = "Scripts" if os.name == "nt" else "bin"
    return {"vate_py": os.path.join(RT, "venv-vate", bin_, "python"),
            "nenrin_py": os.path.join(RT, "venv-nenrin", bin_, "python"),
            "npm_entry": os.path.join(RT, "npm", "node_modules", "nenrin-verify", "nenrin_verify.mjs")}


def setup():
    p = paths()
    try:
        if json.load(open(MARK, encoding="utf-8")) == PINS and all(os.path.exists(x) for x in p.values()):
            say("runtimes already installed at %s" % RT)
            return 0
    except (OSError, ValueError):
        pass
    if os.path.isdir(RT):
        shutil.rmtree(RT)
    os.makedirs(os.path.join(RT, "npm"))
    steps = [
        [sys.executable, "-m", "venv", os.path.join(RT, "venv-vate")],
        [p["vate_py"], "-m", "pip", "install", "-q", "--disable-pip-version-check", "jsonschema==" + PINS["jsonschema"]],
        [sys.executable, "-m", "venv", os.path.join(RT, "venv-nenrin")],
        [p["nenrin_py"], "-m", "pip", "install", "-q", "--disable-pip-version-check", "nenrin-verify==" + PINS["nenrin-verify-pypi"]],
        ["npm", "install", "--silent", "--no-audit", "--no-fund", "--prefix", os.path.join(RT, "npm"),
         "nenrin-verify@" + PINS["nenrin-verify-npm"]],
    ]
    for argv in steps:
        if run(argv) != 0:
            return 2
    for k, v in p.items():
        if not os.path.exists(v):
            say("installed, but %s is missing: %s" % (k, v))
            return 2
    with open(MARK, "w", encoding="utf-8") as f:
        json.dump(PINS, f)
    say("runtimes installed at %s" % RT)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="what", required=True)
    sub.add_parser("setup")
    r = sub.add_parser("run")
    r.add_argument("--impl", required=True, help="a checkout of Poke-nushi/Verifiable-Agent-Trust-Envelope")
    r.add_argument("--mode", required=True, choices=("saved", "rerun"))
    r.add_argument("--out", required=True, help="a new file; the comparison report is written here")
    a = ap.parse_args()
    if a.what == "setup":
        return setup()
    impl = os.path.abspath(a.impl)
    ex = os.path.join(impl, EXAMPLE)
    out = os.path.abspath(a.out)
    if not os.path.isdir(ex):
        say("no %s in %s" % (EXAMPLE, impl))
        return 2
    if a.mode == "saved":
        code = run([sys.executable, "-B", os.path.join(ex, "compare_records.py"), "--output", out], cwd=impl)
        say("saved comparison written (exit %d)" % code if os.path.exists(out) else "no report written (exit %d)" % code)
        return code
    p = paths()
    missing = [k for k, v in p.items() if not os.path.exists(v)]
    if missing:
        say("rerun needs the pinned runtimes; run 'vate_crosswalk.py setup' first (missing: %s)" % ", ".join(missing))
        return 2
    node = shutil.which("node")
    if not node:
        say("rerun needs Node.js 20 or later on PATH")
        return 2
    with tempfile.TemporaryDirectory(prefix="tsunagi-vate-") as t:
        vate_run, native_run = os.path.join(t, "vate-run"), os.path.join(t, "native-run")
        if run([p["vate_py"], "-B", os.path.join(ex, "replay_vate.py"), "--output", vate_run], cwd=impl) != 0:
            return 3
        if run([sys.executable, "-B", os.path.join(ex, "replay_native.py"), "--node", node, "--npm-entry", p["npm_entry"],
                "--python", p["nenrin_py"], "--output", native_run], cwd=impl) != 0:
            return 3
        code = run([sys.executable, "-B", os.path.join(ex, "compare_records.py"), "--vate-run", vate_run,
                    "--native-run", native_run, "--output", out], cwd=impl)
    say("fresh comparison written (exit %d)" % code if os.path.exists(out) else "no report written (exit %d)" % code)
    return code


if __name__ == "__main__":
    sys.exit(main())
