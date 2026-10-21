#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""track.py against nenrin-track-go on the vectors and on mutations of them: the two reports must be the same bytes.

    go build -o /tmp/nenrin-track-go ../sdk-go/cmd/nenrin-track-go
    python3 parity.py /tmp/nenrin-track-go [--n 400] [--seed 1]

A mutation edits one file of a vector's mirror: a byte flipped, a JSON value replaced (a number by a float, an
exponent, a huge integer, a string with a lone surrogate escape, a key outside ASCII, a repeated key), a bitcoin_block
moved, an object removed or renamed. Exit 0 when every report agrees."""
import argparse, json, os, random, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "vectors")

EDITS = ['1.5', '1e3', '9007199254740993', '"\\ud800"', '-0', '1000.0', 'null', 'true', '"x"', '[]', '{}']


def pins_args(d):
    p = json.load(open(os.path.join(d, "pins.json")))
    out = []
    for k, v in sorted(p.items()):
        out += ["--pin", "%s@%s" % (v, k)]
    return out


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, timeout=120)
    run.stderr = r.stderr
    return r.returncode, r.stdout


def mutate(d, rnd):
    files = []
    for sub in ("ledger", "objects"):
        for f in sorted(os.listdir(os.path.join(d, sub))):
            files.append(os.path.join(d, sub, f))
    p = rnd.choice(files)
    b = bytearray(open(p, "rb").read())
    k = rnd.randrange(7)
    if k == 0 and b:
        i = rnd.randrange(len(b)); b[i] ^= 1 << rnd.randrange(8)
    elif k == 1:
        os.remove(p); return "remove " + os.path.basename(p)
    elif k == 2:
        os.rename(p, p + ".x"); return "rename " + os.path.basename(p)
    elif k == 3:
        s = b.decode("utf-8", "replace")
        idx = [i for i, ch in enumerate(s) if ch == ":"]
        if idx:
            i = rnd.choice(idx)
            j = i + 1
            depth = 0
            while j < len(s) and not (depth == 0 and s[j] in ",}]"):
                depth += s[j] in "[{"
                depth -= s[j] in "]}"
                j += 1
            s = s[:i + 1] + rnd.choice(EDITS) + s[j:]
        b = bytearray(s.encode("utf-8"))
    elif k == 4:
        s = b.decode("utf-8", "replace").replace('"bitcoin_block":', '"bitcoin_block":%d,"_":' % rnd.choice([972000, 973100, 999999]), 1)
        b = bytearray(s.encode("utf-8"))
    elif k == 5:
        s = b.decode("utf-8", "replace").replace('{"', '{"é":1,"', 1)
        b = bytearray(s.encode("utf-8"))
    else:
        s = b.decode("utf-8", "replace").replace('{"', '{"schema":"x","', 1)
        b = bytearray(s.encode("utf-8"))
    open(p, "wb").write(bytes(b))
    return "edit %d %s" % (k, os.path.basename(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("go")
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    cases = sorted(x for x in os.listdir(VEC) if os.path.isdir(os.path.join(VEC, x)))
    bad = 0
    tmp = tempfile.mkdtemp(prefix="track-parity-")
    try:
        for i in range(a.n + len(cases)):
            c = cases[i % len(cases)]
            d = os.path.join(tmp, "m%d" % i)
            shutil.copytree(os.path.join(VEC, c), d)
            what = "as is" if i < len(cases) else mutate(d, rnd)
            pa = pins_args(d)
            r1 = run([sys.executable, "-I", os.path.join(HERE, "track.py"), "--dir", d, "--json"] + pa)
            e1 = run.stderr
            r2 = run([a.go, "--dir", d, "--json"] + pa)
            if r1 != r2:
                bad += 1
                print("DIFF %s (%s)\n  py %s %s %s\n  go %s %s" % (c, what, r1[0], r1[1][:400], e1[-600:], r2[0], r2[1][:400]))
            shutil.rmtree(d)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("%d runs, %d differences" % (a.n + len(cases), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
