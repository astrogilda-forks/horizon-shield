#!/usr/bin/env python3
"""The Go port against the JavaScript reference, on every frozen bundle and on mutations of every path.

The mutations are the ones the Python port is held to (../../sdk-python/tests/parity/mutate.py over
../../sdk-python/tests/fixtures/bundles.json), plus the five interop corpora and, with --edge, bundles from
../../conformance-v0/gen_edge_bundles.mjs. Each bundle is written once as JSON text and parsed by each language from
the same text. Pass per input: both threw, or the same verdict signature and the same refusals as (code, reason) in
order. Exit 1 on any difference.

  go build -o nenrin-verify-go ./cmd/nenrin-verify-go
  python3 parity/parity.py ./nenrin-verify-go [--edge edge.json ...] [--js path/to/nenrin_verify.mjs]
"""
import argparse, glob, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
NENRIN = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(NENRIN, "sdk-python", "tests", "parity"))
from mutate import mutations  # noqa: E402


def corpus(edges):
    seen, out = set(), []

    def add(name, op, b):
        text = json.dumps(b, ensure_ascii=False, separators=(",", ":"))
        if "\n" in text or text in seen:
            return
        seen.add(text)
        out.append((name, op, text))

    for c in json.load(open(os.path.join(NENRIN, "sdk-python", "tests", "fixtures", "bundles.json"), encoding="utf-8"))["cases"]:
        add(c["name"], "frozen", c["bundle"])
        for p, op, b in mutations(c["bundle"]):
            add(c["name"], "/".join(map(str, p)) + " " + op, b)
    for d in ("interop-v0", "interop-v0.1", "interop-v0.2/edge", "interop-v0.2/action-presence", "interop-v0.3/survivors", "interop-v0.3/own-proto"):
        for f in sorted(glob.glob(os.path.join(NENRIN, d, "fixtures", "*.json"))):
            add(d + "/" + os.path.basename(f)[:-5], "frozen", json.load(open(f, encoding="utf-8")))
    for e in edges:
        for c in json.load(open(e, encoding="utf-8")):
            add(c["name"], "edge", c["bundle"])
    return out


def run(cmd, texts):
    p = subprocess.run(cmd, input="\n".join(texts) + "\n", capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0:
        sys.exit(p.stderr[-2000:])
    rows = [json.loads(l) for l in p.stdout.split("\n") if l]
    assert len(rows) == len(texts), (len(rows), len(texts))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("go_bin")
    ap.add_argument("--js", default=os.path.join(NENRIN, "sdk", "nenrin_verify.mjs"))
    ap.add_argument("--edge", action="append", default=[])
    a = ap.parse_args()
    cases = corpus(a.edge)
    texts = [t for _n, _o, t in cases]
    js = run(["node", os.path.join(HERE, "js_sig_runner.mjs"), a.js], texts)
    go = run([os.path.abspath(a.go_bin), "--lines"], texts)
    bad, threw, refused = [], 0, 0
    for (name, op, _t), j, g in zip(cases, js, go):
        if j["threw"] or g["threw"]:
            threw += 1
            if j["threw"] != g["threw"]:
                bad.append((name, op, "js threw: " + j.get("error", "") if j["threw"] else "go threw: " + g.get("error", "")))
            continue
        if j["signature"]["verdict"] == "refused":
            refused += 1
        gc = [{"code": c["code"], "reason": c.get("reason", "")} for c in g.get("codes") or []]
        if j["signature"] != g["signature"] or j["codes"] != gc:
            bad.append((name, op, json.dumps({"js": j, "go": {"signature": g["signature"], "codes": gc}})[:600]))
    print("go vs js: %d inputs (%d refused, %d both threw), %d differ" % (len(cases), refused, threw, len(bad)))
    for b in bad[:30]:
        print("  ", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
