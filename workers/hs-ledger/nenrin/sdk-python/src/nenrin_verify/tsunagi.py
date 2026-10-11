"""TSUNAGI referee: score any NENRIN verifier against a frozen corpus exactly the way the nightly board does.

The board (tools/tsunagi/run_board.py in the horizon-shield repository) no longer takes an implementation's own
"N/N reproduced" line on trust for these corpora. It hands the implementation the fixtures as one batch file, reads
back one verdict signature per fixture, and compares each one with the corpus's frozen expected.json itself. This
module is that comparison, shipped in the package so that anyone can get the board's answer on their own machine,
offline, before opening a pull request.

    nenrin-tsunagi list
    nenrin-tsunagi batch-in <corpus> <in.json>
    nenrin-tsunagi score <corpus> <out.json>
    nenrin-tsunagi run <corpus> -- <your command, with {in} and {out} where the files go>
    nenrin-tsunagi row <corpus> -- <your command, with {in} and {out}>

The contract an implementation meets, in any language:
  input   {in}:  a JSON array [{"name": <case>, "bundle": <the fixture>}, ...]
  output  {out}: a JSON object {<case>: {"verdict": str, "refusals": [codes], "findings": [codes]}}
                 or {<case>: {"error": str}} for a case the implementation could not evaluate
Refusal and finding codes are compared as sets (VERIFIER.md section 4: a code that occurs twice counts once). A missing case, an extra
case, an error or any difference is a case not reproduced; nothing is rounded up. Exit 0 only when every case
reproduces.
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGED_ROOT = os.path.join(HERE, "_repo")

MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_LIST = 20

CORPORA = {
    "nenrin-interop-v0": "interop-v0",
    "nenrin-interop-v0.1": "interop-v0.1",
    "nenrin-interop-v0.2-edge": "interop-v0.2/edge",
    "nenrin-trace-intake-v0": "trace-intake-v0",
    "nenrin-trace-bind-v0": "trace-bind-v0",
    "nenrin-trace-span-v0": "trace-span-v0",
    "nenrin-interop-v0.2-action-presence": "interop-v0.2/action-presence",
}


def corpus_dir(name, root=None):
    if name not in CORPORA:
        raise KeyError("unknown corpus %r; known: %s" % (name, ", ".join(sorted(CORPORA))))
    return os.path.join(root or PACKAGED_ROOT, CORPORA[name])


def load_corpus(name, root=None):
    """(expected cases, batch) for a corpus. The batch is in the order of expected.json."""
    d = corpus_dir(name, root)
    with open(os.path.join(d, "expected.json"), encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    batch = []
    for case in cases:
        with open(os.path.join(d, "fixtures", case + ".json"), encoding="utf-8") as f:
            batch.append({"name": case, "bundle": json.load(f)})
    return cases, batch


def batch_text(name, root=None):
    """The batch file for a corpus with every fixture's bytes exactly as in the repository (tsunagi.mjs batchText).
    Re-serialising a parsed fixture is not the same input: a literal like 1e400 or 100000000000000000000, or an escaped
    lone surrogate, is exactly what some corpora test (trace-intake-v0), and json.dump cannot write all of them back."""
    d = corpus_dir(name, root)
    with open(os.path.join(d, "expected.json"), encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    parts = []
    for case in cases:
        with open(os.path.join(d, "fixtures", case + ".json"), encoding="utf-8") as f:
            parts.append('{"name":' + json.dumps(case) + ',"bundle":' + f.read().strip() + "}")
    return "[" + ",".join(parts) + "]"


def signature(sig):
    """The comparable form of a verdict signature, or None when the value is not one."""
    if not isinstance(sig, dict) or "error" in sig:
        return None
    v, r, f = sig.get("verdict"), sig.get("refusals"), sig.get("findings")
    if not isinstance(v, str) or not isinstance(r, list) or not isinstance(f, list):
        return None
    if not all(isinstance(x, str) for x in r + f):
        return None
    return {"verdict": v, "refusals": sorted(set(r)), "findings": sorted(set(f))}


def short(sig):
    """One line for a signature, used on the board and in pair comparisons."""
    if sig is None:
        return "no signature"
    s = "%s [%s] [%s]" % (sig["verdict"], ",".join(sig["refusals"]), ",".join(sig["findings"]))
    return s if len(s) <= 200 else s[:197] + "..."


def read_output(path):
    """An implementation's output file, refused when it is too large or not JSON (any parse failure, not just syntax)."""
    if os.path.getsize(path) > MAX_OUTPUT_BYTES:
        raise ValueError("output larger than %d bytes" % MAX_OUTPUT_BYTES)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def score(cases, out):
    """Compare an implementation's output with the frozen expectations, case by case."""
    if not isinstance(out, dict):
        return {"reproduced": 0, "of": len(cases), "per_vector": {}, "missing": sorted(cases), "extra": [],
                "problem": "the output is not a JSON object keyed by case name"}
    per, ok = {}, 0
    for case, c in cases.items():
        want = signature(c["expect"])
        raw = out.get(case)
        got = signature(raw)
        hit = got is not None and got == want
        ok += hit
        entry = {"ok": hit, "got": short(got) if got else None, "want": short(want)}
        if raw is None:
            entry["problem"] = "missing"
        elif got is None:
            entry["problem"] = ("error: " + str(raw.get("error"))[:160]) if isinstance(raw, dict) and "error" in raw else "not a verdict signature"
        per[case] = entry
    extra = sorted(str(k)[:120] for k in out if k not in cases)
    res = {"reproduced": ok, "of": len(cases), "per_vector": per, "missing": sorted(k for k in cases if k not in out), "extra": extra[:MAX_LIST]}
    if len(extra) > MAX_LIST:
        res["extra_more"] = len(extra) - MAX_LIST
    return res


def run(name, cmd, cwd=None, env=None, root=None, timeout=900):
    """Write the batch, run cmd (a list; {in} and {out} are replaced), read the output and score it."""
    cases, batch = load_corpus(name, root)
    with tempfile.TemporaryDirectory(prefix="tsunagi-") as t:
        inp, outp = os.path.join(t, "in.json"), os.path.join(t, "out.json")
        with open(inp, "w", encoding="utf-8") as f:
            f.write(batch_text(name, root))
        argv = [a.replace("{in}", inp).replace("{out}", outp) for a in cmd]
        e = dict(os.environ)
        e.update(env or {})
        try:
            p = subprocess.run(argv, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
            code, stderr = p.returncode, p.stderr
        except subprocess.TimeoutExpired:
            code, stderr = 124, "timeout after %ss" % timeout
        except FileNotFoundError as x:
            code, stderr = 127, str(x)
        try:
            out = read_output(outp)
        except Exception as x:  # too large, not JSON, too deeply nested: the output is unusable, scored as such
            res = score(cases, None)
            res.update({"exit": code, "problem": "no readable output file (%s)" % type(x).__name__, "stderr_tail": stderr.strip()[-300:]})
            return res
    res = score(cases, out)
    res["exit"] = code
    return res


def _print(name, res):
    for case, v in res["per_vector"].items():
        if v["ok"]:
            print("ok   %s  %s" % (case, v["got"]))
        else:
            print("NG   %s  want %s  got %s%s" % (case, v["want"], v["got"], ("  (" + v["problem"] + ")") if v.get("problem") else ""))
    for k in res.get("extra", []):
        print("NG   %s  not in the corpus" % k)
    if res.get("problem"):
        print("problem: " + res["problem"])
    print("%s: %d/%d verdict signatures reproduced (refereed by nenrin-tsunagi)" % (name, res["reproduced"], res["of"]))


def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if a else 2
    cmd = a[0]
    if cmd == "list":
        for n in sorted(CORPORA):
            cases, _ = load_corpus(n)
            print("%-26s %3d cases" % (n, len(cases)))
        return 0
    if cmd == "batch-in" and len(a) == 3:
        _, batch = load_corpus(a[1])
        with open(a[2], "w", encoding="utf-8") as f:
            json.dump(batch, f, ensure_ascii=False)
        print("wrote %d cases of %s to %s" % (len(batch), a[1], a[2]))
        return 0
    if cmd == "score" and len(a) == 3:
        cases, _ = load_corpus(a[1])
        res = score(cases, read_output(a[2]))
        _print(a[1], res)
        return 0 if res["reproduced"] == res["of"] and not res["extra"] else 1
    if cmd in ("run", "row") and len(a) >= 4 and a[2] == "--":
        name, user = a[1], a[3:]
        if len(user) == 1:
            user = shlex.split(user[0])
        if not any("{in}" in x for x in user) or not any("{out}" in x for x in user):
            print("the command must contain {in} and {out}", file=sys.stderr)
            return 2
        if cmd == "row":
            cases, _ = load_corpus(name)
            board = [x.replace("{in}", "@in").replace("{out}", "@out") for x in user]
            print(json.dumps({"corpus": name, "cwd": "@impl", "cmd": board, "parse": "batch_referee", "total": len(cases)}, indent=2))
            return 0
        res = run(name, user)
        _print(name, res)
        return 0 if res["reproduced"] == res["of"] and not res["extra"] and res.get("exit") == 0 else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
