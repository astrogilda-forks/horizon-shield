#!/usr/bin/env python3
"""Cross-language step 1: text-level rewrites that only exist as JSON text, sent as the same bytes to the
JavaScript reference, the Python port and the Go port. Read only, local only, no network.

  cd workers/hs-ledger/nenrin/sdk-go && go build -o /tmp/nv-go ./cmd/nenrin-verify-go
  python3 parity/xlang_step1.py .. /tmp/nv-go /tmp/xlang-out

Each base bundle (interop-v0.2/edge) is written as compact JSON text and rewritten at the text level:
1 duplicate key, different values (the original value last); 2 duplicate key, same value;
3a/3b/3c the integer 0 written as 0.0, 0e0, 0E0; 4 9007199254740993; 5 -0;
6 an escaped lone surrogate \\ud800 in a signed string; 7 a raw U+2028 in a signed string;
8 the grant's keys out of canonical order; 9 a signed string with its ASCII hyphens written as \\u002d (same value);
10 a duplicate key inside a witness-signed observation (conduct.verdict, the signed value last).
A row agrees when the three readers all threw, or give the same verdict signature and the same refusals as
(code, reason) in order (the rule of sdk-go/parity/parity.py).
"""
import json, os, subprocess, sys

NENRIN, GO, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
BASES = ["sig_canonical_ok", "unknown_bundle_keys", "seq_duplicate_same_verdict", "sig_missing_padding", "ts_impossible_day"]
NONCE = '"nonce":"n-edge-1"'
SEQ = '"seq":0'
SCHEMA = '"schema":"task-execution-bind-v0/grant",'


def once(text, old, new):
    assert text.count(old) >= 1, old
    return text.replace(old, new, 1)


def grant_reordered(text):
    i = text.index('"grant":{') + len('"grant":{')
    assert text[i:].startswith(SCHEMA)
    j = text.index("}", text.index('"caller_sig"', i))
    body = text[i + len(SCHEMA):j]
    return text[:i] + body + "," + SCHEMA[:-1] + text[j:]


REWRITES = [
    ("1_dup_key_diff", lambda t: once(t, NONCE, '"nonce":"n-evil",' + NONCE)),
    ("2_dup_key_same", lambda t: once(t, NONCE, NONCE + "," + NONCE)),
    ("3a_num_0.0", lambda t: once(t, SEQ, '"seq":0.0')),
    ("3b_num_0e0", lambda t: once(t, SEQ, '"seq":0e0')),
    ("3c_num_0E0", lambda t: once(t, SEQ, '"seq":0E0')),
    ("4_num_2^53+1", lambda t: once(t, SEQ, '"seq":9007199254740993')),
    ("5_num_-0", lambda t: once(t, SEQ, '"seq":-0')),
    ("6_lone_surrogate", lambda t: once(t, NONCE, '"nonce":"n-edge-1\\ud800"')),
    ("7_raw_u2028", lambda t: once(t, NONCE, '"nonce":"n-edge-1 "')),
    ("8_key_order", grant_reordered),
    ("9_escaped_ascii", lambda t: once(t, NONCE, '"nonce":"n\\u002dedge\\u002d1"')),
    ("10_dup_key_observation", lambda t: once(t, '"verdict":"ok"', '"verdict":"bad","verdict":"ok"')),
]


def py_rows(texts):
    sys.path.insert(0, os.path.join(NENRIN, "sdk-python", "src"))
    import nenrin_verify as nv
    from nenrin_verify._js import loads, assign
    rows = []
    for t in texts:
        try:
            rep = nv.verify_provenance(assign(loads(t), {"resolve": nv.did_key_resolver}))
            rows.append({"threw": False,
                         "signature": {"verdict": rep["verdict"], "refusals": sorted({r["code"] for r in rep["refusals"]}),
                                       "findings": sorted({f["code"] for f in rep["findings"]})},
                         "codes": [{"code": r["code"], "reason": r["reason"] if isinstance(r.get("reason"), str) else (r["status"] if isinstance(r.get("status"), str) else "")} for r in rep["refusals"]]})
        except Exception as e:  # noqa: BLE001
            rows.append({"threw": True, "error": (type(e).__name__ + ": " + str(e))[:200]})
    return rows


def run(cmd, texts):
    p = subprocess.run(cmd, input=("\n".join(texts) + "\n").encode("utf-8", "surrogatepass"), capture_output=True)
    if p.returncode != 0:
        sys.exit(p.stderr.decode()[-2000:])
    rows = [json.loads(l) for l in p.stdout.decode("utf-8").split("\n") if l]
    assert len(rows) == len(texts), (len(rows), len(texts))
    return rows


def norm(r):
    if r["threw"]:
        return ("threw",)
    return (json.dumps(r["signature"], sort_keys=True), json.dumps([{"code": c["code"], "reason": c.get("reason", "")} for c in r.get("codes") or []]))


def short(r):
    if r["threw"]:
        return "threw: " + r.get("error", "")[:90]
    s = r["signature"]
    return s["verdict"] + " " + ",".join(s["refusals"])


def main():
    os.makedirs(OUT, exist_ok=True)
    cases = []
    for b in BASES:
        base = json.dumps(json.load(open(os.path.join(NENRIN, "interop-v0.2/edge/fixtures", b + ".json"), encoding="utf-8")), ensure_ascii=False, separators=(",", ":"))
        cases.append((b, "0_base", base))
        for name, f in REWRITES:
            cases.append((b, name, f(base)))
    texts = [t for _b, _n, t in cases]
    with open(os.path.join(OUT, "inputs.jsonl"), "wb") as fh:
        fh.write(("\n".join(texts) + "\n").encode("utf-8", "surrogatepass"))
    js = run(["node", os.path.join(NENRIN, "sdk-go/parity/js_sig_runner.mjs"), os.path.join(NENRIN, "sdk/nenrin_verify.mjs")], texts)
    go = run([GO, "--lines"], texts)
    py = py_rows(texts)
    table, bad = [], 0
    for (b, n, _t), j, p, g in zip(cases, js, py, go):
        same = norm(j) == norm(p) == norm(g)
        bad += 0 if same else 1
        table.append({"base": b, "rewrite": n, "agree": same, "js": j, "py": p, "go": g})
    with open(os.path.join(OUT, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(table, fh, ensure_ascii=False, indent=1)
    for r in table:
        print("%-5s %-27s %-17s js: %-45s py: %-45s go: %s" % ("ok" if r["agree"] else "DIFF", r["base"], r["rewrite"], short(r["js"]), short(r["py"]), short(r["go"])))
    print("%d inputs (%d rewrites), %d differ" % (len(table), len(table) - len(BASES), bad))
    return 1 if bad else 0


sys.exit(main())
