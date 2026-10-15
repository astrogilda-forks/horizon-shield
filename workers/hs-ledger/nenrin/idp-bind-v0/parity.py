#!/usr/bin/env python3
"""parity.py: the JS reference (idp_bind.mjs) and the Python port (idp_bind.py) over the same inputs, verdict signature
by verdict signature. Inputs: the 14 frozen fixtures, and for each fixture a set of one-field mutations (a key
dropped, a value replaced by null, 0, "", [], {}, a bit of the actor signature flipped, the JWKS digest changed, the
token's segments damaged). Every input is handed to both as the same JSON text; a difference is printed and fails.

    python3 -I parity.py            (needs node on the path)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import idp_bind  # noqa: E402

JS = r"""
import { readFileSync } from "node:fs";
import { verify } from "%s";
const inputs = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = {};
for (const [name, inp] of Object.entries(inputs)) {
  try { const r = verify(inp); out[name] = { verdict: r.verdict, refusals: [...new Set(r.refusals.map((x) => x.code))].sort(), findings: [...new Set(r.findings.map((x) => x.code))].sort() }; }
  catch (e) { out[name] = { threw: String(e && e.message || e) }; }
}
process.stdout.write(JSON.stringify(out));
""" % (os.path.join(HERE, "idp_bind.mjs").replace("\\", "/"))


def mutations(name, inp):
    out = {}
    b = inp["binding"]
    for k in list(b.keys()):
        m = json.loads(json.dumps(inp)); del m["binding"][k]; out[name + "/drop:" + k] = m
        for label, v in (("null", None), ("zero", 0), ("empty", ""), ("list", []), ("obj", {}), ("true", True)):
            m = json.loads(json.dumps(inp)); m["binding"][k] = v; out[name + "/" + label + ":" + k] = m
    if isinstance(b.get("idp"), dict):
        for k in list(b["idp"].keys()):
            m = json.loads(json.dumps(inp)); del m["binding"]["idp"][k]; out[name + "/drop:idp." + k] = m
            m = json.loads(json.dumps(inp)); m["binding"]["idp"][k] = m["binding"]["idp"][k] + "x"; out[name + "/x:idp." + k] = m
    if isinstance(b.get("actor_sig"), str):
        import base64
        raw = bytearray(base64.b64decode(b["actor_sig"])); raw[3] ^= 1
        m = json.loads(json.dumps(inp)); m["binding"]["actor_sig"] = base64.b64encode(bytes(raw)).decode(); out[name + "/flip:actor_sig"] = m
        m = json.loads(json.dumps(inp)); m["binding"]["actor_sig"] = b["actor_sig"] + "\n"; out[name + "/newline:actor_sig"] = m
    if isinstance(b.get("token"), str):
        parts = b["token"].split(".")
        if len(parts) == 3:
            for i in range(3):
                p2 = list(parts); p2[i] = p2[i][:-1] + ("A" if p2[i][-1] != "A" else "B")
                m = json.loads(json.dumps(inp)); m["binding"]["token"] = ".".join(p2); out[name + "/damage:token.%d" % i] = m
            m = json.loads(json.dumps(inp)); m["binding"]["token"] = ".".join(parts[:2]); out[name + "/two-segments:token"] = m
            m = json.loads(json.dumps(inp)); m["binding"]["token"] = b["token"] + "="; out[name + "/padding:token"] = m
    for k in ("jwks",):
        m = json.loads(json.dumps(inp)); m.pop(k, None); out[name + "/drop:" + k] = m
        m = json.loads(json.dumps(inp)); m[k] = {"sha256": "0" * 64, "document": inp.get(k, {}).get("document", "")}; out[name + "/badsha:" + k] = m
        m = json.loads(json.dumps(inp)); d = inp.get(k, {}).get("document", "{}"); m[k] = {"sha256": idp_bind.sha256hex("{}"), "document": "{}"}; out[name + "/emptydoc:" + k] = m
        m = json.loads(json.dumps(inp)); m[k] = {"sha256": idp_bind.sha256hex("not json"), "document": "not json"}; out[name + "/notjson:" + k] = m
    for label, v in (("binding:null", {"binding": None, "jwks": inp.get("jwks")}), ("binding:list", {"binding": [], "jwks": inp.get("jwks")}), ("empty", {}), ("list", [])):
        out[name + "/" + label] = v
    return out


def main():
    exp = json.load(open(os.path.join(HERE, "expected.json"), encoding="utf-8"))
    inputs = {}
    for name in exp["cases"]:
        inp = json.load(open(os.path.join(HERE, "fixtures", name + ".json"), encoding="utf-8"))
        inputs[name] = inp
        inputs.update(mutations(name, inp))
    with tempfile.TemporaryDirectory() as td:
        ip = os.path.join(td, "inputs.json"); jp = os.path.join(td, "run.mjs")
        with open(ip, "w", encoding="utf-8") as f:
            json.dump(inputs, f)
        with open(jp, "w", encoding="utf-8") as f:
            f.write(JS)
        js = json.loads(subprocess.run(["node", jp, ip], capture_output=True, check=True).stdout)
    py = {}
    for name, inp in inputs.items():
        try:
            py[name] = idp_bind.signature(idp_bind.verify(json.loads(json.dumps(inp))))
        except Exception as e:  # noqa: BLE001
            py[name] = {"threw": str(e)}
    diff = [n for n in inputs if js.get(n) != py.get(n)]
    for n in diff[:20]:
        print("DIFF", n, "js=", json.dumps(js.get(n)), "py=", json.dumps(py.get(n)))
    threw = sum(1 for n in inputs if "threw" in js.get(n, {}) or "threw" in py.get(n, {}))
    print("%d inputs (%d fixtures + mutations), %d differences, %d threw" % (len(inputs), len(exp["cases"]), len(diff), threw))
    sys.exit(1 if diff or threw else 0)


if __name__ == "__main__":
    main()
