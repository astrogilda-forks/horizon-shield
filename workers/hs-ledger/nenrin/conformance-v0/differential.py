#!/usr/bin/env python3
"""conformance-v0 judge: run every bundle through each verifier and print every disagreement.

Verifiers compared (verdict signature = verdict, set of refusal codes, set of finding codes):
  js     ../sdk/nenrin_verify.mjs (the published npm file), through node
  py     ../sdk-python/src (the PyPI port)
  extra  any number of --impl path.py modules exposing verify(bundle) -> (signature, reasons) or signature,
         for example an implementation written from VERIFIER.md alone.
Inputs: the frozen corpora (../interop-v0, ../interop-v0.1), the pinned edge bundles (pinned/), plus a generated
file from gen_edge_bundles.mjs. Exit 1 when any verifier disagrees with js, or js disagrees with pinned/expected.json. A disagreement is a finding against the spec, the reference or the
other implementation; the triage says which, never this script.
  python3 differential.py [--edge edge_bundles.json ...] [--impl path/to/verify.py ...]
"""
import argparse, glob, importlib.util, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NENRIN = os.path.dirname(HERE)


def corpus():
    out = []
    for d in ("interop-v0", "interop-v0.1"):
        for f in sorted(glob.glob(os.path.join(NENRIN, d, "fixtures", "*.json"))):
            out.append({"name": d + "/" + os.path.basename(f)[:-5], "bundle": json.load(open(f))})
    for f in sorted(glob.glob(os.path.join(HERE, "pinned", "fixtures", "*.json"))):
        out.append({"name": "pinned/" + os.path.basename(f)[:-5], "bundle": json.load(open(f))})
    return out


def pinned_expected():
    p = os.path.join(HERE, "pinned", "expected.json")
    if not os.path.exists(p):
        return {}
    return {"pinned/" + k: v["expect"] for k, v in json.load(open(p))["cases"].items()}


def sig(verdict, refusals, findings):
    return {"verdict": verdict, "refusals": sorted(set(refusals)), "findings": sorted(set(findings))}


def run_js(cases):
    with tempfile.TemporaryDirectory() as t:
        inp, outp = os.path.join(t, "in.json"), os.path.join(t, "out.json")
        json.dump(cases, open(inp, "w"))
        script = (
            "import {readFileSync,writeFileSync} from 'node:fs';"
            "import {verifyProvenance,didKeyResolver} from " + json.dumps("file://" + os.path.join(NENRIN, "sdk", "nenrin_verify.mjs")) + ";"
            "const c=JSON.parse(readFileSync(process.argv[1],'utf8'));const o={};"
            "for(const m of c){try{const p=verifyProvenance(Object.assign({},m.bundle,{resolve:didKeyResolver}));"
            "o[m.name]={verdict:p.verdict,refusals:[...new Set(p.refusals.map(r=>r.code))].sort(),findings:[...new Set(p.findings.map(f=>f.code))].sort()};}"
            "catch(e){o[m.name]={error:String(e.message)};}}writeFileSync(process.argv[2],JSON.stringify(o));")
        subprocess.run(["node", "--input-type=module", "-e", script, inp, outp], check=True)
        return json.load(open(outp))


def run_py(cases):
    sys.path.insert(0, os.path.join(NENRIN, "sdk-python", "src"))
    import nenrin_verify as m
    out = {}
    for c in cases:
        try:
            b = dict(c["bundle"]); b["resolve"] = m.did_key_resolver
            p = m.verify_provenance(b)
            out[c["name"]] = sig(p["verdict"], [r["code"] for r in p["refusals"]], [f["code"] for f in p["findings"]])
        except Exception as e:
            out[c["name"]] = {"error": str(e)}
    return out


def run_impl(path, cases):
    spec = importlib.util.spec_from_file_location("impl_" + str(abs(hash(path))), path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    out = {}
    for c in cases:
        try:
            r = mod.verify(json.loads(json.dumps(c["bundle"])))
            s = r[0] if isinstance(r, tuple) else r
            out[c["name"]] = sig(s["verdict"], s["refusals"], s["findings"])
        except Exception as e:
            out[c["name"]] = {"error": str(e)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edge", action="append", default=[], help="bundles from gen_edge_bundles.mjs (repeatable)")
    ap.add_argument("--impl", action="append", default=[], help="extra verifier module with verify(bundle)")
    a = ap.parse_args()
    cases = corpus()
    for e in a.edge:
        cases += json.load(open(e))
    results = {"js": run_js(cases), "py": run_py(cases)}
    for p in a.impl:
        results[os.path.basename(p)] = run_impl(p, cases)
    pinned = pinned_expected()
    bad = 0
    for c in cases:
        n = c["name"]; ref = results["js"][n]
        diffs = {k: v[n] for k, v in results.items() if k != "js" and v[n] != ref}
        if n in pinned and ref != pinned[n]:
            diffs["pinned"] = pinned[n]
        if diffs:
            bad += 1
            print("DISAGREE " + n + "\n  js      " + json.dumps(ref) + "".join("\n  %-7s %s" % (k, json.dumps(v)) for k, v in diffs.items()))
    print("\n%d bundles, %d verifiers, %d disagreements" % (len(cases), len(results), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
