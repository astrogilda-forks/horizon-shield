#!/usr/bin/env python3
"""Mutation adequacy of the NENRIN provenance corpora: can the frozen corpora tell deliberately wrong verifiers apart?

What it does, in order (any failed step stops the run and the report says which):
  1. pins: the repository commit, the checker bytes (provenance.py, and a digest of the whole nenrin_verify tree),
     every corpus file's sha256, and that sdk/tsunagi_corpora.json carries the same four interop corpora;
  2. baseline: the UNMUTATED Python port must reproduce every expected verdict signature (and every reason the
     corpora record) before any mutant is run. If it does not, nothing below is measured;
  3. the tool: stages a disposable tree (the nenrin_verify source, verdict_signature.py, byte copies of the vectors),
     writes a corpus-adequacy manifest from mutations.json and runs corpus-adequacy (Rul1an's tool,
     github.com/corpus-adequacy/corpus-adequacy) on it with --json. The tool compares each mutant with the baseline
     run; step 2 made the baseline equal to the expected outcomes, so a moved outcome is an outcome that differs
     from expected;
  4. the cross-check: applies the same substitutions itself and compares each mutant's outcome with expected.json
     directly. This is what names the killing case ids (the tool reports counts, not ids), and it must agree with
     the tool on every verdict;
  5. proposed vectors (proposed_vectors/, not part of any frozen corpus): each must give its intended outcome on the
     unmutated checker and a different outcome under the fault it targets. When node is on PATH the published JS
     reference (sdk/nenrin_verify.mjs) is run on them too. Then the tool runs once more with the proposals added to
     the frozen vectors (tool_report_with_proposals.v0.json): the score the corpora would have if they adopted them;
  6. a side probe, outside the score: F7 applied to the JS reference's execution check, on the frozen vectors.

  python3 run_adequacy.py --tool /path/to/corpus-adequacy [--out DIR] [--no-tool]

Writes report.json, tool_report.v0.json and tool_report_with_proposals.v0.json (the tool's own bytes) into --out
(default: this directory), plus corpus_adequacy.manifest.json, the exact manifest bytes the tool measured (the same
bytes for both runs; only the staged vectors.json differs). The tool reports carry the temporary path of the staged
manifest. No network, no clock in any verdict.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NENRIN = os.path.normpath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(NENRIN, "sdk-python", "src")
PKG = os.path.join(SRC, "nenrin_verify")
CHECKER = os.path.join(PKG, "provenance.py")
ADAPTER = os.path.join(HERE, "verdict_signature.py")

# corpora that carry an expected verdict signature per fixture, in the provenance verifier's input format
CORPORA = [
    ("interop-v0", "interop-v0"),
    ("interop-v0.1", "interop-v0.1"),
    ("interop-v0.2-edge", "interop-v0.2/edge"),
    ("interop-v0.2-action-presence", "interop-v0.2/action-presence"),
    ("conformance-v0-pinned", "conformance-v0/pinned"),
]
TSUNAGI_NAMES = {"interop-v0": "nenrin-interop-v0", "interop-v0.1": "nenrin-interop-v0.1",
                 "interop-v0.2-edge": "nenrin-interop-v0.2-edge",
                 "interop-v0.2-action-presence": "nenrin-interop-v0.2-action-presence"}
GROUP = "provenance"


def sha256_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def tree_digest(root):
    """sha256 over sorted 'relpath NUL sha256 LF' lines of every regular file under root (no __pycache__)."""
    lines = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for f in sorted(files):
            if f.endswith(".pyc"):
                continue
            p = os.path.join(d, f)
            lines.append(os.path.relpath(p, root).replace(os.sep, "/") + "\0" + sha256_file(p) + "\n")
    return hashlib.sha256("".join(sorted(lines)).encode("utf-8")).hexdigest(), len(lines)


def git(*args):
    p = subprocess.run(["git", "-C", NENRIN] + list(args), capture_output=True)
    return p.stdout if p.returncode == 0 else None


def rel(p):
    top = git("rev-parse", "--show-toplevel")
    base = top.decode().strip() if top else NENRIN
    return os.path.relpath(p, base).replace(os.sep, "/")


def sig_of(expect):
    return {"verdict": expect["verdict"], "refusals": ",".join(sorted(set(expect["refusals"]))),
            "findings": ",".join(sorted(set(expect["findings"])))}


def load_vectors():
    vectors, files, problems = [], {}, []
    for cid, d in CORPORA:
        base = os.path.join(NENRIN, d)
        exp_path = os.path.join(base, "expected.json")
        files[rel(exp_path)] = sha256_file(exp_path)
        exp = json.load(open(exp_path, encoding="utf-8"))
        listed = set()
        for name, case in exp["cases"].items():
            fx = os.path.join(base, "fixtures", name + ".json")
            if not os.path.isfile(fx):
                problems.append("missing fixture " + rel(fx))
                continue
            listed.add(name + ".json")
            files[rel(fx)] = sha256_file(fx)
            row = {"vector_id": cid + "/" + name, "corpus": cid, "case": name, "src": fx,
                   "path": "vectors/" + cid + "/" + name + ".json", "expect": sig_of(case["expect"])}
            if case.get("reasons"):
                row["pinned_reasons"] = ",".join(sorted(set(case["reasons"])))
            vectors.append(row)
        extra = sorted(set(os.listdir(os.path.join(base, "fixtures"))) - listed)
        if extra:
            problems.append("fixtures not in %s/expected.json: %s" % (d, extra))
    return vectors, files, problems


def tsunagi_check(vectors):
    path = os.path.join(NENRIN, "sdk", "tsunagi_corpora.json")
    doc = json.load(open(path, encoding="utf-8"))["corpora"]
    out = {"file": rel(path), "sha256": sha256_file(path), "corpora": {}}
    by = {}
    for v in vectors:
        by.setdefault(v["corpus"], []).append(v)
    for cid, tname in TSUNAGI_NAMES.items():
        c = doc[tname]
        d = dict(CORPORA)[cid]
        same_exp = c["expected_sha256"] == sha256_file(os.path.join(NENRIN, d, "expected.json"))
        same_fx = sorted(c["fixtures"]) == sorted(v["case"] for v in by[cid]) and all(
            c["fixtures"][v["case"]]["sha256"] == sha256_file(v["src"])
            and c["fixtures"][v["case"]]["text"].encode("utf-8") == open(v["src"], "rb").read() for v in by[cid])
        out["corpora"][tname] = {"expected_sha256_matches": same_exp, "fixtures_match": same_fx}
    out["ok"] = all(x["expected_sha256_matches"] and x["fixtures_match"] for x in out["corpora"].values())
    return out


def run_batch(src, vectors, stage):
    vfile = os.path.join(stage, "vectors.json")
    p = subprocess.run([sys.executable, "-I", "-B", ADAPTER, "--src", src, "--batch", vfile, stage],
                       capture_output=True, timeout=600)
    if p.returncode != 0:
        return None, p.stderr.decode("utf-8", "replace")[-2000:]
    return json.loads(p.stdout), None


def apply_mutation(source_text, mut):
    n = source_text.count(mut["anchor"])
    if n != 1:
        raise SystemExit("%s: anchor occurs %d times in provenance.py (must be exactly once)" % (mut["id"], n))
    return source_text.replace(mut["anchor"], mut["replacement"])


def mutated_tree(work, mut, original):
    d = os.path.join(work, "mut_" + mut["id"])
    shutil.copytree(SRC, d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    with open(os.path.join(d, "nenrin_verify", "provenance.py"), "w", encoding="utf-8", newline="") as f:
        f.write(apply_mutation(original, mut))
    return d


def sigkey(o):
    return (o["verdict"], o["refusals"], o["findings"])


def _reasons_cover(got, recorded):
    """interop-v0.1 records the reason of the refusal each case is about, not every reason: a subset check."""
    have = set(x for x in got.split(",") if x)
    return set(x for x in recorded.split(",") if x) <= have


def classify(vectors, outcomes, baseline):
    """Compare a mutant's outcomes with expected (signature) and with the baseline (reasons)."""
    killing, reason_moved, pinned_reason_moved = [], [], []
    for v in vectors:
        o = outcomes[v["vector_id"]]
        if sigkey(o) != sigkey(v["expect"]):
            killing.append(v["vector_id"])
        elif o["reasons"] != baseline[v["vector_id"]]["reasons"]:
            reason_moved.append(v["vector_id"])
            if "pinned_reasons" in v and not _reasons_cover(o["reasons"], v["pinned_reasons"]):
                pinned_reason_moved.append(v["vector_id"])
    verdict = "killed" if killing else ("silent" if reason_moved else "survived")
    return {"verdict": verdict, "killing_case_ids": killing, "reason_only_moves": reason_moved,
            "pinned_reason_moves": pinned_reason_moved}


def stage_tree(vectors, mutations, stage):
    shutil.copytree(SRC, os.path.join(stage, "src"), ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(ADAPTER, os.path.join(stage, "verdict_signature.py"))
    for v in vectors:
        dst = os.path.join(stage, v["path"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(v["src"], dst)
        if sha256_file(dst) != sha256_file(v["src"]):
            raise SystemExit("staged copy differs: " + v["path"])
    doc = {"vectors": [{"vector_id": v["vector_id"], "path": v["path"]} for v in vectors]}
    with open(os.path.join(stage, "vectors.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")
    manifest = {
        "schema": "corpus-adequacy.manifest.v0",
        "runner": "process",
        "repo_root": ".",
        "implementation": "src/nenrin_verify/provenance.py",
        "implementation_sources": ["src/nenrin_verify/provenance.py"],
        "build": [],
        "entrypoint_command": ["python3", "-I", "-B", "verdict_signature.py", "{vector}"],
        "outcome_from": ["verdict", "refusals", "findings"],
        "diagnostic_from": ["reasons"],
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "path",
        "default_group": GROUP,
        "vector_timeout": 120,
        "mutants": {GROUP: [{"label": m["label"], "anchor": m["anchor"], "replacement": m["replacement"]}
                            for m in mutations["faults"]]
                   + [{"label": c["label"], "control": True, "control_polarity": c["polarity"],
                       "anchor": c["anchor"], "replacement": c["replacement"]} for c in mutations["controls"]]},
    }
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open(os.path.join(stage, "manifest.json"), "wb") as f:
        f.write(raw)
    return raw


def run_tool(tool, stage):
    cli = os.path.join(tool, "corpus_adequacy.py")
    ver = subprocess.run([sys.executable, cli, "--version"], capture_output=True, text=True, timeout=60)
    p = subprocess.run([sys.executable, cli, os.path.join(stage, "manifest.json"), "--json"],
                       capture_output=True, timeout=3600)
    return ver.stdout.strip(), p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")[-3000:]


def run_js(fixtures):
    """The published JS reference on the proposed vectors, when node is present."""
    if shutil.which("node") is None:
        return None
    script = ("import {readFileSync} from 'node:fs';"
              "import {verifyProvenance,didKeyResolver} from " + json.dumps(
                  "file://" + os.path.join(NENRIN, "sdk", "nenrin_verify.mjs")) + ";"
              "const c=JSON.parse(readFileSync(0,'utf8'));const o={};"
              "for(const [n,f] of Object.entries(c)){const b=JSON.parse(readFileSync(f,'utf8'));"
              "const p=verifyProvenance(Object.assign({},b,{resolve:didKeyResolver}));"
              "o[n]={verdict:p.verdict,refusals:[...new Set(p.refusals.map(r=>r.code))].sort().join(','),"
              "findings:[...new Set(p.findings.map(f=>f.code))].sort().join(',')};}"
              "process.stdout.write(JSON.stringify(o));")
    p = subprocess.run(["node", "--input-type=module", "-e", script], input=json.dumps(fixtures).encode(),
                       capture_output=True, timeout=300)
    if p.returncode != 0:
        return {"error": p.stderr.decode("utf-8", "replace")[-1000:]}
    return json.loads(p.stdout)


def proposed(mutations, work, original, baseline_src):
    pdir = os.path.join(HERE, "proposed_vectors")
    exp_path = os.path.join(pdir, "expected.json")
    if not os.path.isfile(exp_path):
        return None
    exp = json.load(open(exp_path, encoding="utf-8"))
    rows = []
    for name, case in exp["cases"].items():
        fx = os.path.join(pdir, "fixtures", name + ".json")
        rows.append({"vector_id": "proposed/" + name, "case": name, "src": fx, "path": os.path.relpath(fx, pdir),
                     "expect": sig_of(case["expect"]), "targets": case["targets"]})
    stage =tempfile.mkdtemp(prefix="nenrin-adequacy-proposed-", dir=work)
    for r in rows:
        dst = os.path.join(stage, r["path"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(r["src"], dst)
    with open(os.path.join(stage, "vectors.json"), "w") as f:
        json.dump({"vectors": [{"vector_id": r["vector_id"], "path": r["path"]} for r in rows]}, f)
    base, err = run_batch(baseline_src, rows, stage)
    if base is None:
        raise SystemExit("proposed vectors: unmutated checker failed: " + err)
    js = run_js({r["vector_id"]: r["src"] for r in rows})
    per_fault = {}
    for m in mutations["faults"] + mutations["controls"]:
        d = mutated_tree(work, dict(m, id="p_" + m["id"]), original)
        out, err = run_batch(d, rows, stage)
        if out is None:
            raise SystemExit("proposed vectors: mutant %s failed: %s" % (m["id"], err))
        per_fault[m["id"]] = out
    results = {}
    for r in rows:
        vid = r["vector_id"]
        kills = [fid for fid, out in per_fault.items() if sigkey(out[vid]) != sigkey(r["expect"])
                 and not fid.startswith("CONTROL")]
        js_sig = None if js is None or "error" in js else js.get(vid)
        results[r["case"]] = {
            "file": rel(r["src"]), "sha256": sha256_file(r["src"]), "targets": r["targets"],
            "expect": r["expect"], "unmutated_python": {k: base[vid][k] for k in ("verdict", "refusals", "findings")},
            "unmutated_python_matches_expect": sigkey(base[vid]) == sigkey(r["expect"]),
            "js_reference": js_sig,
            "js_reference_matches_expect": None if js_sig is None else sigkey(js_sig) == sigkey(r["expect"]),
            "kills": kills,
            "kills_every_target": all(t in kills for t in r["targets"]),
            "outcome_under_targets": {t: {k: per_fault[t][vid][k] for k in ("verdict", "refusals", "findings")}
                                      for t in r["targets"]},
        }
    return {"expected_file": rel(exp_path), "expected_sha256": sha256_file(exp_path),
            "status": exp.get("status"), "vectors": results,
            "all_verified": all(x["unmutated_python_matches_expect"] and x["kills_every_target"]
                                and x["js_reference_matches_expect"] is not False for x in results.values())}


JS_F7_ANCHOR = ('  if (!isRfc3339Utc(r.executed_at) || (g.not_before != null && !isRfc3339Utc(g.not_before)) || '
                '(g.not_after != null && !isRfc3339Utc(g.not_after)))\n    return { ok: false, reason: "invalid_timestamp", findings };')
JS_F7_REPLACEMENT = '  if (false) return { ok: false, reason: "invalid_timestamp", findings };'


def js_probe_f7(vectors, work):
    """Side probe, not part of the score: F7 applied to the JS reference's execution check (step 2a), run on every
    frozen vector. The Python port's date_parse returns None for strings outside the strict RFC3339 form, where V8's
    Date.parse reads offsets and lowercase letters, so the same fault can be visible in one checker and not the other."""
    if shutil.which("node") is None:
        return None
    src = open(os.path.join(NENRIN, "sdk", "nenrin_verify.mjs"), encoding="utf-8").read()
    if src.count(JS_F7_ANCHOR) != 1:
        return {"error": "the JS anchor does not occur exactly once"}
    d = os.path.join(work, "js_f7")
    os.makedirs(d)
    with open(os.path.join(d, "nenrin_verify.mjs"), "w", encoding="utf-8") as f:
        f.write(src.replace(JS_F7_ANCHOR, JS_F7_REPLACEMENT))
    script = ("import {readFileSync} from 'node:fs';"
              "import {verifyProvenance,didKeyResolver} from " + json.dumps(
                  "file://" + os.path.join(d, "nenrin_verify.mjs")) + ";"
              "const c=JSON.parse(readFileSync(0,'utf8'));const o={};"
              "for(const [n,f] of Object.entries(c)){const b=JSON.parse(readFileSync(f,'utf8'));"
              "const p=verifyProvenance(Object.assign({},b,{resolve:didKeyResolver}));"
              "o[n]={verdict:p.verdict,refusals:[...new Set(p.refusals.map(r=>r.code))].sort().join(','),"
              "findings:[...new Set(p.findings.map(f=>f.code))].sort().join(',')};}"
              "process.stdout.write(JSON.stringify(o));")
    p = subprocess.run(["node", "--input-type=module", "-e", script],
                       input=json.dumps({v["vector_id"]: v["src"] for v in vectors}).encode(),
                       capture_output=True, timeout=300)
    if p.returncode != 0:
        return {"error": p.stderr.decode("utf-8", "replace")[-1000:]}
    out = json.loads(p.stdout)
    killing = [v["vector_id"] for v in vectors if sigkey(out[v["vector_id"]]) != sigkey(v["expect"])]
    return {"checker": rel(os.path.join(NENRIN, "sdk", "nenrin_verify.mjs")),
            "checker_sha256": sha256_file(os.path.join(NENRIN, "sdk", "nenrin_verify.mjs")),
            "function": "verifyExecution (step 2a)", "anchor": JS_F7_ANCHOR, "replacement": JS_F7_REPLACEMENT,
            "verdict": "killed" if killing else "not killed", "killing_case_ids": killing,
            "note": "applied to the execution check only; the preflight check (step 3) is left strict"}


def tool_with_proposals(a, mutations, vectors, work):
    """The same tool run with the proposed vectors added to the frozen ones: what the score would be if the
    proposals were adopted. The proposals' intended outcomes were already checked against both references."""
    pdir = os.path.join(HERE, "proposed_vectors")
    exp = json.load(open(os.path.join(pdir, "expected.json"), encoding="utf-8"))
    rows = list(vectors) + [{"vector_id": "proposed/" + n, "src": os.path.join(pdir, "fixtures", n + ".json"),
                             "path": "vectors/proposed/" + n + ".json"} for n in exp["cases"]]
    stage = os.path.join(work, "stage_with_proposals")
    os.makedirs(stage)
    stage_tree(rows, mutations, stage)
    ver, code, stdout, stderr = run_tool(a.tool, stage)
    with open(os.path.join(a.out, "tool_report_with_proposals.v0.json"), "wb") as f:
        f.write(stdout)
    try:
        trep = json.loads(stdout)
    except Exception:
        return {"error": stderr, "exit": code}
    return {"report_file": "tool_report_with_proposals.v0.json", "report_sha256": hashlib.sha256(stdout).hexdigest(),
            "vectors": len(rows), "exit": code, "control_status": trep.get("control_status"),
            "killed": trep.get("killed"), "survived": trep.get("survived"), "silent": trep.get("silent"),
            "unproved": trep.get("unproved"), "score_percent": trep.get("score_percent"),
            "adequate": trep.get("adequate"),
            "rows": {r["label"]: {"verdict": r["verdict"], "moved": r.get("moved")} for r in trep.get("mutants", [])}}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", help="path to a corpus-adequacy checkout (corpus_adequacy.py)")
    ap.add_argument("--out", default=HERE)
    ap.add_argument("--no-tool", action="store_true", help="skip the corpus-adequacy run (cross-check only)")
    a = ap.parse_args(argv)
    if not a.no_tool and not a.tool:
        ap.error("--tool is required unless --no-tool")
    mutations = json.load(open(os.path.join(HERE, "mutations.json"), encoding="utf-8"))
    original = open(CHECKER, encoding="utf-8", newline="").read()
    for m in mutations["faults"] + mutations["controls"]:
        apply_mutation(original, m)          # every anchor exactly once, before anything runs

    head = (git("rev-parse", "HEAD") or b"").decode().strip() or None
    checker_rel = rel(CHECKER)
    at_head = git("show", "HEAD:" + checker_rel)
    tdig, tcount = tree_digest(PKG)
    vectors, corpus_files, problems = load_vectors()
    report = {
        "schema": "nenrin-adequacy-report-v0",
        "measured": "mutation adequacy of the frozen NENRIN provenance corpora against the Python port",
        "pins": {
            "repository": "github.com/ogasurfproject-jpg/horizon-shield",
            "repo_commit": head,
            "checker": {"file": checker_rel, "sha256": sha256_file(CHECKER),
                        "identical_to_repo_commit": at_head is not None and at_head == open(CHECKER, "rb").read(),
                        "package_tree": rel(PKG), "package_tree_sha256": tdig, "package_tree_files": tcount,
                        "adapter": rel(ADAPTER), "adapter_sha256": sha256_file(ADAPTER)},
            "mutations_file": rel(os.path.join(HERE, "mutations.json")),
            "mutations_sha256": sha256_file(os.path.join(HERE, "mutations.json")),
            # sha256sum lines ("<sha256>  <path>"), not a {path: sha256} map: fixture names such as
            # grant_key_not_object.json followed by a hex digest read as a credential to secret scanners
            "corpus_files_sha256sum": sorted("%s  %s" % (h, p) for p, h in corpus_files.items()),
            "python": platform.python_version(),
        },
        "outcome_definition": {
            "outcome": "verdict signature of VERIFIER.md section 4: verdict, sorted set of refusal codes, sorted set of finding codes",
            "diagnostic": "sorted set of refusal reasons (and the status of execution_unreconciled); not part of the signature. interop-v0.1 records, for readers, the reason of the refusal 6 of its cases are about (checked as a subset); no corpus makes reasons normative",
            "killed": "at least one vector's outcome differs from its expected signature",
            "silent": "no outcome differs, but at least one refusal reason moved (corpus-adequacy's silent class): the corpora cannot see the fault in their pinned outcomes",
            "survived": "nothing moved",
        },
    }
    try:
        import cryptography
        report["pins"]["cryptography"] = cryptography.__version__
    except Exception:
        pass
    if problems:
        report["status"] = "corpus_problem"
        report["problems"] = problems
        return finish(a.out, report, 1)
    report["pins"]["vectors"] = len(vectors)
    report["pins"]["vectors_per_corpus"] = {cid: sum(1 for v in vectors if v["corpus"] == cid) for cid, _ in CORPORA}
    report["pins"]["tsunagi_corpora"] = tsunagi_check(vectors)

    work = tempfile.mkdtemp(prefix="nenrin-adequacy-")
    try:
        stage = os.path.join(work, "stage")
        os.makedirs(stage)
        manifest_raw = stage_tree(vectors, mutations, stage)
        with open(os.path.join(a.out, "corpus_adequacy.manifest.json"), "wb") as f:
            f.write(manifest_raw)
        report["pins"]["tool_manifest"] = {"file": "corpus_adequacy.manifest.json",
                                           "sha256": hashlib.sha256(manifest_raw).hexdigest()}

        # 2. baseline must equal expected before anything is mutated
        baseline, err = run_batch(SRC, vectors, stage)
        if baseline is None:
            report["status"] = "baseline_error"
            report["error"] = err
            return finish(a.out, report, 1)
        mism = [{"vector_id": v["vector_id"], "expected": v["expect"], "got": baseline[v["vector_id"]]}
                for v in vectors if sigkey(baseline[v["vector_id"]]) != sigkey(v["expect"])]
        rmism = [{"vector_id": v["vector_id"], "expected_reasons": v["pinned_reasons"],
                  "got": baseline[v["vector_id"]]["reasons"]}
                 for v in vectors if "pinned_reasons" in v and not _reasons_cover(baseline[v["vector_id"]]["reasons"], v["pinned_reasons"])]
        report["baseline"] = {"vectors": len(vectors), "signature_mismatches": mism,
                              "recorded_reason_mismatches": rmism,
                              "vectors_with_recorded_reasons": sum(1 for v in vectors if "pinned_reasons" in v)}
        if mism or rmism:
            report["status"] = "baseline_mismatch"
            return finish(a.out, report, 1)

        # 4. cross-check (done before the tool so the ids exist even if the tool refuses)
        cross = {}
        for m in mutations["faults"] + mutations["controls"]:
            d = mutated_tree(work, m, original)
            out, err = run_batch(d, vectors, stage)
            if out is None:
                cross[m["id"]] = {"verdict": "error", "error": err}
                continue
            cross[m["id"]] = classify(vectors, out, baseline)

        # 3. the tool
        tool_rows = {}
        if not a.no_tool:
            ver, code, stdout, stderr = run_tool(a.tool, stage)
            with open(os.path.join(a.out, "tool_report.v0.json"), "wb") as f:
                f.write(stdout)
            try:
                trep = json.loads(stdout)
            except Exception:
                report["status"] = "tool_error"
                report["tool"] = {"version_line": ver, "exit": code, "stderr": stderr}
                return finish(a.out, report, 1)
            tool_rows = {r["label"]: r for r in trep.get("mutants", [])}
            report["tool"] = {
                "name": "corpus-adequacy", "repository": "github.com/corpus-adequacy/corpus-adequacy",
                "version": trep.get("tool_version"), "commit": trep.get("tool_commit"),
                "source_state": trep.get("tool_source_state"), "content_sha256": trep.get("tool_content_sha256"),
                "version_line": ver, "exit": code,
                "report_file": "tool_report.v0.json", "report_sha256": hashlib.sha256(stdout).hexdigest(),
                "manifest_sha256": trep.get("manifest_sha256"), "runner": trep.get("runner"),
                "control_status": trep.get("control_status"), "killed": trep.get("killed"),
                "survived": trep.get("survived"), "silent": trep.get("silent"), "unproved": trep.get("unproved"),
                "score_percent": trep.get("score_percent"), "adequate": trep.get("adequate"),
                "failures": trep.get("failures"),
            }

        def row(m, control=False):
            c = cross[m["id"]]
            r = {"id": m["id"], "label": m["label"], "file": mutations["file"], "function": m["function"],
                 "rule": m["rule"], "anchor": m["anchor"], "replacement": m["replacement"],
                 "verdict": c["verdict"], "killing_case_ids": c.get("killing_case_ids", []),
                 "reason_only_moves": c.get("reason_only_moves", []),
                 "recorded_reason_moves": c.get("pinned_reason_moves", [])}
            if control:
                r["polarity"] = m["polarity"]
                r["control_ok"] = (c["verdict"] == "killed") if m["polarity"] == "positive" else (
                    c["verdict"] == "survived")
            t = tool_rows.get(m["label"])
            if t is not None:
                r["tool_verdict"] = t["verdict"]
                r["tool_how"] = t.get("how")
                r["tool_moved"] = t.get("moved")
                if control:
                    # the tool's control rows: control-killed / control-SURVIVED (positive),
                    # control-unchanged / control-MOVED (inert), control-error
                    want = {"positive": ("control-killed", "killed"), "inert": ("control-unchanged", "survived")}
                    tv, cv = want[m["polarity"]]
                    r["tool_agrees"] = (t["verdict"] == tv) == (c["verdict"] == cv)
                else:
                    r["tool_agrees"] = t["verdict"] == c["verdict"]
            return r

        report["controls"] = [row(c, True) for c in mutations["controls"]]
        report["faults"] = [row(m) for m in mutations["faults"]]
        controls_ok = all(c["control_ok"] for c in report["controls"])
        agree = all(r.get("tool_agrees", True) for r in report["controls"] + report["faults"])
        report["summary"] = {
            "controls_ok": controls_ok,
            "tool_and_cross_check_agree": agree if not a.no_tool else None,
            "faults": len(report["faults"]),
            "killed": [r["id"] for r in report["faults"] if r["verdict"] == "killed"],
            "silent": [r["id"] for r in report["faults"] if r["verdict"] == "silent"],
            "survived": [r["id"] for r in report["faults"] if r["verdict"] == "survived"],
        }
        report["js_probe_F7"] = js_probe_f7(vectors, work)
        report["proposed_vectors"] = proposed(mutations, work, original, SRC)
        if not a.no_tool and report["proposed_vectors"] is not None:
            report["proposed_vectors"]["tool_run_with_frozen_corpora"] = tool_with_proposals(
                a, mutations, vectors, work)
        if not controls_ok:
            report["status"] = "void_controls"
            return finish(a.out, report, 1)
        if not agree:
            report["status"] = "tool_cross_check_disagree"
            return finish(a.out, report, 1)
        report["status"] = "measured"
        return finish(a.out, report, 0)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def finish(out, report, code):
    with open(os.path.join(out, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    s = report.get("summary", {})
    print("status: %s" % report.get("status"))
    if s:
        print("killed:   %s" % " ".join(s["killed"]))
        print("silent:   %s" % " ".join(s["silent"]))
        print("survived: %s" % " ".join(s["survived"]))
        print("controls ok: %s  tool agrees: %s" % (s["controls_ok"], s["tool_and_cross_check_agree"]))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
