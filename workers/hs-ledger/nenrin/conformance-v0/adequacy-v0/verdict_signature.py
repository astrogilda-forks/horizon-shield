#!/usr/bin/env python3
"""Print the verdict signature of one NENRIN bundle, as the Python port (nenrin_verify) gives it.

This is the checker adapter that the mutation runs execute. It imports nenrin_verify from a source tree, never from
an installed package, so a mutated copy of the source is what runs:

  python3 -I -B verdict_signature.py BUNDLE.json
      one bundle. The source tree is ./src next to this file when it exists (the staged tree run_adequacy.py builds
      for corpus-adequacy), else ../../sdk-python/src (this file in place in the repository).
  python3 -I -B verdict_signature.py --src DIR --batch VECTORS.json BASE_DIR
      every vector in VECTORS.json (paths relative to BASE_DIR), one JSON object {vector_id: outcome} on stdout.

The outcome is the verdict signature of VERIFIER.md section 4 (verdict, sorted set of refusal codes, sorted set of
finding codes), written as strings, plus one diagnostic member, "reasons": the sorted set of refusal reasons (and
status for execution_unreconciled). Reasons are not part of the signature; the corpora record them for readers only,
and the manifest declares them as the diagnostic channel. If the verifier raises, the outcome is verdict "error"
with the exception type, so a mutant that crashes is an outcome change rather than a silent nonzero exit.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _default_src():
    staged = os.path.join(HERE, "src")
    if os.path.isdir(os.path.join(staged, "nenrin_verify")):
        return staged
    return os.path.normpath(os.path.join(HERE, "..", "..", "sdk-python", "src"))


def _load_verifier(src):
    src = os.path.abspath(src)
    sys.path.insert(0, src)
    import nenrin_verify  # noqa: E402
    if not os.path.abspath(nenrin_verify.__file__).startswith(src + os.sep):
        raise SystemExit("nenrin_verify was not imported from " + src)
    return nenrin_verify


def _reason(x):
    v = x.get("reason", x.get("status", ""))
    return v if isinstance(v, str) else str(v)


def outcome(nv, bundle):
    try:
        r = nv.verify_bundle(bundle)
    except Exception as e:  # a crash is an outcome, see the module docstring
        return {"verdict": "error", "refusals": "", "findings": "", "reasons": "raised:" + type(e).__name__}
    refusals = sorted({x["code"] for x in r["refusals"]})
    findings = sorted({x["code"] for x in r["findings"]})
    reasons = sorted({_reason(x) for x in r["refusals"]})
    return {"verdict": r["verdict"], "refusals": ",".join(refusals), "findings": ",".join(findings),
            "reasons": ",".join(reasons)}


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def main(argv):
    if len(argv) >= 1 and argv[0] == "--src":
        if len(argv) != 5 or argv[2] != "--batch":
            raise SystemExit("usage: --src DIR --batch VECTORS.json BASE_DIR")
        src, vectors_path, base = argv[1], argv[3], argv[4]
        nv = _load_verifier(src)
        rows = json.loads(_read(vectors_path))["vectors"]
        out = {}
        for row in rows:
            bundle = nv.js_loads(_read(os.path.join(base, row["path"])))
            out[row["vector_id"]] = outcome(nv, bundle)
        sys.stdout.write(json.dumps(out, sort_keys=True))
        return 0
    if len(argv) != 1:
        raise SystemExit("usage: verdict_signature.py BUNDLE.json")
    nv = _load_verifier(_default_src())
    bundle = nv.js_loads(_read(argv[0]))
    sys.stdout.write(json.dumps(outcome(nv, bundle), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
