#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
furui-rules-id-v0: one name for the content check a relying party says it ran (2026-10-27).

A content check (FURUI) is rules first, then, for some arrangements, one or two models asked a fixed question. What
"the same check" means is the rule files, the text of each question, the output schema, the model names and the way the
stages are arranged. This file writes those five things down as one object and names it by one digest:

    rules_sha256 = sha256(musubi-canonical-v0 bytes of the object)

The object, with every key required and no other key allowed:

    {"id": "furui-rules-id-v0",
     "version": "0.2.9a",                                        the check's own version name, printable ASCII
     "rule_files": [{"name": "fieldwise_v1.py", "sha256": ..}],  sorted by name, names unique, at least one
     "prompts": [{"name": "system_v1", "sha256": ..}],           sha256 of each question's UTF-8 text, sorted by name;
                                                                 [] when no stage asks a model
     "schema_sha256": <hex64> | null,                            sha256 of the output schema's canonical bytes; null
                                                                 exactly when no stage asks a model
     "stages": [{"n": 1, "kind": "rules"},
                {"n": 2, "kind": "model", "model": "claude-haiku-5-5"},
                {"n": 3, "kind": "model", "model": "claude-opus-5-5", "when": "stage_2_flagged"}],
     "arrangement": "rules-haiku-opus_on_flag"}

Arrangements are a closed list, each with the shape its stages must have:

    rules-only                  [rules]
    rules-model                 [rules, model]
    rules-haiku-opus_on_flag    [rules, model, model when stage_2_flagged]   the two stage check of FURUI 0.2.8 and v4

A relying party's door compares rules_sha256 for equality only (policy.furui.rules_sha256, the admission's
content.rules_sha256, a contract's requirements.furui.rules_sha256). The digest names what the party says it used. It
does not make a model answer the same way twice: the same model name can answer differently on the same bytes.

admission_verify_v0 and settle_v1_17 never need this file; they compare digests. It is here so that anyone holding the
object (a blind's PIN publishes it) can recompute the digest, in Python or in furui_rules_id_v0.mjs.

  python3 furui_rules_id_v0.py --selftest
  python3 furui_rules_id_v0.py --id ID.json            prints rules_sha256, or the problems
"""
import hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from contract_v0 import canonical

ID = "furui-rules-id-v0"
KEYS = ("arrangement", "id", "prompts", "rule_files", "schema_sha256", "stages", "version")
ARRANGEMENTS = {
    "rules-only": [("rules", None)],
    "rules-model": [("rules", None), ("model", None)],
    "rules-haiku-opus_on_flag": [("rules", None), ("model", None), ("model", "stage_2_flagged")],
}
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
NAME = re.compile(r"\A[\x21-\x7e][\x20-\x7e]{0,127}\Z")
VERSION = re.compile(r"\A[\x21-\x7e]{1,64}\Z")


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _named(xs, where, empty_ok):
    if not isinstance(xs, list) or (not xs and not empty_ok):
        return ["%s_malformed" % where]
    out = []
    for x in xs:
        if not (isinstance(x, dict) and sorted(x) == ["name", "sha256"] and isinstance(x["name"], str) and NAME.match(x["name"])
                and isinstance(x["sha256"], str) and HEX64.match(x["sha256"])):
            return ["%s_malformed" % where]
    names = [x["name"] for x in xs]
    if names != sorted(set(names)):
        out.append("%s_not_sorted_unique" % where)
    return out


def problems(obj):
    """[] when obj is a well formed furui-rules-id-v0 object; otherwise the codes, in a fixed order."""
    if not isinstance(obj, dict):
        return ["not_an_object"]
    if sorted(obj) != list(KEYS):
        return ["keys_not_exact"]
    p = []
    if obj["id"] != ID:
        p.append("id_unknown")
    if not (isinstance(obj["version"], str) and VERSION.match(obj["version"])):
        p.append("version_malformed")
    p += _named(obj["rule_files"], "rule_files", False)
    p += _named(obj["prompts"], "prompts", True)
    st = obj["stages"]
    shape = None
    if not isinstance(st, list) or not st:
        p.append("stages_malformed")
    else:
        shape = []
        for i, s in enumerate(st):
            if not (isinstance(s, dict) and _is_int(s.get("n")) and s["n"] == i + 1 and s.get("kind") in ("rules", "model")):
                p.append("stages_malformed"); shape = None; break
            allowed = {"n", "kind"} | ({"model", "when"} if s["kind"] == "model" else set())
            if set(s) - allowed or (s["kind"] == "model" and not (isinstance(s.get("model"), str) and NAME.match(s["model"]))) \
                    or ("when" in s and not isinstance(s["when"], str)):
                p.append("stages_malformed"); shape = None; break
            shape.append((s["kind"], s.get("when")))
    if obj["arrangement"] not in ARRANGEMENTS:
        p.append("arrangement_unknown")
    elif shape is not None and shape != ARRANGEMENTS[obj["arrangement"]]:
        p.append("stages_not_the_arrangement")
    models = shape is not None and any(k == "model" for k, _ in shape)
    sch = obj["schema_sha256"]
    if not (sch is None or (isinstance(sch, str) and HEX64.match(sch))):
        p.append("schema_sha256_malformed")
    elif shape is not None and (sch is None) == models:
        p.append("schema_sha256_not_the_stages")
    if shape is not None and isinstance(obj["prompts"], list) and (len(obj["prompts"]) == 0) == models:
        p.append("prompts_not_the_stages")
    return p


def rules_sha256(obj):
    """The digest of a well formed object. Raises ValueError with the problems otherwise."""
    p = problems(obj)
    if p:
        raise ValueError(", ".join(p))
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def build(version, rule_files, prompts, schema, models, arrangement):
    """rule_files {name: bytes}, prompts {name: text}, schema the output JSON schema (or None), models the model names in
    stage order. Returns the object; rules_sha256(build(...)) is the digest."""
    stages = [{"n": 1, "kind": "rules"}]
    for (kind, when), m in zip(ARRANGEMENTS[arrangement][1:], models):
        s = {"n": len(stages) + 1, "kind": kind, "model": m}
        if when:
            s["when"] = when
        stages.append(s)
    return {"id": ID, "version": version,
            "rule_files": [{"name": n, "sha256": hashlib.sha256(b).hexdigest()} for n, b in sorted(rule_files.items())],
            "prompts": [{"name": n, "sha256": hashlib.sha256(t.encode("utf-8")).hexdigest()} for n, t in sorted(prompts.items())],
            "schema_sha256": hashlib.sha256(canonical(schema).encode("utf-8")).hexdigest() if schema is not None else None,
            "stages": stages, "arrangement": arrangement}


def example():
    """A fixed example in the shape of the two stage check with the scope question (v4). The bytes are stand-ins, not
    the real rule files or questions, which are not public."""
    return build("example-v4",
                 {"sieve_v0.py": b"example sieve", "ja_fix_v1.py": b"example ja_fix", "fieldwise_v1.py": b"example fieldwise"},
                 {"system_v1": "Example question.", "scope_add_v4": "Example scope sentence."},
                 {"type": "object", "properties": {"verdict": {"type": "string"}}, "required": ["verdict"]},
                 ["claude-haiku-5-5", "claude-opus-5-5"], "rules-haiku-opus_on_flag")


def mutants():
    """Objects that each break one rule, with the code they must give."""
    e = example()
    def m(**kw):
        x = json.loads(json.dumps(e)); x.update(kw); return x
    st = e["stages"]
    return [
        ("extra key", dict(e, note="x"), ["keys_not_exact"]),
        ("id", m(id="furui-rules-id-v1"), ["id_unknown"]),
        ("version empty", m(version=""), ["version_malformed"]),
        ("version with a space", m(version="0 2"), ["version_malformed"]),
        ("rule files unsorted", m(rule_files=list(reversed(e["rule_files"]))), ["rule_files_not_sorted_unique"]),
        ("rule files empty", m(rule_files=[]), ["rule_files_malformed"]),
        ("rule file sha upper", m(rule_files=[dict(e["rule_files"][0], sha256=e["rule_files"][0]["sha256"].upper())] + e["rule_files"][1:]), ["rule_files_malformed"]),
        ("prompt duplicated", m(prompts=[e["prompts"][0], e["prompts"][0]]), ["prompts_not_sorted_unique"]),
        ("prompts empty with models", m(prompts=[]), ["prompts_not_the_stages"]),
        ("schema null with models", m(schema_sha256=None), ["schema_sha256_not_the_stages"]),
        ("stage numbered from 0", m(stages=[dict(s, n=s["n"] - 1) for s in st]), ["stages_malformed"]),
        ("when on stage 2", m(stages=[st[0], dict(st[1], when="stage_2_flagged"), st[2]]), ["stages_not_the_arrangement"]),
        ("arrangement unknown", m(arrangement="rules-opus"), ["arrangement_unknown"]),
        ("rules-only with models", m(arrangement="rules-only"), ["stages_not_the_arrangement"]),
        ("rules-only well formed", m(arrangement="rules-only", stages=[st[0]], prompts=[], schema_sha256=None), []),
        ("rules-only with a schema", m(arrangement="rules-only", stages=[st[0]], prompts=[]), ["schema_sha256_not_the_stages"]),
        ("not an object", [e], ["not_an_object"]),
    ]


def _selftest():
    n = 0
    e = example()
    assert problems(e) == [], problems(e)
    h = rules_sha256(e)
    assert h == rules_sha256(json.loads(json.dumps(e, sort_keys=False))) and HEX64.match(h)
    reordered = dict(reversed(list(e.items())))
    assert rules_sha256(reordered) == h
    n += 1; print("[1] the example is well formed; rules_sha256 %s does not depend on the order keys were written in" % h)
    ms = mutants()
    for label, x, want in ms:
        assert problems(x) == want, (label, problems(x), want)
    for label, x, want in ms:
        if want:
            try:
                rules_sha256(x); raise AssertionError(label)
            except ValueError:
                pass
    n += 1; print("[2] %d objects that break one rule each give their code, and have no digest" % sum(1 for _, _, w in ms if w))
    other = json.loads(json.dumps(e)); other["stages"][2]["model"] = "claude-sonnet-5-5"
    assert problems(other) == [] and rules_sha256(other) != h
    n += 1; print("[3] the same files and questions under another model name are another check (another digest)")
    try:
        r = subprocess.run(["node", os.path.join(HERE, "furui_rules_id_v0.mjs"), "--batch"], input=json.dumps([e] + [x for _, x, _ in ms]),
                           capture_output=True, text=True)
    except FileNotFoundError:
        r = None
    if r is None:
        print("[4] node not found: the JavaScript twin was not run")
    else:
        assert r.returncode == 0, r.stderr[-400:]
        js = json.loads(r.stdout)
        py = [{"problems": problems(x), "rules_sha256": rules_sha256(x) if not problems(x) else None} for x in [e] + [x for _, x, _ in ms]]
        assert js == py, (js, py)
        n += 1; print("[4] furui_rules_id_v0.mjs gives the same codes and the same digest on all %d objects" % len(py))
    print("\nSELF-TEST PASSED: furui-rules-id-v0, %d checks (one object, one digest; closed keys, sorted names, closed arrangements; the twin agrees)" % n)


def main():
    a = sys.argv[1:]
    if a == ["--selftest"]:
        _selftest(); return 0
    if len(a) == 2 and a[0] == "--id":
        obj = json.loads(open(a[1], encoding="utf-8").read())
        p = problems(obj)
        print(json.dumps({"problems": p}) if p else rules_sha256(obj))
        return 1 if p else 0
    print(__doc__); return 1


if __name__ == "__main__":
    sys.exit(main())
