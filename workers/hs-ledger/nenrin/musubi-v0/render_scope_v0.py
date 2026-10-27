#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
musubi-scope-v0: the task scope a content check reads, made from the contract alone (2026-10-27).

A content check that is given the task's scope can say whether the text it reads would make the assistant act outside
it (FURUI v4, scope_conflict). If each relying party wrote its own scope, nobody else could say which scope was used.
So the scope is made from the signed contract and nothing else: the door's own policy (targets, exposure) is not part
of it. Anyone holding the contract (both parties, a settler, a witness the contract is disclosed to) can make the same
object, the same digest and the same text again.

    scope = {"id": "musubi-scope-v0",
             "contract_sha256": ..,                    contract_v0.contract_sha256 of the contract
             "purpose": task.purpose,
             "authorized_actions": grant.authorized_actions or [],
             "prohibited_actions": grant.prohibited_actions or [],
             "conditional": grant.conditional or [],
             "limits": grant.limits or {},
             "data_access": grant.data_access or null,
             "privacy": grant.privacy or null,
             "scope_text": requirements.furui.scope_text or null}      the task in the parties' own words
    scope_sha256 = sha256(musubi-canonical-v0 bytes of scope)

render(scope) writes the object as English lines in a fixed order. The text is what the content check is given; the
digest names the object, and the text follows from the object, so the digest names the text as well. render_scope_v0.mjs
writes the same bytes.

A grant is short. A contract that carries no requirements.furui.scope_text gives a thin scope (actions and limits only),
and a scope conflict is then harder to see. This was not measured.

  python3 render_scope_v0.py --selftest
  python3 render_scope_v0.py --contract CONTRACT.json      prints scope_sha256 and the text
"""
import hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from contract_v0 import canonical, contract_sha256, parse_strict
import requirements_furui_v0 as RF

ID = "musubi-scope-v0"


def scope_of(contract):
    """The scope object of a contract. Raises ValueError when the contract has no task.purpose or no grant object."""
    task = contract.get("task") if isinstance(contract, dict) else None
    grant = contract.get("grant") if isinstance(contract, dict) else None
    if not (isinstance(task, dict) and isinstance(task.get("purpose"), str) and task["purpose"] and isinstance(grant, dict)):
        raise ValueError("a scope needs task.purpose and a grant object")
    if RF.problems(contract):
        raise ValueError("requirements.furui is not in the shape requirements_furui_v0 reads")
    rq = contract.get("requirements")
    f = rq.get("furui") if isinstance(rq, dict) else None
    st = f.get("scope_text") if isinstance(f, dict) else None
    g = lambda k, empty: grant.get(k) if grant.get(k) is not None else empty
    return {"id": ID, "contract_sha256": contract_sha256(contract), "purpose": task["purpose"],
            "authorized_actions": g("authorized_actions", []), "prohibited_actions": g("prohibited_actions", []),
            "conditional": g("conditional", []), "limits": g("limits", {}),
            "data_access": g("data_access", None), "privacy": g("privacy", None),
            "scope_text": st if isinstance(st, str) and st else None}


def scope_sha256(scope):
    return hashlib.sha256(canonical(scope).encode("utf-8")).hexdigest()


def _list(xs):
    return ", ".join(str(x) for x in xs) if xs else "none"


def render(scope):
    """The scope as English lines, in a fixed order, ending with a line feed."""
    out = ["Task: " + scope["purpose"],
           "Allowed actions: " + _list(scope["authorized_actions"]),
           "Forbidden actions: " + _list(scope["prohibited_actions"])]
    cond = []
    for c in scope["conditional"]:
        c = c if isinstance(c, dict) else {}
        extra = ["requires " + c["requires"]] if isinstance(c.get("requires"), str) else []
        extra += ["%s %s" % (k, canonical(c[k])) for k in sorted(c) if k not in ("action", "requires")]
        cond.append(str(c.get("action")) + (" (" + "; ".join(extra) + ")" if extra else ""))
    out.append("Actions allowed only after an approval: " + (", ".join(cond) if cond else "none"))
    lim = []
    for a in sorted(scope["limits"]):
        v = scope["limits"][a] if isinstance(scope["limits"][a], dict) else {}
        lim.append("%s at most %s %s" % (a, canonical(v.get("max_amount")), v.get("unit")))
    out.append("Limits: " + (", ".join(lim) if lim else "none"))
    if scope["data_access"] is not None:
        out.append("Data the assistant may use: " + (_list(scope["data_access"]) if isinstance(scope["data_access"], list) else str(scope["data_access"])))
    if scope["privacy"] is not None:
        out.append("Privacy: " + str(scope["privacy"]))
    if scope["scope_text"] is not None:
        out.append("The task in the parties' words: " + scope["scope_text"])
    return "\n".join(out) + "\n"


def _contracts():
    rd = lambda n: parse_strict(open(os.path.join(HERE, n), encoding="utf-8").read())
    a, b = rd("first_contract_AB.json"), rd("second_contract_AB.json")
    c = json.loads(json.dumps(b))
    c.setdefault("requirements", {})["furui"] = {"scope_text": "Walk the public endpoint once and report what it serves; do not change anything."}
    d = json.loads(json.dumps(b))
    d["grant"]["limits"] = {"pay": {"max_amount": 100000, "unit": "JPY"}}
    d["grant"]["conditional"] = [{"action": "spend", "requires": "human_approval", "threshold_jpy": 100000}, {"action": "export"}]
    return [("first_contract_AB.json", a), ("second_contract_AB.json", b), ("second contract with requirements.furui.scope_text", c),
            ("second contract with limits and conditional actions", d)]


def _selftest():
    n = 0
    cs = _contracts()
    for label, c in cs:
        s = scope_of(c)
        assert sorted(s) == sorted(["id", "contract_sha256", "purpose", "authorized_actions", "prohibited_actions", "conditional", "limits",
                                    "data_access", "privacy", "scope_text"])
        assert scope_sha256(s) == scope_sha256(scope_of(json.loads(json.dumps(c)))) and render(s) == render(scope_of(c))
    s1, s2, s3, s4 = [scope_of(c) for _, c in cs]
    assert len({scope_sha256(x) for x in (s1, s2, s3, s4)}) == 4
    assert s3["scope_text"] and "The task in the parties' words: " in render(s3) and s2["scope_text"] is None
    assert "Limits: pay at most 100000 JPY" in render(s4) and "spend (requires human_approval; threshold_jpy 100000), export" in render(s4)
    n += 1; print("[1] four contracts, four scopes; the object and the text are made from the contract alone, the same way each time")
    for label, c in cs:
        print("    %-52s scope_sha256 %s" % (label, scope_sha256(scope_of(c))))
    for bad in ({}, {"task": {"purpose": ""}, "grant": {}}, {"task": {"purpose": "x"}, "grant": []}, []):
        try:
            scope_of(bad); raise AssertionError(bad)
        except ValueError:
            pass
    n += 1; print("[2] a contract with no purpose or no grant object has no scope")
    try:
        r = subprocess.run(["node", os.path.join(HERE, "render_scope_v0.mjs"), "--batch"], input=json.dumps([c for _, c in cs]),
                           capture_output=True, text=True)
    except FileNotFoundError:
        r = None
    if r is None:
        print("[3] node not found: the JavaScript twin was not run")
    else:
        assert r.returncode == 0, r.stderr[-400:]
        js = json.loads(r.stdout)
        py = [{"scope_sha256": scope_sha256(scope_of(c)), "text": render(scope_of(c))} for _, c in cs]
        assert js == py, (js, py)
        n += 1; print("[3] render_scope_v0.mjs gives the same digest and the same text, byte for byte, on all %d" % len(py))
    print("\nSELF-TEST PASSED: musubi-scope-v0, %d checks (made from the contract alone; one object, one digest, one text; the twin agrees)" % n)


def main():
    a = sys.argv[1:]
    if a == ["--selftest"]:
        _selftest(); return 0
    if len(a) == 2 and a[0] == "--contract":
        s = scope_of(parse_strict(open(a[1], encoding="utf-8").read()))
        print(scope_sha256(s)); sys.stdout.write(render(s)); return 0
    print(__doc__); return 1


if __name__ == "__main__":
    sys.exit(main())
