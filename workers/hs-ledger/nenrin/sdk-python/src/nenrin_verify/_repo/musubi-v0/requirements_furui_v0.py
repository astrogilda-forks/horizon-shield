#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
requirements.furui: the content check both parties name in the signed terms, and the shape it must have (2026-10-27).

A contract may carry requirements.furui = {"rules_sha256": .., "scope_text": ..}. rules_sha256 names the content check
the parties expect a relying party's door to run (a furui-rules-id-v0 digest, furui_rules_id_v0.py); scope_text is the
task in the parties' own words (render_scope_v0 puts it into the scope a content check reads). Both are optional.

    problems(contract)   [] when requirements.furui is absent, null or well formed; ["bad_requirements_furui"] otherwise

The shape: an object whose keys are only rules_sha256 and scope_text. rules_sha256, when present and not null, is 64
lowercase hex; scope_text, when present and not null, is a non-empty string.

Who reads this. Whoever builds a contract, before both parties sign it, and settle v1.17 (settle_v1_17.py), which
refuses to settle under a contract whose requirements.furui has another shape (contract_not_verified), and
render_scope_v0, which makes no scope from it. Nothing in settle core v0 reads it: the contract door of core v0
(contract_v0.verify_contract, contract_door_v0.mjs, SETTLE_CORE_v0.md 4.1) is unchanged, and a core v0
implementation that does not know requirements.furui settles every contract exactly as before.

  python3 requirements_furui_v0.py --selftest
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = frozenset(("rules_sha256", "scope_text"))
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
CODE = "bad_requirements_furui"


def problems(contract):
    rq = contract.get("requirements") if isinstance(contract, dict) else None
    f = rq.get("furui") if isinstance(rq, dict) else None
    if f is None:
        return []
    if not isinstance(f, dict) or set(f) - KEYS:
        return [CODE]
    r, t = f.get("rules_sha256"), f.get("scope_text")
    if r is not None and not (isinstance(r, str) and HEX64.match(r)):
        return [CODE]
    if t is not None and not (isinstance(t, str) and t):
        return [CODE]
    return []


GOOD = ({}, {"rules_sha256": "ab" * 32}, {"scope_text": "Walk the public endpoint and report what it serves."},
        {"rules_sha256": "ab" * 32, "scope_text": "x"}, {"rules_sha256": None, "scope_text": None}, None)
BAD = ([], "ab" * 32, {"rules_sha256": "AB" * 32}, {"rules_sha256": "ab" * 31}, {"rules_sha256": "ab" * 32 + "\n"},
       {"scope_text": ""}, {"scope_text": 7}, {"rules": "ab" * 32}, {"rules_sha256": "ab" * 32, "on_scope_conflict": "refuse"})


def _cases():
    out = [{"task": {"purpose": "x"}}, {"requirements": None}, {"requirements": {"evidence": "nenrin_required"}}, "not a contract"]
    out += [{"requirements": {"evidence": "nenrin_required", "furui": f}} for f in GOOD + BAD]
    return out


def _selftest():
    n = 0
    for f in GOOD:
        assert problems({"requirements": {"furui": f}}) == [], f
    for f in BAD:
        assert problems({"requirements": {"furui": f}}) == [CODE], f
    assert problems({}) == [] and problems({"requirements": None}) == [] and problems("x") == []
    n += 1; print("[1] %d accepted shapes, %d refused shapes (bad_requirements_furui); a contract without requirements.furui has none" % (len(GOOD), len(BAD)))
    try:
        r = subprocess.run(["node", os.path.join(HERE, "requirements_furui_v0.mjs"), "--batch"], input=json.dumps(_cases()),
                           capture_output=True, text=True)
    except FileNotFoundError:
        r = None
    if r is None:
        print("[2] node not found: the JavaScript twin was not run")
    else:
        assert r.returncode == 0, r.stderr[-400:]
        js, py = json.loads(r.stdout), [problems(c) for c in _cases()]
        assert js == py, (js, py)
        n += 1; print("[2] requirements_furui_v0.mjs gives the same codes on all %d" % len(py))
    print("\nSELF-TEST PASSED: requirements.furui, %d checks (closed keys, typed values, absent is fine; the twin agrees)" % n)


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        _selftest(); sys.exit(0)
    print(__doc__); sys.exit(1)
