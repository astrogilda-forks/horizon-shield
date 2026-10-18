"""nenrin-tsunagi: the referee the TSUNAGI board uses, shipped so anyone can get the board's answer offline."""
import json
import os
import subprocess
import sys

import pytest

import nenrin_verify as nv
from nenrin_verify import tsunagi as T

SIZES = {"nenrin-interop-v0": 5, "nenrin-interop-v0.1": 13, "nenrin-interop-v0.2-edge": 36,
         "nenrin-interop-v0.2-action-presence": 9, "nenrin-interop-v0.3-survivors": 9}


def port_output(name):
    _, batch = T.load_corpus(name)
    out = {}
    for c in batch:
        b = dict(c["bundle"])
        b["resolve"] = nv.did_key_resolver
        p = nv.verify_provenance(b)
        out[c["name"]] = {"verdict": p["verdict"], "refusals": [r["code"] for r in p["refusals"]], "findings": [f["code"] for f in p["findings"]]}
    return out


@pytest.mark.parametrize("name", sorted(SIZES))
def test_every_packaged_corpus_loads_whole(name):
    cases, batch = T.load_corpus(name)
    assert len(cases) == len(batch) == SIZES[name]
    assert [c["name"] for c in batch] == list(cases)


@pytest.mark.parametrize("name", sorted(SIZES))
def test_the_pypi_port_reproduces_every_case(name):
    cases, _ = T.load_corpus(name)
    res = T.score(cases, port_output(name))
    assert res["reproduced"] == res["of"] == SIZES[name], [k for k, v in res["per_vector"].items() if not v["ok"]]


def test_a_missing_case_an_extra_case_an_error_and_a_wrong_verdict_each_count_against():
    cases, _ = T.load_corpus("nenrin-interop-v0")
    out = port_output("nenrin-interop-v0")
    names = list(cases)
    del out[names[0]]
    out[names[1]] = {"error": "boom"}
    out[names[2]] = dict(out[names[2]], verdict="refused" if out[names[2]]["verdict"] == "accepted" else "accepted")
    out["not-a-case"] = {"verdict": "accepted", "refusals": [], "findings": []}
    res = T.score(cases, out)
    assert res["reproduced"] == 2 and res["missing"] == [names[0]] and res["extra"] == ["not-a-case"]
    assert res["per_vector"][names[1]]["problem"].startswith("error: boom")


def test_codes_are_compared_as_sets_as_verifier_md_section_4_says():
    cases, _ = T.load_corpus("nenrin-interop-v0")
    out = port_output("nenrin-interop-v0")
    first = list(cases)[0]
    out[first]["findings"] = out[first]["findings"] * 2
    assert T.score(cases, out)["reproduced"] == 5


def test_a_value_that_is_not_a_verdict_signature_is_not_one():
    assert T.signature({"verdict": "accepted", "refusals": "x", "findings": []}) is None
    assert T.signature({"verdict": 1, "refusals": [], "findings": []}) is None
    assert T.signature(None) is None
    cases, _ = T.load_corpus("nenrin-interop-v0")
    assert T.score(cases, ["not", "an", "object"])["reproduced"] == 0


def test_run_writes_the_batch_runs_the_command_and_scores_it(tmp_path):
    script = tmp_path / "impl.py"
    script.write_text(
        "import json,sys\n"
        "import nenrin_verify as nv\n"
        "o={}\n"
        "for c in json.load(open(sys.argv[1])):\n"
        "    b=dict(c['bundle']); b['resolve']=nv.did_key_resolver; p=nv.verify_provenance(b)\n"
        "    o[c['name']]={'verdict':p['verdict'],'refusals':[r['code'] for r in p['refusals']],'findings':[f['code'] for f in p['findings']]}\n"
        "json.dump(o,open(sys.argv[2],'w'))\n")
    res = T.run("nenrin-interop-v0.2-edge", [sys.executable, str(script), "{in}", "{out}"])
    assert res["exit"] == 0 and res["reproduced"] == res["of"] == 36


def test_a_command_that_writes_nothing_scores_zero(tmp_path):
    res = T.run("nenrin-interop-v0", [sys.executable, "-c", "pass", "{in}", "{out}"])
    assert res["reproduced"] == 0 and "no readable output" in res["problem"]


def test_cli_last_line_says_not_a_pass_when_the_command_exits_non_zero(tmp_path):
    # aeoess/agent-governance-vocabulary#177 (2026-10-18): "36/36 reproduced" with exit 1 read as a pass to anyone who only read the last line
    script = tmp_path / "impl.py"
    script.write_text(
        "import json,sys\n"
        "import nenrin_verify as nv\n"
        "o={}\n"
        "for c in json.load(open(sys.argv[1])):\n"
        "    b=dict(c['bundle']); b['resolve']=nv.did_key_resolver; p=nv.verify_provenance(b)\n"
        "    o[c['name']]={'verdict':p['verdict'],'refusals':[r['code'] for r in p['refusals']],'findings':[f['code'] for f in p['findings']]}\n"
        "json.dump(o,open(sys.argv[2],'w'))\n"
        "sys.exit(1)\n")
    p = subprocess.run([sys.executable, "-m", "nenrin_verify.tsunagi", "run", "nenrin-interop-v0", "--", sys.executable, str(script), "{in}", "{out}"],
                       capture_output=True, text=True)
    assert p.returncode == 1
    assert p.stdout.strip().splitlines()[-1] == "nenrin-interop-v0: 5/5 verdict signatures reproduced (refereed by nenrin-tsunagi); not a pass: the command exited 1"


def test_cli_row_prints_the_board_entry():
    p = subprocess.run([sys.executable, "-m", "nenrin_verify.tsunagi", "row", "nenrin-interop-v0.1", "--", "python3 my.py {in} {out}"],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    row = json.loads(p.stdout)
    assert row == {"corpus": "nenrin-interop-v0.1", "cwd": "@impl", "cmd": ["python3", "my.py", "@in", "@out"], "parse": "batch_referee", "total": 13}


def test_cli_refuses_a_command_without_in_and_out():
    p = subprocess.run([sys.executable, "-m", "nenrin_verify.tsunagi", "run", "nenrin-interop-v0", "--", "true"], capture_output=True, text=True)
    assert p.returncode == 2


@pytest.mark.skipif(not os.path.isdir(os.path.join(os.path.dirname(__file__), "..", "..", "interop-v0")), reason="outside the repository")
def test_the_packaged_corpora_are_the_repository_corpora():
    repo = os.path.join(os.path.dirname(__file__), "..", "..")
    for name in SIZES:
        assert T.load_corpus(name) == T.load_corpus(name, repo)
