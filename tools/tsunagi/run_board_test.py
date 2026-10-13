#!/usr/bin/env python3
"""Offline checks of how TSUNAGI reads each implementation's output. No network; the pin checks clone a throwaway local repository."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_board as rb

fail = 0
def t(name, ok):
    global fail
    print(("ok   " if ok else "NG   ") + name); fail += (not ok)

r = rb.parse("count_line", 0, "interop-v0: 5/5 verdict signatures reproduced\n", 5)
t("count line: 5/5 and exit 0 is a pass", r["passed"] and r["reproduced"] == 5)
r = rb.parse("count_line", 1, "interop-v0: 4/5 verdict signatures reproduced\n", 5)
t("count line: 4/5 is not a pass", not r["passed"])
r = rb.parse("count_line", 0, "13/13 verdict signatures reproduced\n", 36)
t("count line: a full count of a smaller corpus than registered is not a pass", not r["passed"])
r = rb.parse("count_line", 0, "nothing printed here\n", 5)
t("count line: no count line is not a pass", not r["passed"] and r["reproduced"] is None)
r = rb.parse("all_pass", 0, "ALL PASS (nenrin reference interop)\n", 13)
t("all pass: the phrase and exit 0 is a pass", r["passed"])
r = rb.parse("all_pass", 1, "ALL PASS\n", 13)
t("all pass: a non-zero exit is not a pass even with the phrase", not r["passed"])
out = "ok   v2-a   approved   \nok   v2-b   approval_unverified    bad_signature\n2/2 agree\n"
r = rb.parse("approval_lines", 0, out, 2)
t("approval lines: per vector result and reason", r["passed"] and r["per_vector"]["v2-b"] == {"ok": True, "result": "approval_unverified", "reason": "bad_signature"} and r["per_vector"]["v2-a"]["reason"] is None)
r = rb.parse("json_results", 0, 'noise line\n{"passed": true, "results": [{"id": "S3-001", "matches": true, "canonical_sha256": "aa"}, {"id": "S3-002", "matches": false}]}', 2)
t("json results: a vector that does not match is not a pass", not r["passed"] and r["reproduced"] == 1 and r["per_vector"]["S3-002"]["ok"] is False)
r = rb.parse("pytest", 0, "..........\n10 passed in 0.22s\n", 10)
t("pytest: 10 passed is a pass", r["passed"])
r = rb.parse("pytest", 1, "9 passed, 1 failed in 0.3s\n", 10)
t("pytest: one failure is not a pass", not r["passed"] and r["of"] == 10)
try:
    rb.parse("guess", 0, "", 1); t("an unknown parse kind is refused", False)
except ValueError:
    t("an unknown parse kind is refused", True)
spec = __import__("json").load(open(os.path.join(rb.HERE, "implementations.json"), encoding="utf-8"))
ids = [i["id"] for i in spec["implementations"]]
t("implementation ids are unique", len(ids) == len(set(ids)))
t("every refereed run names a corpus the referee knows", all(r["corpus"] in rb.REFEREE.CORPORA for i in spec["implementations"] for r in i["runs"] if r["parse"] == "batch_referee"))
t("every outside row names a public https repository and a licence", all(i["repo"] and i["repo"].startswith("https://") and i.get("license") for i in spec["implementations"] if not i["ours"]))
t("every pair names two registered implementations", all(p["a"] in ids and p["b"] in ids for p in spec["pairs"]))

# ---- refereed runs, history, badges, differential (offline: fake implementations written to a temp dir) ----------
import json, tempfile
cases, batch = rb.REFEREE.load_corpus("nenrin-interop-v0", rb.NENRIN)
good = {k: v["expect"] for k, v in cases.items()}
r = rb.refereed("nenrin-interop-v0", 0, good, 5)
t("refereed: the frozen expectations themselves score 5/5 and pass", r["passed"] and r["scored_by"] == "board")
bad = dict(good); first = list(bad)[0]; bad[first] = dict(bad[first], verdict="accepted" if bad[first]["verdict"] != "accepted" else "refused")
r = rb.refereed("nenrin-interop-v0", 0, bad, 5)
t("refereed: one changed verdict is 4/5 and not a pass", not r["passed"] and r["reproduced"] == 4 and r["per_vector"][first]["ok"] is False)
r = rb.refereed("nenrin-interop-v0", 0, None, 5)
t("refereed: no output file is not a pass", not r["passed"] and "no readable output" in r["problem"])
r = rb.refereed("nenrin-interop-v0", 1, good, 5)
t("refereed: a non-zero exit is not a pass even with every case right", not r["passed"])
extra = dict(good); extra["invented"] = good[first]
t("refereed: an extra case is not a pass", not rb.refereed("nenrin-interop-v0", 0, extra, 5)["passed"])

b1 = {"measured_at": "2026-10-08T00:00:00Z", "runs": [{"implementation": "x", "corpus": "c", "scored_by": "board", "passed": True, "commit": "a" * 40}]}
h = rb.update_history(None, b1)
b2 = {"measured_at": "2026-10-09T00:00:00Z", "runs": [{"implementation": "x", "corpus": "c", "scored_by": "board", "passed": True, "commit": "a" * 40}]}
h = rb.update_history(h, b2)
cell = h["cells"]["x | c | board"]
t("history: two passing runs make a streak of 2 from the first pass", cell["streak"] == 2 and cell["first_pass"].startswith("2026-10-08"))
b3 = {"measured_at": "2026-10-10T00:00:00Z", "runs": [{"implementation": "x", "corpus": "c", "scored_by": "board", "passed": False, "commit": "b" * 40}]}
h = rb.update_history(h, b3)
cell = h["cells"]["x | c | board"]
t("history: a failure resets the streak and a new commit is noted with its date", cell["streak"] == 0 and cell["commit"] == "b" * 12 and cell["commit_since"].startswith("2026-10-10"))

bd = rb.badges({"runs": [{"implementation": "x", "status": "ran", "passed": True, "reproduced": 5, "expected_total": 5, "scored_by": "board"},
                         {"implementation": "y", "status": "ran", "passed": False, "reproduced": 3, "expected_total": 5},
                         {"implementation": "z", "status": "not_run", "expected_total": 5}]})
t("badges: green when every run passes, red on a failure, grey when nothing ran",
  bd["x"]["color"] == "brightgreen" and "refereed" in bd["x"]["message"] and bd["y"]["color"] == "red" and bd["z"]["color"] == "lightgrey")

with tempfile.TemporaryDirectory() as tmp:
    gen = os.path.join(tmp, "gen.py")
    open(gen, "w").write("import json,sys\njson.dump([{'name':'b1','bundle':{}},{'name':'b2','bundle':{}}],open(sys.argv[1],'w'))\n")
    impl = os.path.join(tmp, "impl.py")
    open(impl, "w").write("import json,sys\nv=sys.argv[1]\no={c['name']:{'verdict':'accepted' if (c['name']=='b1' or v=='a') else 'refused','refusals':[],'findings':[]} for c in json.load(open(sys.argv[2]))}\njson.dump(o,open(sys.argv[3],'w'))\n")
    spec = {"differential": {"generator": {"cwd": tmp, "cmd": [sys.executable, gen, "@gen"]},
                             "implementations": [{"id": "A", "cwd": tmp, "cmd": [sys.executable, impl, "a", "@in", "@out"]},
                                                 {"id": "B", "cwd": tmp, "cmd": [sys.executable, impl, "b", "@in", "@out"]}]}}
    heads = {"A": {"clone_error": None}, "B": {"clone_error": None}}
    d = rb.differential(spec, heads, {"A": None, "B": None}, {})
    t("differential: two implementations that differ on one fresh bundle are listed on exactly that bundle",
      d["status"] == "ran" and d["bundles"] == 2 and d["agree"] == 1 and [x["case"] for x in d["disagreements"]] == ["b2"])

with tempfile.TemporaryDirectory() as tmp:
    gen = os.path.join(tmp, "gen.py")
    open(gen, "w").write("import json,sys\njson.dump([{'name':'a|b','bundle':{}}],open(sys.argv[1],'w'))\n")
    weird = os.path.join(tmp, "weird.py")
    open(weird, "w").write("import json,sys\njson.dump({'a|b':'accepted'},open(sys.argv[2],'w'))\n")
    ok_impl = os.path.join(tmp, "ok.py")
    open(ok_impl, "w").write("import json,sys\njson.dump({'a|b':{'verdict':'accepted','refusals':[],'findings':[]}},open(sys.argv[2],'w'))\n")
    spec = {"differential": {"generator": {"cwd": tmp, "cmd": [sys.executable, gen, "@gen"]},
                             "implementations": [{"id": "W", "cwd": tmp, "cmd": [sys.executable, weird, "@in", "@out"]},
                                                 {"id": "K", "cwd": tmp, "cmd": [sys.executable, ok_impl, "@in", "@out"]}]}}
    d = rb.differential(spec, {"W": {"clone_error": None}, "K": {"clone_error": None}}, {"W": None, "K": None}, {})
    t("differential: an output whose case value is not an object is recorded, not a crash",
      d["status"] == "ran" and d["disagreements"] and d["disagreements"][0]["by"]["W"] == "not a verdict signature")
    md = rb.to_md({"board_sha256": "x", "measured_at": "t", "summary": {"passed": 0, "runs": 0, "outside_passed": 0}, "implementations": {},
                   "runs": [], "pairs": [], "differential": d})
    t("board markdown: a bundle name with a pipe does not break the table", "a\\|b" in md)

# approval corpus refereed by the board (2026-10-09, #34): the pinned copy, no expected value in the batch, exact comparison
cases, batch = rb.load_approval_corpus("musubi-approval-v2")
t("approval corpus: nine cases from the pinned copy", len(cases) == 9 and len(batch) == 9)
t("approval corpus: the batch carries no expected value", all(set(b) == {"name", "contract", "approval"} for b in batch))
right = {k: dict(v) for k, v in cases.items()}
r = rb.score_approval(cases, right, 9)
t("approval referee: every answer equal is 9/9 with no extra", r["reproduced"] == 9 and not r.get("extra_cases"))
wrong = dict(right); k0 = sorted(cases)[0]; wrong[k0] = {"result": right[k0]["result"], "reason": "something_else"}
t("approval referee: a different reason is not reproduced", rb.score_approval(cases, wrong, 9)["reproduced"] == 8)
padded = dict(right); padded[k0] = dict(right[k0], note="x")
t("approval referee: an extra key in an answer is not reproduced", rb.score_approval(cases, padded, 9)["reproduced"] == 8)
extra = dict(right); extra["made-up"] = {"result": "approved", "reason": None}
t("approval referee: an extra case is listed", rb.score_approval(cases, extra, 9).get("extra_cases") == ["made-up"])
t("approval referee: no output is 0 and says so", rb.score_approval(cases, None, 9)["reproduced"] == 0 and "problem" in rb.score_approval(cases, None, 9))
t("approval referee: a list instead of an object is 0", rb.score_approval(cases, [1, 2], 9)["reproduced"] == 0)
impls = __import__("json").load(open(os.path.join(rb.HERE, "implementations.json"), encoding="utf-8"))["implementations"]
appr_runs = [r for i in impls for r in i["runs"] if r["parse"] == "batch_approval_referee"]
t("every approval-refereed run names a pinned approval corpus", appr_runs and all(r["corpus"] in rb.APPROVAL_CORPORA for r in appr_runs))
import shutil
saved = rb.APPROVAL_CORPORA["musubi-approval-v2"]
rb.APPROVAL_CORPORA["musubi-approval-v2"] = (saved[0], "0" * 64)
try:
    rb.load_approval_corpus("musubi-approval-v2"); t("approval corpus: a changed pin is refused", False)
except ValueError:
    t("approval corpus: a changed pin is refused", True)
rb.APPROVAL_CORPORA["musubi-approval-v2"] = saved

snap = rb.snapshot()
target = os.path.join(rb.HERE, "README.md")
keep = open(target, "rb").read()
open(target, "ab").write(b"tampered")
changed = rb.restore_if_changed(snap)
t("integrity: a guarded file changed by a run is detected and restored", changed == [os.path.relpath(target, rb.ROOT)] and open(target, "rb").read() == keep)
t("integrity: nothing changed reports nothing", rb.restore_if_changed(snap) == [])
import tempfile, subprocess
with tempfile.TemporaryDirectory(prefix="tsunagi-pin-test-") as td:
    src = os.path.join(td, "src")
    g = lambda *a: subprocess.run(["git", "-C", src] + list(a), capture_output=True, text=True, check=True).stdout.strip()
    os.makedirs(src)
    subprocess.run(["git", "init", "-q", src], check=True)
    g("config", "user.email", "t@t"); g("config", "user.name", "t"); g("config", "uploadpack.allowAnySHA1InWant", "true")
    open(os.path.join(src, "f"), "w").write("one"); g("add", "f"); g("commit", "-q", "-m", "one"); first = g("rev-parse", "HEAD")
    open(os.path.join(src, "f"), "w").write("two"); g("commit", "-q", "-am", "two"); second = g("rev-parse", "HEAD")
    url = "file://" + src
    ok, err = rb.clone(url, os.path.join(td, "a"))
    t("pin: without a pin the default branch head is cloned", ok and rb.head(os.path.join(td, "a")) == second)
    ok, err = rb.clone(url, os.path.join(td, "b"), first)
    t("pin: with a pin exactly that commit is checked out, not the head", ok and rb.head(os.path.join(td, "b")) == first)
    ok, err = rb.clone(url, os.path.join(td, "c"), first[:12])
    t("pin: a short sha is refused, not guessed", (not ok) and "40-hex" in err)
    ok, err = rb.clone(url, os.path.join(td, "d"), "0" * 40)
    t("pin: a pin that cannot be fetched is a clone error, never a fallback to the head", (not ok) and "could not" in err)
print("")
if fail:
    print("FAIL %d (tsunagi)" % fail); sys.exit(1)
print("ALL PASS (tsunagi: how each implementation's output is read)")
