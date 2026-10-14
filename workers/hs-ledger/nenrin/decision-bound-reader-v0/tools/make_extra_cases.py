#!/usr/bin/env python3
"""Build the three extra cases used in the 4cbf5c8 comparison from giskard09's vectors_decision_bound.json (at
4cbf5c85a22659ebd13bb5aa2f4fb7e924b3c207, or its blind copy). Each case is an existing case with only
`recorded_output_hash` replaced, to test the two places the text leaves open:

  X-FORGED-CITATION-OVER-LEGACY  DECISION-BOUND-FORGED-CITATION, hash = "sha256:" + content_sha256 (legacy form)
  X-DENIED-OVER-LEGACY           DECISION-BOUND-DENIED, hash = legacy form
  X-DENIED-NEITHER               DECISION-BOUND-DENIED, hash = "sha256:" + "1" * 64 (matches neither form)

    python3 -I -B make_extra_cases.py <vectors_decision_bound.json> <extra_cases.json>
"""
import copy, json, sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
cases = {c["case_id"]: c for c in d["cases"]}
out = []
for src, cid in (("DECISION-BOUND-FORGED-CITATION", "X-FORGED-CITATION-OVER-LEGACY"),
                 ("DECISION-BOUND-DENIED", "X-DENIED-OVER-LEGACY"),
                 ("DECISION-BOUND-DENIED", "X-DENIED-NEITHER")):
    c = copy.deepcopy(cases[src])
    c.pop("expected_code", None)
    c.pop("note", None)
    c["case_id"] = cid
    c["recorded_output_hash"] = ("sha256:" + c["content_sha256"]) if cid.endswith("LEGACY") else "sha256:" + "1" * 64
    out.append(c)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(json.dumps({"profile": d["profile"], "cases": out}, indent=2) + "\n")
