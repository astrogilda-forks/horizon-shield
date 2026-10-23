#!/usr/bin/env python3
"""rfc8785() in a2a_conduct_walk.py against the rfc8785 target of the a2a-tck canonicalization corpus
(vectors-a2a-jcs-v01) that agent-evidence-vectors ships. Suggested by astrogilda on
probityai/agent-evidence-vectors#55, whose run of 0.20.0 found nine non-integer numbers refused.

    pip install agent-evidence-vectors==0.20.0
    python3 rfc8785_corpus_check.py          exit 0 when every rfc8785 vector passes

Each failing line names the vector and its RFC 8785 clause.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_evidence_vectors import a2ajcs  # noqa: E402
import a2a_conduct_walk as W  # noqa: E402

bad = list(a2ajcs.check(lambda v: W.rfc8785(v).encode("utf-8"), "rfc8785"))
print("\n".join(bad) if bad else "rfc8785: every vector passes")
sys.exit(1 if bad else 0)
