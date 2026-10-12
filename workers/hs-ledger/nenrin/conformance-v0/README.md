# conformance-v0: keeping the specs, the reference and every reimplementation in agreement

interop-v0 and interop-v0.1 freeze 18 verdict signatures. They cannot show a rule that no frozen bundle reaches.
This directory is the standing check for those rules, built from what the first independent implementation and two
blind reimplementations (one from the specs as they stood, one from provenance-v0/VERIFIER.md) taught us on 2026-10-04.

- gen_edge_bundles.mjs (the adversary): builds freshly signed bundles that reach the deep rules of VERIFIER.md:
  timestamp grammar and window edges, null versus absent, evidence shapes, action_binding, R3/R4 edges, linkage forms,
  preflight. Every bundle is validly signed, so a disagreement on it is a disagreement about rules, never a broken hash.
- pinned/ (30 bundles, 2026-10-12): the rules the blind triage of 2026-10-12 found unwritten (S1 to S12), now
  written into VERIFIER.md and frozen here, one validly signed bundle per rule, with pinned/expected.json holding the
  verdict signature the npm and PyPI references both give. make_pinned.mjs built them (fresh keys, so the committed
  bytes are the frozen ones); pin_expected.py writes expected.json and refuses to when the two references disagree.
  Not part of the conformance condition at the top of VERIFIER.md: a check you can run, and a place to send us
  a disagreement.
- differential.py (the judge): runs the frozen corpora, the pinned bundles and the generated bundles through the published JS verifier,
  the PyPI port and any extra implementation (--impl path.py exposing verify(bundle)), and prints every bundle where a
  verdict signature differs from the JS reference. Exit 1 on any disagreement.

A disagreement is triaged by a person, not by the script, into one of three: the spec is silent or ambiguous (fix the
text, add a frozen vector), the reference is wrong (fix it, release), or the other implementation misread a clear rule.

    node gen_edge_bundles.mjs /tmp/edge.json
    python3 differential.py --edge /tmp/edge.json [--impl your_verify.py]

First run (2026-10-04): JS and the PyPI port agree on all 58 bundles. A blind implementation written before
VERIFIER.md section 5 existed differed on 4, each a rule section 5 now pins (fraction truncation, missing action,
missing prev_evidence_id at seq 0). If you implement VERIFIER.md, run your verifier through this and send us every
disagreement.
