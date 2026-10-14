#!/usr/bin/env python3
"""Cases for the atlas cell "Canonical JSON signature x occurrence" (probityai/agent-evidence-atlas#76): does a
NENRIN verifier refuse a well-signed authorization that carries no signed occurrence from a separate party?

Each case is a provenance bundle (task-execution-bind-v0: a grant signed by the caller, a receipt signed by the
provider). The keys and the base pair come from ../conformance-v0/adequacy-v0/proposed_vectors/
make_proposed_vectors.py, imported unchanged: sha256 of a public label is the Ed25519 seed, so the bytes are the
same on every machine and no key material is stored. They are test keys and protect nothing.

  python3 -B make_occurrence_cases.py [out.json]      (default: in.json next to this file)
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PV = os.path.join(HERE, "..", "conformance-v0", "adequacy-v0", "proposed_vectors", "make_proposed_vectors.py")
spec = importlib.util.spec_from_file_location("make_proposed_vectors", PV)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
P, CALLER = M.P, M.CALLER
outp = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "in.json")

cases = []


def add(name, b):
    cases.append({"name": name, "bundle": b})


# The pair the others change in one place: caller-signed grant, receipt signed by the provider the grant names.
g = M.grant()
add("o00_signed_grant_and_provider_receipt", M.bundle(g, M.receipt(g)))

# The cell's passing case: a validly signed authorization and nothing that says the run happened.
g = M.grant()
add("o01_signed_grant_no_receipt_key", {"task_id": M.TASK, "grant": g})

g = M.grant()
add("o02_signed_grant_receipt_null", {"task_id": M.TASK, "grant": g, "receipt": None})

# The caller writes the occurrence itself, naming the provider, signed with the caller's own key.
g = M.grant()
r = M.receipt(g)
r["provider_sig"] = CALLER.sign(P.receipt_preimage(r))
add("o03_receipt_signed_by_caller_key", M.bundle(g, r))

# The caller names itself as provider, then signs both the authorization and the occurrence.
g = M.grant(provider_id=CALLER.id)
add("o04_self_named_provider_self_receipt", M.bundle(g, M.receipt(g, signer=CALLER)))

# The provider signs that the run failed: a signed occurrence, whatever its outcome.
g = M.grant()
r = M.receipt(g, outcome={"status": "failed", "result_sha256": "sha_res_1",
                          "evidence": {"kind": "ledger_record", "ref": M.REF, "system": "ledger.horizonshield.dev"}})
add("o05_signed_receipt_status_failed", M.bundle(g, r))

# A valid provider receipt whose outcome names no evidence pointer: nothing outside the provider's claim to check.
g = M.grant()
add("o09_receipt_without_evidence_pointer",
    M.bundle(g, M.receipt(g, outcome={"status": "completed", "result_sha256": "sha_res_1"})))

with open(outp, "w", encoding="utf-8", newline="\n") as f:
    json.dump(cases, f, indent=2)
    f.write("\n")
print("wrote %d cases to %s" % (len(cases), os.path.basename(outp)))
