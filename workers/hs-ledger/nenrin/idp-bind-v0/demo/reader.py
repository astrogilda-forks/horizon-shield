#!/usr/bin/env python3
"""reader.py: the outside reader of entra_delegation_demo.mjs, in the other runtime. Reads the four files a run wrote
(binding_a.json, binding_b.json, jwks.json, bundle.json), verifies the two bindings with the Python idp-bind-v0 port
and the NENRIN grant + receipt with the Python nenrin-verify port, and prints the same verdict lines. No key, no
credential, no network.

    python3 -I reader.py out/
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "sdk-python", "src")))
import idp_bind  # noqa: E402
from nenrin_verify import verify_bundle  # noqa: E402


def sig(r):
    return r["verdict"] + " " + json.dumps(sorted({x["code"] for x in r["refusals"]})) + " " + json.dumps(sorted({x["code"] for x in r["findings"]}))


def main(d):
    rd = lambda n: json.load(open(os.path.join(d, n), encoding="utf-8"))  # noqa: E731
    a, b, jwks, bundle = rd("binding_a.json"), rd("binding_b.json"), rd("jwks.json"), rd("bundle.json")
    ra, rb = idp_bind.verify({"binding": a, "jwks": jwks}), idp_bind.verify({"binding": b, "jwks": jwks})
    rp = verify_bundle(bundle)
    print("reader (python):")
    print("  binding A: " + sig(ra))
    print("  binding B: " + sig(rb))
    print("  NENRIN grant + receipt: " + sig(rp))
    g, rc = bundle["grant"], bundle["receipt"]
    ok = (ra["verdict"] == rb["verdict"] == rp["verdict"] == "accepted" and g["caller_id"] == a["actor_id"]
          and g["provider_id"] == b["actor_id"] and rc["provider_id"] == b["actor_id"])
    print("\n" + ("established: %s / %s authorized %s %s; %s / %s executed it; executed == authorized, receipt bound to the grant"
                  % (a["idp"]["issuer"], a["idp"]["subject"], g["action"]["tool"], g["action"]["target"], b["idp"]["issuer"], b["idp"]["subject"])
                  if ok else "NOT ESTABLISHED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "out")))
