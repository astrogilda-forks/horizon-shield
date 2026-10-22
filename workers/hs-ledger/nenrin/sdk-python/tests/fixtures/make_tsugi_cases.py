"""The frozen TSUGI cases the Python port is held to, and what `node tsugi_verify.mjs` prints for each.

Inputs: the repository's three real chains (recovery-v0/incident_20260920_resign_chain.json, 12 records with the real
operator signature; recovery_fixture_20260920.json, the 7-record incident of the same week; witness_fixture_20260920.json,
the same incident re-verified by a random draw of witnesses with a commit-then-reveal anchor), each under the command
lines that matter, and edits of them that reach every refusal code tsugi_verify.mjs has. Edited chains are re-sealed
(tests/parity/tsugi_tools.py) so an edit is seen by the rule it targets and not only as a hash mismatch.

The JavaScript output is the reference: for each case the JavaScript CLI runs on the case's files and its stdout
and exit code are frozen. Node 22 writes one refusal text differently from Node 24 (a public key that is not 32 bytes,
see tsugi.KEY_LENGTH_MESSAGE); the frozen text is Node 24's.

    python make_tsugi_cases.py            write ../../src/nenrin_verify/tsugi_selftest.json.gz (the cases, their files and
                                          the JavaScript output, gzip-compressed: the chains repeat, and compress 20 to 1)
    python make_tsugi_cases.py --check    exit 1 if a re-run would write different content
"""
import copy
import gzip
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests", "parity"))

from nenrin_verify import tsugi  # noqa: E402
from tsugi_tools import OPERATOR, OPERATOR_PUB, OTHER_PUB, KEYS, dumps, key_from_seed_text, reseal, sign  # noqa: E402

REC = os.path.normpath(os.path.join(ROOT, "..", "recovery-v0"))
JS = os.environ.get("TSUGI_JS") or os.path.normpath(os.path.join(ROOT, "..", "sdk", "tsugi_verify.mjs"))
SELFTEST = os.path.join(ROOT, "src", "nenrin_verify", "tsugi_selftest.json.gz")
NODE22_KEY_TEXT = "Ed25519 raw keys must be exactly 32-bytes"


def load(name):
    with open(os.path.join(REC, name), encoding="utf-8") as f:
        return json.load(f)


INCIDENT = load("incident_20260920_resign_chain.json")
WEEK = load("recovery_fixture_20260920.json")
WF = load("witness_fixture_20260920.json")
POOL, WCHAIN, BEACON = WF["pool"], WF["records"], WF["beacon"]["hash"]
FULL = ["--pool", "pool.json", "--q", "2", "--k", "3", "--beacon", BEACON, "--require-commitment", "--anchor-height", "0"]

CASES = []


def case(name, chain, args=(), pool=None, raw=None):
    files = {"chain.json": raw if raw is not None else dumps(chain)}
    if pool is not None:
        files["pool.json"] = pool if isinstance(pool, str) else dumps(pool)
    CASES.append({"name": name, "args": ["chain.json"] + list(args), "files": files})


def edit(root, path, value, seal=True, pool=POOL):
    """root with the value at path replaced (value _DEL deletes it), then re-sealed unless seal is False; with
    seal="outer" the chain is re-sealed and an edited embedded observation is left broken."""
    r = copy.deepcopy(root)
    cur = r
    for k in path[:-1]:
        cur = cur[k]
    if value is _DEL:
        del cur[path[-1]]
    elif callable(value):
        cur[path[-1]] = value(cur[path[-1]])
    else:
        cur[path[-1]] = copy.deepcopy(value)
    if not seal:
        return r
    return reseal(r, path, pool, inner=(seal != "outer"))


_DEL = object()


def strict_week():
    """The week's 7-record chain with its authorization signed by this test's operator key."""
    r = copy.deepcopy(WEEK)
    r[4] = sign(r[4], OPERATOR)
    return reseal(r, None)


def build():
    del CASES[:]
    # ---- the real chains, as published ----
    case("incident: lenient", INCIDENT)
    case("incident: strict with the embedded operator key", INCIDENT, ["--trust-embedded-key"])
    case("incident: strict with a key that is not the operator's", INCIDENT, ["--operator-key", OTHER_PUB])
    case("incident: strict with a key list, the operator's second", INCIDENT, ["--operator-key", OTHER_PUB + " , " + INCIDENT["operator_public_key_ed25519_b64"] + ",,"])
    case("incident: records array only", INCIDENT["records"], ["--trust-embedded-key"])
    case("week: lenient", WEEK)
    case("week: strict, authorization unsigned", WEEK, ["--operator-key", OPERATOR_PUB])
    case("witness: no policy", WCHAIN)
    case("witness: full policy", WCHAIN, FULL, POOL)
    case("witness: quorum 3", WCHAIN, ["--pool", "pool.json", "--q", "3"], POOL)
    case("witness: policy k 4, beacon in capitals, anchor at another height and hash", WCHAIN,
         ["--pool", "pool.json", "--k", "4", "--beacon", BEACON.upper(), "--anchor-height", "7", "--anchor-hash", "ab" * 32], POOL)
    case("witness: beacon not the one fetched", WCHAIN, ["--beacon", "0" * 64])
    # The live pool as it was from 2026-09-23 to 2026-10-22 (one entry), frozen here so that the pool growing does not
    # move this case (recovery-v0/witness_pool.json is the live pool; it has two entries from 2026-10-22, horizon-shield #56).
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "witness_pool_one_entry_20260923.json"), encoding="utf-8") as f:
        one_entry_pool = json.load(f)
    case("witness: the live one-entry pool", WCHAIN, ["--pool", "pool.json", "--q", "2"], one_entry_pool)
    case("witness: flags without values", WCHAIN, ["--q", "--k", "--beacon", "--anchor-height", "--require-commitment"])
    case("witness: q and k not numbers", WCHAIN, ["--q", "two", "--k", "1e1", "--pool", "pool.json"], POOL)
    case("witness: q and k hexadecimal beyond a double", WCHAIN, ["--q", "0x" + "f" * 260, "--k", "0X" + "F" * 14, "--pool", "pool.json"], POOL)

    # ---- strict mode ----
    sw = strict_week()
    case("strict: signed by the operator", sw, ["--operator-key", OPERATOR_PUB])
    case("strict: signed, key not trusted", sw, ["--operator-key", OTHER_PUB])
    case("strict: execution after expiry", edit(sw, (5, "recorded_at"), "2026-09-20T13:00:00Z"), ["--operator-key", OPERATOR_PUB])
    case("strict: decision refused", edit(sw, (4, "decision"), "refused"), ["--operator-key", OPERATOR_PUB])
    case("strict: auto primitive needs no signature", edit(edit(WEEK, (3, "primitive"), "quarantine_endpoint"), (5, "primitive"), "quarantine_endpoint"), ["--operator-key", OPERATOR_PUB])
    case("strict: segment ends at the proposal", WEEK[:4], ["--operator-key", OPERATOR_PUB])
    case("strict: signature does not verify", edit(sw, (4, "by"), "someone else", seal=False), ["--operator-key", OPERATOR_PUB])

    # ---- one record ----
    case("record: hash does not recompute", edit(WEEK, (1, "surface"), "elsewhere", seal=False))
    case("record: numbers in a record", edit(WEEK, (0, "observed"), {"count": 43, "ratio": 0.5}))
    case("record: every common field wrong", edit(WEEK, (0,), {"schema": "x", "recorded_at": "2026-09-20 07:00", "witness": {"name": ""}, "establishes": [], "does_not_establish": [""], "prev": "AB", "record_sha256": "z"}, seal=False))
    case("record: drift fields wrong", edit(WEEK, (0,), dict(WEEK[0], endpoint="", surface=[], drift="true", observed=[], expected=None, kind=None, source="s", prev="0" * 64), seal=False))
    case("record: drift true without kind", edit(WEEK, (0,), dict(WEEK[0], drift=True, kind="")))
    case("record: authorization every field wrong", edit(WEEK, (4,), dict(WEEK[4], proposal_sha256="x", decision="yes", by="", expires_at="tomorrow"), seal=False))
    case("record: execution link wrong", edit(WEEK, (5, "authorization_sha256"), _DEL, seal=False))
    case("record: verify fields wrong", edit(WEEK, (6,), dict(WEEK[6], execution_sha256=None, observed="o", recovered="true"), seal=False))
    case("record: observation fields wrong", edit(WCHAIN, (6, "external", 1, "record"), dict(WCHAIN[6]["external"][1]["record"], endpoint="", observed={"s": "v"}, request_sha256="r", prev="0" * 64), seal="outer"), FULL, POOL)
    case("record: observation observed empty", edit(WCHAIN, (6, "external", 1, "record", "observed"), {}), FULL, POOL)
    case("record: not an object", [None, "x", 3])
    case("record: proposal fields wrong", edit(WEEK, (3,), {"schema": "nenrin-repair-proposal-v1", "drift_sha256": ["x"], "primitive": "reboot", "rejected": [{"primitive": "a"}]}))
    case("record: authorization fields wrong", edit(WEEK, (4, "prev"), "0" * 64))
    case("record: execution fields wrong", edit(WEEK, (5,), {"schema": "nenrin-repair-execution-v1", "recorded_at": "2026-09-20T08:00:00Z", "outcome": "maybe", "steps": [], "before": [], "prev": "1" * 64, "authorization_sha256": "2" * 64}))
    case("record: draw fields wrong", edit(WCHAIN, (6, "draw"), {"beacon": {"kind": "", "height": "1.0", "hash": "x"}, "pool_size": "six", "drawn": [""], "commitment": {"ledger_url": "http://x", "anchor": []}}))
    case("record: verify external entries wrong", edit(WCHAIN, (6, "external"), ["x", {"record": "r"}, {"record": {}, "signed_domain": ""}, {"answered": "yes"}]))
    case("record: schema names an Object.prototype method", edit(WEEK, (0, "schema"), "toString"))
    case("record: schema is __proto__ (the JavaScript throws)", edit(WEEK, (0, "schema"), "__proto__"))
    case("record: schema is an array naming the drift schema", edit(WEEK, (0, "schema"), ["nenrin-drift-record-v1"]))
    case("record: schema is an object with its own toString (the JavaScript throws)", edit(WEEK, (0, "schema"), {"toString": "x"}))
    case("record: primitive toString passes the catalog", edit(edit(WEEK, (3, "primitive"), "toString"), (5, "primitive"), "hasOwnProperty"), ["--operator-key", OPERATOR_PUB])
    case("record: non-ASCII, escapes and a lone surrogate, re-sealed", edit(WEEK, (0, "witness", "vantage"), "日本語 é \U0001f600   \x7f \x01 \"\\ \ud800 end"))
    case("record: signature fields that are not strings", edit(sw, (4, "public_key_ed25519_b64"), {"type": "Buffer", "data": ["1"] * 32}, seal=False), ["--operator-key", OPERATOR_PUB])
    case("record: public key of 31 bytes", edit(sw, (4, "public_key_ed25519_b64"), "AAAA" * 10 + "AAA=", seal=False), ["--operator-key", OPERATOR_PUB])
    case("record: signature is true", edit(sw, (4, "signature_ed25519_b64"), True, seal=False), ["--operator-key", OPERATOR_PUB])
    case("record: own __proto__ key, re-sealed", edit(WEEK, (0, "expected"), {"__proto__": {"a": "b"}, "x": "y"}))

    # ---- the chain ----
    case("chain: empty", [])
    case("chain: object without records", {"what": "no records"})
    case("chain: null (the JavaScript throws)", None, raw="null")
    case("chain: not JSON (the JavaScript throws)", None, raw="{\"records\": [")
    case("chain: no drift", WEEK[3:])
    case("chain: bad order", [WEEK[0], WEEK[1], WEEK[2], WEEK[4], WEEK[3], WEEK[5], WEEK[6]])
    case("chain: too many records", WEEK + [WEEK[6]])
    case("chain: an observation in the chain", WEEK[:3] + [WCHAIN[6]["external"][1]["record"]])
    case("chain: prev broken", edit(WEEK, (5, "prev"), "a" * 64))
    case("chain: refs broken", edit(edit(WEEK, (4, "proposal_sha256"), "b" * 64), (4, "prev"), "b" * 64))
    case("chain: unknown drift", edit(WEEK, (3, "drift_sha256"), lambda x: x + ["c" * 64]))
    case("chain: refused then executed", edit(WEEK, (4, "decision"), "refused"))
    case("chain: primitive mismatch", edit(WEEK, (5, "primitive"), "rotate_credential"))
    case("chain: expected_after moved", edit(WEEK, (6, "expected_after", "extra"), {"x": "y"}))
    case("chain: recovered but unobserved", edit(edit(WEEK, (6, "observed"), {}), (6, "recovered"), True))
    case("chain: recovered with Object.prototype names in expected_after", edit(edit(edit(WEEK, (3, "expected_after"), {"toString": {"a": "b"}, "__proto__": {}}), (6, "expected_after"), {"toString": {"a": "b"}, "__proto__": {}}), (6, "observed"), {}))

    # ---- the witness draw ----
    case("draw: subject is not the execution", edit(WCHAIN, (6, "draw", "subject_sha256"), "d" * 64), FULL, POOL)
    case("draw: own host drawn", edit(WCHAIN, (6, "draw", "drawn"), ["gate.horizonshield.dev", "witness-b.example"]), FULL, POOL)
    case("draw: k shortened", edit(WCHAIN, (6, "draw", "k"), "1"), FULL, POOL)
    case("draw: commitment absent", edit(WCHAIN, (6, "draw", "commitment"), _DEL), FULL, POOL)
    case("draw: commitment for another subject", edit(WCHAIN, (6, "draw", "commitment", "subject_sha256"), "e" * 64), FULL, POOL)
    case("draw: claim does not commit the subject", edit(WCHAIN, (6, "draw", "commitment", "claim_sha256"), "f" * 64), FULL, POOL)
    case("draw: beacon not the next block", edit(WCHAIN, (6, "draw", "commitment", "anchor", "height"), "99999999999999999999"), FULL, POOL)
    case("draw: pool given is another pool", WCHAIN, FULL, dict(POOL, entries=POOL["entries"][:4]))
    case("draw: pool size differs", edit(WCHAIN, (6, "draw", "pool_size"), "7"), FULL, POOL)
    case("draw: pool malformed, duplicate domain", WCHAIN, FULL, dict(POOL, entries=POOL["entries"] + [dict(POOL["entries"][0], public_key_ed25519_b64=OTHER_PUB)]))
    case("draw: pool malformed, key is not canonical base64 of a usable key (0.3.1)", WCHAIN, FULL, dict(POOL, entries=POOL["entries"] + [dict(POOL["entries"][0], signed_domain="witness-z.example", key_url="https://witness-z.example/k.json", public_key_ed25519_b64="AAAA")]))
    case("draw: pool malformed, key is a small-order point (0.3.1)", WCHAIN, FULL, dict(POOL, entries=POOL["entries"] + [dict(POOL["entries"][0], signed_domain="witness-z.example", key_url="https://witness-z.example/k.json", public_key_ed25519_b64="AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]))
    case("strict: operator key given on the command line is not a usable key (0.3.1, usage error)", sw, ["--operator-key", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="])
    case("strict: operator key given on the command line is not canonical base64 (0.3.1, usage error)", sw, ["--operator-key", OPERATOR_PUB.rstrip("=")])
    case("draw: pool malformed, key_url host is not the domain", WCHAIN, FULL, dict(POOL, entries=[dict(POOL["entries"][0], key_url="https://elsewhere.example/k")] + POOL["entries"][1:]))
    case("draw: pool malformed, key_url not a URL", WCHAIN, FULL, dict(POOL, entries=[dict(POOL["entries"][0], key_url="not a url")] + POOL["entries"][1:]))
    case("draw: pool is not a pool", WCHAIN, FULL, "\"a string\"")
    case("draw: pool key_url in capitals with the default port", WCHAIN, FULL,
         dict(POOL, entries=[dict(e, key_url=e["key_url"].replace("https://", "HTTPS://").replace(".example/", ".EXAMPLE:443/")) for e in POOL["entries"]]))
    case("draw: k digits beyond a double", edit(WCHAIN, (6, "draw", "k"), "9" * 400), FULL, POOL)

    # ---- the embedded witnesses ----
    obs = (6, "external", 1, "record")
    case("witness: observation hash broken", edit(WCHAIN, obs + ("endpoint",), "https://x.example", seal="outer"), FULL, POOL)
    case("witness: observation signature broken", edit(WCHAIN, obs + ("public_key_ed25519_b64",), "AAAA" * 10 + "AAA=", seal="outer"), FULL, POOL)
    case("witness: observation is another schema", edit(WCHAIN, (6, "external", 1, "record"), WEEK[0]), FULL, POOL)
    case("witness: observation signature deleted", edit(WCHAIN, obs + ("signature_ed25519_b64",), _DEL), FULL, POOL)
    case("witness: observation unsigned", edit(edit(WCHAIN, obs + ("signature_ed25519_b64",), _DEL), obs + ("public_key_ed25519_b64",), _DEL), FULL, POOL)
    case("witness: domain mismatch", edit(WCHAIN, (6, "external", 1, "signed_domain"), "witness-c.example"), FULL, POOL)
    case("witness: not drawn", edit(edit(edit(WCHAIN, obs + ("source", "signed_domain"), "witness-c.example"), obs + ("source", "key_url"), "https://witness-c.example/.well-known/hs-witness-key.json"), (6, "external", 1, "signed_domain"), "witness-c.example"), FULL, POOL)
    case("witness: endpoint mismatch", edit(WCHAIN, obs + ("endpoint",), "https://other.example/path"), FULL, POOL)
    case("witness: endpoint same host other spelling", edit(WCHAIN, obs + ("endpoint",), "https:\\\\GATE.horizonshield.dev:443\\x"), FULL, POOL)
    case("witness: request mismatch", edit(WCHAIN, obs + ("request_sha256",), "9" * 64), FULL, POOL)
    case("witness: before the execution", edit(WCHAIN, obs + ("recorded_at",), "2026-09-20T07:00:00Z"), FULL, POOL)
    case("witness: key not the pool's", edit(WCHAIN, obs, lambda r: sign(r, KEYS[OTHER_PUB])), FULL, POOL)
    case("witness: disagrees", edit(WCHAIN, obs + ("observed", "health.gate_commit", "gate_commit"), "000000000000"), FULL, POOL)
    case("witness: counted once per domain", edit(WCHAIN, (6, "external"), lambda x: x + [copy.deepcopy(x[1])]), FULL, POOL)
    case("witness: source key_url host is not signed_domain", edit(WCHAIN, obs + ("source", "key_url"), "https://witness-b.example.evil/k"), FULL, POOL)
    case("witness: expected_after key toString (the JavaScript throws)", edit(edit(WCHAIN, (3, "expected_after", "toString"), {"a": "b"}), (6, "expected_after", "toString"), {"a": "b"}), FULL, POOL)
    case("witness: expected_after __proto__ meets Object.prototype", edit(edit(WCHAIN, (3, "expected_after", "__proto__"), {}), (6, "expected_after", "__proto__"), {}), FULL, POOL)
    case("witness: segment endpoint uppercase with port", edit(WCHAIN, (0, "endpoint"), "HTTPS://Gate.HorizonShield.dev:443/a2a"), FULL, POOL)
    # ---- v2.4 (2026-10-22, red team R2-1 and R5-F1): the attack and control cases of recovery-v0/witness_v24_cases.mjs ----
    for c in v24_cases():
        q, args, pool = c["quorum"], [], None
        if "pool" in q:
            args += ["--pool", "pool.json"]; pool = q["pool"]
        for key, flag in (("q", "--q"), ("k", "--k"), ("beaconHash", "--beacon"), ("beaconTime", "--beacon-time")):
            if key in q:
                args += [flag, str(q[key])]
        for key, flag in (("requireCommitment", "--require-commitment"), ("requireV24", "--require-v24")):
            if q.get(key):
                args.append(flag)
        case("v2.4: " + c["name"], c["records"], args, pool)
    return CASES


def v24_cases():
    """The v2.4 cases, built by the JavaScript module (deterministic keys and Ed25519, so the same bytes every run)."""
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "v24.json")
        subprocess.run(["node", os.path.join(REC, "witness_v24_cases.mjs"), out], check=True, cwd=REC)
        with open(out, encoding="utf-8") as f:
            return json.load(f)["cases"]


def run_js(c):
    """The JavaScript CLI on one case: (stdout, exit code); a throw is recorded as no stdout."""
    with tempfile.TemporaryDirectory() as d:
        for name, text in c["files"].items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(text)
        p = subprocess.run(["node", JS] + c["args"], cwd=d, capture_output=True, text=True, encoding="utf-8")
    out = p.stdout.replace(NODE22_KEY_TEXT, tsugi.KEY_LENGTH_MESSAGE)
    return {"stdout": out, "exit": p.returncode, "threw": p.returncode not in (0, 1, 2) or (p.returncode == 1 and out == "")}


def main():
    cases = build()
    names = [c["name"] for c in cases]
    assert len(set(names)) == len(names), "duplicate case names"
    for c in cases:
        c["js"] = run_js(c)
    text = json.dumps({"reference": "tsugi_verify.mjs " + tsugi.VERIFIER_VERSION, "cases": cases}, ensure_ascii=False, indent=1) + "\n"
    if "--check" in sys.argv:
        same = os.path.exists(SELFTEST) and gzip.decompress(open(SELFTEST, "rb").read()).decode("utf-8") == text
        print("unchanged" if same else "would change: " + SELFTEST)
        return 0 if same else 1
    with open(SELFTEST, "wb") as f:
        f.write(gzip.compress(text.encode("utf-8"), 9, mtime=0))
    codes = set()
    for c in cases:
        for line in c["js"]["stdout"].split("\n"):
            if '"code": ' in line:
                codes.add(line.split('"code": ')[1].strip(' ",'))
    print("%d cases, %d threw in JavaScript, %d refusal codes reached" % (len(cases), sum(c["js"]["threw"] for c in cases), len(codes)))
    print(" ".join(sorted(codes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
