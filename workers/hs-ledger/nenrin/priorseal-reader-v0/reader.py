#!/usr/bin/env python3
"""priorseal-reader-v0: an independent reader for the PriorSeal exact-call matrix, contract 1.0.1.

Written from the published contract and fixture only. It does not import, open or copy any PriorSeal
verifier, reader, runner, generator or SDK source. The files it opens are listed in OPENED below and the
verifier sources are only hashed (sha256 over bytes, never decoded) to check them against MANIFEST.json.

Usage:
    python3 -I reader.py --clone <PriorSeal checkout at 2ff89d8> [--out report.json]

Exit code: 0 when every claim is ESTABLISHED or NOT_ESTABLISHED (no contradiction) and every comparable
field equals the published report.json; 1 otherwise. NOT_ESTABLISHED never counts as a pass in the summary.
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from importlib import metadata

from Crypto.Hash import keccak  # pycryptodome
from eth_keys import keys as eth_keys_mod
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

READER_ID = "hs-nenrin/priorseal-reader-v0"
PINNED_COMMIT = "2ff89d86611257b4440232e5c2793926b3d52043"
TEMPLATE_COMMIT = "d90e5d3aaccc7e83e19ca39d2e785290a480801a"
REPO = "https://github.com/imokokok/PriorSeal"
MATRIX = "examples/open-evidence-lab-exact-call-matrix-v1"
CONTRACT_VERSION = "1.0.1"
PROFILE = "priorseal.execution-profile.exact-call.v1"
# Values stated in the task brief / published report that the reader must reproduce on its own.
PUBLISHED_DIGEST = "0x9e404bfc63c56cda555b71c4e59237178edc7a428de7f50738804a1f092cf5b1"
PUBLISHED_AUTHORIZER = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

# Files this program opens as text/JSON (matrix-relative).
OPENED = [
    "INPUT-CONTRACT.md",
    "README.md",
    "MANIFEST.json",
    "expected.json",
    "report.json",
    "fixture/signed-authorization.json",
    "fixture/public-test-keys.json",
    "fixture/observed/case-00-exact-call-observed-match.json",
    "fixture/observed/case-01-call-target-mismatch.json",
    "fixture/observed/case-02-calldata-mismatch.json",
    "fixture/observed/case-03-transaction-value-mismatch.json",
    "fixture/observed/case-04-execution-evidence-unavailable.json",
    "fixture/observed/case-05-time-window-expired.json",
]
# Producer code: hashed as bytes for the manifest check, never decoded, parsed or executed.
HASHED_ONLY = [
    "reader.mjs", "reader.mts", "verify.mjs", "verify.mts", "generate-fixture.mjs", "generate-fixture.mts",
]

ESTABLISHED, CONTRADICTED, NOT_ESTABLISHED = "ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"

# Rule sources, cited per claim so a reviewer can see which text each check rests on.
SRC_IC = "INPUT-CONTRACT.md (1.0.1)"
SRC_APS = "docs/architecture/aps-priorseal-signing-bytes-v0.4.0.md (written for a different fixture; applied here)"
SRC_LC = "docs/architecture/lifecycle.md"
SRC_EIP712 = "EIP-712 (standard), with the field list of INPUT-CONTRACT.md 2.1 and 2.3"
SRC_PKT = "docs/runs/priorseal-exact-call-matrix-v1.0.1-cold-run/README.md at d90e5d3 (authorization check at notBefore)"
SRC_MAN = "MANIFEST.json"


# ---------------------------------------------------------------------------------------------- helpers

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(p):
    with open(p, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def k256(b):
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def claim(cid, status, statement, rule_source, ours=None, published=None, note=None):
    c = {"id": cid, "status": status, "statement": statement, "ruleSource": rule_source}
    if ours is not None:
        c["ours"] = ours
    if published is not None:
        c["published"] = published
    if note:
        c["note"] = note
    return c


def est(ok):
    return ESTABLISHED if ok else CONTRADICTED


# Canonical JSON as stated in the APS signing-bytes doc: no whitespace, object keys sorted by JavaScript
# string order (UTF-16 code units), primitives serialized like JSON.stringify. Written here from that text.
def _js_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)  # lone surrogate, as JSON.stringify (ES2019) does
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s):
    return s.encode("utf-16-be")


def canon(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > 2 ** 53 - 1:
            raise ValueError("unsafe integer in canonical input")
        return str(v)
    if isinstance(v, float):
        raise ValueError("non-integer number in canonical input; not exercised by this fixture")
    if isinstance(v, str):
        return _js_str(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if k in ("__proto__", "prototype", "constructor"):
                raise ValueError("unsafe key " + k)
        items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_js_str(k) + ":" + canon(x) for k, x in items) + "}"
    raise ValueError("unsupported JSON value")


def H(v):
    return hashlib.sha256(canon(v).encode("utf-8")).hexdigest()


def without(d, *ks):
    return {k: x for k, x in d.items() if k not in ks}


# JavaScript String() coercion as stated in INPUT-CONTRACT.md 4 "Comparison semantics".
def js_string(v):
    if v is None:
        return ""
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        raise ValueError("fractional number comparison is not specified by the contract")
    if isinstance(v, str):
        return v
    raise ValueError("object/array comparison is not specified by the contract")


def ci_eq(a, b):
    # ASCII-case-insensitive, after String() coercion.
    def low(s):
        return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)
    return low(js_string(a)) == low(js_string(b))


def eip55(addr_hex40_lower):
    a = addr_hex40_lower.lower().replace("0x", "")
    hh = k256(a.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(hh[i], 16) >= 8 else c for i, c in enumerate(a))


# ---------------------------------------------------------------------------------------------- EIP-712

AUTH_FIELDS = [
    ("intentHash", "bytes32"), ("principalType", "string"), ("principalId", "string"),
    ("principalAccount", "address"), ("authorizerType", "string"), ("authorizer", "address"),
    ("agentId", "string"), ("executor", "address"), ("issuedAt", "uint256"), ("notBefore", "uint256"),
    ("expiresAt", "uint256"), ("authorizationNonce", "bytes32"), ("maxUses", "uint256"),
    ("audience", "string"), ("policyHash", "bytes32"),
]


def auth_message(a):
    # INPUT-CONTRACT.md 2.3 struct field -> JSON path map.
    return {
        "intentHash": "0x" + a["intentHash"],
        "principalType": a["principal"]["type"],
        "principalId": a["principal"]["id"],
        "principalAccount": a["principal"]["account"],
        "authorizerType": a["authorizer"]["type"],
        "authorizer": a["authorizer"]["address"],
        "agentId": a["delegate"]["agentId"],
        "executor": a["delegate"]["executor"],
        "issuedAt": int(a["issuedAt"]),
        "notBefore": int(a["notBefore"]),
        "expiresAt": int(a["expiresAt"]),
        "authorizationNonce": a["authorizationNonce"],
        "maxUses": int(a["maxUses"]),
        "audience": a["audience"],
        "policyHash": a["policyHash"],
    }


def _enc(typ, val):
    if typ == "string":
        return k256(val.encode("utf-8"))
    if typ == "bytes32":
        b = bytes.fromhex(val[2:] if val.startswith("0x") else val)
        if len(b) != 32:
            raise ValueError("bytes32 length")
        return b
    if typ == "address":
        b = bytes.fromhex(val[2:])
        if len(b) != 20:
            raise ValueError("address length")
        return b"\x00" * 12 + b
    if typ == "uint256":
        v = int(val)
        if v < 0 or v >= 2 ** 256:
            raise ValueError("uint256 range")
        return v.to_bytes(32, "big")
    raise ValueError(typ)


def struct_hash(name, fields, msg):
    tstr = name + "(" + ",".join(t + " " + n for n, t in fields) + ")"
    return k256(k256(tstr.encode("ascii")) + b"".join(_enc(t, msg[n]) for n, t in fields)), tstr


def eip712_digest(chain_id, msg):
    dom_fields = [("name", "string"), ("version", "string"), ("chainId", "uint256")]
    dsep, dstr = struct_hash("EIP712Domain", dom_fields, {"name": "PriorSeal", "version": "2", "chainId": chain_id})
    sh, tstr = struct_hash("PriorSealAuthorization", AUTH_FIELDS, msg)
    return k256(b"\x19\x01" + dsep + sh), dsep, sh, tstr, dstr


def recover(digest, sig_hex):
    sig = bytes.fromhex(sig_hex[2:])
    if len(sig) != 65:
        raise ValueError("signature length")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    if v not in (27, 28):
        raise ValueError("v not 27/28")
    pub = eth_keys_mod.Signature(vrs=(v - 27, r, s)).recover_public_key_from_msg_hash(digest)
    addr = "0x" + k256(pub.to_bytes())[-20:].hex()
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return addr, {"v": v, "lowS": s <= n // 2}


def eth_account_crosscheck(chain_id, msg, sig_hex):
    """Second, library path (eth-account) for the same digest and recovery. Not PriorSeal code."""
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data, _hash_eip191_message
        typed = {
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                                 {"name": "chainId", "type": "uint256"}],
                "PriorSealAuthorization": [{"name": n, "type": t} for n, t in AUTH_FIELDS],
            },
            "primaryType": "PriorSealAuthorization",
            "domain": {"name": "PriorSeal", "version": "2", "chainId": chain_id},
            "message": msg,
        }
        sm = encode_typed_data(full_message=typed)
        return "0x" + _hash_eip191_message(sm).hex(), Account.recover_message(sm, signature=sig_hex).lower()
    except Exception as e:  # pragma: no cover
        return "error: " + type(e).__name__ + ": " + str(e), None


# ---------------------------------------------------------------------------------------------- field map

def observed_time(obs):
    # INPUT-CONTRACT.md 4: executedAt (fallback observedAt).
    t = obs.get("executedAt")
    if t is None:
        t = obs.get("observedAt")
    return t, ("executedAt" if obs.get("executedAt") is not None else "observedAt")


def time_int(t):
    """The observed time as an integer, or None when it is not one (G10: a non-numeric executedAt such as "late"
    made this reader raise ValueError instead of answering; piiiico, atlas #49, 2026-10-15). A bool is not a time."""
    return t if isinstance(t, int) and not isinstance(t, bool) else None


def present(intent, k):
    # "only when present in the signed intent": read as key present with a non-null value (see spec gap G6).
    return k in intent and intent[k] is not None


def field_map(auth, obs):
    intent = auth["intent"]
    rows = []

    def row(code, signed_path, observed_path, rule, applies, mismatch, signed, observed):
        rows.append({"code": code, "signed": signed_path, "observed": observed_path, "rule": rule,
                     "applies": applies, "signedValue": signed, "observedValue": observed,
                     "mismatch": bool(applies and mismatch)})

    # chainId: "strict equality of the integer values"
    sc, oc = intent.get("chainId"), obs.get("chainId")
    if isinstance(sc, int) and isinstance(oc, int):
        mm = sc != oc
    else:
        mm = js_string(sc) != js_string(oc)
    row("CHAIN_MISMATCH", "intent.chainId", "chainId", "strict equality of the integer values", True, mm, sc, oc)
    row("ACTION_MISMATCH", "intent.action", "action", "case-insensitive equality", True,
        not ci_eq(intent.get("action"), obs.get("action")), intent.get("action"), obs.get("action"))
    row("SENDER_MISMATCH", "intent.sender", "sender", "case-insensitive equality", True,
        not ci_eq(intent.get("sender"), obs.get("sender")), intent.get("sender"), obs.get("sender"))
    sn = intent.get("nonce") if intent.get("nonce") is not None else "0"
    on = obs.get("nonce") if obs.get("nonce") is not None else "0"
    row("NONCE_MISMATCH", "intent.nonce", "nonce", "equality of decimal-string forms, default \"0\"", True,
        js_string(sn) != js_string(on), intent.get("nonce"), obs.get("nonce"))
    row("CALL_TARGET_MISMATCH", "intent.callTarget", "target", "case-insensitive equality, when signed present",
        present(intent, "callTarget"), not ci_eq(intent.get("callTarget"), obs.get("target")),
        intent.get("callTarget"), obs.get("target"))
    row("CALLDATA_MISMATCH", "intent.calldataHash", "calldataHash",
        "case-insensitive equality, when signed present", present(intent, "calldataHash"),
        not ci_eq(intent.get("calldataHash"), obs.get("calldataHash")),
        intent.get("calldataHash"), obs.get("calldataHash"))
    row("TRANSACTION_VALUE_MISMATCH", "intent.transactionValue", "nativeValue",
        "equality of decimal-string forms, when signed present", present(intent, "transactionValue"),
        js_string(intent.get("transactionValue")) != js_string(obs.get("nativeValue")),
        intent.get("transactionValue"), obs.get("nativeValue"))
    t, tsrc = observed_time(obs)
    ti = time_int(t)
    vu = intent.get("validUntil")
    # G9/G10: a missing time (both fields absent) or a non-integer time cannot pass a window check. The two
    # shipped paths disagree on the first (reader.mjs skips, the profile fails closed) and both pass the second;
    # this reader marks the row as applying and mismatched, so the case is not bound, and says why in the rule.
    bad_time = t is None or ti is None
    why = "" if not bad_time else (" (no observed time: cannot be inside any window)" if t is None
                                   else " (observed time is not an integer: cannot be inside any window)")
    row("OUTSIDE_TIME_WINDOW", "intent.validUntil", tsrc, "observed time greater than validUntil" + why,
        vu is not None, bad_time or ti > int(vu), vu, t)
    nb, ex = auth.get("notBefore"), auth.get("expiresAt")
    row("OUTSIDE_AUTHORIZATION_WINDOW", "authorization.notBefore / authorization.expiresAt", tsrc,
        "observed time earlier than notBefore or greater than expiresAt" + why, True,
        bad_time or ti < int(nb) or ti > int(ex), [nb, ex], t)
    mismatch = sorted(r["code"] for r in rows if r["mismatch"])
    # INPUT-CONTRACT.md 5: executionDataAvailable false yields EXECUTION_UNAVAILABLE.
    avail = sorted(["EXECUTION_UNAVAILABLE"] if obs.get("executionDataAvailable") is False else [])
    return rows, mismatch, avail


UNDETERMINED_STATES = {"PENDING", "NOT_FOUND", "RPC_ERROR", "RPC_TIMEOUT"}  # lifecycle.md


def correlation(auth, obs):
    # lifecycle.md: a final execution correlated by chain, delegated executor and nonce is assessable.
    intent = auth["intent"]
    return {
        "chain": js_string(intent.get("chainId")) == js_string(obs.get("chainId")),
        "delegatedExecutor": ci_eq(auth["delegate"]["executor"], obs.get("sender")),
        "nonce": js_string(intent.get("nonce") if intent.get("nonce") is not None else "0")
        == js_string(obs.get("nonce") if obs.get("nonce") is not None else "0"),
    }


def outcome_of(obs, avail):
    # Inferred from lifecycle.md prose; the contract itself states no general outcome rule (spec gap G3).
    st = obs.get("status")
    if avail or st in UNDETERMINED_STATES:
        return "UNDETERMINED"
    if st in ("CONFIRMED", "FINALIZED"):
        return "COMPLETED"
    if st == "REORGED":
        return "REORGED"
    return None  # REVERTED and anything else: label not published for this profile


def compliance_of(obs, mismatch, avail, corr):
    # Inferred from lifecycle.md and evidence-relationship-levels.md; not stated in the contract (gap G3, G4).
    if avail:
        return "NOT_ASSESSABLE", list(avail)
    if obs.get("status") in UNDETERMINED_STATES or obs.get("status") == "REORGED":
        return "NOT_ASSESSABLE", []
    if not all(corr.values()):
        return "NOT_ASSESSABLE", list(mismatch)  # "an unrelated transaction remains not assessable"
    if mismatch:
        return "NON_COMPLIANT", list(mismatch)
    return "COMPLIANT", []


# ---------------------------------------------------------------------------------------------- main

def tool_versions():
    out = {"python": platform.python_version(), "implementation": platform.python_implementation()}
    for d in ("pycryptodome", "eth-keys", "eth-account", "cryptography", "eth-hash", "eth-utils"):
        try:
            out[d] = metadata.version(d)
        except metadata.PackageNotFoundError:
            out[d] = None
    return out


def git_head(clone):
    try:
        return subprocess.run(["git", "-C", clone, "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except Exception:
        return None


def readme_case_outcomes(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"\|\s*`(case-\d\d-[a-z0-9-]+)`\s*\|[^|]*\|(.*)\|\s*$", line)
        if m:
            cell = m.group(2)
            out[m.group(1)] = sorted(set(re.findall(r"\b(COMPLETED|UNDETERMINED)\b", cell)))
    return out


def cmp_field(rows, path, ours, theirs, kind="equal"):
    if kind == "set":
        eq = sorted(ours) == sorted(theirs) if (ours is not None and theirs is not None) else False
    elif kind == "ci":
        eq = (ours is not None and theirs is not None and ours.lower() == theirs.lower())
    else:
        eq = ours == theirs
    rows.append({"field": path, "ours": ours, "published": theirs, "equal": eq,
                 "comparison": {"equal": "exact", "set": "sorted-set", "ci": "case-insensitive"}[kind]})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clone", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    clone = os.path.abspath(args.clone)
    mdir = os.path.join(clone, MATRIX)
    P = lambda rel: os.path.join(mdir, rel)  # noqa: E731

    head = git_head(clone)
    files = []
    for rel in OPENED:
        files.append({"path": MATRIX + "/" + rel, "sha256": sha256_file(P(rel)), "bytes": os.path.getsize(P(rel)),
                      "use": "opened"})
    for rel in HASHED_ONLY:
        files.append({"path": MATRIX + "/" + rel, "sha256": sha256_file(P(rel)), "bytes": os.path.getsize(P(rel)),
                      "use": "hashed-only (bytes digested for the manifest check; never decoded or executed)"})

    src = load_json(P("fixture/signed-authorization.json"))
    tk = load_json(P("fixture/public-test-keys.json"))
    expected = load_json(P("expected.json"))
    theirs = load_json(P("report.json"))
    manifest = load_json(P("MANIFEST.json"))
    with open(P("README.md"), encoding="utf-8") as f:
        readme = f.read()
    auth, acc = src["authorization"], src["acceptance"]
    intent = auth["intent"]

    matrix_claims = []
    # M1 pin
    matrix_claims.append(claim("M1.commit", est(head == PINNED_COMMIT), "checkout HEAD is the pinned commit",
                               "task pin", ours=head, published=PINNED_COMMIT))
    # M2 manifest digests
    bad = []
    for a in manifest["artifacts"]:
        p = P(a["path"])
        got = sha256_file(p) if os.path.exists(p) else None
        if got != a["sha256"] or os.path.getsize(p) != a["bytes"]:
            bad.append({"path": a["path"], "manifest": a["sha256"], "ours": got})
    matrix_claims.append(claim("M2.manifest-digests", est(not bad),
                               "every MANIFEST.json artifact digest and byte length matches the checkout",
                               SRC_MAN, ours={"artifacts": len(manifest["artifacts"]), "mismatched": bad}))
    matrix_claims.append(claim("M3.contract-version", est(manifest.get("contractVersion") == CONTRACT_VERSION
                                                          and expected.get("contractVersion") == CONTRACT_VERSION
                                                          and theirs.get("contractVersion") == CONTRACT_VERSION),
                               "MANIFEST, expected.json and report.json all carry contract 1.0.1", SRC_MAN))
    rep_sha = sha256_file(P("report.json"))
    matrix_claims.append(claim("M4.report-sha256", est(rep_sha == "223db1554639f242eae559b1f010dcabe3e9466e610cfa95aefe2e1ce564a363"),
                               "committed report.json sha256 equals the value in the d90e5d3 cold-run packet",
                               SRC_PKT, ours=rep_sha))
    # M5 expected blocks inside report.json equal expected.json
    exp_by_id = {c["id"]: c for c in expected["cases"]}
    same = all(c["expected"] == exp_by_id[c["id"]]["expected"] for c in theirs["cases"])
    matrix_claims.append(claim("M5.report-embeds-expected", est(same and len(theirs["cases"]) == len(expected["cases"])),
                               "every expected block in report.json equals expected.json", "expected.json"))
    # M6 README case table outcome vs expected.json
    rd = readme_case_outcomes(readme)
    diffs = []
    for cid, c in exp_by_id.items():
        r = rd.get(cid)
        if r != [c["expected"]["outcome"]]:
            diffs.append({"case": cid, "readmeOutcome": r, "expectedOutcome": c["expected"]["outcome"]})
    matrix_claims.append(claim("M6.readme-table-consistent", est(not diffs),
                               "the matrix README case table states the same outcome as expected.json for every case",
                               "README.md vs expected.json", ours=diffs or None,
                               note="documentation consistency only; does not affect any computed result"))

    # ---------------------------------------------------------------- authorization-level claims
    ac = []
    ih = H(without(intent, "intentHash"))
    ac.append(claim("A1.intentHash", est(ih == intent.get("intentHash") == auth.get("intentHash") == acc.get("intentHash")),
                    "intentHash = H(intent without intentHash), and the intent, authorization and acceptance copies agree",
                    SRC_APS, ours=ih, published=auth.get("intentHash")))
    aid = "auth_" + H(without(auth, "authorizationId", "signature"))[:32]
    ac.append(claim("A2.authorizationId", est(aid == auth.get("authorizationId") == acc.get("authorizationId")),
                    "authorizationId = auth_ + first 32 hex of H(authorization without authorizationId, signature); acceptance carries the same id",
                    SRC_APS, ours=aid, published=auth.get("authorizationId")))
    ah = H(auth)
    ac.append(claim("A3.authorizationHash", est(ah == acc.get("authorizationHash")),
                    "acceptance.authorizationHash = H(full authorization)", SRC_APS, ours=ah,
                    published=acc.get("authorizationHash")))
    eh = H({"sequence": acc["sequence"], "authorizationHash": acc["authorizationHash"],
            "acceptedAt": acc["acceptedAt"], "previousEntryHash": acc["previousEntryHash"]})
    ac.append(claim("A4.entryHash", est(eh == acc.get("entryHash")),
                    "acceptance.entryHash = H({sequence, authorizationHash, acceptedAt, previousEntryHash})",
                    SRC_APS, ours=eh, published=acc.get("entryHash")))
    chain_id = int(intent["chainId"])
    msg = auth_message(auth)
    dig, dsep, sh, tstr, dstr = eip712_digest(chain_id, msg)
    dig_hex = "0x" + dig.hex()
    ac.append(claim("A5.eip712-digest", est(dig_hex == PUBLISHED_DIGEST == theirs["signature"]["eip712Digest"]),
                    "EIP-712 digest recomputed by hand from the 2.1 field list, 2.3 path map and domain {PriorSeal, 2, intent.chainId}",
                    SRC_EIP712, ours=dig_hex, published=theirs["signature"]["eip712Digest"],
                    note="typeString=" + tstr + "; domainType=" + dstr + "; domainSeparator=0x" + dsep.hex()
                    + "; structHash=0x" + sh.hex()))
    rec, sigmeta = recover(dig, auth["signature"])
    ac.append(claim("A6.signer-recovery", est(rec == auth["authorizer"]["address"].lower() == PUBLISHED_AUTHORIZER
                                               and rec == tk["authorizer"]["address"].lower()),
                    "signer recovered from (digest, authorization.signature) equals authorization.authorizer.address and the published test address",
                    SRC_IC + " 2.1", ours=eip55(rec), published=theirs["signature"]["recoveredAuthorizer"],
                    note="v=%d lowS=%s" % (sigmeta["v"], sigmeta["lowS"])))
    x_dig, x_rec = eth_account_crosscheck(chain_id, msg, auth["signature"])
    ac.append(claim("A7.library-crosscheck", est(x_dig == dig_hex and x_rec == rec),
                    "a second path (eth-account encode_typed_data + recover_message) yields the same digest and signer",
                    "eth-account (not PriorSeal code)", ours={"digest": x_dig, "signer": x_rec}))
    # Acceptance Ed25519
    pub = serialization.load_pem_public_key(tk["issuer"]["publicKeyPem"].encode("ascii"))
    unsigned = without(acc, "signature")
    sig_b = base64.urlsafe_b64decode(acc["signature"] + "=" * (-len(acc["signature"]) % 4))
    try:
        assert isinstance(pub, Ed25519PublicKey)
        pub.verify(sig_b, canon(unsigned).encode("utf-8"))
        ed_ok = True
    except (InvalidSignature, AssertionError):
        ed_ok = False
    ac.append(claim("A8.acceptance-signature", est(ed_ok and len(sig_b) == 64),
                    "Ed25519 signature over UTF-8(canonical JSON of acceptance without signature) verifies under the published issuer key",
                    SRC_IC + " 2.2 + " + SRC_APS + " (canonical form)", ours=ed_ok,
                    published=theirs["signature"]["acceptanceSignatureValid"]))
    ac.append(claim("A9.acceptance-identity", est(acc["issuer"] == tk["issuer"]["issuer"] and acc["keyId"] == tk["issuer"]["keyId"]
                                                  and acc["algorithm"] == "Ed25519"),
                    "acceptance issuer, keyId and algorithm match fixture/public-test-keys.json", SRC_IC + " 2.2",
                    ours={"issuer": acc["issuer"], "keyId": acc["keyId"]}))
    ac.append(claim("A10.acceptance-status", est(acc["status"] == "ACCEPTED" and acc["sequence"] == 1
                                                 and acc["previousEntryHash"] is None
                                                 and acc["schema"] == "priorseal.authorization-receipt.v1"),
                    "acceptance is an ACCEPTED priorseal.authorization-receipt.v1, first log entry (sequence 1, previousEntryHash null)",
                    SRC_APS + "; " + SRC_LC))
    # Authorization window at the reference time (notBefore).
    t_ref = int(auth["notBefore"])
    win = {"issuedAt<=notBefore": int(auth["issuedAt"]) <= int(auth["notBefore"]),
           "notBefore<=tRef<=expiresAt": int(auth["notBefore"]) <= t_ref <= int(auth["expiresAt"]),
           "issuedAt<=acceptedAt<=expiresAt": int(auth["issuedAt"]) <= int(acc["acceptedAt"]) <= int(auth["expiresAt"]),
           "maxUses>=1": int(auth["maxUses"]) >= 1,
           "principal.account==authorizer.address (eip712 EOA)": auth["principal"]["account"].lower() == auth["authorizer"]["address"].lower(),
           "authorizer.type==eip712": auth["authorizer"]["type"] == "eip712",
           "schema/domain": auth["schema"] == "priorseal.authorization.v2" and auth["domain"] == "priorseal/authorization/v2",
           "intent.executionProfile": intent.get("executionProfile") == PROFILE and src.get("profile") == PROFILE}
    win_ok = all(win.values())
    ac.append(claim("A11.authorization-window-at-reference-time", est(win_ok),
                    "at reference time tRef = notBefore the authorization is inside [notBefore, expiresAt], was issued no later than notBefore, accepted inside its window, and is a single-use eip712 v2 authorization for this profile",
                    SRC_PKT + "; " + SRC_IC + " 2", ours={"tRef": t_ref, "checks": win},
                    published=theirs["signature"]["authorizationValidAtNotBefore"],
                    note="the reference time is not stated in INPUT-CONTRACT.md at 2ff89d8 (spec gap G2); policyHash is the zero hash and no policy document is published, so policy admission is not checked"))
    # Test-material self-consistency (public deterministic TEST values published in the fixture).
    try:
        seed = bytes.fromhex(tk["issuer"]["testSeedHex"])
        derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pem_raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pk = eth_keys_mod.PrivateKey(bytes.fromhex(tk["authorizer"]["testPrivateKey"][2:]))
        derived_addr = pk.public_key.to_checksum_address()
        ok = derived == pem_raw and derived_addr == tk["authorizer"]["address"]
    except Exception:
        ok = False
    ac.append(claim("A12.test-material-consistency", est(ok),
                    "the published TEST seed and TEST secp256k1 value derive the published Ed25519 key and authorizer address",
                    "fixture/public-test-keys.json",
                    note="informational; shows the key file is self-consistent, adds nothing to signature validity"))
    # EIP-55 form of the recovered address equals the published checksummed form.
    ac.append(claim("A13.checksum-form", est(eip55(rec) == tk["authorizer"]["address"] == theirs["signature"]["recoveredAuthorizer"]),
                    "EIP-55 checksum form of the recovered signer equals the published form", "EIP-55",
                    ours=eip55(rec)))
    auth_all_ok = all(c["status"] == ESTABLISHED for c in ac)

    # ---------------------------------------------------------------- per-case
    cases_out = []
    field_rows_all = []
    their_cases = {c["id"]: c for c in theirs["cases"]}
    for ec in expected["cases"]:
        cid = ec["id"]
        obs = load_json(P(ec["observed"]))
        rows, mismatch, avail = field_map(auth, obs)
        bound = len(mismatch) == 0
        raw_codes = sorted(set(mismatch) | set(avail))
        corr = correlation(auth, obs)
        comp, comp_codes = compliance_of(obs, mismatch, avail, corr)
        outc = outcome_of(obs, avail)
        cls = "evidence-availability" if avail else "envelope-binding"
        t, tsrc = observed_time(obs)
        cc = []
        cc.append(claim("C1.schema", est(obs.get("schema") == "priorseal.execution-observation.v1"),
                        "observation is a priorseal.execution-observation.v1 envelope", SRC_IC + " 3"))
        cc.append(claim("C2.binding-authorization-to-observation", est(all(corr.values())),
                        "observation correlates to the authorization by chain, delegated executor (authorization.delegate.executor vs observed sender) and nonce",
                        SRC_LC, ours=corr,
                        note="the observation carries no authorizationId or intentHash; the pairing itself is by fixture layout (spec gap G5)"))
        cc.append(claim("C3.acceptance-before-execution", est(time_int(t) is not None and int(acc["acceptedAt"]) <= time_int(t)),
                        "acceptance.acceptedAt is not later than the observed execution time (else AUTHORIZATION_AFTER_EXECUTION)",
                        SRC_LC, ours={"acceptedAt": acc["acceptedAt"], tsrc: t}))
        cc.append(claim("C4.decision-evidence-binding", NOT_ESTABLISHED,
                        "binding to separate decision evidence", "n/a",
                        note="the matrix contains no decision-evidence object and the intent carries no contextCommitments; the only pre-execution evidence is the issuer acceptance (A1 to A10)"))
        exp = ec["expected"]
        cc.append(claim("C5.mismatch-codes", est(mismatch == sorted(exp["reasonCodes"])),
                        "section 4 mismatch set recomputed from the field map", SRC_IC + " 4",
                        ours=mismatch, published=sorted(exp["reasonCodes"])))
        cc.append(claim("C6.availability-codes", est(avail == sorted(exp["availabilityCodes"])),
                        "section 5 availability set recomputed", SRC_IC + " 5", ours=avail,
                        published=sorted(exp["availabilityCodes"])))
        cc.append(claim("C7.bound", est(bound == exp["bound"]), "bound = (mismatch set is empty)", SRC_IC + " 4",
                        ours=bound, published=exp["bound"]))
        cc.append(claim("C8.compliance", est(comp == exp["complianceStatus"] and comp_codes == sorted(exp["complianceReasonCodes"])),
                        "compliance status and reason codes from an inferred rule (availability -> NOT_ASSESSABLE with those codes; correlated final mismatch -> NON_COMPLIANT with the mismatch codes; else COMPLIANT)",
                        SRC_LC + " (inferred; not stated in the contract, spec gap G3/G4)",
                        ours={"status": comp, "codes": comp_codes},
                        published={"status": exp["complianceStatus"], "codes": sorted(exp["complianceReasonCodes"])}))
        cc.append(claim("C9.outcome", est(outc == exp["outcome"]) if outc else NOT_ESTABLISHED,
                        "outcome from observation state (CONFIRMED -> COMPLETED; NOT_FOUND/PENDING/RPC_* or unavailable evidence -> UNDETERMINED)",
                        SRC_LC + " (inferred; spec gap G3)", ours=outc, published=exp["outcome"]))
        cc.append(claim("C10.raw-profile-binding", est(raw_codes == sorted(their_cases[cid]["profile"]["rawBinding"]["reasonCodes"])
                                                         and (len(raw_codes) == 0) == their_cases[cid]["profile"]["rawBinding"]["bound"]),
                        "the shipped profile's raw binding equals mismatch set UNION availability set (as the contract changelog note describes)",
                        SRC_IC + " 0 (note on the shipped profile)", ours={"bound": len(raw_codes) == 0, "codes": raw_codes},
                        published=their_cases[cid]["profile"]["rawBinding"]))
        cc.append(claim("C11.receiptClaimsValid", NOT_ESTABLISHED,
                        "profile.receiptClaimsValid", "not specified",
                        note="no receipt object is published in the matrix and the contract does not define this field; not independently derivable"))
        cc.append(claim("C12.className", est(cls == ec["className"]),
                        "case class derived from the result (availability code present -> evidence-availability)",
                        SRC_IC + " 5", ours=cls, published=ec["className"]))

        # Field-by-field comparison with the published report.json
        tc = their_cases[cid]
        fr = []
        cmp_field(fr, "reader.bound", bound, tc["reader"]["bound"])
        cmp_field(fr, "reader.mismatchCodes", mismatch, tc["reader"]["mismatchCodes"], "set")
        cmp_field(fr, "reader.availabilityCodes", avail, tc["reader"]["availabilityCodes"], "set")
        cmp_field(fr, "profile.partitionedBinding.bound", bound, tc["profile"]["partitionedBinding"]["bound"])
        cmp_field(fr, "profile.partitionedBinding.mismatchCodes", mismatch, tc["profile"]["partitionedBinding"]["mismatchCodes"], "set")
        cmp_field(fr, "profile.partitionedBinding.availabilityCodes", avail, tc["profile"]["partitionedBinding"]["availabilityCodes"], "set")
        cmp_field(fr, "profile.rawBinding.bound", len(raw_codes) == 0, tc["profile"]["rawBinding"]["bound"])
        cmp_field(fr, "profile.rawBinding.reasonCodes", raw_codes, tc["profile"]["rawBinding"]["reasonCodes"], "set")
        cmp_field(fr, "profile.complianceStatus", comp, tc["profile"]["complianceStatus"])
        cmp_field(fr, "profile.complianceReasonCodes", comp_codes, tc["profile"]["complianceReasonCodes"], "set")
        cmp_field(fr, "profile.outcome", outc, tc["profile"]["outcome"])
        cmp_field(fr, "className", cls, tc["className"])
        cmp_field(fr, "pass", all(c["status"] != CONTRADICTED for c in cc) and auth_all_ok, tc["pass"])
        not_comparable = [{"field": "profile.receiptClaimsValid", "published": tc["profile"]["receiptClaimsValid"],
                           "reason": "not specified by the contract; no receipt object in the matrix"},
                          {"field": "agreement.*", "published": tc["agreement"],
                           "reason": "their internal cross-implementation agreement flags; replaced here by our own comparison rows"}]
        field_rows_all.extend({"case": cid, **r} for r in fr)
        cases_out.append({"id": cid, "observed": ec["observed"],
                          "observedSha256": sha256_file(P(ec["observed"])),
                          "derived": {"fieldMap": rows, "mismatchCodes": mismatch, "availabilityCodes": avail,
                                      "bound": bound, "rawBinding": {"bound": len(raw_codes) == 0, "reasonCodes": raw_codes},
                                      "correlation": corr, "complianceStatus": comp, "complianceReasonCodes": comp_codes,
                                      "outcome": outc, "className": cls},
                          "claims": cc, "comparison": fr, "notComparable": not_comparable})

    # Signature block comparison
    sig_rows = []
    ts = theirs["signature"]
    cmp_field(sig_rows, "signature.declaredAuthorizer", auth["authorizer"]["address"], ts["declaredAuthorizer"])
    cmp_field(sig_rows, "signature.recoveredAuthorizer", eip55(rec), ts["recoveredAuthorizer"])
    cmp_field(sig_rows, "signature.authorizerMatches", rec == auth["authorizer"]["address"].lower(), ts["authorizerMatches"])
    cmp_field(sig_rows, "signature.eip712Digest", dig_hex, ts["eip712Digest"])
    cmp_field(sig_rows, "signature.acceptanceIssuer", acc["issuer"], ts["acceptanceIssuer"])
    cmp_field(sig_rows, "signature.acceptanceKeyId", acc["keyId"], ts["acceptanceKeyId"])
    cmp_field(sig_rows, "signature.acceptanceSignatureValid", ed_ok, ts["acceptanceSignatureValid"])
    cmp_field(sig_rows, "signature.authorizationValidAtNotBefore", win_ok, ts["authorizationValidAtNotBefore"])
    sig_nc = [{"field": "signature.authorizationCode", "published": ts["authorizationCode"],
               "reason": "code vocabulary not published; we report the individual checks of A11 instead"}]

    summ_rows = []
    cmp_field(summ_rows, "summary.cases", len(cases_out), theirs["summary"]["cases"])
    cmp_field(summ_rows, "summary.envelopeBindingCases",
              sum(1 for c in cases_out if c["derived"]["className"] == "envelope-binding"), theirs["summary"]["envelopeBindingCases"])
    cmp_field(summ_rows, "summary.evidenceAvailabilityCases",
              sum(1 for c in cases_out if c["derived"]["className"] == "evidence-availability"), theirs["summary"]["evidenceAvailabilityCases"])

    all_claims = matrix_claims + ac + [c for k in cases_out for c in k["claims"]]
    counts = {s: sum(1 for c in all_claims if c["status"] == s) for s in (ESTABLISHED, CONTRADICTED, NOT_ESTABLISHED)}
    comp_rows = sig_rows + field_rows_all + summ_rows
    n_eq = sum(1 for r in comp_rows if r["equal"])
    n_ne = sum(1 for r in comp_rows if not r["equal"])
    n_nc = len(sig_nc) + sum(len(k["notComparable"]) for k in cases_out)
    contradictions_excl_docs = [c["id"] for c in all_claims if c["status"] == CONTRADICTED and not c["id"].startswith("M6")]
    result = "AGREES" if (not contradictions_excl_docs and n_ne == 0) else "DISAGREES"

    report = {
        "schema": "hs-nenrin.priorseal-reader.report.v0",
        "reader": READER_ID,
        "independence": {
            "statement": "Implemented from the published contract, fixture and docs only. No PriorSeal verifier, reader, runner, generator or SDK source was opened, imported or copied; the producer files listed as hashed-only were digested as bytes for the manifest check.",
            "openedByThisProgram": [MATRIX + "/" + r for r in OPENED],
            "hashedOnlyByThisProgram": [MATRIX + "/" + r for r in HASHED_ONLY],
        },
        "pins": {
            "repository": REPO, "commit": head, "expectedCommit": PINNED_COMMIT,
            "contractVersion": CONTRACT_VERSION, "profile": PROFILE,
            "coldRunTemplateCommit": TEMPLATE_COMMIT,
            "files": files, "tools": tool_versions(),
            "self": {
                "reader.py": sha256_file(os.path.abspath(__file__)),
                "requirements.txt": (sha256_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt"))
                                     if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")) else None),
            },
        },
        "matrixClaims": matrix_claims,
        "authorizationClaims": ac,
        "cases": cases_out,
        "comparison": {"signature": sig_rows, "signatureNotComparable": sig_nc, "summary": summ_rows},
        "summary": {
            "claims": counts,
            "fields": {"equal": n_eq, "different": n_ne, "notComparable": n_nc},
            "contradictionsExcludingDocConsistency": contradictions_excl_docs,
            "documentationFindings": [c["id"] for c in all_claims if c["status"] == CONTRADICTED and c["id"].startswith("M6")],
            "result": result,
        },
        "limits": [
            "Synthetic, offline fixtures: no chain observation, no RPC, no real execution or finality.",
            "Answer-exposed: expected.json and report.json were read before and while writing this reader.",
            "Compliance and outcome rules are inferred from lifecycle.md prose; the contract publishes them only per case.",
            "Hash identities (intentHash, authorizationId, authorizationHash, entryHash) use rules from a doc written for a different fixture.",
            "Not adoption, endorsement, integration or pilot by any party. Written by a different project (HORIZON SHIELD / NENRIN).",
        ],
    }
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    sys.stdout.write(json.dumps({"result": result, "claims": counts, "fields": report["summary"]["fields"],
                                 "contradictionsExcludingDocConsistency": contradictions_excl_docs,
                                 "documentationFindings": report["summary"]["documentationFindings"]}) + "\n")
    return 0 if result == "AGREES" else 1


if __name__ == "__main__":
    sys.exit(main())
