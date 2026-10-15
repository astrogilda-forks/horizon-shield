#!/usr/bin/env python3
"""idp-bind-v0 in Python: the port of idp_bind.mjs (SPEC.md is the normative text), held to the same verdict signatures
on the frozen fixtures and on mutations (parity.py). Needs the sdk-python checkout next to this directory for the
canonical form, did:key and the strict timestamp, and `cryptography` for RSA, P-256 and Ed25519.

    python3 -I idp_bind.py <input.json>        prints the report, exit 0 on accepted, 1 otherwise
    python3 -I idp_bind.py --fixtures          the frozen fixtures against expected.json
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "sdk-python", "src")))
from nenrin_verify._js import canonical, CanonicalError  # noqa: E402
from nenrin_verify.provenance import sig_bytes, is_rfc3339_utc, public_key_from_did_key, date_parse  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

IDP_BIND_VERSION = "0.1.0"
SCHEMA = "idp-bind-v0/binding"
DERIVED = ("binding_id", "actor_sig")
ALGS = {"RS256": ("rsa", None), "ES256": ("ec", "P-256")}
B64U = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def binding_preimage(b):
    return {k: v for k, v in b.items() if k not in DERIVED}


def binding_id(b):
    return sha256hex(canonical(binding_preimage(b)))


def parse_jwt(token):
    """idp_bind.mjs parseJwt: three non-empty base64url segments, JSON object header and payload, a signature
    segment that round-trips; else None."""
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3 or not all(p and set(p) <= B64U for p in parts):
        return None
    try:
        header = json.loads(b64u_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64u_decode(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    sig = b64u_decode(parts[2])
    if b64u_encode(sig) != parts[2]:
        return None
    return {"header": header, "payload": payload, "signing_input": parts[0] + "." + parts[1], "signature": sig}


def _uint(b64u):
    return int.from_bytes(b64u_decode(b64u), "big")


def jwk_from_jwks(document, kid, alg):
    """idp_bind.mjs jwkFromJwks: (key, None) or (None, reason)."""
    try:
        doc = json.loads(document)
    except ValueError:
        return None, "jwks_not_json"
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        return None, "jwks_without_keys"
    matches = [k for k in doc["keys"] if isinstance(k, dict) and k.get("kid") == kid]
    if len(matches) != 1:
        return None, ("kid_ambiguous" if matches else "key_not_in_jwks")
    jwk = matches[0]
    if jwk.get("use") is not None and jwk.get("use") != "sig":
        return None, "key_not_for_signing"
    if jwk.get("alg") is not None and jwk.get("alg") != alg:
        return None, "key_alg_mismatch"
    want = ALGS.get(alg)
    if not want:
        return None, "alg_unsupported"
    if want[0] == "rsa" and jwk.get("kty") != "RSA":
        return None, "key_type_mismatch"
    if want[0] == "ec" and (jwk.get("kty") != "EC" or jwk.get("crv") != want[1]):
        return None, "key_type_mismatch"
    try:
        if want[0] == "rsa":
            return rsa.RSAPublicNumbers(_uint(jwk["e"]), _uint(jwk["n"])).public_key(), None
        return ec.EllipticCurvePublicNumbers(_uint(jwk["x"]), _uint(jwk["y"]), ec.SECP256R1()).public_key(), None
    except Exception:
        return None, "key_unusable"


def verify_jwt_signature(parsed, key, alg):
    want = ALGS.get(alg)
    if not want:
        return False
    data = parsed["signing_input"].encode("ascii")
    try:
        if want[0] == "rsa":
            key.verify(parsed["signature"], data, padding.PKCS1v15(), hashes.SHA256())
            return True
        sig = parsed["signature"]
        if len(sig) != 64:
            return False
        der = asym_utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _aud_matches(aud, want):
    return want in aud if isinstance(aud, list) else aud == want


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def verify(inp):
    refusals, findings, establishes, does_not = [], [], [], []

    def refuse(code, why):
        refusals.append({"code": code, "why": why})

    def find(code, why):
        findings.append({"code": code, "why": why})

    b = inp.get("binding") if isinstance(inp, dict) else None
    if not isinstance(b, dict):
        refuse("binding_not_object", "input.binding is not an object")
        return _report(refusals, findings, establishes, does_not, None)
    if b.get("schema") != SCHEMA:
        refuse("bad_schema", "schema must be " + SCHEMA)
    idp = b.get("idp")
    idp_ok = isinstance(idp, dict) and all(isinstance(idp.get(k), str) and idp.get(k) for k in ("issuer", "subject", "audience", "kid", "alg"))
    if not idp_ok:
        refuse("bad_idp", "idp must carry issuer, subject, audience, kid and alg as non-empty strings")
    if not isinstance(b.get("nonce"), str) or not b.get("nonce"):
        refuse("bad_nonce", "nonce must be a non-empty string")
    if not is_rfc3339_utc(b.get("bound_at")):
        refuse("bad_bound_at", "bound_at must be a strict RFC3339 UTC instant")

    # 1. the binding is what its id says, and the actor signed it
    bid = None
    try:
        bid = binding_id(b)
    except CanonicalError as e:
        refuse("canonical_refused", str(e))
    if bid is not None:
        if b.get("binding_id") != bid:
            refuse("binding_recompute_mismatch", "binding_id is not sha256 of the canonical preimage")
        pub = None
        try:
            pub = public_key_from_did_key(b.get("actor_id"))
        except Exception:
            refuse("actor_id_unresolvable", "actor_id is not a usable Ed25519 did:key")
        sig = sig_bytes(b.get("actor_sig"))
        if pub is not None and sig is None:
            refuse("actor_sig_malformed", "actor_sig is not canonical base64 of 64 bytes")
        if pub is not None and sig is not None:
            ok = False
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(sig, canonical(binding_preimage(b)).encode("utf-8"))
                ok = True
            except Exception:
                ok = False
            if not ok:
                refuse("actor_sig_invalid", "actor_sig does not verify under actor_id over the canonical preimage")
            else:
                establishes.append("the holder of the private key of %s signed this binding (possession of the NENRIN actor key)" % b["actor_id"])

    # 2. the token is the one the binding names, and it is a well formed JWT
    if not isinstance(b.get("token"), str) or sha256hex(b["token"]) != b.get("token_sha256"):
        refuse("token_digest_mismatch", "token_sha256 is not sha256 of token")
    jwt = parse_jwt(b.get("token"))
    if jwt is None:
        refuse("token_malformed", "token is not a compact JWS with three base64url segments and JSON header and payload")
    claims_ok = False
    if jwt is not None and idp_ok:
        h, p = jwt["header"], jwt["payload"]
        before = len(refusals)
        if h.get("alg") != idp["alg"] or h.get("kid") != idp["kid"]:
            refuse("header_mismatch", "token header alg/kid differ from idp.alg/idp.kid")
        if idp["alg"] not in ALGS:
            refuse("alg_unsupported", "idp.alg must be RS256 or ES256")
        if p.get("iss") != idp["issuer"]:
            refuse("issuer_mismatch", "token iss differs from idp.issuer")
        if p.get("sub") != idp["subject"]:
            refuse("subject_mismatch", "token sub differs from idp.subject")
        if not _aud_matches(p.get("aud"), idp["audience"]):
            refuse("audience_mismatch", "token aud does not contain idp.audience")
        if not _is_int(p.get("exp")):
            refuse("token_without_exp", "token has no integer exp")
        if p.get("nbf") is not None and not _is_int(p.get("nbf")):
            refuse("bad_nbf", "token nbf is not an integer")
        if is_rfc3339_utc(b.get("bound_at")) and _is_int(p.get("exp")) and (p.get("nbf") is None or _is_int(p.get("nbf"))):
            t = date_parse(b["bound_at"]) // 1000
            nbf = p.get("nbf") if p.get("nbf") is not None else (p.get("iat") if _is_int(p.get("iat")) else None)
            if t > p["exp"] or (nbf is not None and t < nbf):
                refuse("outside_token_window", "bound_at is not inside the token's [nbf (or iat), exp]")
        claims_ok = len(refusals) == before
        if p.get("cnf") is not None:
            cnf = p["cnf"] if isinstance(p["cnf"], dict) else {}
            aid = b.get("actor_id")
            if isinstance(aid, str) and (cnf.get("kid") == aid or cnf.get("did") == aid):
                find("cnf_bound", "the issuer bound this token to the actor key (RFC 7800 cnf), so the identity side is possession-proven")
            else:
                refuse("cnf_mismatch", "token cnf names a key other than actor_id")
        else:
            find("bearer_only", "the token carries no cnf: it binds whoever held it while it was live, within its audience and lifetime")

    # 3. the issuer signed the token, under a key in the pinned JWKS
    jwks = inp.get("jwks")
    jwks_ok = isinstance(jwks, dict) and isinstance(jwks.get("document"), str) and isinstance(jwks.get("sha256"), str)
    if not jwks_ok:
        refuse("jwks_missing", "input.jwks must carry the issuer's JWKS document and its pinned sha256")
    elif sha256hex(jwks["document"]) != jwks["sha256"]:
        refuse("jwks_digest_mismatch", "the JWKS document is not the pinned bytes")
    elif jwt is not None and idp_ok:
        key, reason = jwk_from_jwks(jwks["document"], idp["kid"], idp["alg"])
        if key is None:
            refuse(reason, "no usable signing key for kid %s in the pinned JWKS (%s)" % (idp["kid"], reason))
        elif not verify_jwt_signature(jwt, key, idp["alg"]):
            refuse("idp_signature_invalid", "the token signature does not verify under the pinned JWKS key")
        elif claims_ok:
            establishes.append("the issuer %s signed a token for subject %s (audience %s) that was live at %s, under a key in the JWKS pinned at %s"
                               % (idp["issuer"], idp["subject"], idp["audience"], b.get("bound_at"), jwks["sha256"][:16]))

    does_not.append("that the subject performed any action: this binds a key to an identity, nothing more")
    does_not.append("that the identity provider's statement about the subject is true; only that it made it")
    if not any(f["code"] == "cnf_bound" for f in findings):
        does_not.append("possession of the provider identity beyond holding a live bearer token at bound_at")
    return _report(refusals, findings, establishes, does_not, bid)


def _report(refusals, findings, establishes, does_not, bid):
    return {"schema": "idp-bind-v0/report", "version": IDP_BIND_VERSION, "verdict": "refused" if refusals else "accepted",
            "binding_id": bid, "refusals": refusals, "findings": findings, "establishes": establishes,
            "does_not_establish": does_not}


def signature(report):
    return {"verdict": report["verdict"], "refusals": sorted({r["code"] for r in report["refusals"]}),
            "findings": sorted({f["code"] for f in report["findings"]})}


def _fixtures():
    exp = json.load(open(os.path.join(HERE, "expected.json"), encoding="utf-8"))
    bad = 0
    for name, c in exp["cases"].items():
        inp = json.load(open(os.path.join(HERE, "fixtures", name + ".json"), encoding="utf-8"))
        got = signature(verify(inp))
        ok = got == c["expect"]
        bad += 0 if ok else 1
        print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "  got " + json.dumps(got)))
    n = len(exp["cases"])
    print("\n" + ("%d FAILED" % bad if bad else "ALL PASS (idp-bind-v0 Python: %d/%d verdict signatures)" % (n, n)))
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--fixtures":
        sys.exit(_fixtures())
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    rep = verify(json.load(open(sys.argv[1], encoding="utf-8")))
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    sys.exit(0 if rep["verdict"] == "accepted" else 1)
