"""0.4.2: tsugi.verify_signature reads the key and the signature as canonical standard base64 only, like
tsugi_verify.mjs 0.3.1 (b64Exact). The operator's real signed authorization of the 2026-09-20 incident verifies as
written; every lenient spelling of the same bytes is refused with the JavaScript's text."""
import json
import os

from nenrin_verify import tsugi

REC = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "recovery-v0"))
KEY_WHY = "public_key_ed25519_b64 must be a 32-byte Ed25519 key in canonical standard base64"
SIG_WHY = "signature_ed25519_b64 must be a 64-byte Ed25519 signature in canonical standard base64"


def _signed():
    with open(os.path.join(REC, "incident_20260920_resign_chain.json"), encoding="utf-8") as f:
        inc = json.load(f)
    recs = inc if isinstance(inc, list) else inc["records"]
    return next(r for r in recs if r.get("signature_ed25519_b64") and r.get("public_key_ed25519_b64"))


def _variants(s):
    out = [s.rstrip("="), s[:10] + " " + s[10:], s + "\n", s + "!!"]
    if "+" in s or "/" in s:
        out.append(s.replace("+", "-").replace("/", "_"))
    return out


def test_the_real_signature_verifies():
    assert tsugi.verify_signature(_signed()) == {"ok": True}
    assert tsugi.VERIFIER_VERSION == "0.4.0"


def test_lenient_spellings_are_refused():
    r = _signed()
    for v in _variants(r["signature_ed25519_b64"]):
        assert tsugi.verify_signature(dict(r, signature_ed25519_b64=v)) == {"ok": False, "why": SIG_WHY}, v
    for v in _variants(r["public_key_ed25519_b64"]):
        assert tsugi.verify_signature(dict(r, public_key_ed25519_b64=v)) == {"ok": False, "why": KEY_WHY}, v
    assert tsugi.b64_exact(r["public_key_ed25519_b64"], 32) and tsugi.b64_exact(r["signature_ed25519_b64"], 64)


SMALL_ORDER = ["AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=",
               "7v///////////////////////////////////////38=", "7P///////////////////////////////////////38=",
               "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
FORGED_SIG = "AQ" + "A" * 84 + "=="   # R = the identity point, S = 0: valid under a small-order key for every message


def test_small_order_keys_are_refused():
    r = _signed()
    why = "public_key_ed25519_b64 is not a usable Ed25519 key (it must be the canonical encoding of a point in the prime-order subgroup)"
    for k in SMALL_ORDER:
        assert tsugi.verify_signature(dict(r, public_key_ed25519_b64=k, signature_ed25519_b64=FORGED_SIG)) == {"ok": False, "why": why}, k


def test_did_key_of_a_small_order_point_does_not_resolve():
    import base64
    from nenrin_verify import provenance as P
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def did(raw):
        b = bytes([0xED, 0x01]) + raw
        n, s = int.from_bytes(b, "big"), ""
        while n:
            n, m = divmod(n, 58)
            s = alphabet[m] + s
        return "did:key:z" + s
    for k in SMALL_ORDER:
        assert P.did_key_resolver(did(base64.b64decode(k))) is None, k


def test_mixed_order_key_is_refused():
    """A real key plus the order-2 point (0, -1) is (-x, -y): signable with the real key's private key, yet a
    different string. Refused, as tsugi_verify.mjs 0.3.1 refuses it: a key must lie in the prime-order subgroup."""
    import base64
    from nenrin_verify.provenance import ed25519_key_ok
    r = _signed()
    raw = base64.b64decode(r["public_key_ed25519_b64"])
    p = 2 ** 255 - 19
    y = int.from_bytes(raw[:31] + bytes([raw[31] & 0x7F]), "little")
    mixed = bytearray(((p - y) % p).to_bytes(32, "little"))
    mixed[31] |= (raw[31] & 0x80) ^ 0x80
    assert ed25519_key_ok(raw) and not ed25519_key_ok(bytes(mixed))
    why = "public_key_ed25519_b64 is not a usable Ed25519 key (it must be the canonical encoding of a point in the prime-order subgroup)"
    assert tsugi.verify_signature(dict(r, public_key_ed25519_b64=base64.b64encode(bytes(mixed)).decode())) == {"ok": False, "why": why}
