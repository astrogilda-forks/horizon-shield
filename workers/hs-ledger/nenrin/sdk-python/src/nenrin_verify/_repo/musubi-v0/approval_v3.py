#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
a2a-approval-v3: a pinned approver's approval that names the most it covers (APPROVAL_V3.md).

Why this file exists. An a2a-approval-v2 approval (babyblueviper1's format, settle v1.10) carries no amount in its
signed bytes, so one approval covers any amount the grant allows. grant.limits (settle v1.12) caps an action but cannot
say "this approval is for 150,000 and no more". v3 puts max_amount and unit into the signed bytes. Agreed on #29
(2026-10-10): v2 stays frozen as babyblueviper1's reference, v3 lives here next to settle and grant.limits, with a
domain tag of its own (so a v2 signature never verifies as v3, nor a v3 signature as v2) and max_amount as an integer
string in the unit's smallest denomination, so no float is ever in the signed bytes.

The approval is an approvals[] entry with exactly these keys:

    {"approval": "a2a-approval-v3", "action", "by": "approver", "approver", "max_amount", "unit",
     "valid_until_height", "nonce", "single_use", "sig_b64"}

signed with Ed25519 by the key the grant pins for that approver, over

    b"a2a-approval-v3\\n" + canonical({"contract_sha256", "action", "approver_key", "max_amount", "unit",
                                      "valid_until_height", "nonce", "single_use"})

contract_sha256 is recomputed from the contract the reader holds. canonical is musubi-canonical-v0 (contract_v0).

verify_approval_v3(contract, e) -> ("approved", None) | ("approval_unverified", reason), checked in this order:

    not_a_v3_approval                   e is not an object, "approval" is not "a2a-approval-v3", or "by" is not "approver"
    malformed                           a key missing or extra; action not a non empty string; max_amount not
                                        ^(0|[1-9][0-9]{0,17})\\Z; unit not 1 to 64 printable ASCII characters;
                                        valid_until_height not an integer from 0 to 2**53 - 1; nonce not ^[0-9a-f]{32}\\Z; single_use not
                                        a boolean; approver or sig_b64 not a string
    approver_not_pinned                 no grant.approval_policy.approvers entry has this name
    action_not_permitted_for_approver   the pinned approver does not list the action
    malformed_key_or_signature          the pinned key or sig_b64 is not canonical base64 of 32 or 64 bytes
    bad_signature                       the signature does not verify over the v3 bytes
    action_has_no_limit                 grant.limits sets no limit for the action, so there is no unit to read the
                                        amount in
    unit_differs_from_limit             unit is not grant.limits[action].unit

Every pattern is anchored with \\Z, not $: in Python $ also matches before one final newline, in JavaScript it does
not, and a reading the two runtimes disagree on is not a reading (approval_v3.mjs is the twin; both are held to
fixtures/approval_v3/vectors.json).

verify_approver_any(contract, e) is the approver rule settle v1.13 applies: a v3 entry is read by verify_approval_v3,
anything else by the v2 rule with the nonce read as babyblueviper1's reference reads it since bcf6592 (\\Z).

covers(e, amount) says whether a verified v3 approval covers an amount stated in the limit's unit.

What this file does not do: it does not say when an approval is used (ordering, expiry against the action's anchor,
single use); that is settle's walk. A stolen approver key signs a valid approval, and the signature proves the
approver signed, not that it judged well.
"""
import base64, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from contract_v0 import canonical, ed25519_verify, contract_sha256, b64_raw
import clause_eval_v0 as ce

APPROVAL = "a2a-approval-v3"
CONTEXT = b"a2a-approval-v3\n"
V2_CONTEXT = b"a2a-approval-v2\n"
ENTRY_KEYS = frozenset(("approval", "action", "by", "approver", "max_amount", "unit", "valid_until_height", "nonce",
                        "single_use", "sig_b64"))
HEX32 = re.compile(r"^[0-9a-f]{32}\Z")
AMOUNT = re.compile(r"^(0|[1-9][0-9]{0,17})\Z")
UNIT = re.compile(r"^[\x21-\x7e]{1,64}\Z")
SAFE = 2 ** 53 - 1      # the largest integer musubi-canonical-v0 writes in both runtimes
REASONS = ("not_a_v3_approval", "malformed", "approver_not_pinned", "action_not_permitted_for_approver",
           "malformed_key_or_signature", "bad_signature", "action_has_no_limit", "unit_differs_from_limit")
V2_REASONS = ce.REASONS
FIXTURE = os.path.join(HERE, "fixtures", "approval_v3", "vectors.json")
# clause_eval_v0's v2 rule as published, held here so that a settle layer which points clause_eval_v0's name at
# verify_approver_any for the length of one call (settle v1.13) does not make the v2 rule call itself.
_V2_RULE = ce.verify_approver_approval


def verifier_sha256():
    with open(os.path.abspath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def is_v3(e):
    return isinstance(e, dict) and e.get("approval") == APPROVAL


def approval_v3_bytes(contract, e, approver_key_b64):
    return CONTEXT + canonical({
        "contract_sha256": contract_sha256(contract), "action": e.get("action"), "approver_key": approver_key_b64,
        "max_amount": e.get("max_amount"), "unit": e.get("unit"), "valid_until_height": e.get("valid_until_height"),
        "nonce": e.get("nonce"), "single_use": e.get("single_use")}).encode("utf-8")


def sign_approval_v3(key, contract, action, max_amount, unit, valid_until_height, nonce, approver_name, approver_key_b64,
                     single_use=True):
    """key is an Ed25519PrivateKey. max_amount is written as the integer string the signed bytes carry."""
    e = {"approval": APPROVAL, "action": action, "by": "approver", "approver": approver_name,
         "max_amount": max_amount if isinstance(max_amount, str) else str(max_amount), "unit": unit,
         "valid_until_height": valid_until_height, "nonce": nonce, "single_use": single_use}
    e["sig_b64"] = base64.b64encode(key.sign(approval_v3_bytes(contract, e, approver_key_b64))).decode("ascii")
    return e


def _shape_ok(e):
    return (set(e) == ENTRY_KEYS
            and isinstance(e["action"], str) and e["action"] != ""
            and isinstance(e["approver"], str)
            and isinstance(e["max_amount"], str) and AMOUNT.match(e["max_amount"]) is not None
            and isinstance(e["unit"], str) and UNIT.match(e["unit"]) is not None
            and _int(e["valid_until_height"]) and 0 <= e["valid_until_height"] <= SAFE
            and isinstance(e["nonce"], str) and HEX32.match(e["nonce"]) is not None
            and isinstance(e["single_use"], bool)
            and isinstance(e["sig_b64"], str))


def verify_approval_v3(contract, e):
    if not is_v3(e) or e.get("by") != "approver":
        return "approval_unverified", "not_a_v3_approval"
    if not _shape_ok(e):
        return "approval_unverified", "malformed"
    pin = next((a for a in ce.approvers(contract) if a.get("name") == e["approver"]), None)
    if pin is None:
        return "approval_unverified", "approver_not_pinned"
    if e["action"] not in (pin.get("actions") or []):
        return "approval_unverified", "action_not_permitted_for_approver"
    if b64_raw(pin.get("public_key_ed25519_b64"), 32) is None or b64_raw(e["sig_b64"], 64) is None:
        return "approval_unverified", "malformed_key_or_signature"
    if ed25519_verify(pin["public_key_ed25519_b64"], e["sig_b64"], approval_v3_bytes(contract, e, pin["public_key_ed25519_b64"])) is not True:
        return "approval_unverified", "bad_signature"
    lim = ce.limit_for(contract, e["action"])
    if lim is None:
        return "approval_unverified", "action_has_no_limit"
    if lim[1] != e["unit"]:
        return "approval_unverified", "unit_differs_from_limit"
    return "approved", None


def verify_approval_v2_strict(contract, e):
    """The pinned approver rule of settle v1.10 (clause_eval_v0.verify_approver_approval), with the nonce read by \\Z,
    as babyblueviper1's reference reads it since bcf6592 (sha256 72f807a4...)."""
    if not isinstance(e, dict) or e.get("by") != "approver":
        return "approval_unverified", "not_an_approver_approval"
    vu, nonce, su = e.get("valid_until_height"), e.get("nonce"), e.get("single_use")
    if not (isinstance(e.get("action"), str) and _int(vu) and vu >= 0 and isinstance(nonce, str) and HEX32.match(nonce)
            and isinstance(su, bool)):
        return "approval_unverified", "malformed"
    return _V2_RULE(contract, e)


def verify_approver_any(contract, e):
    """settle v1.13's approver rule: v3 entries by verify_approval_v3, everything else by the v2 rule read with \\Z."""
    return verify_approval_v3(contract, e) if is_v3(e) else verify_approval_v2_strict(contract, e)


def covers(e, amount):
    """True when a verified v3 approval covers amount (an integer from 0 to 2**53 - 1 in the limit's unit)."""
    return is_v3(e) and _int(amount) and 0 <= amount <= SAFE and isinstance(e.get("max_amount"), str) \
        and AMOUNT.match(e["max_amount"]) is not None and int(e["max_amount"]) >= amount


# --------------------------------------------------------------------------- fixtures
def _key(label):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("musubi-approval-v3-fixture:" + label).encode("utf-8")).digest())
    return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")


def fixture_contract():
    """A contract the door accepts: pay capped at 100,000 JPY, pay_large conditional on approver.example and capped at
    1,000,000 JPY, emit_witness conditional on the same approver with no limit, admission required (limits need it)."""
    import contract_v0 as v0
    ka, pa = _key("principal"); kb, pb = _key("contractor"); _kw, pw = _key("witness"); _kz, pz = _key("approver")
    grant = {"authorized_actions": ["read", "emit_witness", "pay"], "prohibited_actions": ["delete"],
             "conditional": [{"action": "emit_witness", "requires": "approver"}, {"action": "pay_large", "requires": "approver"}],
             "delegation": {"allowed": []}, "revocation": {"effective_at": "anchor"},
             "finality": {"depth": 3, "max_target_bits": "207fffff"},
             "witnesses": [{"name": "nenrin-walker", "public_key_ed25519_b64": pw}],
             "approval_policy": {"allow_unscoped": False, "approvers": [
                 {"name": "approver.example", "public_key_ed25519_b64": pz, "actions": ["emit_witness", "pay_large"]}]},
             "limits": {"pay": {"max_amount": 100000, "unit": "JPY"}, "pay_large": {"max_amount": 1000000, "unit": "JPY"}}}
    dne = ["that HS enforced any of this at runtime",
           "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
           "that HS judges liability or fault; the verdict is a function anyone recomputes",
           "that a prohibited action was impossible, only that performing one is a provable deviation",
           "that this is a legal contract or determines legal responsibility"]
    c = v0.build_contract(
        {"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
        {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
        {"purpose": "approval_v3_vectors", "payload_digest": "a" * 64, "a2a_task_id": "t-v3"}, grant,
        ["that both parties signed these grant bytes at the stated time"], dne,
        requirements={"evidence": "nenrin_required", "recovery": "tsugi_required", "admission": "required_before_execution"},
        bond={"amount": 1000, "currency": "JPY"}, lower_bound={"kind": "bitcoin_block", "height": 97, "hash": "00" * 32},
        contract_id="0123456789abcdef0123456789abcd03", nonce="3" * 32, agreed_at="2026-10-10T00:00:00Z")
    v0.sign_contract(c, ka, pa, "a.example"); v0.sign_contract(c, kb, pb, "b.example")
    return c


def build_vectors():
    import settle_v1_6 as v16
    C = fixture_contract()
    kz, pz = _key("approver"); ks, ps = _key("stranger"); ka, _pa = _key("principal")
    N = "ab" * 16
    good = lambda **k: sign_approval_v3(kz, C, k.pop("action", "pay_large"), k.pop("max_amount", "150000"), k.pop("unit", "JPY"),
                                        k.pop("vu", 500), k.pop("nonce", N), k.pop("name", "approver.example"), k.pop("pin", pz), **k)
    edit = lambda e, **k: dict(e, **k)
    drop = lambda e, key: {x: y for x, y in e.items() if x != key}
    v2 = ce.sign_approver_approval(kz, C, "pay_large", 500, N, "approver.example", pz)
    v2_nl = ce.sign_approver_approval(kz, C, "pay_large", 500, N + "\n", "approver.example", pz)
    as_v3 = dict(v2, approval=APPROVAL, max_amount="150000", unit="JPY")          # a v2 signature presented as v3
    g = good()
    v3_as_v2 = {k: v for k, v in g.items() if k not in ("approval", "max_amount", "unit")}   # a v3 signature presented as v2
    vec = [
        ("v3/approved", g, "approved", None),
        ("v3/approved_zero", good(max_amount="0", nonce="cd" * 16), "approved", None),
        ("v3/approved_reusable", good(single_use=False, nonce="ce" * 16), "approved", None),
        ("v3/approved_18_digits", good(max_amount="9" * 18, nonce="cf" * 16), "approved", None),
        ("v3/not_v3_marker_missing", drop(g, "approval"), "approval_unverified", "not_a_v3_approval"),
        ("v3/not_v3_other_marker", edit(g, approval="a2a-approval-v2"), "approval_unverified", "not_a_v3_approval"),
        ("v3/not_v3_by_principal", edit(g, by="principal"), "approval_unverified", "not_a_v3_approval"),
        ("v3/malformed_amount_number", edit(g, max_amount=150000), "approval_unverified", "malformed"),
        ("v3/malformed_amount_float_string", edit(g, max_amount="150000.0"), "approval_unverified", "malformed"),
        ("v3/malformed_amount_leading_zero", edit(g, max_amount="0150000"), "approval_unverified", "malformed"),
        ("v3/malformed_amount_negative", edit(g, max_amount="-1"), "approval_unverified", "malformed"),
        ("v3/malformed_amount_exponent", edit(g, max_amount="1e5"), "approval_unverified", "malformed"),
        ("v3/malformed_amount_19_digits", edit(g, max_amount="1" + "0" * 18), "approval_unverified", "malformed"),
        ("v3/malformed_amount_trailing_newline", edit(g, max_amount="150000\n"), "approval_unverified", "malformed"),
        ("v3/malformed_amount_empty", edit(g, max_amount=""), "approval_unverified", "malformed"),
        ("v3/malformed_unit_empty", edit(g, unit=""), "approval_unverified", "malformed"),
        ("v3/malformed_unit_space", edit(g, unit="J PY"), "approval_unverified", "malformed"),
        ("v3/malformed_nonce_trailing_newline", edit(g, nonce=N + "\n"), "approval_unverified", "malformed"),
        ("v3/malformed_nonce_upper", edit(g, nonce=N.upper()), "approval_unverified", "malformed"),
        ("v3/malformed_height_negative", edit(g, valid_until_height=-1), "approval_unverified", "malformed"),
        ("v3/malformed_height_bool", edit(g, valid_until_height=True), "approval_unverified", "malformed"),
        ("v3/malformed_height_above_2_53", edit(g, valid_until_height=2 ** 53), "approval_unverified", "malformed"),
        ("v3/malformed_single_use_missing", drop(g, "single_use"), "approval_unverified", "malformed"),
        ("v3/malformed_extra_key", edit(g, contract_sha256="0" * 64), "approval_unverified", "malformed"),
        ("v3/malformed_action_empty", edit(g, action=""), "approval_unverified", "malformed"),
        ("v3/approver_not_pinned", good(name="other.example", nonce="d0" * 16), "approval_unverified", "approver_not_pinned"),
        ("v3/action_not_permitted", good(action="pay", nonce="d1" * 16), "approval_unverified", "action_not_permitted_for_approver"),
        ("v3/signature_not_base64", edit(g, sig_b64="not base64"), "approval_unverified", "malformed_key_or_signature"),
        ("v3/stranger_key", sign_approval_v3(ks, C, "pay_large", "150000", "JPY", 500, "d2" * 16, "approver.example", pz),
         "approval_unverified", "bad_signature"),
        ("v3/amount_raised_after_signing", edit(g, max_amount="1500000"), "approval_unverified", "bad_signature"),
        ("v3/unit_changed_after_signing", edit(g, unit="USD"), "approval_unverified", "bad_signature"),
        ("v3/v2_signature_presented_as_v3", as_v3, "approval_unverified", "bad_signature"),
        ("v3/no_limit_for_action", good(action="emit_witness", nonce="d3" * 16), "approval_unverified", "action_has_no_limit"),
        ("v3/unit_differs_from_limit", good(unit="USD", nonce="d4" * 16), "approval_unverified", "unit_differs_from_limit"),
    ]
    v2vec = [
        # (id, entry, result under v1.13's v2 rule, reason; result under clause_eval_v0 / settle v1.10 to v1.12, reason)
        ("v2/approved", v2, "approved", None, "approved", None),
        ("v2/nonce_trailing_newline", v2_nl, "approval_unverified", "malformed", "approved", None),
        ("v2/v3_signature_presented_as_v2", v3_as_v2, "approval_unverified", "bad_signature", "approval_unverified", "bad_signature"),
        ("v2/principal_signature", v16.sign_approval_v2(ka, C, "pay_large", 500, N), "approval_unverified", "not_an_approver_approval",
         "approval_unverified", "not_an_approver_approval"),
    ]
    out = {"schema": "a2a-approval-v3-vectors", "note": "Keys are derived from public labels: seed = sha256('musubi-approval-v3-fixture:' + "
           "label) for label in principal, contractor, witness, approver, stranger. No key bytes are in this file. "
           "approval_v3.py --selftest regenerates it byte for byte; approval_v3.test.mjs reads it in JavaScript.",
           "contract": C, "contract_sha256": contract_sha256(C),
           "vectors": [{"id": i, "approval": e, "expect": {"result": r, "reason": w}} for i, e, r, w in vec],
           "v2_vectors": [{"id": i, "approval": e, "expect_v1_13": {"result": r, "reason": w}, "expect_v0": {"result": r0, "reason": w0}}
                          for i, e, r, w, r0, w0 in v2vec],
           "covers": [{"max_amount": m, "amount": a, "covers": c} for m, a, c in
                      (("150000", 150000, True), ("150000", 149999, True), ("150000", 150001, False), ("0", 0, True), ("0", 1, False),
                       ("999999999999999999", 9007199254740991, True), ("9007199254740990", 9007199254740991, False))]}
    return out


def vectors_bytes():
    return (json.dumps(build_vectors(), ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- self test
def _selftest():
    import subprocess
    import contract_v0 as v0
    n = 0
    raw = open(FIXTURE, "rb").read()
    assert raw == vectors_bytes(), "fixtures/approval_v3/vectors.json does not regenerate byte for byte: python3 approval_v3.py --write"
    F = json.loads(raw.decode("utf-8"))
    C = F["contract"]
    assert v0.verify_contract(C)["verdict"] == "accepted" and contract_sha256(C) == F["contract_sha256"]
    n += 1; print("[1] fixtures/approval_v3/vectors.json regenerates byte for byte; its contract passes the door")

    for v in F["vectors"]:
        assert list(verify_approval_v3(C, v["approval"])) == [v["expect"]["result"], v["expect"]["reason"]], v["id"]
        assert list(verify_approver_any(C, v["approval"])) == [v["expect"]["result"], v["expect"]["reason"]] or not is_v3(v["approval"]), v["id"]
    seen = {v["expect"]["reason"] for v in F["vectors"]}
    assert seen == set(REASONS) | {None}, seen
    n += 1; print("[2] %d v3 vectors give the expected result; every reason is reached" % len(F["vectors"]))

    for v in F["v2_vectors"]:
        assert list(verify_approver_any(C, v["approval"])) == [v["expect_v1_13"]["result"], v["expect_v1_13"]["reason"]], v["id"]
        assert list(ce.verify_approver_approval(C, v["approval"])) == [v["expect_v0"]["result"], v["expect_v0"]["reason"]], v["id"]
    n += 1; print("[3] %d v2 vectors: a nonce with a trailing newline is malformed here and approved by clause_eval_v0 ($); "
                  "a v3 signature never verifies as v2, nor a v2 signature as v3" % len(F["v2_vectors"]))

    for c in F["covers"]:
        assert covers(dict(F["vectors"][0]["approval"], max_amount=c["max_amount"]), c["amount"]) is c["covers"], c
    g = F["vectors"][0]["approval"]
    assert covers(g, True) is False and covers(g, -1) is False and covers(g, None) is False and covers(dict(g, approval="x"), 1) is False
    assert covers(dict(g, max_amount="9" * 18), 2 ** 53) is False
    n += 1; print("[4] covers: at max_amount is covered, one above is not; a missing, negative, boolean or non canonical (above 2**53 - 1) amount is not covered")

    # [5] mutants: each must change a result the vectors expect
    killed = 0
    g_ = globals()
    for name, fake in (("HEX32", re.compile(r"^[0-9a-f]{32}$")), ("AMOUNT", re.compile(r"^-?[0-9]+(\.[0-9]+)?$")),
                       ("CONTEXT", V2_CONTEXT)):
        saved = g_[name]
        g_[name] = fake
        try:
            bad = [v["id"] for v in F["vectors"] if list(verify_approval_v3(C, v["approval"])) != [v["expect"]["result"], v["expect"]["reason"]]]
        finally:
            g_[name] = saved
        killed += bool(bad)
    saved = ce.limit_for
    ce.limit_for = lambda c, a: (10 ** 9, "JPY")
    try:
        killed += any(list(verify_approval_v3(C, v["approval"])) != [v["expect"]["result"], v["expect"]["reason"]] for v in F["vectors"])
    finally:
        ce.limit_for = saved
    assert killed == 4, killed
    n += 1; print("[5] 4 mutants ($ for \\Z, a float-accepting amount, the v2 domain tag, every action limited): all 4 change an expected result")

    node = None
    for cand in ("node", "/usr/local/bin/node", "/usr/bin/node"):
        try:
            if subprocess.run([cand, "--version"], capture_output=True).returncode == 0:
                node = cand; break
        except OSError:
            pass
    if node:
        r = subprocess.run([node, os.path.join(HERE, "approval_v3.test.mjs")], capture_output=True, text=True)
        assert r.returncode == 0, (r.stdout[-600:], r.stderr[-600:])
        n += 1; print("[6] the JavaScript twin (approval_v3.mjs) gives the same result on every vector: %s" % r.stdout.strip().splitlines()[-1])
    else:
        print("[6] node not found: the JavaScript twin was not run here")

    print("\nSELF-TEST PASSED: a2a-approval-v3, %d checks (vectors regenerate; every reason reached; v2 and v3 never cross; covers; "
          "4 mutants; JavaScript twin)" % n)


def main():
    if "--selftest" in sys.argv:
        _selftest(); return 0
    if "--write" in sys.argv:
        os.makedirs(os.path.dirname(FIXTURE), exist_ok=True)
        open(FIXTURE, "wb").write(vectors_bytes())
        print("wrote", os.path.relpath(FIXTURE, HERE)); return 0
    print(APPROVAL, verifier_sha256())
    return 0


if __name__ == "__main__":
    sys.exit(main())
