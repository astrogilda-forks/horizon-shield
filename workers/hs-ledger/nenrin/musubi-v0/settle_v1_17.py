#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI settle v1.17: when the contract names the content check, the admission's content check is read against it
(a2a-settlement-v1.17). One rule, and nothing else.

Why this file exists. A relying party's door can read the content that comes with a request (FURUI) and refuse or
escalate on what it finds. An admission record of version 0.3 says which check the door says it read
(content.rules_sha256, a furui-rules-id-v0 digest) and whether the content was checked at all (content.checked).
A contract can name the check both parties expect (requirements.furui.rules_sha256). Until now nothing compared the
two, so a door could admit under another check, or with no check, and leave nothing for an audit to find.

When the rule applies. Only when contract.requirements.furui.rules_sha256 is 64 lowercase hex. For every other
contract this file returns settle v1.16's result unchanged, the same bytes, schema line included: the 128 settle core
v0 vectors, run0002, the second contract, the outside parties' contract and the admission fixtures settle exactly as
before.

The rule, for each action in each execution record v1.16 accepted, in (anchor height, record sha256) order, whose
admission_ref names an admission that verifies under the relying party's key in hand (the admissions v1.11 reads):

  content_rules_mismatch   the admission is version 0.3 and content.rules_sha256 is not the contract's
                           requirements.furui.rules_sha256: the door says it read another check than the one the
                           parties signed for.
  content_not_checked      the admission's decision is admit, and it is older than 0.3 (it carries no content check)
                           or content.checked is not true.

Each admission is read once. Precedence: where v1.11 already raised executed_after_refusal for the same action and
admission, neither clause is added (the act ran against the door's answer, which is the finding); otherwise the clause
stands beside any other, admitted_out_of_grant included. A mismatch is reported instead of content_not_checked.

Inputs: as v1.16 (admissions and relying_keys are the ones v1.11 reads). The rule reads digests and fields only. It
does not read the content, does not run a check, and does not recompute rules_sha256 from any file.

Stated limits: as v1.16, and: that the door ran the check its admission names, or that the same check would answer
the same way again, is not established. An admission's content block is the relying party's own statement, signed by
it. A contract that does not name the check is not read by this rule at all.

The shape of requirements.furui is checked here (requirements_furui_v0.problems), not by the core contract door: a
contract whose requirements.furui has another shape is not settled (contract_not_verified). Settle core v0 does not
read requirements.furui.
"""
import argparse, base64, copy, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import settle_v1 as v1
import settle_v1_5 as v15
import settle_v1_11 as v111
import settle_v1_14 as v114
import settle_v1_16 as v116
import admission_verify_v0 as A
import requirements_furui_v0 as RF
from contract_v0 import canonical, parse_strict, contract_sha256, EXEC_SCHEMA

SETTLE_SCHEMA = "a2a-settlement-v1.17"
CLAUSES = ("content_rules_mismatch", "content_not_checked")
CONTENT_VERSION = "0.3"
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
ESTABLISH = ("that each admission an accepted execution names was read against requirements.furui.rules_sha256 under the rule in "
             "a2a-settlement-v1.17: the content check it names, and whether it says the content was checked")
DOES_NOT = ["that any content check ran, or that it would answer the same way again; an admission's content block is the relying "
            "party's own signed statement, and only its digests and flags were compared"]


def named_rules(contract):
    """contract.requirements.furui.rules_sha256 when it is 64 lowercase hex, else None."""
    rq = contract.get("requirements") if isinstance(contract, dict) else None
    f = rq.get("furui") if isinstance(rq, dict) else None
    r = f.get("rules_sha256") if isinstance(f, dict) else None
    return r if isinstance(r, str) and HEX64.match(r) else None


def content_deviations(contract, events, accepted, admissions, relying_keys, refused_already):
    """The v1.17 rule. accepted: the record sha256 of the executions v1.16 accepted. refused_already: (record sha256,
    action, admission sha256) triples for which executed_after_refusal was raised. Returns (deviations, read)."""
    want = named_rules(contract)
    csha = contract_sha256(contract)
    index, _unverified = v111._admission_index(contract, v114.lowest_admission_copies(admissions), relying_keys)
    recs, seen = [], set()
    for ev in events if isinstance(events, list) else []:
        if not (isinstance(ev, dict) and ev.get("schema") == EXEC_SCHEMA):
            continue
        s = v116._sha(ev)
        if s is None or s not in accepted or s in seen or (ev.get("contract_ref") or {}).get("contract_sha256") != csha:
            continue
        seen.add(s)
        recs.append((accepted[s], s, ev))
    recs.sort(key=lambda t: (t[0], t[1]))
    devs, read, used = [], [], set()
    for h, s, ev in recs:
        refs = [r for r in ev.get("admission_ref") if isinstance(r, dict)] if isinstance(ev.get("admission_ref"), list) else []
        taken = set()
        for a in [x for x in (ev.get("performed_actions") or []) if isinstance(x, str)]:
            i = next((i for i, r in enumerate(refs) if i not in taken and r.get("action") == a), None)
            if i is None:
                continue
            taken.add(i)
            sha = refs[i].get("admission_sha256")
            if not isinstance(sha, str) or sha not in index or sha in used:
                continue
            used.add(sha)
            adm, _ah = index[sha]
            rules = adm.get("rules") if isinstance(adm.get("rules"), dict) else {}
            ver = rules.get("version")
            content = adm.get("content") if isinstance(adm.get("content"), dict) else None
            got = content.get("rules_sha256") if (ver == CONTENT_VERSION and content) else None
            checked = bool(content and content.get("checked") is True) if ver == CONTENT_VERSION else False
            read.append({"action": a, "admission_sha256": sha, "admission_version": ver, "decision": adm.get("decision"),
                         "rules_sha256": got, "checked": checked, "record_sha256": s})
            if (s, a, sha) in refused_already:
                continue
            d = lambda clause, why: {"clause": clause, "observed": a, "height": h, "record_sha256": s, "admission_sha256": sha, "why": why}
            dom = (adm.get("relying_party") or {}).get("domain") if isinstance(adm.get("relying_party"), dict) else None
            if ver == CONTENT_VERSION and got != want:
                devs.append(d("content_rules_mismatch", "relying party %s's admission names content check %s; the contract names %s"
                              % (dom, got if isinstance(got, str) else "none", want)))
            elif adm.get("decision") == "admit" and not checked:
                devs.append(d("content_not_checked", "relying party %s signed admit with %s" % (
                    dom, "no content check (admission version %s)" % (ver if ver is not None else "0") if ver != CONTENT_VERSION
                    else "content.checked false")))
    return devs, read


def settle_v1_17(contract, events, view, parent=None, **kw):
    if RF.problems(contract):                                        # the shape is checked here, not by the core contract door
        out = v116._no_settlement(contract, [{"reason": "contract_not_verified", "detail": "requirements.furui is not in the shape "
                                              "requirements_furui_v0 reads (bad_requirements_furui)"}])
        out["schema"] = SETTLE_SCHEMA
        return out
    s = v116.settle_v1_16(contract, events, view, parent=parent, **kw)
    if named_rules(contract) is None:
        return s
    out = dict(s)
    out["schema"], out["settled_under"] = SETTLE_SCHEMA, s.get("schema")
    devs, read = [], []
    if s.get("verdict") in ("within_grant", "deviation", "nothing_to_settle"):
        accepted = {x.get("sha256"): x.get("height") for x in (s.get("authoritative_event_set") or [])
                    if isinstance(x, dict) and x.get("kind") == "execution"}
        refused_already = {(d.get("record_sha256"), d.get("observed"), d.get("admission_sha256")) for d in (s.get("deviations") or [])
                           if isinstance(d, dict) and d.get("clause") == "executed_after_refusal"}
        devs, read = content_deviations(contract, events, accepted, kw.get("admissions"), kw.get("relying_keys"), refused_already)
    if devs:
        out["deviations"] = sorted(list(s.get("deviations") or []) + devs, key=canonical)
        out["verdict"] = "deviation"
        out["bond_outcome"] = v15._bond_outcome(contract, "deviation", out.get("status"))
    out["content_gate"] = {"rule": SETTLE_SCHEMA, "rules_sha256": named_rules(contract), "admissions_read": sorted(read, key=canonical),
                           "counts": {c: sum(1 for d in devs if d["clause"] == c) for c in CLAUSES}}
    out["establishes"] = list(s.get("establishes") or []) + [ESTABLISH]
    out["does_not_establish"] = list(s.get("does_not_establish") or []) + DOES_NOT
    return out


# --------------------------------------------------------------------------- a small world for the tests and vectors
def seedkey(name):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("settle v1.17 synthetic key: " + name).encode()).digest())
    return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


DOM_P, DOM_C, DOM_R = "principal.synthetic.invalid", "contractor.synthetic.invalid", "door.synthetic.invalid"
CONTENT_DNE_LINE = ("that any content check ran, or that the same check would answer the same way again; the record carries the digests of the "
                    "bytes the relying party says it checked and of the verdict it says it read, the identifier of the rule set, and the flags, "
                    "and nothing else about the content")


class World(object):
    """Synthetic parties, a regtest chain, a contract that requires admission, executions and admissions signed by keys
    made from fixed seeds. Deterministic: the same calls give the same bytes."""
    H0 = 900000

    def __init__(self, furui=None, label="settle v1.17 synthetic"):
        import contract_v0 as v0
        import settle_v1_1 as v11
        self.v11 = v11
        self.KP, self.PP = seedkey("principal"); self.KC, self.PC = seedkey("contractor"); self.KR, self.PR = seedkey("door")
        self.headers, self.hashes, self.prev = [], {}, "00" * 32
        self.block(); self.block()
        ck = self.H0 + 1
        rq = {"admission": v111.REQUIRED}
        if furui is not None:
            rq["furui"] = furui
        payload = "synthetic task for the settle v1.17 tests; no real party, key or endpoint is named"
        c = v0.build_contract(
            {"domain": DOM_P, "key_url": "https://%s/keys/agreement.json" % DOM_P, "public_key_ed25519_b64": self.PP},
            {"domain": DOM_C, "key_url": "https://%s/keys/agreement.json" % DOM_C, "public_key_ed25519_b64": self.PC},
            {"purpose": "price_list_questions", "payload_digest": hashlib.sha256(payload.encode()).hexdigest()},
            {"authorized_actions": ["read"], "prohibited_actions": ["delete"], "delegation": {"allowed": []},
             "finality": {"depth": 3, "max_target_bits": "207fffff"}, "revocation": {"effective_at": "anchor"}},
            ["that both parties signed these grant bytes"],
            ["that HS enforced any of this at runtime", "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
             "that HS judges liability or fault; the verdict is a function anyone recomputes", "that this is a legal contract or determines legal responsibility"],
            requirements=rq, bond={"amount": 1000, "currency": "JPY"},
            lower_bound={"kind": "bitcoin_block", "height": ck, "hash": self.hashes[ck]},
            contract_id=hashlib.sha256((label + " id").encode()).hexdigest()[:32], nonce=hashlib.sha256((label + " nonce").encode()).hexdigest()[:32],
            agreed_at="2026-10-27T00:00:00Z")
        v0.sign_contract(c, self.KP, self.PP, DOM_P); v0.sign_contract(c, self.KC, self.PC, DOM_C)
        assert v0.verify_contract(c)["verdict"] == "accepted", v0.verify_contract(c)
        self.contract = c
        self.keys = {DOM_R: self.PR}

    def block(self, leaves=()):
        v11 = self.v11
        if leaves:
            root, proofs = v11._tree(list(leaves))
        else:
            root, proofs = hashlib.sha256(("v1.17-%d" % (self.H0 + len(self.headers))).encode()).digest(), []
        h = self.H0 + len(self.headers)
        raw = v11._mine(self.prev, root, salt=h * 11)
        hh = v11.header_hash(raw)
        self.headers.append({"height": h, "hex": raw.hex()}); self.hashes[h] = hh; self.prev = hh
        return h, hh, proofs

    def tip(self):
        return self.H0 + len(self.headers) - 1

    def admission(self, action, nonce, decision="admit", reasons=("within_grant",), version="0.1", content=None, anchor=None):
        csha = contract_sha256(self.contract)
        req = {"action": {"action": action, "target": None, "amount": None}, "nonce": nonce, "expiry_height": 999999}
        rec = {"schema": A.SCHEMA, "admission_id": "adm-" + nonce[:8],
               "relying_party": {"domain": DOM_R, "key_url": "https://%s/keys/agreement.json" % DOM_R},
               "contract_ref": {"contract_id": self.contract["contract_id"], "contract_sha256": csha},
               "action_ref": {"action_binding_digest": A.action_digest(csha, req), "nonce": nonce}, "presentation_ref": [],
               "chain_view": {"height": self.tip(), "header_sha256": "ab" * 32}, "revocations_seen": [], "decision": decision,
               "reasons": list(reasons), "clause": "grant.authorized_actions[0]",
               "rules": {"admit": "a2a-admission-v0", "version": version, "evaluator_sha256": "fee48c3a66c28fe14ecbb8e2aea03a062fbe7be22810d3ca94332b36f660bed0"},
               "establishes": ["that the relying party named here ran admit() over this contract, this action digest and this chain view, and signed the result"]}
        if version == "0.1":
            rec["does_not_establish"] = list(A.DOES_NOT_ESTABLISH)
        else:
            rec["immune"] = {"rules": A.IMMUNE_RULES, "evaluator_sha256": "cd" * 32, "terms_sha256": None, "verdict": "not_run", "codes": [],
                             "evidence_sha256": "ef" * 32, "second_signal": None}
            rec["content"] = content
            rec["does_not_establish"] = list(getattr(A, "DOES_NOT_ESTABLISH_V03", A.DOES_NOT_ESTABLISH_V02 + [CONTENT_DNE_LINE]))
        rec["signatures"] = [{"domain": DOM_R, "alg": "ed25519", "sig": base64.b64encode(self.KR.sign(A.admission_signing_bytes(rec))).decode()}]
        with_anchor = dict(rec, anchor={"height": anchor if anchor is not None else self.tip()})
        return with_anchor, A.admission_sha256(rec)

    def execution(self, actions, refs):
        import settle_v1_2 as v12
        c = self.contract
        r = {"schema": EXEC_SCHEMA,
             "contract_ref": {"contract_id": c["contract_id"], "contract_sha256": contract_sha256(c), "payload_digest": c["task"]["payload_digest"]},
             "performed_actions": list(actions), "approvals": [], "delegated_to": [], "admission_ref": refs}
        v12.sign_record(r, self.KC, "contractor")
        h, hh, proofs = self.block([self.v11.commitment_digest(r)])
        r = copy.deepcopy(r); r["anchor"] = {"height": h, "block_hash": hh, "proof": proofs[0]}
        return r

    def view(self, pad=3):
        for _ in range(pad):
            self.block()
        return {"headers": list(self.headers)}


def content_block(rules_sha256, checked=True, verdict="none", scope_conflict="none", answered=True):
    return {"rules": "a2a-content-check-v0", "input_sha256": "11" * 32 if checked else None, "check_sha256": "22" * 32 if checked else None,
            "rules_sha256": rules_sha256, "scope_sha256": "33" * 32, "verdict": verdict if checked else None,
            "scope_conflict": scope_conflict if checked else None, "answered": answered, "checked": checked}


def ref(action, sha, nonce):
    return {"action": action, "admission_sha256": sha, "executed": {"action": action, "target": None, "amount": None, "nonce": nonce, "expiry_height": 999999}}


R_GOOD, R_OTHER = "a1" * 32, "b2" * 32
NONCE = lambda i: ("%02x" % i) * 16


def scenarios():
    """(name, furui terms, build(world) -> (events, admissions), expected clauses). The 0.3 admissions verify only with an
    admission_verify_v0 that knows version 0.3."""
    def one(action="read", **adm):
        def b(w):
            a, sha = w.admission(action, NONCE(1), **adm)
            return [w.execution([action], [ref(action, sha, NONCE(1))])], [a]
        return b
    F = {"rules_sha256": R_GOOD}
    return [
        ("v01_admit_no_furui", None, one(), []),
        ("v01_admit_under_furui", F, one(), ["content_not_checked"]),
        ("v01_refuse_under_furui", F, one(decision="refuse", reasons=("nonce_reused",)), ["executed_after_refusal"]),
        ("v01_admit_furui_without_rules", {"scope_text": "Answer questions about the price list."}, one(), []),
        ("v03_admit_same_rules", F, one(version="0.3", content=content_block(R_GOOD)), []),
        ("v03_admit_other_rules", F, one(version="0.3", content=content_block(R_OTHER)), ["content_rules_mismatch"]),
        # a v0.3 admit whose content block says unchecked breaks the record's own rules 1 and 7: the verifier reads it as
        # malformed, so the execution has no admission at all
        ("v03_admit_unchecked", F, one(version="0.3", content=content_block(R_GOOD, checked=False)), ["unadmitted_execution"]),
        ("v03_refuse_flagged", F, one(decision="refuse", reasons=("content_flagged",), version="0.3",
                                      content=content_block(R_GOOD, verdict="instruction")), ["executed_after_refusal"]),
        ("v03_refuse_other_rules", F, one(decision="refuse", reasons=("content_flagged",), version="0.3",
                                          content=content_block(R_OTHER, verdict="instruction")), ["executed_after_refusal"]),
        ("v03_admit_prohibited_same_rules", F, one(action="delete", version="0.3", content=content_block(R_GOOD)),
         ["admitted_out_of_grant", "prohibited"]),
        ("v03_admit_prohibited_other_rules", F, one(action="delete", version="0.3", content=content_block(R_OTHER)),
         ["admitted_out_of_grant", "content_rules_mismatch", "prohibited"]),
    ]


def _shim_0_3():
    """When admission_verify_v0 does not know version 0.3 yet, accept a 0.3 record whose signature verifies and whose
    contract_ref names the contract (a stand-in, for this file's own tests only). Returns the function to restore."""
    if getattr(A, "VERSION_CONTENT", None) == CONTENT_VERSION:
        return None
    real = A.verify_admission
    from contract_v0 import ed25519_verify

    def verify(record, key, contract=None):
        if isinstance(record, dict) and (record.get("rules") or {}).get("version") == CONTENT_VERSION:
            dom = (record.get("relying_party") or {}).get("domain")
            msg = A.admission_signing_bytes(record)
            ok = any(isinstance(s, dict) and s.get("domain") == dom and ed25519_verify(key, s.get("sig"), msg) is True for s in record.get("signatures") or [])
            ok = ok and (contract is None or (record.get("contract_ref") or {}).get("contract_sha256") == contract_sha256(contract))
            return {"verdict": "accepted" if ok else "refused", "refusals": [] if ok else ["bad_signature"]}
        return real(record, key, contract)
    A.verify_admission = verify
    return real


# --------------------------------------------------------------------------- self test
def _selftest():
    import subprocess
    sys.path.insert(0, os.path.join(HERE, "settle-core-v0"))
    n = 0
    # [1] no requirements.furui: the bytes of v1.16 on every settle core v0 vector and every admission fixture case
    from run_reference import settle_dir
    idx = json.load(open(os.path.join(HERE, "settle-core-v0", "vectors", "vectors.json"), encoding="utf-8"))
    from run_reference import core_fields
    named = 0
    for v in idx["vectors"]:
        d = os.path.join(HERE, "settle-core-v0", "vectors", v["id"])
        a, b = settle_dir(d, v116.settle_v1_16, parse_strict), settle_dir(d, settle_v1_17, parse_strict)
        if named_rules(parse_strict(open(os.path.join(d, "contract.json"), encoding="utf-8").read())) is None:
            assert canonical(a) == canonical(b), v["id"]
        else:                                       # names a check, carries no admission: the same core fields
            named += 1
            assert core_fields(a) == core_fields(b) and b["content_gate"]["counts"] == {c: 0 for c in CLAUSES}, v["id"]
    contracts, cases, keys = v111.load_fixture()
    for k, c in sorted(cases.items()):
        a = v116.settle_v1_16(contracts[c["contract"]], c["events"], c["view"], admissions=c["admissions"], relying_keys=keys)
        b = settle_v1_17(contracts[c["contract"]], c["events"], c["view"], admissions=c["admissions"], relying_keys=keys)
        assert canonical(a) == canonical(b), k
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    rr = os.path.join(HERE, "run0002")
    C2 = rd(os.path.join(HERE, "second_contract_AB.json"))
    args = (C2, [rd(os.path.join(rr, "exec_19c44a79.anchored.json"))], rd(os.path.join(rr, "view.json")))
    nr = [rd(os.path.join(rr, "walk_8bf29f1a.json"))]
    assert canonical(settle_v1_17(*args, nenrin_records=nr)) == canonical(v116.settle_v1_16(*args, nenrin_records=nr))
    n += 1; print("[1] no requirements.furui.rules_sha256: v1.16 byte for byte (%d settle core v0 vectors, %d admission fixture cases, run0002); "
                  "%d vector that names a check and carries no admission: the same core fields" % (len(idx["vectors"]) - named, len(cases), named))

    # [2] the rule, on a synthetic world: the 0.1 admissions verify as they are; the 0.3 ones need a verifier that knows 0.3
    restore = _shim_0_3()
    try:
        clauses = lambda s: sorted({d["clause"] for d in s["deviations"]})
        for name, furui, build, want in scenarios():
            w = World(furui, label="settle v1.17 " + name)
            events, adms = build(w)
            view = w.view()
            s = settle_v1_17(w.contract, events, view, admissions=adms, relying_keys=w.keys)
            assert s["status"] == "final" and clauses(s) == want, (name, s["verdict"], clauses(s), s.get("underspecified"))
            if furui is None or named_rules(w.contract) is None:
                assert canonical(s) == canonical(v116.settle_v1_16(w.contract, events, view, admissions=adms, relying_keys=w.keys)), name
            else:
                assert s["schema"] == SETTLE_SCHEMA and s["content_gate"]["rules_sha256"] == R_GOOD, name
                assert s["verdict"] == ("deviation" if want else "within_grant"), (name, s["verdict"])
            print("    %-36s %-12s %s" % (name, s["verdict"], ",".join(want) or "-"))
    finally:
        if restore:
            A.verify_admission = restore
    n += 1; print("[2] %d scenarios: content_rules_mismatch, content_not_checked, executed_after_refusal first, beside admitted_out_of_grant%s"
                  % (len(scenarios()), "" if restore is None else " (0.3 admissions through a stand-in verifier: admission_verify_v0 here does not know 0.3)"))

    # [3] the same input gives the same bytes; one admission is read once
    restore = _shim_0_3()
    try:
        w = World({"rules_sha256": R_GOOD}, label="settle v1.17 twice")
        a, sha = w.admission("read", NONCE(2), version="0.3", content=content_block(R_OTHER))
        e1 = w.execution(["read"], [ref("read", sha, NONCE(2))])
        e2 = w.execution(["read"], [ref("read", sha, NONCE(2))])
        view = w.view()
        s = settle_v1_17(w.contract, [e1, e2], view, admissions=[a], relying_keys=w.keys)
        assert [d["clause"] for d in s["deviations"]].count("content_rules_mismatch") == 1, s["deviations"]
        assert canonical(s) == canonical(settle_v1_17(w.contract, [e2, e1], view, admissions=[a], relying_keys=w.keys))
    finally:
        if restore:
            A.verify_admission = restore
    n += 1; print("[3] one admission named twice: one content_rules_mismatch; the order of the input does not change the bytes")

    r = subprocess.run([sys.executable, os.path.join(HERE, "settle_v1_16.py"), "--selftest"], capture_output=True, text=True)
    assert r.returncode == 0 and "SELF-TEST PASSED" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
    n += 1; print("[4] settle_v1_16 self test (and every layer it runs) still passes")
    print("\nSELF-TEST PASSED: MUSUBI settle v1.17, %d checks (v1.16 byte for byte without requirements.furui; content_rules_mismatch; "
          "content_not_checked; executed_after_refusal first; one admission read once; lower layers unchanged)" % n)


# --------------------------------------------------------------------------- command line
def main():
    ap = argparse.ArgumentParser(description="MUSUBI settle v1.17 (the admission's content check against requirements.furui)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--settle", metavar="CONTRACT.json")
    ap.add_argument("--event", action="append", default=[])
    ap.add_argument("--view", action="append", default=[])
    ap.add_argument("--nenrin", action="append", default=[])
    ap.add_argument("--admission", action="append", default=[], help="a signed a2a-admission-v0 record with its anchor")
    ap.add_argument("--relying-key", action="append", default=[], metavar="DOMAIN=BASE64", help="the relying party's Ed25519 key, fetched from its key_url")
    ap.add_argument("--parent", metavar="PARENT_CONTRACT.json")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return 0
    if not a.settle or not a.view:
        ap.print_help(); return 1
    rd = lambda p: parse_strict(open(p, encoding="utf-8").read())
    contract = rd(a.settle)
    views = [rd(p) for p in a.view]
    for vw in views:
        why = v116.view_problem(vw)
        if why:
            print(json.dumps({"view_not_strict": why}, indent=2)); return 2
    cmp = v116.v115.v110.v19.v18.v17.v14.compare_views_v1_4(views, contract)
    if cmp["chosen"] is None:
        print(json.dumps({"fork_choice": cmp}, indent=2)); return 2
    keys = dict(x.split("=", 1) for x in a.relying_key)
    s = settle_v1_17(contract, [rd(p) for p in a.event], views[cmp["chosen"]], parent=rd(a.parent) if a.parent else None,
                     admissions=[rd(p) for p in a.admission], relying_keys=keys, nenrin_records=[rd(p) for p in a.nenrin] or None)
    if a.out:
        open(a.out, "w", encoding="utf-8", newline="").write(canonical(s))
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0 if s["status"] == "final" else 2


if __name__ == "__main__":
    sys.exit(main())
