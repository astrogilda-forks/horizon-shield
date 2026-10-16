"""count_adoption.py against a local fake ledger and a fake GitHub, so the counting rules are checked offline.

    python3 tools/adoption/count_adoption_test.py
"""
import http.server, json, os, sys, threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

BATCH1 = {"schema": "nenrin-witness-batch-v1", "records": [
    {"sha": "a", "signed": True, "signed_domain": "api.babyblueviper.com"},
    {"sha": "b", "signed": True, "signed_domain": "gate.horizonshield.dev"},
    {"sha": "c", "signed": False, "witness_name": "someone-unsigned"},
    {"sha": "c2", "signed": False, "witness_name": "HORIZON SHIELD self-witness (github runner)"}]}
BATCH2 = {"schema": "nenrin-witness-batch-v1", "records": [
    {"sha": "d", "signed": True, "signed_domain": "PIPAVLO82.github.io"},
    {"sha": "e", "signed": True, "signed_domain": "api.babyblueviper.com"},
    {"sha": "f", "signed": True, "signed_domain": "raw.githubusercontent.com"},
    {"sha": "g", "signed": True, "signed_domain": "github.com/Alice"}]}
ENTRIES = {1: {"record_canonical": "# a plain text claim"}, 2: {"record_canonical": json.dumps(BATCH1)},
           3: {"record_canonical": json.dumps(BATCH2)}}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/ledger/head":
            body = {"n": 4, "head": "h"}
        elif self.path.startswith("/ledger/"):
            n = int(self.path.rsplit("/", 1)[1])
            if n == 4:
                self.send_response(500); self.end_headers(); return
            body = ENTRIES[n]
        else:
            self.send_response(404); self.end_headers(); return
        b = json.dumps(body).encode()
        self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)


def main():
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    os.environ["HS_LEDGER"] = "http://127.0.0.1:%d" % s.server_address[1]
    import count_adoption as C
    C.LEDGER = os.environ["HS_LEDGER"]
    bad = 0

    def check(name, got, want):
        nonlocal bad
        ok = got == want
        bad += not ok
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  got %r want %r" % (got, want)))

    our = ["horizonshield.dev", "the-horizons-innovation.com", "ogasurfproject-jpg"]
    w = C.ledger_witnesses(our, ["horizon shield", "toshikatsu oga"])
    check("outside signed domains, ours left out, case folded, GitHub owner counted", sorted(w["signed_domains"]), ["api.babyblueviper.com", "github.com/alice", "pipavlo82.github.io"])
    check("a shared host is never an identity: refused and listed", w["refused_shared_host"], [{"entry": 3, "signed_domain": "raw.githubusercontent.com"}])
    check("a domain that filed twice is one witness", w["signed_domains"]["api.babyblueviper.com"], [2, 3])
    check("unsigned names listed, not counted, our own names left out", list(w["unsigned_names"]), ["someone-unsigned"])
    check("an entry that cannot be read is reported, not skipped silently", w["unreadable_entries"], [4])
    check("only witness batches are read", w["witness_batches"], 2)
    check("ours(): subdomain of ours", C.ours("gate.horizonshield.dev", our), True)
    check("ours(): look-alike is not ours", C.ours("evilhorizonshield.dev", our), False)
    c = C.contracts(our)
    check("committed contracts both sides signed have an outside party", c["with_an_outside_party"] >= 1, True)
    check("no contract without us is invented", c["with_no_party_from_us"], 0)
    # a contract two outside parties keep in their own repository, listed in the registry by URL
    try:
        import base64, tempfile
        sys.path.insert(0, C.MUSUBI)
        import contract_v0 as v0
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        have_crypto = True
    except Exception:
        have_crypto = False
    if have_crypto:
        def nk():
            k = Ed25519PrivateKey.generate()
            return k, base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        ka, pa = nk(); kb, pb = nk()
        lb = {"kind": "bitcoin_block", "height": 969500, "hash": "0" * 64}
        g = {"authorized_actions": ["read"], "prohibited_actions": ["delete"], "conditional": [], "delegation": {"allowed": []},
             "revocation": {"effective_at": "anchor"}, "finality": {"depth": 6, "max_target_bits": "17080000"}, "witnesses": []}
        dne = ["that anyone enforced any of this at runtime", "that the contractor obeyed the grant, only that its recorded acts match or deviate from it",
               "that anyone judges liability or fault; the verdict is a function anyone recomputes",
               "that a prohibited action was impossible, only that performing one is a provable deviation",
               "that this is a legal contract or determines legal responsibility"]
        ct = v0.build_contract({"domain": "a.example", "key_url": "https://a.example/k.json", "public_key_ed25519_b64": pa},
                               {"domain": "b.example", "key_url": "https://b.example/k.json", "public_key_ed25519_b64": pb},
                               {"purpose": "p", "payload_digest": "a" * 64}, g, ["that both parties signed these grant bytes at the stated time"], dne,
                               lower_bound=lb, contract_id="0123456789abcdef0123456789abcdef", nonce="2" * 32, agreed_at="2026-10-02T00:00:00Z")
        v0.sign_contract(ct, ka, pa, "a.example")
        tdir = tempfile.mkdtemp()
        one = os.path.join(tdir, "one.json"); open(one, "w").write(json.dumps(ct))
        v0.sign_contract(ct, kb, pb, "b.example")
        both = os.path.join(tdir, "both.json"); open(both, "w").write(json.dumps(ct))
        forged = json.loads(json.dumps(ct)); forged["grant"]["authorized_actions"] = ["read", "delete"]
        fg = os.path.join(tdir, "forged.json"); open(fg, "w").write(json.dumps(forged))
        reg = {"published_contracts": [{"contract_url": "file://" + both}, {"contract_url": "file://" + one},
                                       {"contract_url": "file://" + fg}, {"contract_url": "file://" + both, "contract_sha256": "f" * 64},
                                       {"contract_url": "file://" + os.path.join(tdir, "missing.json")}]}
        pub, probs = C.published_contracts(reg, our)
        check("a published contract both outside parties signed is counted once", [p["parties"] for p in pub], [["a.example", "b.example"]])
        check("one signature, an edited grant, a wrong pin, a missing file: each listed, none counted", len(probs), 4)
        c2 = C.contracts(our, pub, probs)
        check("with it, a contract with no party from this project", c2["with_no_party_from_us"], 1)
        # a published settlement is counted as settled only when it is recomputed here byte for byte
        csha = pub[0]["contract_sha256"]
        sp = os.path.join(tdir, "s.json"); open(sp, "w").write(json.dumps({"schema": "a2a-settlement-v1.10", "status": "final", "contract_sha256": csha}))
        wp = os.path.join(tdir, "w.json"); open(wp, "w").write(json.dumps({"schema": "a2a-settlement-v1.10", "status": "final", "contract_sha256": "e" * 64}))
        no_inputs = C.recompute_settlement({"settlement_url": "file://" + sp}, open(both, "rb").read(), csha)
        other = C.recompute_settlement({"settlement_url": "file://" + wp, "settle_inputs": {"event_url": "file://" + sp, "view_url": "file://" + sp}}, open(both, "rb").read(), csha)
        check("a settlement with no inputs to recompute it, and one naming another contract: neither counts as settled",
              (no_inputs["recomputed_identical"], "settle_inputs" in no_inputs["why"], other["recomputed_identical"], "names contract" in other["why"]), (False, True, False, True))
        pub[0]["settlement"] = no_inputs
        check("an unrecomputed settlement leaves settled_final_recomputed at 0", C.contracts(our, pub, probs)["settled_final_recomputed"], 0)
    else:
        print("skip  published contracts (the cryptography package is not installed, signatures cannot be checked)")
    d = {"measured_at": "2026-10-02T00:00:00Z", "metrics": {
        "independent_implementations": {"count": 1, "distinct_authors": 1, "by_subject": {"x": 1}, "open_calls": {}},
        "independent_witnesses": {"count": None, "ledger": None, "reverification_pool": {"admitted": [], "file": "p", "quorum_of_independent_controls_needed": 2}},
        "external_contracts": {"with_an_outside_party": 0, "with_no_party_from_us": 0},
        "external_evidence_producers": {"count": None}, "third_party_ci_reproductions": {"count": None}}}
    blk = C.readme_block(d)
    check("an unreadable source prints 'not measured', never 0 (witnesses, producers, TRACE pins, CI)", blk.count("not measured"), 4)
    real_get = C.get
    C.get = lambda url, accept="", timeout=20: (200, b"")
    try:
        imp = C.implementations({"implementations": [
            {"who": "A", "subject": "s1", "what": "free text naming CASE-001", "evidence": "https://example.com/1", "date": "2026-10-02"},
            {"who": "B", "subject": "s1", "what": "more free text", "evidence": "https://example.com/2", "date": "2026-10-03"},
            {"who": "A, written another way", "author": "a", "subject": "s1", "what": "x", "evidence": "https://example.com/3", "date": "2026-10-04"}]})
    finally:
        C.get = real_get
    check("the snapshot counts the registry rows, authors by id not by spelling", (imp["count"], imp["distinct_authors"], imp["links_answering"], imp["by_subject"]), (3, 2, 3, {"s1": 3}))
    check("a row keeps who, subject, evidence and date, and gets a kind", sorted(imp["items"][0]), ["date", "evidence", "kind", "link_ok", "link_status", "subject", "who"])
    C.get = lambda url, accept="", timeout=20: (200, b"")
    try:
        imp2 = C.implementations({"implementations": [
            {"who": "A", "author": "a", "subject": "s1", "what": "own code", "evidence": "https://example.com/1", "date": "2026-10-02"},
            {"who": "P", "author": "p", "kind": "reproduction", "subject": "s1", "what": "reran ours", "evidence": "https://example.com/2", "date": "2026-10-03"},
            {"who": "O", "author": "o", "kind": "integration", "subject": "s2", "what": "our vectors in their tests", "evidence": "https://example.com/3", "date": "2026-10-04"}]})
        try:
            C.implementations({"implementations": [{"who": "X", "kind": "adoption", "subject": "s", "what": "", "evidence": "https://example.com/4", "date": "2026-10-05"}]})
            unknown_refused = False
        except ValueError:
            unknown_refused = True
    finally:
        C.get = real_get
    check("only implementation rows feed the implementation count and its authors", (imp2["count"], imp2["distinct_authors"], imp2["by_subject"]), (1, 1, {"s1": 1}))
    check("reproductions and integrations are reported apart", imp2["other_kinds"], {"reproduction": {"count": 1, "distinct_authors": 1}, "integration": {"count": 1, "distinct_authors": 1}})
    check("an unknown kind is refused, not counted", unknown_refused, True)
    d2 = json.loads(json.dumps(d)); d2["metrics"]["independent_implementations"].update({"other_kinds": imp2["other_kinds"]})
    check("the README block prints the other kinds on their own line", "reproduction 1 row by 1 author, integration 1 row by 1 author" in C.readme_block(d2), True)
    check("the free-text 'what' of a registry row is not copied into the snapshot", "CASE-001" in json.dumps(imp), False)
    print("\n%s" % ("all passed" if not bad else "%d failed" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
