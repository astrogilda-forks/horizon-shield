#!/usr/bin/env python3
"""slot_check_test: the reader side of slot-witness-v0. BIP-340 (written separately from the intake's) against the BIP's
vectors and a real invinoveritas event; every observation the JS intake wrote in fixtures/slot_fixtures.json recomputed
here; tampering refused by name; and a synthetic ledger with an OpenTimestamps path and a mined regtest header view.
v0.1: the decider field recomputed on the JS intake's v0.1 observations and on the first live decider-scoped slot.
No network, standard library only. Run: python3 slot_check_test.py"""
import base64, copy, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "musubi-v0"))
import bip340  # noqa: E402
import slot_check as SC  # noqa: E402
import anchor_compose as AC  # noqa: E402
import settle_v1_1 as v11  # noqa: E402

results = []


def t(name, ok, detail=""):
    results.append((name, bool(ok), detail))


# ---- BIP-340 -------------------------------------------------------------------------------------------------
rows = [l.split(",") for l in open(os.path.join(HERE, "fixtures", "bip340_test_vectors.csv")).read().strip().split("\n")[1:]]
v = sum(1 for r in rows if bip340.verify(bytes.fromhex(r[2]), bytes.fromhex(r[4]), bytes.fromhex(r[5])) == (r[6] == "TRUE"))
t("BIP-340 verify (Python) agrees with all %d test vectors" % len(rows), v == len(rows), "%d/%d" % (v, len(rows)))
signed = [r for r in rows if r[1]]
s = sum(1 for r in signed if bip340.sign(bytes.fromhex(r[1]), bytes.fromhex(r[4]), bytes.fromhex(r[3])).hex().upper() == r[5])
t("BIP-340 sign (Python) reproduces every vector with a secret key", s == len(signed) and s > 0)
real = json.load(open(os.path.join(HERE, "fixtures", "invinoveritas_event.json"), encoding="utf-8"))["event"]
ok, why = bip340.nostr_event_check(real)
t("a real invinoveritas event verifies here (NIP-01 id and BIP-340)", ok, why)
t("the invinoveritas key is the one this checker reads", real["pubkey"] in SC.ISSUERS)
bad = dict(real, content=real["content"].replace("reject", "rejecT"))
t("one character of content changed: refused on the id", not bip340.nostr_event_check(bad)[0])

# ---- every observation the intake wrote ------------------------------------------------------------------------
FX = json.load(open(os.path.join(HERE, "fixtures", "slot_fixtures.json"), encoding="utf-8"))
TEST = {FX["test_issuer_pubkey"]: {"name": "test-issuer", "slot_url_prefix": FX["test_slot_url_prefix"]}}
for c in FX["cases"]:
    raw = c["record_jcs"].encode("utf-8")
    rep, prob = SC.check_record(raw, hashlib.sha256(raw).hexdigest(), issuers=TEST)
    t("%s: the JS intake's observation recomputes here, verdict %s" % (c["name"], c["expect_verdict"]), not prob and rep["verdict"] == c["expect_verdict"], prob)
rep, prob = SC.check_record(FX["cases"][0]["record_jcs"].encode())
t("with only the real issuer list, a test-issuer receipt is refused", any("not an issuer" in p for p in prob), prob)


def mutate(name, f):
    obs = json.loads(next(c for c in FX["cases"] if c["name"] == name)["record_jcs"])
    f(obs)
    return SC.VC.jcs(obs).encode("utf-8")


def problems(raw):
    return SC.check_record(raw, issuers=TEST)[1]


t("a record claiming unique over bytes that list two receipts: refused", any("does not recompute" in p for p in problems(mutate("listed_with_others", lambda o: o.update(verdict="unique", event_ids_seen=o["event_ids_seen"][:1])))))
t("a record whose kept bytes were swapped: refused", any("do not match" in p for p in problems(mutate("unique", lambda o: o.update(response_b64=base64.b64encode(b'{"slot":"x"}').decode())))))
t("a record naming another slot than the signed content: refused", any("request_slot" in p for p in problems(mutate("unique", lambda o: o.update(request_slot="c" * 64)))))
t("a record whose receipt signature was altered: refused", any("receipt:" in p for p in problems(mutate("unique", lambda o: o["receipt_event"].update(sig="0" * 128)))))
t("a record pointing at another endpoint: refused", any("slot_url" in p for p in problems(mutate("unique", lambda o: o.update(slot_url="https://evil.example/slot/" + o["request_slot"])))))
spaced = json.dumps(json.loads(FX["cases"][0]["record_jcs"]), indent=1).encode()
t("the same record not in RFC 8785 form: refused", any("RFC 8785" in p for p in problems(spaced)))
t("judge: the same id twice is never unique", SC.judge(200, b'{"slot":"s","taken":true,"event_ids":["e","e"]}', "s", "e")[0] == "listed_with_others")
t("judge: taken with an empty list is not_listed", SC.judge(200, b'{"slot":"s","taken":true,"event_ids":[]}', "s", "e")[0] == "not_listed")


# ---- v0.1: the decider field -------------------------------------------------------------------------------------
FX1 = json.load(open(os.path.join(HERE, "fixtures", "slot_fixtures_v01.json"), encoding="utf-8"))
for c in FX1["cases"]:
    raw = c["record_jcs"].encode("utf-8")
    rep, prob = SC.check_record(raw, hashlib.sha256(raw).hexdigest(), issuers=TEST)
    exp = c["expect_decider"]
    dec_ok = rep.get("decider") is None if exp is None else (rep.get("decider") or {}).get(exp[0]) == exp[1]
    t("v0.1 %s: the JS intake's observation and its decider recompute here" % c["name"], not prob and rep["verdict"] == c["expect_verdict"] and dec_ok, (prob, rep.get("decider")))


def mutate1(name, f):
    obs = json.loads(next(c for c in FX1["cases"] if c["name"] == name)["record_jcs"])
    f(obs)
    return SC.VC.jcs(obs).encode("utf-8")


t("v0.1: a record claiming no equivocation over bytes that show it: refused", any("decider does not recompute" in p for p in problems(mutate1("equivocation_one_conflict", lambda o: o["decider"].update(equivocation=False)))))
t("v0.1: a record claiming equivocation over bytes whose conflict does not verify: refused", any("decider does not recompute" in p for p in problems(mutate1("conflict_with_bad_signature", lambda o: o["decider"].update(conflicts_verified=1, equivocation=True)))))
t("v0.1: a record with the decider field removed: refused", any("carries no decider field" in p for p in problems(mutate1("holder_verifies_no_conflicts", lambda o: o.pop("decider")))))
t("v0: a record that adds a decider field: refused", any("has no decider field" in p for p in problems(mutate("unique", lambda o: o.update(decider=None)))))
t("an unknown observation schema: refused", any("schema is neither" in p for p in problems(mutate("unique", lambda o: o.update(schema="nenrin-slot-observation-v9")))))


def big_body(o, n):
    body = json.dumps({"slot": o["request_slot"], "taken": True, "event_ids": [o["receipt_event_id"]], "pad": "x" * n}).encode()
    o.update(response_b64=base64.b64encode(body).decode(), response_sha256=hashlib.sha256(body).hexdigest(), response_bytes=len(body))


t("v0: more than 16384 response bytes kept without truncation: refused", any("more than 16384" in p for p in problems(mutate("unique", lambda o: big_body(o, 20000)))))
t("v0.1: 20000 response bytes kept whole: accepted", not problems(mutate1("account_scoped_no_decider_claim", lambda o: big_body(o, 20000))))

LIVE = json.load(open(os.path.join(HERE, "fixtures", "invinoveritas_slot_decider_20261010.json"), encoding="utf-8"))
lb = base64.b64decode(LIVE["response_b64"])
lrc = LIVE["receipt_content_decider"]
t("the live slot bytes are the ones the ledger kept (sha256)", hashlib.sha256(lb).hexdigest() == LIVE["response_sha256"])
t("the live slot (2026-10-10): BIP-340 here (written apart from the intake's) finds both decider signatures valid: equivocation",
  SC.decider_reading(200, lb, lrc["request_slot"], lrc) == LIVE["expect_decider"], SC.decider_reading(200, lb, lrc["request_slot"], lrc))
lj = json.loads(lb)
lj["conflicts"][0]["decider_sig"] = ("1" if lj["conflicts"][0]["decider_sig"][0] == "0" else "0") + lj["conflicts"][0]["decider_sig"][1:]
d1 = SC.decider_reading(200, json.dumps(lj).encode(), lrc["request_slot"], lrc)
t("the live bytes with the conflict's signature altered: verified 0, no equivocation", d1["conflicts_verified"] == 0 and d1["equivocation"] is False)


# ---- v0.2: the issuer's slot log ------------------------------------------------------------------------------
FX2 = json.load(open(os.path.join(HERE, "fixtures", "slot_fixtures_v02.json"), encoding="utf-8"))
for c in FX2["cases"]:
    raw = c["record_jcs"].encode("utf-8")
    rep, prob = SC.check_record(raw, hashlib.sha256(raw).hexdigest(), issuers=TEST)
    t("v0.2 %s: issuer_log recomputes here as %s" % (c["name"], c["expect_issuer_log_status"]),
      not prob and (rep.get("issuer_log") or {}).get("status") == c["expect_issuer_log_status"], (prob, rep.get("issuer_log")))


def leaf_root_of_file(text):
    """The snapshot file read on its own, by the SPEC's rules (written here, apart from the reading of the proof)."""
    rows = text.split("\n")[:-1]
    level = [hashlib.sha256(r.encode()).hexdigest() for r in rows[1:]]
    while len(level) > 1:
        level = [hashlib.sha256((level[i] + (level[i + 1] if i + 1 < len(level) else level[i])).encode()).hexdigest() for i in range(0, len(level), 2)]
    header = json.loads(rows[0])
    return header, level[0], hashlib.sha256(rows[0].encode()).hexdigest(), [json.loads(r) for r in rows[1:]]


for c in FX2["cases"]:
    if "snapshot_jsonl" not in c:
        continue
    header, root, log_root, lines = leaf_root_of_file(c["snapshot_jsonl"])
    il = json.loads(c["record_jcs"])["issuer_log"]
    slot = json.loads(c["record_jcs"])["request_slot"]
    t("v0.2 %s: the snapshot file's own Merkle root is its header's, its log_root is the one the slot's proof reaches, and it holds the slot's line" % c["name"],
      root == header["merkle_root"] and log_root == il["log_root"] and SC.VC.jcs(header) == c["snapshot_jsonl"].split("\n")[0]
      and [x["slot"] for x in lines] == sorted(x["slot"] for x in lines) and any(x["slot"] == slot for x in lines))


def mutate2(name, f):
    obs = json.loads(next(c for c in FX2["cases"] if c["name"] == name)["record_jcs"])
    f(obs)
    return SC.VC.jcs(obs).encode("utf-8")


t("v0.2: a record claiming included over a proof that fails: refused", any("issuer_log does not recompute" in p for p in problems(mutate2("path_altered", lambda o: o["issuer_log"].update(status="included")))))
t("v0.2: a record hiding a conflict the log omits: refused", any("issuer_log does not recompute" in p for p in problems(mutate2("conflict_shown_but_missing_from_the_log", lambda o: o["issuer_log"].update(status="included", disagreements=[])))))
t("v0.2: a record with the issuer_log field removed: refused", any("carries no issuer_log field" in p for p in problems(mutate2("included", lambda o: o.pop("issuer_log")))))
t("v0.1: a record that adds an issuer_log field: refused", any("has no issuer_log field" in p for p in problems(mutate1("holder_verifies_no_conflicts", lambda o: o.update(issuer_log=None)))))

inc = json.loads(next(c for c in FX2["cases"] if c["name"] == "included")["record_jcs"])
ib = json.loads(base64.b64decode(inc["response_b64"]))


def il_of(f):
    b = copy.deepcopy(ib)
    f(b)
    return SC.issuer_log_reading(200, json.dumps(b).encode(), inc["request_slot"])


t("issuer_log: a line edited after the snapshot (another slot) no longer reaches the root: proof_fails", il_of(lambda b: b["log"]["line"].update(slot="0" * 64))["status"] == "proof_fails")
t("issuer_log: slot bytes for another slot beside a valid proof disagree on slot", "slot" in il_of(lambda b: b.update(slot="0" * 64))["disagreements"])
t("issuer_log: a merkle path longer than 64 steps is malformed", il_of(lambda b: b["log"].update(merkle_path=b["log"]["merkle_path"] * 40))["status"] == "malformed")
t("issuer_log: a step with side X is malformed", il_of(lambda b: b["log"]["merkle_path"][0].update(side="X"))["status"] == "malformed")
t("issuer_log: another schema in the header is malformed", il_of(lambda b: b["log"]["header"].update(schema="x"))["status"] == "malformed")
t("issuer_log: no log key is absent, a non-200 or non-JSON answer is null", il_of(lambda b: b.pop("log"))["status"] == "absent"
  and SC.issuer_log_reading(503, b"{}", "s") is None and SC.issuer_log_reading(200, b"\xff", "s") is None)

REAL = json.load(open(os.path.join(HERE, "fixtures", "invinoveritas_slot_log_20261010.json"), encoding="utf-8"))
t("the live slot after the issuer's 2026-10-10 snapshot: its log reads as included under log_root 9214af3a...",
  SC.issuer_log_reading(200, REAL["body"].encode("utf-8"), REAL["slot"]) == REAL["expect_issuer_log"], SC.issuer_log_reading(200, REAL["body"].encode("utf-8"), REAL["slot"]))
rb = json.loads(REAL["body"])
rb["log"]["line"]["conflicts"] = []
t("the same live bytes with the logged conflict removed from the line: the proof fails", SC.issuer_log_reading(200, json.dumps(rb).encode(), REAL["slot"])["status"] == "proof_fails")

# --log-anchor: the issuer's .ots for the snapshot, read with anchor_compose (the same reader as the ledger's own stamps)
lroot = bytes.fromhex(inc["issuer_log"]["log_root"])
ltree = [(0xf0, b"cal", [(0x08, None, [("att", "bitcoin", 101)])])]
lots = AC.OTS_MAGIC + b"\x01" + b"\x08" + lroot + AC._ser(ltree)
lmerkle = AC._run(ltree, lroot)
hdrs, prev = [], "00" * 32
for hgt in (100, 101, 102):
    rawh = v11._mine(prev, lmerkle if hgt == 101 else hashlib.sha256(b"x%d" % hgt).digest(), t=1791700000 + (hgt - 101) * 600, salt=hgt)
    hdrs.append({"height": hgt, "hex": rawh.hex()})
    prev = v11.header_hash(rawh)
ots_route = {SC.LOG_URL + "2026-10-10.ots": lots}
fetch_ots = lambda u: (200, ots_route[u]) if u in ots_route else (_ for _ in ()).throw(OSError("404 " + u))
la, lp = SC.log_anchor(inc["issuer_log"], fetch_ots, view={"headers": hdrs}, floor_bits="207fffff")
t("--log-anchor: the issuer's .ots stamps the log_root, Bitcoin attestation at 101, block checked against the header view", not lp and la.get("log_anchored") and la["log_block_height"] == 101, (la, lp))
other_ots = AC.OTS_MAGIC + b"\x01" + b"\x08" + bytes(32) + AC._ser(ltree)
la, lp = SC.log_anchor(inc["issuer_log"], lambda u: (200, other_ots), view=None)
t("--log-anchor: an .ots stamping another digest is refused", any("not the log_root" in p for p in lp))
la, lp = SC.log_anchor({"status": "not_yet_in_a_snapshot"}, fetch_ots)
t("--log-anchor: nothing to anchor before the line is in a snapshot", any("no included line" in p for p in lp))


# ---- the outside copy of the issuer's slot log --------------------------------------------------------------------
for c in FX2["cases"]:
    if "snapshot_jsonl" in c:
        h, ls, lr, fp = SC.check_day_file(c["snapshot_jsonl"].encode())
        t("check_day_file (Python) on the day file the JS fixture built (%s): no problems, the same log_root" % c["name"], not fp and lr == json.loads(c["record_jcs"])["issuer_log"]["log_root"], fp)
empty_header = {"schema": SC.LOG_SCHEMA, "date": "2026-10-09", "cutoff": 1791590400, "prev_root": "0" * 64, "n_slots": 0,
                "merkle_root": hashlib.sha256((SC.LOG_SCHEMA + "|empty").encode()).hexdigest(), "rules": "r"}
empty_file = (SC.VC.jcs(empty_header) + "\n").encode()
t("check_day_file: an empty day whose root is the SPEC's empty tree passes", SC.check_day_file(empty_file)[3] == [])
t("check_day_file: n_slots edited is named", "n_slots_differs" in SC.check_day_file(empty_file.replace(b'"n_slots":0', b'"n_slots":1'))[3])
t("check_day_file: a file without the last newline is refused", SC.check_day_file(empty_file[:-1])[3] == ["not_newline_terminated"])
day_file = FX2["cases"][[c["name"] for c in FX2["cases"]].index("included")]["snapshot_jsonl"].encode()
h, ls, lr, fp = SC.check_day_file(day_file)
cots = AC.OTS_MAGIC + b"\x01" + b"\x08" + bytes.fromhex(lr) + AC._ser(ltree)
cmerkle = AC._run(ltree, bytes.fromhex(lr))
chdrs, prev = [], "00" * 32
for hgt in (100, 101, 102):
    rawh = v11._mine(prev, cmerkle if hgt == 101 else hashlib.sha256(b"y%d" % hgt).digest(), t=1791700000 + (hgt - 101) * 600, salt=hgt)
    chdrs.append({"height": hgt, "hex": rawh.hex()})
    prev = v11.header_hash(rawh)
LC = "https://ledger.test"
croutes = {LC + "/evidence/slot-log/2026-10-10.json": json.dumps({"date": "2026-10-10", "file_sha256": hashlib.sha256(day_file).hexdigest(), "log_root": lr, "problems": [], "ots": [{"sha256": "x"}], "copied_at": "2026-10-11T00:30:00Z"}).encode(),
           LC + "/evidence/slot-log/2026-10-10": day_file, LC + "/evidence/slot-log/2026-10-10.ots": cots}
cfetch = lambda u: (200, croutes[u]) if u in croutes else (_ for _ in ()).throw(OSError("404 " + u))
rep, prob = SC.check_log_copy(LC, "2026-10-10", cfetch, view={"headers": chdrs}, floor_bits="207fffff")
t("--log-copy: the kept file passes the rules, its log_root is the copy record's, the kept .ots stamps it, block checked", not prob and rep["anchor"].get("log_anchored"), (rep, prob))
croutes[LC + "/evidence/slot-log/2026-10-10"] = day_file.replace(b'"n_slots":4', b'"n_slots":5')
t("--log-copy: a file served that is not the one the copy record names is refused", any("hashes to" in p for p in SC.check_log_copy(LC, "2026-10-10", cfetch)[1]))


# ---- a synthetic ledger: batch, OTS path, mined header view ----------------------------------------------------------
L = "https://ledger.test"


def build(records, listed=None, block_t=1791700000, height=101, lie_claim=False, anchored=True):
    shas = [hashlib.sha256(r).hexdigest() for r in records]
    listed = shas if listed is None else listed
    batch = {"schema": SC.BATCH_SCHEMA, "anchored_at": "2026-10-11T00:30:00Z", "count": len(listed), "records": [{"sha": x} for x in listed]}
    bb = json.dumps(batch).encode()
    claim = hashlib.sha256(bb).digest()
    tree = [(0xf0, b"nonce", [(0x08, None, [(0xf1, b"agg", [(0x08, None, [("att", "bitcoin", height)])])])])]
    ots = AC.OTS_MAGIC + b"\x01" + b"\x08" + claim + AC._ser(tree)
    root = AC._run(tree, claim)
    headers, prev = [], "00" * 32
    for h in (height - 1, height, height + 1):
        raw = v11._mine(prev, root if h == height else hashlib.sha256(b"h%d" % h).digest(), t=block_t + (h - height) * 600, salt=h)
        headers.append({"height": h, "hex": raw.hex()})
        prev = v11.header_hash(raw)
    entry = {"n": 900, "claim_sha256": ("0" * 64) if lie_claim else claim.hex(), "block_time": SC.VC.iso(block_t), "bitcoin_block": height}
    routes = {L + "/ledger/900": json.dumps(entry).encode(), L + "/ledger/900?format=raw": bb, L + "/ledger/900/ots": ots}
    obs_list = []
    for r, x in zip(records, shas):
        o = json.loads(r)
        routes[L + "/evidence/slot/" + x + "?format=raw"] = r
        routes[L + "/evidence/slot/" + x] = json.dumps({"sha": x, "status": "anchored" if anchored else "pending", "anchor": {"ledger_entry": 900} if anchored else None}).encode()
        obs_list.append({"sha": x, "observed_at": o["observed_at"], "event_ids_seen": o["event_ids_seen"]})
        routes[L + "/evidence/slot/s/" + o["request_slot"]] = json.dumps({"observations": obs_list}).encode()

    def fetcher(url):
        if url in routes:
            return 200, routes[url]
        raise OSError("404 " + url)
    return fetcher, {"headers": headers}, shas


SC.ISSUERS.update(TEST)
recs = [c["record_jcs"].encode() for c in FX["cases"] if c["name"] in ("unique", "listed_with_others")]
F, VIEW, shas = build(recs)
rep, prob = SC.check_online(L, shas[0], F, view=VIEW, floor_bits="207fffff")
t("online: the observation recomputes and is anchored, block time from the checked header", not prob and rep.get("anchored") and rep["block_time_source"].startswith("the header in the view"), prob)
rep, prob = SC.check_online(L, shas[0], F, view=None)
t("online without a header view: the ledger's time is reported as NOT checked", "NOT checked" in rep["block_time_source"])
F2, V2, s2 = build(recs, listed=[shas[1]])
t("a batch that does not list the observation: refused", any("exactly once" in p for p in SC.check_online(L, shas[0], F2, view=V2, floor_bits="207fffff")[1]))
F3, V3, s3 = build(recs, lie_claim=True)
t("an entry whose claim is not the batch's hash: refused", any("entry claims" in p for p in SC.check_online(L, shas[0], F3, view=V3, floor_bits="207fffff")[1]))
F4, V4, s4 = build(recs, anchored=False)
t("not yet batched: reported, not anchored", any("not yet in a batch" in p for p in SC.check_online(L, shas[0], F4)[1]))
slot_rep, prob = SC.check_slot(L, json.loads(recs[0])["request_slot"], F, view=VIEW, floor_bits="207fffff")
t("--slot: both observations recompute and the listing change (one receipt, then two) is reported", not prob and slot_rep["slot_listing_changed"] and len(slot_rep["distinct_event_id_lists_seen"]) == 2, prob)
for k in TEST:
    SC.ISSUERS.pop(k, None)

bad = [r for r in results if not r[1]]
for name, okk, detail in results:
    print(("ok    " if okk else "FAIL  ") + name + ("" if okk else "  [%s]" % (detail,)))
print("\n%d/%d passed" % (len(results) - len(bad), len(results)))
sys.exit(1 if bad else 0)
