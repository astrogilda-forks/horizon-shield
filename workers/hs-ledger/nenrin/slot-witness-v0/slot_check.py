#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slot_check: recompute, without trusting the NENRIN ledger, what a slot witness observation says.

    python3 slot_check.py --sha <observation sha>            [--ledger https://ledger.horizonshield.dev] [--headers view.json]
    python3 slot_check.py --slot <request_slot>               (every observation of one slot, and whether the listing changed)
    python3 slot_check.py --record observation.json           (offline: the raw bytes /evidence/slot/<sha>?format=raw served)

For each observation this:
  1. checks the record is its own RFC 8785 form and hashes to its sha;
  2. checks the receipt it carries: the NIP-01 event id recomputes, the BIP-340 signature verifies under an issuer key
     listed here (written separately from the ledger's code), and request_slot is the one in the signed content;
  3. decodes the response bytes the ledger kept, checks their sha256 and length, and recomputes the verdict from them
     with the same rule the intake uses (unique only when the slot is taken and lists exactly this event id);
     from nenrin-slot-observation-v0.1, it also recomputes the decider field from the same bytes: whether the decider
     claim holding the slot verifies (BIP-340 over sha256(JCS(decider_claim)) by the receipt's decider_pubkey), how
     many conflicts the issuer lists, how many verify under the same key, and equivocation;
     from v0.2, it recomputes the issuer_log field: the slot's line in the issuer's daily slot log, its Merkle path to
     the header and log_root, and whether the line agrees with the slot bytes (--log-anchor also reads the issuer's .ots);
  4. with --sha or --slot, reads the ledger batch that lists the observation, checks it is the entry's claim and lists
     the sha exactly once, reads the entry's OpenTimestamps proof (musubi-v0/anchor_compose.read_ots) and, given a
     header view, the block's merkle root, linkage, work and time (vouch-pin-v0/vouch_check.header_time).
With --slot it also reports every distinct list of event ids the issuer served over time.
Exit 0 when every observation recomputes (and, online, is anchored), 1 otherwise, 2 on usage errors. Standard library only.
"""
import argparse, base64, hashlib, json, os, re, sys, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "vouch-pin-v0"))
sys.path.insert(0, os.path.join(HERE, "..", "musubi-v0"))
import bip340  # noqa: E402
import vouch_check as VC  # noqa: E402  (jcs, header_time, iso, parse_time: no third-party import at module load)
import anchor_compose as AC  # noqa: E402

OBS_SCHEMA_V0 = "nenrin-slot-observation-v0"
OBS_SCHEMA_V01 = "nenrin-slot-observation-v0.1"
OBS_SCHEMA = "nenrin-slot-observation-v0.2"
BATCH_SCHEMA = "nenrin-slot-witness-batch-v0"
MAX_RESPONSE_BYTES = {OBS_SCHEMA_V0: 16384, OBS_SCHEMA_V01: 65536, OBS_SCHEMA: 65536}  # bytes the intake keeps, by observation schema
LOG_SCHEMA = "invinoveritas.decision_receipt.slot_log.v1"
LOG_URL = "https://api.babyblueviper.com/decision-receipt/slots/log/"
MAX_MERKLE_PATH = 64
MAX_CONFLICTS_READ = 64
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
ISSUERS = {
    "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7": {
        "name": "invinoveritas", "slot_url_prefix": "https://api.babyblueviper.com/decision-receipt/slot/"},
}
VERDICTS = ["unique", "listed_with_others", "not_listed", "not_taken", "slot_mismatch", "unreadable", "fetch_failed"]


def judge(status, body, slot, event_id):
    """The intake's rule, from the stored bytes: (verdict, event_ids_seen)."""
    if status is None:
        return "fetch_failed", None
    if status != 200:
        return "unreadable", None
    try:
        b = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return "unreadable", None
    if not isinstance(b, dict):
        return "unreadable", None
    if b.get("slot") != slot:
        return "slot_mismatch", None
    ids = b.get("event_ids")
    ids_ok = isinstance(ids, list) and all(isinstance(x, str) for x in ids)
    if b.get("taken") is not True:
        return "not_taken", (ids if ids_ok else None)
    if not ids_ok:
        return "unreadable", None
    if ids == [event_id]:
        return "unique", ids
    if event_id in ids:
        return "listed_with_others", ids
    return "not_listed", ids


def _is_obj(x):
    return isinstance(x, dict)


def _claim_sig_ok(claim, sig, pubkey):
    if not _is_obj(claim) or not isinstance(sig, str) or not HEX128.fullmatch(sig) or not isinstance(pubkey, str) or not HEX64.fullmatch(pubkey):
        return False
    try:
        return bip340.verify(bytes.fromhex(pubkey), hashlib.sha256(VC.jcs(claim).encode("utf-8")).digest(), bytes.fromhex(sig))
    except Exception:  # noqa: BLE001
        return False


def decider_reading(status, body, slot, content):
    """The v0.1 intake's decider rule (slot_witness_v0.mjs deciderReading), from the stored bytes.
    None when the bytes carry no decider claim."""
    if status != 200:
        return None
    try:
        b = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not _is_obj(b) or not _is_obj(b.get("decider_claim")):
        return None
    dc = b["decider_claim"]
    rc = content if _is_obj(content) else {}
    if isinstance(rc.get("decider_pubkey"), str):
        pubkey = rc["decider_pubkey"]
    elif isinstance(dc.get("decider_pubkey"), str):
        pubkey = dc["decider_pubkey"]
    else:
        pubkey = None
    usable = pubkey is not None and HEX64.fullmatch(pubkey) is not None

    def names(c):
        return _is_obj(c) and isinstance(c.get("decider_pubkey"), str) and c["decider_pubkey"] == pubkey \
            and isinstance(c.get("request_slot"), str) and c["request_slot"] == slot

    valid = set()
    holder = "malformed"
    if usable:
        if not isinstance(dc.get("decider_pubkey"), str) or dc["decider_pubkey"] != pubkey:
            holder = "other_key"
        elif not isinstance(dc.get("request_slot"), str) or dc["request_slot"] != slot:
            holder = "other_slot"
        elif not _claim_sig_ok(dc, b.get("decider_sig"), pubkey):
            holder = "bad_signature"
        else:
            valid.add(VC.jcs(dc))
            holder = "not_the_receipts_claim" if _is_obj(rc.get("decider_claim")) and VC.jcs(rc["decider_claim"]) != VC.jcs(dc) else "verifies"
    lst = b.get("conflicts") if isinstance(b.get("conflicts"), list) else []
    verified = 0
    holder_jcs = VC.jcs(dc)
    if usable:
        for c in lst[:MAX_CONFLICTS_READ]:
            if not _is_obj(c) or not names(c.get("decider_claim")) or VC.jcs(c["decider_claim"]) == holder_jcs:
                continue
            if _claim_sig_ok(c["decider_claim"], c.get("decider_sig"), pubkey):
                verified += 1
                valid.add(VC.jcs(c["decider_claim"]))
        if names(rc.get("decider_claim")) and _claim_sig_ok(rc["decider_claim"], rc.get("decider_sig"), pubkey):
            valid.add(VC.jcs(rc["decider_claim"]))
    return {"pubkey": pubkey, "holder_claim": holder, "conflicts_listed": len(lst), "conflicts_verified": verified,
            "equivocation": len(valid) >= 2}


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hex64(x):
    return isinstance(x, str) and HEX64.fullmatch(x) is not None


def _int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def issuer_log_reading(status, body, slot):
    """The v0.2 intake's issuer_log rule (slot_witness_v0.mjs issuerLogReading), from the stored bytes. The slot's
    "log" object (decision-receipt SPEC v0.4, slot log): the slot's line in the issuer's latest daily snapshot, its
    Merkle path, the snapshot header and log_root = sha256(JCS(header)), the digest the issuer stamps to Bitcoin.
    None when the bytes are not a 200 slot object. Otherwise {"status", "date", "log_root", "disagreements"}:
      absent                 no log object
      not_yet_in_a_snapshot  the issuer says so
      malformed              a log object without the fields the SPEC names, in their forms
      proof_fails            leaf != sha256(JCS(line)), the path does not reach header.merkle_root, or log_root != sha256(JCS(header))
      line_disagrees         the proof holds, but the line says something else than the slot bytes beside it (disagreements)
      included               the proof holds and the line agrees with the slot bytes
    It does not check the stamp; slot_check.py --log-anchor does, from the issuer's .ots."""
    if status != 200:
        return None
    try:
        b = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not _is_obj(b):
        return None
    out = {"status": "absent", "date": None, "log_root": None, "disagreements": []}
    if "log" not in b:
        return out
    lg = b["log"]
    if _is_obj(lg) and lg.get("status") == "not_yet_in_a_snapshot" and "line" not in lg:
        return dict(out, status="not_yet_in_a_snapshot")
    h = lg.get("header") if _is_obj(lg) else None
    path = lg.get("merkle_path") if _is_obj(lg) else None
    shape = (_is_obj(lg) and _is_obj(lg.get("line")) and _hex64(lg.get("leaf")) and _hex64(lg.get("log_root")) and _is_obj(h)
             and h.get("schema") == LOG_SCHEMA and isinstance(h.get("date"), str) and _int(h.get("cutoff")) and _hex64(h.get("merkle_root"))
             and isinstance(path, list) and len(path) <= MAX_MERKLE_PATH
             and all(_is_obj(st) and st.get("side") in ("L", "R") and _hex64(st.get("hash")) for st in path))
    if not shape:
        return dict(out, status="malformed")
    out = dict(out, date=h["date"], log_root=lg["log_root"])
    leaf = _sha(VC.jcs(lg["line"]))
    node = leaf
    for st in path:
        node = _sha(node + st["hash"]) if st["side"] == "R" else _sha(st["hash"] + node)
    if leaf != lg["leaf"] or node != h["merkle_root"] or _sha(VC.jcs(h)) != lg["log_root"]:
        return dict(out, status="proof_fails")
    ln, dis = lg["line"], []
    if ln.get("slot") != slot or b.get("slot") != slot:
        dis.append("slot")
    for k in ("scope", "event_ids", "taken_at"):
        if VC.jcs(ln.get(k)) != VC.jcs(b.get(k)):
            dis.append(k)
    dc = b.get("decider_claim")
    if VC.jcs(ln.get("claim_sha256")) != VC.jcs(_sha(VC.jcs(dc)) if _is_obj(dc) else None):
        dis.append("claim_sha256")
    if VC.jcs(ln.get("decider_sig")) != VC.jcs(b.get("decider_sig") if _is_obj(dc) else None):
        dis.append("decider_sig")
    if not (_int(ln.get("taken_at")) and ln["taken_at"] < h["cutoff"]):
        dis.append("taken_at_not_before_cutoff")
    lc = ln.get("conflicts")
    bc = b.get("conflicts", [])
    if not isinstance(lc, list) or not isinstance(bc, list) or len(lc) > MAX_CONFLICTS_READ or len(bc) > MAX_CONFLICTS_READ:
        dis.append("conflicts_unreadable")
    else:
        shown = set()
        before = set()
        for c in bc:
            if not _is_obj(c) or not _is_obj(c.get("decider_claim")):
                continue
            e = VC.jcs({"claim_sha256": _sha(VC.jcs(c["decider_claim"])), "decider_sig": c.get("decider_sig"), "received_at": c.get("received_at")})
            shown.add(e)
            if _int(c.get("received_at")) and c["received_at"] < h["cutoff"]:
                before.add(e)
        logged = set(VC.jcs(c) for c in lc)
        if before - logged:
            dis.append("conflict_shown_by_slot_missing_from_log")
        if logged - shown:
            dis.append("conflict_in_log_not_shown_by_slot")
    return dict(out, status="line_disagrees" if dis else "included", disagreements=dis)


def check_record(raw, sha=None, issuers=None):
    """Offline checks of one observation's raw bytes. Returns (report, problems)."""
    issuers = ISSUERS if issuers is None else issuers
    prob = []
    got = hashlib.sha256(raw).hexdigest()
    rep = {"sha256": got}
    if sha and got != sha:
        prob.append("the bytes hash to %s, not %s" % (got, sha))
    try:
        obs = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return rep, prob + ["the record is not JSON"]
    if VC.jcs(obs).encode("utf-8") != raw:
        prob.append("the record is not in its RFC 8785 form")
    schema = obs.get("schema")
    if schema not in MAX_RESPONSE_BYTES:
        prob.append("schema is neither %s nor %s" % (OBS_SCHEMA_V0, OBS_SCHEMA))
    rep["schema"] = schema
    ev = obs.get("receipt_event")
    ok, why = bip340.nostr_event_check(ev)
    rep["receipt_signature"] = "verifies" if ok else why
    if not ok:
        prob.append("receipt: %s" % why)
        return rep, prob
    issuer = issuers.get(ev["pubkey"])
    rep["issuer"] = issuer["name"] if issuer else None
    if not issuer:
        prob.append("the receipt's key is not an issuer this checker reads")
        return rep, prob
    try:
        content = json.loads(ev["content"])
        slot = content.get("request_slot")
    except Exception:  # noqa: BLE001
        content, slot = None, None
    rep["request_slot"] = slot
    if not isinstance(slot, str) or slot != obs.get("request_slot"):
        prob.append("request_slot in the record is not the one in the signed content")
    if obs.get("receipt_event_id") != ev["id"] or obs.get("issuer_pubkey") != ev["pubkey"] or obs.get("receipt_created_at") != ev["created_at"]:
        prob.append("the record's receipt fields are not the event's")
    if isinstance(slot, str) and obs.get("slot_url") != issuer["slot_url_prefix"] + urllib.parse.quote(slot, safe="-_.!~*'()"):
        prob.append("slot_url is not the issuer's slot endpoint for this slot")
    try:
        body = base64.b64decode(obs.get("response_b64") or "", validate=True)
    except Exception:  # noqa: BLE001
        return rep, prob + ["response_b64 is not base64"]
    if hashlib.sha256(body).hexdigest() != obs.get("response_sha256") or len(body) != obs.get("response_bytes"):
        prob.append("the kept response bytes do not match response_sha256 or response_bytes")
    truncated = obs.get("response_truncated") is True
    cap = MAX_RESPONSE_BYTES.get(schema, MAX_RESPONSE_BYTES[OBS_SCHEMA])
    if truncated and len(body) != cap:
        prob.append("response_truncated is true but the kept bytes are not %d" % cap)
    if not truncated and len(body) > cap:
        prob.append("more than %d response bytes kept under %s" % (cap, schema))
    verdict, ids = ("unreadable", None) if truncated else judge(obs.get("http_status"), body, slot, ev["id"])
    rep.update({"observed_at": obs.get("observed_at"), "http_status": obs.get("http_status"), "verdict": verdict, "event_ids_seen": ids,
                "trigger": obs.get("trigger"), "previous_observation": (obs.get("previous_observation") or {}).get("sha")})
    if verdict != obs.get("verdict") or ids != obs.get("event_ids_seen"):
        prob.append("the verdict does not recompute from the kept bytes: record says %s, bytes say %s" % (obs.get("verdict"), verdict))
    if schema in (OBS_SCHEMA_V01, OBS_SCHEMA):
        dec = None if truncated else decider_reading(obs.get("http_status"), body, slot, content)
        rep["decider"] = dec
        if "decider" not in obs:
            prob.append("a %s observation carries no decider field" % schema)
        elif obs.get("decider") != dec:
            prob.append("decider does not recompute from the kept bytes: record says %s, bytes say %s" % (json.dumps(obs.get("decider")), json.dumps(dec)))
    elif "decider" in obs:
        prob.append("a %s observation has no decider field; this one carries one" % OBS_SCHEMA_V0)
    if schema == OBS_SCHEMA:
        il = None if truncated else issuer_log_reading(obs.get("http_status"), body, slot)
        rep["issuer_log"] = il
        if "issuer_log" not in obs:
            prob.append("a %s observation carries no issuer_log field" % OBS_SCHEMA)
        elif obs.get("issuer_log") != il:
            prob.append("issuer_log does not recompute from the kept bytes: record says %s, bytes say %s" % (json.dumps(obs.get("issuer_log")), json.dumps(il)))
    elif "issuer_log" in obs:
        prob.append("a %s observation has no issuer_log field; this one carries one" % schema)
    return rep, prob


def anchor_leg(ledger, sha, n, fetcher, view, floor_bits):
    rep, prob = {"ledger_entry": n}, []
    st, eb = fetcher("%s/ledger/%d" % (ledger, n))
    entry = json.loads(eb.decode("utf-8"))
    st, batch_bytes = fetcher("%s/ledger/%d?format=raw" % (ledger, n))
    claim = hashlib.sha256(batch_bytes).hexdigest()
    if claim != entry.get("claim_sha256"):
        prob.append("the batch bytes hash to %s, the entry claims %s" % (claim, entry.get("claim_sha256")))
    try:
        batch = json.loads(batch_bytes.decode("utf-8"))
        recs = batch.get("records") or []
        if batch.get("schema") != BATCH_SCHEMA or batch.get("count") != len(recs) or len([r for r in recs if isinstance(r, dict) and r.get("sha") == sha]) != 1:
            prob.append("the batch is not a %s that lists this sha exactly once" % BATCH_SCHEMA)
    except Exception:  # noqa: BLE001
        prob.append("the batch is not JSON")
    try:
        st, ots = fetcher("%s/ledger/%d/ots" % (ledger, n))
        digest, atts = AC.read_ots(ots)
    except Exception as e:  # noqa: BLE001
        return rep, prob + ["no readable OpenTimestamps proof yet: %s" % e]
    if digest.hex() != claim:
        prob.append("the .ots stamps %s, not the batch %s" % (digest.hex(), claim))
    btc = [x for x in atts if x.get("kind") == "bitcoin" and x.get("msg") is not None]
    if not btc:
        return rep, prob + ["the .ots has no Bitcoin attestation yet"]
    low = min(btc, key=lambda x: x["height"])
    rep["block_height"] = low["height"]
    if view is not None:
        try:
            t, hh = VC.header_time(view, low["height"], low["msg"], floor_bits)
            rep["block_time"], rep["block_time_source"] = VC.iso(t), "the header in the view you gave, checked here"
        except ValueError as e:
            prob.append("header view: %s" % e)
    else:
        rep["block_time"] = entry.get("block_time")
        rep["block_time_source"] = "as served by the ledger, NOT checked here; pass --headers view.json to check it"
    rep["anchored"] = not prob
    return rep, prob


def log_anchor(issuer_log, fetcher=VC.fetch, view=None, floor_bits="1903a30c", log_url=LOG_URL):
    """The issuer's stamp of the snapshot an included line sits in: fetch <log_url><date>.ots, check it stamps log_root
    (musubi-v0/anchor_compose.read_ots), and read its Bitcoin attestation; with a header view, the block's merkle root,
    linkage, work and time are checked here (vouch-pin-v0/vouch_check.header_time). Returns (report, problems)."""
    rep, prob = {"log_date": issuer_log.get("date"), "log_root": issuer_log.get("log_root")}, []
    if (issuer_log or {}).get("status") != "included":
        return rep, ["issuer_log is %s, so there is no included line to anchor" % (issuer_log or {}).get("status")]
    try:
        st, ots = fetcher(log_url + urllib.parse.quote(issuer_log["date"], safe="") + ".ots")
        digest, atts = AC.read_ots(ots)
    except Exception as e:  # noqa: BLE001
        return rep, ["no readable OpenTimestamps proof for the %s snapshot yet: %s" % (issuer_log["date"], e)]
    if digest.hex() != issuer_log["log_root"]:
        prob.append("the issuer's .ots stamps %s, not the log_root %s" % (digest.hex(), issuer_log["log_root"]))
    btc = [x for x in atts if x.get("kind") == "bitcoin" and x.get("msg") is not None]
    if not btc:
        return rep, prob + ["the issuer's .ots has no Bitcoin attestation yet (pending)"]
    low = min(btc, key=lambda x: x["height"])
    rep["log_block_height"] = low["height"]
    if view is not None:
        try:
            t, hh = VC.header_time(view, low["height"], low["msg"], floor_bits)
            rep["log_block_time"], rep["log_block_time_source"] = VC.iso(t), "the header in the view you gave, checked here"
        except ValueError as e:
            prob.append("header view: %s" % e)
    else:
        rep["log_block_time_source"] = "no header view given; the height is the attestation's, the block is NOT checked here"
    rep["log_anchored"] = not prob
    return rep, prob


LOG_LINE_KEYS = {"slot", "scope", "event_ids", "taken_at", "claim_sha256", "decider_sig", "conflicts"}


def check_day_file(data):
    """An issuer slot log day file by the SPEC's rules (written apart from slot_log_copy.mjs). Returns
    (header, lines, log_root, problems)."""
    try:
        text = data.decode("utf-8")
    except Exception:  # noqa: BLE001
        return None, [], None, ["not_utf8"]
    if not text.endswith("\n"):
        return None, [], None, ["not_newline_terminated"]
    raw = text.split("\n")[:-1]
    if not raw:
        return None, [], None, ["empty_file"]
    try:
        header = json.loads(raw[0])
    except Exception:  # noqa: BLE001
        return None, [], None, ["header_not_json"]
    if not _is_obj(header) or VC.jcs(header) != raw[0]:
        return None, [], None, ["header_not_canonical"]
    prob = [] if header.get("schema") == LOG_SCHEMA else ["unknown_schema"]
    lines = []
    for r in raw[1:]:
        try:
            x = json.loads(r)
        except Exception:  # noqa: BLE001
            return header, [], None, prob + ["line_not_json"]
        if not _is_obj(x) or VC.jcs(x) != r:
            return header, [], None, prob + ["line_not_canonical"]
        if set(x) != LOG_LINE_KEYS or not _hex64(x.get("slot")) or x.get("scope") not in ("account", "decider"):
            return header, [], None, prob + ["malformed_line"]
        lines.append(x)
    if prob:
        return header, lines, None, prob
    slots = [x["slot"] for x in lines]
    if any(not (a < b) for a, b in zip(slots, slots[1:])):
        prob.append("slots_not_strictly_sorted")
    if header.get("n_slots") != len(lines):
        prob.append("n_slots_differs")
    level = [_sha(r) for r in raw[1:]] or [_sha(LOG_SCHEMA + "|empty")]
    while len(level) > 1:
        level = [_sha(level[i] + (level[i + 1] if i + 1 < len(level) else level[i])) for i in range(0, len(level), 2)]
    if level[0] != header.get("merkle_root"):
        prob.append("merkle_root_differs")
    if not _int(header.get("cutoff")) or any(not _int(x.get("taken_at")) or x["taken_at"] >= header["cutoff"] for x in lines):
        prob.append("slot_taken_after_cutoff")
    return header, lines, _sha(raw[0]), prob


def check_log_copy(ledger, date, fetcher=VC.fetch, view=None, floor_bits="1903a30c"):
    """This ledger's copy of the issuer's slot log for one day: the day record, the file bytes it keeps, the SPEC's
    rules on them, and the kept .ots stamping the log_root. Returns (report, problems)."""
    st, b = fetcher("%s/evidence/slot-log/%s.json" % (ledger, date))
    day = json.loads(b.decode("utf-8"))
    st, data = fetcher("%s/evidence/slot-log/%s" % (ledger, date))
    rep, prob = {"date": date, "file_sha256": hashlib.sha256(data).hexdigest(), "copied_at": day.get("copied_at")}, []
    if rep["file_sha256"] != day.get("file_sha256"):
        prob.append("the served file hashes to %s, the copy record says %s" % (rep["file_sha256"], day.get("file_sha256")))
    header, lines, log_root, fp = check_day_file(data)
    rep.update(log_root=log_root, n_slots=len(lines), problems_at_copy=day.get("problems"))
    prob += ["day file: %s" % x for x in fp]
    if log_root != day.get("log_root"):
        prob.append("log_root recomputes to %s, the copy record says %s" % (log_root, day.get("log_root")))
    recorded = set(day.get("problems") or [])
    file_rules = {"not_utf8", "not_newline_terminated", "empty_file", "header_not_json", "header_not_canonical", "unknown_schema", "line_not_json",
                  "line_not_canonical", "malformed_line", "slots_not_strictly_sorted", "n_slots_differs", "merkle_root_differs", "slot_taken_after_cutoff"}
    if set(fp) != recorded & file_rules:
        prob.append("the copy recorded file problems %s, the file shows %s" % (sorted(recorded & file_rules), sorted(fp)))
    if log_root and day.get("ots"):
        la, lp = log_anchor({"status": "included", "date": date, "log_root": log_root}, fetcher, view, floor_bits, log_url=ledger + "/evidence/slot-log/")
        rep["anchor"] = la
        prob += ["kept .ots: %s" % x for x in lp]
    else:
        prob.append("no .ots kept for this day yet")
    return rep, prob


def check_online(ledger, sha, fetcher=VC.fetch, view=None, floor_bits="1903a30c", with_log_anchor=False):
    st, raw = fetcher("%s/evidence/slot/%s?format=raw" % (ledger, sha))
    rep, prob = check_record(raw, sha)
    if with_log_anchor:
        la, lp = log_anchor(rep.get("issuer_log") or {}, fetcher, view, floor_bits)
        rep["issuer_log_anchor"] = la
        prob = prob + ["issuer log: %s" % x for x in lp]
    st, b = fetcher("%s/evidence/slot/%s" % (ledger, sha))
    meta = json.loads(b.decode("utf-8"))
    n = (meta.get("anchor") or {}).get("ledger_entry")
    if n is None:
        rep["anchored"] = False
        return rep, prob + ["observed, not yet in a batch"]
    a, p2 = anchor_leg(ledger, sha, n, fetcher, view, floor_bits)
    rep.update(a)
    return rep, prob + p2


def check_slot(ledger, slot, fetcher=VC.fetch, view=None, floor_bits="1903a30c", with_log_anchor=False):
    st, b = fetcher("%s/evidence/slot/s/%s" % (ledger, urllib.parse.quote(slot, safe="")))
    hist = json.loads(b.decode("utf-8"))
    out, problems = [], []
    for o in hist.get("observations") or []:
        r, p = check_online(ledger, o["sha"], fetcher, view, floor_bits, with_log_anchor=with_log_anchor and o is (hist.get("observations") or [])[-1])
        out.append(r)
        problems += ["%s: %s" % (o["sha"][:12], x) for x in p]
    lists = []
    for r in out:
        if r.get("event_ids_seen") not in lists:
            lists.append(r.get("event_ids_seen"))
    return {"request_slot": slot, "observations": out, "distinct_event_id_lists_seen": lists, "slot_listing_changed": len(lists) > 1}, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sha")
    g.add_argument("--slot")
    g.add_argument("--record", help="an observation's raw bytes in a file (offline)")
    g.add_argument("--log-copy", metavar="DATE", help="this ledger's copy of the issuer's slot log for DATE (YYYY-MM-DD): file, rules, kept .ots")
    ap.add_argument("--ledger", default="https://ledger.horizonshield.dev")
    ap.add_argument("--headers", help="a header view {\"headers\": [{\"height\", \"hex\"}]} covering the attested block")
    ap.add_argument("--max-target-bits", default="1903a30c")
    ap.add_argument("--log-anchor", action="store_true", help="also fetch the issuer's .ots for the snapshot an included line sits in (reaches the issuer's domain)")
    a = ap.parse_args()
    view = json.load(open(a.headers, encoding="utf-8")) if a.headers else None
    led = a.ledger.rstrip("/")
    if a.log_copy:
        rep, prob = check_log_copy(led, a.log_copy, view=view, floor_bits=a.max_target_bits)
        rep["problems"] = prob
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 1 if prob else 0
    if a.record:
        rep, prob = check_record(open(a.record, "rb").read())
        online_needed = False
    elif a.sha:
        rep, prob = check_online(led, a.sha.lower(), view=view, floor_bits=a.max_target_bits, with_log_anchor=a.log_anchor)
        online_needed = True
    else:
        rep, prob = check_slot(led, a.slot, view=view, floor_bits=a.max_target_bits, with_log_anchor=a.log_anchor)
        online_needed = True
    rep["problems"] = prob
    rep["establishes"] = ["the receipt verifies under the issuer key and names this slot",
                          "the ledger kept exactly these response bytes, and they say what the verdict says",
                          "from v0.1, what the same bytes show about the decider key: whether the claim holding the slot verifies and how many listed conflicts verify under the same key",
                          "from v0.2, whether the same bytes carry the slot's line in the issuer's daily slot log with a proof to log_root, and whether the line agrees with the slot; with --log-anchor, whether the issuer's .ots stamps that log_root"]
    rep["does_not_establish"] = ["that only one receipt was issued; the slot is the issuer's record",
                                 "what the endpoint served between observations or to anyone else",
                                 "which of two conflicting decider claims was the real decision, or whose the decider key is",
                                 "that the issuer kept every claim it was sent; the log shows what it wrote"]
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    if prob:
        return 1
    return 0 if (not online_needed or a.slot or rep.get("anchored")) else 1


if __name__ == "__main__":
    sys.exit(main())
