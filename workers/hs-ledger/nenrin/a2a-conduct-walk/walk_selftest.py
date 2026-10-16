#!/usr/bin/env python3
"""walk_selftest.py : offline red team for a2a_conduct_walk.py. No network. Deterministic.

    python3 walk_selftest.py

Mocks the transport, walks eleven agents (honest and dishonest), and checks that the walk
says PASS only for the honest ones, names the failing assertion for the others, produces the
same canonical bytes twice for the same input, satisfies the ledger's witness intake rules,
and is counted by make_ring.py for the endpoint it touched (and listed as a discrepancy when
its verdict is not ok). Exit 1 on any miss.
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import a2a_conduct_walk as W  # noqa: E402

RING_DIR = os.path.join(HERE, "..", "ring-v1")
sys.path.insert(0, RING_DIR)
try:
    import make_ring  # noqa: E402
except Exception:
    make_ring = None

EXT = W.EXT_URI
ORIGIN = "https://agent.selftest.invalid"
EP = ORIGIN + "/mcp"
A2A_URL = ORIGIN + "/a2a"
REC = "https://gate.horizonshield.dev/history?endpoint=x"
INTAKE = "https://ledger.horizonshield.dev/witness"
COMP = {"paid_by": "buyer", "referral_fee": False, "listing_fee": False, "success_fee_pct": 0, "disclosure_url": "https://example.invalid/d"}


def card(comp=COMP, ext=True, top=None, required=False, measured=None, extra=None, uri=None, sigs=None):
    c = {"name": "Selftest Agent", "description": "mock", "url": ORIGIN, "capabilities": {"streaming": False}}
    if ext:
        c["capabilities"]["extensions"] = [{"uri": uri or EXT, "description": "conduct", "required": required, "params": {
            "compensation": comp, "measured_endpoints": measured if measured is not None else [EP],
            "conduct_record": REC, "witness_intake": INTAKE}}]
    if top is not None:
        c["compensation"] = top
    if sigs is not None:
        c["signatures"] = sigs
    if extra:
        c.update(extra)
    return c


def b64u(obj):
    import base64 as _b
    return _b.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")


def card_sig(kid="sel-2026-09", alg="ES256", jku=ORIGIN + "/.well-known/jwks.json"):
    hdr = {"alg": alg, "typ": "JOSE", "kid": kid}
    if jku is not None:
        hdr["jku"] = jku
    return [{"protected": b64u(hdr), "signature": "not-checked-by-this-client"}]


def honest_meta(url, **over):
    """conduct-v1.4. What an honest server writes: section 3's three keys plus served_by = where the request arrived."""
    m = {EXT + "/endpoint": EP, EXT + "/conduct_record": REC, EXT + "/witness_intake": INTAKE, EXT + "/served_by": url}
    for k, v in over.items():
        if v is None:
            m.pop(EXT + "/" + k, None)
        else:
            m[EXT + "/" + k] = v
    return m


def mock(cards, ep_status=200, ep_result=True, echo=True, submit_status=200, echo_spelling="mirror", answer_shape="wire",
         meta="honest", serve_at=(EP,), task=None):
    """cards: list of card objects returned in order for successive GETs (last one repeats).

    echo_spelling: "mirror" (honest: A2A-Extensions always, plus X-A2A-Extensions when the request used it),
                   "new_only" (a server that only knows the 1.0 spelling: a 0.3 client never sees the echo),
                   "old_only" (a 0.3-era server that only echoes X-A2A-Extensions).
    answer_shape:  "wire" (honest: 1.0 shape to SendMessage, 0.3 shape to message/send),
                   "0.3" (always the kind-shaped result, even to SendMessage: what our own servers did before 2026-09-06),
                   "1.0" (always the wrapped result, even to message/send).
    meta:          conduct-v1.4. "honest" (honest_meta at the URL hit), None (no metadata), or a function url -> dict.
                   Attached only to an activated A2A message, as the real servers do.
    serve_at:      the URLs that answer POST (default only the measured endpoint EP).
    task:          None (answer with a Message), "task" (a Task carrying metadata), "status" (a Task whose
                   status.message carries it).
    """
    state = {"i": 0, "posts": []}

    def fetch(method, url, headers=None, body=None):
        if method == "GET" and url.endswith("/.well-known/agent-card.json"):
            c = cards[min(state["i"], len(cards) - 1)]
            state["i"] += 1
            return 200, {"content-type": "application/json"}, json.dumps(c, ensure_ascii=False).encode("utf-8")
        if method == "POST" and url in serve_at:
            state["posts"].append((headers, body))
            h = {"content-type": "application/json"}
            hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}
            asked = hdrs.get("a2a-extensions") or hdrs.get("x-a2a-extensions")
            if echo and asked:
                if echo_spelling in ("mirror", "new_only"):
                    h["A2A-Extensions"] = asked
                if echo_spelling == "old_only" or (echo_spelling == "mirror" and "x-a2a-extensions" in hdrs):
                    h["X-A2A-Extensions"] = asked
            if ep_status != 200:
                return ep_status, h, b"<html>nope</html>"
            try:
                method_name = json.loads(body.decode("utf-8")).get("method")
            except Exception:
                method_name = None
            if not ep_result:
                j = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}}
            elif method_name in ("SendMessage", "message/send"):
                shape = answer_shape if answer_shape in ("0.3", "1.0") else ("1.0" if method_name == "SendMessage" else "0.3")
                md = (honest_meta(url) if meta == "honest" else meta(url) if callable(meta) else None) if asked else None
                if task:
                    t03 = {"kind": "task", "id": "t", "contextId": "c", "status": {"state": "completed"}}
                    t10 = {"id": "t", "contextId": "c", "status": {"state": "TASK_STATE_COMPLETED"}}
                    for t, sm in ((t03, {"kind": "message", "role": "agent", "messageId": "m", "parts": [{"kind": "text", "text": "ok"}]}),
                                  (t10, {"role": "ROLE_AGENT", "messageId": "m", "parts": [{"text": "ok"}]})):
                        if md is not None and task == "task":
                            t["metadata"] = md
                        if md is not None and task == "status":
                            sm["metadata"] = md
                            t["status"]["message"] = sm
                    j = {"jsonrpc": "2.0", "id": 1, "result": {"task": t10} if shape == "1.0" else t03}
                else:
                    msg03 = {"kind": "message", "role": "agent", "messageId": "m", "parts": [{"kind": "text", "text": "ok"}]}
                    msg10 = {"message": {"role": "ROLE_AGENT", "messageId": "m", "parts": [{"text": "ok"}]}}
                    if md is not None:
                        msg03["metadata"] = md
                        msg10["message"]["metadata"] = md
                    j = {"jsonrpc": "2.0", "id": 1, "result": msg10 if shape == "1.0" else msg03}
            else:
                j = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "mock"}}}
            return 200, h, json.dumps(j).encode("utf-8")
        if method == "POST" and url.endswith("/witness"):
            state["posts"].append((headers, body))
            return submit_status, {"content-type": "application/json"}, json.dumps({"sha": "x" * 64, "status": "pending"}).encode("utf-8")
        return 404, {}, b"not found"
    fetch.state = state
    return fetch


def results(rec):
    return {a["claim"].split(":")[0]: a["result"] for a in rec["assertions"]}


def ledger_shape_ok(rc):
    """Mirror of witnessValidate in hs-ledger/src/worker.js."""
    r = json.loads(rc)
    if r.get("schema") != "jidec-path-v1":
        return False
    for k in ("purpose", "walked_at", "base"):
        if not isinstance(r.get(k), str) or not r[k]:
            return False
    if not isinstance(r.get("nodes"), list) or not r["nodes"]:
        return False
    if not isinstance(r.get("assertions"), list) or not r["assertions"]:
        return False
    if not isinstance(r.get("verdict"), dict):
        return False
    w = r.get("witness")
    return isinstance(w, dict) and isinstance(w.get("name"), str) and w["name"] and isinstance(w.get("vantage"), str) and w["vantage"]


def ledger_v11_reason(rc):
    """Mirror of the conduct-v1.1 branches of witnessValidate (worker.js, 2026-09-07). Returns the
    reason_code the intake would answer, or None when the record passes those branches."""
    r = json.loads(rc)
    if "mode" not in r:
        return None
    if r["mode"] not in ("full", "hash-only", "commitment"):
        return "bad_mode"
    ok_list = lambda x: isinstance(x, list) and x and all(isinstance(s, str) and s.strip() for s in x)
    if not ok_list(r.get("establishes")) or not ok_list(r.get("does_not_establish")):
        return "disclaimer_missing"
    if r["mode"] == "commitment":
        c = r.get("commitment")
        if not (isinstance(c, str) and len(c) == 64 and all(ch in "0123456789abcdef" for ch in c)):
            return "bad_commitment"
    else:
        if not r.get("nodes") or not r.get("assertions") or not isinstance(r.get("verdict"), dict):
            return "schema"
    if r["mode"] == "hash-only":
        from urllib.parse import urlsplit
        for nd in r["nodes"]:
            req = nd.get("request") if isinstance(nd, dict) else None
            if not isinstance(req, dict):
                continue
            if "url" in req:
                s = urlsplit(req["url"])
                if (s.path and s.path != "/") or s.query or s.fragment:
                    return "path_leaks_tool"
            if "method" in req and req["method"] != "REDACTED":
                return "path_leaks_tool"
    ku = r["witness"].get("key_url")
    if ku is not None and not (isinstance(ku, str) and ku.startswith("https://")):
        return "bad_key_url"
    return None


V = []


def vec(name, kind, fetch, mode, expect_ok, expect_results, endpoint=None, wire="1.0"):
    V.append((name, kind, fetch, mode, expect_ok, expect_results, endpoint, wire))


vec("honest_mcp", "control", mock([card()]), "mcp", True, {"card_bytes_stable": True, "conduct_ext_declared": True, "compensation_well_formed": True, "measured_endpoint_answered": True, "extension_echoed": None, "metadata_echoed": None, "endpoint_bound": None})
vec("honest_a2a", "control", mock([card()]), "a2a", True, {"extension_echoed": True, "metadata_echoed": True, "endpoint_bound": True})
vec("honest_a2a_top_level_copy_equal", "control", mock([card(top=dict(COMP))]), "a2a", True, {"compensation_well_formed": True})
vec("card_changes_between_fetches", "attack", mock([card(), card(extra={"description": "mock v2"})]), "mcp", False, {"card_bytes_stable": False})
# conduct-v1.3 (2026-09-11): this vector used to expect compensation_well_formed False, and that
# expectation was the bug written down. The card's top-level compensation here is flawless; the
# missing extension is conduct_ext_declared's whole job. A walk that answers a question about
# field A with the reason for field B is the fault named in the reply about key_urls_checked,
# one tool over. The record is still FAIL, for the one reason that is true.
vec("no_extension_declared", "attack", mock([card(ext=False, top=dict(COMP))]), "mcp", False, {"conduct_ext_declared": False, "compensation_well_formed": True, "measured_endpoint_answered": True}, endpoint=EP)
vec("no_extension_and_top_level_malformed", "attack", mock([card(ext=False, top=dict(COMP, paid_by="Buyer"))]), "mcp", False, {"conduct_ext_declared": False, "compensation_well_formed": False}, endpoint=EP)
vec("no_compensation_anywhere_is_not_applicable", "attack", mock([card(ext=False)]), "mcp", False, {"conduct_ext_declared": False, "compensation_well_formed": None}, endpoint=EP)
vec("no_extension_no_endpoint_given", "attack", mock([card(ext=False)]), "mcp", False, {"conduct_ext_declared": False, "measured_endpoint_answered": False})
# spec section 12 (2026-09-09): the w3id.org permanent identifier is the same extension; nothing else is.
vec("perma_id_declared", "control", mock([card(uri=W.EXT_PERMANENT_ID)]), "a2a", True, {"conduct_ext_declared": True, "compensation_well_formed": True, "extension_echoed": True})
vec("perma_id_next_version_is_not_this_one", "attack", mock([card(uri="https://w3id.org/horizonshield/conduct/v2")]), "mcp", False, {"conduct_ext_declared": False}, endpoint=EP)
vec("perma_id_foreign_project", "attack", mock([card(uri="https://w3id.org/someoneelse/conduct/v1")]), "mcp", False, {"conduct_ext_declared": False}, endpoint=EP)
vec("compensation_paid_by_case", "attack", mock([card(comp=dict(COMP, paid_by="Buyer"))]), "mcp", False, {"compensation_well_formed": False})
vec("compensation_success_fee_string", "attack", mock([card(comp=dict(COMP, success_fee_pct="see site"))]), "mcp", False, {"compensation_well_formed": False})
vec("top_level_disagrees", "attack", mock([card(top=dict(COMP, paid_by="referral"))]), "mcp", False, {"compensation_well_formed": False})
vec("declared_required_true", "attack", mock([card(required=True)]), "mcp", False, {"compensation_well_formed": False})
vec("measured_endpoints_empty", "attack", mock([card(measured=[])]), "mcp", False, {"compensation_well_formed": False, "measured_endpoint_answered": False})
vec("endpoint_http_500", "attack", mock([card()], ep_status=500), "mcp", False, {"measured_endpoint_answered": False})
vec("endpoint_jsonrpc_error", "attack", mock([card()], ep_result=False), "mcp", False, {"measured_endpoint_answered": False})
vec("a2a_declared_but_not_echoed", "attack", mock([card()], echo=False), "a2a", False, {"extension_echoed": False})
vec("mcp_mode_no_echo_is_not_applicable", "control", mock([card()], echo=False), "mcp", True, {"extension_echoed": None})
# 2026-09-06 second wave: two spellings of the header, two versions of the wire
vec("honest_a2a_wire03", "control", mock([card()]), "a2a", True, {"measured_endpoint_answered": True, "extension_echoed": True}, wire="0.3")
vec("a2a_wire03_server_echoes_new_spelling_only", "attack", mock([card()], echo_spelling="new_only"), "a2a", False, {"extension_echoed": False}, wire="0.3")
vec("a2a_wire10_server_echoes_old_spelling_only", "attack", mock([card()], echo_spelling="old_only"), "a2a", False, {"extension_echoed": False}, wire="1.0")
vec("a2a_wire10_server_answers_03_shape", "attack", mock([card()], answer_shape="0.3"), "a2a", False, {"measured_endpoint_answered": False, "extension_echoed": True}, wire="1.0")
vec("a2a_wire03_server_answers_10_shape", "attack", mock([card()], answer_shape="1.0"), "a2a", False, {"measured_endpoint_answered": False}, wire="0.3")
# conduct-v1.3 (2026-09-11), 402. Found by walking api.babyblueviper.com, which charges and says
# so. Every fixture above is free, which is why 47 green vectors saw nothing. A walk never pays:
# a witness that pays the agent it walks has the relationship this layer exists to disclose.
vec("paid_endpoint_402_declared", "control", mock([card(extra={"x402": True})], ep_status=402), "mcp", True,
    {"measured_endpoint_answered": None, "payment_required_as_declared": True})
vec("paid_endpoint_402_undeclared", "attack", mock([card(comp=dict(COMP, paid_by="public"))], ep_status=402), "mcp", False,
    {"measured_endpoint_answered": None, "payment_required_as_declared": False})
vec("free_endpoint_makes_no_payment_claim", "control", mock([card(comp=dict(COMP, paid_by="public"))]), "mcp", True,
    {"measured_endpoint_answered": True, "payment_required_as_declared": None})
vec("paid_card_answered_without_charging", "control", mock([card(extra={"x402": True})]), "mcp", True,
    {"measured_endpoint_answered": True, "payment_required_as_declared": None})
# 402 must not become a way to stop being measured. Without the undeclared row above, an agent
# could answer 402 to everything and take n/a on the endpoint assertion for ever.
vec("402_does_not_hide_a_missing_extension", "attack", mock([card(ext=False, top=dict(COMP))], ep_status=402), "mcp", False,
    {"conduct_ext_declared": False, "measured_endpoint_answered": None, "payment_required_as_declared": True}, endpoint=EP)
vec("500_is_still_a_failure_not_a_payment", "attack", mock([card(extra={"x402": True})], ep_status=500), "mcp", False,
    {"measured_endpoint_answered": False, "payment_required_as_declared": None})
# conduct-v1.4 (2026-09-28, section 14). Found by a walk from outside, against our own gate: /a2a answered
# with .../endpoint = /mcp, and this client passed it 5 of 5 because no vector above ever carried metadata,
# and the client never read it. Every vector above now carries honest metadata unless it says otherwise.
vec("v14_honest_metadata_bound_wire10", "control", mock([card()]), "a2a", True, {"metadata_echoed": True, "endpoint_bound": True})
vec("v14_honest_metadata_bound_wire03", "control", mock([card()]), "a2a", True, {"metadata_echoed": True, "endpoint_bound": True}, wire="0.3")
vec("v14_honest_task_carries_metadata", "control", mock([card()], task="task"), "a2a", True, {"measured_endpoint_answered": True, "metadata_echoed": True, "endpoint_bound": True})
vec("v14_honest_task_status_message_carries_it", "control", mock([card()], task="status"), "a2a", True, {"metadata_echoed": True, "endpoint_bound": True}, wire="0.3")
# the fault as found: A2A served at a URL that is not measured, .../endpoint naming the measured one, no served_by
vec("v14_found_a2a_not_measured_no_served_by", "attack", mock([card()], serve_at=(A2A_URL,), meta=lambda u: honest_meta(u, served_by=None)), "a2a", False,
    {"metadata_echoed": True, "endpoint_bound": False}, endpoint=A2A_URL)
vec("v14_fixed_a2a_not_measured_with_served_by", "control", mock([card()], serve_at=(A2A_URL,)), "a2a", True,
    {"metadata_echoed": True, "endpoint_bound": True}, endpoint=A2A_URL)
vec("v14_pre_v14_agent_at_measured_endpoint_without_served_by", "control", mock([card()], meta=lambda u: honest_meta(u, served_by=None)), "a2a", True,
    {"metadata_echoed": True, "endpoint_bound": True})
vec("v14_served_by_names_another_url", "attack", mock([card()], meta=lambda u: honest_meta(u, served_by=A2A_URL)), "a2a", False,
    {"metadata_echoed": True, "endpoint_bound": False})
vec("v14_host_case_and_port_443_are_the_same_url", "control", mock([card()], meta=lambda u: honest_meta(u, served_by="https://AGENT.Selftest.invalid:443/mcp")), "a2a", True,
    {"endpoint_bound": True})
vec("v14_trailing_slash_is_a_different_path", "attack", mock([card()], meta=lambda u: honest_meta(u, served_by=EP + "/")), "a2a", False,
    {"endpoint_bound": False})
vec("v14_metadata_missing_wire10", "attack", mock([card()], meta=None), "a2a", False, {"extension_echoed": True, "metadata_echoed": False, "endpoint_bound": None})
vec("v14_metadata_missing_wire03", "attack", mock([card()], meta=None), "a2a", False, {"metadata_echoed": False, "endpoint_bound": None}, wire="0.3")
vec("v14_keys_under_the_permanent_identifier", "attack",
    mock([card()], meta=lambda u: {W.EXT_PERMANENT_ID + k[len(EXT):]: v for k, v in honest_meta(u).items()}), "a2a", False,
    {"metadata_echoed": False, "endpoint_bound": None})
vec("v14_endpoint_not_on_the_card", "attack", mock([card()], meta=lambda u: honest_meta(u, endpoint=ORIGIN + "/other")), "a2a", False,
    {"metadata_echoed": False, "endpoint_bound": True})
vec("v14_conduct_record_differs_from_the_card", "attack", mock([card()], meta=lambda u: honest_meta(u, conduct_record="https://elsewhere.invalid/history")), "a2a", False,
    {"metadata_echoed": False, "endpoint_bound": True})
vec("v14_402_in_a2a_mode_both_stand_aside", "control", mock([card(extra={"x402": True})], ep_status=402), "a2a", True,
    {"measured_endpoint_answered": None, "payment_required_as_declared": True, "metadata_echoed": None, "endpoint_bound": None})
vec("v14_no_extension_nothing_obliges_the_echo", "attack", mock([card(ext=False, top=dict(COMP))], meta=None), "a2a", False,
    {"conduct_ext_declared": False, "metadata_echoed": None, "endpoint_bound": None}, endpoint=EP)


def main():
    bad = []
    n = 0
    for name, kind, fetch, mode, expect_ok, expect_results, endpoint, wire in V:
        n += 1
        rec = W.walk(ORIGIN, endpoint, mode, "selftest", "offline-mock", fetch=fetch, walked_at="2026-09-06T00:00:00Z", wire=wire)
        if mode == "a2a":
            sent = {str(k).lower() for k, _b in fetch.state["posts"][:1] for k in (k or {})}
            want = "a2a-extensions" if wire == "1.0" else "x-a2a-extensions"
            other = "x-a2a-extensions" if wire == "1.0" else "a2a-extensions"
            if not (want in sent and other not in sent):
                bad.append((name, "walk sent the wrong header spelling for wire " + wire + ": " + str(sorted(sent))))
        res = results(rec)
        problems = []
        if rec["verdict"]["ok"] is not expect_ok:
            problems.append("verdict.ok %s != %s" % (rec["verdict"]["ok"], expect_ok))
        if (rec["verdict"]["outcome"] == "PASS") is not rec["verdict"]["ok"]:
            problems.append("outcome and ok disagree")
        applicable = [a for a in rec["assertions"] if a["result"] is not None]
        if rec["verdict"]["n_total"] != len(applicable) or rec["verdict"]["n_pass"] != sum(1 for a in applicable if a["result"] is True):
            problems.append("counts wrong")
        for k, v in expect_results.items():
            if res.get(k, "missing") is not v:
                problems.append("%s=%s expected %s" % (k, res.get(k, "missing"), v))
        rc = W.canonical(rec)
        if not ledger_shape_ok(rc):
            problems.append("record would be refused by the ledger's witness intake rules")
        # request to the endpoint carried the activation header
        want_hdr = "X-A2A-Extensions" if (mode == "a2a" and wire == "0.3") else "A2A-Extensions"
        posts = [h for h, b in fetch.state["posts"] if h and h.get(want_hdr) == EXT]
        has_n3 = any(nd.get("n") == 3 for nd in rec["nodes"])
        if has_n3 and not posts:
            problems.append("node 3 did not send " + want_hdr)
        if not has_n3 and expect_results.get("measured_endpoint_answered") is True:
            problems.append("no node 3 although an answer was expected")
        if problems:
            bad.append(name + ": " + " / ".join(problems))
            print("  RED    %-6s %-40s << %s" % ("LEAK" if kind == "attack" else "WRONG", name, " / ".join(problems)))
        else:
            print("  green  %-6s %-40s (%s %d/%d)" % ("BLOCK" if kind == "attack" else "PASS", name, rec["verdict"]["outcome"], rec["verdict"]["n_pass"], rec["verdict"]["n_total"]))

    # determinism: same input, same walked_at, same bytes
    n += 1
    r1 = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-06T00:00:00Z")
    r2 = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-06T00:00:00Z")
    c1, c2 = W.canonical(r1), W.canonical(r2)
    for nd in json.loads(c1)["nodes"]:
        nd.pop("duration_ms", None)
    for nd in json.loads(c2)["nodes"]:
        nd.pop("duration_ms", None)
    strip = lambda c: W.canonical({**json.loads(c), "nodes": [{k: v for k, v in nd.items() if k != "duration_ms"} for nd in json.loads(c)["nodes"]]})
    if strip(c1) == strip(c2):
        print("  green  PASS   %-40s (sha %s)" % ("deterministic_bytes_modulo_duration", W.sha256_hex(strip(c1))[:16]))
    else:
        bad.append("deterministic_bytes_modulo_duration"); print("  RED    WRONG  deterministic_bytes_modulo_duration")

    # ring builder compatibility
    n += 1
    if make_ring is None:
        print("  skip   ----   make_ring_counts_the_walk (ring-v1/make_ring.py not found next to this directory)")
    else:
        ok_rec = W.walk(ORIGIN, None, "mcp", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-06T00:00:00Z")
        bad_rec = W.walk(ORIGIN, None, "mcp", "selftest", "offline-mock", fetch=mock([card()], ep_status=500), walked_at="2026-09-06T00:00:00Z")
        probs = []
        for rec, want_disc in ((ok_rec, False), (bad_rec, True)):
            rc = W.canonical(rec)
            stored = {"sha": W.sha256_hex(rc), "witness_name": "selftest", "vantage": "offline-mock", "submitted_at": "2026-09-06T00:00:01Z", "record_canonical": rc}
            w = make_ring.normalise_witness(stored)
            if not w or not make_ring.witness_covers(w, EP):
                probs.append("walk not counted for " + EP)
            if bool(w and w.get("discrepancy_sha256")) is not want_disc:
                probs.append("discrepancy flag %s, wanted %s" % (bool(w and w.get("discrepancy_sha256")), want_disc))
            if w and make_ring.witness_covers(w, "https://other.selftest.invalid/mcp"):
                probs.append("walk counted for a foreign endpoint")
        if probs:
            bad.append("make_ring_counts_the_walk: " + " / ".join(probs)); print("  RED    WRONG  make_ring_counts_the_walk << " + " / ".join(probs))
        else:
            print("  green  PASS   %-40s (counted for %s, discrepancy only when ok is false, not counted elsewhere)" % ("make_ring_counts_the_walk", EP))

    # conduct-v1.1 (2026-09-07): mode, disclaimers, hash-only redaction, commitment, signing.
    def v11(name, cond, detail=""):
        nonlocal n
        n += 1
        if cond:
            print("  green  PASS   %-40s %s" % (name, detail))
        else:
            bad.append(name + (": " + detail if detail else "")); print("  RED    WRONG  %-40s << %s" % (name, detail))

    full = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-07T00:00:00Z")
    v11("v11_full_record_carries_mode_and_disclaimers",
        full.get("mode") == "full" and isinstance(full.get("establishes"), list) and len(full["establishes"]) == 3
        and W.DOES_NOT_ESTABLISH_UNSIGNED in full["does_not_establish"] and all(s in full["does_not_establish"] for s in W.DOES_NOT_ESTABLISH_ALWAYS),
        "mode=%s establishes=%d dne=%d" % (full.get("mode"), len(full.get("establishes") or []), len(full.get("does_not_establish") or [])))
    v11("v11_full_record_passes_intake_v11_rules", ledger_v11_reason(W.canonical(full)) is None, str(ledger_v11_reason(W.canonical(full))))
    dropped = json.loads(W.canonical(full)); dropped.pop("does_not_establish")
    v11("v11_disclaimer_dropped_is_refused", ledger_v11_reason(W.canonical(dropped)) == "disclaimer_missing" and ledger_shape_ok(W.canonical(dropped)),
        "still v1 shape-valid, refused by the v1.1 branch")

    ho = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-07T00:00:00Z", privacy="hash-only")
    leaks = [nd["request"].get("url") for nd in ho["nodes"] if nd.get("kind") == "fetch" and nd["request"].get("url") != ORIGIN + "/"]
    meth = [nd["request"].get("method") for nd in ho["nodes"] if nd.get("kind") == "fetch" and nd["request"].get("method") != "REDACTED"]
    hashes = [k for nd in ho["nodes"] if nd.get("kind") == "fetch" for k in ("headers_sha256", "body_sha256") if k in nd["request"]]
    claims_leak = [a["claim"] for a in ho["assertions"] if "/mcp" in a["claim"]]
    v11("v11_hash_only_names_no_tool", not leaks and not meth and not hashes and not claims_leak and ho["mode"] == "hash-only"
        and W.DOES_NOT_ESTABLISH_HASH_ONLY in ho["does_not_establish"] and ho["purpose"].endswith(EP),
        "urls=%s methods=%s reqhashes=%s claims=%s" % (leaks, meth, hashes, len(claims_leak)))
    v11("v11_hash_only_passes_intake_v11_rules", ledger_v11_reason(W.canonical(ho)) is None, str(ledger_v11_reason(W.canonical(ho))))
    v11("v11_hash_only_keeps_response_hashes_and_verdict",
        all(nd["response"].get("body_sha256") for nd in ho["nodes"] if nd.get("kind") == "fetch") and ho["verdict"]["ok"] is True and ho["verdict"]["n_total"] == 7)
    leaky = json.loads(W.canonical(ho)); leaky["nodes"][3]["request"]["url"] = EP
    v11("v11_hash_only_with_a_path_is_refused", ledger_v11_reason(W.canonical(leaky)) == "path_leaks_tool")

    # v1.2 (2026-09-09): which spelling the card used is written into the record, never silently normalised.
    canon_walk = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-09T00:00:00Z")
    perma_walk = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card(uri=W.EXT_PERMANENT_ID)]), walked_at="2026-09-09T00:00:00Z")
    v11("v12_record_names_the_declared_spelling",
        canon_walk["conduct_ext"]["declared_uri"] == W.EXT_URI and perma_walk["conduct_ext"]["declared_uri"] == W.EXT_PERMANENT_ID
        and perma_walk["conduct_ext"]["uri"] == W.EXT_URI and perma_walk["verdict"]["ok"] is True,
        "identifier stays %s, declared spelling recorded" % W.EXT_URI)
    v11("v12_perma_id_record_still_passes_intake", ledger_v11_reason(W.canonical(perma_walk)) is None and ledger_shape_ok(W.canonical(perma_walk)),
        str(ledger_v11_reason(W.canonical(perma_walk))))
    v11("v12_walk_never_fetches_the_redirect",
        not any("w3id.org" in str(nd.get("request", {}).get("url") or "") for nd in perma_walk["nodes"]),
        "nodes touch only the walked origin")

    # 第四波 4a-1 (2026-09-10): 歩いた card の署名を読む。真偽は出さん。
    unsigned = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-10T00:00:00Z")
    signed = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card(sigs=card_sig())]), walked_at="2026-09-10T00:00:00Z")
    v11("v13_unsigned_card_is_not_a_finding",
        unsigned["card_signature"]["present"] is False and unsigned["card_signature"]["verified"] is None
        and "does not require" in unsigned["card_signature"]["verified_reason"],
        json.dumps(unsigned["card_signature"], ensure_ascii=False)[:90])
    cs = signed["card_signature"]
    v11("v13_signed_card_header_is_read_and_unverifiable_is_null",
        cs["present"] is True and cs["count"] == 1 and cs["alg"] == "ES256" and cs["kid"] == "sel-2026-09"
        and cs["jku_same_host"] is True and cs["protected_readable"] is True and cs["verified"] is None
        and cs["verified_reason"].startswith("not established") and "was not fetched" in cs["verified_reason"],
        json.dumps(cs, ensure_ascii=False)[:160])
    v11("v13_signed_card_record_still_passes_intake",
        ledger_v11_reason(W.canonical(signed)) is None and ledger_shape_ok(W.canonical(signed)),
        str(ledger_v11_reason(W.canonical(signed))))
    foreign = W.read_card_signature(card(sigs=card_sig(jku="https://elsewhere.selftest.invalid/jwks.json")), ORIGIN, "full")
    v11("v13_foreign_jku_is_recorded_as_not_same_host", foreign["jku_same_host"] is False and foreign["verified"] is None)
    broken = W.read_card_signature({"signatures": [{"protected": "not base64 at all", "signature": "x"}]}, ORIGIN, "full")
    v11("v13_unreadable_header_does_not_crash_and_claims_nothing",
        broken["present"] is True and broken["protected_readable"] is False and broken["kid"] is None
        and broken["alg"] is None and broken["jku_same_host"] is None and broken["verified"] is None,
        json.dumps(broken, ensure_ascii=False)[:90])
    ho_sig = W.read_card_signature(card(sigs=card_sig()), ORIGIN, "hash-only")
    v11("v13_hash_only_drops_the_url_and_keeps_the_host_fact",
        ho_sig["jku"] is None and ho_sig["jku_same_host"] is True and ho_sig["kid"] == "sel-2026-09")
    v11("v13_unsigned_card_costs_attribution_not_a_pass",
        any("can repudiate them" in x for x in unsigned["does_not_establish"])
        and unsigned["verdict"]["ok"] is True
        and not any("card_signature" in a["claim"] for a in unsigned["assertions"]),
        "無署名は assertion にせん。does_not_establish に「この歩きに帰属するだけ」と書くだけ")
    v11("v13_signed_but_unverified_uses_the_other_wording",
        any("could not verify it" in x for x in signed["does_not_establish"])
        and not any("carried no signature" in x for x in signed["does_not_establish"]),
        "署名ありで検証できんかった時と、そもそも署名が無い時は別の事実。文を分ける")
    v11("v13_no_verdict_either_way_when_nothing_could_be_checked",
        all('"verified":true' not in W.canonical(r) and '"verified":false' not in W.canonical(r) for r in (unsigned, signed)),
        "the mock serves no JWKS: neither true nor false may be written")

    # cs1 (2026-10-16): verify the card signature in the forms this client reproduces. Found by Sankalp Gilda's walk
    # of gate.horizonshield.dev with his own verifier (probityai/agent-evidence-vectors#55): the record said "signed"
    # and could not say by whom. The card and JWKS here are the gate's own public bytes (fixtures_live_card).
    here = os.path.dirname(os.path.abspath(__file__))
    gfix = os.path.join(here, "..", "..", "..", "hs-verify-gate", "test", "fixtures_live_card")
    gcard = json.load(open(os.path.join(gfix, "card.json"), encoding="utf-8"))
    gjwks = open(os.path.join(gfix, "jwks.json"), "rb").read()
    G = "https://gate.horizonshield.dev"
    sdk_on = W.sdk_form({"name": "x"}) is not None

    def jfetch(served=gjwks):
        def f(method, url, headers=None, body=None):
            return (200, {}, served) if url == G + "/.well-known/jwks.json" else (404, {}, b"")
        return f
    live = W.read_card_signature(gcard, G, "full", fetch=jfetch())
    rows = {r["index"]: r for r in live.get("signatures", [])}
    v11("cs1_gate_card_signature_0_verifies_over_the_served_bytes",
        live["verified"] is True and "served-rfc8785" in rows[0]["verified_in"] and live["covers_compensation"] is True
        and live["form_payload_sha256"]["served-rfc8785"] == "c577d9bbd59c868dd3ad09ea56d97d9ed5990e3ffb356f9716eae6359f95dfac",
        live["verified_reason"])
    v11("cs1_gate_card_signature_1_verifies_in_the_sdk_form_when_a2a_sdk_is_present",
        (not sdk_on) or ("a2a-sdk-proto" in rows[1]["verified_in"] and live["form_payload_sha256"]["a2a-sdk-proto"] ==
                         "093ed47a1c1d9f559dd4f616d46cf35661c9d166de09372d1495db15b8090b20"),
        "a2a-sdk present" if sdk_on else "a2a-sdk not installed: the SDK form is not checked, and the record says so")
    v11("cs1_each_signature_fails_the_other_form",
        "a2a-sdk-proto" not in rows[0]["verified_in"] and "served-rfc8785" not in rows[1]["verified_in"])
    tc = json.loads(json.dumps(gcard)); tc["compensation"]["model"] = "edited-after-signing"
    tamp = W.read_card_signature(tc, G, "full", fetch=jfetch())
    v11("cs1_compensation_edited_after_signing_is_not_covered",
        (tamp["verified"] is True and tamp["covers_compensation"] is False) if sdk_on else tamp["verified"] is None,
        tamp["verified_reason"][:120])
    tn = json.loads(json.dumps(gcard)); tn["name"] = "edited"
    tamp2 = W.read_card_signature(tn, G, "full", fetch=jfetch())
    v11("cs1_schema_field_edited_is_false_only_when_both_forms_were_tried",
        tamp2["verified"] is (False if sdk_on else None), str(tamp2["verified"]) + " " + tamp2["verified_reason"][:100])
    other = W.read_card_signature(gcard, G, "full", fetch=jfetch(json.dumps({"keys": []}).encode()))
    v11("cs1_a_jwks_without_the_kid_is_null_not_false", other["verified"] is None and "no key with this kid" in other["verified_reason"])
    flip = json.loads(json.dumps(gcard)); s0 = flip["signatures"][0]["signature"]
    flip["signatures"][0]["signature"] = ("B" if s0[0] == "A" else "A") + s0[1:]
    rflip = W.read_card_signature(flip, G, "full", fetch=jfetch())
    v11("cs1_a_flipped_signature_does_not_verify", "served-rfc8785" not in {r["index"]: r for r in rflip["signatures"]}[0]["verified_in"])
    try:
        W.rfc8785({"x": 1.5}); refused = False
    except W.NotReproducible:
        refused = True
    v11("cs1_a_non_integer_number_is_refused_not_guessed", refused)
    try:
        import rfc8785 as ref
    except Exception:
        ref = None
    corpus = os.path.join(here, "..", "..", "..", "a2a-card-sign", "interop-matrix", "vectors", "a2a-card-sign-v01")
    man = json.load(open(os.path.join(corpus, "MANIFEST.json"), encoding="utf-8"))
    tkey = man["test_key"]["jwk"] if isinstance(man.get("test_key"), dict) and isinstance(man["test_key"].get("jwk"), dict) else None
    agree = verified_n = same_bytes = total_v = 0
    for item in man["vectors"]:
        vec = json.load(open(os.path.join(corpus, item["path"]), encoding="utf-8"))
        bare = {k: v for k, v in vec["served_card"].items() if k != "signatures"}
        try:
            mine = W.rfc8785(bare)
        except W.NotReproducible:
            continue
        total_v += 1
        if ref is not None and ref.dumps(bare) == mine.encode("utf-8"):
            agree += 1
        if mine.encode("utf-8").hex() == vec["canonical_utf8_hex"]:
            same_bytes += 1
            reject = vec.get("disposition") == "MUST-REJECT"
            for s in vec["served_card"].get("signatures", []):
                si = (s["protected"] + "." + W.base64.urlsafe_b64encode(mine.encode("utf-8")).decode().rstrip("=")).encode()
                ok = bool(tkey) and W.es256_verify(tkey, si, s["signature"]) is True
                verified_n += 1 if ok != reject else 0
    v11("cs1_rfc8785_matches_the_rfc8785_package_on_every_corpus_card", ref is None or agree == total_v,
        "%d/%d" % (agree, total_v) if ref is not None else "rfc8785 package not installed")
    v11("cs1_es256_answers_every_corpus_signature_over_its_served_bytes_as_disposed", same_bytes > 0 and tkey is not None and verified_n >= same_bytes,
        "%d vectors whose canonical bytes are the served bytes, %d signatures answer as their disposition says (MUST-REJECT ones fail)" % (same_bytes, verified_n))

    salt = "ab" * 32
    cm = W.commitment_record(full, salt)
    recomputed = W.sha256_hex(W.canonical(full).encode("utf-8") + bytes.fromhex(salt))
    v11("v11_commitment_record_shape", cm["mode"] == "commitment" and cm["commitment"] == recomputed and "nodes" not in cm
        and W.DOES_NOT_ESTABLISH_COMMITMENT in cm["does_not_establish"] and cm["purpose"] == full["purpose"] and ledger_v11_reason(W.canonical(cm)) is None,
        "commitment " + cm["commitment"][:16])
    v11("v11_commitment_reveals_nothing", all(k not in W.canonical(cm) for k in ("body_sha256", "assertions", "card_bytes", "headers_sha256", "\"nodes\"")),
        "no node, no assertion, no response hash in the filed bytes (the purpose keeps the endpoint so the ring can attribute it)")

    try:
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import tempfile
        k = Ed25519PrivateKey.generate()
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as f:
            f.write(pem); kp = f.name
        key, pub = W.load_signing_key(kp)
        signed = W.walk(ORIGIN, None, "a2a", "selftest", "offline-mock", fetch=mock([card()]), walked_at="2026-09-07T00:00:00Z",
                        key_url="https://witness.selftest.invalid/.well-known/nenrin-witness-key.json")
        sc = W.canonical(signed)
        sig = W.sign_canonical(key, sc)
        k.public_key().verify(base64.b64decode(sig), sc.encode("utf-8"))
        v11("v11_signed_record_binds_key_url_and_drops_identity_disclaimer",
            signed["witness"]["key_url"].startswith("https://witness.selftest.invalid/") and W.DOES_NOT_ESTABLISH_UNSIGNED not in signed["does_not_establish"]
            and len(base64.b64decode(pub)) == 32 and ledger_v11_reason(sc) is None, "signature verifies with the served public key")
        os.unlink(kp)
    except ImportError:
        print("  skip   ----   v11_signed_record (cryptography not installed; signing is optional)")

    # conduct-v1.3 (2026-09-11). The assertion list lives in three places: this client,
    # section 4 of CONDUCT_EXT_v1.md, and the gate's published JSON. Nothing compared them,
    # so when this client grew payment_required_as_declared the other two silently did not.
    # d01 and d02 are the easy half. d03 is the half that matters: today's real fault was a
    # DEFINITION mismatch, the spec saying "status 200" while the client had learned that a
    # 402 is an answer, and a guard that only compared names would have stayed green through
    # the whole thing.
    def _probe(method, url, headers=None, body=None):
        if method == "GET":
            return 200, {}, json.dumps({"name": "x", "url": "https://a.invalid",
                                        "capabilities": {}}).encode("utf-8")
        return 200, {}, b'{"jsonrpc":"2.0","id":1,"result":{"message":{"role":"ROLE_AGENT","content":[]}}}'
    emitted = [x["claim"].split(":")[0].strip() for x in
               W.walk("https://a.invalid", "https://a.invalid/a2a", "a2a", "n", "v",
                      fetch=_probe)["assertions"]]
    gate = os.path.join(HERE, "..", "..", "..", "hs-verify-gate")
    spec_path = os.path.join(gate, "ext", "CONDUCT_EXT_v1.md")
    worker_path = os.path.join(gate, "src", "worker.js")
    if not (os.path.exists(spec_path) and os.path.exists(worker_path)):
        v11("d00_spec_and_gate_are_where_this_guard_expects_them", False,
            "expects the horizon-shield layout; drop d00 to d03 if vendoring this client alone")
    else:
        spec_text = io.open(spec_path, encoding="utf-8").read()
        worker_text = io.open(worker_path, encoding="utf-8").read()
        m = re.search(r"- `assertions`.*?(?=\n- `|\n\n)", spec_text, re.S)
        in_spec = set(re.findall(r"`([a-z][a-z_]{5,})`", m.group(0))) if m else set()
        miss_s = [x for x in emitted if x not in in_spec]
        v11("d01_every_assertion_emitted_is_named_in_the_spec", not miss_s,
            "section 4 does not name: " + ", ".join(miss_s) if miss_s else "section 4 names all %d" % len(emitted))
        m2 = re.search(r"assertions: \[(.*?)\]", worker_text, re.S)
        in_gate = set(x.strip().strip('"').split(" ")[0] for x in m2.group(1).split(",")) if m2 else set()
        miss_g = [x for x in emitted if x not in in_gate]
        v11("d02_every_assertion_emitted_is_named_by_the_gate", not miss_g,
            "the gate's published list does not name: " + ", ".join(miss_g) if miss_g else "the gate names all %d" % len(emitted))
        m3 = re.search(r"`measured_endpoint_answered` \(([^)]*)\)", spec_text)
        d = m3.group(1) if m3 else ""
        v11("d03_the_spec_definition_of_measured_endpoint_answered_knows_402", "402" in d,
            "the spec still defines it by status 200 alone, so an endpoint that charges reads as "
            "non-conforming for charging" if "402" not in d else "the definition covers the paid case")
        # conduct-v1.4. The client now reads a metadata key the v1.3 documents never named. Same fault
        # class as 13.5, one field over: check that both documents name it.
        m4 = re.search(r"metadata_keys: \[(.*?)\]", worker_text, re.S)
        v11("d04_served_by_is_named_by_the_spec_and_by_the_gate",
            "`.../served_by`" in spec_text and "/conduct/v1/served_by`" in spec_text and bool(m4) and "served_by" in m4.group(1),
            "spec section 3/14 and the gate's metadata_keys both name served_by" if (m4 and "served_by" in m4.group(1)) else "the gate's metadata_keys does not name served_by")

    total = n
    print("\n=== %d / %d 合格 (a2a_conduct_walk.py) ===" % (total - len(bad), total))
    if bad:
        print("不適格 (fail-closed):")
        for b in bad:
            print("  - " + b)
        return 1
    print("正直な agent だけ PASS、崩れた agent は落ちる assertion を名指し、台帳の受理規則と年輪の数え方に合う。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
