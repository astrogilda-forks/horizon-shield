#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUSUBI companion for cA2A, profile v0.1: a refusal by the operator no longer decides anything.

Profile v0 proves an operator cheated once it has signed an entry: a later log that drops, changes or
leaves out that entry is shown by the operator's own signatures. What v0 could not touch was refusal. An
operator that never signs a revocation leaves the revoker with nothing to show, and the revocation never
takes effect. cA2A names the same hole: a supplier "can withhold a statement".

v0.1 adds one lane around the operator, for restrictions only:

  - A revocation or a use limit may be handed to independent witnesses named in the relying party's trust
    configuration. Each witness signs an acknowledgement naming the log, the item's digest and a Bitcoin
    block it had seen, and the acknowledgement is anchored in Bitcoin by anyone (the item's author can do it
    through public OpenTimestamps calendars). The operator plays no part.
  - Once the threshold of distinct witnesses is reached, the restriction is published at the height where
    that threshold is first met, whether or not the operator ever logs it.
  - A receipt is judged against it by blocks, not by the operator's clock: in force when published at or
    before the block the receipt says it had seen; not in force when published only after the receipt was
    anchored; otherwise the order is unresolved and the receipt is reported as such, never as within.
  - The operator must carry a witnessed restriction in any checkpoint whose as_of is at or after the time
    of the block max_merge_blocks after its publication. If it does not, the witnesses' and the operator's
    signatures show it (the checkpoint's anchor height is not when it was signed: anyone can anchor again).

Only restrictions use this lane. They only narrow what is allowed, so accepting one from outside the
sequencer can never widen anything. Uses and receipts still go through the operator's sequence.

What this does not remove: it needs threshold many trusted witnesses that really publish what they sign.
If all of them side with the operator, refusal is silent again. A responder that names a stale seen block,
and slow anchoring, widen the unresolved window; they cannot buy a within verdict.

Usage:
  companion_v0_1.py --selftest
  companion_v0_1.py --settle BUNDLE.json
"""
import argparse, hashlib, json, os, sys

import companion_v0 as c0
from companion_v0 import (Bad, jcs, sha256_hex, strict_value, load_strict, _nonneg, _is, _need, _fields,
                          body_of, check_sig, _block, parse_item, request_sha256, commitment_of,
                          verify_log, _ca2a, _parse_chain, _sigs_ok, HEX32, TIME_SLACK)
from ca2a_runtime.errors import CA2AError
from ca2a_runtime.delegation.revocation import RevocationSnapshot, RevocationStatement, credential_digest

v11 = c0.v11

PROFILE = "musubi.ca2a.companion.v0.1"
T_ACK = "musubi.ca2a.witness-ack.v0"
T_SETTLEMENT = c0.T_SETTLEMENT
MAX_WITNESSES = 32
MAX_RECORDS = 256
MAX_ACKS = 64
MAX_TOTAL_ACKS = 512                 # over the whole bundle
MAX_MERGE = 1008                     # one week of blocks
SOFT = ("revocation_published_late", "revocation_order_unresolved", "use_policy_order_unresolved")
RESTRICTIONS = frozenset(("revocation", "use-policy"))   # kinds the witnessed lane accepts


# ==== trust
def _trust(trust):
    v0_fields = {k: v for k, v in trust.items() if k not in ("witnesses", "witness_threshold",
                                                            "max_merge_blocks")} \
        if isinstance(trust, dict) else trust
    c0._trust(v0_fields)
    lane = [k for k in ("witnesses", "witness_threshold", "max_merge_blocks") if k in trust]
    if not lane:
        return
    if len(lane) != 3:
        raise Bad("bad_trust", "witnesses, witness_threshold and max_merge_blocks go together")
    w = trust["witnesses"]
    if not (isinstance(w, list) and 1 <= len(w) <= MAX_WITNESSES and all(_is(HEX32, k) for k in w)
            and len(set(w)) == len(w)):
        raise Bad("bad_trust", "witnesses")
    if trust["operator"] in w:
        raise Bad("bad_trust", "the operator cannot witness its own log")
    t = trust["witness_threshold"]
    if not (_nonneg(t) and 1 <= t <= len(w)):
        raise Bad("bad_trust", "witness_threshold")
    m = trust["max_merge_blocks"]
    if not (_nonneg(m) and 1 <= m <= MAX_MERGE):
        raise Bad("bad_trust", "max_merge_blocks")


# ==== witnessed restrictions
def item_sha256(item):
    return sha256_hex(jcs(item))


def _ack(ack, digest, trust, res):
    """One acknowledgement. Returns (witness, seen_height or None, anchor_height or None, problems).
    A valid signature over a seen block in the view gives the lower bound (the witness signed after that
    block); a valid anchor gives the upper bound (it had signed by then). Each part counts on its own.
    Raises Bad when the signature itself does not count."""
    _fields(ack, ("type", "log_id", "witness", "item_sha256", "seen_block", "signature"), ("anchor",), "ack")
    if ack["type"] != T_ACK:
        raise Bad("wrong_type", "ack")
    if ack["log_id"] != trust["log_id"]:
        raise Bad("ack_for_another_log")
    _need(HEX32, ack["witness"], "bad_key")
    if ack["witness"] not in trust["witnesses"]:
        raise Bad("not_a_trusted_witness")
    _need(HEX32, ack["item_sha256"], "bad_item_sha256")
    if ack["item_sha256"] != digest:
        raise Bad("ack_for_another_item")
    _block(ack["seen_block"], "ack seen_block")
    check_sig(ack, "witness")
    sb = ack["seen_block"]
    problems, seen = [], sb["height"]
    if res["hashes"].get(sb["height"]) != sb["hash"]:
        problems.append("ack_seen_block_not_in_view")        # no lower bound from this one; the anchor may still count
        seen = None
    if "anchor" not in ack:
        return ack["witness"], seen, None, problems + ["ack_not_anchored"]
    try:
        a = ack["anchor"]
        _fields(a, ("height", "block_hash", "proof"), (), "ack anchor")
        if not _nonneg(a["height"]):
            raise Bad("bad_anchor_height")
        _need(HEX32, a["block_hash"], "bad_anchor_block_hash")
        h = a["height"]
        if res["hashes"].get(h) != a["block_hash"]:
            raise Bad("ack_anchor_block_not_in_view")
        got = v11.run_proof(hashlib.sha256(jcs(body_of(ack, ("anchor",)))).digest(), a["proof"])
        if got is None or got != res["merkle"][h]:
            raise Bad("ack_anchor_proof_fails")
        if res["tip"] - h + 1 < trust["min_depth"]:
            raise Bad("ack_anchor_too_shallow")
        if sb["height"] >= h:
            raise Bad("ack_anchor_not_after_seen_block")
    except Bad as exc:
        return ack["witness"], seen, None, problems + [exc.code]
    return ack["witness"], seen, h, problems


def witnessed_restrictions(records, trust, res, extensions=None, restrictions=RESTRICTIONS):
    """Returns (accepted, rejected). accepted: item digest -> {kind, item, published, earliest, signers,
    anchored, ack_problems}. earliest: the threshold-th lowest seen height over the witnesses that signed
    (threshold many had not all signed before that block). published: the threshold-th lowest anchor height
    over the witnesses whose acknowledgement is anchored (threshold many had signed by then), or None when
    fewer than threshold many are anchored: the restriction exists, and no block bounds it from above."""
    accepted, rejected = {}, []
    if not records:
        return accepted, rejected
    if "witnesses" not in trust:
        return accepted, [{"index": i, "reason": "no_witnesses_trusted"} for i in range(len(records))]
    pool, seen_acks, total = {}, set(), 0        # item digest -> acks from every record that carries it
    for i, rec in enumerate(records):
        try:
            _fields(rec, ("item", "acks"), (), "witnessed record")
            kind, item = parse_item(rec["item"], extensions)
            if kind not in restrictions:
                raise Bad("not_a_restriction", kind)
            acks = rec["acks"]
            if not (isinstance(acks, list) and 1 <= len(acks) <= MAX_ACKS):
                raise Bad("bad_acks")
            total += len(acks)
            if total > MAX_TOTAL_ACKS:
                raise Bad("too_many_acks")
            digest = item_sha256(item)
            p = pool.setdefault(digest, {"kind": kind, "item": item, "seen": {}, "anch": {}, "problems": [],
                                         "records": []})
            p["records"].append(i)
            for j, ack in enumerate(acks):
                try:
                    key = (digest, sha256_hex(jcs(ack)))        # the same bytes again are checked once
                except Exception:
                    key = None
                if key in seen_acks:
                    continue
                try:
                    w, seen, h, problems = _ack(ack, digest, trust, res)
                except Bad as exc:
                    p["problems"].append({"record": i, "ack": j, "reason": exc.code})
                    continue
                if key is not None:
                    seen_acks.add(key)
                for code in problems:
                    p["problems"].append({"record": i, "ack": j, "reason": code})
                # per witness: the lowest seen block it signed after, and separately the lowest anchor it
                # had signed by; one acknowledgement cannot bound both (a later one can be anchored sooner)
                if seen is not None:
                    p["seen"][w] = min(p["seen"].get(w, seen), seen)
                if h is not None:
                    p["anch"][w] = min(p["anch"].get(w, h), h)
        except Bad as exc:
            rejected.append({"index": i, "reason": exc.code})
        except CA2AError as exc:
            rejected.append({"index": i, "reason": exc.code})
    t = trust["witness_threshold"]
    for digest in sorted(pool):
        p = pool[digest]
        signers = set(p["seen"]) | set(p["anch"])
        if len(signers) < t:
            rejected.append({"index": p["records"][0], "reason": "too_few_witnesses", "witnesses": len(signers),
                             "ack_problems": p["problems"]})
            continue
        seen, anchored = sorted(p["seen"].values()), sorted(p["anch"].values())
        accepted[digest] = {"kind": p["kind"], "item": p["item"],
                            "earliest": seen[t - 1] if len(seen) >= t else None,
                            "published": anchored[t - 1] if len(anchored) >= t else None,
                            "signers": sorted(signers), "anchored": sorted(p["anch"]),
                            "ack_problems": p["problems"]}
    rejected.sort(key=lambda x: x["index"])
    return accepted, rejected


def order(w, seen_height, anchor_height):
    """Where a witnessed restriction stands against a receipt made after block seen_height and anchored by
    anchor_height: 'before', 'after' or 'unresolved'. Without an upper bound it is never before."""
    if w["published"] is not None and w["published"] <= seen_height:
        return "before"
    if w["earliest"] is not None and w["earliest"] >= anchor_height:
        return "after"
    return "unresolved"


# ==== settlement
def settle(bundle, extensions=None, restrictions=RESTRICTIONS):
    """As profile v0, plus bundle["witnessed"]: [{item, acks: [ack, ...]}, ...]. Deterministic; returns the
    settlement object, never raises on input. extensions and restrictions are for a profile built on this one;
    this profile's own CLI and selftest pass none."""
    out = {"type": T_SETTLEMENT, "profile": PROFILE}
    try:
        _fields(bundle, ("profile", "trust", "view", "log", "chains"), ("requests", "witnessed"), "bundle")
        if bundle["profile"] != PROFILE:
            raise Bad("wrong_profile")
        strict_value(bundle)
        _trust(bundle["trust"])
        _fields(bundle["log"], ("entries", "checkpoint"), ("extra_anchors",), "log")
        ea = bundle["log"].get("extra_anchors", [])
        if not (isinstance(ea, list) and len(ea) <= 16):
            raise Bad("bad_bundle", "extra_anchors")
        if not isinstance(bundle["chains"], list) or not isinstance(bundle.get("requests", []), list):
            raise Bad("bad_bundle", "chains and requests are lists")
        wit = bundle.get("witnessed", [])
        if not (isinstance(wit, list) and len(wit) <= MAX_RECORDS):
            raise Bad("bad_bundle", "witnessed")
    except Bad as exc:
        out["refused"] = exc.code
        return out
    trust, log = bundle["trust"], bundle["log"]
    try:
        status, hashes, times = verify_log(log["entries"], log["checkpoint"], trust, bundle["view"])
    except Bad as exc:
        out["log"] = {"verified": False, "problem": exc.code}
        return out
    out["log"] = dict(status, verified=True)
    entries = log["entries"]
    A = status["anchor_height"]
    pseudo = {"grant": {"finality": {"max_target_bits": trust["max_target_bits"]}},
              "lower_bound": trust["lower_bound"]}
    res, _ = v11.verify_view(bundle["view"], pseudo)     # accepted already by verify_log
    # the checkpoint may have been anchored more than once; a receipt existed by the earliest valid anchor,
    # so a later re-anchoring by anyone cannot widen the receipts' unresolved window
    extra = bundle["log"].get("extra_anchors", [])
    cp_digest = hashlib.sha256(jcs(body_of(log["checkpoint"], ("anchor",)))).digest()
    extra_rows = []
    for k, a in enumerate(extra):
        try:
            _fields(a, ("height", "block_hash", "proof"), (), "extra anchor")
            if not _nonneg(a["height"]):
                raise Bad("bad_anchor_height")
            _need(HEX32, a["block_hash"], "bad_anchor_block_hash")
            h = a["height"]
            if res["hashes"].get(h) != a["block_hash"]:
                raise Bad("anchor_block_not_in_view")
            got = v11.run_proof(cp_digest, a["proof"])
            if got is None or got != res["merkle"][h]:
                raise Bad("anchor_proof_fails")
            if res["tip"] - h + 1 < trust["min_depth"]:
                raise Bad("anchor_too_shallow")
            extra_rows.append({"index": k, "height": h})
            A = min(A, h)
        except Bad as exc:
            extra_rows.append({"index": k, "problem": exc.code})
    if extra:
        out["log"]["extra_anchors"] = extra_rows
        out["log"]["earliest_anchor_height"] = A

    supplied = {}
    for raw in bundle["chains"]:
        try:
            chain = _parse_chain(raw)
        except Bad:
            continue
        k = tuple(credential_digest(c) for c in chain)
        if k not in supplied or (not _sigs_ok(supplied[k]) and _sigs_ok(chain)):
            supplied[k] = chain
    requests = {}
    for r in bundle.get("requests", []):
        try:
            requests.setdefault(request_sha256(r), r)
        except Bad:
            continue

    items, rejected, flagged = [], [], []
    for e in entries:
        seq, t = e["seq"], e["logged_at"]
        try:
            kind, item = parse_item(e["item"], extensions)
            extra = {}
            if kind == "use":
                chain = _parse_chain(item["chain"])
                if item["holder"] != chain[-1].subject:
                    raise Bad("holder_not_leaf_subject")
                code = _ca2a(chain, trust, t, None)
                if code != "ok":
                    raise Bad("use_chain:" + code)
                extra = {"chain_obj": chain, "lineage": [credential_digest(c) for c in chain]}
            if kind == "revocation" and item["issued_at"] > t:
                flagged.append({"seq": seq, "flag": "revocation_dated_after_logging"})
            items.append(dict(extra, seq=seq, t=t, kind=kind, item=item))
        except Bad as exc:
            rejected.append({"seq": seq, "reason": exc.code})
        except CA2AError as exc:
            rejected.append({"seq": seq, "reason": exc.code})
    out["items_rejected"] = rejected
    out["items_flagged"] = flagged
    out["counts"] = {k: sum(1 for x in items if x["kind"] == k)
                     for k in ("revocation", "use-policy", "use", "receipt", "commit", "reveal")}

    # the lane around the operator
    witnessed, wrejected = witnessed_restrictions(bundle.get("witnessed", []), trust, res, extensions, restrictions)
    in_log = {}
    for e in entries:
        try:
            in_log.setdefault(item_sha256(e["item"]), e["seq"])
        except Exception:                                  # an entry item JCS cannot encode
            continue
    wrows, findings = [], []
    as_of = log["checkpoint"]["as_of"]
    for d in sorted(witnessed):
        w = witnessed[d]
        row = {"item_sha256": d, "kind": w["kind"], "published_height": w["published"],
               "earliest_height": w["earliest"], "signers": w["signers"], "anchored": w["anchored"],
               "in_log_seq": in_log.get(d)}
        if w["ack_problems"]:
            row["ack_problems"] = w["ack_problems"]
        wrows.append(row)
        if w["published"] is None:
            continue
        if w["kind"] == "revocation" and w["item"]["issued_at"] > times[w["published"]] + TIME_SLACK:
            flagged.append({"item_sha256": d, "flag": "revocation_dated_after_witnessing"})
        # the operator signed the checkpoint knowing its as_of; the anchor height is not when it signed
        due = w["published"] + trust["max_merge_blocks"]
        row["due_height"] = due
        if d in in_log:
            row["omission_check"] = "carried"
        elif due not in times:
            row["omission_check"] = "due_block_not_in_view"
        elif as_of >= times[due]:
            row["omission_check"] = "omitted"
            findings.append({"finding": "operator_omitted_witnessed_item", "item_sha256": d,
                             "published_height": w["published"], "due_height": due,
                             "due_block_time": times[due], "checkpoint_as_of": as_of})
        else:
            row["omission_check"] = "not_yet_due"
    out["witnessed"] = wrows
    out["witnessed_rejected"] = wrejected
    out["operator_findings"] = findings

    log_revs = [(x["seq"], RevocationStatement.from_dict(x["item"])) for x in items if x["kind"] == "revocation"]
    w_revs = [(w, RevocationStatement.from_dict(w["item"])) for d, w in sorted(witnessed.items())
              if w["kind"] == "revocation"]
    full_snapshot = RevocationSnapshot(as_of=as_of, statements=tuple(s for _, s in log_revs) +
                                       tuple(s for _, s in w_revs))
    uses = [x for x in items if x["kind"] == "use"]
    log_pols = [x for x in items if x["kind"] == "use-policy"]
    w_pols = [w for d, w in sorted(witnessed.items()) if w["kind"] == "use-policy"]
    rank = {}
    for u in uses:
        pair = (u["item"]["request_sha256"], u["item"]["responder"])
        for d in set(u["lineage"]):
            book = rank.setdefault(d, {})
            if pair not in book:
                book[pair] = len(book) + 1

    def limit_reasons(policy_items, lineage, chain, own, it):
        reasons, limits = [], []
        for i, d in enumerate(lineage):
            caps = [p["max_uses"] for p in policy_items
                    if p["credential_digest"] == d and p["issuer"] == chain[i].issuer]
            if not caps:
                continue
            limit = min(caps)
            if own is None:
                reasons.append("use_not_logged_before_execution")
                limits.append({"hop": i, "limit": limit, "rank": None})
                continue
            k = rank[d][(it["request_sha256"], it["responder"])]
            limits.append({"hop": i, "limit": limit, "rank": k})
            if k > limit:
                reasons.append("use_limit_exceeded")
        return set(reasons), limits

    receipts, executed = [], {}
    for x in items:
        if x["kind"] != "receipt":
            continue
        it, seq, t = x["item"], x["seq"], x["t"]
        lineage = it["lineage"]
        r = {"seq": seq, "request_sha256": it["request_sha256"], "outcome": it["outcome"]["kind"],
             "stage": it["outcome"]["stage"], "responder": it["responder"], "capability": it["capability"]}
        own = next((u for u in uses if u["seq"] < seq and u["lineage"] == lineage
                    and u["item"]["request_sha256"] == it["request_sha256"]
                    and u["item"]["responder"] == it["responder"]), None)
        chain = own["chain_obj"] if own else supplied.get(tuple(lineage))
        sb = it["seen_block"]
        if chain is None or hashes.get(sb["height"]) != sb["hash"]:
            r["disposition"] = "unassessed"
            r["reasons"] = (["chain_not_supplied"] if chain is None else []) + \
                ([] if hashes.get(sb["height"]) == sb["hash"] else ["seen_block_not_in_view"])
            receipts.append(r)
            continue
        S = sb["height"]
        reasons = []
        if S >= A:
            reasons.append("seen_block_not_before_anchor")
        if t + TIME_SLACK < times[S]:
            reasons.append("logged_before_seen_block")
        leaf = chain[-1]
        if it["caller"] != leaf.subject:
            reasons.append("caller_not_leaf_subject")
        if it["capability"] not in leaf.scope:
            reasons.append("capability_not_in_scope")
        req = requests.get(it["request_sha256"])
        r["request_known"] = req is not None
        if req is not None and (req["caller"], req["responder"], req["lineage"], req["capability"]) != \
                (it["caller"], it["responder"], lineage, it["capability"]):
            reasons.append("request_does_not_match_receipt")
        # revocations: logged before the receipt, or witnessed at or before the block it had seen
        before = tuple(s for q, s in log_revs if q < seq) + \
            tuple(s for w, s in w_revs if order(w, S, A) == "before")
        unresolved = tuple(s for w, s in w_revs if order(w, S, A) == "unresolved")
        published = RevocationSnapshot(as_of=as_of, statements=before)
        r["ca2a_at_execution"] = _ca2a(chain, trust, t, published, by_log_order=True)
        r["ca2a_audit"] = _ca2a(chain, trust, t, full_snapshot)
        if r["ca2a_at_execution"] not in ("ok", "CREDENTIAL_REVOKED"):
            reasons.append("outside_delegation:" + r["ca2a_at_execution"])
        elif r["ca2a_at_execution"] == "CREDENTIAL_REVOKED":
            reasons.append("executed_after_published_revocation")
        else:
            maybe = "ok"
            if unresolved:
                maybe = _ca2a(chain, trust, t, RevocationSnapshot(as_of=as_of, statements=before + unresolved),
                              by_log_order=True)
            if maybe == "CREDENTIAL_REVOKED":
                reasons.append("revocation_order_unresolved")
            elif r["ca2a_audit"] == "CREDENTIAL_REVOKED":
                reasons.append("revocation_published_late")
        # use limits: logged before the receipt, or witnessed at or before its seen block
        sure = [p["item"] for p in log_pols if p["seq"] < seq] + \
            [w["item"] for w in w_pols if order(w, S, A) == "before"]
        maybe_pols = sure + [w["item"] for w in w_pols if order(w, S, A) == "unresolved"]
        got, limits = limit_reasons(sure, lineage, chain, own, it)
        reasons += sorted(got)
        if len(maybe_pols) > len(sure):
            got2, _ = limit_reasons(maybe_pols, lineage, chain, own, it)
            if got2 - got:
                reasons.append("use_policy_order_unresolved")
        if limits:
            r["use_limits"] = limits
        key = (it["responder"], it["request_sha256"])
        if it["outcome"]["kind"] == "result":
            if key in executed:
                reasons.append("duplicate_execution")
                r["first_execution_seq"] = executed[key]
            else:
                executed[key] = seq
        r["reasons"] = sorted(set(reasons))
        hard = [x for x in r["reasons"] if x not in SOFT]
        if not r["reasons"]:
            r["disposition"] = "within_delegation"
        elif hard:
            r["disposition"] = "outside"
        elif "revocation_order_unresolved" in r["reasons"] or "use_policy_order_unresolved" in r["reasons"]:
            r["disposition"] = "order_unresolved"
        else:
            r["disposition"] = "late_revocation_only"
        receipts.append(r)
    out["receipts"] = receipts

    sessions = {}
    for x in items:
        if x["kind"] == "commit":
            it = x["item"]
            s = sessions.setdefault(it["session_id"], {"participants": it["participants"], "commits": {},
                                                       "reveals": {}})
            s["commits"].setdefault(it["committer"], dict(it, seq=x["seq"]))
    for x in items:
        if x["kind"] == "reveal":
            it = x["item"]
            s = sessions.get(it["session_id"])
            if s is not None and it["committer"] in s["participants"]:
                s["reveals"].setdefault(it["committer"], dict(it, seq=x["seq"]))
    sres = []
    for sid in sorted(sessions):
        s = sessions[sid]
        rows, problems = [], []
        for p in s["participants"]:
            c, v = s["commits"].get(p), s["reveals"].get(p)
            row = {"committer": p, "commit_seq": c and c["seq"], "reveal_seq": v and v["seq"]}
            if c is None:
                problems.append("commit_missing")
            if v is None:
                problems.append("reveal_missing")
            elif c is not None:
                row["matches"] = commitment_of(sid, p, v["evidence_sha256"], v["salt"]) == c["commitment"]
                if not row["matches"]:
                    problems.append("reveal_does_not_match")
            rows.append(row)
        cs = [r["commit_seq"] for r in rows if r["commit_seq"] is not None]
        vs = [r["reveal_seq"] for r in rows if r["reveal_seq"] is not None]
        if cs and vs and max(cs) > min(vs):
            problems.append("a_reveal_preceded_a_commit")
        sres.append({"session_id": sid, "parties": rows, "simultaneous": not problems,
                     "problems": sorted(set(problems))})
    out["sessions"] = sres
    return out


# ==== cli
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--settle", help="bundle JSON file")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "vectors", "vectors_v0_1.json"), "rb") as f:
            vs = json.loads(f.read())
        bad = 0
        for v in vs["vectors"]:
            if json.loads(jcs(settle(v["bundle"]))) != v["expected"]:
                bad += 1
                print("FAIL", v["id"])
        n = len(vs["vectors"])
        print("%d/%d vectors agree" % (n - bad, n))
        sys.exit(1 if bad else 0)
    if a.settle:
        # exit 0: a settlement with receipts; 2: refused or the log did not verify; 3: the file is unreadable
        try:
            with open(a.settle, "rb") as f:
                b = load_strict(f.read())
        except (Bad, ValueError, RecursionError, OSError) as exc:
            code = exc.code if isinstance(exc, Bad) else "unreadable_input"
            sys.stdout.write(jcs({"type": T_SETTLEMENT, "profile": PROFILE, "refused": code}).decode("utf-8") + "\n")
            sys.exit(3)
        out = settle(b)
        sys.stdout.write(jcs(out).decode("utf-8") + "\n")
        sys.exit(2 if "refused" in out or not out.get("log", {}).get("verified") else 0)
    ap.print_help()


if __name__ == "__main__":
    main()
