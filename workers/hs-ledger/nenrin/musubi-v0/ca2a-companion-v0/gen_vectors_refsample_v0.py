#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate vectors/vectors_refsample_v0.json: reference sampling, the spot check a provider cannot steer.

Keys of gen_vectors.py and the spaced test chain of gen_vectors_v0_1.py. P provides a 60-row dataset; K1 and K2
are the checkers it names; Z is a key nobody named. Deterministic: running it twice gives the same bytes.
"""
import base64, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import gen_vectors as G                # noqa: E402
import gen_vectors_v0_1 as GV          # noqa: E402
import companion_v0 as C               # noqa: E402
import companion_v0_1 as C1            # noqa: E402
import refsample_v0 as R               # noqa: E402

P, P_PUB = G.key("refsample-provider")
K1, K1_PUB = G.key("refsample-checker-1")
K2, K2_PUB = G.key("refsample-checker-2")
Z, Z_PUB = G.key("refsample-puppet")
RULE = "json-pointer-array:/rows"
RATE = 200000                          # 20 percent


def dataset_file(n=60, bad=(), pad=0):
    rows = []
    for i in range(n):
        rows.append({"id": "r%02d" % i, "price": 1000 + 10 * i, "unit": "m2",
                     "source": "https://example.invalid/price-book.pdf", "page": 1 + i // 10})
    for i in range(pad):
        rows.append({"id": "pad%02d" % i, "price": 1, "unit": "m2", "source": None, "page": None})
    return json.dumps({"title": "test reference", "rows": rows}, ensure_ascii=False, sort_keys=True).encode("utf-8")


def facts(raw, rule=RULE):
    rows = R.rows_of_file(raw, rule)
    digs = [R.row_sha256(r) for _, r in rows]
    return C.sha256_hex(raw), sorted(set(digs)), R.dataset_sha256(digs, rule)


def commitment(raw, draw_height, seen, checkers=(K1_PUB, K2_PUB), dataset_id="test-reference", rule=RULE,
               rate=RATE, k=P, pub=P_PUB, mutate=None):
    fsha, uniq, dsha = facts(raw, rule)
    body = {"type": R.T_COMMIT, "provider": pub, "dataset_id": dataset_id, "dataset_sha256": dsha,
            "row_count": len(uniq), "row_rule": rule, "file_sha256": fsha, "rate_ppm": rate,
            "draw_height": draw_height, "checkers": list(checkers), "seen_block": seen}
    if mutate:
        mutate(body)
    return C.sign(body, k)


def check(cm, row_d, verdict, seen, k=K1, pub=K1_PUB, url="https://example.invalid/price-book.pdf",
          locator="p1"):
    return C.sign({"type": R.T_CHECK, "checker": pub, "commitment_sha256": C1.item_sha256(cm), "row_sha256": row_d,
                   "verdict": verdict, "evidence": {"url": url, "sha256": C.sha256_hex(b"source bytes"),
                                                    "locator": locator}, "seen_block": seen}, k)


def blk(s, h):
    return {"height": h, "hash": s.ch.hashes[h]}


def sampled(s, raw, h, rule=RULE, rate=RATE):
    _, uniq, _ = facts(raw, rule)
    return [d for d in uniq if R.drawn(s.ch.hashes[h], d, rate)]


VECTORS = []


def policy_for(b, checkers=(K1_PUB, K2_PUB), quorum=1, min_sampled=1, log=True, **over):
    tr = b["trust"]
    p = {"type": R.T_POLICY, "lower_bound": tr["lower_bound"], "max_target_bits": tr["max_target_bits"],
         "min_depth": tr["min_depth"], "checkers": list(checkers), "quorum": quorum, "min_sampled": min_sampled}
    if log:
        p["companion_trust"] = tr
    p.update(over)
    return json.loads(C.jcs(p))


def vec(vid, desc, b, cm, raw=None, checks=(), digests=None, rows=None, policy=None, mutate=None):
    b = json.loads(json.dumps(b))
    pol = policy or policy_for(b)
    b["profile"] = R.PROFILE
    b["commitment_sha256"] = C1.item_sha256(cm)
    ds = {}
    if raw is not None:
        ds["file_b64"] = base64.b64encode(raw).decode("ascii")
    if digests is not None:
        ds["row_sha256"] = digests
    if rows is not None:
        ds["rows"] = rows
    b["dataset"] = ds
    b["checks"] = list(checks)
    if mutate:
        mutate(b)
    b = json.loads(C.jcs(b))
    VECTORS.append({"id": vid, "description": desc, "bundle": b, "policy": pol,
                    "expected": json.loads(C.jcs(R.settle(b, pol)))})
    return VECTORS[-1]["expected"]


def logged_scene(raw=None, ahead=3, verdicts=None, extra_checks=None, cm_kw=None, depth=10, items_extra=()):
    """The commitment in the log, the draw `ahead` blocks after the block the provider had seen."""
    raw = raw or dataset_file()
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = commitment(raw, seen["height"] + ahead, seen, **(cm_kw or {}))
    b = s.finish([cm] + list(items_extra), depth=depth)
    H = cm["draw_height"]
    checks = []
    if H in s.ch.hashes:
        smp = sampled(s, raw, H, cm["row_rule"], cm["rate_ppm"])
        after = blk(s, H)
        for i, d in enumerate(smp):
            v = (verdicts or {}).get(i, "match")
            if v is not None:
                checks.append(check(cm, d, v, after))
        if extra_checks:
            checks += extra_checks(s, cm, smp, after)
    return s, b, cm, raw, checks


def main():
    s, b, cm, raw, checks = logged_scene()
    e = vec("RS01_all_sampled_rows_match", "the commitment is logged and anchored below the draw block; checker K1 shows "
            "every sampled row correct: settled, with the 95% bound on the rows not shown correct", b, cm, raw, checks)
    assert e["refsample"]["status"] == "settled" and e["refsample"]["tally"]["match"] == e["refsample"]["bound"]["sampled"]
    assert e["refsample"]["bound"]["sampled"] > 0

    # the same, fixed by witnesses only: the commitment is never logged
    raw = dataset_file()
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = commitment(raw, seen["height"] + 3, seen)
    w = s.witness(cm, GV.TWO)
    b = s.finish([G.policy(5)], [w], depth=10)
    smp = sampled(s, raw, cm["draw_height"])
    checks = [check(cm, d, "match", blk(s, cm["draw_height"])) for d in smp]
    e = vec("RS02_fixed_by_witnesses", "the commitment reaches the checkers through two witnesses and is never logged; "
            "published below the draw block, so it binds, and hedging is visible to whoever collects from the "
            "witnesses", b, cm, raw, checks)
    assert e["refsample"]["fixed_by"] == "witnesses"

    s, b, cm, raw, checks = logged_scene(ahead=1)
    e = vec("RS03_anchored_at_the_draw_block", "the checkpoint holding the commitment is anchored in the draw block "
            "itself: nothing shows the commitment existed before the hash was known; the sample binds nothing",
            b, cm, raw, checks)
    assert e["refsample"]["status"] == "not_fixed_before_draw"

    raw = dataset_file()
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = commitment(raw, seen["height"] + 1, seen)
    s.mine()
    s.mine()
    w = s.witness(cm, GV.TWO, seen=blk(s, seen["height"] + 2))
    b = s.finish([G.policy(5)], [w], depth=10)
    checks = [check(cm, d, "match", blk(s, cm["draw_height"])) for d in sampled(s, raw, cm["draw_height"])]
    e = vec("RS04_witnessed_after_the_draw", "the witnesses first saw the commitment after the draw block: order after, "
            "not binding", b, cm, raw, checks)
    assert e["refsample"]["status"] == "not_fixed_before_draw"

    s, b, cm, raw, checks = logged_scene()
    altered = raw.replace(b'"price": 1000', b'"price": 1001')
    vec("RS05_file_changed_after_commitment", "the relying party is handed a file whose bytes differ from the "
        "committed file", b, cm, altered, checks)

    raw = dataset_file()
    raw2 = dataset_file(pad=1)
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = commitment(raw, seen["height"] + 3, seen)
    cm2 = commitment(raw2, seen["height"] + 3, seen)
    b = s.finish([cm, cm2], depth=10)
    checks = [check(cm, d, "match", blk(s, cm["draw_height"])) for d in sampled(s, raw, cm["draw_height"])]
    e = vec("RS06_two_commitments_for_one_dataset", "the provider committed two versions of the same dataset id before "
            "the draw; the one shown settles, and the other is named", b, cm, raw, checks)
    assert e["refsample"]["other_commitments"]

    def extras(s, cm, smp, after):
        unsampled = [d for d in facts(dataset_file())[1] if d not in smp][0]
        before = blk(s, cm["draw_height"] - 1)
        return [check(cm, smp[0], "match", after, Z, Z_PUB),                # nobody named Z
                check(cm, unsampled, "match", after),                       # not in the sample
                check(cm, smp[1], "match", before, K2, K2_PUB),             # made before the draw
                check(cm, smp[2], "mismatch", after),                       # K1 says match and mismatch
                check(cm, smp[3], "mismatch", after, K2, K2_PUB),           # K1 match, K2 mismatch
                check(cm, smp[0], "match", after)]                          # same bytes as K1's first check
    s, b, cm, raw, checks = logged_scene(verdicts={4: "mismatch", 5: "unreachable", 6: None}, extra_checks=extras)
    e = vec("RS07_checks_that_do_not_count_and_rows_that_fail", "a key nobody named, a row outside the sample, a check "
            "made before the draw, a duplicate; one row mismatched, one contradicted by its own checker, one where "
            "the checkers disagree, one unreachable, one unchecked", b, cm, raw, checks)
    t = e["refsample"]["tally"]
    assert t["mismatch"] >= 2 and t["contradicted"] == 1 and t["unreachable"] == 1

    s, b, cm, raw, checks = logged_scene(verdicts={i: "not_checkable" for i in range(60)})
    e = vec("RS08_rows_without_a_source", "every sampled row is not_checkable (a reference whose rows name no source): "
            "the bound says the dataset is not shown correct at all", b, cm, raw, checks)
    assert e["refsample"]["bound"]["not_shown_correct_upper_95_ppm"] == R.PPM

    s, b, cm, raw, checks = logged_scene(ahead=40)
    vec("RS09_draw_block_not_yet_in_view", "the draw block is beyond the relying party's view", b, cm, raw, checks)

    csv_raw = ("id,item,price,source,page\r\n" + "".join(
        "c%02d,\"生コン, 30-18-20\",%d,https://example.invalid/tanka.pdf,%d\r\n" % (i, 15000 + 100 * i, 10 + i // 5)
        for i in range(40))).encode("utf-8")
    s, b, cm, raw, checks = logged_scene(raw=csv_raw, cm_kw={"rule": "csv-header-rows"})
    vec("RS10_csv_rows", "the same scene over a CSV file read as header-keyed rows (RFC 4180 quoting)", b, cm, raw, checks)

    # rows supplied by digest only: a provider that does not publish the whole dataset
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    rows = [r for _, r in R.rows_of_file(dataset_file(), RULE)]
    digs = sorted({R.row_sha256(r) for r in rows})
    cm = C.sign({"type": R.T_COMMIT, "provider": P_PUB, "dataset_id": "test-reference-digests",
                 "dataset_sha256": R.dataset_sha256(digs, "jcs-sha256"), "row_count": len(digs), "row_rule": "jcs-sha256",
                 "file_sha256": None, "rate_ppm": RATE, "draw_height": seen["height"] + 3,
                 "checkers": [K1_PUB], "seen_block": seen}, P)
    b = s.finish([cm], depth=10)
    smp = [d for d in digs if R.drawn(s.ch.hashes[cm["draw_height"]], d, RATE)]
    revealed = [r for r in rows if R.row_sha256(r) in set(smp)]
    checks = [check(cm, d, "match", blk(s, cm["draw_height"])) for d in smp]
    vec("RS11_digests_only", "the provider publishes row digests and reveals only the sampled rows", b, cm,
        None, checks, digests=digs, rows=revealed)

    s, b, cm, raw, checks = logged_scene(cm_kw={"checkers": (P_PUB, K1_PUB)})
    vec("RS12_provider_names_itself", "the provider names itself as a checker: the commitment is refused",
        b, cm, raw, checks)

    raw = dataset_file()
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = commitment(raw, seen["height"], seen)
    b = s.finish([cm], depth=10)
    vec("RS13_draw_block_already_seen", "the provider names as draw block one it had already seen", b, cm, raw, [])

    s, b, cm, raw, _ = logged_scene(cm_kw={"checkers": (G.O_PUB, K1_PUB)})
    smp = sampled(s, raw, cm["draw_height"])
    checks = [check(cm, d, "match", blk(s, cm["draw_height"]), G.O, G.O_PUB) for d in smp]
    e = vec("RS14_log_operator_as_checker", "the provider names the log operator as a checker; its checks do not count",
            b, cm, raw, checks)
    assert e["refsample"]["tally"]["match"] == 0

    # no log: the provider anchors the commitment itself (OpenTimestamps in practice)
    def direct(anchor_at_draw=False, wrong_proof=False):
        raw = dataset_file()
        s = GV.Sc()
        s.mine()
        seen = s.tip()
        cm = commitment(raw, seen["height"] + (1 if anchor_at_draw else 3), seen)
        [stamped] = s.mine([dict(cm)])
        anchor = stamped["anchor"]
        if wrong_proof:
            anchor = dict(anchor, proof=[{"op": "sha256"}] + anchor["proof"])
        for _ in range(10):
            s.mine()
        H = cm["draw_height"]
        checks = [check(cm, d, "match", blk(s, H)) for d in sampled(s, raw, H)]
        b = {"profile": R.PROFILE, "commitment_sha256": C1.item_sha256(cm),
             "view": s.ch.view(), "commitment": cm, "commitment_anchors": [anchor],
             "dataset": {"file_b64": base64.b64encode(raw).decode("ascii")}, "checks": checks}
        b = json.loads(C.jcs(b))
        pol = policy_for({"trust": {"lower_bound": {"kind": "bitcoin_block", "height": 95, "hash": s.ch.hashes[95]},
                                    "max_target_bits": "207fffff", "min_depth": 6}}, log=False)
        VECTORS.append({"id": None, "bundle": b, "policy": pol, "expected": json.loads(C.jcs(R.settle(b, pol)))})
        return VECTORS[-1]
    v = direct()
    v.update(id="RS15_direct_anchor", description="no log at all: the provider stamped the commitment itself and the "
             "stamp is in a block below the draw block; settled, hedging not excluded")
    assert v["expected"]["refsample"]["fixed_by"] == "direct_anchor"
    v = direct(anchor_at_draw=True)
    v.update(id="RS16_direct_anchor_in_the_draw_block", description="the provider's own stamp lands in the draw block: "
             "not fixed before the draw")
    assert v["expected"]["refsample"]["status"] == "not_fixed_before_draw"
    v = direct(wrong_proof=True)
    v.update(id="RS17_direct_anchor_for_other_bytes", description="the anchor's path does not start from the "
             "commitment's digest: anchor_proof_fails, not fixed")
    assert v["expected"]["refsample"]["status"] == "not_fixed_before_draw"
    for v in VECTORS:
        v.setdefault("description", "")
    VECTORS[:] = [{"id": v["id"], "description": v["description"], "bundle": v["bundle"], "policy": v["policy"],
                   "expected": v["expected"]} for v in VECTORS]

    # sixth review round
    s, b, cm, raw, checks = logged_scene()
    vec("RS18_view_easier_than_the_policy_floor", "the relying party's floor is harder than the chain the bundle "
        "carries (a provider's own fork would have to be): the view is refused, nothing settles", b, cm, raw, checks,
        policy=policy_for(b, max_target_bits="1f00ffff", companion_trust=dict(b["trust"], max_target_bits="1f00ffff")))

    def puppet(s, cm, smp, after):
        return [check(cm, d, "match", after, Z, Z_PUB) for d in smp]
    s, b, cm, raw, _ = logged_scene(verdicts={i: None for i in range(60)}, extra_checks=puppet,
                                    cm_kw={"checkers": (K1_PUB, Z_PUB)})
    e = vec("RS19_provider_names_a_checker_the_relying_party_does_not_accept", "the provider names K1 and its own Z; "
            "K1's checks are left out of the bundle and Z says match on every row; the policy accepts K1 and K2 "
            "only: no row is shown correct", b, cm, raw, _)
    assert e["refsample"]["tally"]["match"] == 0

    def k2_half(s, cm, smp, after):
        return [check(cm, d, "match", after, K2, K2_PUB) for d in smp[: len(smp) // 2]]
    s, b, cm, raw, checks = logged_scene(extra_checks=k2_half)
    e = vec("RS20_quorum_of_two", "the policy wants two of K1 and K2 to say match: rows only K1 checked are "
            "short_of_quorum", b, cm, raw, checks, policy=policy_for(b, quorum=2))
    assert e["refsample"]["tally"]["short_of_quorum"] > 0

    s, b, cm, raw, checks = logged_scene(cm_kw={"rate": 1})
    e = vec("RS21_empty_sample", "a rate of one in a million samples nothing: no_bound, not settled", b, cm, raw, checks)
    assert e["refsample"]["status"] == "no_bound"

    raw = dataset_file()
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = commitment(raw, seen["height"] + 3, seen)
    cm2 = commitment(raw, seen["height"] + 4, seen, dataset_id="renamed-reference")
    b = s.finish([cm, cm2], depth=10)
    checks = [check(cm, d, "match", blk(s, cm["draw_height"])) for d in sampled(s, raw, cm["draw_height"])]
    e = vec("RS22_same_file_under_another_name_and_height", "a second commitment of the same file under another "
            "dataset id and draw height is still named", b, cm, raw, checks)
    assert e["refsample"]["other_commitments"]

    s, b, cm, raw, checks = logged_scene()
    pol = policy_for(b)
    del pol["companion_trust"]
    vec("RS23_log_without_the_relying_partys_log_trust", "a logged bundle and a policy with no trust in any log: "
        "refused", b, cm, raw, checks, policy=pol)

    s, b, cm, raw, checks = logged_scene()
    vec("RS24_one_malformed_check", "one check with a float in it is one problem row, not a refused bundle",
        b, cm, raw, checks + [dict(checks[0], verdict=1.5)])

    # seventh review round
    def k1_objects(s, cm, smp, after):
        return [check(cm, d, "mismatch", after) for d in smp[:3]]
    s, b, cm, raw, _ = logged_scene(verdicts={i: None for i in range(60)}, extra_checks=None,
                                    cm_kw={"checkers": (K2_PUB,)})
    smp = sampled(s, raw, cm["draw_height"])
    after = blk(s, cm["draw_height"])
    checks = [check(cm, d, "match", after, K2, K2_PUB) for d in smp] + k1_objects(s, cm, smp, after)
    e = vec("RS25_accepted_checker_the_provider_did_not_name", "the provider names only K2, who says match on every "
            "row; K1, whom the policy also accepts, says three rows are wrong: those rows are mismatch", b, cm, raw,
            checks)
    assert e["refsample"]["tally"]["mismatch"] == 3

    s, b, cm, raw, checks = logged_scene(cm_kw={"checkers": (K1_PUB,)})
    e = vec("RS26_quorum_out_of_reach", "the policy wants two matches but the provider named only one accepted "
            "checker: quorum_unreachable", b, cm, raw, checks, policy=policy_for(b, quorum=2))
    assert e["refsample"]["status"] == "quorum_unreachable"

    s, b, cm, raw, checks = logged_scene()
    vec("RS27_witnessed_not_a_list", "the bundle's witnessed field is a string: refused, not a crash", b, cm, raw,
        checks, mutate=lambda bb: bb.__setitem__("witnessed", "x"))

    s, b, cm, raw, checks = logged_scene(cm_kw={"mutate": lambda body: body.__setitem__("type", "musubi.other.v0")})
    vec("RS28_signed_object_of_another_type", "a provider-signed object with the commitment's fields but another type "
        "is not a commitment", b, cm, raw, checks)

    s, b, cm, raw, checks = logged_scene()
    pol = policy_for(b, companion_trust=dict(b["trust"], operator=K2_PUB))
    e = vec("RS29_log_signed_by_another_operator", "the relying party trusts another log operator: the log does not "
            "verify and the settlement says so", b, cm, raw, checks, policy=pol)
    assert e["refsample"]["status"] == "log_not_verified"

    # padding cannot remove a row from the sample: a property of the draw, shown on the vectors' chain
    s = GV.Sc()
    for _ in range(4):
        s.mine()
    h = s.tip()["height"]
    base, padded = sampled(s, dataset_file(), h), sampled(s, dataset_file(pad=500), h)
    assert set(base) <= set(padded)

    bounds = [[[0, 10], R.cp_upper_ppm(0, 10)], [[0, 30], R.cp_upper_ppm(0, 30)], [[0, 59], R.cp_upper_ppm(0, 59)],
              [[1, 30], R.cp_upper_ppm(1, 30)], [[3, 100], R.cp_upper_ppm(3, 100)],
              [[5, 12], R.cp_upper_ppm(5, 12)], [[12, 12], R.PPM], [[0, 300], R.cp_upper_ppm(0, 300)]]
    out = {"profile": R.PROFILE, "note": "headers are regtest difficulty, ten minutes apart; bounds are exact integer "
           "Clopper-Pearson upper bounds in parts per million", "vectors": VECTORS, "bounds": bounds}
    with open(os.path.join(HERE, "vectors", "vectors_refsample_v0.json"), "wb") as f:
        f.write(C.jcs(out))
    for v in VECTORS:
        r = v["expected"].get("refsample", {})
        print(v["id"], r.get("status"), r.get("fixed_by"), r.get("tally"),
              (r.get("bound") or {}).get("not_shown_correct_upper_95_ppm"))


if __name__ == "__main__":
    main()
