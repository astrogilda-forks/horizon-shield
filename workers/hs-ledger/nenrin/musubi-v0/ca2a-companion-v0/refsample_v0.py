"""
MUSUBI reference sampling, profile v0: a spot check of a reference dataset that its provider cannot steer.

The gap it closes, found by putting the pilot together (horizon-shield Issue #51): an audit carries the
digest of the dataset its verdict was computed from, and an acceptance record checks the audit against the
buyer's criteria. Both only show that the answer agrees with the reference. Nothing showed that the
reference agrees with the world, and the provider of the reference is the one party that cannot be asked.

The method is ordinary audit sampling. What this profile adds is that nobody can choose the sample:

  musubi.refsample.commitment.v0  provider-signed, before the draw: the dataset (its rows, by digest), the
                                  rule that turns a published file into rows, a sampling rate, the checker
                                  keys it proposes, and a Bitcoin block height in the provider's future.
  musubi.refsample.check.v0       checker-signed, after the draw: one sampled row, a verdict (match,
                                  mismatch, unreachable, not_checkable) and the source it was checked against.
  musubi.refsample.policy.v0      the relying party's own settings, never taken from the bundle: the chain
                                  floor and lower bound its view must meet, the depth it wants, the checker
                                  keys it accepts and how many of them must say match, the smallest sample
                                  it accepts, and, for a logged commitment, its trust in the log.

  - The draw is the hash of the named block. A row is in the sample when SHA-256 of a domain tag, that hash
    and the row's own digest falls under the rate. Each row's fate depends on nothing but itself and the
    block: adding rows can never push a row out of the sample.
  - The commitment counts only when it is shown to exist before that block: by the provider's own Bitcoin
    anchor (OpenTimestamps), by a companion log whose checkpoint is anchored below it, or through the
    witnesses of profile v0.1. Otherwise the sample proves nothing: not_fixed_before_draw.
  - The chain parameters come from the policy. A provider that hands over its own header view could grind a
    fork at the draw block until its bad rows fall outside the sample; a floor near the real difficulty and
    a view the relying party compared with a header source of its own close that (REFSAMPLE_v0.md section 5).
  - A row is shown correct when at least quorum of the checkers the policy accepts (and the commitment
    names) say match and none of them says mismatch or contradicts itself. A mismatch from any checker the
    policy accepts blocks the row even if the provider did not name it or it looked before the draw. Leaving
    an accepted checker's checks out of a bundle can still make a row match when the quorum is smaller than
    the accepted checkers; a relying party that wants omission to fail sets the quorum to all of them, or
    collects the checks from its checkers itself.
  - A provider that commits several versions and shows only the lucky one is not stopped by the draw. Every
    other commitment in the bundle sharing the provider, the dataset id, the dataset or the file is listed.
  - The settlement gives the one-sided 95% Clopper-Pearson upper bound on the fraction of the dataset that
    would not be shown correct, exact integers rounded up to parts per million, or the status no_bound.

What this does not prove: that the accepted checkers are honest or competent, that rows outside the sample
are right (only the bound), that the sources the checkers read were the same before the draw (unless the
rows carry their sources' digests), or anything about a row nobody could check: not_checkable counts against
the dataset, which is the point: a reference whose rows carry no source is a reference nobody can check.

Usage:
  refsample_v0.py --selftest
  refsample_v0.py --settle BUNDLE.json --policy POLICY.json
  refsample_v0.py --rows FILE RULE          print the file digest, the rows and the dataset digest
"""
import argparse, base64, csv, hashlib, io, json, os, re, sys

import companion_v0 as c0
import companion_v0_1 as c1
from companion_v0 import (Bad, jcs, sha256_hex, strict_value, load_strict, _nonneg, _need, _fields, check_sig,
                          HEX32, TEXT)

PROFILE = "musubi.refsample.v0"
T_COMMIT = "musubi.refsample.commitment.v0"
T_CHECK = "musubi.refsample.check.v0"
T_POLICY = "musubi.refsample.policy.v0"
T_SETTLEMENT = "musubi.refsample.settlement.v0"
KIND = "refsample-commitment"
DRAW_TAG = b"musubi.refsample.v0.draw\x00"
DATASET_TAG = b"musubi.refsample.v0.dataset\x00"
VERDICTS = ("match", "mismatch", "unreachable", "not_checkable")
MAX_ROWS = 200000
MAX_CHECKERS = 8
MAX_ACCEPTED = 32
MAX_CHECKS = 4096
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_CSV_FIELD = 131072
MAX_STAT_N = 2000
PPM = 1000000
URL = re.compile(r"[\x21-\x7e]{1,2048}")
POINTER = re.compile(r"(/([^~/]|~[01])*)*")


# ==== items
def _commitment(item):
    _fields(item, ("type", "provider", "dataset_id", "dataset_sha256", "row_count", "row_rule", "file_sha256",
                   "rate_ppm", "draw_height", "checkers", "seen_block", "signature"), (), T_COMMIT)
    if item.get("type") != T_COMMIT:
        raise Bad("wrong_type")
    _need(HEX32, item["provider"], "bad_key")
    _need(TEXT, item["dataset_id"], "bad_dataset_id")
    _need(HEX32, item["dataset_sha256"], "bad_dataset_sha256")
    if not (_nonneg(item["row_count"]) and 1 <= item["row_count"] <= MAX_ROWS):
        raise Bad("bad_row_count")
    rule = item["row_rule"]
    if not rule_ok(rule):
        raise Bad("bad_row_rule")
    if rule == "jcs-sha256":
        if item["file_sha256"] is not None:
            raise Bad("file_sha256_without_file_rule")
    else:
        _need(HEX32, item["file_sha256"], "bad_file_sha256")
    if not (_nonneg(item["rate_ppm"]) and 1 <= item["rate_ppm"] <= PPM):
        raise Bad("bad_rate_ppm")
    if not _nonneg(item["draw_height"]):
        raise Bad("bad_draw_height")
    c0._block(item["seen_block"], "seen_block")
    if item["draw_height"] <= item["seen_block"]["height"]:
        raise Bad("draw_not_in_future")          # the provider names a block it has not seen
    ck = item["checkers"]
    if not (isinstance(ck, list) and 1 <= len(ck) <= MAX_CHECKERS and all(isinstance(k, str) for k in ck)
            and len(set(ck)) == len(ck)):
        raise Bad("bad_checkers")
    for k in ck:
        _need(HEX32, k, "bad_key")
    if item["provider"] in ck:
        raise Bad("provider_is_checker")
    check_sig(item, "provider")
    return KIND, item


def _check(item):
    _fields(item, ("type", "checker", "commitment_sha256", "row_sha256", "verdict", "evidence", "seen_block",
                   "signature"), (), T_CHECK)
    if item.get("type") != T_CHECK:
        raise Bad("wrong_type")
    _need(HEX32, item["commitment_sha256"], "bad_commitment_sha256")
    _need(HEX32, item["row_sha256"], "bad_row_sha256")
    if item["verdict"] not in VERDICTS:
        raise Bad("bad_verdict")
    ev = item["evidence"]
    _fields(ev, ("url", "sha256", "locator"), (), "evidence")
    if ev["url"] is not None:
        _need(URL, ev["url"], "bad_evidence_url")
    if ev["sha256"] is not None:
        _need(HEX32, ev["sha256"], "bad_evidence_sha256")
    if ev["locator"] is not None:
        _need(TEXT, ev["locator"], "bad_evidence_locator")
    c0._block(item["seen_block"], "seen_block")
    check_sig(item, "checker")
    return "refsample-check", item


EXTENSIONS = {T_COMMIT: _commitment}
COMMIT_LANE = frozenset((KIND,))       # the v0.1 acknowledgement machinery, not the restriction lane


# ==== rows
def _data_value(v, depth=0):
    """A data file may hold floats, which the signed items of this profile never do. Rows are hashed as
    RFC 8785 bytes, which fix one spelling per number; integers beyond 2^53 and non-finite numbers are refused
    because two readers would not agree on them."""
    if depth > 64:
        raise Bad("too_deep")
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return
    if isinstance(v, int):
        if abs(v) > c0.MAX_SAFE:
            raise Bad("integer_out_of_range")
        return
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise Bad("non_finite_number")
        if abs(v) >= 2.0 ** 53:
            raise Bad("number_out_of_range")     # 9007199254740993.0 reads as ...992: two readers, two values
        return
    if isinstance(v, list):
        for x in v:
            _data_value(x, depth + 1)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            _data_value(x, depth + 1)
        return
    raise Bad("bad_value")


def load_data(raw):
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise Bad("duplicate_key", k)
            d[k] = v
        return d

    def no_const(x):
        raise Bad("non_finite_number", x)
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Bad("file_not_utf8")
    if text.startswith("\ufeff"):
        raise Bad("file_bom")
    try:
        doc = json.loads(text, object_pairs_hook=pairs, parse_constant=no_const)
    except (ValueError, RecursionError):
        raise Bad("file_not_json")
    _data_value(doc)
    return doc


def _pointer(doc, ptr):
    cur = doc
    if ptr == "":
        return cur
    for tok in ptr[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and tok in cur:
            cur = cur[tok]
        elif isinstance(cur, list) and re.fullmatch(r"0|[1-9][0-9]*", tok) and int(tok) < len(cur):
            cur = cur[int(tok)]
        else:
            raise Bad("pointer_not_found")
    return cur


def rule_ok(rule):
    return isinstance(rule, str) and 1 <= len(rule) <= 160 and all("\x21" <= ch <= "\x7e" for ch in rule) and (
        rule in ("jcs-sha256", "csv-header-rows")
        or (rule.startswith("json-pointer-array:") and POINTER.fullmatch(rule[len("json-pointer-array:"):])))


def rows_of_file(raw, rule):
    """[(locator, row)] from the published bytes under the rule. Deterministic; raises Bad."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_FILE_BYTES:
        raise Bad("bad_file")
    if not rule_ok(rule) or rule == "jcs-sha256":
        raise Bad("bad_row_rule")
    if rule.startswith("json-pointer-array:"):
        ptr = rule[len("json-pointer-array:"):]
        doc = load_data(raw)
        arr = _pointer(doc, ptr)
        if not isinstance(arr, list):
            raise Bad("pointer_not_array")
        if len(arr) > MAX_ROWS:
            raise Bad("too_many_rows")
        return [("%s/%d" % (ptr, i), r) for i, r in enumerate(arr)]
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Bad("csv_not_utf8")
    if text.startswith("\ufeff"):
        raise Bad("csv_bom")
    old_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(MAX_CSV_FIELD)
        recs = []
        for rec in csv.reader(io.StringIO(text, newline=""), strict=True):
            recs.append(rec)
            if len(recs) > MAX_ROWS + 1:
                raise Bad("too_many_rows")
    except csv.Error as exc:
        raise Bad("csv_malformed", str(exc)[:120])
    finally:
        csv.field_size_limit(old_limit)
    if not recs or not recs[0] or len(set(recs[0])) != len(recs[0]) or any(h == "" for h in recs[0]):
        raise Bad("csv_bad_header")
    head = recs[0]
    out = []
    for n, r in enumerate(recs[1:], start=1):
        if len(r) != len(head):
            raise Bad("csv_ragged_row", "record %d" % n)
        out.append(("record %d" % n, dict(zip(head, r))))
    return out


def row_sha256(row):
    _data_value(row)
    try:
        return sha256_hex(c0.rfc8785.dumps(row))
    except Exception:
        raise Bad("row_not_canonical")


def dataset_sha256(digests, rule):
    """Over the rule (length-prefixed) and the sorted set of row digests: order and repetition in the file do
    not change it."""
    r = rule.encode("ascii")
    return hashlib.sha256(DATASET_TAG + len(r).to_bytes(2, "big") + r
                          + b"".join(bytes.fromhex(d) for d in sorted(set(digests)))).hexdigest()


def drawn(beacon_hex, digest, rate_ppm):
    score = int.from_bytes(hashlib.sha256(DRAW_TAG + bytes.fromhex(beacon_hex) + bytes.fromhex(digest)).digest(),
                           "big")
    return score * PPM < rate_ppm * (1 << 256)




# ==== the bound
def _cdf_le_twentieth(x, n, m):
    """Exact: P(X <= x | n, m/10^6) <= 1/20, summing whichever tail has fewer terms."""
    q = PPM - m
    total = PPM ** n
    if x <= n // 2:
        lo, hi = 0, x
    else:
        lo, hi = x + 1, n
    c = 1
    for i in range(1, lo + 1):
        c = c * (n - i + 1) // i
    mp, qp = m ** lo, q ** (n - hi)
    terms = []
    for i in range(lo, hi + 1):
        terms.append(c)
        c = c * (n - i) // (i + 1)
    s = 0
    m_pows = [1]
    for _ in range(hi - lo):
        m_pows.append(m_pows[-1] * m)
    for k in range(hi - lo, -1, -1):           # i = lo + k, q exponent n - i rises as k falls
        s += terms[k] * m_pows[k] * qp
        qp *= q
    s *= mp
    return 20 * s <= total if x <= n // 2 else 20 * s >= 19 * total


def _cp_float(x, n):
    import math

    def cdf(p):
        if p <= 0.0:
            return 1.0
        if p >= 1.0:
            return 0.0
        lp, lq = math.log(p), math.log1p(-p)
        return sum(math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq)
                   for i in range(x + 1))
    a, b = 0.0, 1.0
    for _ in range(60):
        mid = (a + b) / 2
        if cdf(mid) <= 0.05:
            b = mid
        else:
            a = mid
    return b


def cp_upper_ppm(x, n):
    """One-sided 95% Clopper-Pearson upper bound for x failures in n, as the smallest p in parts per million
    with P(X <= x | n, p) <= 1/20. The answer is decided with exact integers; a floating-point estimate only
    chooses where to start looking. None when n is 0 or above MAX_STAT_N."""
    if n == 0 or n > MAX_STAT_N:
        return None
    if x >= n:
        return PPM
    m = min(PPM, max(0, int(_cp_float(x, n) * PPM)))
    ok = lambda v: _cdf_le_twentieth(x, n, v)     # monotone: false below the answer, true from it on
    if ok(m):
        step = 1
        while m - step >= 0 and ok(m - step):
            step *= 2
        lo, hi = max(0, m - step), m - step // 2   # ok(hi) holds; ok(lo) fails or lo is 0
        if lo == 0 and ok(0):
            return 0
    else:
        step = 1
        while not ok(min(PPM, m + step)):
            step *= 2
        lo, hi = m + step // 2, min(PPM, m + step)  # ok(lo) fails, ok(hi) holds
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ok(mid):
            hi = mid
        else:
            lo = mid
    return hi


# ==== the relying party's policy
def check_policy(policy):
    _fields(policy, ("type", "lower_bound", "max_target_bits", "min_depth", "checkers", "quorum", "min_sampled"),
            ("companion_trust",), "policy")
    if policy["type"] != T_POLICY:
        raise Bad("wrong_type", "policy")
    strict_value(policy)
    lb = policy["lower_bound"]
    _fields(lb, ("kind", "height", "hash"), (), "lower_bound")
    if lb["kind"] != "bitcoin_block" or not _nonneg(lb["height"]):
        raise Bad("bad_lower_bound")
    _need(HEX32, lb["hash"], "bad_lower_bound")
    if not (isinstance(policy["max_target_bits"], str) and re.fullmatch(r"[0-9a-f]{8}", policy["max_target_bits"])):
        raise Bad("bad_max_target_bits")
    if not (_nonneg(policy["min_depth"]) and 1 <= policy["min_depth"] <= 1008):
        raise Bad("bad_min_depth")
    ck = policy["checkers"]
    if not (isinstance(ck, list) and 1 <= len(ck) <= MAX_ACCEPTED and len(set(map(str, ck))) == len(ck)):
        raise Bad("bad_policy_checkers")
    for k in ck:
        _need(HEX32, k, "bad_key")
    if not (_nonneg(policy["quorum"]) and 1 <= policy["quorum"] <= len(ck)):
        raise Bad("bad_quorum")
    if not (_nonneg(policy["min_sampled"]) and 1 <= policy["min_sampled"] <= MAX_STAT_N):
        raise Bad("bad_min_sampled")
    if "companion_trust" in policy:
        ct = policy["companion_trust"]
        c1._trust(ct)
        if (ct.get("lower_bound"), ct.get("max_target_bits"), ct.get("min_depth")) != \
                (lb, policy["max_target_bits"], policy["min_depth"]):
            raise Bad("policy_inconsistent", "companion_trust chain settings differ from the policy's")


# ==== settlement
def settle(bundle, policy):
    """bundle: what the provider, the log and the checkers hand over. policy: the relying party's own settings
    (check_policy), never read from the bundle. Two bundle shapes. With a log, a companion v0.1 bundle (its
    trust replaced by policy.companion_trust) plus the fields below. Without one: the view, the commitment and
    the provider's own anchors. In both: commitment_sha256 names the commitment asked about, dataset carries the
    file (or the row digests), checks the checkers' records, commitment_anchors (optional, up to 16) Bitcoin
    anchors of the commitment's digest. Deterministic; never raises on input."""
    out = {"type": T_SETTLEMENT, "profile": PROFILE}
    try:
        check_policy(policy)
        out["policy_sha256"] = sha256_hex(jcs(policy))
        out["chain"] = {"max_target_bits": policy["max_target_bits"], "lower_bound_height": policy["lower_bound"]["height"],
                        "min_depth": policy["min_depth"]}
        if int(policy["max_target_bits"][:2], 16) > 0x1d:
            out["chain"]["floor_note"] = "easier than Bitcoin's minimum difficulty: test chains only"
    except Bad as exc:
        out["refused"] = "policy:" + exc.code
        return out
    try:
        if not isinstance(bundle, dict) or bundle.get("profile") != PROFILE:
            raise Bad("wrong_profile")
        _need(HEX32, bundle.get("commitment_sha256"), "bad_commitment_sha256")
        checks = bundle.get("checks", [])
        if not (isinstance(checks, list) and len(checks) <= MAX_CHECKS):
            raise Bad("bad_bundle", "checks")
        ds = bundle.get("dataset")
        _fields(ds, (), ("file_b64", "row_sha256", "rows"), "dataset")
        anchors = bundle.get("commitment_anchors", [])
        if not (isinstance(anchors, list) and len(anchors) <= 16):
            raise Bad("bad_bundle", "commitment_anchors")
        strict_value(anchors)
        strict_value({k: v for k, v in ds.items() if k != "rows"})
        _data_value(ds.get("rows", []))
        direct = "log" not in bundle
        if direct:
            _fields(bundle, ("profile", "commitment_sha256", "view", "commitment", "dataset"),
                    ("checks", "commitment_anchors", "trust"), "bundle")
            strict_value(bundle["commitment"])
        else:
            if "companion_trust" not in policy:
                raise Bad("policy_has_no_log_trust")
            wl = bundle.get("witnessed", [])
            if not (isinstance(wl, list) and len(wl) <= c1.MAX_RECORDS and all(isinstance(r, dict) for r in wl)):
                raise Bad("bad_bundle", "witnessed")
    except Bad as exc:
        out["refused"] = exc.code
        return out
    pseudo = {"grant": {"finality": {"max_target_bits": policy["max_target_bits"]}},
              "lower_bound": policy["lower_bound"]}
    target = bundle["commitment_sha256"]
    rs = {"commitment_sha256": target}
    known, logged, wit, why, A, operator = {}, {}, {}, None, None, None
    try:
        res, problem = c1.v11.verify_view(bundle["view"], pseudo)
    except Exception:
        res, problem = None, "view_rejected"
    if res is None:
        out["refused"] = "view_rejected"
        out["view_problem"] = str(problem)[:200]
        return out
    if direct:
        try:
            _, cm0 = _commitment(bundle["commitment"])
            known[c1.item_sha256(cm0)] = cm0
        except Bad as exc:
            why = exc.code
    else:
        trust = policy["companion_trust"]
        wit_all = bundle.get("witnessed", [])
        mine = [r for r in wit_all if isinstance(r.get("item"), dict) and r["item"].get("type") == T_COMMIT]
        rest = [r for r in wit_all if not (isinstance(r.get("item"), dict) and r["item"].get("type") == T_COMMIT)]
        inner = {k: v for k, v in bundle.items()
                 if k not in ("commitment_sha256", "checks", "dataset", "commitment_anchors", "commitment")}
        inner["profile"] = c1.PROFILE
        inner["trust"] = trust
        inner["witnessed"] = rest
        comp = c1.settle(inner, EXTENSIONS)
        out["companion"] = comp
        if "refused" in comp:
            out["refused"] = comp["refused"]
            return out
        if not comp["log"]["verified"]:
            out["refsample"] = {"commitment_sha256": target, "status": "log_not_verified"}
            return out
        A = comp["log"].get("earliest_anchor_height", comp["log"]["anchor_height"])
        operator = trust["operator"]
        rejected = {x["seq"]: x["reason"] for x in comp["items_rejected"]}
        for e in bundle["log"]["entries"]:
            if not isinstance(e["item"], dict) or e["item"].get("type") != T_COMMIT:
                continue
            try:
                d = c1.item_sha256(e["item"])
            except Exception:
                continue
            if e["seq"] in rejected:
                if d == target:
                    why = why or rejected[e["seq"]]
                continue
            logged.setdefault(d, (e["seq"], e["item"]))
        try:
            wacc, wrej = c1.witnessed_restrictions(mine, trust, res, EXTENSIONS, COMMIT_LANE)
        except Bad as exc:
            wacc, wrej = {}, [{"reason": exc.code}]
        wit = {d: {"published_height": w["published"], "earliest_height": w["earliest"]} for d, w in wacc.items()}
        for d, w in wacc.items():
            known.setdefault(d, w["item"])
        for x in wrej:
            i = x.get("index")
            try:
                d = c1.item_sha256(mine[i]["item"]) if isinstance(i, int) and 0 <= i < len(mine) else None
            except Exception:
                d = None
            if d == target and x.get("reason"):
                why = why or "witnessed:" + x["reason"]
        known.update({d: it for d, (q, it) in logged.items()})
    hashes = res["hashes"]
    out["refsample"] = rs
    if target not in known:
        rs["status"] = "commitment_rejected" if why else "commitment_not_found"
        if why:
            rs["reason"] = why
        return out
    cm = known[target]
    H = cm["draw_height"]
    rs.update(provider=cm["provider"], dataset_id=cm["dataset_id"], dataset_sha256=cm["dataset_sha256"],
              row_count=cm["row_count"], row_rule=cm["row_rule"], file_sha256=cm["file_sha256"],
              rate_ppm=cm["rate_ppm"], draw_height=H, checkers=cm["checkers"])
    psb = cm["seen_block"]
    if psb["height"] in hashes and hashes[psb["height"]] != psb["hash"]:
        rs["provider_seen_block_not_in_view"] = True

    # fixed before the draw?
    fixed_by, how = None, {}
    arows, D = [], None
    for k, a in enumerate(anchors):
        try:
            _fields(a, ("height", "block_hash", "proof"), (), "commitment anchor")
            if not _nonneg(a["height"]):
                raise Bad("bad_anchor_height")
            _need(HEX32, a["block_hash"], "bad_anchor_block_hash")
            h = a["height"]
            if hashes.get(h) != a["block_hash"]:
                raise Bad("anchor_block_not_in_view")
            got = c1.v11.run_proof(bytes.fromhex(target), a["proof"])
            if got is None or got != res["merkle"][h]:
                raise Bad("anchor_proof_fails")
            if res["tip"] - h + 1 < policy["min_depth"]:
                raise Bad("anchor_too_shallow")
            arows.append({"index": k, "height": h})
            D = h if D is None else min(D, h)
        except Bad as exc:
            arows.append({"index": k, "problem": exc.code})
    if anchors:
        how["direct"] = {"anchors": arows, "earliest_height": D, "before_draw": D is not None and D < H}
        if D is not None and D < H:
            fixed_by = "direct_anchor"
    if target in logged:
        how["log"] = {"seq": logged[target][0], "anchor_height": A, "before_draw": A < H}
        if A < H and fixed_by is None:
            fixed_by = "log"
    if target in wit:
        w = wit[target]
        pub, ear = w["published_height"], w["earliest_height"]
        st = "before" if pub is not None and pub < H else ("after" if ear is not None and ear >= H else "unresolved")
        how["witnesses"] = dict(w, order=st)
        if st == "before":
            fixed_by = "witnesses"
    rs["fixed"] = how
    rs["fixed_by"] = fixed_by
    # several versions shown one at a time: every other commitment in the bundle that shares anything
    others = sorted(d for d, it in known.items() if d != target and (
        it["provider"] == cm["provider"] or it["dataset_id"] == cm["dataset_id"]
        or it["dataset_sha256"] == cm["dataset_sha256"]
        or (cm["file_sha256"] is not None and it["file_sha256"] == cm["file_sha256"])))
    if others:
        rs["other_commitments"] = others
    rs["hedging"] = ("visible_only_if_every_version_went_through_these_witnesses" if fixed_by == "witnesses"
                     else "not_excluded" if fixed_by else None)
    binding = fixed_by is not None

    # the dataset the relying party has must be the committed one
    try:
        located = {}
        if cm["row_rule"] == "jcs-sha256":
            digs = ds.get("row_sha256")
            if not (isinstance(digs, list) and len(digs) <= MAX_ROWS and all(isinstance(d, str) for d in digs)):
                raise Bad("dataset_digests_missing")
            for d in digs:
                _need(HEX32, d, "bad_row_sha256")
            supplied = ds.get("rows", [])
            if not isinstance(supplied, list):
                raise Bad("bad_rows")
            for i, r in enumerate(supplied):
                located.setdefault(row_sha256(r), ("supplied %d" % i, r))
        else:
            b64 = ds.get("file_b64")
            if not isinstance(b64, str):
                raise Bad("dataset_file_missing")
            try:
                raw = base64.b64decode(b64, validate=True)
            except ValueError:
                raise Bad("bad_file_b64")
            if hashlib.sha256(raw).hexdigest() != cm["file_sha256"]:
                raise Bad("file_does_not_match_commitment")
            digs = []
            for loc, r in rows_of_file(raw, cm["row_rule"]):
                d = row_sha256(r)
                digs.append(d)
                located.setdefault(d, (loc, r))
        uniq = sorted(set(digs))
        if len(uniq) != cm["row_count"] or dataset_sha256(uniq, cm["row_rule"]) != cm["dataset_sha256"]:
            raise Bad("dataset_does_not_match_commitment")
    except Bad as exc:
        rs["status"] = exc.code
        return out
    rs["duplicate_rows_collapsed"] = len(digs) - len(uniq)
    uniq_set = set(uniq)

    # the draw
    if H not in hashes:
        rs["status"] = "draw_block_not_in_view"
        return out
    if res["tip"] - H + 1 < policy["min_depth"]:
        rs["status"] = "draw_block_too_shallow"
        return out
    beacon = hashes[H]
    sample = [d for d in uniq if drawn(beacon, d, cm["rate_ppm"])]
    in_sample = set(sample)
    rs["draw"] = {"height": H, "block_hash": beacon, "sampled": len(sample)}

    # checks: only checkers both named by the provider and accepted by the relying party count
    policy_ok = set(policy["checkers"]) - {cm["provider"], operator}
    accepted = set(cm["checkers"]) & policy_ok
    rs["accepted_checkers"] = sorted(accepted)
    crows, seen_bytes, by_row, objections = [], set(), {}, {}
    for i, raw_check in enumerate(checks):
        row = {"index": i, "counted": False}
        try:
            strict_value(raw_check)
            _, ck = _check(raw_check)
        except Bad as exc:
            row["problem"] = exc.code
            crows.append(row)
            continue
        b = jcs(ck)
        if b in seen_bytes:
            row["problem"] = "duplicate_check"
            crows.append(row)
            continue
        seen_bytes.add(b)
        row.update(checker=ck["checker"], row_sha256=ck["row_sha256"], verdict=ck["verdict"])
        reasons = []
        if ck["commitment_sha256"] != target:
            reasons.append("another_commitment")
        if ck["checker"] not in cm["checkers"]:
            reasons.append("checker_not_named")
        elif ck["checker"] not in accepted:
            reasons.append("checker_not_accepted")
        if ck["checker"] in (cm["provider"], operator):
            reasons.append("checker_is_party")
        if ck["row_sha256"] not in uniq_set:
            reasons.append("row_not_in_dataset")
        elif ck["row_sha256"] not in in_sample:
            reasons.append("row_not_sampled")
        sb = ck["seen_block"]
        if hashes.get(sb["height"]) != sb["hash"]:
            reasons.append("seen_block_not_in_view")
        elif sb["height"] < H:
            reasons.append("checked_before_draw")
        row["reasons"] = sorted(reasons)
        if not reasons:
            row["counted"] = True
            by_row.setdefault(ck["row_sha256"], {}).setdefault(ck["checker"], set()).add(ck["verdict"])
        elif (ck["verdict"] == "mismatch" and ck["checker"] in policy_ok and ck["row_sha256"] in in_sample
              and ck["commitment_sha256"] == target
              and set(reasons) <= {"checker_not_named", "checked_before_draw", "seen_block_not_in_view"}):
            # a checker the relying party trusts says this sampled row is wrong: whether or not the provider
            # named it and whenever it looked, that blocks the row from counting as shown correct
            row["objection"] = True
            objections.setdefault(ck["row_sha256"], set()).add(ck["checker"])
        crows.append(row)
    rs["checks"] = crows

    q = policy["quorum"]
    rows_out = []
    tally = {k: 0 for k in ("match", "mismatch", "contradicted", "short_of_quorum", "not_checkable",
                            "unreachable", "unchecked")}
    for d in sample:
        per = by_row.get(d, {})
        finals = {k: (next(iter(vs)) if len(vs) == 1 else "contradicted") for k, vs in per.items()}
        fv = list(finals.values())
        matches = fv.count("match")
        if "mismatch" in fv or d in objections:
            st = "mismatch"
        elif "contradicted" in fv:
            st = "contradicted"
        elif matches >= q:
            st = "match"
        elif "not_checkable" in fv:
            st = "not_checkable"
        elif "unreachable" in fv:
            st = "unreachable"
        elif matches:
            st = "short_of_quorum"
        else:
            st = "unchecked"
        tally[st] += 1
        r = {"row_sha256": d, "status": st, "checkers": {k: finals[k] for k in sorted(finals)}}
        if d in located:
            r["locator"] = located[d][0]
        if d in objections:
            r["objections"] = sorted(objections[d])
        if len(set(fv)) > 1 or (d in objections and "match" in fv):
            r["checkers_disagree"] = True
        rows_out.append(r)
    rs["rows"] = rows_out
    rs["tally"] = tally
    n = len(sample)
    enough = n >= policy["min_sampled"]
    ub = cp_upper_ppm(n - tally["match"], n) if binding and enough else None
    rs["bound"] = {"sampled": n, "shown_correct": tally["match"], "quorum": q,
                   "quorum_covers_every_accepted_checker": q >= len(accepted),
                   "not_shown_correct_upper_95_ppm": ub}
    if not binding:
        rs["status"] = "not_fixed_before_draw"
    elif len(accepted) < q:
        rs["status"] = "quorum_unreachable"
        rs["bound"]["not_shown_correct_upper_95_ppm"] = None
    elif ub is None:
        rs["status"] = "no_bound"
    else:
        rs["status"] = "settled"
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--settle")
    ap.add_argument("--policy")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--rows", nargs=2, metavar=("FILE", "RULE"))
    a = ap.parse_args()
    if a.selftest:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "vectors", "vectors_refsample_v0.json"), "rb") as f:
            vs = json.loads(f.read())
        bad = bad_b = 0
        for v in vs["vectors"]:
            if json.loads(jcs(settle(v["bundle"], v["policy"]))) != v["expected"]:
                bad += 1
                print("FAIL", v["id"])
        for (x, n), want in vs["bounds"]:
            if cp_upper_ppm(x, n) != want:
                bad_b += 1
                print("FAIL bound", x, n)
        print("%d/%d vectors agree, %d/%d bounds agree" % (len(vs["vectors"]) - bad, len(vs["vectors"]),
                                                          len(vs["bounds"]) - bad_b, len(vs["bounds"])))
        sys.exit(1 if bad or bad_b else 0)
    if a.rows:
        try:
            with open(a.rows[0], "rb") as f:
                raw = f.read()
            rows = rows_of_file(raw, a.rows[1])
            digs = [row_sha256(r) for _, r in rows]
        except (Bad, OSError) as exc:
            print(json.dumps({"refused": exc.code if isinstance(exc, Bad) else "unreadable_input"}))
            sys.exit(3)
        print(json.dumps({"file_sha256": hashlib.sha256(raw).hexdigest(), "rows": len(digs),
                          "row_count": len(set(digs)), "dataset_sha256": dataset_sha256(digs, a.rows[1])}))
        return
    if a.settle:
        if not a.policy:
            sys.stderr.write("--settle needs --policy: the relying party's own settings, never taken from the bundle\n")
            sys.exit(3)
        try:
            with open(a.settle, "rb") as f:
                b = load_data(f.read())
            with open(a.policy, "rb") as f:
                p = load_strict(f.read())
        except (Bad, ValueError, RecursionError, OSError) as exc:
            code = exc.code if isinstance(exc, Bad) else "unreadable_input"
            sys.stdout.write(jcs({"type": T_SETTLEMENT, "profile": PROFILE, "refused": code}).decode("utf-8") + "\n")
            sys.exit(3)
        out = settle(b, p)
        sys.stdout.write(jcs(out).decode("utf-8") + "\n")
        sys.exit(0 if out.get("refsample", {}).get("status") == "settled" else 2)
    ap.print_help()


if __name__ == "__main__":
    main()
