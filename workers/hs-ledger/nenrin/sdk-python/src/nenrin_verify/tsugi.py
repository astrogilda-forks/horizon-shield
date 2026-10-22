"""TSUGI recovery-chain verifier: the Python port of tsugi_verify.mjs (verifier 0.3.1), held to the same report.

A TSUGI segment is one incident written as append-only records: drift+ -> proposal -> authorization -> execution ->
verify. This module checks what the JavaScript checks, in the same order, with the same refusal codes and the same
refusal text:

  one record   the schema (recovery_schema), record_sha256 recomputed from the canonical bytes, the Ed25519
               signature when one is carried
  the chain    order, prev links, the hashes each record cites, an execution with no approved authorization,
               the proposal's primitive and expected_after against the execution and the re-verification
  strict mode  with operator keys, a human-approval primitive needs an authorization signed by a trusted key and
               not yet expired
  v2 draw      the random witness draw recomputed from beacon, pool and subject, the commit-then-reveal anchor,
               the embedded witness observations (signature, domain, drawn, pool key, request, time), the quorum

    import nenrin_verify.tsugi as tsugi
    report = tsugi.verify_chain(records, operator_keys=[b64], witness_quorum={"pool": pool, "q": 2, "k": 3})

    tsugi-verify chain.json [--operator-key <b64> | --fetch-operator-key <origin> | --trust-embedded-key]
                            [--pool pool.json --q N --k N --beacon <hash> --require-commitment
                             --anchor-height H --anchor-hash <hash>]

The command prints what `node tsugi_verify.mjs` prints, byte for byte, and exits the same way (0 ok, 1 refused,
2 usage). The JavaScript is the reference; where Python and JavaScript differ by default the port goes through
_js.py and _url.py. Nothing here opens a socket except `--fetch-operator-key`, which asks the origin you name.
"""
import hashlib
import math
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._js import (OBJECT_PROTOTYPE_KEYS, UNDEF, JSTypeError, NotReproduced, _JS_WS, _js_key_order,
                  is_num, loads, lower, nullish, number_to_string, prop, seq, stringify, to_number_js, to_string,
                  truthy, utf8)
from ._url import URLFailure, url_host
from .provenance import ed25519_key_ok

VERIFIER_VERSION = "0.4.0"

# Up to verifier 0.3.0, Node's WebCrypto rejected an Ed25519 raw public key that is not 32 bytes with a DOMException
# whose text depends on the Node release ("Invalid keyData" from Node 24, "Ed25519 raw keys must be exactly 32-bytes"
# on Node 22) and the refusal carried that text. From 0.3.1 the key is checked as canonical base64 of 32 bytes before
# WebCrypto sees it, so no refusal depends on the Node release; the constant stays for the case tooling.
KEY_LENGTH_MESSAGE = "Invalid keyData"


class JSError(Exception):
    """An Error the JavaScript throws with this message (caught where the JavaScript catches it)."""

    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


def _msg(e):
    return e.message if isinstance(e, JSError) else str(e)


# ============================== agreement_canonical: canonicalUtf8 ==============================

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0a: "\\n", 0x0c: "\\f", 0x0d: "\\r"}


def str_utf8(s):
    """json.dumps(ensure_ascii=False) string escaping: quote, backslash, and controls below 0x20 only."""
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif o in _SHORT:
            out.append(_SHORT[o])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _num(v):
    """agreement_canonical num(): a JavaScript number is a Python float and is written as repr(float) writes it."""
    f = float(v)
    if math.isnan(f):
        return "NaN"
    if math.isinf(f):
        return "Infinity" if f > 0 else "-Infinity"
    return repr(f)


class _Proto(object):
    """Object.prototype, as subsetMatches reaches it through `k in observed` and observed[k]."""

    def __repr__(self):
        return "Object.prototype"


class _Func(object):
    """A method of Object.prototype (observed.toString and the like), which canonicalUtf8 cannot write."""

    def __repr__(self):
        return "function"


OBJ_PROTO = _Proto()
FUNC = _Func()


def canonical_utf8(v):
    """canonicalUtf8: keys sorted by code point at every depth, separators , and :, non-ASCII written raw."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_num(v):
        return _num(v)
    if isinstance(v, str):
        return str_utf8(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical_utf8(x) for x in v) + "]"
    if v is OBJ_PROTO:
        return "{}"
    if isinstance(v, dict):
        return "{" + ",".join(str_utf8(k) + ":" + canonical_utf8(v[k]) for k in sorted(v)) + "}"
    raise JSTypeError("書けん型: " + ("function" if v is FUNC else "undefined"))


# ============================== recovery_schema ==============================

SCHEMAS = {
    "drift": "nenrin-drift-record-v1",
    "proposal": "nenrin-repair-proposal-v1",
    "authorization": "nenrin-authorization-v1",
    "execution": "nenrin-repair-execution-v1",
    "verify": "nenrin-verify-record-v1",
    "observation": "nenrin-witness-observation-v1",
}
ORDER = [SCHEMAS["drift"], SCHEMAS["proposal"], SCHEMAS["authorization"], SCHEMAS["execution"], SCHEMAS["verify"]]
EMBEDDED = [SCHEMAS["observation"]]

PRIMITIVES = {
    "quarantine_endpoint": {"reversible": True, "approval": "auto"},
    "redeploy_pinned": {"reversible": True, "approval": "human"},
    "resign_agent_card": {"reversible": True, "approval": "human"},
    "revert_to_last_witnessed_good": {"reversible": True, "approval": "human"},
    "rotate_credential": {"reversible": False, "approval": "human"},
}

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_ISO = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z\Z")
_DIGITS = re.compile(r"\A[0-9]+\Z")
_HTTPS = re.compile(r"\Ahttps://[^/" + re.escape(_JS_WS) + r"]")


def _is_str(v):
    return isinstance(v, str) and len(v) > 0


def _is_str_arr(v):
    return isinstance(v, list) and len(v) > 0 and all(_is_str(x) for x in v)


def _is_obj(v):
    return isinstance(v, dict)


def _is_hex(v):
    return _is_str(v) and bool(_HEX64.match(v))


def _is_digits(v):
    return _is_str(v) and bool(_DIGITS.match(v))


def _is_https(v):
    return _is_str(v) and bool(_HTTPS.match(v))


def _includes(xs, v):
    return isinstance(v, str) and v in xs


def _in_catalog(p):
    """`p in PRIMITIVES`: the in operator also finds Object.prototype's names (toString, __proto__, ...)."""
    return p in PRIMITIVES or p in OBJECT_PROTOTYPE_KEYS


def has_number(v):
    if is_num(v):
        return True
    if isinstance(v, list):
        return any(has_number(x) for x in v)
    if isinstance(v, dict):
        return any(has_number(x) for x in v.values())
    return False


def _check_common(r, refuse):
    if not _is_obj(r):
        refuse("not_object", "record is not a JSON object")
        return
    schema = prop(r, "schema")
    if not (_includes(ORDER, schema) or _includes(EMBEDDED, schema)):
        refuse("bad_schema", "schema must be one of " + ", ".join(ORDER + EMBEDDED))
    at = prop(r, "recorded_at")
    if not _is_str(at) or not _ISO.match(at):
        refuse("bad_recorded_at", "recorded_at must be ISO-8601 UTC ending in Z")
    w = prop(r, "witness")
    if not _is_obj(w) or not _is_str(prop(w, "name")) or not _is_str(prop(w, "vantage")):
        refuse("bad_witness", "witness.name and witness.vantage are required")
    if not _is_str_arr(prop(r, "establishes")):
        refuse("disclaimer_missing", "establishes must be a non-empty array of strings")
    if not _is_str_arr(prop(r, "does_not_establish")):
        refuse("disclaimer_missing", "does_not_establish must be a non-empty array of strings")
    prev = prop(r, "prev")
    if not (prev is None or _is_hex(prev)):
        refuse("bad_prev", "prev must be null or 64 hex")
    rs = prop(r, "record_sha256")
    if rs is not UNDEF and not _is_hex(rs):
        refuse("bad_record_sha256", "record_sha256, when present, must be 64 hex")
    if has_number(r):
        refuse("number_in_record", "v0 records carry no JSON numbers; write counts as strings")


def _check_drift(r, refuse):
    if not _is_str(prop(r, "endpoint")):
        refuse("bad_endpoint", "endpoint is required")
    if not _is_str(prop(r, "surface")):
        refuse("bad_surface", "surface is required (what was measured)")
    if not isinstance(prop(r, "drift"), bool):
        refuse("bad_drift", "drift must be a boolean")
    if not _is_obj(prop(r, "observed")):
        refuse("bad_observed", "observed must be an object")
    if not _is_obj(prop(r, "expected")):
        refuse("bad_expected", "expected must be an object")
    if prop(r, "drift") is True and not _is_str(prop(r, "kind")):
        refuse("bad_kind", "kind is required when drift is true")
    if prop(r, "prev") is not None:
        refuse("bad_prev", "a drift record starts a segment: prev must be null")
    if prop(r, "source") is not UNDEF and not _is_obj(prop(r, "source")):
        refuse("bad_source", "source, when present, is an object naming the external witness")


def _check_proposal(r, refuse):
    ds = prop(r, "drift_sha256")
    if not isinstance(ds, list) or len(ds) == 0 or not all(_is_hex(x) for x in ds):
        refuse("bad_drift_sha256", "drift_sha256 must be a non-empty array of 64 hex")
    p = prop(r, "primitive")
    if not _is_str(p) or not _in_catalog(p):
        refuse("primitive_not_in_catalog", "primitive must be one of " + ", ".join(PRIMITIVES))
    if not _is_str(prop(r, "diagnosis")):
        refuse("bad_diagnosis", "diagnosis is required")
    if not _is_obj(prop(r, "expected_after")):
        refuse("bad_expected_after", "expected_after must be an object: surface -> expected state")
    if not _is_str(prop(r, "rollback")):
        refuse("bad_rollback", "rollback is required")
    if not _is_hex(prop(r, "prev")):
        refuse("bad_prev", "proposal must link to the last drift record")
    rej = prop(r, "rejected")
    if rej is not UNDEF and not (isinstance(rej, list) and all(
            _is_obj(x) and _is_str(prop(x, "primitive")) and _is_str(prop(x, "why")) for x in rej)):
        refuse("bad_rejected", "rejected entries need primitive and why")


def _check_authorization(r, refuse):
    if not _is_hex(prop(r, "proposal_sha256")):
        refuse("bad_proposal_sha256", "proposal_sha256 must be 64 hex")
    if not _includes(["approved", "refused"], prop(r, "decision")):
        refuse("bad_decision", "decision must be approved or refused")
    if not _is_str(prop(r, "by")):
        refuse("bad_by", "by is required (who decided)")
    ex = prop(r, "expires_at")
    if not _is_str(ex) or not _ISO.match(ex):
        refuse("bad_expires_at", "expires_at must be ISO-8601 UTC")
    if not _is_hex(prop(r, "prev")):
        refuse("bad_prev", "authorization must link to the proposal")
    elif not seq(prop(r, "prev"), prop(r, "proposal_sha256")):
        refuse("prev_mismatch", "authorization.prev must equal proposal_sha256")


def _check_execution(r, refuse):
    if not _is_hex(prop(r, "authorization_sha256")):
        refuse("bad_authorization_sha256", "authorization_sha256 must be 64 hex")
    p = prop(r, "primitive")
    if not _is_str(p) or not _in_catalog(p):
        refuse("primitive_not_in_catalog", "primitive must be in the catalog")
    if not _is_obj(prop(r, "before")):
        refuse("bad_before", "before must be an object (state before)")
    if not _is_obj(prop(r, "after")):
        refuse("bad_after", "after must be an object (state after)")
    if not _includes(["ok", "failed", "rolled_back"], prop(r, "outcome")):
        refuse("bad_outcome", "outcome must be ok, failed or rolled_back")
    if not _is_str_arr(prop(r, "steps")):
        refuse("bad_steps", "steps must be a non-empty array of strings")
    if not _is_hex(prop(r, "prev")):
        refuse("bad_prev", "execution must link to the authorization")
    elif not seq(prop(r, "prev"), prop(r, "authorization_sha256")):
        refuse("prev_mismatch", "execution.prev must equal authorization_sha256")


def _check_verify(r, refuse):
    if not _is_hex(prop(r, "execution_sha256")):
        refuse("bad_execution_sha256", "execution_sha256 must be 64 hex")
    if not _is_obj(prop(r, "observed")):
        refuse("bad_observed", "observed must be an object")
    if not _is_obj(prop(r, "expected_after")):
        refuse("bad_expected_after", "expected_after must be an object")
    if not isinstance(prop(r, "recovered"), bool):
        refuse("bad_recovered", "recovered must be a boolean")
    ext = prop(r, "external")
    if ext is not UNDEF and not isinstance(ext, list):
        refuse("bad_external", "external, when present, is an array of external witness results")
    elif isinstance(ext, list):
        for e in ext:
            if not _is_obj(e):
                refuse("bad_external", "external entries must be objects")
                continue
            if prop(e, "record") is not UNDEF:
                if not _is_obj(prop(e, "record")):
                    refuse("bad_external", "external[].record, when present, is the witness's signed observation record")
                if not _is_str(prop(e, "signed_domain")):
                    refuse("bad_external", "external[].signed_domain is required beside a record")
            if prop(e, "answered") is not UNDEF and not isinstance(prop(e, "answered"), bool):
                refuse("bad_external", "external[].answered, when present, is a boolean")
    d = prop(r, "draw")
    if d is not UNDEF:
        if not _is_obj(d):
            refuse("bad_draw", "draw must be an object")
        else:
            b = prop(d, "beacon")
            if not _is_obj(b) or not _is_str(prop(b, "kind")) or not _is_digits(prop(b, "height")) or not _is_hex(prop(b, "hash")):
                refuse("bad_draw", "draw.beacon needs kind, height (digits as a string) and hash (64 hex)")
            if not _is_hex(prop(d, "pool_sha256")):
                refuse("bad_draw", "draw.pool_sha256 must be 64 hex")
            if not _is_digits(prop(d, "pool_size")):
                refuse("bad_draw", "draw.pool_size must be digits as a string")
            if not _is_digits(prop(d, "k")):
                refuse("bad_draw", "draw.k must be digits as a string")
            if not _is_hex(prop(d, "subject_sha256")):
                refuse("bad_draw", "draw.subject_sha256 must be 64 hex (the record the draw serves)")
            if not _is_hex(prop(d, "request_sha256")):
                refuse("bad_draw", "draw.request_sha256 must be 64 hex (the request every drawn witness received)")
            dr = prop(d, "drawn")
            if not isinstance(dr, list) or not all(_is_str(x) for x in dr):
                refuse("bad_draw", "draw.drawn must be an array of signed_domain strings (may be empty when the pool is empty)")
            c = prop(d, "commitment")
            if c is not UNDEF:
                if not _is_obj(c):
                    refuse("bad_draw", "draw.commitment must be an object")
                else:
                    if not _is_hex(prop(c, "subject_sha256")):
                        refuse("bad_draw", "draw.commitment.subject_sha256 must be 64 hex")
                    if not _is_digits(prop(c, "ledger_entry")):
                        refuse("bad_draw", "draw.commitment.ledger_entry must be digits as a string")
                    if not _is_https(prop(c, "ledger_url")):
                        refuse("bad_draw", "draw.commitment.ledger_url must be https")
                    if not _is_hex(prop(c, "claim_sha256")):
                        refuse("bad_draw", "draw.commitment.claim_sha256 must be 64 hex")
                    a = prop(c, "anchor")
                    if not _is_obj(a) or not _is_str(prop(a, "kind")) or not _is_digits(prop(a, "height")) or not _is_hex(prop(a, "hash")):
                        refuse("bad_draw", "draw.commitment.anchor needs kind, height (digits as a string) and hash (64 hex)")
                    # v2.4: a v2 commitment also fixes the pool and k (red team R5-F1). Both or neither.
                    if (prop(c, "pool_sha256") is not UNDEF) != (prop(c, "k_requested") is not UNDEF):
                        refuse("bad_draw", "draw.commitment carries pool_sha256 and k_requested together (v2) or neither (v1)")
                    if prop(c, "pool_sha256") is not UNDEF and not _is_hex(prop(c, "pool_sha256")):
                        refuse("bad_draw", "draw.commitment.pool_sha256 must be 64 hex")
                    if prop(c, "k_requested") is not UNDEF and not _is_digits(prop(c, "k_requested")):
                        refuse("bad_draw", "draw.commitment.k_requested must be digits as a string")
            # v2.4 (red team R2-1): the request body and the requested k travel with the draw. Optional, strict when present.
            if prop(d, "k_requested") is not UNDEF and not _is_digits(prop(d, "k_requested")):
                refuse("bad_draw", "draw.k_requested must be digits as a string")
            rqv = prop(d, "request")
            if rqv is not UNDEF:
                if not _is_obj(rqv):
                    refuse("bad_draw", "draw.request must be an object (the request body sent to every drawn witness)")
                else:
                    if not _is_hex(prop(rqv, "subject_sha256")) or not _is_hex(prop(rqv, "pool_sha256")):
                        refuse("bad_draw", "draw.request needs subject_sha256 and pool_sha256 (64 hex)")
                    rb = prop(rqv, "beacon")
                    if not _is_obj(rb) or not _is_str(prop(rb, "kind")) or not _is_digits(prop(rb, "height")) or not _is_hex(prop(rb, "hash")):
                        refuse("bad_draw", "draw.request.beacon needs kind, height (digits as a string) and hash (64 hex)")
                    if not _is_str(prop(rqv, "endpoint")) or not _is_str(prop(rqv, "requested_at")):
                        refuse("bad_draw", "draw.request needs endpoint and requested_at strings")
    if not _is_hex(prop(r, "prev")):
        refuse("bad_prev", "verify must link to the execution")
    elif not seq(prop(r, "prev"), prop(r, "execution_sha256")):
        refuse("prev_mismatch", "verify.prev must equal execution_sha256")


def _check_observation(r, refuse):
    if not _is_str(prop(r, "endpoint")):
        refuse("bad_endpoint", "endpoint is required (the origin that was measured)")
    obs = prop(r, "observed")
    if not _is_obj(obs) or len(obs) == 0 or not all(_is_obj(x) for x in obs.values()):
        refuse("bad_observed", "observed must be an object: surface -> observed state object")
    if not _is_hex(prop(r, "request_sha256")):
        refuse("bad_request_sha256", "request_sha256 must be 64 hex (canonical sha256 of the request the witness answered)")
    src = prop(r, "source")
    if (not _is_obj(src) or not seq(prop(src, "kind"), "external_witness") or not _is_str(prop(src, "signed_domain"))
            or not _is_https(prop(src, "key_url"))):
        refuse("bad_source", "source must be { kind: external_witness, signed_domain, key_url (https) }")
    elif truthy(prop(src, "key_url")) and truthy(prop(src, "signed_domain")):
        try:
            host = url_host(src["key_url"])
        except URLFailure:
            host = ""
        if lower(host) != lower(src["signed_domain"]):
            refuse("bad_source", "source.signed_domain must be the host of source.key_url (conduct-v1.1 11.4)")
    if prop(r, "prev") is not None:
        refuse("bad_prev", "an observation stands alone: prev must be null")


CHECK = {
    SCHEMAS["drift"]: _check_drift,
    SCHEMAS["proposal"]: _check_proposal,
    SCHEMAS["authorization"]: _check_authorization,
    SCHEMAS["execution"]: _check_execution,
    SCHEMAS["verify"]: _check_verify,
    SCHEMAS["observation"]: _check_observation,
}

# CHECK[record.schema] on a JavaScript object literal: a schema naming an Object.prototype method finds that method.
# "__proto__" finds Object.prototype itself, which is not callable; these six convert their first argument (the
# record) to a property key; the rest return without touching it.
_KEYING_METHODS = frozenset(("__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
                             "hasOwnProperty", "propertyIsEnumerable"))


def validate(record):
    """One record's schema check: the list of refusals, each (code, why) once (empty means the shape passed)."""
    refusals, seen = [], set()

    def refuse(code, why):
        k = code + "|" + why
        if k in seen:
            return
        seen.add(k)
        refusals.append({"code": code, "why": why})

    _check_common(record, refuse)
    if _is_obj(record):
        key = to_string(prop(record, "schema"))
        if key in CHECK:
            CHECK[key](record, refuse)
        elif key == "__proto__":
            raise JSTypeError("CHECK[record.schema] is not a function")
        elif key in _KEYING_METHODS:
            to_string(record)
    return refusals


# ============================== witness_draw ==============================

POOL_SCHEMA = "nenrin-witness-pool-v1"
DRAW_VERSION = "0.1.0"
COMMITMENT_SCHEMA = "tsugi-draw-commitment-v1"


def sha256_hex(b):
    return hashlib.sha256(utf8(b) if isinstance(b, str) else b).hexdigest()


def _hashed_entry(e):
    return {"signed_domain": e["signed_domain"], "key_url": e["key_url"], "public_key_ed25519_b64": e["public_key_ed25519_b64"]}


def _utf16(s):
    return s.encode("utf-16-be", "surrogatepass")


def normalize_pool(pool):
    """The pool in key order (UTF-16 code unit order of public_key_ed25519_b64), every entry checked."""
    if isinstance(pool, list):
        entries = pool
    elif truthy(pool) and isinstance(prop(pool, "entries"), list):
        entries = pool["entries"]
    else:
        raise JSError("pool must be an array of entries or { entries: [...] }")
    out = []
    for e in entries:
        if not _is_obj(e):
            raise JSError("pool entry is not an object")
        for k in ("signed_domain", "key_url", "public_key_ed25519_b64"):
            if not isinstance(prop(e, k), str) or not e[k]:
                raise JSError("pool entry lacks " + k)
        try:
            host = url_host(e["key_url"])
        except URLFailure:
            raise JSError("pool entry key_url is not a URL: " + e["key_url"])
        if lower(host) != lower(e["signed_domain"]):
            raise JSError("pool entry signed_domain " + e["signed_domain"] + " is not the host of its key_url (11.4)")
        pk = b64_exact(e["public_key_ed25519_b64"], 32)
        if pk is None or not ed25519_key_ok(pk):
            raise JSError("pool entry for " + e["signed_domain"] + " has a public_key_ed25519_b64 that is not canonical base64 of a usable Ed25519 key")
        n = _hashed_entry(e)
        if isinstance(prop(e, "a2a_url"), str):
            n["a2a_url"] = e["a2a_url"]
        out.append(n)
    out.sort(key=lambda x: _utf16(x["public_key_ed25519_b64"]))
    keys, domains = set(), set()
    for e in out:
        if e["public_key_ed25519_b64"] in keys:
            raise JSError("pool has a duplicate key " + e["public_key_ed25519_b64"])
        if lower(e["signed_domain"]) in domains:
            raise JSError("pool has a duplicate domain " + e["signed_domain"])
        keys.add(e["public_key_ed25519_b64"])
        domains.add(lower(e["signed_domain"]))
    return out


def pool_canonical(pool):
    return canonical_utf8({"schema": POOL_SCHEMA, "entries": [_hashed_entry(e) for e in normalize_pool(pool)]})


def pool_sha256(pool):
    return sha256_hex(pool_canonical(pool))


def draw(pool, beacon_hash, subject_sha256, k, exclude_host=None):
    """The witness draw: seed = sha256(beacon | pool_sha256 | subject), partial Fisher-Yates over the pool in key order."""
    bh = to_string(beacon_hash) if truthy(beacon_hash) else ""
    if not _HEX64.match(bh):
        raise JSError("beaconHash must be 64 hex (a Bitcoin block hash)")
    sh = to_string(subject_sha256) if truthy(subject_sha256) else ""
    if not _HEX64.match(sh):
        raise JSError("subjectSha256 must be 64 hex (the record_sha256 the draw serves)")
    want = to_number_js(k)
    if not (is_num(want) and math.isfinite(want) and float(want).is_integer()) or want < 0:
        raise JSError("k must be a non-negative integer")
    every = normalize_pool(pool)
    psha = sha256_hex(canonical_utf8({"schema": POOL_SCHEMA, "entries": [_hashed_entry(e) for e in every]}))
    ex = lower(to_string(exclude_host)) if truthy(exclude_host) else None
    eligible = [e for e in every if not ex or lower(e["signed_domain"]) != ex]
    n = len(eligible)
    kk = int(min(want, n))
    seed = sha256_hex(to_string(beacon_hash) + "|" + psha + "|" + to_string(subject_sha256))
    arr = list(eligible)
    for i in range(kk):
        r = sha256_hex(seed + "|" + str(i))
        j = i + int(r[:16], 16) % (n - i)
        arr[i], arr[j] = arr[j], arr[i]
    chosen = arr[:kk]
    return {"pool_sha256": psha, "pool_size": str(len(every)), "eligible": str(n), "k": str(kk),
            "k_requested": number_to_string(want), "seed_sha256": seed, "drawn": [e["signed_domain"] for e in chosen],
            "entries": chosen}


def commitment_claim_text(subject_sha256):
    s = to_string(subject_sha256) if truthy(subject_sha256) else ""
    if not _HEX64.match(s):
        raise JSError("subjectSha256 must be 64 hex")
    return ("# " + COMMITMENT_SCHEMA + "\n\nsubject_sha256: " + subject_sha256 + "\n\nThis entry commits the record named "
            "by subject_sha256 (a TSUGI execution record) to the ledger before any re-verification witness is drawn. "
            "The draw's beacon must be the Bitcoin block after the block this entry is anchored to. Establishes: that "
            "subject_sha256 existed no later than the anchor block. Does not establish: anything about the record's content.\n")


COMMITMENT_SCHEMA_V2 = "tsugi-draw-commitment-v2"


def commitment_claim_text_v2(subject_sha256, pool_sha256, k_requested):
    """commitmentClaimTextV2 (v2.4, red team R5-F1): the subject, the pool hash and the requested k, fixed together."""
    if not _HEX64.match(to_string(subject_sha256) if truthy(subject_sha256) else ""):
        raise JSError("subjectSha256 must be 64 hex")
    if not _HEX64.match(to_string(pool_sha256) if truthy(pool_sha256) else ""):
        raise JSError("poolSha256 must be 64 hex")
    if not re.fullmatch(r"0|[1-9][0-9]*", to_string(k_requested)):
        raise JSError("kRequested must be digits as a string")
    return ("# " + COMMITMENT_SCHEMA_V2 + "\n\nsubject_sha256: " + to_string(subject_sha256) + "\npool_sha256: " + to_string(pool_sha256)
            + "\nk_requested: " + to_string(k_requested) + "\n\nThis entry commits the record named by subject_sha256 (a TSUGI "
            "execution record), the witness pool named by pool_sha256 and the number of witnesses to draw, before any "
            "re-verification witness is drawn. The draw's beacon must be the Bitcoin block after the block this entry is "
            "anchored to. Establishes: that subject, pool and k were fixed no later than the anchor block. Does not "
            "establish: anything about the record's content or about the witnesses in the pool.\n")


# ============================== recovery_verify ==============================

_SIG_FIELDS = ("record_sha256", "signature_ed25519_b64", "public_key_ed25519_b64")


def hashed_body(record):
    return {k: v for k, v in record.items() if k not in _SIG_FIELDS}


def canonical_text(record):
    return canonical_utf8(hashed_body(record))


def canonical_bytes(record):
    return utf8(canonical_text(record))


def record_sha256(record):
    return sha256_hex(canonical_bytes(record))


_B64_STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def b64_exact(s, n):
    """tsugi_verify.mjs b64Exact (0.3.1): the n bytes of a field written in canonical standard base64 (RFC 4648
    section 4: the standard alphabet, padding present, no whitespace, unused trailing bits zero), else None."""
    import base64 as _b64
    if not isinstance(s, str) or len(s) == 0 or len(s) % 4 != 0 or not _B64_STD.fullmatch(s):
        return None
    try:
        b = _b64.b64decode(s, validate=True)
    except Exception:
        return None
    if len(b) != n or _b64.b64encode(b).decode("ascii") != s:
        return None
    return b


def verify_signature(record):
    sig, pub = prop(record, "signature_ed25519_b64"), prop(record, "public_key_ed25519_b64")
    if not truthy(sig) or not truthy(pub):
        return {"ok": False, "why": "signature_ed25519_b64 and public_key_ed25519_b64 must both be present"}
    raw = b64_exact(pub, 32)
    if raw is None:
        return {"ok": False, "why": "public_key_ed25519_b64 must be a 32-byte Ed25519 key in canonical standard base64"}
    if not ed25519_key_ok(raw):
        return {"ok": False, "why": "public_key_ed25519_b64 is not a usable Ed25519 key (it must be the canonical encoding of a point in the prime-order subgroup)"}
    sb = b64_exact(sig, 64)
    if sb is None:
        return {"ok": False, "why": "signature_ed25519_b64 must be a 64-byte Ed25519 signature in canonical standard base64"}
    try:
        key = Ed25519PublicKey.from_public_bytes(raw)
        try:
            key.verify(sb, canonical_bytes(record))
            ok = True
        except InvalidSignature:
            ok = False
    except (JSError, JSTypeError) as e:
        return {"ok": False, "why": "signature check failed: " + _msg(e)}
    return {"ok": True} if ok else {"ok": False, "why": "Ed25519 signature does not verify over the canonical bytes"}


def verify_record(record):
    refusals = validate(record)
    if refusals:
        return {"ok": False, "refusals": refusals}
    h = record_sha256(record)
    rs = prop(record, "record_sha256")
    if rs is not UNDEF and not seq(rs, h):
        return {"ok": False, "refusals": [{"code": "hash_mismatch", "why": "record_sha256 does not recompute: carried " + to_string(rs) + ", computed " + h}]}
    if prop(record, "signature_ed25519_b64") is not UNDEF or prop(record, "public_key_ed25519_b64") is not UNDEF:
        s = verify_signature(record)
        if not s["ok"]:
            return {"ok": False, "refusals": [{"code": "bad_signature", "why": s["why"]}]}
    return {"ok": True, "refusals": [], "record_sha256": h}


def _has(o, k):
    if o is OBJ_PROTO:
        return k in OBJECT_PROTOTYPE_KEYS
    return k in o or k in OBJECT_PROTOTYPE_KEYS


def _get(o, k):
    if o is not OBJ_PROTO and k in o:
        return o[k]
    if k == "__proto__":
        return None if o is OBJ_PROTO else OBJ_PROTO
    return FUNC


def subset_matches(expected, observed):
    """Every key of expected is in observed with the same value (observed may carry more). `k in observed` also
    finds Object.prototype's names, so an expected key such as toString meets a function and the JavaScript throws."""
    eo = isinstance(expected, dict) or expected is OBJ_PROTO
    oo = isinstance(observed, dict) or observed is OBJ_PROTO
    if eo and oo:
        keys = [] if expected is OBJ_PROTO else _js_key_order(list(expected))
        return all(_has(observed, k) and subset_matches(_get(expected, k), _get(observed, k)) for k in keys)
    return canonical_utf8(expected) == canonical_utf8(observed)


def host_of(u):
    try:
        return lower(url_host(u))
    except URLFailure:
        return ""


def verify_witnesses(verify, own_host=None, endpoint=None, execution_sha256=None, execution_at=None, quorum=None):
    refusals = []

    def refuse(code, why):
        refusals.append({"code": code, "why": why})

    qv = prop(quorum, "q") if truthy(quorum) else UNDEF
    q = to_number_js(qv) if truthy(quorum) and not nullish(qv) else None
    pool = prop(quorum, "pool") if truthy(quorum) and truthy(prop(quorum, "pool")) else None
    beacon_hash = lower(to_string(quorum["beaconHash"])) if truthy(quorum) and truthy(prop(quorum, "beaconHash")) else None
    kv = prop(quorum, "k") if truthy(quorum) else UNDEF
    k_expected = to_string(kv) if truthy(quorum) and not nullish(kv) else None
    require_commitment = bool(truthy(quorum) and truthy(prop(quorum, "requireCommitment")))
    anchor = prop(quorum, "commitmentAnchor") if truthy(quorum) and truthy(prop(quorum, "commitmentAnchor")) else None
    # 0.4.0 (v2.4): requireV24 refuses a draw in the older form; beaconTime is the beacon block time the reader fetched
    require_v24 = bool(truthy(quorum) and truthy(prop(quorum, "requireV24")))
    beacon_time = to_string(prop(quorum, "beaconTime")) if truthy(quorum) and truthy(prop(quorum, "beaconTime")) else None
    forms = []
    requested_at = None
    d = prop(verify, "draw")
    drawn = d["drawn"] if truthy(d) and isinstance(prop(d, "drawn"), list) else []
    own = lower(to_string(own_host)) if truthy(own_host) else ""
    if truthy(d):
        if truthy(execution_sha256) and not seq(prop(d, "subject_sha256"), execution_sha256):
            refuse("draw_subject_mismatch", "draw.subject_sha256 " + to_string(prop(d, "subject_sha256")) + " is not the execution record_sha256 " + execution_sha256)
        if own and any(lower(to_string(x)) == own for x in drawn):
            refuse("self_witness", "the draw lists the endpoint's own host " + to_string(own_host) + " as a witness (11.4)")
        if beacon_hash and lower(to_string(d["beacon"]["hash"])) != beacon_hash:
            refuse("beacon_mismatch", "draw.beacon.hash " + to_string(d["beacon"]["hash"]) + " is not the beacon the verifier fetched " + beacon_hash)
        if (k_expected and not seq(prop(d, "k"), k_expected) and not seq(prop(d, "pool_size"), "0")
                and to_number_js(prop(d, "k")) < to_number_js(k_expected)):
            refuse("draw_mismatch", "draw.k " + to_string(prop(d, "k")) + " is below the policy k " + k_expected + " (the operator may not shorten the draw)")
        # 0.4.0 (red team R2-1): k is held to the policy in both directions
        if prop(d, "k_requested") is not UNDEF:
            if k_expected and not seq(prop(d, "k_requested"), k_expected):
                refuse("draw_k_mismatch", "draw.k_requested " + to_string(prop(d, "k_requested")) + " is not the policy k " + k_expected + " (the operator may not widen or shorten the draw)")
            if to_number_js(prop(d, "k")) > to_number_js(prop(d, "k_requested")):
                refuse("draw_k_mismatch", "draw.k " + to_string(prop(d, "k")) + " is above draw.k_requested " + to_string(prop(d, "k_requested")))
        else:
            forms.append("k_not_recorded")
            if require_v24:
                refuse("draw_k_unrecorded", "policy requires a v2.4 draw; draw.k_requested is absent")
            if k_expected and to_number_js(prop(d, "k")) > to_number_js(k_expected):
                refuse("draw_k_mismatch", "draw.k " + to_string(prop(d, "k")) + " is above the policy k " + k_expected + " (the operator may not widen the draw)")
        # 0.4.0 (red team R2-1): the request travels with the draw and must name this draw's subject, pool and beacon
        if prop(d, "request") is not UNDEF:
            rq = d["request"]
            rs = sha256_hex(canonical_utf8(rq))
            if not seq(rs, prop(d, "request_sha256")):
                refuse("draw_request_mismatch", "sha256 of draw.request is " + rs + ", draw.request_sha256 says " + to_string(prop(d, "request_sha256")))
            rb = prop(rq, "beacon")
            same_beacon = (truthy(rb) and to_string(prop(rb, "kind")) == to_string(d["beacon"]["kind"])
                           and to_string(prop(rb, "height")) == to_string(d["beacon"]["height"])
                           and lower(to_string(prop(rb, "hash"))) == lower(to_string(d["beacon"]["hash"])))
            if not seq(prop(rq, "subject_sha256"), prop(d, "subject_sha256")) or not seq(prop(rq, "pool_sha256"), prop(d, "pool_sha256")) or not same_beacon:
                refuse("draw_request_unbound", "draw.request names subject " + to_string(prop(rq, "subject_sha256")) + ", pool " + to_string(prop(rq, "pool_sha256"))
                       + " and beacon " + to_string(prop(rb, "hash") if truthy(rb) else rb) + "; the draw is for subject " + to_string(prop(d, "subject_sha256"))
                       + ", pool " + to_string(prop(d, "pool_sha256")) + " and beacon " + to_string(d["beacon"]["hash"]))
            if truthy(endpoint) and host_of(prop(rq, "endpoint")) != host_of(endpoint):
                refuse("draw_request_unbound", "draw.request is about " + to_string(prop(rq, "endpoint")) + ", the segment is about " + to_string(endpoint))
            if beacon_time and to_string(prop(rq, "requested_at")) < beacon_time:
                refuse("request_before_beacon", "draw.request.requested_at " + to_string(prop(rq, "requested_at")) + " is before the beacon block time " + beacon_time)
            requested_at = to_string(prop(rq, "requested_at"))
        else:
            forms.append("request_not_carried")
            if require_v24:
                refuse("draw_request_absent", "policy requires a v2.4 draw; draw.request is absent, so request_sha256 is not tied to this subject, pool and beacon")
        c = prop(d, "commitment")
        if not truthy(c):
            forms.append("pool_not_committed")
        if require_commitment and not truthy(c):
            refuse("draw_uncommitted", "policy requires the draw's subject to be anchored on the ledger before the beacon block; draw.commitment is absent (the operator could have re-ground the draw)")
        if truthy(c):
            if not seq(prop(c, "subject_sha256"), prop(d, "subject_sha256")):
                refuse("draw_subject_mismatch", "draw.commitment.subject_sha256 is not draw.subject_sha256")
            if prop(c, "pool_sha256") is not UNDEF:
                # 0.4.0 (red team R5-F1): a v2 commitment fixes the pool and k before the beacon
                claim = None
                try:
                    claim = sha256_hex(commitment_claim_text_v2(prop(c, "subject_sha256"), prop(c, "pool_sha256"), prop(c, "k_requested")))
                except JSError as e:
                    refuse("bad_draw", "draw.commitment v2 fields: " + _msg(e))
                if claim and not seq(prop(c, "claim_sha256"), claim):
                    refuse("commitment_claim_mismatch", "draw.commitment.claim_sha256 " + to_string(prop(c, "claim_sha256")) + " is not sha256(commitmentClaimTextV2(subject, pool, k)) " + claim + ": the ledger entry named does not commit this subject, pool and k")
                if not seq(prop(c, "pool_sha256"), prop(d, "pool_sha256")):
                    refuse("commitment_pool_mismatch", "the draw uses pool " + to_string(prop(d, "pool_sha256")) + ", the commitment fixed pool " + to_string(prop(c, "pool_sha256")) + " before the beacon")
                if not seq(prop(c, "k_requested"), prop(d, "k_requested")):
                    refuse("commitment_k_mismatch", "the draw requested k " + to_string(prop(d, "k_requested")) + ", the commitment fixed k " + to_string(prop(c, "k_requested")) + " before the beacon")
            else:
                claim = sha256_hex(commitment_claim_text(c["subject_sha256"]))
                if not seq(prop(c, "claim_sha256"), claim):
                    refuse("commitment_claim_mismatch", "draw.commitment.claim_sha256 " + to_string(prop(c, "claim_sha256")) + " is not sha256(commitmentClaimText(subject)) " + claim + ": the ledger entry named does not commit this subject")
                forms.append("pool_not_committed")
                if require_v24:
                    refuse("draw_pool_uncommitted", "policy requires a v2.4 draw; draw.commitment is v1 and does not fix the pool, so the pool could have been chosen after the beacon")
            ah, bh = c["anchor"]["height"], d["beacon"]["height"]
            if number_to_string(to_number_js(ah) + 1) != to_string(bh):
                refuse("beacon_not_next_block", "beacon.height " + to_string(bh) + " is not anchor.height + 1 (" + to_string(ah) + " + 1): the beacon must be the block after the one the subject is anchored to")
            if anchor is not None:
                if not seq(to_string(prop(anchor, "height")), ah):
                    refuse("commitment_mismatch", "the ledger entry's OTS proof anchors at height " + to_string(prop(anchor, "height")) + ", the record says " + to_string(ah))
                if truthy(prop(anchor, "hash")) and lower(to_string(anchor["hash"])) != lower(to_string(c["anchor"]["hash"])):
                    refuse("commitment_mismatch", "the anchor block hash the reader verified is not the one in the record")
        if pool is not None:
            try:
                re_ = draw(pool, d["beacon"]["hash"], prop(d, "subject_sha256"), prop(d, "k_requested") if prop(d, "k_requested") is not UNDEF else prop(d, "k"), own or None)
                if not seq(re_["pool_sha256"], prop(d, "pool_sha256")):
                    refuse("pool_mismatch", "the pool given to the verifier hashes to " + re_["pool_sha256"] + ", the record says " + to_string(prop(d, "pool_sha256")))
                elif canonical_utf8(re_["drawn"]) != canonical_utf8(drawn):
                    refuse("draw_mismatch", "recomputing the draw from beacon, pool and subject gives [" + ", ".join(re_["drawn"]) + "], the record says [" + ", ".join(to_string(x) for x in drawn) + "]")
                elif not seq(re_["pool_size"], prop(d, "pool_size")):
                    refuse("draw_mismatch", "draw.pool_size " + to_string(prop(d, "pool_size")) + " is not the size of the pool given (" + re_["pool_size"] + ")")
                elif not seq(re_["k"], prop(d, "k")):
                    refuse("draw_mismatch", "drawing k_requested " + to_string(prop(d, "k_requested")) + " from the pool given draws " + re_["k"] + ", the record says " + to_string(prop(d, "k")))
            except (JSError, JSTypeError) as e:
                refuse("bad_pool", "the pool given to the verifier is malformed: " + _msg(e))
    pool_by_domain = None
    if pool is not None:
        try:
            pool_by_domain = {lower(e["signed_domain"]): e for e in normalize_pool(pool)}
        except (JSError, JSTypeError):
            pool_by_domain = None
    answered, agreeing, disagreeing, key_voted = [], [], [], set()
    ext = prop(verify, "external")
    ext = ext if isinstance(ext, list) else []
    for n, e in enumerate(ext):
        if not truthy(e) or not truthy(prop(e, "record")):
            continue
        rec, tag = e["record"], "external[" + str(n) + "]"
        v = verify_record(rec)
        if not v["ok"]:
            for x in v["refusals"]:
                refuse(x["code"], tag + ": " + x["why"])
            continue
        if not seq(prop(rec, "schema"), SCHEMAS["observation"]):
            refuse("bad_external", tag + ": record is " + to_string(prop(rec, "schema")) + ", not " + SCHEMAS["observation"])
            continue
        if not truthy(prop(rec, "signature_ed25519_b64")) or not truthy(prop(rec, "public_key_ed25519_b64")):
            refuse("witness_unsigned", tag + ": an embedded observation must be signed")
            continue
        src = rec["source"]
        dom = lower(to_string(src["signed_domain"]))
        if dom != lower(to_string(prop(e, "signed_domain"))):
            refuse("witness_domain_mismatch", tag + ": record is signed for " + to_string(src["signed_domain"]) + ", entry says " + to_string(prop(e, "signed_domain")))
            continue
        if own and dom == own:
            refuse("self_witness", tag + ": the endpoint's own host witnessed itself (11.4)")
            continue
        if not any(lower(to_string(x)) == dom for x in drawn):
            refuse("witness_not_drawn", tag + ": " + to_string(src["signed_domain"]) + " was not drawn")
            continue
        if truthy(endpoint) and host_of(rec["endpoint"]) != host_of(endpoint):
            refuse("witness_endpoint_mismatch", tag + ": observation is about " + to_string(rec["endpoint"]) + ", the segment is about " + to_string(endpoint))
            continue
        if truthy(d) and not seq(prop(rec, "request_sha256"), prop(d, "request_sha256")):
            refuse("witness_request_mismatch", tag + ": observation answers request " + to_string(prop(rec, "request_sha256")) + ", the draw sent " + to_string(prop(d, "request_sha256")))
            continue
        if requested_at and rec["recorded_at"] < requested_at:
            refuse("witness_before_request", tag + ": observation recorded_at " + rec["recorded_at"] + " is before the request it answers was made (" + requested_at + ")")
            continue
        if beacon_time and rec["recorded_at"] < beacon_time:
            refuse("witness_before_beacon", tag + ": observation recorded_at " + rec["recorded_at"] + " is before the beacon block time " + beacon_time + " that drew this witness")
            continue
        if truthy(execution_at) and rec["recorded_at"] < execution_at:
            refuse("witness_before_execution", tag + ": observation recorded_at " + rec["recorded_at"] + " is before the execution " + execution_at + " it is supposed to re-verify")
            continue
        if pool_by_domain is not None:
            pe = pool_by_domain.get(dom)
            if (pe is None or not seq(pe["public_key_ed25519_b64"], prop(rec, "public_key_ed25519_b64"))
                    or not seq(pe["key_url"], prop(src, "key_url"))):
                refuse("witness_key_mismatch", tag + ": signed with a key or key_url that is not the pool's for " + to_string(src["signed_domain"]))
                continue
        answered.append(src["signed_domain"])
        if dom in agreeing or dom in disagreeing:
            continue
        signer = prop(rec, "public_key_ed25519_b64")   # one key, one vote (0.3.1), as tsugi_verify.mjs
        if signer in key_voted:
            continue
        key_voted.add(signer)
        (agreeing if subset_matches(prop(verify, "expected_after"), prop(rec, "observed")) else disagreeing).append(dom)
    if q is not None and prop(verify, "recovered") is True and len(agreeing) < q:
        refuse("witness_quorum_short", "recovered is true but " + str(len(agreeing)) + " of the required " + to_string(q)
               + " drawn witnesses observed the expected state (drawn " + str(len(drawn)) + ", answered " + str(len(answered))
               + ", disagreeing " + str(len(disagreeing)) + ")")
    out = {"refusals": refusals, "drawn": list(drawn), "answered": answered, "agreeing": agreeing, "disagreeing": disagreeing}
    if truthy(d):
        out["forms"] = forms
    return out


def verify_chain(records, opts=None, operator_keys=None, witness_quorum=None):
    """verifyChain(records, opts). opts uses the JavaScript names ({"operatorKeys": [...], "witnessQuorum": {...}});
    operator_keys and witness_quorum are the same two options as keyword arguments."""
    opts = dict(opts or {})
    if operator_keys is not None:
        opts["operatorKeys"] = operator_keys
    if witness_quorum is not None:
        opts["witnessQuorum"] = witness_quorum
    operator_keys = opts.get("operatorKeys") if isinstance(opts.get("operatorKeys"), list) else None
    wq = opts.get("witnessQuorum") if isinstance(opts.get("witnessQuorum"), (dict, list)) else None
    refusals = []

    def refuse(code, why):
        refusals.append({"code": code, "why": why})

    if not isinstance(records, list) or len(records) == 0:
        refuse("empty_chain", "no records")
        return {"ok": False, "refusals": refusals}
    hashes = []
    for i, r in enumerate(records):
        v = verify_record(r)
        if not v["ok"]:
            schema = prop(r, "schema") if truthy(r) else r
            for x in v["refusals"]:
                refuse(x["code"], "record[" + str(i) + "] (" + to_string(schema) + "): " + x["why"])
            return {"ok": False, "refusals": refusals}
        hashes.append(v["record_sha256"])
    i, drifts = 0, []
    while i < len(records) and seq(records[i]["schema"], SCHEMAS["drift"]):
        drifts.append(hashes[i])
        i += 1
    if not drifts:
        refuse("no_drift", "a segment starts with at least one drift record")
        return {"ok": False, "refusals": refusals}
    rest = records[i:]
    expect = [SCHEMAS["proposal"], SCHEMAS["authorization"], SCHEMAS["execution"], SCHEMAS["verify"]]
    if len(rest) > len(expect):
        refuse("bad_order", "more than " + str(len(expect)) + " records after the drift records")
    for k in range(min(len(rest), len(expect))):
        if not seq(rest[k]["schema"], expect[k]):
            refuse("bad_order", "record[" + str(i + k) + "] is " + to_string(rest[k]["schema"]) + ", expected " + expect[k])
    if refusals:
        return {"ok": False, "refusals": refusals}
    for k in range(i, len(records)):
        if not seq(records[k]["prev"], hashes[k - 1]):
            refuse("chain_broken", "record[" + str(k) + "].prev " + to_string(records[k]["prev"]) + " != previous record_sha256 " + hashes[k - 1])
    proposal, authorization, execution, verify = (rest + [UNDEF] * 4)[:4]
    if truthy(proposal):
        for h in proposal["drift_sha256"]:
            if h not in drifts:
                refuse("unknown_drift", "proposal cites drift " + h + " that is not in this segment")
    if truthy(authorization) and not seq(authorization["proposal_sha256"], hashes[i]):
        refuse("ref_mismatch", "authorization.proposal_sha256 != proposal record_sha256")
    if truthy(execution) and not seq(execution["authorization_sha256"], hashes[i + 1]):
        refuse("ref_mismatch", "execution.authorization_sha256 != authorization record_sha256")
    if truthy(verify) and not seq(verify["execution_sha256"], hashes[i + 2]):
        refuse("ref_mismatch", "verify.execution_sha256 != execution record_sha256")
    if truthy(authorization) and truthy(execution) and not seq(authorization["decision"], "approved"):
        refuse("unauthorized_execution", "execution follows an authorization whose decision is " + to_string(authorization["decision"]))
    if truthy(execution):
        prim = execution["primitive"]
        needs_human = prim in PRIMITIVES and PRIMITIVES[prim]["approval"] == "human"
        if needs_human and operator_keys is not None:
            if not truthy(authorization):
                refuse("unauthorized_execution", "human-approval primitive " + prim + " executed with no authorization")
            else:
                pub = prop(authorization, "public_key_ed25519_b64")
                if not (truthy(prop(authorization, "signature_ed25519_b64")) and truthy(pub)):
                    refuse("authorization_unsigned", "human-approval primitive " + prim + " follows an authorization not signed by an operator key")
                elif not any(seq(x, pub) for x in operator_keys):
                    refuse("authorization_untrusted_key", "authorization signed by a key not in the operator trust set")
        if truthy(authorization) and truthy(prop(authorization, "expires_at")) and execution["recorded_at"] > authorization["expires_at"]:
            refuse("authorization_expired", "execution.recorded_at " + execution["recorded_at"] + " is after authorization.expires_at " + authorization["expires_at"])
    if truthy(proposal) and truthy(execution) and not seq(proposal["primitive"], execution["primitive"]):
        refuse("primitive_mismatch", "execution.primitive " + execution["primitive"] + " != proposal.primitive " + proposal["primitive"])
    if truthy(proposal) and truthy(verify) and canonical_utf8(proposal["expected_after"]) != canonical_utf8(verify["expected_after"]):
        refuse("expected_after_drift", "verify.expected_after differs from proposal.expected_after: the target moved after authorization")
    if truthy(verify) and verify["recovered"] is True:
        for k in _js_key_order(list(verify["expected_after"])):
            if not _has(verify["observed"], k):
                refuse("recovered_unobserved", "recovered is true but observed has no entry for surface " + k)
    witness = None
    if truthy(verify) and (wq is not None or prop(verify, "draw") is not UNDEF or (
            isinstance(prop(verify, "external"), list) and any(truthy(e) and truthy(prop(e, "record")) for e in verify["external"]))):
        witness = verify_witnesses(verify, own_host=host_of(records[0]["endpoint"]), endpoint=records[0]["endpoint"],
                                   execution_sha256=hashes[i + 2],
                                   execution_at=execution["recorded_at"] if truthy(execution) else execution, quorum=wq)
        for x in witness["refusals"]:
            refuse(x["code"], x["why"])
    segment = {"drifts": drifts, "hashes": hashes, "complete": len(rest) == 4}
    if witness is not None:
        segment["witness"] = {"drawn": witness["drawn"], "answered": witness["answered"], "agreeing": witness["agreeing"],
                              "disagreeing": witness["disagreeing"]}
        if "forms" in witness:
            segment["witness"]["forms"] = witness["forms"]
    return {"ok": len(refusals) == 0, "refusals": refusals, "segment": segment}


def fetch_operator_keys(origin):
    """fetchOperatorKeys(origin): GET <origin>/keys/operator.json (404 means none published yet). The only network
    call in this package, made only when asked for."""
    import urllib.error
    import urllib.request
    url = re.sub(r"/+\Z", "", to_string(origin)) + "/keys/operator.json"
    req = urllib.request.Request(url, headers={"user-agent": "recovery-verify/" + VERIFIER_VERSION})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise JSError("operator key route answered http " + str(e.code))
    text = body.decode("utf-8", "replace")
    if text.startswith("﻿"):
        text = text[1:]
    j = loads(text)
    pk = prop(j, "public_key_ed25519_b64") if truthy(j) else UNDEF
    if truthy(j) and isinstance(pk, str) and pk.strip(_JS_WS):
        return [pk.strip(_JS_WS)]
    return []


# ============================== CLI ==============================

USAGE = ("usage: tsugi-verify chain.json [--operator-key <b64> | --fetch-operator-key <origin> | --trust-embedded-key] "
         "[--pool pool.json --q N --k N --beacon <hash> --require-commitment --anchor-height H --anchor-hash <hash>]")
NOTE = ("lenient: no operator key given, so a chat-approved (unsigned) authorization passes; pass --operator-key or "
        "--fetch-operator-key <origin> for strict")
DOES_NOT_ESTABLISH = [
    "that any record is true: hashes and signatures prove who wrote what and in which order, not that the observation was correct",
    "that the repair was the right one: that is the proposal's own does_not_establish",
    "operator independence of the witness that wrote the drift records: read witness.vantage",
]


class Usage(Exception):
    pass


def _args(argv):
    a, pos, i = {}, [], 0
    while i < len(argv):
        x = argv[i]
        if x.startswith("--"):
            v = argv[i + 1] if i + 1 < len(argv) else UNDEF
            if v is not UNDEF and not v.startswith("--"):
                a[x[2:]] = v
                i += 1
            else:
                a[x[2:]] = True
        else:
            pos.append(x)
        i += 1
    return a, pos


def _read_file(path):
    if not isinstance(path, str):
        raise JSTypeError('The "path" argument must be of type string or an instance of Buffer or URL.')
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def run(argv, read_file=_read_file, fetch_keys=fetch_operator_keys):
    """What tsugiMain does, short of printing and exiting: (the object it prints, the exit code). Raises Usage where
    it prints the usage line and exits 2, and lets errors through where the JavaScript throws."""
    a, pos = _args(list(argv))
    g = lambda k: a.get(k, UNDEF)  # noqa: E731
    file = pos[0] if pos else UNDEF
    if not truthy(file):
        raise Usage(USAGE)
    loaded = loads(read_file(file))
    records = loaded if isinstance(loaded, list) else prop(loaded, "records")
    opts = {}
    if truthy(g("operator-key")):
        opts["operatorKeys"] = [t for t in (s.strip(_JS_WS) for s in to_string(g("operator-key")).split(",")) if t]
    elif truthy(g("fetch-operator-key")):
        opts["operatorKeys"] = fetch_keys(g("fetch-operator-key"))
    elif (not isinstance(loaded, list) and isinstance(prop(loaded, "operator_public_key_ed25519_b64"), str)
          and truthy(g("trust-embedded-key"))):
        opts["operatorKeys"] = [loaded["operator_public_key_ed25519_b64"]]
    for k in opts.get("operatorKeys", []):   # 0.3.1: a wrong operator key is a usage error, not "untrusted"
        pk = b64_exact(k, 32)
        if pk is None or not ed25519_key_ok(pk):
            raise Usage("tsugi-verify: operator key " + stringify(k) + " is not canonical base64 of a usable Ed25519 key")
    if any(truthy(g(k)) for k in ("pool", "q", "k", "beacon", "require-commitment", "anchor-height", "require-v24", "beacon-time")):
        wq = {}
        if truthy(g("pool")):
            wq["pool"] = loads(read_file(g("pool")))
        if truthy(g("q")):
            wq["q"] = to_number_js(g("q"))
        if truthy(g("k")):
            wq["k"] = to_number_js(g("k"))
        if truthy(g("beacon")):
            wq["beaconHash"] = to_string(g("beacon"))
        if truthy(g("require-commitment")):
            wq["requireCommitment"] = True
        if truthy(g("anchor-height")):
            ca = {"height": to_string(g("anchor-height"))}
            if truthy(g("anchor-hash")):
                ca["hash"] = to_string(g("anchor-hash"))
            wq["commitmentAnchor"] = ca
        if truthy(g("require-v24")):
            wq["requireV24"] = True
        if truthy(g("beacon-time")):
            wq["beaconTime"] = to_string(g("beacon-time"))
        opts["witnessQuorum"] = wq
    report = verify_chain(records, opts)
    out = {"verifier": "tsugi_verify " + VERIFIER_VERSION,
           "mode": {"operator_keys": len(opts["operatorKeys"]) if "operatorKeys" in opts else 0,
                    "witness_quorum": opts.get("witnessQuorum") or None}}
    out.update(report)
    out["note"] = UNDEF if "operatorKeys" in opts else NOTE
    out["does_not_establish"] = list(DOES_NOT_ESTABLISH)
    return out, (0 if report["ok"] else 1)


def output_text(out):
    """console.log(JSON.stringify(out, null, 2))"""
    return stringify(out, indent=2) + "\n"


def main(argv=None):
    if argv is None:
        import os
        argv = [os.fsencode(x).decode("utf-8", "replace") for x in sys.argv[1:]]   # Node reads argv as UTF-8
    try:
        out, code = run(list(argv))
        text = output_text(out)
    except Usage as e:
        print(str(e), file=sys.stderr)
        return 2
    except RecursionError:
        print("tsugi-verify: the input is nested deeper than this Python allows; no report", file=sys.stderr)
        return 2
    except NotReproduced as e:
        print("tsugi-verify: this input reaches a case the port does not reproduce (%s); no report" % e, file=sys.stderr)
        return 2
    except Exception as e:
        print("tsugi-verify: no report for this input (%s: %s)" % (type(e).__name__, e), file=sys.stderr)
        return 2
    out_bytes = text.encode("utf-8")   # console.log writes UTF-8 whatever the locale
    if hasattr(sys.stdout, "buffer"):
        sys.stdout.flush()
        sys.stdout.buffer.write(out_bytes)
        sys.stdout.buffer.flush()
    else:
        sys.stdout.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
