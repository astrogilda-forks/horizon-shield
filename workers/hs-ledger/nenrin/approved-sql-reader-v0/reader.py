#!/usr/bin/env python3
"""Clean-room reader for the oel-approved-sql-illustration/v1 profile.

Written only from INPUT-CONTRACT.md and the fixture shapes. Python 3 stdlib only.

Usage: python3 reader.py <fixture.json>
Exit:  0 recorded_commit_matches, 1 any other assessment, 2 invalid input.
"""
import base64
import binascii
import json
import sys

PROFILE = "oel-approved-sql-illustration/v1"
ORIGIN = "author-created-fixture"

# Result names. Only RESULT_MATCH and RESULT_NO_MATCH appear verbatim in the
# contract; the others are spelled by this reader (see GAPS.md).
RESULT_MATCH = "recorded_commit_matches"                      # contract
RESULT_NO_MATCH = "no_match_in_declared_complete_scope"       # contract
RESULT_INSUFFICIENT = "insufficient_evidence"                 # contract prose "insufficient evidence"
RESULT_AMBIGUOUS = "ambiguous"                                # contract prose "is ambiguous"
RESULT_NOT_GRANTED = "approval_not_granted"                   # invented
RESULT_CALL_DIFFERS = "call_differs_from_approval"            # invented
RESULT_APP_DISAGREES = "application_disagrees_with_audit"     # invented
RESULT_NOT_COMMIT = "recorded_outcome_not_successful_commit"  # invented
RESULT_INVALID = "invalid_input"                              # invented

LATER_ABSENT = "not_supplied"          # invented
LATER_UNCHANGED = "unchanged"          # invented
LATER_CHANGED = "changed"              # invented

STATEMENTS = ("succeeded", "failed")
TRANSACTIONS = ("committed", "rolled_back", "unknown")


class InvalidInput(Exception):
    pass


# ---------------------------------------------------------------- parsing

def _no_dup_object(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise InvalidInput("duplicate key %r" % k)
        obj[k] = v
    return obj


def _bad_constant(name):
    raise InvalidInput("non-JSON numeric constant %s" % name)


def load(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise InvalidInput("cannot read input: %s" % exc)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidInput("input is not UTF-8")
    if text.startswith("\ufeff"):
        raise InvalidInput("byte order mark not allowed")
    try:
        return json.loads(text, object_pairs_hook=_no_dup_object,
                          parse_constant=_bad_constant)
    except InvalidInput:
        raise
    except ValueError as exc:
        raise InvalidInput("not valid JSON: %s" % exc)


# ---------------------------------------------------------------- validation

def _obj(value, keys, where):
    if not isinstance(value, dict):
        raise InvalidInput("%s must be an object" % where)
    got = set(value.keys())
    want = set(keys)
    if got != want:
        missing = sorted(want - got)
        extra = sorted(got - want)
        raise InvalidInput("%s keys mismatch (missing=%s extra=%s)" % (where, missing, extra))
    return value


def _str(value, where, nonempty=False):
    if not isinstance(value, str):
        raise InvalidInput("%s must be a string" % where)
    if nonempty and value == "":
        raise InvalidInput("%s must be nonempty" % where)
    return value


def _bool(value, where):
    if not isinstance(value, bool):
        raise InvalidInput("%s must be a JSON boolean" % where)
    return value


def _b64(value, where):
    """Canonical standard base64 (RFC 4648 section 4, padded, no whitespace)."""
    _str(value, where)
    try:
        ascii_bytes = value.encode("ascii")
    except UnicodeEncodeError:
        raise InvalidInput("%s is not canonical base64" % where)
    try:
        decoded = base64.b64decode(ascii_bytes, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidInput("%s is not canonical base64" % where)
    if base64.b64encode(decoded) != ascii_bytes:
        raise InvalidInput("%s is not canonical base64" % where)
    return decoded


def _target(value, where):
    _obj(value, ("instance", "database", "schema"), where)
    return (_str(value["instance"], where + ".instance"),
            _str(value["database"], where + ".database"),
            _str(value["schema"], where + ".schema"))


def _call(value, where):
    _obj(value, ("request_id", "sql_utf8_b64", "parameters", "target",
                 "executing_principal"), where)
    request_id = _str(value["request_id"], where + ".request_id", nonempty=True)
    sql = _b64(value["sql_utf8_b64"], where + ".sql_utf8_b64")
    try:
        sql.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidInput("%s.sql_utf8_b64 does not decode to UTF-8" % where)
    params = value["parameters"]
    if not isinstance(params, list):
        raise InvalidInput("%s.parameters must be an array" % where)
    typed = []
    for i, p in enumerate(params):
        pw = "%s.parameters[%d]" % (where, i)
        _obj(p, ("position", "database_type", "value_b64"), pw)
        pos = p["position"]
        if isinstance(pos, bool) or not isinstance(pos, int):
            raise InvalidInput("%s.position must be an integer" % pw)
        if pos != i + 1:
            raise InvalidInput("%s.position must be %d (consecutive from 1)" % (pw, i + 1))
        dtype = _str(p["database_type"], pw + ".database_type", nonempty=True)
        if p["value_b64"] is None:
            val = None  # SQL NULL, distinct from empty bytes
        else:
            val = _b64(p["value_b64"], pw + ".value_b64")
        typed.append((pos, dtype, val))
    target = _target(value["target"], where + ".target")
    principal = _str(value["executing_principal"], where + ".executing_principal",
                     nonempty=True)
    return {
        "request_id": request_id,
        "sql": sql,
        "parameters": tuple(typed),
        "target": target,
        "executing_principal": principal,
    }


def _outcome(value, where):
    _obj(value, ("statement", "transaction"), where)
    st = value["statement"]
    tx = value["transaction"]
    if st not in STATEMENTS or not isinstance(st, str):
        raise InvalidInput("%s.statement must be succeeded|failed" % where)
    if tx not in TRANSACTIONS or not isinstance(tx, str):
        raise InvalidInput("%s.transaction must be committed|rolled_back|unknown" % where)
    return (st, tx)


def validate(doc):
    _obj(doc, ("profile", "origin", "approval", "application", "audit", "later_state"),
         "input")
    if doc["profile"] != PROFILE:
        raise InvalidInput("profile must be %s" % PROFILE)
    if doc["origin"] != ORIGIN:
        raise InvalidInput("origin must be %s" % ORIGIN)

    appr = _obj(doc["approval"], ("granted", "call"), "approval")
    granted = _bool(appr["granted"], "approval.granted")
    approval_call = _call(appr["call"], "approval.call")

    application = None
    if doc["application"] is not None:
        app = _obj(doc["application"], ("call", "outcome"), "application")
        application = {
            "call": _call(app["call"], "application.call"),
            "outcome": _outcome(app["outcome"], "application.outcome"),
        }

    aud = _obj(doc["audit"], ("scope", "complete", "records"), "audit")
    scope = _obj(aud["scope"], ("request_id", "target", "window_label"), "audit.scope")
    scope_v = {
        "request_id": _str(scope["request_id"], "audit.scope.request_id", nonempty=True),
        "target": _target(scope["target"], "audit.scope.target"),
        "window_label": _str(scope["window_label"], "audit.scope.window_label",
                             nonempty=True),
    }
    complete = _bool(aud["complete"], "audit.complete")
    if not isinstance(aud["records"], list):
        raise InvalidInput("audit.records must be an array")
    records = []
    seen = set()
    for i, r in enumerate(aud["records"]):
        rw = "audit.records[%d]" % i
        _obj(r, ("event_id", "call", "outcome"), rw)
        eid = _str(r["event_id"], rw + ".event_id", nonempty=True)
        if eid in seen:
            raise InvalidInput("duplicate audit event_id %r" % eid)
        seen.add(eid)
        records.append({
            "event_id": eid,
            "call": _call(r["call"], rw + ".call"),
            "outcome": _outcome(r["outcome"], rw + ".outcome"),
        })

    later = None
    if doc["later_state"] is not None:
        ls = _obj(doc["later_state"], ("target", "resource", "at_commit_b64", "later_b64"),
                  "later_state")
        later = {
            "target": _target(ls["target"], "later_state.target"),
            "resource": _str(ls["resource"], "later_state.resource", nonempty=True),
            "at_commit": _b64(ls["at_commit_b64"], "later_state.at_commit_b64"),
            "later": _b64(ls["later_b64"], "later_state.later_b64"),
        }

    return {
        "granted": granted,
        "approval_call": approval_call,
        "application": application,
        "scope": scope_v,
        "complete": complete,
        "records": records,
        "later": later,
    }


# ---------------------------------------------------------------- assessment

def _call_diffs(a, b):
    fields = []
    if a["request_id"] != b["request_id"]:
        fields.append("request_id")
    if a["sql"] != b["sql"]:
        fields.append("sql_utf8_b64")
    if a["parameters"] != b["parameters"]:
        fields.append("parameters")
    for i, name in enumerate(("instance", "database", "schema")):
        if a["target"][i] != b["target"][i]:
            fields.append("target." + name)
    if a["executing_principal"] != b["executing_principal"]:
        fields.append("executing_principal")
    return fields


def _later_state(v):
    later = v["later"]
    if later is None:
        return LATER_ABSENT, None
    detail = {
        "resource": later["resource"],
        "target_matches_approval": later["target"] == v["approval_call"]["target"],
        "bytes_differ": later["at_commit"] != later["later"],
    }
    return (LATER_CHANGED if detail["bytes_differ"] else LATER_UNCHANGED), detail


def assess(v):
    out = {}
    approval = v["approval_call"]
    rid = approval["request_id"]

    later_state, later_detail = _later_state(v)
    out["later_state"] = later_state
    if later_detail is not None:
        out["later_state_detail"] = later_detail
    out["later_change_attribution"] = "not_assessed"

    if not v["granted"]:
        out["result"] = RESULT_NOT_GRANTED
        return out

    scope = v["scope"]
    scope_matches = scope["request_id"] == rid and scope["target"] == approval["target"]
    out["audit_scope"] = {
        "window_label": scope["window_label"],
        "declared_complete": v["complete"],
        "matches_approval": scope_matches,
    }

    matches = [r for r in v["records"] if r["call"]["request_id"] == rid]
    if len(matches) > 1:
        out["result"] = RESULT_AMBIGUOUS
        out["matching_event_ids"] = [r["event_id"] for r in matches]
        return out
    if not matches:
        if v["complete"] and scope_matches:
            out["result"] = RESULT_NO_MATCH
        else:
            out["result"] = RESULT_INSUFFICIENT
            out["reason"] = ("audit_scope_differs_from_approval" if not scope_matches
                             else "audit_collection_not_declared_complete")
        return out

    rec = matches[0]
    out["matched_event_id"] = rec["event_id"]
    diffs = _call_diffs(approval, rec["call"])
    if diffs:
        out["result"] = RESULT_CALL_DIFFERS
        out["differing_fields"] = diffs
        return out

    app = v["application"]
    if app is None:
        out["result"] = RESULT_INSUFFICIENT
        out["reason"] = "application_record_absent"
        return out
    app_diffs = _call_diffs(rec["call"], app["call"])
    if app["outcome"][0] != rec["outcome"][0]:
        app_diffs.append("outcome.statement")
    if app["outcome"][1] != rec["outcome"][1]:
        app_diffs.append("outcome.transaction")
    if app_diffs:
        out["result"] = RESULT_APP_DISAGREES
        out["differing_fields"] = app_diffs
        out["audit_outcome"] = {"statement": rec["outcome"][0],
                                "transaction": rec["outcome"][1]}
        out["application_outcome"] = {"statement": app["outcome"][0],
                                      "transaction": app["outcome"][1]}
        return out

    st, tx = rec["outcome"]
    out["recorded_outcome"] = {"statement": st, "transaction": tx}
    if st == "succeeded" and tx == "committed":
        out["result"] = RESULT_MATCH
    else:
        out["result"] = RESULT_NOT_COMMIT
    return out


def _ordered(out):
    first = ("result", "later_state", "later_change_attribution")
    res = {k: out[k] for k in first if k in out}
    for k, val in out.items():
        if k not in res:
            res[k] = val
    return res


def main(argv):
    if len(argv) != 2:
        print(json.dumps({"result": RESULT_INVALID, "later_state": None,
                          "error": "usage: reader.py <fixture.json>"}))
        return 2
    try:
        v = validate(load(argv[1]))
    except InvalidInput as exc:
        print(json.dumps({"result": RESULT_INVALID, "later_state": None,
                          "error": str(exc)}))
        return 2
    out = _ordered(assess(v))
    print(json.dumps(out, sort_keys=False))
    return 0 if out["result"] == RESULT_MATCH else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
