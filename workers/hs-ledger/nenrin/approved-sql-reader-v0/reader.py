#!/usr/bin/env python3
"""Reader for the oel-approved-sql-illustration/v1 profile (clean-room at 5037ecf8, revised to the contract 2026-10-24).

The clean-room version (5037ecf8) was written only from INPUT-CONTRACT.md and the fixture shapes. Python 3 stdlib only.

Revision 2026-10-24 (not clean-room): the result names, the check order and the later_state values now follow
INPUT-CONTRACT.md at probityai/agent-evidence@c4780c28 (site/examples/approved-sql/docs/INPUT-CONTRACT.md), which
lists all eleven results and their order. This revision was made by the operator's AI agent, which had seen the manifest
since the comparison; it read no other reader's code. The clean-room version is 5037ecf8. Line numbers below are of that file.

Usage: python3 reader.py <fixture.json>
Exit:  0 recorded_commit_matches, 1 any other assessment, 2 invalid input.
"""
import base64
import binascii
import json
import sys

PROFILE = "oel-approved-sql-illustration/v1"
ORIGIN = "author-created-fixture"

# Result names, exactly as INPUT-CONTRACT.md lines 40-54 list them (c4780c28).
RESULT_NO_MATCH = "no_match_in_declared_complete_scope"       # line 44
RESULT_INSUFFICIENT = "insufficient_audit_evidence"           # line 45
RESULT_AMBIGUOUS = "ambiguous_database_join"                  # line 46
RESULT_NOT_GRANTED = "approval_not_granted"                   # line 47
RESULT_CALL_DIFFERS = "execution_differs_from_approval"       # line 48
RESULT_APP_MISSING = "application_record_missing"             # line 49
RESULT_APP_DISAGREES = "application_audit_disagreement"       # line 50
RESULT_STATEMENT_FAILED = "statement_failed"                  # line 51
RESULT_ROLLED_BACK = "transaction_rolled_back"                # line 52
RESULT_COMMIT_UNKNOWN = "commit_not_established"              # line 53
RESULT_MATCH = "recorded_commit_matches"                      # line 54
RESULT_INVALID = "invalid_input"                              # not a result; exit 2 (line 38)

# later_state values, INPUT-CONTRACT.md line 57.
LATER_ABSENT = "not_supplied"
LATER_NOT_COMPARABLE = "target_not_comparable"
LATER_UNCHANGED = "supplied_state_unchanged"
LATER_CHANGED = "supplied_state_differs"

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
    if not detail["target_matches_approval"]:
        return LATER_NOT_COMPARABLE, detail          # line 57: the later read names another target
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

    # The join comes first (lines 26-29, 44-46); the approval is read only once one record matches (lines 47, 56).
    scope = v["scope"]
    scope_matches = scope["request_id"] == rid and scope["target"] == approval["target"]
    out["audit_scope"] = {
        "window_label": scope["window_label"],
        "declared_complete": v["complete"],
        "matches_approval": scope_matches,
    }

    matches = [r for r in v["records"] if r["call"]["request_id"] == rid]
    if len(matches) > 1:
        out["result"] = RESULT_AMBIGUOUS                  # line 46
        out["matching_event_ids"] = [r["event_id"] for r in matches]
        return out
    if not matches:
        if v["complete"] and scope_matches:
            out["result"] = RESULT_NO_MATCH               # line 44 (line 28)
        else:
            out["result"] = RESULT_INSUFFICIENT           # line 45
            out["reason"] = ("audit_scope_differs_from_approval" if not scope_matches
                             else "audit_collection_not_declared_complete")
        return out

    # One matching record: the rows from approval_not_granted down, first that applies (line 56).
    rec = matches[0]
    out["matched_event_id"] = rec["event_id"]
    if not v["granted"]:
        out["result"] = RESULT_NOT_GRANTED                # line 47 (lines 34-35)
        return out
    diffs = _call_diffs(approval, rec["call"])
    if diffs:
        out["result"] = RESULT_CALL_DIFFERS               # line 48 (line 30)
        out["differing_fields"] = diffs
        return out

    app = v["application"]
    if app is None:
        out["result"] = RESULT_APP_MISSING                # line 49 (lines 34-35)
        return out
    app_diffs = _call_diffs(rec["call"], app["call"])
    if app["outcome"][0] != rec["outcome"][0]:
        app_diffs.append("outcome.statement")
    if app["outcome"][1] != rec["outcome"][1]:
        app_diffs.append("outcome.transaction")
    if app_diffs:
        out["result"] = RESULT_APP_DISAGREES              # line 50 (line 31)
        out["differing_fields"] = app_diffs
        out["audit_outcome"] = {"statement": rec["outcome"][0],
                                "transaction": rec["outcome"][1]}
        out["application_outcome"] = {"statement": app["outcome"][0],
                                      "transaction": app["outcome"][1]}
        return out

    st, tx = rec["outcome"]
    out["recorded_outcome"] = {"statement": st, "transaction": tx}
    if st == "failed":
        out["result"] = RESULT_STATEMENT_FAILED           # line 51
    elif tx == "rolled_back":
        out["result"] = RESULT_ROLLED_BACK                # line 52
    elif tx == "unknown":
        out["result"] = RESULT_COMMIT_UNKNOWN             # line 53
    else:
        out["result"] = RESULT_MATCH                      # line 54 (line 33)
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
