#!/usr/bin/env python3
"""reader17: blind reader for the OBS-06 commitment_anchor draft.

Written from README.md alone (plus the shape of vectors.blind.json).
Standard library only, no network. Usage:

    python3 -I reader17.py vectors.blind.json

Prints one line per vector, in file order:
    <id> result=<RESULT> precedence_established=<true|false> rule=<rule>
"""
import hashlib
import json
import sys

DEFAULT_RULE = "header_time_plus_tolerance"
KNOWN_RULES = ("header_time_plus_tolerance", "later_median", "height")

# NIP-01 escaping as the README states it: only these seven are escaped,
# every other character is written as it is (no \uXXXX, no ASCII forcing).
_NIP01_ESC = {
    "\n": "\\n",
    '"': '\\"',
    "\\": "\\\\",
    "\r": "\\r",
    "\t": "\\t",
    "\b": "\\b",
    "\f": "\\f",
}


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v):
    return (isinstance(v, (int, float))) and not isinstance(v, bool)


def nip01_str(s):
    return '"' + "".join(_NIP01_ESC.get(ch, ch) for ch in s) + '"'


def nip01_value(v):
    if isinstance(v, str):
        return nip01_str(v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if _is_int(v):
        return str(v)
    if isinstance(v, list):
        return "[" + ",".join(nip01_value(x) for x in v) + "]"
    # NIP-01 event fields are strings, integers and arrays of strings.
    # Anything else (float, object, null) has no serialization fixed by the
    # README, so refuse rather than guess.
    raise ValueError("value outside NIP-01 event field types: %r" % (type(v).__name__,))


def nip01_event_id(ev):
    for k in ("pubkey", "created_at", "kind", "tags", "content"):
        if k not in ev:
            raise ValueError("missing event field %s" % k)
    if not isinstance(ev["pubkey"], str) or not isinstance(ev["content"], str):
        raise ValueError("pubkey/content must be strings")
    if not _is_int(ev["created_at"]) or not _is_int(ev["kind"]):
        raise ValueError("created_at/kind must be integers")
    if not isinstance(ev["tags"], list) or not all(
        isinstance(t, list) and all(isinstance(x, str) for x in t) for t in ev["tags"]
    ):
        raise ValueError("tags must be an array of arrays of strings")
    ser = "[" + ",".join(
        [
            "0",
            nip01_str(ev["pubkey"]),
            str(ev["created_at"]),
            str(ev["kind"]),
            nip01_value(ev["tags"]),
            nip01_str(ev["content"]),  # hashed exactly as it stands
        ]
    ) + "]"
    return hashlib.sha256(ser.encode("utf-8")).hexdigest()


def event_of(record):
    """Locate the NIP-01 event inside the record.

    The README does not name the field; the vectors carry it under
    `subject`. Fall back to the record itself if it looks like an event.
    """
    sub = record.get("subject")
    if isinstance(sub, dict):
        return sub
    return record


def digest_covers(record, ca):
    if not isinstance(ca, dict):
        return False
    stated = ca.get("digest")
    rule = ca.get("digest_rule")
    if not isinstance(stated, str):
        return False
    if rule != "nip01-event-id":
        # Only the one deterministic rule the README spells out byte for byte
        # is implemented; anything else cannot be recomputed here.
        return False
    try:
        got = nip01_event_id(event_of(record))
    except ValueError:
        return False
    return got == stated.lower()


def rule_of(ca):
    r = ca.get("anchor_time_rule") if isinstance(ca, dict) else None
    if r is None:
        return DEFAULT_RULE
    return r


def established(record, ca, rule):
    if not isinstance(ca, dict):
        return False
    if rule == "header_time_plus_tolerance":
        at = ca.get("anchor_time")
        tol = ca.get("anchor_time_tolerance_s")
        ot = record.get("outcome_time")
        if not (_is_num(at) and _is_num(tol) and _is_num(ot)):
            return False
        return at + tol < ot
    if rule == "later_median":
        ceil = ca.get("anchor_ceiling_time")
        ot = record.get("outcome_time")
        if not (_is_num(ceil) and _is_num(ot)):
            return False
        return ceil < ot
    if rule == "height":
        ah = ca.get("anchor_height")
        oh = record.get("outcome_height")
        if not (_is_int(ah) and _is_int(oh)):
            return False
        return ah < oh
    return False  # unknown rule establishes nothing


def evaluate(record):
    ca = record.get("commitment_anchor")
    rule = rule_of(ca)
    if not digest_covers(record, ca):
        return "ANCHOR_DOES_NOT_COVER_RECORD", False, rule
    est = established(record, ca, rule)
    asserts = record.get("asserts_precedence") is True
    dna = record.get("does_not_assert")
    declared = isinstance(dna, list) and "precedence_before_outcome" in dna
    if asserts and not est:
        return "NONCONFORMING_UNSUPPORTED_PRECEDENCE_CLAIM", est, rule
    if not est and not asserts and not declared:
        return "NONCONFORMING_UNDECLARED_LIMITATION", est, rule
    return "CONFORMING", est, rule


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: reader17.py vectors.blind.json\n")
        return 2
    with open(argv[1], "r", encoding="utf-8") as f:
        doc = json.load(f)
    for v in doc.get("vectors", []):
        rec = v.get("record", {})
        res, est, rule = evaluate(rec)
        print("%s result=%s precedence_established=%s rule=%s"
              % (v.get("id"), res, "true" if est else "false", rule))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
