#!/usr/bin/env python3
"""Blind second reader for commitment_anchor (OBS-06), written from README.md alone.

Stdlib only. Usage: python3 -I -B reader.py vectors.blind.json

Per vector it:
 (a) recomputes the anchored digest from the record under digest_rule,
 (b) derives the ceiling under anchor_time_rule (absent means
     header_time_plus_tolerance),
 (c) decides whether precedence is established,
 (d) checks the record's own claims (asserts_precedence, does_not_assert).

Result names are this reader's own; the README names no result values.
  conformant             the record's claims agree with the rule
  unsupported_claim      asserts precedence that the rule does not establish
                         (README: "MUST NOT assert precedence")
  undeclared_limitation  precedence not established, not asserted, but
                         precedence_before_outcome missing from does_not_assert
                         (README: "MUST list precedence_before_outcome")
When both apply, both are printed joined by "+", unsupported_claim first.
Extra tags in "notes": no_anchor_digest_mismatch (README: "has no anchor for
this rule"), inputs_missing (README: "establishes nothing"), unknown_rule,
unknown_digest_rule.
"""
import hashlib
import json
import sys

LIMITATION = "precedence_before_outcome"


def nip01_serialize(ev):
    # [0, pubkey, created_at, kind, tags, content], no whitespace, UTF-8,
    # non-ASCII kept as-is. Python's json escapes ", \\ and control chars;
    # NIP-01 lists \n \" \\ \r \t \b \f; other control chars do not occur here
    # (checked below).
    arr = [0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]]
    s = json.dumps(arr, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def has_odd_control(obj):
    if isinstance(obj, str):
        return any(ord(c) < 0x20 and c not in "\n\r\t\b\f" for c in obj)
    if isinstance(obj, list):
        return any(has_odd_control(x) for x in obj)
    return False


def recompute_digest(record, anchor):
    rule = anchor.get("digest_rule")
    if rule == "nip01-event-id":
        ev = record.get("subject")
        if not isinstance(ev, dict):
            return None, "subject_missing"
        try:
            if has_odd_control(ev["tags"]) or has_odd_control(ev["content"]):
                return None, "nip01_escape_ambiguous"
            return hashlib.sha256(nip01_serialize(ev)).hexdigest(), None
        except KeyError as e:
            return None, "subject_field_missing:" + str(e)
    return None, "unknown_digest_rule"


def is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def evaluate(vec):
    rec = vec["record"]
    anc = rec.get("commitment_anchor")
    notes = []
    ceiling_desc = "none"
    established = False

    if not isinstance(anc, dict):
        notes.append("no_commitment_anchor")
    else:
        dig, err = recompute_digest(rec, anc)
        digest_ok = dig is not None and dig == str(anc.get("digest", "")).lower()
        if err:
            notes.append(err)
        elif not digest_ok:
            notes.append("no_anchor_digest_mismatch(recomputed=%s)" % dig)

        rule = anc.get("anchor_time_rule", "header_time_plus_tolerance")
        if "anchor_time_rule" not in anc:
            notes.append("rule_defaulted")

        if rule == "header_time_plus_tolerance":
            t, tol, out = anc.get("anchor_time"), anc.get("anchor_time_tolerance_s"), rec.get("outcome_time")
            if is_num(t) and is_num(tol) and is_num(out):
                ceil = t + tol
                ceiling_desc = "time:%s(anchor_time %s + tolerance %s)" % (ceil, t, tol)
                cmp_ok = ceil < out
            else:
                notes.append("inputs_missing")
                cmp_ok = False
        elif rule == "later_median":
            ceil, out = anc.get("anchor_ceiling_time"), rec.get("outcome_time")
            if is_num(ceil) and is_num(out):
                ceiling_desc = "time:%s(anchor_ceiling_time)" % ceil
                cmp_ok = ceil < out
                if not anc.get("anchor_ceiling_source"):
                    notes.append("anchor_ceiling_source_missing")
            else:
                notes.append("inputs_missing")
                cmp_ok = False
        elif rule == "height":
            ah = anc.get("anchor_height")
            oh = rec.get("outcome_height", anc.get("outcome_height"))
            if isinstance(ah, int) and isinstance(oh, int) and not isinstance(ah, bool) and not isinstance(oh, bool):
                ceiling_desc = "height:anchor %d vs outcome %d" % (ah, oh)
                cmp_ok = ah < oh
            else:
                notes.append("inputs_missing")
                cmp_ok = False
        else:
            notes.append("unknown_rule:%s" % rule)
            cmp_ok = False

        if cmp_ok and not digest_ok:
            notes.append("ceiling_would_establish_but_no_anchor")
        established = bool(cmp_ok and digest_ok)

    asserts = rec.get("asserts_precedence") is True
    dna = rec.get("does_not_assert") or []
    listed = isinstance(dna, list) and LIMITATION in dna

    violations = []
    if not established:
        if asserts:
            violations.append("unsupported_claim")
        if not listed:
            violations.append("undeclared_limitation")
    else:
        if listed:
            notes.append("limitation_listed_though_established")
    result = "+".join(violations) if violations else "conformant"
    return result, established, ceiling_desc, notes


def main():
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for vec in data["vectors"]:
        result, est, ceil, notes = evaluate(vec)
        line = "%s result=%s precedence_established=%s ceiling=%s" % (
            vec["id"], result, "true" if est else "false", ceil)
        if notes:
            line += " notes=" + ",".join(notes)
        print(line)


if __name__ == "__main__":
    main()
