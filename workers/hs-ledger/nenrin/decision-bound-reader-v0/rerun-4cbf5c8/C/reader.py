"""Blind second reader for decision-bound-output-v1.

Written only from the contract text (docstrings/comments of decision_bound.py),
the description of the canonical form (jcs.py docstring: RFC 8785), and the
vector files with expected answers removed. No code from those files is
imported, executed or copied. Standard library only.

usage: python3 -I -B reader.py <vectors.json> <out.json>

Check order (the contract prescribes one, "CHECK ORDER" paragraph):
  1. recompute decision_id = "sha256:" + hex(SHA-256(JCS(decision_preimage)))
     and compare to claimed_decision_id. Mismatch -> FORGED_DECISION_CITATION,
     stop; the bound hash is never constructed.
  2. recompute bound_output_hash = "sha256:" + hex(SHA-256(JCS(
       {content_sha256, decision_id, version:"decision-bound-output-v1"})))
     and compare to recorded_output_hash.
     2a. match and decision_preimage.outcome == "permit" -> COMMITMENT_AFTER_DECISION
     2b. match and outcome != "permit"                  -> UNAUTHORIZED_BINDING
  3. no bound match: compare recorded_output_hash to the legacy form
     "sha256:" + content_sha256. Match -> ORDERING_UNVERIFIABLE.
  4. matches neither -> BINDING_MISMATCH.
The relative order of steps 2 and 3 is not prescribed by the text; it only
matters if the two forms collide (see GAPS.md).

Exit codes: 0 every case evaluated; 2 input malformed (file unreadable, not
JSON, wrong shape, or any case missing a required field). Exit 2 for a usage
error as well (own choice).
"""
from __future__ import annotations

import hashlib
import json
import math
import sys

# Result names taken verbatim from the contract text.
FORGED = "FORGED_DECISION_CITATION"
UNAUTHORIZED = "UNAUTHORIZED_BINDING"
OK = "COMMITMENT_AFTER_DECISION"
MISMATCH = "BINDING_MISMATCH"
LEGACY = "ORDERING_UNVERIFIABLE"
# OWN CHOICE (the contract gives no name for this outcome): a case that could
# not be evaluated because a required field is missing or has the wrong type.
MALFORMED = "MALFORMED_INPUT"

VERDICT_ORDER = [FORGED, UNAUTHORIZED, OK, MISMATCH, LEGACY, MALFORMED]

# The preimage-shape constant named in the contract ("version" is this
# module's VERSION, not the vectors file's "profile" label).
VERSION = "decision-bound-output-v1"

# The five decision_preimage fields named in the contract text. Used only
# for a reported (non-gating) shape observation; see GAPS.md.
FIVE_FIELDS = ("action_ref", "canonicalization_profile_id", "outcome",
               "policy_id", "ts_ms")

REQUIRED_CASE_FIELDS = {
    "case_id": str,
    "claimed_decision_id": str,
    "content_sha256": str,
    "decision_preimage": dict,
    "recorded_output_hash": str,
}


class Malformed(Exception):
    pass


# ---------------------------------------------------------------- RFC 8785 --

def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise Malformed("lone surrogate in string; not representable in I-JSON")
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _es_number(x: float) -> str:
    """ECMAScript Number.prototype.toString for a finite double (RFC 8785 3.2.2.3)."""
    if math.isnan(x) or math.isinf(x):
        raise Malformed("non-finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))  # shortest round-trip digits, same digit set as ES
    if "e" in r:
        mant, e = r.split("e")
        exp10 = int(e)
    else:
        mant, exp10 = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead = len(ip + fp) - len(digits)
    n = len(ip) - lead + exp10          # decimal point position
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + es
    return sign + digits[0] + "." + digits[1:] + "e" + es


def _jcs_number(v) -> str:
    if isinstance(v, int):
        # RFC 8785 treats every number as an IEEE-754 double. Integers that a
        # double represents exactly print as plain decimal; larger ones go
        # through the double path (see GAPS.md: big-integer note).
        if abs(v) <= 2 ** 53:
            return str(v)
        return _es_number(float(v))
    return _es_number(v)


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _jcs_number(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise Malformed("value of type %s is not JSON" % type(v).__name__)


def sha256_ref(obj) -> str:
    return "sha256:" + hashlib.sha256(jcs(obj).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ input --

def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Malformed("duplicate key %r" % k)
        d[k] = v
    return d


def _bad_constant(name):
    raise Malformed("non-finite number literal %s" % name)


def load(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_dupes,
                          parse_constant=_bad_constant)
    except Malformed:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise Malformed("cannot read JSON: %s" % e)


def validate_case(c):
    if not isinstance(c, dict):
        raise Malformed("case is not an object")
    for k, t in REQUIRED_CASE_FIELDS.items():
        if k not in c:
            raise Malformed("missing field %s" % k)
        if not isinstance(c[k], t):
            raise Malformed("field %s is not %s" % (k, t.__name__))
    if not c["case_id"]:
        raise Malformed("empty case_id")


# ------------------------------------------------------------------ check --

def evaluate(c):
    d = {
        "case_id": c["case_id"],
        "checks_run": [],
        "inputs": {
            "claimed_decision_id": c["claimed_decision_id"],
            "content_sha256": c["content_sha256"],
            "recorded_output_hash": c["recorded_output_hash"],
        },
        "fields_present_but_not_read": sorted(
            k for k in c if k not in REQUIRED_CASE_FIELDS),
    }
    pre = c["decision_preimage"]
    names = sorted(pre.keys())
    d["preimage_field_names"] = names
    # Reported only; does not affect the verdict (see GAPS.md).
    d["preimage_has_exactly_the_five_named_fields"] = names == sorted(FIVE_FIELDS)

    # Step 1: citation.
    recomputed_id = sha256_ref(pre)
    d["recomputed_decision_id"] = recomputed_id
    d["decision_preimage_jcs"] = jcs(pre)
    cite_ok = recomputed_id == c["claimed_decision_id"]
    d["checks_run"].append({"step": 1, "check": "claimed_decision_id == recomputed_decision_id",
                            "passed": cite_ok})
    d["citation_recomputes"] = cite_ok
    if not cite_ok:
        d["bound_output_hash"] = None   # never constructed, per contract
        d["legacy_output_hash"] = None
        d["verdict"] = FORGED
        return d

    # Step 2: bound commitment. claimed == recomputed at this point.
    bound_pre = {"content_sha256": c["content_sha256"],
                 "decision_id": c["claimed_decision_id"],
                 "version": VERSION}
    bound = sha256_ref(bound_pre)
    d["bound_output_preimage_jcs"] = jcs(bound_pre)
    d["bound_output_hash"] = bound
    bound_ok = bound == c["recorded_output_hash"]
    d["checks_run"].append({"step": 2, "check": "recorded_output_hash == bound_output_hash",
                            "passed": bound_ok})
    d["bound_matches"] = bound_ok
    if bound_ok:
        outcome = pre.get("outcome", None)
        permit = outcome == "permit"
        d["outcome"] = outcome
        d["checks_run"].append({"step": "2a", "check": 'decision_preimage.outcome == "permit"',
                                "passed": permit})
        d["outcome_is_permit"] = permit
        d["legacy_output_hash"] = "sha256:" + c["content_sha256"]
        d["verdict"] = OK if permit else UNAUTHORIZED
        return d

    # Step 3: legacy form.
    legacy = "sha256:" + c["content_sha256"]
    d["legacy_output_hash"] = legacy
    legacy_ok = legacy == c["recorded_output_hash"]
    d["checks_run"].append({"step": 3, "check": "recorded_output_hash == legacy_output_hash",
                            "passed": legacy_ok})
    d["legacy_matches"] = legacy_ok
    d["outcome"] = pre.get("outcome", None)  # reported, not used for these verdicts
    d["verdict"] = LEGACY if legacy_ok else MISMATCH
    return d


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: python3 -I -B reader.py <vectors.json> <out.json>\n")
        return 2
    src, dst = argv[1], argv[2]
    report = {"reader": "blind second reader, decision-bound-output-v1",
              "input": src, "cases": [], "errors": []}
    malformed = False
    try:
        doc = load(src)
        if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list):
            raise Malformed("top level must be an object with a 'cases' list")
        report["file_profile_label_not_hashed"] = doc.get("profile")
        cases = doc["cases"]
    except Malformed as e:
        sys.stderr.write("MALFORMED: %s\n" % e)
        report["errors"].append(str(e))
        cases = []
        malformed = True

    counts = {}
    seen = set()
    for i, c in enumerate(cases):
        label = c.get("case_id") if isinstance(c, dict) and isinstance(c.get("case_id"), str) and c.get("case_id") else "#%d" % i
        try:
            validate_case(c)
            if c["case_id"] in seen:
                raise Malformed("duplicate case_id")  # own choice
            seen.add(c["case_id"])
            d = evaluate(c)
        except Malformed as e:
            malformed = True
            d = {"case_id": label, "verdict": MALFORMED, "error": str(e)}
        report["cases"].append(d)
        counts[d["verdict"]] = counts.get(d["verdict"], 0) + 1
        print("%s %s" % (d["case_id"], d["verdict"]))

    parts = ["total=%d" % len(report["cases"])]
    for v in VERDICT_ORDER:
        if counts.get(v):
            parts.append("%s=%d" % (v, counts[v]))
    print("SUMMARY " + " ".join(parts))
    report["summary"] = {"total": len(report["cases"]), "counts": counts}

    try:
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, sort_keys=False)
            f.write("\n")
    except OSError as e:
        sys.stderr.write("cannot write %s: %s\n" % (dst, e))
        return 2
    return 2 if malformed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
