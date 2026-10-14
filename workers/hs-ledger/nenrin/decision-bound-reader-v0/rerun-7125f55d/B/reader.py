#!/usr/bin/env python3
"""Blind second reader for decision-bound-output-v1.

Built from the contract text (docstring and comments of decision_bound.py)
and the canonical-JSON form described by jcs.py (RFC 8785). Neither file is
imported or copied; canonicalization and hashing are written here from
scratch, standard library only.

Usage: python3 -I -B reader.py <vectors.json> <out.json>

Verdicts (C# = contract sentence, quoted in GAPS.md):
  ACCEPTED              word taken from C4 ("A citation is only accepted if ...")
  UNAUTHORIZED_BINDING  name taken verbatim from C4
  UNVERIFIABLE_LEGACY   name chosen by this reader for the case C5 calls
                        "the unverifiable-but-not-tampered case"
  DECISION_ID_MISMATCH  name chosen by this reader (C1 + C3)
  OUTPUT_HASH_MISMATCH  name chosen by this reader (C2 + C3, C5 not met)

Exit code: 0 when every case was evaluated (whatever the verdicts),
2 when the input could not be read or a case is malformed.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys

# C2: `version` is the module constant "decision-bound-output-v1".
VERSION = "decision-bound-output-v1"
PREFIX = "sha256:"
DECLARED_DECISION_FIELDS = (
    "action_ref", "canonicalization_profile_id", "outcome", "policy_id", "ts_ms",
)


# ---------------------------------------------------------------- canonical JSON
# RFC 8785 (JCS): object members sorted by the UTF-16 code units of the key,
# no insignificant whitespace, strings in minimal JSON escaping with non-ASCII
# kept as UTF-8, numbers in ECMAScript Number-to-String form, UTF-8 output.

def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


_SHORT_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
              "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _str(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _SHORT_ESC:
            out.append(_SHORT_ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _num(x: float) -> str:
    # ECMAScript Number::toString applied to the shortest round-trip digits
    # (Python's repr gives the same shortest digit string as JS).
    if math.isnan(x) or math.isinf(x):
        raise ValueError("non-finite number is not representable in JCS")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    m, _, e = repr(abs(x)).partition("e")
    exp = int(e) if e else 0
    ip, _, fp = m.partition(".")
    digits = (ip + fp).lstrip("0")
    point = len(ip) - (len(ip + fp) - len(digits)) + exp  # decimal point position
    digits = digits.rstrip("0")
    k, n = len(digits), point
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    ex = n - 1
    es = ("+" if ex >= 0 else "-") + str(abs(ex))
    mant = digits[0] + ("." + digits[1:] if k > 1 else "")
    return sign + mant + "e" + es


def canon(o) -> str:
    if o is True:
        return "true"
    if o is False:
        return "false"
    if o is None:
        return "null"
    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        return _num(o)
    if isinstance(o, str):
        return _str(o)
    if isinstance(o, list):
        return "[" + ",".join(canon(v) for v in o) + "]"
    if isinstance(o, dict):
        keys = sorted(o.keys(), key=_utf16_key)
        return "{" + ",".join(_str(k) + ":" + canon(o[k]) for k in keys) + "}"
    raise TypeError("not JSON-representable: %r" % type(o).__name__)


def ref(o) -> str:
    # C1: ref() = "sha256:" + hex(SHA-256(JCS(preimage)))
    return PREFIX + hashlib.sha256(canon(o).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- the checks

def evaluate(case: dict) -> dict:
    for f in ("case_id", "claimed_decision_id", "content_sha256",
              "decision_preimage", "recorded_output_hash"):
        if f not in case:
            raise KeyError("case missing field %r" % f)
    pre = case["decision_preimage"]
    claimed = case["claimed_decision_id"]
    content = case["content_sha256"]          # C2: bare hex, used as given
    recorded = case["recorded_output_hash"]

    recomputed_id = ref(pre)                                          # C1
    bound_claimed = ref({"content_sha256": content,                   # C2
                         "decision_id": claimed, "version": VERSION})
    bound_recomputed = ref({"content_sha256": content,
                            "decision_id": recomputed_id, "version": VERSION})
    legacy = PREFIX + content                                         # C5

    id_ok = recomputed_id == claimed
    bound_ok = recorded == bound_claimed
    legacy_hit = recorded == legacy
    outcome = pre.get("outcome") if isinstance(pre, dict) else None

    if not id_ok:
        verdict, rule = "DECISION_ID_MISMATCH", "C1+C3"
    elif bound_ok:
        if outcome == "permit":
            verdict, rule = "ACCEPTED", "C2+C3+C4"
        else:
            verdict, rule = "UNAUTHORIZED_BINDING", "C4"
    elif legacy_hit:
        verdict, rule = "UNVERIFIABLE_LEGACY", "C5"
    else:
        verdict, rule = "OUTPUT_HASH_MISMATCH", "C2+C3"

    info = {
        "decision_preimage_keys_are_the_declared_five":
            isinstance(pre, dict) and tuple(sorted(pre)) == DECLARED_DECISION_FIELDS,
        "content_sha256_is_bare_hex": isinstance(content, str)
            and not content.startswith(PREFIX),
        "claimed_decision_id_has_sha256_prefix": isinstance(claimed, str)
            and claimed.startswith(PREFIX),
    }
    return {
        "case_id": case["case_id"],
        "verdict": verdict,
        "rule": rule,
        "recomputed_decision_id": recomputed_id,
        "claimed_decision_id": claimed,
        "decision_id_matches": id_ok,
        "bound_output_hash_from_claimed_id": bound_claimed,
        "bound_output_hash_from_recomputed_id": bound_recomputed,
        "legacy_output_hash": legacy,
        "recorded_output_hash": recorded,
        "recorded_equals_bound_from_claimed_id": bound_ok,
        "recorded_equals_bound_from_recomputed_id": recorded == bound_recomputed,
        "recorded_equals_legacy": legacy_hit,
        "outcome": outcome,
        "informational_not_used_in_verdict": info,
    }


def main(argv) -> int:
    if len(argv) != 3:
        print("usage: reader.py <vectors.json> <out.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        cases = doc["cases"]
        results = [evaluate(c) for c in cases]
    except Exception as exc:  # malformed input is an input error, not a verdict
        print("INPUT_ERROR %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2
    counts = {}
    for r in results:
        print("%s %s" % (r["case_id"], r["verdict"]))
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    summary = " ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))
    print("SUMMARY cases=%d %s" % (len(results), summary))
    out = {"input": argv[1], "profile_label_not_hashed": doc.get("profile"),
           "version_constant": VERSION, "results": results,
           "summary": {"cases": len(results), "by_verdict": counts}}
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
