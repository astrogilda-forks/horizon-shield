#!/usr/bin/env python3
"""Drives the underspecified reasons that the vector layout cannot carry, and shows the four that cannot fire.

Revision 0.4 (NOTES.md N17). The vectors in vectors/ hand the settler a contract, a list of event files and a view, so they
cannot give it events that are not a list, and 10,001 records would be 10,001 files. This script builds those inputs in memory
from the same synthetic parties as gen_vectors.py, calls the reference as a library, and prints one line per case:

    id | what the input is | what the text says | the core fields the reference returns

It also runs, for each of the four rows of 4.2 that cannot fire, the input that row describes, and shows that 4.1 refuses it
first with contract_not_verified.

    python3 exercise_inputs.py            # prints the lines (about a minute: two cases settle 10,000 records)
    python3 exercise_inputs.py --check    # the same, and compares them with EXERCISE.txt byte for byte

Nothing here changes a vector. The lines are the record of which input drove which outcome.
"""
import base64, contextlib, copy, hashlib, io, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
with contextlib.redirect_stdout(io.StringIO()):
    import gen_vectors as g                                   # builds the synthetic parties; writes nothing on import
from run_reference import core_fields                         # noqa: E402


def fields(s):
    c = core_fields(s)
    return "%s %s %s" % (c["verdict"], c["status"], ",".join(c["deviation_codes"] + c["underspecified_reasons"]) or "-")


def chain_with_one():
    ch = g.Chain()
    rec = ch.put(g.ex(g.BASE))
    ch.pad(g.DEPTH)
    return rec, ch.view()


def distinct(n, first):
    return [first] + [g.ex(g.BASE, extra={"nenrin_ref": hashlib.sha256(b"%d" % i).hexdigest()}) for i in range(n - 1)]


def grant(name, mutate):
    c = g.synth_contract(sign=False, label="settle-core-v0 synthetic exercise " + name)
    mutate(c["grant"])
    return g._resigned(c)


def main():
    rec, view = chain_with_one()
    s16 = g.s16.settle_v1_16
    rows = []
    for cid, what, events in (("E1", "events is an object", {"e00": rec}), ("E2", "events is null", None),
                              ("E3", "events is the string \"[]\"", "[]")):
        rows.append((cid, what, "input_not_settleable (section 2)", fields(s16(g.BASE, events, view))))
    rows.append(("E4", "10,001 distinct records", "input_too_large (6.0)", fields(s16(g.BASE, distinct(10001, rec), view))))
    rows.append(("E5", "10,000 distinct records", "not input_too_large: the limit is more than 10,000",
                 fields(s16(g.BASE, distinct(10000, rec), view))))
    rows.append(("E6", "10,001 copies of one record", "not input_too_large: identical bytes are one record (6.3), counted once (6.2)",
                 fields(s16(g.BASE, [rec] * 10001, view))))
    for cid, what, row, mutate in (
            ("D1", "grant.authorized_actions is the string \"read\"", "authorized_actions_missing",
             lambda gr: gr.__setitem__("authorized_actions", "read")),
            ("D2", "grant.authorized_actions is absent", "authorized_actions_missing", lambda gr: gr.pop("authorized_actions")),
            ("D3", "a witness key decodes to 31 bytes", "witness_key_invalid",
             lambda gr: gr.__setitem__("witnesses", [{"name": "w", "public_key_ed25519_b64": base64.b64encode(b"\x01" * 31).decode()}])),
            ("D4", "grant.revocation.effective_at is \"immediately\"", "revocation_policy_not_recomputable",
             lambda gr: gr.__setitem__("revocation", {"effective_at": "immediately"})),
            ("D5", "grant.expiry_height is -1", "bad_expiry_height", lambda gr: gr.__setitem__("expiry_height", -1)),
            ("D6", "grant.expiry_height is the string \"800010\"", "bad_expiry_height",
             lambda gr: gr.__setitem__("expiry_height", "800010"))):
        c = grant(cid, mutate)
        ch = g.Chain()
        r = ch.put(g.ex(c))
        ch.pad(g.DEPTH)
        rows.append((cid, what, "the 4.2 row says " + row + "; 4.1 refuses first", fields(s16(c, [r], ch.view()))))
    return "".join("%s | %s | %s | %s\n" % r for r in rows)


if __name__ == "__main__":
    out = main()
    sys.stdout.write(out)
    if "--check" in sys.argv:
        with open(os.path.join(HERE, "EXERCISE.txt"), encoding="utf-8", newline="") as f:
            want = f.read()
        if out != want:
            sys.stdout.write("DIFFER from EXERCISE.txt\n")
            sys.exit(1)
        sys.stdout.write("EXERCISE.txt agrees\n")
