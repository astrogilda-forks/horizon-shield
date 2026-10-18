#!/usr/bin/env python3
"""Independent check of Poke-nushi's sidecar-swap control (horizon-shield #51).

Reads the two swapped files in this folder, the live_smoke records beside it (../live_smoke/receipt.json and
call.json) and the invinoveritas checker key Federico posted on #51 (pinned below, not read from the files).
For each file it prints: whether the acceptance-record signature and the sidecar signature verify, the JCS
SHA-256 of the inner acceptance receipt, the receipt digest the sidecar names, and whether the sidecar's
execution and occurrence digests match the live_smoke bytes. Exits 0 only when every expectation in
control-manifest.json holds: both signatures valid, the receipt join false, the other two joins true.

    python3 check_swap.py            # prints the lines kept in CHECK.txt
    python3 check_swap.py --check    # compares them with CHECK.txt
"""
import base64, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER_PUB_B64 = "pY0UINp9HP6CVUTRBcOeKo5MPbhqRlEsuiAAw3JR3WU="   # invinoveritas-checker-a4cecab2, posted on #51


def jcs(o):
    # The objects here hold only strings, integers, booleans, lists and objects, so sorted keys and compact
    # separators give the RFC 8785 bytes.
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify(sig_b64, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(CHECKER_PUB_B64)).verify(base64.b64decode(sig_b64), msg)
        return True
    except Exception:
        return False


def main():
    man = json.load(open(os.path.join(HERE, "control-manifest.json"), encoding="utf-8"))
    ls = os.path.join(HERE, "..", "live_smoke")
    exec_sha = hashlib.sha256(open(os.path.join(ls, "receipt.json"), "rb").read()).hexdigest()
    occ_sha = hashlib.sha256(jcs(json.load(open(os.path.join(ls, "call.json"), encoding="utf-8"))["request"])).hexdigest()
    lines, good = [], True
    for f in man["files"]:
        raw = open(os.path.join(HERE, f["file"]), "rb").read()
        d = json.loads(raw)
        rec = d["inputs"]["receipt"]["receipt"]
        sc = dict(d["bindings_sidecar"])
        sc_sig = sc.pop("signature")
        got = {
            "file_sha256": hashlib.sha256(raw).hexdigest(),
            "acceptance_signature_valid": verify(d["inputs"]["receipt"]["signature"]["value"], jcs(rec)),
            "sidecar_signature_valid": verify(sc_sig, jcs(sc)),
            "acceptance_receipt_canonical_sha256": hashlib.sha256(jcs(rec)).hexdigest(),
            "sidecar_receipt_sha256": sc["receipt_sha256"],
        }
        got["sidecar_receipt_digest_matches"] = got["acceptance_receipt_canonical_sha256"] == sc["receipt_sha256"]
        got["sidecar_execution_digest_matches"] = sc["bindings"]["execution_receipt_sha256"] == exec_sha
        got["sidecar_occurrence_digest_matches"] = sc["bindings"]["request_occurrence_sha256"] == occ_sha
        exp = f["expected"]
        want = {"file_sha256": f["sha256"]}
        want.update({k: exp[k] for k in ("acceptance_signature_valid", "sidecar_signature_valid",
                                          "acceptance_receipt_canonical_sha256", "sidecar_receipt_sha256",
                                          "sidecar_receipt_digest_matches", "sidecar_execution_digest_matches",
                                          "sidecar_occurrence_digest_matches")})
        bad = [k for k in want if want[k] != got[k]]
        good = good and not bad
        lines.append("%s %s" % ("ok  " if not bad else "FAIL", f["file"]))
        for k in sorted(got):
            lines.append("     %s %s" % (k, json.dumps(got[k])))
        for k in bad:
            lines.append("     MISMATCH %s: manifest %s" % (k, json.dumps(want[k])))
    lines.append("execution receipt %s (../live_smoke/receipt.json bytes), occurrence %s (JCS of call.json request)"
                 % (exec_sha, occ_sha))
    lines.append("%s: %d files" % ("CONTROL_OK" if good else "CONTROL_FAIL", len(man["files"])))
    out = "\n".join(lines) + "\n"
    if "--check" in sys.argv:
        kept = open(os.path.join(HERE, "CHECK.txt"), encoding="utf-8").read()
        if kept != out:
            sys.stdout.write(out)
            print("CHECK.txt differs")
            return 1
        print("CHECK.txt agrees")
        return 0 if good else 1
    sys.stdout.write(out)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
