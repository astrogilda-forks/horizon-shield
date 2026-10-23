#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
settle core v0, held-out set blind-01: commit to the answers before anyone sees them, and check the opening.

    python3 blind_commit.py commit --public PUBDIR --expected EXPDIR --salts SALTS.json --spec SETTLE_CORE_v0.md \
                                   --spec-commit <git commit> --generator blind_gen.py --seed-file blind_seed.txt
        writes PUBDIR/COMMITMENT.txt. Creates SALTS.json (private) when it does not exist; never overwrites it.

    python3 blind_commit.py check-inputs --public PUBDIR
        every file under PUBDIR/inputs is in PUBDIR/SHA256SUMS with its sha256, and nothing else is.

    python3 blind_commit.py open --public PUBDIR --expected EXPDIR --salts SALTS.json [--generator F --seed-file F]
        at opening: every expected.json and the root match COMMITMENT.txt. Anyone can run it once the salts are out.

Why salts. An expected.json holds eight fields. Five of them (contract_sha256, the sha256 and height in event_set, the
keys of dispositions) can be computed from the inputs by anyone; the rest come from short lists (4 verdicts, 3 statuses,
5 bond outcomes, subsets of 10 deviation codes and 28 reasons, one of about 20 dispositions per record). A realistic
candidate list for one vector is well under 2^32 answers, so a bare sha256 of each expected.json can be inverted on a
laptop in minutes. Each vector therefore gets its own 256-bit random salt (secrets.token_bytes(32)); 128 bits would be
enough against guessing, 256 costs nothing. Per-vector salts let each answer be opened on its own, and one salt never
helps with another vector. The root has a salt of its own as well, so the single value that is timestamped says
nothing about the set before opening.

Commitment of vector i:  sha256( b"settle-core-v0 blind-01 answer v1\n" + id + b"\n" + salt_hex + b"\n" + expected.json bytes )
Root:                    sha256( b"settle-core-v0 blind-01 root v1\n" + root_salt_hex + b"\n" + every line of COMMITMENT.txt above the root line )
expected.json bytes are exactly as written by blind_gen.py: json.dumps(core fields, indent=1, sort_keys=True) + "\n".
"""
import argparse, hashlib, json, os, secrets, sys

DOM_ANSWER = b"settle-core-v0 blind-01 answer v1\n"
DOM_ROOT = b"settle-core-v0 blind-01 root v1\n"
HEAD = "settle-core-v0 blind-01 commitment v1"

sha = lambda b: hashlib.sha256(b).hexdigest()
sha_file = lambda p: sha(open(p, "rb").read())


def answer_commit(vid, salt_hex, exp_bytes):
    return sha(DOM_ANSWER + vid.encode() + b"\n" + salt_hex.encode() + b"\n" + exp_bytes)


def root_of(body_lines, root_salt_hex):
    return sha(DOM_ROOT + root_salt_hex.encode() + b"\n" + "".join(l + "\n" for l in body_lines).encode())


def ids_of(pub):
    return sorted(os.listdir(os.path.join(pub, "inputs")))


def check_inputs(pub):
    want = {}
    for line in open(os.path.join(pub, "SHA256SUMS"), encoding="utf-8"):
        h, p = line.rstrip("\n").split("  ", 1)
        want[p] = h
    got = {}
    for root, _, fs in os.walk(os.path.join(pub, "inputs")):
        for f in fs:
            p = os.path.join(root, f)
            got[os.path.relpath(p, pub).replace(os.sep, "/")] = sha_file(p)
    bad = sorted(p for p in set(want) | set(got) if want.get(p) != got.get(p))
    for p in bad:
        print("MISMATCH %s listed %s found %s" % (p, (want.get(p) or "-")[:12], (got.get(p) or "-")[:12]))
    print("inputs: %d files, %d listed, %d mismatches" % (len(got), len(want), len(bad)))
    return not bad


def read_commitment(pub):
    lines = open(os.path.join(pub, "COMMITMENT.txt"), encoding="utf-8").read().splitlines()
    assert lines[0] == HEAD, "not a blind-01 commitment"
    assert lines[-1].startswith("root "), "last line must be the root"
    kv, per = {}, {}
    for l in lines[1:-1]:
        k, v = l.split(" ", 1)
        if k.startswith("b") and k[1:].isdigit():
            per[k] = v
        else:
            kv[k] = v
    return lines[:-1], lines[-1].split(" ", 1)[1], kv, per


def cmd_commit(a):
    pub = a.public
    if os.path.exists(os.path.join(pub, "COMMITMENT.txt")):
        sys.exit("COMMITMENT.txt exists; a commitment is never rewritten")
    if not check_inputs(pub):
        sys.exit("inputs do not match SHA256SUMS")
    ids = ids_of(pub)
    if os.path.exists(a.salts):
        salts = json.load(open(a.salts, encoding="utf-8"))
        assert sorted(salts["vectors"]) == ids, "salt file is for another id list"
    else:
        salts = {"root": secrets.token_hex(32), "vectors": {i: secrets.token_hex(32) for i in ids}}
        fd = os.open(a.salts, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(salts, indent=1, sort_keys=True) + "\n")
    body = [HEAD,
            "spec SETTLE_CORE_v0.md sha256 %s at commit %s" % (sha_file(a.spec), a.spec_commit),
            "inputs SHA256SUMS sha256 %s" % sha_file(os.path.join(pub, "SHA256SUMS")),
            "count %d" % len(ids),
            "generator blind_gen.py sha256 %s (published at opening)" % sha_file(a.generator),
            "seed sha256 %s (published at opening)" % sha(open(a.seed_file, "rb").read().strip()),
            "answer sha256(\"settle-core-v0 blind-01 answer v1\\n\" + id + \"\\n\" + salt_hex + \"\\n\" + expected.json bytes)"]
    for i in ids:
        e = open(os.path.join(a.expected, i, "expected.json"), "rb").read()
        body.append("%s %s" % (i, answer_commit(i, salts["vectors"][i], e)))
    root = root_of(body, salts["root"])
    with open(os.path.join(pub, "COMMITMENT.txt"), "w", encoding="utf-8", newline="") as f:
        f.write("".join(l + "\n" for l in body) + "root %s\n" % root)
    print("COMMITMENT.txt written: %d answers, root %s" % (len(ids), root))


def verify_opening(pub, expected, salts_path, generator=None, seed_file=None):
    body, root, kv, per = read_commitment(pub)
    salts = json.load(open(salts_path, encoding="utf-8"))
    ok = True
    if root_of(body, salts["root"]) != root:
        print("ROOT does not match")
        ok = False
    if kv.get("inputs", "").split(" ")[2:3] != [sha_file(os.path.join(pub, "SHA256SUMS"))]:
        print("SHA256SUMS is not the committed one")
        ok = False
    for i, c in sorted(per.items()):
        e = open(os.path.join(expected, i, "expected.json"), "rb").read()
        if answer_commit(i, salts["vectors"][i], e) != c:
            print("ANSWER %s does not match its commitment" % i)
            ok = False
    if generator and sha_file(generator) != kv["generator"].split(" ")[2]:
        print("generator is not the committed one")
        ok = False
    if seed_file and sha(open(seed_file, "rb").read().strip()) != kv["seed"].split(" ")[1]:
        print("seed is not the committed one")
        ok = False
    print("opening: %d answers, root %s: %s" % (len(per), root[:16], "OK" if ok else "FAILED"))
    return ok


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("commit")
    for k in ("--public", "--expected", "--salts", "--spec", "--spec-commit", "--generator", "--seed-file"):
        c.add_argument(k, required=True)
    ci = sub.add_parser("check-inputs")
    ci.add_argument("--public", required=True)
    o = sub.add_parser("open")
    for k in ("--public", "--expected", "--salts"):
        o.add_argument(k, required=True)
    o.add_argument("--generator")
    o.add_argument("--seed-file")
    a = ap.parse_args()
    if a.cmd == "commit":
        cmd_commit(a)
        return 0
    if a.cmd == "check-inputs":
        return 0 if check_inputs(a.public) else 1
    return 0 if verify_opening(a.public, a.expected, a.salts, a.generator, a.seed_file) else 1


if __name__ == "__main__":
    sys.exit(main())
