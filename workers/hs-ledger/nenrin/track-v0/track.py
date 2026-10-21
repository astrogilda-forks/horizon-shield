#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nenrin-track-v0: follow a relying party's signed admissions in a mirror you hold, and say whether its history is one.

A mirror (../mirror-v0) copies the ledger's entries and the records its daily batches name, so the bytes survive the
operator. This reads such a copy, offline, and asks the question a copy alone can answer about a door that signs one
admission per decision and chains each to the one before (admission_id "<name>:seq=<n>:prev=<sha256 of the previous
admission's signed bytes>", as SHIKEN's door and SEKI write them):

  fork          two different admissions, both signed under the key you pinned for that key_url, with the same seq.
                The signer signed two histories. Nobody else can make this finding go away.
  broken_link   an admission whose prev is not the sha256 of the signed bytes of the one admission held at seq - 1
                (seq 1 must name 64 zeros).
  anchored_late an admission first anchored (the Bitcoin block of the ledger entry whose batch names it) more than
                late_blocks after the chain height it says it was decided at: a record that surfaced after the fact.
  gap           a seq below the highest one held that this copy does not hold (not published, or not mirrored).
  unchained     an admission signed by the pinned key whose admission_id names no seq and prev (SEKI's door writes a
                UUID): counted, and judged for anchored_late only.
  bad_signature, unsigned, not_canonical, bytes_mismatch, bad_chain_view: an admission this copy holds that cannot
                be read as signed by the pinned key with a chain height. It is listed and left out.

Keys are pinned by you (--pin <base64 Ed25519 public key>@<key_url the admissions name>), never fetched: the point is to need nothing from the
operator. A key_url you did not pin is listed as unpinned and not judged. A chain is one key_url and one admission_id name.

    python3 track.py --dir ./nenrin-mirror --pin <b64>@https://shield.the-horizons-innovation.com/keys/shiken-door.json    # report, exit 0 clean, 1 findings, 2 input error
    python3 track.py --dir ./nenrin-mirror --pin ... --json                                           # the report as canonical JSON

The report is the same, byte for byte, from this file and from nenrin-track-go (../sdk-go/cmd/nenrin-track-go); the
vectors in vectors/ hold both to it. Standard library, plus the cryptography package for Ed25519.

What it establishes: that the admissions this copy holds, under the keys you pinned, form one chain (or exactly where
they do not), and when each was first anchored. What it does not: that the decisions were right (admission_verify_v0
and the settlement recompute those), that the copy is complete (a gap is named, an admission nobody published is not
seen), or that the Bitcoin block numbers in the ledger entries are true (check the .ots files yourself).
"""
import argparse, base64, hashlib, json, os, re, sys

SCHEMA = "nenrin-track-v0"
CONTEXT = b"a2a-admission-v0\n"
ADMISSION_SCHEMA = "a2a-admission-v0"
BATCH_SCHEMA = "nenrin-agreement-batch-v1"
GENESIS = "0" * 64
LATE_BLOCKS = 576
MAX_SAFE = 9007199254740991
ADMISSION_ID = re.compile(r"\A([^\x00-\x20:][^\x00-\x20]*):seq=([1-9][0-9]{0,14}):prev=([0-9a-f]{64})\Z")
DIGITS = re.compile(r"\A[0-9]{1,15}\Z")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class Unreadable(ValueError):
    pass


def _reject(s):
    raise Unreadable("NaN or Infinity")


def _norm(v):
    """JSON.parse semantics for numbers, so this file and the Go port read the same values: every number is a
    double; one that is not an integer, or is beyond 2^53 - 1, is not read. Object keys must be printable ASCII and no string
    may hold a lone surrogate (where two canonical forms could differ, the input is not read at all)."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        f = float(v) if isinstance(v, int) else v
        if isinstance(v, int) and abs(v) > MAX_SAFE:
            raise Unreadable("an integer beyond 2^53")
        if f != f or f in (float("inf"), float("-inf")) or f != int(f) or abs(f) > MAX_SAFE:
            raise Unreadable("a number that is not an integer within 2^53")
        return int(f)
    if isinstance(v, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v):
            raise Unreadable("a lone surrogate")
        return v
    if isinstance(v, list):
        return [_norm(x) for x in v]
    if isinstance(v, dict):
        if not all(all(0x20 <= ord(c) <= 0x7E for c in k) for k in v):
            raise Unreadable("a key outside printable ASCII")
        return {k: _norm(x) for k, x in v.items()}
    raise Unreadable("unknown value")


def parse(b):
    """A JSON value from UTF-8 bytes, read as JSON.parse reads it (a repeated key: the last wins), or Unreadable."""
    try:
        v = json.loads(b.decode("utf-8"), parse_constant=_reject)
    except Unreadable:
        raise
    except Exception as e:  # noqa: BLE001
        raise Unreadable(str(e)[:80])
    return _norm(v)


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def b64_strict(s):
    if not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
    except Exception:  # noqa: BLE001
        return None
    return raw if base64.b64encode(raw).decode("ascii") == s else None


def ed25519_ok(pub, sig, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _load_json_file(p):
    with open(p, "rb") as f:
        return parse(f.read())


def anchors(d):
    """{admission sha: (ledger entry n, bitcoin_block or None)} from the batch entries this mirror holds, the earliest
    entry first. Entries are read from <dir>/ledger/<n>.json; the batch is the entry's record_canonical."""
    out = {}
    ld = os.path.join(d, "ledger")
    if not os.path.isdir(ld):
        return out
    ns = sorted(int(f[:-5]) for f in os.listdir(ld) if f.endswith(".json") and DIGITS.match(f[:-5]))
    for n in ns:
        try:
            e = _load_json_file(os.path.join(ld, "%d.json" % n))
            rc = e.get("record_canonical") if isinstance(e, dict) else None
            batch = parse(rc.encode("utf-8")) if isinstance(rc, str) else None
        except Unreadable:
            continue
        if not isinstance(batch, dict) or batch.get("schema") != BATCH_SCHEMA:
            continue
        bb = e.get("bitcoin_block")
        bb = bb if isinstance(bb, int) and not isinstance(bb, bool) else None
        recs = batch.get("records")
        if not isinstance(recs, list):
            continue
        for it in recs:
            if isinstance(it, dict) and it.get("record_schema") == ADMISSION_SCHEMA and isinstance(it.get("canonical_sha256"), str) \
                    and HEX64.match(it["canonical_sha256"]) and it["canonical_sha256"] not in out:
                out[it["canonical_sha256"]] = (n, bb)
    return out


def read_admission(sha, b, pins):
    """(record, problem or None, key_url, signed bytes). pins: {key_url: 32 key bytes}."""
    if sha256_hex(b) != sha:
        return None, "bytes_mismatch", None, None
    try:
        rec = parse(b)
    except Unreadable:
        return None, "not_canonical", None, None
    if not isinstance(rec, dict) or canonical(rec).encode("utf-8") != b:
        return None, "not_canonical", None, None
    if rec.get("schema") != ADMISSION_SCHEMA:
        return None, "not_an_admission", None, None
    rp = rec.get("relying_party")
    dom = rp.get("domain") if isinstance(rp, dict) and isinstance(rp.get("domain"), str) else None
    ku = rp.get("key_url") if isinstance(rp, dict) and isinstance(rp.get("key_url"), str) else None
    if not dom or not ku:
        return rec, "unsigned", None, None
    msg = CONTEXT + canonical({k: v for k, v in rec.items() if k != "signatures"}).encode("utf-8")
    if ku not in pins:
        return rec, "unpinned", ku, msg
    sigs = [s for s in (rec.get("signatures") if isinstance(rec.get("signatures"), list) else [])
            if isinstance(s, dict) and s.get("domain") == dom and s.get("alg") == "ed25519"]
    if not sigs:
        return rec, "unsigned", ku, msg
    for s in sigs:
        raw = b64_strict(s.get("sig"))
        if raw is not None and len(raw) == 64 and ed25519_ok(pins[ku], raw, msg):
            return rec, None, ku, msg
    return rec, "bad_signature", ku, msg


def track(d, pins, late_blocks=LATE_BLOCKS):
    """The report (a dict) for the mirror at d under pins ({key_url: 32 key bytes}). A chain is one key_url and one
    admission_id name: two doors that share a domain (as SHIKEN's and SEKI's do) are two chains."""
    anch = anchors(d)
    od = os.path.join(d, "objects")
    held = {}
    for sha in sorted(anch):
        p = os.path.join(od, sha)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                held[sha] = f.read()
    problems, unpinned, loose = [], {}, {}
    chains = {}                     # (key_url, name) -> seq -> [(asha, prev, sha, height)]
    for sha in sorted(held):
        rec, why, ku, msg = read_admission(sha, held[sha], pins)
        if why == "unpinned":
            unpinned[ku] = unpinned.get(ku, 0) + 1
            continue
        if why is not None:
            problems.append({"sha256": sha, "what": why})
            continue
        m = ADMISSION_ID.match(rec.get("admission_id") or "") if isinstance(rec.get("admission_id"), str) else None
        cv = rec.get("chain_view")
        h = cv.get("height") if isinstance(cv, dict) else None
        if not (isinstance(h, int) and not isinstance(h, bool) and h >= 0):
            problems.append({"sha256": sha, "what": "bad_chain_view"})
            continue
        if m is None:            # signed, but its admission_id names no seq and prev (SEKI's door uses a UUID): judged for lateness only
            loose.setdefault(ku, []).append((sha, h))
            continue
        chains.setdefault((ku, m.group(1)), {}).setdefault(int(m.group(2)), []).append((sha256_hex(msg), m.group(3), sha, h))
    missing = sorted(sha for sha in anch if sha not in held)
    doms = []
    for key in sorted(chains):
        c = chains[key]
        seqs = sorted(c)
        forks, broken, late, gaps = [], [], [], []
        for s in seqs:
            items = sorted(c[s])
            if len({x[0] for x in items}) > 1:
                forks.append({"seq": s, "admissions": sorted(x[2] for x in items)})
            for asha, prev, sha, h in items:
                if s == 1:
                    if prev != GENESIS:
                        broken.append({"seq": s, "sha256": sha, "why": "seq 1 names a previous admission"})
                elif s - 1 in c and len({x[0] for x in c[s - 1]}) == 1 and prev != c[s - 1][0][0]:
                    broken.append({"seq": s, "sha256": sha, "why": "prev is not the admission held at seq %d" % (s - 1)})
                n, bb = anch[sha]
                if bb is not None and bb - h > late_blocks:
                    late.append({"seq": s, "sha256": sha, "height": h, "bitcoin_block": bb, "ledger_entry": n})
        top = seqs[-1]
        for lo, hi in zip([0] + seqs, seqs):
            if hi - lo > 1:
                gaps.append([lo + 1, hi - 1])
        heads = sorted({x[0] for x in c[top]})
        unanchored = sorted(x[2] for s in seqs for x in c[s] if anch[x[2]][1] is None)
        doms.append({"key_url": key[0], "name": key[1], "admissions": sum(len(c[s]) for s in seqs), "first_seq": seqs[0], "last_seq": top,
                     "head": heads[0] if len(heads) == 1 else None, "forks": forks, "broken_links": broken,
                     "anchored_late": late, "gaps": gaps, "not_yet_on_bitcoin": len(unanchored)})
    unchained = []
    for ku in sorted(loose):
        late = []
        for sha, h in sorted(loose[ku]):
            n, bb = anch[sha]
            if bb is not None and bb - h > late_blocks:
                late.append({"sha256": sha, "height": h, "bitcoin_block": bb, "ledger_entry": n})
        unchained.append({"key_url": ku, "admissions": len(loose[ku]), "anchored_late": late,
                          "not_yet_on_bitcoin": sum(1 for sha, _h in loose[ku] if anch[sha][1] is None)})
    finding = any(x["forks"] or x["broken_links"] or x["anchored_late"] for x in doms) or any(x["anchored_late"] for x in unchained)
    incomplete = bool(missing) or any(x["gaps"] for x in doms) or bool(problems)
    rep = {"schema": SCHEMA, "late_blocks": late_blocks, "pinned": sorted(pins),
           "verdict": "findings" if finding else ("incomplete" if incomplete else "one_history"),
           "chains": doms, "unchained": unchained, "problems": problems, "unpinned": [{"key_url": k, "admissions": v} for k, v in sorted(unpinned.items())],
           "named_not_held": missing,
           "does_not_establish": ["that any decision was right; admission_verify_v0 and the settlement recompute that",
                                  "that this copy holds every admission the signer made; a gap is named, an unpublished admission is not seen",
                                  "that a ledger entry's bitcoin_block is true; verify its .ots against Bitcoin headers"]}
    rep["report_sha256"] = sha256_hex(canonical(rep).encode("utf-8"))
    return rep


def parse_pins(items):
    """["<base64 key>@<key_url>", ...] -> {key_url: key bytes}. The key_url is the one the admissions name."""
    pins = {}
    for it in items or []:
        k, _, ku = it.partition("@")
        raw = b64_strict(k)
        if not ku or raw is None or len(raw) != 32:
            raise SystemExit("--pin wants <base64 of a 32 byte Ed25519 public key>@<key_url>: %r" % it)
        pins[ku] = raw
    return pins


def main(argv=None):
    ap = argparse.ArgumentParser(description="follow signed admissions in a nenrin mirror and say whether each history is one")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--pin", action="append", default=[])
    ap.add_argument("--late-blocks", type=int, default=LATE_BLOCKS)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.dir):
        print("no such directory: %s" % a.dir, file=sys.stderr)
        return 2
    rep = track(a.dir, parse_pins(a.pin), a.late_blocks)
    if a.json:
        print(canonical(rep))
    else:
        print("verdict: %s" % rep["verdict"])
        for x in rep["chains"]:
            print("  %s %s: %d admissions, seq %d to %d, head %s" % (x["key_url"], x["name"], x["admissions"], x["first_seq"], x["last_seq"], (x["head"] or "(forked)")[:16]))
            for k in ("forks", "broken_links", "anchored_late", "gaps"):
                if x[k]:
                    print("    %s: %s" % (k, json.dumps(x[k])))
        for x in rep["unchained"]:
            print("  %s: %d signed admissions with no seq and prev (judged for lateness only)%s" % (x["key_url"], x["admissions"],
                  ", anchored late: %s" % json.dumps(x["anchored_late"]) if x["anchored_late"] else ""))
        for p in rep["problems"]:
            print("  problem %s %s" % (p["what"], p["sha256"][:16]))
        for u in rep["unpinned"]:
            print("  unpinned %s (%d admissions, not judged)" % (u["key_url"], u["admissions"]))
        if rep["named_not_held"]:
            print("  named by a batch and not in this copy: %d" % len(rep["named_not_held"]))
        print("report_sha256 %s" % rep["report_sha256"])
    return 1 if rep["verdict"] == "findings" else 0


if __name__ == "__main__":
    sys.exit(main())
