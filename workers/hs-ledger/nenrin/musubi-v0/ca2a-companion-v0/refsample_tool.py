#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The provider's and the checker's side of MUSUBI reference sampling (refsample_v0.py, REFSAMPLE_v0.md).

Provider, before the draw:
  python3 refsample_tool.py keygen provider.key
  python3 refsample_tool.py commit provider.key FILE RULE --dataset-id ID --rate-ppm 10000 \\
          --draw-height H --checker <hex> [--checker <hex> ...] --seen-height N --seen-hash <hex> > commitment.json
  python3 refsample_tool.py stampable commitment.json commitment.stamp      then: ots stamp commitment.stamp
  (once Bitcoin has confirmed it: ots upgrade commitment.stamp.ots)
  python3 refsample_tool.py compose commitment.json commitment.stamp.ots VIEW.json > anchor.json

  H must be a block nobody has seen yet, far enough ahead that the stamp confirms below it: the commitment
  binds only if its anchor is at a height below H. A day ahead (about 144 blocks) is comfortable.

Checker, after block H is mined:
  python3 refsample_tool.py draw commitment.json FILE --block-hash <hash of block H>    the worklist: every
          sampled row with its locator in the file
  python3 refsample_tool.py check checker.key commitment.json --row <row sha256> --verdict match \\
          --url <source> --source-sha256 <sha256 of the source bytes> --locator <where in it> \\
          --seen-height N --seen-hash <hex>                                            one signed check

The seen block of a check must be at or after H. A row whose source does not say which value it supports is
not_checkable; a source that cannot be fetched is unreachable. Those count against the dataset, by design.
"""
import argparse, hashlib, json, os, secrets, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey   # noqa: E402
import companion_v0 as C               # noqa: E402
import refsample_v0 as R               # noqa: E402


def _priv(path):
    with open(path, "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().decode("ascii").strip()))


def _pub(priv):
    return priv.public_key().public_bytes_raw().hex()


def _load(path):
    with open(path, "rb") as f:
        return C.load_strict(f.read())


def _out(obj):
    sys.stdout.write(C.jcs(obj).decode("utf-8") + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("key")
    c = sub.add_parser("commit")
    for a in ("key", "file", "rule"):
        c.add_argument(a)
    c.add_argument("--dataset-id", required=True)
    c.add_argument("--rate-ppm", type=int, required=True)
    c.add_argument("--draw-height", type=int, required=True)
    c.add_argument("--checker", action="append", required=True)
    c.add_argument("--seen-height", type=int, required=True)
    c.add_argument("--seen-hash", required=True)
    s = sub.add_parser("stampable"); s.add_argument("commitment"); s.add_argument("out")
    m = sub.add_parser("compose"); m.add_argument("commitment"); m.add_argument("ots"); m.add_argument("view")
    m.add_argument("--max-target-bits", default="1d00ffff"); m.add_argument("--lower-bound-height", type=int)
    d = sub.add_parser("draw"); d.add_argument("commitment"); d.add_argument("file"); d.add_argument("--block-hash", required=True)
    ch = sub.add_parser("check")
    ch.add_argument("key"); ch.add_argument("commitment")
    ch.add_argument("--row", required=True); ch.add_argument("--verdict", required=True, choices=R.VERDICTS)
    ch.add_argument("--url"); ch.add_argument("--source-sha256"); ch.add_argument("--locator")
    ch.add_argument("--seen-height", type=int, required=True); ch.add_argument("--seen-hash", required=True)
    a = ap.parse_args()

    try:
        if a.cmd == "keygen":
            seed = secrets.token_bytes(32)
            fd = os.open(a.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(seed.hex().encode("ascii") + b"\n")
            print(_pub(Ed25519PrivateKey.from_private_bytes(seed)))
        elif a.cmd == "commit":
            priv = _priv(a.key)
            with open(a.file, "rb") as f:
                raw = f.read()
            digs = [R.row_sha256(r) for _, r in R.rows_of_file(raw, a.rule)]
            body = {"type": R.T_COMMIT, "provider": _pub(priv), "dataset_id": a.dataset_id,
                    "dataset_sha256": R.dataset_sha256(digs, a.rule), "row_count": len(set(digs)), "row_rule": a.rule,
                    "file_sha256": hashlib.sha256(raw).hexdigest(), "rate_ppm": a.rate_ppm,
                    "draw_height": a.draw_height, "checkers": a.checker,
                    "seen_block": {"height": a.seen_height, "hash": a.seen_hash}}
            item = C.sign(body, priv)
            R._commitment(item)                  # refuse to emit what the verifier would refuse
            _out(item)
        elif a.cmd == "stampable":
            item = _load(a.commitment)
            R._commitment(item)
            b = C.jcs(item)
            with open(a.out, "wb") as f:
                f.write(b)
            print(hashlib.sha256(b).hexdigest())
        elif a.cmd == "compose":
            sys.path.insert(0, os.path.dirname(HERE))
            import anchor_compose as ac
            item = _load(a.commitment)
            d = bytes.fromhex(C.sha256_hex(C.jcs(item)))
            with open(a.ots, "rb") as f:
                fdig, atts = ac.read_ots(f.read())
            if fdig != d:
                sys.exit("the .ots stamps other bytes: stamp the file `stampable` writes")
            view = _load(a.view)
            hs = view["headers"]
            lbh = a.lower_bound_height if a.lower_bound_height is not None else hs[0]["height"]
            hx = next((x["hex"] for x in hs if x["height"] == lbh), None)
            if hx is None:
                sys.exit("the lower bound height is not in the view")
            lb = {"kind": "bitcoin_block", "height": lbh, "hash": R.c1.v11.header_hash(bytes.fromhex(hx))}
            res, problem = R.c1.v11.verify_view(view, {"grant": {"finality": {"max_target_bits": a.max_target_bits}},
                                                       "lower_bound": lb})
            if res is None:
                sys.exit("view rejected: %s" % problem)
            for att in sorted((x for x in atts if x["kind"] == "bitcoin"), key=lambda x: x["height"]):
                h = att["height"]
                if h not in res["hashes"]:
                    continue
                proof = ac.ots_ops(att)
                if R.c1.v11.run_proof(d, proof) == res["merkle"][h]:
                    _out({"height": h, "block_hash": res["hashes"][h], "proof": proof})
                    return
            sys.exit("no Bitcoin attestation in the .ots reaches a header in the view (pending? run ots upgrade)")
        elif a.cmd == "draw":
            item = _load(a.commitment)
            R._commitment(item)
            if not C.HEX32.fullmatch(a.block_hash):
                sys.exit("--block-hash must be the 64 hex digits of block %d" % item["draw_height"])
            with open(a.file, "rb") as f:
                raw = f.read()
            if hashlib.sha256(raw).hexdigest() != item["file_sha256"]:
                sys.exit("this file is not the committed file")
            seen, rows = set(), []
            for loc, r in R.rows_of_file(raw, item["row_rule"]):
                dg = R.row_sha256(r)
                if dg in seen:
                    continue
                seen.add(dg)
                if R.drawn(a.block_hash, dg, item["rate_ppm"]):
                    rows.append({"row_sha256": dg, "locator": loc, "row": r})
            _out({"commitment_sha256": C.sha256_hex(C.jcs(item)), "draw_height": item["draw_height"],
                  "block_hash": a.block_hash, "sampled": len(rows), "rows": rows})
        elif a.cmd == "check":
            priv = _priv(a.key)
            item = _load(a.commitment)
            R._commitment(item)
            if a.seen_height < item["draw_height"]:
                sys.exit("a check names a block at or after the draw block %d" % item["draw_height"])
            body = {"type": R.T_CHECK, "checker": _pub(priv), "commitment_sha256": C.sha256_hex(C.jcs(item)),
                    "row_sha256": a.row, "verdict": a.verdict,
                    "evidence": {"url": a.url, "sha256": a.source_sha256, "locator": a.locator},
                    "seen_block": {"height": a.seen_height, "hash": a.seen_hash}}
            ck = C.sign(body, priv)
            R._check(ck)
            _out(ck)
    except C.Bad as exc:
        sys.exit("refused: %s%s" % (exc.code, (" (%s)" % exc.detail) if getattr(exc, "detail", None) else ""))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        sys.exit("refused: %s" % exc)
    except Exception as exc:                       # anchor_compose.Refused and the like
        sys.exit("refused: %s %s" % (type(exc).__name__, getattr(exc, "code", exc)))


if __name__ == "__main__":
    main()
