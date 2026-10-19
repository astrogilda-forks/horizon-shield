#!/usr/bin/env python3
"""Regenerate evidence/claims/* against the souba-db release that is live in data/souba-db.json.

Run from the repository root:  python3 evidence/claims/regen_claims.py --anchor-entry N
N is the JIDEC entry that anchors the dataset release (the entry whose dataset_sha256 equals the
sha256 of data/souba-db.json). The script refuses if the dataset bytes do not hash to what the
entry is expected to carry (pass --expect-sha256), so the index cannot name an anchor for other bytes.

For each claim it keeps the question, page, mcp call, self_check, region note and does_not_establish
as they are; it re-reads every values[] row from the dataset by category_id, rebuilds answer and
comparison from those values, sets source.* and valid_from from the dataset's _meta, points the
anchor at the given entry, and recomputes object_sha256 by the rule the objects state
(sha256 of json.dumps(object without object_sha256, sort_keys=True, separators=(',', ':'),
ensure_ascii=False)). The index gets the dataset version, digest, anchor and the new object digests.
Files are written as before: json.dumps(..., ensure_ascii=False, indent=1, sort_keys=True) + newline.
--check reports what would change and writes nothing.
"""
import argparse, hashlib, json, sys
from pathlib import Path

ROOT = Path.cwd()
DATA = ROOT / "data" / "souba-db.json"
CLAIMS = ROOT / "evidence" / "claims"
LEDGER = "https://ledger.horizonshield.dev/ledger/"


def man(yen):
    """150000 -> '15', 99000 -> '9.9', 30000 -> '3' (in units of 10,000 yen, as the claims print)."""
    v = yen / 10000
    return str(int(v)) if v == int(v) else ("%.1f" % v).rstrip("0").rstrip(".")


def span(row):
    return "%s〜%s万円(平均%s万円)" % (man(row["min"]), man(row["max"]), man(row["avg"]))


def obj_sha(o):
    body = {k: v for k, v in o.items() if k != "object_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def dump(o):
    return json.dumps(o, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--anchor-entry", type=int, required=True)
    ap.add_argument("--expect-sha256", required=True)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    raw = DATA.read_bytes()
    ds_sha = hashlib.sha256(raw).hexdigest()
    if ds_sha != a.expect_sha256:
        sys.exit("data/souba-db.json is %s, not %s; refusing" % (ds_sha, a.expect_sha256))
    db = json.loads(raw)
    meta = db["_meta"]
    cats = {c["id"]: c for c in db["categories"]}
    index = json.loads((CLAIMS / "index.json").read_text(encoding="utf8"))
    out = {}
    for entry in index["claims"]:
        p = CLAIMS / (entry["id"] + ".json")
        c = json.loads(p.read_text(encoding="utf8"))
        rows = []
        for v in c["values"]:
            row = cats.get(v["category_id"])
            if row is None:
                sys.exit("%s: category %s is not in the dataset" % (entry["id"], v["category_id"]))
            rows.append({"avg": row["avg"], "category_id": row["id"], "max": row["max"], "min": row["min"],
                         "unit": row["unit"], "work": row["work"]})
        c["values"] = rows
        c["answer"] = "%s の目安は %s です。" % (rows[0]["work"], span(rows[0]))
        c["comparison"] = ["%s: %s" % (r["work"], span(r)) for r in rows]
        c["source"]["dataset_sha256"] = ds_sha
        c["source"]["dataset_version"] = meta["version"]
        c["valid_from"] = meta["updated_at"]
        c["anchor"] = {"jidec_entry": a.anchor_entry, "ledger_url": LEDGER + str(a.anchor_entry),
                       "what": "the SHA-256 of this exact souba-db.json release is recorded in JIDEC entry %d with an OpenTimestamps proof" % a.anchor_entry}
        c["object_sha256"] = obj_sha(c)
        entry["object_sha256"] = c["object_sha256"]
        out[p] = c
    index["dataset_sha256"] = ds_sha
    index["dataset_version"] = meta["version"]
    index["anchor"] = LEDGER + str(a.anchor_entry)
    out[CLAIMS / "index.json"] = index
    for p, o in out.items():
        new = dump(o)
        old = p.read_text(encoding="utf8")
        print(("same    " if new == old else "changed ") + str(p.relative_to(ROOT)), o.get("object_sha256", ""))
        if not a.check and new != old:
            p.write_text(new, encoding="utf8")


if __name__ == "__main__":
    main()
