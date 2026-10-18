#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rehearsal of reference sampling on a real file: one JCCDB observation file, test keys, the test chain.

The file is data/jccdb-obs-v2/observations/jp/material_kkr_namacon_r8_10.csv of this repository (ready-mixed
concrete design unit prices of the Kinki Regional Development Bureau, October 2026; 846 rows, each with the
PDF it comes from and the page). The provider and the checkers are test keys and the draw block is a block of
the test chain, so nothing here binds: it shows what the provider commits to, what the checker's worklist
looks like, and what a settlement says before anyone has checked a row (every sampled row unchecked, so the
bound covers the whole dataset). The real run uses a real future block and checkers who posted their keys.

Writes rehearsal_refsample/ next to this file. Deterministic.

  python3 refsample_rehearsal.py [path to the repository root]
"""
import base64, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import gen_vectors as G                # noqa: E402
import gen_vectors_v0_1 as GV          # noqa: E402
import companion_v0 as C               # noqa: E402
import refsample_v0 as R               # noqa: E402
import gen_vectors_refsample_v0 as GR  # noqa: E402

REL = "data/jccdb-obs-v2/observations/jp/material_kkr_namacon_r8_10.csv"
RATE = 20000                            # 2 percent: about 17 of 846 rows
OUT = os.path.join(HERE, "rehearsal_refsample")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
    with open(os.path.join(root, REL), "rb") as f:
        raw = f.read()
    s = GV.Sc()
    s.mine()
    seen = s.tip()
    cm = GR.commitment(raw, seen["height"] + 3, seen, dataset_id="jccdb-obs-v2:" + REL.split("/")[-1],
                       rule="csv-header-rows", rate=RATE)
    [stamped] = s.mine([dict(cm)])
    for _ in range(10):
        s.mine()
    H = cm["draw_height"]
    beacon = s.ch.hashes[H]
    rows = []
    seen_d = set()
    for loc, r in R.rows_of_file(raw, "csv-header-rows"):
        d = R.row_sha256(r)
        if d in seen_d or not R.drawn(beacon, d, RATE):
            seen_d.add(d)
            continue
        seen_d.add(d)
        rows.append({"row_sha256": d, "locator": loc, "obs_id": r["obs_id"], "item": r["item_name"], "spec": r["spec"],
                     "area": "%s / %s" % (r["geo_name"], r["area_label"]), "unit": r["unit"], "price": r["price"],
                     "source_pdf": r["evidence_url"], "pdf_page_index": r["source_page"]})
    bundle = {"profile": R.PROFILE, "commitment_sha256": C.sha256_hex(C.jcs(cm)),
              "view": s.ch.view(), "commitment": cm, "commitment_anchors": [stamped["anchor"]],
              "dataset": {"file_b64": base64.b64encode(raw).decode("ascii")}, "checks": []}
    bundle = json.loads(C.jcs(bundle))
    policy = {"type": R.T_POLICY, "lower_bound": {"kind": "bitcoin_block", "height": 95, "hash": s.ch.hashes[95]},
              "max_target_bits": "207fffff", "min_depth": 6, "checkers": [GR.K1_PUB, GR.K2_PUB], "quorum": 1,
              "min_sampled": 10}
    st = json.loads(C.jcs(R.settle(bundle, policy)))
    os.makedirs(OUT, exist_ok=True)
    worklist = {"what": "the rows a checker would look up, each against the named PDF at the given page index "
                        "(1-based page of the PDF file, front matter included), in the column of the named area",
                "file": REL, "file_sha256": hashlib.sha256(raw).hexdigest(), "commitment_sha256": bundle["commitment_sha256"],
                "draw_height": H, "block_hash": beacon, "rate_ppm": RATE, "sampled": len(rows), "rows": rows}
    for name, obj in (("commitment.json", cm), ("policy.json", policy), ("worklist.json", worklist), ("settlement.json", st),
                      ("bundle.sha256", {"bundle_sha256": C.sha256_hex(C.jcs(bundle)),
                                         "note": "the bundle carries the 846-row file and is rebuilt by this script"})):
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(C.jcs(obj))
    rsr = st["refsample"]
    print(rsr["status"], rsr["fixed_by"], rsr["draw"]["sampled"], rsr["tally"], rsr["bound"]["not_shown_correct_upper_95_ppm"])


if __name__ == "__main__":
    main()
