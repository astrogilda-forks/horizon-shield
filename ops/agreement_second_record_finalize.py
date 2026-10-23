#!/usr/bin/env python3
"""
ops/agreement_second_record_finalize.py

Writes the UNSIGNED canonical a2a-agreement-v1.1 record for the SECOND bilateral record between
HORIZON SHIELD and babyblueviper1 (babyblueviper.com): the mutual a2a-conduct-v1 walks of 2026-09-24.
Unlike the first record (JIDEC entry 34, self-measured), each party here pins the OTHER's endpoint,
walked live and passing 5/5, and babyblueviper1's side is signed and content-addressed on babyblueviper1's own host.

It signs nothing, fetches nothing, never touches a private key. Standard library only, Python 3.8+.
All known values are baked as defaults from the 2026-09-25 prep run, so it runs with no arguments.

    python3 ops/agreement_second_record_finalize.py

The counterparty (babyblueviper1) walked gate.horizonshield.dev; HORIZON SHIELD walked
api.babyblueviper.com. That is why party B's conduct subject_domain is gate.horizonshield.dev here,
not mcp.horizonshield.dev as in the first record.
"""
import argparse, json, re, secrets, sys, time, io, os, hashlib

LEDGER = "https://ledger.horizonshield.dev"
# --- 2026-09-25 prep run values (read-only prep: cards, HS walk, lower_bound) ---
A_PUB   = "Q8DJu/tXWNNzsrmIkIUm4r2cR4MYaXNf1E2j+oZi+oo="   # gate /keys/agreement.json
A_CARD  = "9851541310db6b83a9a325e6a0b7250ccdd8eb62421398bd8aa5df71276e75d2"   # mcp.horizonshield.dev card, 11325 B
A_WALK  = "db73e0ceaf180c502bb324c67fa10bf87f343a5d2b980dead330d5f6b9e7a1c8"   # HS walked api.babyblueviper.com, PASS 5/5
B_PUB   = "poTpqz0G34FMkZ1okV/fd5Dcvq7mCO4v1+qOgqBsje4="   # api.babyblueviper.com /keys/agreement.json (same key as record 1)
B_CARD  = "5306018339599f3a8c7f6c932487b86f4c8d88a9766db3a1c2cec2f832816dac"   # api.babyblueviper.com card, 21082 B
B_WALK  = "aba24be0b26463773432d1d090a16601440ba09a0ea8b81ab9fbe1051634e476"   # babyblueviper1 walked gate.horizonshield.dev, a2a 0.3, PASS 5/5
B_WALK_URL = "https://api.babyblueviper.com/record/aba24be0b26463773432d1d090a16601440ba09a0ea8b81ab9fbe1051634e476"
LB_HEIGHT = 968416
LB_HASH   = "0000000000000000000122af55415c0cfe39fa65742f4083a4e464d5f074b9ac"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def die(m):
    print("refused: " + m, file=sys.stderr); sys.exit(2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agreement-id", default=None)
    ap.add_argument("--agreed-at", default=None)
    ap.add_argument("--lb-height", type=int, default=LB_HEIGHT)
    ap.add_argument("--lb-hash", default=LB_HASH)
    ap.add_argument("--a-pubkey", default=A_PUB)
    ap.add_argument("--b-pubkey", default=B_PUB)
    ap.add_argument("--a-card-sha", default=A_CARD)
    ap.add_argument("--b-card-sha", default=B_CARD)
    ap.add_argument("--a-conduct-sha", default=A_WALK)
    ap.add_argument("--b-conduct-sha", default=B_WALK)
    ap.add_argument("--b-conduct-url", default=B_WALK_URL)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    for k, v in (("a-card", a.a_card_sha), ("b-card", a.b_card_sha), ("a-conduct", a.a_conduct_sha),
                 ("b-conduct", a.b_conduct_sha), ("lb-hash", a.lb_hash)):
        if not HEX64.match(v): die("--%s must be 64 lowercase hex" % k)
    if not a.b_conduct_url.startswith("https://"): die("--b-conduct-url must be https")

    agreement_id = a.agreement_id or secrets.token_hex(16)
    agreed_at = a.agreed_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not re.match(r"^[0-9a-f]{32}$", agreement_id): die("agreement_id must be 32 lowercase hex")

    record = {
        "schema": "a2a-agreement-v1.1",
        "agreement_id": agreement_id,
        "agreed_at": agreed_at,
        "lower_bound": {"kind": "bitcoin_block", "height": a.lb_height, "hash": a.lb_hash},
        "parties": [
            {
                "domain": "horizonshield.dev",
                "key_url": "https://gate.horizonshield.dev/keys/agreement.json",
                "public_key_ed25519_b64": a.a_pubkey,
                "agent_card": "https://mcp.horizonshield.dev/.well-known/agent-card.json",
                "agent_card_sha256": a.a_card_sha,
                "conduct_record": {
                    "sha256": a.a_conduct_sha,
                    "url": LEDGER + "/witness/" + a.a_conduct_sha,
                    "subject_domain": "api.babyblueviper.com",
                    "measured_by_domain": "horizonshield.dev",
                    "self_measured": True,
                },
                "role": "peer",
            },
            {
                "domain": "babyblueviper.com",
                "key_url": "https://api.babyblueviper.com/keys/agreement.json",
                "public_key_ed25519_b64": a.b_pubkey,
                "agent_card": "https://api.babyblueviper.com/.well-known/agent-card.json",
                "agent_card_sha256": a.b_card_sha,
                "conduct_record": {
                    "sha256": a.b_conduct_sha,
                    "url": a.b_conduct_url,
                    "subject_domain": "gate.horizonshield.dev",
                    "measured_by_domain": "babyblueviper.com",
                    "self_measured": True,
                },
                "role": "peer",
            },
        ],
        "terms": {
            "what": ("that on 2026-09-24 each party walked the other's a2a-conduct-v1 endpoint and pinned "
                     "its signed result: HORIZON SHIELD walked https://api.babyblueviper.com/a2a and Federico's "
                     "agent walked https://gate.horizonshield.dev/a2a, each passing five of five applicable "
                     "conduct checks"),
            "consideration": "none",
            "disclosure_url": LEDGER + "/witness/" + a.a_conduct_sha,
        },
        "recorder": {"domain": "horizonshield.dev", "is_a_party": True, "fee": {"basis": "none"}},
        "record_paid_by": "neither",
        "establishes": [
            "that both parties signed these bytes at the stated time",
            "that each party named, by sha256, a signed conduct walk of the other's a2a endpoint at that moment",
            "that at the walked instant each endpoint passed the five applicable conduct checks, as recorded in the pinned walk",
        ],
        "does_not_establish": [
            "that either party performed any other work under this record",
            "that this record is a contract",
            "that money moved, or was ever owed",
            "that the conduct record each side pinned is accurate, only that both parties stand behind the exact bytes they named",
            "that either endpoint behaves the same at other instants or from other vantages",
            "that either implementation is free of defects",
        ],
        # record-privacy-v1 (intake 0.2.0): the ledger publishes an agreement only when both signatures
        # cover this field. Without it the both-signed record is refused (422 publication_consent_missing).
        "publication": "public",
        "signatures": [],
    }

    text = canonical(record)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    # own directory on purpose: ops/second_record_prep_out/ belongs to the 2026-09-23 record (commit d5ad6e9b)
    out = a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutual_walk_record_20260925", "mutual_walk_unsigned.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    io.open(out, "w", encoding="utf-8", newline="").write(text)
    print("unsigned canonical record written: " + out)
    print("bytes " + str(len(text.encode("utf-8"))) + "  sha256(unsigned) " + sha)
    print("agreement_id " + agreement_id + "  agreed_at " + agreed_at + "  lower_bound " + str(a.lb_height))
    print("")
    print("next, in order (V = workers/hs-ledger/nenrin/agreement-v0):")
    print("  0. file HS's own walk so its url resolves (publish, your hand). The intake takes")
    print("     {\"record_canonical\": \"<exact record text>\"}, not the raw file, so wrap it first:")
    print("     python3 -c 'import json;open(\"/tmp/witness_body.json\",\"w\",encoding=\"utf-8\").write(json.dumps({\"record_canonical\":open(\"ops/first_record_prep_out/walk_babyblueviper.json\",encoding=\"utf-8\").read()},ensure_ascii=False))' && curl -sS -X POST %s/witness -H 'content-type: application/json' --data-binary @/tmp/witness_body.json" % LEDGER)
    print("     (expect a JSON reply whose sha equals the walk sha pinned above)")
    print("  1. sign as party A (set V first: V=workers/hs-ledger/nenrin/agreement-v0):")
    print("     python3 $V/agreement_sign.py " + out + " --key ~/.hs_agreement_key.pem --domain horizonshield.dev --out ops/mutual_walk_record_20260925/mutual_walk_A.json")
    print("  2. hand mutual_walk_A.json to the counterparty by exact bytes (commit it and give the raw URL at that commit plus its sha256); the counterparty runs:")
    print("     python3 agreement_sign.py mutual_walk_A.json --key <babyblueviper1.pem> --domain babyblueviper.com --out mutual_walk_AB.json")
    print("  3. when it returns, verify and file:")
    print("     python3 $V/agreement_verify.py mutual_walk_AB.json --keys ops/second_record_prep_out/keys.json   # expect accepted; findings conduct_self_measured x2, operator_is_a_party")
    print("     curl -sS -X POST https://agreement.horizonshield.dev/agreement -H 'content-type: application/json' --data-binary @mutual_walk_AB.json")
    print("")
    print("before sending anything: check no other HS-signed record for the same subject is already waiting on the counterparty")
    print("(on 2026-09-25 one was: agreement-v0/second_record_A.json, id 121ce3d2, commit d5ad6e9b). Two records for one subject confuse the signer.")
    print("As of 2026-09-28 that record came back both-signed (second_record_AB.json) but was never filed, and it has no")
    print("publication field, so the ledger refuses it. Re-sign it with ops/agreement_republish.py first; send this one only")
    print("if the counterparty asks for a separate record of the 2026-09-24 walks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
