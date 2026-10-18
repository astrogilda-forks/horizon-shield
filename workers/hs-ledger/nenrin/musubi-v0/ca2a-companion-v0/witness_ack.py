#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A witness for the MUSUBI companion, profile v0.1: sign that you received and published a restriction.

A witness is anyone a relying party chooses to trust, other than the log operator. Its whole job:

  1. receive a restriction (a cA2A revocation statement or a musubi.ca2a.use-policy.v0) from its author;
  2. publish it where relying parties can read it (a static file, a git repository, anything public);
  3. sign an acknowledgement naming the log, the item's digest and a recent Bitcoin block it has seen.

Anyone can then anchor the acknowledgement in Bitcoin (for example with OpenTimestamps), and a verifier
counts it: the signature and the seen block give the lower bound on when the restriction was public, the
anchor the upper bound. The operator is not involved. See COMPANION_v0_1.md sections 3 and 4.

This file needs only `cryptography` (pip install cryptography) and `rfc8785`; it does not import cA2A.

  python3 witness_ack.py keygen witness.key                 # writes a 32-byte seed, prints the public key
  python3 witness_ack.py digest item.json                   # the item_sha256 an acknowledgement names
  python3 witness_ack.py sign witness.key item.json --log-id nenrin:ca2a-companion:main \\
          --seen-height 920000 --seen-hash <64 hex>          # prints the acknowledgement as canonical JSON
  python3 witness_ack.py check ack.json item.json           # verifies the signature and the item digest

The seen block is a block the witness has itself observed; its height and hash come from any Bitcoin node
or explorer the witness trusts. Naming a block is the only thing that bounds the acknowledgement in time
from below, so a witness names the newest block it has seen, never an old one.
"""
import argparse, hashlib, json, os, re, secrets, sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

T_ACK = "musubi.ca2a.witness-ack.v0"
HEX32 = re.compile(r"[0-9a-f]{64}")
TEXT = re.compile(r"[\x21-\x7e]{1,128}")


def jcs(obj):
    return rfc8785.dumps(obj)


def load(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def item_sha256(item):
    return hashlib.sha256(jcs(item)).hexdigest()


def keygen(path):
    seed = secrets.token_bytes(32)
    with open(path, "wb") as f:
        f.write(seed.hex().encode("ascii") + b"\n")
    os.chmod(path, 0o600)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    print(pub)


def sign(key_path, item_path, log_id, seen_height, seen_hash):
    if not TEXT.fullmatch(log_id):
        sys.exit("log-id must be 1 to 128 printable ASCII characters without spaces")
    if not HEX32.fullmatch(seen_hash):
        sys.exit("seen-hash must be 64 lowercase hex characters")
    if seen_height < 0:
        sys.exit("seen-height must be a non-negative integer")
    with open(key_path, "rb") as f:
        seed = bytes.fromhex(f.read().decode("ascii").strip())
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    item = load(item_path)
    if not (isinstance(item, dict) and isinstance(item.get("type"), str)):
        sys.exit("the item must be a JSON object with a type")
    body = {"type": T_ACK, "log_id": log_id, "witness": priv.public_key().public_bytes_raw().hex(),
            "item_sha256": item_sha256(item), "seen_block": {"height": seen_height, "hash": seen_hash}}
    body["signature"] = priv.sign(jcs(body)).hex()
    sys.stdout.write(jcs(body).decode("utf-8") + "\n")


def check(ack_path, item_path):
    ack, item = load(ack_path), load(item_path)
    need = {"type", "log_id", "witness", "item_sha256", "seen_block", "signature"}
    if not isinstance(ack, dict) or set(ack) - (need | {"anchor"}) or need - set(ack):
        sys.exit("ack: wrong fields")
    if ack["type"] != T_ACK:
        sys.exit("ack: wrong type")
    if ack["item_sha256"] != item_sha256(item):
        sys.exit("ack: names another item (item_sha256 %s, this item %s)" % (ack["item_sha256"], item_sha256(item)))
    body = {k: v for k, v in ack.items() if k not in ("signature", "anchor")}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(ack["witness"])).verify(bytes.fromhex(ack["signature"]), jcs(body))
    except (InvalidSignature, ValueError):
        sys.exit("ack: signature does not verify")
    print("ok: witness %s acknowledged item %s after block %d%s" % (
        ack["witness"], ack["item_sha256"], ack["seen_block"]["height"],
        ", anchored at %d" % ack["anchor"]["height"] if isinstance(ack.get("anchor"), dict) else ", not anchored"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("key_path")
    d = sub.add_parser("digest"); d.add_argument("item_path")
    s = sub.add_parser("sign"); s.add_argument("key_path"); s.add_argument("item_path")
    s.add_argument("--log-id", required=True); s.add_argument("--seen-height", type=int, required=True)
    s.add_argument("--seen-hash", required=True)
    c = sub.add_parser("check"); c.add_argument("ack_path"); c.add_argument("item_path")
    a = ap.parse_args()
    if a.cmd == "keygen":
        keygen(a.key_path)
    elif a.cmd == "digest":
        print(item_sha256(load(a.item_path)))
    elif a.cmd == "sign":
        sign(a.key_path, a.item_path, a.log_id, a.seen_height, a.seen_hash)
    else:
        check(a.ack_path, a.item_path)


if __name__ == "__main__":
    main()
