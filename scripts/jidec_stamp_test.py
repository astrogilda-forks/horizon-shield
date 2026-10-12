#!/usr/bin/env python3
"""jidec_stamp_test: the block an entry records is the earliest Bitcoin attestation in the proof (2026-10-12, entry 86)."""
import os, sys
os.environ.setdefault("LEDGER_URL", "https://ledger.invalid")
os.environ.setdefault("LEDGER_ADMIN_TOKEN", "test")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jidec_stamp as J  # noqa: E402

INFO_86 = """File sha256 hash: 2cf03de3edea266bddbc39fdd0a3e046f2d181cb8828a82d4b691ac8495744ba
Timestamp:
append 1a2b
sha256
 -> append 3c4d
    sha256
    verify BitcoinBlockHeaderAttestation(971047)
 -> append 5e6f
    sha256
    verify BitcoinBlockHeaderAttestation(971024)
 -> verify PendingAttestation('https://finney.calendar.eternitywall.com')
"""
checks = [
    ("two attestations, later printed first: the earliest (971024) is recorded", J.earliest_bitcoin_height(INFO_86) == 971024),
    ("one attestation: that one", J.earliest_bitcoin_height("verify BitcoinBlockHeaderAttestation(970852)") == 970852),
    ("pending only: None, so the entry stays pending", J.earliest_bitcoin_height("verify PendingAttestation('https://a.pool.opentimestamps.org')") is None),
    ("empty or missing output: None", J.earliest_bitcoin_height("") is None and J.earliest_bitcoin_height(None) is None),
]
bad = [n for n, ok in checks if not ok]
for n, ok in checks:
    print(("ok    " if ok else "FAIL  ") + n)
print("\n%d/%d passed" % (len(checks) - len(bad), len(checks)))
sys.exit(1 if bad else 0)
