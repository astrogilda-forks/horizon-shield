# Notes: MUSUBI companion for cA2A, profile v0

## Running it

    pip install ca2a-runtime==0.4.0     # brings rfc8785 and cryptography; Python 3.11 or later
    python companion_v0.py --selftest   # 57/57 vectors agree
    python gen_vectors.py               # rebuilds vectors/vectors.json byte for byte

The verifier imports `settle_v1_1.py` from the directory above for the Bitcoin header view and the anchor proof, unchanged.

One import is private: the at-execution verdict calls cA2A's `_check_revocation` directly, so that every revocation the log published before a receipt is in force whatever its `issued_at` (CA45). A private function can change without notice, so the profile is pinned to ca2a-runtime 0.4.0 until cA2A offers a public way to say "these statements are in force".

Checked against both cA2A sources on 2026-10-17: agentrust-io/ca2a at 305fedc (editable install) and the PyPI release ca2a-runtime 0.4.0. Both give 57/57.

## Why a companion and not a fork

cA2A's delegation rules are theirs to change. If this profile reimplemented them, every cA2A release could silently split the two. So `settle` only ever asks `ca2a_runtime.delegation.verify_chain` and reports its error code as is (`outside_delegation:SCOPE_ESCALATION` and so on). What this profile adds is ordering, publication, and signed statements that live outside one process.

## Decisions taken in v0

- **Two verdicts on revocation.** cA2A's audit mode goes by the revoker's `issued_at`. The log knows when the statement became public. Both are reported (`ca2a_at_execution`, `ca2a_audit`); a revocation that only the audit sees is `late_revocation_only`, not hidden either way.
- **A revocation dated after its logging is kept and flagged, never dropped, and in force from its log position.** Dropping it let the operator void a valid revocation by logging it a few seconds early (CA33); leaving it to cA2A's `at_time` filter let it lose to its own date (CA45). The at-execution verdict goes by log order; the audit verdict by `issued_at` is reported beside it.
- **Use items carry their whole chain and name their responder.** A use of a credential is a (request, responder) pair under any chain that contains it, so delegating onward, re-issuing an ancestor or fanning one request out to several responders does not reset a limit (CA32, CA43, CA44, CA35).
- **Limits come only from the hop's own issuer, only when logged before the receipt, tightest wins.** Revocation in cA2A is monotonic; a limit behaves the same way.
- **One use per distinct request.** Logging the same use twice is a retry, not a second use.
- **Denials are not executions** for deduplication.
- **Unknown lineage is unassessed.** No chain, no verdict.
- **The evidence functions verify the entries against the checkpoint first.** Otherwise whoever supplies the entries decides the verdict (EV06 to EV10).
- **A receipt names a block it has seen.** That is the only lower bound on time that the operator does not set.
- **The log is a hash chain in v0.** A verifier reads the whole log. Merkle proofs and witnesses are v1.

## Review record

2026-10-17, first round: an adversarial review of the first draft (36 vectors) reported 4 high, 3 medium and 4 low findings. All were fixed; each is a vector (CA32 to CA42, EV06 to EV10).

2026-10-17, second round: 2 high, 2 medium and 2 low. A single-use credential could still run once per responder, and a re-issued ancestor started a fresh count (now counted per credential, at any position, per request and responder: CA43, CA44). A revocation logged early lost to its own later issued_at (now in force by log order, cA2A's audit verdict beside it: CA45). A short checkpoint could hide a promised entry (now operator_withheld: EV11). Use ranks are computed once (1,000 uses and 1,000 receipts settle in about 3 s). Deep nesting is an input error (EV12).

vectors/vectors.json sha256: 4b4e2362ab6dda3743e5ba1cd76285a0872344f40086bc95b18b3bd34490d2a2 (57 vectors).
