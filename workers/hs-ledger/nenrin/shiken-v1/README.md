# SHIKEN v1: an agent that asks a door before every act

SHIKEN is the work agent of TOshi, the representative of The HORIZONs Co., Ltd. It runs on TOshi's own Mac. In v1,
SHIKEN passes every layer of this repository: a MUSUBI contract that TOshi signs, a SEKI door that signs a decision
before each act, execution records that name those decisions, and a daily settlement.

The principal (TOshi), the contractor (SHIKEN) and the relying party (SHIKEN's door) are all The HORIZONs Co., Ltd.
and its representative. This is not an arm's-length agreement. What it shows is narrower and checkable: the records
below verify, they link into one chain, and they recompute.

## Files

| file | what it is |
|---|---|
| `contract_phase1.json` | the a2a-contract-v0 in force for phase 1 (read only). TOshi and SHIKEN signed it |
| `../../../../keys/shiken-principal.json` | TOshi's key: signs the contract, the approvals (approver `toshi`) and revocations |
| `../../../../keys/shiken-agent.json` | SHIKEN's key: signs a2a-action-request-v0 and a2a-execution-v0 |
| `../../../../keys/shiken-door.json` | the door's key: signs a2a-admission-v0 |

The keys are served at `https://shield.the-horizons-innovation.com/keys/`.

## The grant

Phase 1 authorizes reading mail, GitHub, CI, the IETF archive and this ledger, and closing a day. Phase 2 adds drafts,
and sending mail or posting to an IETF list with TOshi's approval. Phase 3 adds work files, and GitHub comments and
public issues with TOshi's approval. Every phase prohibits `git_push`, `wrangler_deploy`, secret operations,
passwords, account creation, payments, deletion and delegation. An act that no list names is refused.

The door holds the only tool credentials. No credential that can push, deploy or touch a secret exists on the door.

## The records and how to check them

Each admission is published to `https://ledger.horizonshield.dev/admission/<sha256>`, and each execution record to the
agreement intake. They carry action kinds and commitments only. Mail bodies, subjects and recipients are never in
them.

1. **Signature.** `python3 ../musubi-v0/admission_verify_v0.py --verify adm.json --key <key from shiken-door.json> --contract contract_phase1.json`
   must say `accepted`.
2. **Chain.** `admission_id` is `shiken-door-v1:seq=<n>:prev=<admission_sha256 of record n-1>`, inside the signed
   bytes. Record 1 has `prev` of 64 zeros. A missing or reordered record breaks the numbering or the link.
3. **Target.** An action's `target` is `sha256:` + sha256 of `shiken-target-v1\n`, a 16 byte salt and the
   musubi-canonical-v0 bytes of what the door does. The salt and the detail stay on TOshi's Mac.
4. **Approval.** A conditional act counts only with an a2a-approval-v2 by the pinned approver `toshi` whose `nonce` is
   the first 32 hex of sha256 of `shiken-approval-v1\n` followed by the target. So one approval covers one draft, and
   `single_use` stops a second send.
5. **Day.** The door closes each day with a `close_day` act whose target commits to the list of that day's admission
   and execution hashes.

## What this does not establish

- That the door ran any particular code. The door and SHIKEN's own code are private, like the SEKI door
  (`tools/boundary/private_patterns.txt`). The records verify and the decisions recompute from the contract.
- What SHIKEN did without asking its door. Acts that need no credential leave no record here.
- That a mail or a comment said the right thing. Only that what was sent is what TOshi approved.
- That the parties are independent.
