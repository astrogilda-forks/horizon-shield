# Security policy

This file covers this repository and what is built from it. The full policy, in English and Japanese, is
https://shield.the-horizons-innovation.com/security/ , and the machine readable contact is
https://shield.the-horizons-innovation.com/.well-known/security.txt (RFC 9116, expires 2027-10-03).

## How to report a vulnerability privately

Please do not open a public issue for a vulnerability.

1. GitHub private vulnerability reporting: on this repository, open the **Security** tab and choose
   **Report a vulnerability**. The report is visible only to you and the maintainers until it is published.
2. Email: contact@the-horizons-innovation.com , with a subject starting with `[security]`. English or Japanese.
   This is the Contact in security.txt.

If the Report a vulnerability button is not shown, use email.

Include what you did, the exact file, commit, package version, URL or endpoint, what you saw, and where you
measured it from. A report that contradicts our own measurement is the most useful kind.

## Scope

- The code in this repository.
- The npm package `nenrin-verify` and the PyPI package `nenrin-verify`, built from
  `workers/hs-ledger/nenrin/sdk` and `workers/hs-ledger/nenrin/sdk-python`, and the Go module in
  `workers/hs-ledger/nenrin/sdk-go`.
- The public endpoints listed in README.md:
  - https://shield.the-horizons-innovation.com
  - https://mcp.horizonshield.dev
  - https://ccdb.horizonshield.dev/mcp
  - https://gate.horizonshield.dev
  - https://ledger.horizonshield.dev
  - https://jidec.horizonshield.dev/mcp
  - https://agreement.horizonshield.dev

Examples of what we treat as a security problem: a signature or hash that verifies when it should not (or fails
when it should verify), a verdict or record that is wrong, a break in the ledger chain or its anchoring, a way to
make the gate record something the measured server did not do, and any personal data or secret on a public
surface.

What we protect, who we assume attacks it, what stops each attack today and where nothing does: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Out of scope: denial of service and load testing, social engineering, physical attacks, findings that need a
compromised device of the reporter, and scanner output without a demonstrated impact.

## What to expect

- The policy page states an aim to acknowledge a report within 3 business days and to say what will be done.
- Fixes to code in this repository are made here, and the fix commit is named in the record. Some services in scope
  (for example mcp.horizonshield.dev) run code that is not in this repository; for those, the record says what
  changed and when. Findings that changed a
  verdict or a record are published.
- Reporters are credited by name unless they ask not to be.
- There is no bug bounty.

The safe harbor terms for good faith research are on the policy page.

## Signing keys

The public keys used to sign records, with their dates and status, are listed at
https://gate.horizonshield.dev/.well-known/key-history.json . A signature that verifies against a key not in that
list is worth reporting.
