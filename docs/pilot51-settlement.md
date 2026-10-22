# Three paid agent calls, a budget of 20,000, and a settlement anyone can recompute

[日本語](pilot51-settlement.ja.md)

On 22 October 2026, between 00:00 and 03:00 UTC, an AI agent made three paid calls to another agent, and the record
of what happened was settled so that anyone can check it without trusting us. This is what happened, what was
checked by people outside our company, and what this does not show.

## What happened

The buyer had a budget of 20,000 JPY-testnet. Each call was priced at 7,000. Calls A and B were paid and executed; the
running total reached 14,000. Call C was paid and executed too, and the total became 21,000.

Every step went into a signed log: the budget, the acceptance criteria for each call, and for each call its use, its
payment and the responder's receipt. That is 13 entries. The log's checkpoint was stamped with OpenTimestamps and is
anchored in Bitcoin block 972551.

The settlement reads the log against the signed budget and the delegation. For call C it reports:

- the execution: `within_delegation`. The responder was allowed to do what it did.
- the payment: `budget_exceeded`. The third payment took the total past the budget.

Calls A and B carry no reasons. The full record, the bundle and the settlement are public in
[`pilot51/set2/`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/pilot51/set2),
and the run is discussed in [Issue #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51).

In the same window, aeoess ran the same three calls through its own system (Agent Passport System), with a budget of
15,000. There, call C was refused before anything was sent
([#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6329364718)). The two rows show two
designs for one situation: one refuses before the call, the other records after it.

## What people outside our company checked

- **The settlement, recomputed.** Poke-nushi recomputed the settlement from the published files on their own machine
  and got the same output hash. They also checked the signatures and the OpenTimestamps proof, and rebuilt the Bitcoin
  header view from Blockstream and mempool.space headers up to block 972564. The verdicts did not change; only the
  anchor's depth moved, from 9 to 14
  ([#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6332669484)).
- **The audit bytes.** aeoess reported that the audit files for calls A and B on their side are byte for byte the same
  as ours ([#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6330218168)).
- **The rules themselves.** The settlement rules are written as a specification,
  [draft-oga-musubi-settlement](https://datatracker.ietf.org/doc/draft-oga-musubi-settlement/), with 128 test vectors.
  Two implementations written by other authors agree with ours on all 128:
  [aeoess/musubi-settle-core-check](https://github.com/aeoess/musubi-settle-core-check) and
  [kuangmi-bit/nenrin-independent-verifiers](https://github.com/kuangmi-bit/nenrin-independent-verifiers/tree/bbe455c/settle-core-v0).
  The rows, with their commits, are in [docs/INTEROP_TABLE.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/docs/INTEROP_TABLE.md).

## Check it yourself

    pipx run --spec 'nenrin-verify[ca2a]==0.7.0' musubi-verify --pilot51-set2
    pipx run --spec 'nenrin-verify[ca2a]==0.7.0' musubi-verify --settle-core

The first recomputes this run's settlement and compares it with the published hash (`18a19f8a...`). The second runs
the specification's 128 vectors (about 30 seconds). Python 3.11 or later. The five-minute version is
[QUICKSTART.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/QUICKSTART.md).

## What this does not show

- **It was not real money.** The unit is JPY-testnet and the payment rail is a signed test transfer. No funds moved.
- **The overspend was not prevented.** The settlement recorded it after the fact. Preventing it is a different job,
  which aeoess's row did in the same run.
- **Every party to the calls was us.** The buyer, the responder and the log operator were all our company. The outside
  parties were witnesses and readers, not parties to the payment.
- **The outside recomputation used our tool.** Poke-nushi ran our companion settler on our published bundle. That is
  an independent run, not an independent implementation of the companion. The two implementations by other authors
  above cover the settle core rules, not the companion, and neither was written from the text alone: one also read our
  notes, and the other had the expected outputs.
- **There has been no external audit.** An internal adversarial review found defects, which are listed and fixed in
  public. That is not a third-party audit.
- **A signature shows who said something, not that it is true.** A recomputed settlement shows that the published
  bytes give the published answer under the published rules.

## Try to break it

We would rather hear that this is wrong than that it is right. [Issue #55](https://github.com/ogasurfproject-jpg/horizon-shield/issues/55)
has a "Break MUSUBI" lane: a bundle that settles as within the grant while its signed terms say otherwise, two readers
that follow the text and disagree on the same bytes, or a check that passes after a covered byte changes. Bring the
bytes and we will rerun them in public. A finding against a live service goes through
[SECURITY.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/SECURITY.md).
