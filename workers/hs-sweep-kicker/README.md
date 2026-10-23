# hs-sweep-kicker

A small Worker that asks the verify gate (`workers/hs-verify-gate`, https://gate.horizonshield.dev) for one more
sweep on a day when the gate's own daily sweep could not measure every row that was due. It does not change the
gate. It is a stopgap until the gate covers its whole due list by itself (gate 0.4.21, "stage 2").

## Why it exists

The gate re-measures its watched endpoints from one cron a day (`0 18 * * *` UTC). One sweep measures at most
`MAX_PER_SWEEP = 8` rows, and stops earlier when the 50 subrequests a Workers Free invocation allows run out. The
rows left over are written to `/sweep/last` as `skipped`, with a reason that starts with `over MAX_PER_SWEEP` or
`subrequest budget`. On 2026-10-22 the sweep had 18 rows due and measured 7: all 9 self rows were skipped
`over MAX_PER_SWEEP`, as were one free row (`over MAX_PER_SWEEP`) and another (`subrequest budget`).
`tools/gate_coverage/coverage.mjs --day 2026-10-22` lists the 11.

## What it does

Three crons, UTC (JST in brackets):

| cron | UTC | JST |
|---|---|---|
| `17 19 * * *` | 19:17 | 04:17 |
| `41 19 * * *` | 19:41 | 04:41 |
| `13 20 * * *` | 20:13 | 05:13 |

On each one it reads `GET /sweep/last` from the gate and calls the gate's own `POST /sweep` (body `{}`, header
`x-sweep-token`, the gate's operator sweep) only when all of these hold:

| # | condition | when it does not hold |
|---|---|---|
| 0 | this Worker's own log for today can be read (to know how many calls it has made) | no GET, no POST, nothing written (a failed read is not an empty day) |
| 1 | `/sweep/last` was read: HTTP 200 and JSON | `record_only` / `sweep_last_unreadable`, not retried |
| 2 | the last sweep is from today (UTC day of `at`) | `skip` / `not_today` |
| 3 | it says `ran: true` | `skip` / `not_ran` |
| 4 | a skipped row's reason starts with `over MAX_PER_SWEEP` or `subrequest budget` (the gate's exact words) | `skip` / `no_capacity_skips` |
| 5 | at least one of those rows was not measured today: an `over MAX_PER_SWEEP` row whose reason says `last measured <time>` with a time before today, or `never`; every `subrequest budget` row (its reason does not say when) | `skip` / `all_capacity_skips_measured_today` |
| 6 | this Worker has called `POST /sweep` fewer than 3 times this UTC day | `skip` / `daily_cap_reached` |
| 7 | the secret `SWEEP_TOKEN` is set on this Worker | `record_only` / `token_not_configured` |
| | all hold | `kick`: one `POST /sweep`, never retried |

The result of the POST is written down and nothing else happens: 200 (the gate ran the sweep), 403 (the token does
not match the gate's `SWEEP_TOKEN`), 409 (another sweep held the gate's lease), 503 (the gate has no `SWEEP_TOKEN`,
or its sweep lease was unavailable), or 0 (no answer: network error or timeout). Any call that was attempted counts
toward the 3 a day, whatever came back.

Condition 5 is stricter than "a skipped row says over MAX_PER_SWEEP": the gate sorts its due rows by when they were
last measured, so after one kick the rows it just measured sit at the end of the list and are skipped
`over MAX_PER_SWEEP` again with today's time. Without condition 5 every day would use all 3 calls.

## The log

Every decision and result is written to the KV namespace `KICK_LOG`, one key per UTC day (`log:YYYY-MM-DD`, kept
400 days), as `{ schema: "hs-sweep-kicker-log-v1", day, entries: [...] }`. Each entry has `at`, `scheduled_at`,
`cron`, `sweep_last` (counts only: `ran`, `at`, `is_today`, `watched_total`, `measured`, `skipped_total`,
`skipped_over_max`, `skipped_over_max_measured_today`, `skipped_budget`, `pending_not_measured_today`), `kicks_before`,
`decision`, `reason`, `why`, and `post` (`http`, `ran`, `at`, `measured`, `error`, the same skipped counts of the
sweep it caused, `meaning`, `retried: false`) or `null`.

- `GET /log?day=YYYY-MM-DD`: that day's log. 200 with `entries: []` for a day with none; 503 `log_read_failed` when it
  could not be read (not "nothing happened").
- `GET /` or `GET /health`: what this Worker is, its crons, whether the token and the KV are configured (true/false).
- `GET /probe`: reads `/sweep/last` once and says whether it was readable. No POST, nothing stored. For checking the
  path to the gate right after a deploy.

The token, request headers and response headers are never written and never served. Endpoint URLs are not copied
into the log either; the gate publishes them in `/sweep/last` and `/history`.

## How it reaches the gate, and /usage

`vars.GATE_VIA` is `"url"`: requests go to the public `https://gate.horizonshield.dev`, so the sweep the gate runs for
`POST /sweep` is a request of its own with its own subrequest allowance (the gate counts its budget as 50 from zero).
`"binding"` sends them over the service binding `GATE` instead, the way hs-ledger reads the gate's records. Whether a
service binding call shares the caller's subrequest allowance on Workers Free was not measured; keep `"url"` unless
`GET /probe` cannot read the gate.

Every request carries `User-Agent: hs-sweep-kicker/<version> (+https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/workers/hs-sweep-kicker)`
and `x-hs-requester: operator`. The gate does not count `GET /sweep/last` or `POST /sweep` in `/usage` at all (it
counts only `POST /check`, `POST /a2a`, MCP `tools/call`, `/spec` and the testbed). The sweep a kick causes does what
the 18:00 cron does: when it measures the gate's own `/mcp` (a self row with tool-call consent), those `tools/call`
requests arrive through the relay and are counted under `requesters` like the cron's are.

## What it does not fix

- **It re-measures when fewer than 8 rows are left.** The gate does not yet drop rows already measured today from
  its due list. A kicked sweep takes the 8 least recently measured due rows; when fewer than 8 are still unmeasured,
  the rest of its 8 seats go to rows already measured earlier that day, so those get a second record that day.
- **It adds requests to the gate.** Up to 3 sweeps a day more than the gate's own one, each up to about 50 outbound
  requests from the gate to the measured endpoints, plus 1 to 2 requests from this Worker per cron.
- **A kicked sweep probes the gate's own zone through the relay.** `POST /sweep` runs in the gate's HTTP context, where
  the gate reaches every endpoint of its own zone (the self rows) through `RELAY_URL` instead of directly, as the
  operator's manual `POST /sweep` always has (the cron goes direct to every row but the gate itself). The records
  say so in `probed_via`. If the relay is down, those self rows are not measured by the kick.
- **Free rows skipped on their day still wait a week.** A free row is due on one day of the 7-day window. If no kick
  reaches it that day (the 3 calls are used, or the gate answered 409 or 503), it is next due in the next window.
- It depends on the gate's own sentences (`over MAX_PER_SWEEP`, `subrequest budget`, `last measured <time>, so it
  goes first`). If the gate rewords them, condition 4 stops holding and the kicker stops calling; it does not call
  more.

When gate 0.4.21 measures every due row itself, this Worker should be removed (delete the Worker, then this folder).

## Setup (owner only)

The KV namespace, the secret and the deploy are done by the owner, never by CI:

```
cd workers/hs-sweep-kicker
npx wrangler kv namespace create KICK_LOG      # its id goes into wrangler.jsonc in place of the 32 zeros, before the commit
npx wrangler secret put SWEEP_TOKEN            # paste the gate's SWEEP_TOKEN; it is never written to a file
npx wrangler deploy
curl -s https://hs-sweep-kicker.oga-surf-project.workers.dev/health
curl -s https://hs-sweep-kicker.oga-surf-project.workers.dev/probe
```

## Tests

```
node test/run_all.mjs
```

Offline: the gate is a fake `fetch` that records every request, KV is a `Map` that can be made to fail. They cover
each row of the table above, the cap of 3, 403/409/503/no answer recorded without a retry, an unreadable
`/sweep/last` or own log, and that `/log` and `/health` never show the token.
