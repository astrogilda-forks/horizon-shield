# Endpoint status

Written by `tools/status/probe.mjs` at 2026-10-21T05:00:21.636Z. Machine readable: [status.json](status.json) (status_sha256 `059a8a46aaddd22e0f5c5b46b63911070027bb17dc9be752910169ea08a6164c`). Raw rows of the last 30 days: [history.jsonl](history.jsonl).

| Endpoint | Last run | Reach 24 h | Reach 7 d | Call success 7 d | Call P50 7 d | Call P95 7 d | Server version | Tools |
|---|---|---|---|---|---|---|---|---|
| [hs-mcp](https://mcp.horizonshield.dev/mcp)<br>`get_price_range` | ok at 2026-10-21T05:00:21.636Z | 100% (6/6) | 100% (40/40) | 100% (40/40) | 553 ms | 839 ms | 1.1.0 | 15 |
| [ccdb](https://ccdb.horizonshield.dev/mcp)<br>`search_jccdb_items` | ok at 2026-10-21T05:00:21.636Z | 100% (6/6) | 100% (40/40) | 100% (40/40) | 2368 ms | 8769 ms | 1.0.0 | 15 |
| [gate](https://gate.horizonshield.dev/mcp)<br>`get_conditions` | ok at 2026-10-21T05:00:21.636Z | 100% (6/6) | 100% (40/40) | 100% (40/40) | 44 ms | 82 ms | 0.4.20 | 6 |
| [jidec](https://jidec.horizonshield.dev/mcp)<br>`nenrin_ledger_head` | ok at 2026-10-21T05:00:21.636Z | 100% (6/6) | 100% (40/40) | 100% (40/40) | 1233 ms | 1639 ms | 1.3.0 | 9 |
| [yakumo-contractors](https://hearing.horizonshield.dev/mcp)<br>`mall_overview` | ok at 2026-10-21T05:00:21.636Z | 100% (6/6) | 100% (40/40) | 100% (40/40) | 765 ms | 1078 ms | 2.3.2-rmw-20261013 | 6 |
| [ledger](https://ledger.horizonshield.dev/health)<br>GET | ok at 2026-10-21T05:00:21.636Z | 100% (6/6) | 100% (40/40) | 100% (40/40) | 157 ms | 233 ms | n/a | n/a |

## How it is measured

- Once an hour a GitHub Actions hosted runner probes each endpoint in turn, with a 20 second timeout per request.
- MCP endpoints: `initialize` (protocol 2025-06-18, accepting JSON or an SSE framed answer, keeping any `mcp-session-id`), `tools/list`, then one read only `tools/call` named in `tools/status/endpoints.json`. HTTP endpoints: one GET of a documented JSON path.
- Reach: the first step answered correctly (`initialize` returned a result, or the GET returned the expected JSON). Call success: the `tools/call` returned a result without `isError` (for HTTP, the GET). Runs where the endpoint was not reached count as failed calls.
- Latency is the time until the whole answer was read. P50 and P95 are nearest rank over the last 7 days; a timeout counts as 20000 ms; connection errors have no latency.
- Server version and tool count are what the endpoint itself reported in its last successful `initialize` and `tools/list`.

## What it does not establish

- One vantage point: one runner region per run, chosen by GitHub and not disclosed (usually the United States). Users in Japan or elsewhere may see very different times.
- One sample per endpoint per hour. A short outage between samples is not seen; one slow sample moves a 24 hour figure a lot.
- It is not a measure of user experience, of correctness of the answers, or of any tool other than the one called.
- Scheduled GitHub runs can start late or be skipped under load; a missing hour is a gap in the data, not an outage.
- The probe's own calls are counted by the servers' usage counters where those exist.
