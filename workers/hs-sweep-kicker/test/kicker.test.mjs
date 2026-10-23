// test/kicker.test.mjs: hs-sweep-kicker offline. The gate is a fake fetch that records every request; KV is a Map
// that can be told to fail. Nothing here reaches the network.
// Run: node test/kicker.test.mjs   (or node test/run_all.mjs)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import worker, { decide, summarizeSweep, lastMeasuredFromReason, runOnce, CRONS, MAX_KICKS_PER_DAY, USER_AGENT } from "../src/worker.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
let bad = 0, n = 0;
const chk = (name, ok, info = "") => { n++; if (!ok) bad++; console.log((ok ? "PASS  " : "FAIL  ") + name + (ok ? "" : "  " + info)); };

const TOKEN = "fake-token-for-tests-only";
// The gate's own sentences, copied from GET https://gate.horizonshield.dev/sweep/last on 2026-10-23.
const R_NOT_DUE = "not due today (derived: the day is HMAC-derived from a committed salt bound to a Bitcoin block, so the subject cannot predict it)";
const rOver = (last) => "over MAX_PER_SWEEP for this run (order is least recently measured first; this endpoint was last measured " + last + ", so it goes first next time)";
const R_BUDGET = "subrequest budget: 50 of 50 used before this row (the window's first sweep fetches the beacon from three sources and files the commitments; each measured row costs about 6). An overrun aborts a measurement half way, so this row was not measured and goes first next time (order is least recently measured first)";

const T = Date.parse("2026-10-23T19:17:00Z");
const TODAY = "2026-10-23";

function sweep({ at = "2026-10-23T18:00:52.468Z", ran = true, skipped = [] } = {}) {
  return { ran, at, watched_total: 42, measured: 7, results: [], skipped: skipped.map((r, i) => ({ endpoint: "https://e" + i + ".example/mcp", tier: "self", reason: r })) };
}

function kv({ failGet = false, failPut = false } = {}) {
  const m = new Map();
  const b = {
    m,
    puts: 0,
    failGet, failPut,
    get: async (k) => { if (b.failGet) throw new Error("kv down"); return m.has(k) ? m.get(k) : null; },
    put: async (k, v) => { if (b.failPut) throw new Error("kv down"); b.puts++; m.set(k, v); }
  };
  return b;
}

// Fake gate. sweepLast: object | {status, body} | "throw". post: {status, body} | "throw".
function gate({ sweepLast, post = { status: 200, body: sweep({ at: "2026-10-23T19:17:40.000Z" }) } }) {
  const calls = [];
  const f = async (req) => {
    const u = new URL(req.url);
    const headers = Object.fromEntries(req.headers.entries());
    const body = req.method === "POST" ? await req.text() : null;
    calls.push({ method: req.method, path: u.pathname, headers, body });
    const J = (o, s) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
    if (req.method === "GET" && u.pathname === "/sweep/last") {
      if (sweepLast === "throw") throw new Error("network");
      if (sweepLast && sweepLast.status) return J(sweepLast.body, sweepLast.status);
      return J(sweepLast, 200);
    }
    if (req.method === "POST" && u.pathname === "/sweep") {
      if (post === "throw") throw new Error("timeout");
      return J(post.body, post.status);
    }
    return J({ error: "not_found" }, 404);
  };
  return { f, calls };
}

function env(g, store, extra = {}) {
  return Object.assign({ KICK_LOG: store, SWEEP_TOKEN: TOKEN, __fetch: g.f }, extra);
}
const posts = (g) => g.calls.filter((c) => c.method === "POST");
const stored = (store, day = TODAY) => JSON.parse(store.m.get("log:" + day));

// ---------------------------------------------------------------- the pure decision table
const base = summarizeSweep(sweep({ skipped: [rOver("2026-10-20T18:01:02.522Z")] }), TODAY);
const D = (o) => decide(Object.assign({ readable: true, http: 200, summary: base, kicksToday: 0, tokenConfigured: true }, o));
chk("table: all conditions hold -> kick", D({}).decision === "kick");
chk("table: unreadable -> record_only", D({ readable: false, http: 0 }).decision === "record_only" && D({ readable: false }).reason === "sweep_last_unreadable");
chk("table: not today -> skip", D({ summary: summarizeSweep(sweep({ at: "2026-10-22T18:00:52.468Z", skipped: [rOver("2026-10-20T18:01:02.522Z")] }), TODAY) }).reason === "not_today");
chk("table: ran false -> skip", D({ summary: summarizeSweep(sweep({ ran: false, skipped: [rOver("2026-10-20T18:01:02.522Z")] }), TODAY) }).reason === "not_ran");
chk("table: only not-due skips -> skip", D({ summary: summarizeSweep(sweep({ skipped: [R_NOT_DUE, R_NOT_DUE] }), TODAY) }).reason === "no_capacity_skips");
chk("table: budget skip alone -> kick", D({ summary: summarizeSweep(sweep({ skipped: [R_BUDGET] }), TODAY) }).decision === "kick");
chk("table: over MAX rows all measured today -> skip", D({ summary: summarizeSweep(sweep({ skipped: [rOver("2026-10-23T18:00:40.000Z"), rOver("2026-10-23T19:17:41.000Z")] }), TODAY) }).reason === "all_capacity_skips_measured_today");
chk("table: over MAX row never measured -> kick", D({ summary: summarizeSweep(sweep({ skipped: [rOver("never")] }), TODAY) }).decision === "kick");
chk("table: kicks 2 of 3 -> kick", D({ kicksToday: MAX_KICKS_PER_DAY - 1 }).decision === "kick");
chk("table: kicks 3 of 3 -> skip", D({ kicksToday: MAX_KICKS_PER_DAY }).reason === "daily_cap_reached");
chk("table: no token -> record_only", D({ tokenConfigured: false }).reason === "token_not_configured" && D({ tokenConfigured: false }).decision === "record_only");
chk("parse: last measured from the gate's sentence", lastMeasuredFromReason(rOver("2026-10-20T18:01:02.522Z")) === "2026-10-20T18:01:02.522Z" && lastMeasuredFromReason(rOver("never")) === "never" && lastMeasuredFromReason(R_BUDGET) === null);
{
  const s = summarizeSweep(sweep({ skipped: [R_NOT_DUE, rOver("2026-10-20T18:01:02.522Z"), rOver("2026-10-23T18:00:01.000Z"), R_BUDGET] }), TODAY);
  chk("summary: counts", s.skipped_total === 4 && s.skipped_over_max === 2 && s.skipped_over_max_measured_today === 1 && s.skipped_budget === 1 && s.pending_not_measured_today === 2, JSON.stringify(s));
}
chk("constants: three crons, cap 3", CRONS.length === 3 && MAX_KICKS_PER_DAY === 3);
{
  const w = readFileSync(path.join(HERE, "..", "wrangler.jsonc"), "utf8").split("\n").filter((l) => !/^\s*\/\//.test(l)).join("\n");
  const cfg = JSON.parse(w);
  chk("wrangler.jsonc: crons match the code", JSON.stringify(cfg.triggers.crons) === JSON.stringify(CRONS), JSON.stringify(cfg.triggers.crons));
  chk("wrangler.jsonc: KV binding KICK_LOG, no secret in vars", cfg.kv_namespaces[0].binding === "KICK_LOG" && !("SWEEP_TOKEN" in (cfg.vars || {})));
}

// ---------------------------------------------------------------- runOnce against the fake gate
{
  const g = gate({ sweepLast: sweep({ skipped: [rOver("2026-10-20T18:01:02.522Z"), R_NOT_DUE] }) });
  const s = kv();
  const r = await runOnce(env(g, s), T, "17 19 * * *");
  const p = posts(g);
  chk("run: kick sends exactly one POST /sweep", r.decision === "kick" && p.length === 1, JSON.stringify(r));
  chk("run: POST carries x-sweep-token and body {}", p[0] && p[0].headers["x-sweep-token"] === TOKEN && p[0].body === "{}");
  const get = g.calls.find((c) => c.method === "GET");
  chk("run: GET /sweep/last carries no token", get && !("x-sweep-token" in get.headers) && !("authorization" in get.headers));
  chk("run: both calls name the kicker (User-Agent) and declare operator", g.calls.every((c) => c.headers["user-agent"] === USER_AGENT && c.headers["x-hs-requester"] === "operator"));
  const L = stored(s);
  chk("run: one entry stored under log:<today>", L.day === TODAY && L.entries.length === 1 && L.entries[0].post.http === 200 && L.entries[0].cron === "17 19 * * *");
  chk("run: stored log never holds the token", !s.m.get("log:" + TODAY).includes(TOKEN));
}
for (const st of [403, 409, 503]) {
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }), post: { status: st, body: st === 409 ? { ran: false, error: "sweep_in_progress", holder: "cron" } : { error: st === 403 ? "forbidden" : "sweep_token_not_configured" } } });
  const s = kv();
  const r = await runOnce(env(g, s), T, "41 19 * * *");
  const L = stored(s);
  chk("run: POST " + st + " recorded, not retried", posts(g).length === 1 && r.post.http === st && r.post.retried === false && L.entries[0].post.http === st, JSON.stringify(r.post));
}
{
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }), post: "throw" });
  const s = kv();
  const r = await runOnce(env(g, s), T, "41 19 * * *");
  chk("run: POST that throws recorded as http 0, not retried", posts(g).length === 1 && r.post.http === 0 && /fetch_failed/.test(r.post.error) && stored(s).entries.length === 1);
}
{
  const g = gate({ sweepLast: "throw" });
  const s = kv();
  const r = await runOnce(env(g, s), T, "17 19 * * *");
  chk("run: unreadable /sweep/last (network) -> record only, one GET, no POST", r.decision === "record_only" && g.calls.length === 1 && posts(g).length === 0 && stored(s).entries[0].reason === "sweep_last_unreadable");
}
{
  const g = gate({ sweepLast: { status: 503, body: { ran: null, error: "sweep_last_read_failed", read_failed: true } } });
  const s = kv();
  const r = await runOnce(env(g, s), T, "17 19 * * *");
  chk("run: /sweep/last 503 -> record only, no POST", r.decision === "record_only" && posts(g).length === 0 && stored(s).entries[0].sweep_last.http === 503);
}
{
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }) });
  const s = kv();
  const e = env(g, s); delete e.SWEEP_TOKEN;
  const r = await runOnce(e, T, "17 19 * * *");
  chk("run: no token -> record only, no POST", r.reason === "token_not_configured" && posts(g).length === 0 && stored(s).entries.length === 1);
}
{
  // Three crons and a stray fourth run on one day, the gate leaving rows over MAX every time: 3 calls, then no more.
  const g = gate({ sweepLast: sweep({ skipped: [rOver("2026-10-20T18:01:02.522Z")] }) });
  const s = kv();
  for (const c of [...CRONS, "manual"]) await runOnce(env(g, s), T, c);
  const L = stored(s);
  chk("run: cap of 3 POSTs a UTC day", posts(g).length === 3 && L.entries.length === 4 && L.entries[3].reason === "daily_cap_reached", posts(g).length + " posts");
  // The next UTC day starts again from 0.
  await runOnce(env(gate({ sweepLast: sweep({ at: "2026-10-24T18:00:10.000Z", skipped: [rOver("never")] }) }), s), Date.parse("2026-10-24T19:17:00Z"), CRONS[0]);
  chk("run: a new UTC day has its own key and count", stored(s, "2026-10-24").entries[0].decision === "kick");
}
{
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }) });
  const s = kv({ failGet: true });
  const r = await runOnce(env(g, s), T, "17 19 * * *");
  chk("run: own log unreadable -> no GET, no POST, nothing written", r.reason === "kicker_log_unreadable" && g.calls.length === 0 && s.puts === 0);
}
{
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }) });
  const s = kv();
  let n2 = 0;
  const e = env(g, s, { GATE_VIA: "binding", GATE: { fetch: async (req) => { n2++; return g.f(req); } } });
  await runOnce(e, T, "17 19 * * *");
  chk("run: GATE_VIA binding goes over the service binding", n2 === 2);
}

// ---------------------------------------------------------------- the HTTP face never shows the token
{
  const evil = { status: 500, body: { error: "echo " + TOKEN } };   // a gate that (wrongly) echoed the token
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }), post: evil });
  const s = kv();
  await runOnce(env(g, s), T, "17 19 * * *");
  const e = env(g, s);
  const res = await worker.fetch(new Request("https://k.example/log?day=" + TODAY), e);
  const txt = await res.text();
  chk("log: 200 with the day's entries", res.status === 200 && JSON.parse(txt).entries.length === 1);
  chk("log: token never served, even if the gate echoed it", !txt.includes(TOKEN) && txt.includes("[redacted]"));
  chk("log: no request header names in the log", !/x-sweep-token|user-agent|authorization/i.test(txt));
  const h = await (await worker.fetch(new Request("https://k.example/health"), e)).text();
  chk("health: describes, no token", JSON.parse(h).name === "hs-sweep-kicker" && JSON.parse(h).token_configured === true && !h.includes(TOKEN));
  const root = await worker.fetch(new Request("https://k.example/"), e);
  chk("root: same description", root.status === 200 && JSON.parse(await root.text()).crons_utc.length === 3);
  chk("log: bad day -> 400", (await worker.fetch(new Request("https://k.example/log?day=2026-1-1"), e)).status === 400);
  const empty = await worker.fetch(new Request("https://k.example/log?day=2026-01-01"), e);
  chk("log: day without entries -> 200, empty", empty.status === 200 && JSON.parse(await empty.text()).entries.length === 0);
  const broken = await worker.fetch(new Request("https://k.example/log?day=" + TODAY), env(g, kv({ failGet: true })));
  chk("log: unreadable -> 503, not empty", broken.status === 503 && JSON.parse(await broken.text()).error === "log_read_failed");
  chk("http: POST refused", (await worker.fetch(new Request("https://k.example/log", { method: "POST", body: "{}" }), e)).status === 405);
  const pr = await worker.fetch(new Request("https://k.example/probe"), env(gate({ sweepLast: sweep({ skipped: [rOver("never")] }) }), kv()));
  const pj = JSON.parse(await pr.text());
  chk("probe: reads /sweep/last, writes nothing", pj.probe === true && pj.readable === true && pj.sweep_last.skipped_over_max === 1);
}
{
  // scheduled() goes through waitUntil.
  const g = gate({ sweepLast: sweep({ skipped: [rOver("never")] }) });
  const s = kv();
  const waits = [];
  await worker.scheduled({ scheduledTime: T, cron: "13 20 * * *" }, env(g, s), { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  chk("scheduled: runs once through waitUntil", posts(g).length === 1 && stored(s).entries[0].cron === "13 20 * * *");
}

console.log("\n" + (n - bad) + "/" + n + " passed");
if (bad) process.exit(1);
