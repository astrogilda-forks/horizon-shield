// tools/gate_coverage/coverage.mjs: did the verify gate measure, on one UTC day, every row it owed that day?
//
//   node tools/gate_coverage/coverage.mjs                      the latest UTC day whose sweeps are over (see DAY below)
//   node tools/gate_coverage/coverage.mjs --day 2026-10-22     one UTC day
//   options: --gate <origin>  --json <file>  --md <file>
//
// Reads only public GETs of the gate (no key): /watchlist, /sweep/last, /nenrin/window[/<id>], /history?endpoint=.
// None of these is counted in the gate's /usage (the gate counts only POST /check, POST /a2a, MCP tools/call,
// /spec and the testbed).
//
// What is owed on a day:
//   self and paid rows: every day (the gate's cadence is daily for both).
//   free rows: only on the row's day of the week-long NENRIN window. That day is HMAC-derived from a salt the gate
//   reveals only after the window closes, so for a day inside the current window it cannot be recomputed from
//   public data. In order of strength, the signals used are:
//     1. sweep_last   /sweep/last is from that day: every row the gate did not skip as "not due today" was due.
//                     Exact. At 23:30 UTC (the workflow) this is the signal for the day that just had its sweeps.
//     2. window_salt  the window has closed and its salt is public: recompute the row's day (derived rule), or
//                     sha256(endpoint) mod 7 (legacy rule). Exact, after the window closes.
//     3. legacy_rule  the window is pinned to the legacy rule: computable at any time. Exact.
//     4. row_history  the row's own records in that window carry coordinate_derivation.day_in_window, which is the
//                     row's derived day. Exact when present; absent for a row never measured in that window.
//     otherwise the row is listed as unknown (not missing) and the reason is written.
//   Rows the gate itself skipped that day as quarantined, owner declined, or absent from the register at the
//   time of the sweep are listed as excused, not missing (only known through signal 1, or owner_declined on
//   /watchlist).
//
// DAY: without --day, the latest UTC day whose sweeps are over: today (UTC) from 21:00 UTC on (the gate's cron is
// 18:00 UTC and hs-sweep-kicker's last chance is 20:13 UTC), the day before otherwise.
//
// Output: one line per missing, unknown and excused row, then "result_sha256 <hex>", the sha256 of the canonical JSON
// (keys sorted, no whitespace) of the result, which holds no time of the run, so two runs that saw the same gate
// give the same sha. Exit 0 = nothing missing, 1 = a row is missing, 2 = something could not be read (and nothing
// missing among what could), 3 = bad arguments.

import { createHash, createHmac } from "node:crypto";
import { writeFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const SCHEMA = "gate-coverage-v1";
export const DEFAULT_GATE = "https://gate.horizonshield.dev";
export const USER_AGENT = "hs-gate-coverage/0.1 (+https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/tools/gate_coverage)";
const DAY_MS = 86400000;
const WINDOW_DAYS = 7;            // nenrin_instant.js NENRIN_WINDOW_DAYS
const FREE_INTERVAL_DAYS = 7;     // worker.js FREE_INTERVAL_DAYS (legacy rule)
const TIMEOUT_MS = 20000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

export function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  return JSON.stringify(v);
}
export const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const hmacHex = (keyHex, msg) => createHmac("sha256", Buffer.from(keyHex, "hex")).update(msg).digest("hex");

export function defaultDay(nowMs) {
  const d = new Date(nowMs);
  return d.getUTCHours() >= 21 ? d.toISOString().slice(0, 10) : new Date(nowMs - DAY_MS).toISOString().slice(0, 10);
}
export function epochDay(day) { return Math.floor(Date.parse(day + "T00:00:00Z") / DAY_MS); }
export function windowIdOf(day) { return "w" + Math.floor(epochDay(day) / WINDOW_DAYS); }
export function dayInWindow(day) { const d = epochDay(day); return d - Math.floor(d / WINDOW_DAYS) * WINDOW_DAYS; }
// The gate's rules, restated (nenrin_instant.js dueOffset and seed, worker.js isDueToday legacy branch).
export function derivedDay(saltHex, blockHash, wid, endpoint) {
  const seed = hmacHex(saltHex, ["nenrin-instant-v1", "seed", wid, blockHash].join(" "));
  return parseInt(hmacHex(seed, ["nenrin-instant-v1", "day", endpoint, wid].join(" ")).slice(0, 8), 16) % WINDOW_DAYS;
}
export function legacyDue(endpoint, day) {
  const bucket = parseInt(sha256(endpoint).slice(0, 4), 16) % FREE_INTERVAL_DAYS;
  return epochDay(day) % FREE_INTERVAL_DAYS === bucket;
}

async function getJson(fetchImpl, url) {
  try {
    const r = await fetchImpl(url, { headers: { accept: "application/json", "user-agent": USER_AGENT }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    let body = null;
    try { body = await r.json(); } catch (_e) { body = null; }
    return { status: r.status, body };
  } catch (e) {
    return { status: 0, body: null, error: String((e && e.message) || e).slice(0, 120) };
  }
}

// How the gate's sweep record classifies one row on its day.
export function sweepClass(sl, endpoint) {
  if ((sl.results || []).some((r) => r && r.endpoint === endpoint)) return { due: true };
  const s = (sl.skipped || []).find((x) => x && x.endpoint === endpoint);
  if (!s) return { excused: "not on the register when that day's last sweep ran" };
  const r = String(s.reason || "");
  if (r.startsWith("not due today")) return { due: false };
  if (r.startsWith("quarantined")) return { excused: "quarantined by the operator (the gate's own skip reason)" };
  if (r.startsWith("owner declined")) return { excused: "owner declined measurement (the gate's own skip reason)" };
  if (r.startsWith("the register could not be read")) return { unknown: "the gate could not read its register in that sweep" };
  return { due: true };   // over MAX_PER_SWEEP, subrequest budget, or any other skip of a due row
}

export async function coverage({ gate = DEFAULT_GATE, day, fetchImpl = fetch, concurrency = 4 } = {}) {
  const unreadable = [];
  const wl = await getJson(fetchImpl, gate + "/watchlist");
  if (wl.status !== 200 || !wl.body || !Array.isArray(wl.body.watched)) {
    return finish({ gate, day, fatal: "watchlist unreadable (http " + wl.status + ")", rows: [], unreadable: [{ what: "/watchlist", http: wl.status }], source: {} });
  }
  const watched = wl.body.watched.filter((w) => w && typeof w.endpoint === "string");

  // Signal 1.
  const slr = await getJson(fetchImpl, gate + "/sweep/last");
  const sl = slr.status === 200 && slr.body && slr.body.ran === true && typeof slr.body.at === "string" ? slr.body : null;
  if (slr.status !== 200) unreadable.push({ what: "/sweep/last", http: slr.status });
  const slDay = sl ? sl.at.slice(0, 10) : null;
  const useSweep = !!(sl && slDay === day && !sl.registry_read_failed);

  // Signals 2 and 3.
  const wid = windowIdOf(day);
  let win = null;
  const wr = await getJson(fetchImpl, gate + "/nenrin/window/" + wid);
  if (wr.status === 200 && wr.body && wr.body.window_id === wid) win = wr.body;
  else if (wr.status !== 404) unreadable.push({ what: "/nenrin/window/" + wid, http: wr.status });
  const rule = win && win.rule ? win.rule.rule : null;
  let saltOk = false;
  if (win && win.status === "closed" && typeof win.salt === "string" && /^[0-9a-f]{64}$/.test(win.salt)) {
    saltOk = sha256("nenrin-instant-salt-v1:" + win.salt) === win.commitment;
  }
  const blockHash = win && win.beacon && win.beacon.block_hash ? win.beacon.block_hash : null;

  // Histories, a few at a time.
  const hist = new Map();
  let i = 0;
  async function lane() {
    while (i < watched.length) {
      const w = watched[i++];
      const h = await getJson(fetchImpl, gate + "/history?endpoint=" + encodeURIComponent(w.endpoint));
      hist.set(w.endpoint, h.status === 200 && h.body && Array.isArray(h.body.entries) ? h.body.entries : { http: h.status });
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, lane));

  const rows = [];
  for (const w of watched) {
    const tier = w.tier === "self" || w.tier === "paid" ? w.tier : "free";
    const row = { endpoint: w.endpoint, tier };
    const es = hist.get(w.endpoint);
    if (!Array.isArray(es)) { row.state = "unreadable"; row.why = "/history http " + es.http; rows.push(row); continue; }
    const measured = es.some((e) => e && String(e.at || "").slice(0, 10) === day);
    let due = null, dueBy = null, excused = null, unknown = null;
    if (w.owner_declined) excused = "owner declined measurement (/watchlist owner_declined)";
    else if (useSweep) {
      const c = sweepClass(sl, w.endpoint);
      if (c.excused) excused = c.excused; else if (c.unknown) unknown = c.unknown;
      else if (tier !== "free") { due = true; dueBy = "daily"; }
      else { due = c.due; dueBy = "sweep_last"; }
    } else if (tier !== "free") { due = true; dueBy = "daily"; }
    else if (rule === "legacy") { due = legacyDue(w.endpoint, day); dueBy = "legacy_rule"; }
    else if (rule === "derived" && saltOk && blockHash) { due = derivedDay(win.salt, blockHash, wid, w.endpoint) === dayInWindow(day); dueBy = "window_salt"; }
    else {
      const rec = es.find((e) => e && e.coordinate_derivation && e.coordinate_derivation.derived === true && e.coordinate_derivation.window_id === wid && Number.isInteger(e.coordinate_derivation.day_in_window));
      if (rec) { due = rec.coordinate_derivation.day_in_window === dayInWindow(day); dueBy = "row_history"; }
      else unknown = "free row: " + day + " is in window " + wid + " (" + (win ? win.status : "window unreadable") + ", rule " + (rule || "not pinned") + "), its salt is not public yet, /sweep/last is from " + (slDay || "no readable sweep") + ", and the row has no record in this window that carries its day";
    }
    if (excused) { row.state = "excused"; row.why = excused; }
    else if (unknown) { row.state = "unknown"; row.why = unknown; }
    else if (!due) { row.state = "not_due"; row.due_by = dueBy; }
    else { row.state = measured ? "measured" : "missing"; row.due_by = dueBy; }
    rows.push(row);
  }
  return finish({ gate, day, rows, unreadable, source: { sweep_last_day: slDay, sweep_last_used: useSweep, window_id: wid, window_status: win ? win.status : null, window_rule: rule, window_salt_verified: saltOk } });
}

function finish({ gate, day, rows, unreadable, source, fatal }) {
  rows.sort((a, b) => (a.endpoint < b.endpoint ? -1 : a.endpoint > b.endpoint ? 1 : 0));
  const pick = (st) => rows.filter((r) => r.state === st);
  const count = (st) => pick(st).length;
  const tiers = (t) => rows.filter((r) => r.tier === t).length;
  const result = {
    schema: SCHEMA,
    gate,
    day,
    source,
    counts: {
      watched: rows.length, self: tiers("self"), paid: tiers("paid"), free: tiers("free"),
      due: count("measured") + count("missing"), measured: count("measured"), missing: count("missing"),
      not_due: count("not_due"), excused: count("excused"), unknown: count("unknown"), unreadable: count("unreadable") + unreadable.length
    },
    missing: pick("missing").map((r) => ({ endpoint: r.endpoint, tier: r.tier, due_by: r.due_by })),
    unknown: pick("unknown").map((r) => ({ endpoint: r.endpoint, tier: r.tier, why: r.why })),
    excused: pick("excused").map((r) => ({ endpoint: r.endpoint, tier: r.tier, why: r.why })),
    unreadable: unreadable.concat(pick("unreadable").map((r) => ({ what: r.endpoint, why: r.why }))),
    due_by: Object.fromEntries(["daily", "sweep_last", "window_salt", "legacy_rule", "row_history"].map((k) => [k, rows.filter((r) => r.due_by === k).length]))
  };
  if (fatal) result.fatal = fatal;
  const result_sha256 = sha256(canonical(result));
  const exit = result.counts.missing > 0 ? 1 : (result.counts.unreadable > 0 || fatal) ? 2 : 0;
  return { result, result_sha256, exit };
}

export function render({ result, result_sha256, exit }) {
  const c = result.counts;
  const L = [];
  L.push("gate coverage " + result.day + " (UTC) at " + result.gate);
  L.push("watched " + c.watched + " (self " + c.self + ", paid " + c.paid + ", free " + c.free + "); owed " + c.due + ", measured " + c.measured + ", missing " + c.missing + "; free not due " + c.not_due + ", unknown " + c.unknown + ", excused " + c.excused + ", unreadable " + c.unreadable);
  L.push("free rows due by: " + Object.entries(result.due_by).filter(([k]) => k !== "daily").map(([k, v]) => k + " " + v).join(", ") + " (sweep_last day " + (result.source.sweep_last_day || "none") + ", window " + result.source.window_id + " " + (result.source.window_status || "?") + ", rule " + (result.source.window_rule || "?") + ")");
  if (result.fatal) L.push("FATAL " + result.fatal);
  for (const m of result.missing) L.push("MISSING   " + m.tier.padEnd(4) + " " + m.endpoint + "  (owed: " + m.due_by + ")");
  for (const u of result.unknown) L.push("UNKNOWN   " + u.tier.padEnd(4) + " " + u.endpoint + "  " + u.why);
  for (const x of result.excused) L.push("EXCUSED   " + x.tier.padEnd(4) + " " + x.endpoint + "  " + x.why);
  for (const u of result.unreadable) L.push("UNREADABLE " + (u.what || "") + " " + (u.why || ("http " + u.http)));
  L.push("result_sha256 " + result_sha256);
  L.push(exit === 0 ? "COVERED" : exit === 1 ? "NOT COVERED" : "COULD NOT TELL");
  return L.join("\n");
}

function args(argv) {
  const o = {};
  for (let k = 0; k < argv.length; k++) {
    const a = argv[k];
    if (a === "--day" || a === "--gate" || a === "--json" || a === "--md") o[a.slice(2)] = argv[++k];
    else return { error: "unknown argument " + a };
  }
  return o;
}

async function main() {
  const o = args(process.argv.slice(2));
  if (o.error) { console.error(o.error); process.exit(3); }
  const day = o.day || defaultDay(Date.now());
  if (!DAY_RE.test(day)) { console.error("--day must be YYYY-MM-DD"); process.exit(3); }
  const out = await coverage({ gate: (o.gate || DEFAULT_GATE).replace(/\/+$/, ""), day });
  const text = render(out);
  console.log(text);
  if (o.json) writeFileSync(o.json, JSON.stringify(Object.assign({}, out.result, { result_sha256: out.result_sha256 }), null, 2) + "\n");
  if (o.md) writeFileSync(o.md, "```\n" + text + "\n```\n");
  process.exit(out.exit);
}

function invokedDirectly() {
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; } catch (_e) { return false; }
}
if (invokedDirectly()) main();
