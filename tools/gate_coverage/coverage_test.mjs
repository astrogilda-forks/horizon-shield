// tools/gate_coverage/coverage_test.mjs: coverage.mjs offline, against a fake gate (mocked fetch). No network.
// Run: node tools/gate_coverage/coverage_test.mjs
import { createHash } from "node:crypto";
import { coverage, render, derivedDay, legacyDue, dayInWindow, windowIdOf, defaultDay, canonical, sha256 } from "./coverage.mjs";
import * as nenrin from "../../workers/hs-verify-gate/src/nenrin_instant.js";

let bad = 0, n = 0;
const chk = (name, ok, info = "") => { n++; if (!ok) bad++; console.log((ok ? "PASS  " : "FAIL  ") + name + (ok ? "" : "  " + info)); };

const G = "https://gate.example";
const DAY = "2026-10-22";
const NOT_DUE = "not due today (derived: the day is HMAC-derived from a committed salt bound to a Bitcoin block, so the subject cannot predict it)";
const OVER = "over MAX_PER_SWEEP for this run (order is least recently measured first; this endpoint was last measured 2026-10-20T18:01:02.522Z, so it goes first next time)";

// A small world: two self rows, one paid row, three free rows (one due and measured, one due and skipped, one not due).
function world(over = {}) {
  const w = {
    watched: [
      { endpoint: "https://a.self/mcp", tier: "self" },
      { endpoint: "https://b.self/mcp", tier: "self" },
      { endpoint: "https://c.paid/mcp", tier: "paid" },
      { endpoint: "https://d.free/mcp", tier: "free" },
      { endpoint: "https://e.free/mcp", tier: "free" },
      { endpoint: "https://f.free/mcp", tier: "free" }
    ],
    sweepLast: {
      ran: true, at: DAY + "T18:00:52.468Z",
      results: [{ endpoint: "https://a.self/mcp", tier: "self" }, { endpoint: "https://b.self/mcp", tier: "self" }, { endpoint: "https://c.paid/mcp", tier: "paid" }, { endpoint: "https://d.free/mcp", tier: "free" }],
      skipped: [{ endpoint: "https://e.free/mcp", tier: "free", reason: OVER }, { endpoint: "https://f.free/mcp", tier: "free", reason: NOT_DUE }]
    },
    history: {
      "https://a.self/mcp": [{ at: DAY + "T18:01:00Z" }],
      "https://b.self/mcp": [{ at: DAY + "T18:01:10Z" }],
      "https://c.paid/mcp": [{ at: DAY + "T18:01:20Z" }],
      "https://d.free/mcp": [{ at: DAY + "T18:01:30Z" }],
      "https://e.free/mcp": [{ at: DAY + "T19:20:00Z" }],
      "https://f.free/mcp": [{ at: "2026-10-19T18:00:00Z" }]
    },
    window: { status: 404 }
  };
  return Object.assign(w, over);
}

function fake(w) {
  const calls = [];
  const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
  const f = async (url, init) => {
    calls.push({ url: String(url), init });
    const u = new URL(url);
    if (u.pathname === "/watchlist") return w.watchlistStatus ? J({ error: "x" }, w.watchlistStatus) : J({ watched: w.watched });
    if (u.pathname === "/sweep/last") return J(w.sweepLast);
    if (u.pathname.startsWith("/nenrin/window/")) return w.window.status === 404 ? J({ error: "not_found" }, 404) : J(w.window);
    if (u.pathname === "/history") {
      const ep = u.searchParams.get("endpoint");
      if (w.historyFail && w.historyFail === ep) return J({ error: "history_read_failed" }, 503);
      return J({ endpoint: ep, entries: w.history[ep] || [] });
    }
    return J({ error: "not_found" }, 404);
  };
  return { f, calls };
}
const run = (w, day = DAY) => { const fk = fake(w); return coverage({ gate: G, day, fetchImpl: fk.f }).then((o) => Object.assign(o, { calls: fk.calls })); };

{
  const o = await run(world());
  chk("nothing missing -> exit 0", o.exit === 0 && o.result.counts.missing === 0 && o.result.counts.due === 5 && o.result.counts.not_due === 1, JSON.stringify(o.result.counts));
  chk("only GETs, with a User-Agent, no key", o.calls.every((c) => !c.init || !c.init.method || c.init.method === "GET") && o.calls.every((c) => /hs-gate-coverage/.test(c.init.headers["user-agent"]) && !c.init.headers.authorization && !c.init.headers["x-sweep-token"]));
  chk("render says COVERED and prints the sha", /COVERED/.test(render(o)) && render(o).includes("result_sha256 " + o.result_sha256));
}
{
  const w = world(); w.history["https://b.self/mcp"] = [{ at: "2026-10-21T18:00:00Z" }];
  const o = await run(w);
  chk("missing self row -> exit 1, named", o.exit === 1 && o.result.missing.length === 1 && o.result.missing[0].endpoint === "https://b.self/mcp" && o.result.missing[0].tier === "self");
}
{
  const w = world(); w.history["https://c.paid/mcp"] = [];
  const o = await run(w);
  chk("missing paid row -> exit 1, named", o.exit === 1 && o.result.missing.map((m) => m.endpoint).join() === "https://c.paid/mcp" && o.result.missing[0].tier === "paid");
}
{
  const w = world(); w.history["https://e.free/mcp"] = [{ at: "2026-10-15T18:00:00Z" }];
  const o = await run(w);
  chk("due free row (skipped over MAX) missing -> exit 1", o.exit === 1 && o.result.missing.length === 1 && o.result.missing[0].endpoint === "https://e.free/mcp" && o.result.missing[0].due_by === "sweep_last");
}
{
  const w = world(); w.history["https://f.free/mcp"] = [];
  const o = await run(w);
  chk("not-due free row without a record is not missing", o.exit === 0 && o.result.counts.not_due === 1);
}
{
  const a = await run(world());
  const w2 = world(); w2.watched = w2.watched.slice().reverse();
  const b = await run(w2);
  chk("sha stable across runs and watchlist order", a.result_sha256 === b.result_sha256 && a.result_sha256 === (await run(world())).result_sha256);
  chk("sha is sha256 of the canonical result", a.result_sha256 === createHash("sha256").update(canonical(a.result)).digest("hex"));
  const w3 = world(); w3.history["https://a.self/mcp"] = [];
  chk("sha changes when a row changes", (await run(w3)).result_sha256 !== a.result_sha256);
}
{
  // Quarantined row and a row added after the sweep are excused; owner_declined on /watchlist is excused.
  const w = world();
  w.watched.push({ endpoint: "https://g.self/mcp", tier: "self" }, { endpoint: "https://h.free/mcp", tier: "free", owner_declined: true });
  w.sweepLast.skipped.push({ endpoint: "https://a.self/mcp", tier: "self", reason: "quarantined by the operator under TSUGI since 2026-10-01 citing proposal abcd: not measured" });
  w.sweepLast.results = w.sweepLast.results.filter((r) => r.endpoint !== "https://a.self/mcp");
  w.history["https://a.self/mcp"] = [];
  const o = await run(w);
  chk("excused: quarantined, added after the sweep, owner declined", o.exit === 0 && o.result.excused.length === 3, JSON.stringify(o.result.excused));
}
{
  const w = world(); w.historyFail = "https://a.self/mcp";
  const o = await run(w);
  chk("unreadable history -> exit 2, not missing", o.exit === 2 && o.result.counts.missing === 0 && o.result.unreadable.length === 1);
  const w2 = world(); w2.watchlistStatus = 503;
  chk("unreadable watchlist -> exit 2", (await run(w2)).exit === 2);
}

// ---------------------------------------------------------------- free rows on a day the last sweep does not cover
{
  // The gate's own derivation (workers/hs-verify-gate/src/nenrin_instant.js, imported read only) against ours.
  const salt = "4badf4415238c5a18a26aa459a0ddedb165ea2622053e6e7ec222f985d6db30f";
  const bh = "000000000000000000005d11ad7146e09cfa888440ef0134cc050118507cf163";
  const wid = "w2963";
  let same = true;
  for (const ep of ["https://d.free/mcp", "https://e.free/mcp", "https://mesh.agentdiet.dev/mcp", "https://x.example/mcp"]) {
    const seed = await nenrin.prfHex(salt, [nenrin.NENRIN_INSTANT_SCHEMA, "seed", wid, bh]);
    const theirs = await nenrin.dueOffset(seed, ep, wid);
    if (theirs !== derivedDay(salt, bh, wid, ep)) same = false;
  }
  chk("derived day equals the gate's nenrin_instant.js", same);
  chk("window id and day in window equal the gate's", windowIdOf("2026-10-21") === nenrin.windowId(Date.parse("2026-10-21T12:00:00Z")) && dayInWindow("2026-10-21") === nenrin.dayInWindow(Date.parse("2026-10-21T12:00:00Z")));

  // A closed window: due-ness from the revealed salt.
  const day = "2026-10-20";
  const target = dayInWindow(day);
  const commitment = sha256("nenrin-instant-salt-v1:" + salt);
  let dueEp = null, notEp = null;
  for (let k = 0; k < 200 && (!dueEp || !notEp); k++) {
    const ep = "https://r" + k + ".free/mcp";
    if (derivedDay(salt, bh, wid, ep) === target) dueEp = dueEp || ep; else notEp = notEp || ep;
  }
  const w = world({
    watched: [{ endpoint: dueEp, tier: "free" }, { endpoint: notEp, tier: "free" }],
    history: { [dueEp]: [], [notEp]: [] },
    window: { window_id: wid, status: "closed", salt, commitment, rule: { rule: "derived" }, beacon: { block_hash: bh } }
  });
  const o = await run(w, day);
  chk("closed window: due free row found by the salt and missing", o.exit === 1 && o.result.missing.length === 1 && o.result.missing[0].endpoint === dueEp && o.result.missing[0].due_by === "window_salt");
  const wBad = world(Object.assign({}, w, { window: Object.assign({}, w.window, { commitment: "00".repeat(32) }) }));
  const ob = await run(wBad, day);
  chk("closed window whose salt does not match the commitment: no due claim from it", ob.result.due_by.window_salt === 0);
}
{
  // Current window, salt withheld: the row's own record says its day; without one, unknown (not missing).
  const day = "2026-10-23";
  const wid = windowIdOf(day);
  const w = world({
    watched: [{ endpoint: "https://p.free/mcp", tier: "free" }, { endpoint: "https://q.free/mcp", tier: "free" }, { endpoint: "https://s.self/mcp", tier: "self" }],
    history: {
      "https://p.free/mcp": [{ at: "2026-10-22T18:00:00Z", coordinate_derivation: { derived: true, window_id: wid, day_in_window: dayInWindow(day) } }],
      "https://q.free/mcp": [],
      "https://s.self/mcp": [{ at: day + "T18:00:00Z" }]
    },
    window: { window_id: wid, status: "current", salt: null, rule: { rule: "derived" } }
  });
  const o = await run(w, day);
  chk("current window: row_history gives the due day; no record -> unknown", o.exit === 1 && o.result.missing[0].endpoint === "https://p.free/mcp" && o.result.missing[0].due_by === "row_history" && o.result.unknown.length === 1 && o.result.unknown[0].endpoint === "https://q.free/mcp");
}
{
  const day = "2026-10-20";
  const ep = ["https://l0.free/mcp", "https://l1.free/mcp", "https://l2.free/mcp", "https://l3.free/mcp", "https://l4.free/mcp", "https://l5.free/mcp", "https://l6.free/mcp", "https://l7.free/mcp"].find((e) => legacyDue(e, day));
  const w = world({ watched: [{ endpoint: ep, tier: "free" }], history: { [ep]: [] }, window: { window_id: windowIdOf(day), status: "closed", salt: null, rule: { rule: "legacy" } } });
  const o = await run(w, day);
  chk("legacy window: due by sha256(endpoint) mod 7", !!ep && o.result.missing.length === 1 && o.result.missing[0].due_by === "legacy_rule");
}
chk("default day: today from 21:00 UTC, else yesterday", defaultDay(Date.parse("2026-10-23T23:30:00Z")) === "2026-10-23" && defaultDay(Date.parse("2026-10-23T08:00:00Z")) === "2026-10-22");

console.log("\n" + (n - bad) + "/" + n + " passed");
if (bad) process.exit(1);
