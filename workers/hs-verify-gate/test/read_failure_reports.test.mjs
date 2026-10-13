// read_failure_reports: a failed read must not be reported as "nothing there" (2026-10-13, issue #13).
// Every read has three outcomes: ok, absent (KV get returned null), failed (KV get threw). A failed read is answered as
// a failure (HTTP 503 or MCP isError) and never as "no history", "absent", "not stored", "no removals" or an empty
// register. Genuine absence keeps its old wording and status. Same failing-KV mock as read_failure_writes_nothing.
// Offline; *.redteam.invalid never resolves. Run: node test/read_failure_reports.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";
import { createHash } from "node:crypto";

const CTX = { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } };
globalThis.fetch = async () => new Response("", { status: 404 });   // nothing reachable anywhere: fail closed

const failing = new Set();
const store = new Map();
const KV = {
  get: async (k, type) => { if (failing.has(k)) throw new Error("KV read failed (simulated)"); const v = store.has(k) ? store.get(k) : null; return (type === "json" && v !== null) ? JSON.parse(v) : v; },
  put: async (k, v) => { store.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
  delete: async (k) => { store.delete(k); },
  list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || "")).map((name) => ({ name })), list_complete: true }),
};
const TOKEN = "read-failure-reports-token";
const ENV = { HS_VERIFY_KV: KV, SWEEP_TOKEN: TOKEN, GATE_COMMIT: "read-failure-reports-local" };
const O = "https://gate.horizonshield.dev";
const get = (path) => worker.fetch(new Request(O + path), ENV, CTX);
const post = (path, body, headers) => worker.fetch(new Request(O + path, { method: "POST", headers: { "content-type": "application/json", ...(headers || {}) }, body: JSON.stringify(body) }), ENV, CTX);
const tool = async (name, args) => (await (await post("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } })).json()).result || {};
const toolBody = (res) => { try { return JSON.parse(res.content[0].text); } catch (_e) { return {}; } };
const histKey = (ep) => "hist:" + createHash("sha256").update(ep).digest("hex").slice(0, 16);
const rd = async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) });

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 240)); } };

const EP = "https://h.redteam.invalid/mcp";        // never measured: its history key is absent
const enc = encodeURIComponent(EP);

// 1. readHistory and its callers.
console.log("1. history");
let r = await rd(await get("/history?endpoint=" + enc));
t("absent history: /history 200 with entries [] and the old note", r.status === 200 && Array.isArray(r.j.entries) && r.j.entries.length === 0 && /^No history recorded/.test(r.j.note || ""), r.status + " " + JSON.stringify(r.j).slice(0, 160));
let res = await tool("is_verified", { endpoint: EP });
let b = toolBody(res);
t("absent history: is_verified says state absent, verified null, not isError", !res.isError && b.state === "absent" && b.verified === null, JSON.stringify(b).slice(0, 160));
res = await tool("lookup_server", { endpoint: EP });
b = toolBody(res);
t("absent history: lookup_server says on_register false, not isError", !res.isError && b.on_register === false, JSON.stringify(b).slice(0, 160));
r = await rd(await get("/is-verified?endpoint=" + enc));
t("absent history: GET /is-verified 200 state absent", r.status === 200 && r.j.state === "absent", r.status + " " + JSON.stringify(r.j).slice(0, 160));

failing.add(histKey(EP));
r = await rd(await get("/history?endpoint=" + enc));
t("failed history read: /history 503 history_read_failed", r.status === 503 && r.j.error === "history_read_failed" && r.j.read_failed === true, r.status + " " + JSON.stringify(r.j).slice(0, 160));
t("and it does not say 'No history recorded'", !/No history recorded/.test(JSON.stringify(r.j)));
res = await tool("is_verified", { endpoint: EP });
b = toolBody(res);
t("failed history read: is_verified isError, error history_read_failed", res.isError === true && b.error === "history_read_failed", JSON.stringify(res).slice(0, 200));
t("and never state absent, never verified false", b.state !== "absent" && b.verified !== false && /NOT a statement/.test(b.note || ""), JSON.stringify(b).slice(0, 200));
res = await tool("lookup_server", { endpoint: EP });
b = toolBody(res);
t("failed history read: lookup_server isError, not on_register false", res.isError === true && b.error === "history_read_failed" && b.on_register === undefined, JSON.stringify(res).slice(0, 200));
r = await rd(await get("/is-verified?endpoint=" + enc));
t("failed history read: GET /is-verified 503", r.status === 503 && r.j.error === "history_read_failed" && r.j.state !== "absent", r.status + " " + JSON.stringify(r.j).slice(0, 160));
r = await rd(await get("/register/lookup?endpoint=" + enc));
t("failed history read: GET /register/lookup 503, not status unknown", r.status === 503 && r.j.status !== "unknown", r.status + " " + JSON.stringify(r.j).slice(0, 160));
r = await rd(await post("/feed/batch", { endpoints: [EP] }));
t("failed history read: /feed/batch result says history_read_failed, not on_register false", r.status === 200 && r.j.results && r.j.results[0] && r.j.results[0].error === "history_read_failed" && r.j.results[0].on_register === undefined, JSON.stringify(r.j.results || r.j).slice(0, 160));
const SELF = "https://mcp.horizonshield.dev/mcp";
failing.add(histKey(SELF));
r = await rd(await get("/register"));
const selfRow = (r.j.rows || []).find((x) => x.endpoint === SELF) || {};
t("failed history read: /register row says history_read_failed with measurements null, not 0", selfRow.history_read_failed === true && selfRow.measurements === null, JSON.stringify(selfRow).slice(0, 160));
failing.delete(histKey(SELF));
failing.delete(histKey(EP));
r = await rd(await get("/register"));
const selfRow2 = (r.j.rows || []).find((x) => x.endpoint === SELF) || {};
t("readable history: /register row has measurements 0 and no history_read_failed", selfRow2.measurements === 0 && !("history_read_failed" in selfRow2), JSON.stringify(selfRow2).slice(0, 160));

failing.add("watch:registry");
res = await tool("is_verified", { endpoint: EP });
b = toolBody(res);
t("failed register read: is_verified isError registry_read_failed, not state absent", res.isError === true && b.error === "registry_read_failed" && b.state !== "absent", JSON.stringify(res).slice(0, 200));
failing.delete("watch:registry");

// 2. readSweepLast.
console.log("2. sweep:last");
r = await rd(await get("/sweep/last"));
t("absent sweep:last: 200 ran false with the old note", r.status === 200 && r.j.ran === false && /^No sweep has completed yet/.test(r.j.note || ""), r.status + " " + JSON.stringify(r.j).slice(0, 160));
failing.add("sweep:last");
r = await rd(await get("/sweep/last"));
t("failed sweep:last read: 503 sweep_last_read_failed, not 'No sweep has completed yet'", r.status === 503 && r.j.error === "sweep_last_read_failed" && !/No sweep has completed/.test(JSON.stringify(r.j)), r.status + " " + JSON.stringify(r.j).slice(0, 160));
failing.delete("sweep:last");

// 3. record bytes.
console.log("3. record bytes");
const SHA = "c".repeat(64);
r = await rd(await get("/record/" + SHA));
t("absent record bytes: 404 not_stored", r.status === 404 && r.j.error === "not_stored", r.status + " " + JSON.stringify(r.j).slice(0, 160));
failing.add("rec:" + SHA);
r = await rd(await get("/record/" + SHA));
t("failed record bytes read: 503 record_read_failed, not 404 not_stored", r.status === 503 && r.j.error === "record_read_failed" && r.j.sha === SHA, r.status + " " + JSON.stringify(r.j).slice(0, 160));
failing.delete("rec:" + SHA);

// 4. the public list of removals.
console.log("4. removed list");
r = await rd(await get("/watchlist"));
t("absent removed list: /watchlist removed [] and no removed_read_failed", Array.isArray(r.j.removed) && r.j.removed.length === 0 && !("removed_read_failed" in r.j), JSON.stringify(r.j.removed));
r = await rd(await get("/register"));
t("absent removed list: /register removed_rows [] and no removed_read_failed", Array.isArray(r.j.removed_rows) && r.j.removed_rows.length === 0 && !("removed_read_failed" in r.j), JSON.stringify(r.j.removed_rows));
failing.add("watch:removed");
r = await rd(await get("/watchlist"));
t("failed removed list read: /watchlist removed null, removed_read_failed true", r.j.removed === null && r.j.removed_read_failed === true, JSON.stringify({ removed: r.j.removed, f: r.j.removed_read_failed }));
r = await rd(await get("/register"));
t("failed removed list read: /register removed_rows null, removed_read_failed true", r.j.removed_rows === null && r.j.removed_read_failed === true, JSON.stringify({ removed_rows: r.j.removed_rows, f: r.j.removed_read_failed }));
failing.delete("watch:removed");

// 5. the sweep's register read.
console.log("5. sweep register read (runs a sweep twice, a few seconds)");
const OUT = "https://out.redteam.invalid/mcp", QU = "https://qu.redteam.invalid/mcp";
store.set("watch:registry", JSON.stringify({
  [OUT]: { tier: "free", webhook: null, added_at: "2026-10-01T00:00:00Z", requested_by: "anonymous", owner_file_at_request: "absent" },
  [QU]: { tier: "free", webhook: null, added_at: "2026-10-01T00:00:00Z", requested_by: "anonymous", owner_file_at_request: "absent",
          quarantined: { since: "2026-10-12T00:00:00Z", proposal_sha256: "d".repeat(64), reason: "signature drift on the card" } } }));
failing.add("watch:registry");
r = await rd(await post("/sweep", { force: true }, { "x-sweep-token": TOKEN }));
t("failed register read: sweep result says registry_read_failed", r.status === 200 && r.j.registry_read_failed === true && r.j.watched_total === null, r.status + " " + JSON.stringify({ f: r.j.registry_read_failed, w: r.j.watched_total }));
t("and measured nothing (the quarantined row cannot be measured on an unread register)", Array.isArray(r.j.results) && r.j.results.length === 0 && !store.has(histKey(QU)), JSON.stringify((r.j.results || []).map((x) => x.endpoint)));
t("and the same is written to sweep:last", JSON.parse(store.get("sweep:last") || "{}").registry_read_failed === true);
failing.delete("watch:registry");
r = await rd(await post("/sweep", { force: true }, { "x-sweep-token": TOKEN }));
const qSkip = (r.j.skipped || []).find((x) => x.endpoint === QU);
t("readable register: no registry_read_failed, the quarantined row is skipped as quarantined", r.status === 200 && !("registry_read_failed" in r.j) && qSkip && /^quarantined by the operator/.test(qSkip.reason), JSON.stringify(qSkip || r.j).slice(0, 200));
t("and the outside row is in the sweep (measured or skipped, not dropped)", (r.j.results || []).some((x) => x.endpoint === OUT) || (r.j.skipped || []).some((x) => x.endpoint === OUT));

console.log(`\n=== ${pass} / ${pass + fail} 合格 (read failure reports, 2026-10-13) ===`);
process.exit(fail ? 1 : 0);
