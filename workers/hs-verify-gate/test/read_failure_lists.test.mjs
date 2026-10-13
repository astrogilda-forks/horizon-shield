// read_failure_lists: a failed read must not come back as a shorter list, "not registered", "nothing changed" or
// "nobody used it" (2026-10-13, issue #13, follows read_failure_reports). The public register views (/watchlist,
// /register and every page built on it), GET /watch, /changes, /feed.xml, /usage, /nenrin/window, and the sweep's
// NENRIN window state (salt, rule, beacon, commitment filing). A failed read answers 503 (or, for /usage, says the day
// is unreadable) and writes nothing; genuine absence keeps its old answer. Same failing-KV mock as the other two.
// Offline; *.redteam.invalid never resolves. Run: node test/read_failure_lists.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";
import * as nenrin from "../src/nenrin_instant.js";

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
const TOKEN = "read-failure-lists-token";
const ENV = { HS_VERIFY_KV: KV, SWEEP_TOKEN: TOKEN, GATE_COMMIT: "read-failure-lists-local" };
const O = "https://gate.horizonshield.dev";
const get = (path) => worker.fetch(new Request(O + path), ENV, CTX);
const post = (path, body, headers) => worker.fetch(new Request(O + path, { method: "POST", headers: { "content-type": "application/json", ...(headers || {}) }, body: JSON.stringify(body) }), ENV, CTX);
const tool = async (name, args) => (await (await post("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } })).json()).result || {};
const toolBody = (res) => { try { return JSON.parse(res.content[0].text); } catch (_e) { return {}; } };
const rd = async (r) => { const text = await r.text(); let j = {}; try { j = JSON.parse(text); } catch (_e) {} return { status: r.status, j, text }; };
const sweep = async () => rd(await post("/sweep", { force: true }, { "x-sweep-token": TOKEN }));

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 240)); } };

const OUT = "https://out.redteam.invalid/mcp";
const LEG = "https://leg.redteam.invalid/mcp";
store.set("watch:registry", JSON.stringify({ [OUT]: { tier: "free", webhook: null, added_at: "2026-10-01T00:00:00Z", requested_by: "anonymous", owner_file_at_request: "absent" } }));
const enc = encodeURIComponent(OUT);

// 1. The register and every view built on it.
console.log("1. register views");
let r = await rd(await get("/watchlist"));
t("readable register: /watchlist 200 lists the outside row", r.status === 200 && (r.j.watched || []).some((w) => w.endpoint === OUT), r.status);
r = await rd(await get("/register"));
t("readable register: /register 200 lists the outside row", r.status === 200 && (r.j.rows || []).some((w) => w.endpoint === OUT), r.status);
r = await rd(await get("/watch?endpoint=" + enc));
t("readable register: GET /watch?endpoint says registered true", r.status === 200 && r.j.registered === true, r.status + " " + JSON.stringify(r.j));
r = await rd(await get("/watch?endpoint=" + encodeURIComponent("https://never.redteam.invalid/mcp")));
t("absent row: GET /watch?endpoint says registered false (200)", r.status === 200 && r.j.registered === false, r.status + " " + JSON.stringify(r.j));
r = await rd(await get("/watch"));
t("readable register: GET /watch count 1", r.status === 200 && r.j.count === 1, r.status + " " + JSON.stringify(r.j).slice(0, 120));

failing.add("watch:registry");
const failed503 = (x, code) => x.status === 503 && x.j.error === code && x.j.read_failed === true;
r = await rd(await get("/watchlist"));
t("failed register read: /watchlist 503 registry_read_failed, not a list without the outside row", failed503(r, "registry_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/register"));
t("failed register read: /register 503 registry_read_failed", failed503(r, "registry_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/verified.json"));
t("failed register read: /verified.json 503, not register_count without the outside row", failed503(r, "registry_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/.well-known/mcp-register.json"));
t("failed register read: /.well-known/mcp-register.json 503", failed503(r, "registry_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/sitemap.xml"));
t("failed register read: /sitemap.xml 503", failed503(r, "registry_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/e/out.redteam.invalid/mcp"));
t("failed register read: /e/<row> 503, not 404 'not on the register'", failed503(r, "registry_read_failed") && r.j.endpoint === OUT, r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/embed?endpoint=" + enc));
t("failed register read: /embed 503, not 404 'not on the register'", failed503(r, "registry_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/badge?endpoint=" + enc));
t("failed register read: /badge 503, not a 'not listed' badge", failed503(r, "registry_read_failed") && !/not listed/.test(r.text), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/badge/seal?endpoint=" + enc));
t("failed register read: /badge/seal 503, not a 'not listed' seal", failed503(r, "registry_read_failed") && !/not listed/.test(r.text), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/watch?endpoint=" + enc));
t("failed register read: GET /watch?endpoint 503, not registered false", failed503(r, "registry_read_failed") && r.j.registered === undefined && r.j.endpoint === OUT, r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/watch"));
t("failed register read: GET /watch 503, not count 0", failed503(r, "registry_read_failed") && r.j.count === undefined, r.status + " " + r.text.slice(0, 160));
failing.delete("watch:registry");

// 2. The operator's legacy list (watch:endpoints), read inside watchlist().
console.log("2. legacy watch list");
store.set("watch:endpoints", JSON.stringify([LEG]));
let res = await tool("lookup_server", { endpoint: LEG });
let b = toolBody(res);
t("readable legacy list: lookup_server finds the legacy row (not isError)", !res.isError && b.on_register === true, JSON.stringify(b).slice(0, 160));
r = await rd(await get("/watchlist"));
t("readable legacy list: /watchlist lists it", r.status === 200 && (r.j.watched || []).some((w) => w.endpoint === LEG), r.status);
failing.add("watch:endpoints");
r = await rd(await get("/watchlist"));
t("failed legacy list read: /watchlist 503 watchlist_read_failed, not a list without that row", failed503(r, "watchlist_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/register"));
t("failed legacy list read: /register 503 watchlist_read_failed", failed503(r, "watchlist_read_failed"), r.status + " " + r.text.slice(0, 160));
res = await tool("lookup_server", { endpoint: LEG });
b = toolBody(res);
t("failed legacy list read: lookup_server isError watchlist_read_failed, not on_register false", res.isError === true && b.error === "watchlist_read_failed" && b.on_register === undefined, JSON.stringify(res).slice(0, 200));
failing.delete("watch:endpoints");
store.delete("watch:endpoints");

// 3. The change feed.
console.log("3. changes");
r = await rd(await get("/changes"));
t("absent change feed: /changes 200 changes []", r.status === 200 && Array.isArray(r.j.changes) && r.j.changes.length === 0, r.status + " " + r.text.slice(0, 120));
r = await rd(await get("/feed.xml"));
t("absent change feed: /feed.xml 200 atom", r.status === 200 && /<feed/.test(r.text), r.status);
failing.add("changes:recent");
r = await rd(await get("/changes"));
t("failed change feed read: /changes 503 changes_read_failed, not changes []", failed503(r, "changes_read_failed") && r.j.changes === null, r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/feed.xml"));
t("failed change feed read: /feed.xml 503, not an empty feed", failed503(r, "changes_read_failed") && !/<feed/.test(r.text), r.status + " " + r.text.slice(0, 160));
failing.delete("changes:recent");

// 4. /usage.
console.log("4. usage");
const today = new Date().toISOString().slice(0, 10);
r = await rd(await get("/usage?days=2"));
t("no counters recorded: /usage 200 'Nobody outside', no unreadable_days", r.status === 200 && /^Nobody outside/.test(r.j.honest_status || "") && !("unreadable_days" in r.j), r.status + " " + String(r.j.honest_status));
failing.add("usage:" + today);
failing.add("usage:req:" + today);
r = await rd(await get("/usage?days=2"));
t("failed counter read: /usage does not say 'Nobody outside this operator has used it yet'", r.status === 200 && !/^Nobody outside/.test(r.j.honest_status || "") && (r.j.unreadable_days || []).includes(today), r.status + " " + String(r.j.honest_status) + " " + JSON.stringify(r.j.unreadable_days));
const reqDay = ((r.j.requesters || {}).by_day || []).find((d) => d.day === today) || {};
t("failed counter read: requesters by_day says unreadable, not none_recorded", reqDay.state === "unreadable" && reqDay.counts === null, JSON.stringify(reqDay));
failing.delete("usage:" + today);
failing.delete("usage:req:" + today);

// 5. /nenrin/window (read only).
console.log("5. nenrin window page");
const cur = nenrin.windowId(Date.now());
r = await rd(await get("/nenrin/window"));
t("absent window state: /nenrin/window 200 with current null", r.status === 200 && r.j.current === null, r.status + " " + r.text.slice(0, 120));
failing.add("nenrin:window:" + cur);
r = await rd(await get("/nenrin/window"));
t("failed window state read: /nenrin/window 503 window_read_failed, not current null", failed503(r, "window_read_failed"), r.status + " " + r.text.slice(0, 160));
r = await rd(await get("/nenrin/window/" + cur));
t("failed window state read: /nenrin/window/<id> 503, not 404 'no salt was created'", failed503(r, "window_read_failed") && r.j.window_id === cur, r.status + " " + r.text.slice(0, 160));
failing.delete("nenrin:window:" + cur);
const SALT = "ab".repeat(32);
const ST = { window_id: cur, salt: SALT, commitment: await nenrin.saltCommitment(SALT), salt_created_at: "2026-10-01T00:00:00.000Z" };
store.set("nenrin:window:" + cur, JSON.stringify(ST));
r = await rd(await get("/nenrin/window/" + cur));
t("window state readable, no filing: commitment_filed null (200)", r.status === 200 && r.j.commitment === ST.commitment && r.j.commitment_filed === null, r.status + " " + r.text.slice(0, 160));
failing.add("nenrin:commitfiled:" + cur);
r = await rd(await get("/nenrin/window/" + cur));
t("failed filing record read: 503 commitment_filed_read_failed, not commitment_filed null ('not anchored')", failed503(r, "commitment_filed_read_failed"), r.status + " " + r.text.slice(0, 160));
failing.delete("nenrin:commitfiled:" + cur);

// 6. The sweep's NENRIN state: a failed read writes nothing (three sweeps, a few seconds each).
console.log("6. sweep window state (runs the sweep three times)");
failing.add("nenrin:window:" + cur);
await sweep();
failing.delete("nenrin:window:" + cur);
t("failed salt read in the sweep: the committed salt is not replaced", store.get("nenrin:window:" + cur) === JSON.stringify(ST), store.get("nenrin:window:" + cur));

const RULE = { window_id: cur, rule: "derived", pinned_at: "2026-10-01T00:00:01.000Z", beacon_height: 1, block_hash: "e".repeat(64) };
const FILED = { window_id: cur, commitment: ST.commitment, filed_at: "2026-09-30T00:00:00.000Z", before_open: true, http: 201, sha: "f".repeat(64), url: "https://ledger.redteam.invalid/x", counted: true, error: null };
store.set("nenrin:rule:" + cur, JSON.stringify(RULE));
store.set("nenrin:commitfiled:" + cur, JSON.stringify(FILED));
failing.add("nenrin:rule:" + cur);
failing.add("nenrin:commitfiled:" + cur);
r = await sweep();
failing.delete("nenrin:rule:" + cur);
failing.delete("nenrin:commitfiled:" + cur);
t("failed rule read in the sweep: the pinned rule is not replaced", store.get("nenrin:rule:" + cur) === JSON.stringify(RULE), store.get("nenrin:rule:" + cur));
t("failed filing record read in the sweep: the first filing (before_open true) is not replaced", store.get("nenrin:commitfiled:" + cur) === JSON.stringify(FILED), store.get("nenrin:commitfiled:" + cur));
const filedNow = ((r.j.coordinate || {}).commitments_filed) || [];
const cRow = filedNow.find((c) => c.window_id === cur) || {};
t("and the sweep record says the filing record could not be read", cRow.error === "commitment_filed_read_failed" && cRow.read_failed === true, JSON.stringify(filedNow).slice(0, 200));

store.delete("nenrin:rule:" + cur);
failing.add("nenrin:beacon:" + cur);
await sweep();
failing.delete("nenrin:beacon:" + cur);
t("failed beacon read in the sweep: no rule is pinned for the window on the strength of it", !store.has("nenrin:rule:" + cur), store.get("nenrin:rule:" + cur));

console.log(`\n=== ${pass} / ${pass + fail} 合格 (read failure lists, 2026-10-13) ===`);
process.exit(fail ? 1 : 0);
