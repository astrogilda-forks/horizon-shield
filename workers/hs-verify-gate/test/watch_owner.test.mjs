// 2026-10-08 (FIX_LIST 6): an existing webhook can be changed only by the owner (the origin's notify) or the operator.
// Based on watch_decline.mjs (0.3.1): /watch records who asked; an origin's well-known listing: "decline" stops measurement;
// the sweep is ordered least recently measured first; DELETE /watch removes a row with a public tombstone.
// Offline. globalThis.fetch is replaced; *.redteam.invalid never resolves for real (RFC 2606).
// Run: node test/watch_decline.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";

const CTX = { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } };
const jres = (obj, status) => new Response(JSON.stringify(obj), { status: status || 200, headers: { "content-type": "application/json" } });
const CARD = { name: "Redteam Agent", description: "an adversarial mock", url: "",
  compensation: { paid_by: "public", referral_fee: false, listing_fee: false, success_fee_pct: 0, disclosure_url: "https://example.invalid/disclosure" } };
const TOOL = { name: "alpha", description: "redteam tool alpha", inputSchema: { type: "object", properties: {} } };

function kv() {
  const store = new Map();
  return {
    store,
    get: async (k, type) => { const v = store.has(k) ? store.get(k) : null; return (type === "json" && v !== null) ? JSON.parse(v) : v; },
    put: async (k, v) => { store.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
    delete: async (k) => { store.delete(k); },
    list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || "")).map((name) => ({ name })), list_complete: true }),
  };
}

// origin -> well-known body (undefined = 404)
const WK = {
  "https://declined.redteam.invalid": { allow_tool_call: true, listing: "decline" },
  "https://open.redteam.invalid": undefined,
  "https://consenting.redteam.invalid": { allow_tool_call: true },
  "https://sloppy.redteam.invalid": { allow_tool_call: true, listing: "DECLINE" },   // wrong case: not a decline (exact value only)
  "https://owner.redteam.invalid": { notify: "https://owner.redteam.invalid/new-hook" },  // the owner names the new webhook
};
globalThis.fetch = async (url, init) => {
  const u = new URL(url);
  const origin = u.origin;
  if (!/\.redteam\.invalid$/.test(u.hostname)) return new Response("no", { status: 500 });   // beacon etc.: fail closed
  if (u.pathname === "/.well-known/mcp-conduct.json") return WK[origin] === undefined ? new Response("", { status: 404 }) : jres(WK[origin]);
  if (u.pathname === "/.well-known/agent-card.json") return jres(CARD);
  if (u.pathname === "/mcp" && (init && init.method) === "POST") {
    const body = JSON.parse(init.body); const id = body.id;
    if (body.method === "initialize") return jres({ jsonrpc: "2.0", id, result: { protocolVersion: "2024-11-05", serverInfo: { name: "rt", version: "0" }, capabilities: { tools: {} } } });
    if (body.method === "tools/list") return jres({ jsonrpc: "2.0", id, result: { tools: [TOOL] } });
    if (body.method === "tools/call") return jres({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: "constant answer" }] } });
    return jres({ jsonrpc: "2.0", id, error: { code: -32601, message: "nope" } });
  }
  return new Response("not found", { status: 404 });
};

const ENV = { HS_VERIFY_KV: kv(), SWEEP_TOKEN: "redteam-sweep-token", GATE_COMMIT: "redteam-local" };
const call = (path, init) => worker.fetch(new Request("https://gate.horizonshield.dev" + path, init), ENV, CTX);
const post = (path, body, headers) => call(path, { method: "POST", headers: { "content-type": "application/json", ...(headers || {}) }, body: JSON.stringify(body) });

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 200)); } };
const EP_OPEN = "https://open.redteam.invalid/mcp", EP_OWN = "https://owner.redteam.invalid/mcp";

let r = await post("/watch", { endpoint: EP_OPEN, webhook: "https://first.redteam.invalid/hook" });
t("a new row may name a webhook (first registration)", r.status === 200 && (await r.json()).notified === true);
r = await post("/watch", { endpoint: EP_OPEN, webhook: "https://attacker.redteam.invalid/hook" });
let j = await r.json();
t("a stranger cannot redirect an existing webhook: 403 webhook_change_needs_owner", r.status === 403 && j.error === "webhook_change_needs_owner", JSON.stringify(j));
r = await post("/watch", { endpoint: EP_OPEN, webhook: null });
t("a stranger cannot remove an existing webhook", r.status === 403);
// 2026-10-13 (concurrency audit G1): the register is one key per row (watch:reg:<sha256(endpoint)>), the old blob is only read.
const row = (() => { for (const [k, v] of ENV.HS_VERIFY_KV.store) { if (k.startsWith("watch:reg:")) { const rec = JSON.parse(v); if (rec.endpoint === EP_OPEN) return rec.row; } } const b = ENV.HS_VERIFY_KV.store.get("watch:registry"); return b ? JSON.parse(b)[EP_OPEN] : null; })();
t("the stored webhook is unchanged", row && row.webhook === "https://first.redteam.invalid/hook", JSON.stringify(row));
r = await post("/watch", { endpoint: EP_OPEN });
t("re-posting without a webhook field keeps the row and its webhook", r.status === 200 && (await r.json()).notified === true);
r = await post("/watch", { endpoint: EP_OPEN, webhook: "https://first.redteam.invalid/hook" });
t("re-posting the same webhook is not a change", r.status === 200);
r = await post("/watch", { endpoint: EP_OPEN, webhook: "https://ops.redteam.invalid/hook" }, { "x-sweep-token": "redteam-sweep-token" });
t("the operator can change it", r.status === 200);
r = await post("/watch", { endpoint: EP_OWN, webhook: "https://first.redteam.invalid/hook" });
t("owner origin: first registration by anyone", r.status === 200);
r = await post("/watch", { endpoint: EP_OWN, webhook: "https://owner.redteam.invalid/other" });
t("owner origin: a webhook other than the file's notify is refused", r.status === 403);
r = await post("/watch", { endpoint: EP_OWN, webhook: "https://owner.redteam.invalid/new-hook" });
t("owner origin: the webhook named in the file's notify is accepted", r.status === 200);
console.log("\n=== " + pass + " / " + (pass + fail) + " 合格 (watch webhook owner, 2026-10-08) ===");
process.exit(fail ? 1 : 0);
