// 2026-10-13. The mould from issue #13 at the WebMCP gate: when hs-billing threw or answered non-2xx, billingEntitled
// returned false and verifyStore told the caller "store not provisioned for WebMCP (paid option required)", a statement
// about the store that nobody had checked. The gate must stay closed, but say that billing could not be checked.
// Genuine absence (hs-billing answers active:false, or 404) keeps today's -32001 wording exactly.
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const src = readFileSync(new URL("../index.js", import.meta.url), "utf8");
const d = mkdtempSync(join(tmpdir(), "webmcp-billing-"));
const f = join(d, "m.mjs");
writeFileSync(f, src);

// No cache between calls, so each call reaches the mocked fetch.
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
let billing = "down";
globalThis.fetch = async (u) => {
  u = String(u);
  if (u.endsWith("/data/yakumo-contractors.json")) {
    return new Response(JSON.stringify({ contractors: [{ store_id: "s1", member_no: "No.001", webmcp_option: false }] }), { headers: { "content-type": "application/json" } });
  }
  if (u.includes("/entitlement?store=")) {
    if (billing === "down") return new Response("upstream error", { status: 503 });
    if (billing === "throw") throw new Error("network down (simulated)");
    if (billing === "garbage") return new Response("<html>not json</html>", { status: 200 });
    if (billing === "404") return new Response("not found", { status: 404 });
    if (billing === "inactive") return new Response(JSON.stringify({ store: "s1", active: false }), { headers: { "content-type": "application/json" } });
    if (billing === "active") return new Response(JSON.stringify({ store: "s1", active: true }), { headers: { "content-type": "application/json" } });
  }
  return new Response("", { status: 404 });
};
const mod = await import("file://" + f);
const worker = mod.default;

let fail = 0, n = 0;
const chk = (name, c, x = "") => { n++; console.log((c ? "PASS  " : "FAIL  ") + name + (c ? "" : "  <<< " + String(x).slice(0, 300))); if (!c) fail++; };
const call = async (store, tool = "no_such_tool") => (await worker.fetch(new Request("https://x.dev/mcp?store=" + store, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: {} } }),
}), {}, { waitUntil() {} })).json();
const NOT_PROVISIONED = "store not provisioned for WebMCP (paid option required)";
const isReadFailure = (r) => !!(r.error && r.error.code === -32002 && /could not be checked/.test(r.error.message) && r.error.message.indexOf(NOT_PROVISIONED) < 0);

for (const m of ["down", "throw", "garbage"]) {
  billing = m;
  const r = await call("s1");
  chk("hs-billing " + m + ": -32002 billing could not be checked, not 'not provisioned'", isReadFailure(r), JSON.stringify(r));
}
for (const m of ["inactive", "404"]) {
  billing = m;
  const r = await call("s1");
  chk("hs-billing " + m + ": still -32001 with today's wording", r.error && r.error.code === -32001 && r.error.message === NOT_PROVISIONED, JSON.stringify(r));
}
billing = "active";
let r = await call("s1");
chk("hs-billing active: the gate opens (the unknown tool is what answers)", r.error && r.error.code === -32602 && /Unknown tool/.test(r.error.message), JSON.stringify(r));
billing = "down";
r = await call("nobody");
chk("an unknown store is still -32001 unknown store, billing not consulted", r.error && r.error.code === -32001 && r.error.message === "unknown store: nobody", JSON.stringify(r));

if (fail) { console.log("\nbilling_read_failure: " + fail + " FAILURES of " + n); process.exit(1); }
console.log("\nbilling_read_failure: " + n + "/" + n + " PASS");
