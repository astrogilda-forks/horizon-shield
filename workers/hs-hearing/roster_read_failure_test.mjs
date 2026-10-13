/* 2026-10-13. fetchPublished used to return an empty roster when the published file could not be fetched, so
   liveContractors reported read_ok:true with 0 contractors and the guard in tools/call never fired: an outage reached
   homeowner AIs as "0 verified contractors". This checks, on a copy of the real src with a mocked KV and fetch, that a
   failed read is now reported as a failure and a genuinely empty roster is still reported as empty. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRCDIR = path.join(HERE, "src");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hsroster-"));
for (const f of fs.readdirSync(SRCDIR)) {
  if (!f.endsWith(".js")) continue;
  let body = fs.readFileSync(path.join(SRCDIR, f), "utf8");
  body = body.replace(/from "\.\/([a-z0-9_]+)\.js"/g, 'from "./$1.mjs"');
  if (f === "hearing.js") body += "\nexport { liveContractors as __liveContractors };\n";
  fs.writeFileSync(path.join(TMP, f.replace(/\.js$/, ".mjs")), body);
}
const H = await import(path.join(TMP, "hearing.mjs"));
const worker = H.default;
const emptyKV = { list: async () => ({ keys: [], list_complete: true }), get: async () => null, put: async () => {} };
const brokenKV = { list: async () => { throw new Error("KV list failed (simulated)"); }, get: async () => { throw new Error("KV get failed (simulated)"); }, put: async () => {} };
const env = (kv) => ({ HS_HEARING_KV: kv, PUBLIC_DATA_URL: "https://roster.redteam.invalid/yakumo-contractors.json" });
let mode = "down";
globalThis.fetch = async (u) => {
  if (String(u).startsWith("https://roster.redteam.invalid/")) {
    if (mode === "down") return new Response("upstream error", { status: 503 });
    if (mode === "throw") throw new Error("network down (simulated)");
    if (mode === "empty") return new Response(JSON.stringify({ contractors: [], stats: {} }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response("", { status: 404 });
};
let fail = 0;
const ok = (c, m, d = "") => { console.log((c ? "ok   " : "FAIL ") + m + (c ? "" : "  " + String(d).slice(0, 200))); if (!c) fail++; };

let r = await H.__liveContractors(env(emptyKV));
ok(r.read_ok === false && r.source === "none", "KV empty and the published roster answers 503: read_ok false, not a confident zero", JSON.stringify(r));
mode = "throw";
r = await H.__liveContractors(env(emptyKV));
ok(r.read_ok === false, "the published fetch throws: read_ok false", JSON.stringify(r));
mode = "empty";
r = await H.__liveContractors(env(emptyKV));
ok(r.read_ok === true && r.contractors.length === 0 && r.source === "published", "the published roster genuinely lists nobody: read_ok true, 0 contractors", JSON.stringify(r));

mode = "down";
const call = async (kv) => worker.fetch(new Request("https://hs-hearing.example.dev/mcp", { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_verified_stores", arguments: {} } }) }), env(kv), { waitUntil() {} });
let res = await (await call(emptyKV)).json();
ok(res.result && res.result.isError === true && /roster_unavailable/.test(JSON.stringify(res.result)), "list_verified_stores on an outage is an error, not 0 stores", JSON.stringify(res).slice(0, 200));

const cj = await worker.fetch(new Request("https://hs-hearing.example.dev/contractors.json"), env(brokenKV), { waitUntil() {} });
const cb = await cj.json();
ok(cj.status === 503 && cb.error === "roster_unavailable" && cb.read_ok === false, "/contractors.json with KV and roster both down answers 503, not an empty roster", cj.status + " " + JSON.stringify(cb).slice(0, 160));

fs.rmSync(TMP, { recursive: true, force: true });
if (fail) { console.log("落ちた: " + fail); process.exit(1); }
console.log("roster_read_failure 5/5 通過");
