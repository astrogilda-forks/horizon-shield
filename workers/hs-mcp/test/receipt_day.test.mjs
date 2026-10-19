// 2026-10-19: a fair-price receipt is also listed under its UTC day, and GET /ledger/day/<date> serves that list, so
// the daily job can anchor it in JIDEC. No network: souba-db is served from the repository file, KV is a map.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import worker from "../src/mcp.js";

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log("PASS " + m); } else { fail++; console.log("FAIL " + m); } };
const DBTEXT = readFileSync(new URL("../../../data/souba-db.json", import.meta.url), "utf8");
globalThis.fetch = async (url) => {
  const u = String(url && url.url ? url.url : url);
  if (u.includes("/data/souba-db.json")) return new Response(DBTEXT, { headers: { "content-type": "application/json" } });
  return new Response("not here", { status: 404 });
};
function kv(failList) {
  const m = new Map();
  return { m, get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => { m.set(k, String(v)); }, delete: async (k) => { m.delete(k); },
    list: async ({ prefix = "", cursor, limit = 1000 } = {}) => {
      if (failList) throw new Error("kv down");
      const keys = [...m.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0, page = keys.slice(start, start + limit);
      const done = start + limit >= keys.length;
      return { keys: page.map((name) => ({ name })), list_complete: done, cursor: done ? undefined : String(start + limit) };
    } };
}
const CTX = { waitUntil() {}, passThroughOnException() {} };
const call = async (env, name, args) => {
  const r = await worker.fetch(new Request("https://mcp.horizonshield.dev/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) }), env, CTX);
  const t = await r.text(); return JSON.parse(t.match(/\{[\s\S]*\}/)[0]).result;
};
const get = (env, path) => worker.fetch(new Request("https://mcp.horizonshield.dev" + path), env, CTX);
const sha = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

globalThis.__HS_MEMO__ && globalThis.__HS_MEMO__.clear();
const K = kv(false), env = { RL_KV: K };
const a = await call(env, "verify_fair_price", { work: "外壁塗装 シリコン塗料 単価" });
const b = await call(env, "verify_fair_price", { work: "外壁塗装 ラジカル塗料 単価" });
const hashes = [a, b].map((x) => (JSON.stringify(x).match(/"claim_sha256":"([0-9a-f]{64})"/) || [])[1]).filter(Boolean);
ok(hashes.length === 2, "two receipts issued (" + hashes.length + ")");
const day = new Date().toISOString().slice(0, 10);
const r = await get(env, "/ledger/day/" + day);
const j = await r.json();
ok(r.status === 200 && j.schema === "hs-fair-price-receipt-day-v1" && j.complete === true, "GET /ledger/day/<today> answers a complete list");
ok(JSON.stringify(j.receipts) === JSON.stringify([...new Set(hashes)].sort()), "the list is the day's receipt hashes, sorted");
let recompute = true;
for (const h of j.receipts) {
  const one = await (await get(env, "/ledger/" + h)).json();
  recompute = recompute && sha(JSON.stringify(one.claim)) === h;
}
ok(recompute, "every listed receipt is served at /ledger/<sha> and recomputes");
const other = await (await get(env, "/ledger/day/2001-01-01")).json();
ok(other.count === 0 && other.complete === true, "a day with no receipts is an empty, complete list");
for (let i = 0; i < 2500; i++) K.m.set("rcptday:2001-01-02:" + sha(String(i)), "1");
const big = await (await get(env, "/ledger/day/2001-01-02")).json();
ok(big.count === 2500 && big.complete === true, "a day of 2500 receipts is read across pages (" + big.count + ")");
const down = await get({ RL_KV: kv(true) }, "/ledger/day/" + day);
const dj = await down.json();
ok(down.status === 503 && dj.read_failed === true, "a store that cannot be listed is a 503 read failure, never an empty day");
const bad = await get(env, "/ledger/day/2026-1-1");
ok(bad.status === 400, "a malformed date falls through to the per-receipt route and is refused");

console.log(fail ? `${fail} FAIL / ${pass} PASS` : `ALL PASS (${pass})`);
process.exit(fail ? 1 : 0);
