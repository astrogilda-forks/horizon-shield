/* 2026-10-13. Same mould as roster_read_failure_test.mjs, on the paths that test did not reach.
   resources/read and completion/complete called liveContractors but ignored read_ok, so a failed roster read gave
   yakumo://mall zero counts, yakumo://store/X "store not found" and completion no suggestions, all presented as fact.
   And a hearing: profile read that threw was treated as a missing profile, so the store was listed with thin data and
   nothing said so. This checks, on a copy of the real src with a mocked KV and fetch, that each failure is reported as
   a failure and each genuine absence keeps today's answer. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRCDIR = path.join(HERE, "src");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hsresread-"));
for (const f of fs.readdirSync(SRCDIR)) {
  if (!f.endsWith(".js")) continue;
  let body = fs.readFileSync(path.join(SRCDIR, f), "utf8");
  body = body.replace(/from "\.\/([a-z0-9_]+)\.js"/g, 'from "./$1.mjs"');
  fs.writeFileSync(path.join(TMP, f.replace(/\.js$/, ".mjs")), body);
}
const H = await import(path.join(TMP, "hearing.mjs"));
const worker = H.default;

const emptyKV = { list: async () => ({ keys: [], list_complete: true }), get: async () => null, put: async () => {} };
// One store in KV. hearingMode decides what the hearing: profile read does.
let hearingMode = "throw";
const STORE = { store_id: "s1", member_no: "No.001", company: "テスト工務店", area: "神奈川県", areas: ["平塚市"], works: ["リフォーム"], verification: "pending" };
const storeKV = {
  list: async () => ({ keys: [{ name: "store:s1" }], list_complete: true }),
  get: async (k) => {
    if (k === "store:s1") return STORE;
    if (k === "hearing:s1") {
      if (hearingMode === "throw") throw new Error("KV get failed (simulated)");
      if (hearingMode === "absent") return null;
      return { profile: { works: ["外壁塗装", "屋根"], areas_served: ["平塚市", "茅ヶ崎市"] } };
    }
    return null;
  },
  put: async () => {},
};
const env = (kv) => ({ HS_HEARING_KV: kv, PUBLIC_DATA_URL: "https://roster.redteam.invalid/yakumo-contractors.json" });
let mode = "down";
globalThis.fetch = async (u) => {
  if (String(u).startsWith("https://roster.redteam.invalid/")) {
    if (mode === "down") return new Response("upstream error", { status: 503 });
    if (mode === "empty") return new Response(JSON.stringify({ contractors: [], stats: {} }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response("", { status: 404 });
};
let fail = 0, n = 0;
const ok = (c, m, d = "") => { n++; console.log((c ? "ok   " : "FAIL ") + m + (c ? "" : "  " + String(d).slice(0, 220))); if (!c) fail++; };
const rpcCall = async (kv, method, params) => (await worker.fetch(new Request("https://hs-hearing.example.dev/mcp", { method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }), env(kv), { waitUntil() {} })).json();
const isRosterErr = (r) => !!(r.error && r.error.code !== -32002 && /roster_unavailable/.test(r.error.message) && r.error.data && r.error.data.roster_read === false);

// resources/read with the roster unreadable (KV empty, published roster answers 503)
mode = "down";
let r = await rpcCall(emptyKV, "resources/read", { uri: "yakumo://mall" });
ok(isRosterErr(r), "yakumo://mall on a failed read is a roster_unavailable error, not zero counts", JSON.stringify(r));
r = await rpcCall(emptyKV, "resources/read", { uri: "yakumo://store/No.001" });
ok(isRosterErr(r), "yakumo://store/No.001 on a failed read is a roster_unavailable error, not store not found", JSON.stringify(r));
r = await rpcCall(emptyKV, "resources/read", { uri: "yakumo://categories" });
ok(isRosterErr(r), "yakumo://categories on a failed read is a roster_unavailable error, not empty tallies", JSON.stringify(r));
r = await rpcCall(emptyKV, "resources/read", { uri: "yakumo://verification" });
ok(r.result && r.result.contents && r.result.contents[0].mimeType === "text/markdown", "yakumo://verification needs no roster and is still served", JSON.stringify(r).slice(0, 200));

// resources/read with the roster read and genuinely empty: today's answers, unchanged
mode = "empty";
r = await rpcCall(emptyKV, "resources/read", { uri: "yakumo://store/No.009" });
ok(r.error && r.error.code === -32002 && r.error.message === "store not found: No.009" && !("data" in r.error), "a genuinely absent store is still -32002 store not found, same wording", JSON.stringify(r));
r = await rpcCall(emptyKV, "resources/read", { uri: "yakumo://mall" });
ok(r.result && JSON.parse(r.result.contents[0].text).verified_count === 0, "a genuinely empty roster still gives yakumo://mall verified_count 0", JSON.stringify(r).slice(0, 200));

// completion/complete
mode = "down";
r = await rpcCall(emptyKV, "completion/complete", { ref: { type: "ref/prompt", name: "find_a_contractor" }, argument: { name: "work", value: "外" } });
ok(isRosterErr(r), "completion for work on a failed read is a roster_unavailable error, not an empty list", JSON.stringify(r));
mode = "empty";
r = await rpcCall(emptyKV, "completion/complete", { ref: { type: "ref/prompt", name: "find_a_contractor" }, argument: { name: "work", value: "外" } });
ok(r.result && r.result.completion && Array.isArray(r.result.completion.values) && r.result.completion.values.length === 0 && r.result.completion.total === 0, "completion on a genuinely empty roster still returns an empty values list", JSON.stringify(r));

// hearing: profile read inside contractorsFromStores
const listStores = async () => {
  const res = await rpcCall(storeKV, "tools/call", { name: "list_verified_stores", arguments: {} });
  const p = res.result && res.result.structuredContent;
  return p ? p.stores.concat(p.pending_stores) : null;
};
hearingMode = "throw";
let st = await listStores();
ok(st && st.length === 1 && st[0].profile_read_failed === true && /read failure/.test(st[0].profile_note || ""), "a hearing: read that throws keeps the store listed and marks profile_read_failed", JSON.stringify(st));
hearingMode = "absent";
st = await listStores();
ok(st && st.length === 1 && !("profile_read_failed" in st[0]) && st[0].works.join() === "リフォーム", "a genuinely absent hearing: record lists the thin store: works with no flag", JSON.stringify(st));
hearingMode = "present";
st = await listStores();
ok(st && st.length === 1 && !("profile_read_failed" in st[0]) && st[0].works.join() === "外壁塗装,屋根", "a present hearing: profile still supplies works, no flag", JSON.stringify(st));

fs.rmSync(TMP, { recursive: true, force: true });
if (fail) { console.log("落ちた: " + fail + " / " + n); process.exit(1); }
console.log("resource_read_failure " + n + "/" + n + " 通過");
