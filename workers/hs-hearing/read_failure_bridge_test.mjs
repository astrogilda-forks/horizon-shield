/* 2026-10-13 (issue #13, third pass). The KIRA bridge and putStore, when a read they depend on FAILS.
   Offline: a copy of the real src, KV and fetch mocked.

   A failed read is not an absent one:
     - intake:<uid> that cannot be read must not restart a conversation waiting for its industry or for a person;
     - store:<sid> that cannot be read must not be replaced by a new store and token (line2store repointed);
     - putStore must not write when it cannot re-read the saved store (the merge keeps _writes, asked, pending);
     - the daily tick skips such a store, writes nothing for it, and goes on with the others.
   Every "fix" check fails on d118ad9e and passes after the fix. The "guard" checks pin the success path and pass on
   both. node workers/hs-hearing/read_failure_bridge_test.mjs */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRCDIR = path.join(HERE, "src");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hsbridgefail-"));
for (const f of fs.readdirSync(SRCDIR)) {
  if (!f.endsWith(".js")) continue;
  let body = fs.readFileSync(path.join(SRCDIR, f), "utf8");
  body = body.replace(/from "\.\/([a-z0-9_]+)\.js"/g, 'from "./$1.mjs"');
  fs.writeFileSync(path.join(TMP, f.replace(/\.js$/, ".mjs")), body);
}
const H = await import(path.join(TMP, "hearing.mjs") + "?v=" + Math.random());
const AP = await import(path.join(TMP, "autopilot.mjs"));
const worker = H.default;

globalThis.fetch = async () => new Response("{}", { status: 200 });

let fail = 0, checks = 0, guards = 0;
function check(label, cond, detail) {
  checks++;
  console.log((cond ? "  ok   " : "  NG   ") + label + (detail ? "  " + detail : ""));
  if (!cond) fail++;
}
function guard(label, cond, detail) {
  guards++;
  console.log((cond ? "  ok   " : "  NG   ") + "[guard] " + label + (detail ? "  " + detail : ""));
  if (!cond) fail++;
}

// failGet(key, n): n counts the reads of this key so far in this env (1 for the first read).
function makeEnv(failGet) {
  const kv = new Map();
  const puts = [];
  const reads = new Map();
  return {
    _kv: kv, _puts: puts,
    KIRA_BRIDGE_KEY: "bk-test",
    RESEND_API_KEY: "test-key",
    HS_HEARING_KV: {
      get: async (k, type) => {
        const n = (reads.get(k) || 0) + 1; reads.set(k, n);
        if (failGet && failGet(k, n)) throw new Error("KV get failed (simulated)");
        if (!kv.has(k)) return null;
        const v = kv.get(k);
        return type === "json" ? JSON.parse(v) : v;
      },
      put: async (k, v) => { puts.push(k); kv.set(k, v); },
      delete: async (k) => { puts.push("delete:" + k); kv.delete(k); },
      list: async (q) => {
        const p = (q && q.prefix) || "";
        return { keys: [...kv.keys()].filter((k) => k.startsWith(p)).map((name) => ({ name })), list_complete: true };
      },
    },
  };
}
const UID = "U" + "1".repeat(32);
const SID = "kira-oldstore";
const bridge = async (env, text) => {
  const res = await worker.fetch(new Request("https://hearing.example.dev/kira-bridge", {
    method: "POST", headers: { "content-type": "application/json", "X-Bridge-Key": "bk-test" },
    body: JSON.stringify({ userId: UID, text, kira_decides: true }),
  }), env, { waitUntil() {} });
  let body = null; try { body = await res.json(); } catch (_e) {}
  return { status: res.status, body };
};
const UNTOUCHED = JSON.stringify({ store_id: SID, company: "", areas: [], works: [], status: "onboarding", source: "kira-line", token: "ht_oldtoken0000", autopilot: { _writes: [{ at: "2026-10-01T00:00:00Z", by: "seed" }] } });

console.log("\n1) intake cannot be read: a conversation waiting for its industry (store linked)");
{
  const intake = JSON.stringify({ state: "awaiting_industry", store_id: SID, asked_at: "2026-10-12T00:00:00Z", retries: 1 });
  const env = makeEnv((k) => k === "intake:" + UID);
  env._kv.set("line2store:" + UID, SID);
  env._kv.set("store:" + SID, UNTOUCHED);
  env._kv.set("intake:" + UID, intake);
  const r = await bridge(env, "よろしくお願いします");
  check("the bridge answers 503 intake_read_failed", r.status === 503 && r.body && r.body.ok === false && r.body.error === "intake_read_failed", r.status + " " + JSON.stringify(r.body).slice(0, 120));
  check("nothing is written (intake not overwritten, no store, no index)", env._puts.length === 0 && env._kv.get("intake:" + UID) === intake, env._puts.join(","));
}

console.log("\n2) intake cannot be read: a new person already asked for the industry (no store yet)");
{
  const intake = JSON.stringify({ state: "awaiting_industry", store_id: null, asked_at: "2026-10-12T00:00:00Z", retries: 1 });
  const env = makeEnv((k) => k === "intake:" + UID);
  env._kv.set("intake:" + UID, intake);
  const r = await bridge(env, "えーと");
  check("503 intake_read_failed, the industry question is not asked again", r.status === 503 && r.body && r.body.error === "intake_read_failed" && !(r.body.reply || "").length, r.status + " " + JSON.stringify(r.body).slice(0, 120));
  check("intake not reset (retries kept)", env._puts.length === 0 && env._kv.get("intake:" + UID) === intake, env._puts.join(","));
}

console.log("\n3) the store cannot be read when the industry is decided");
{
  const intake = JSON.stringify({ state: "awaiting_industry", store_id: SID, asked_at: "2026-10-12T00:00:00Z", retries: 0 });
  const env = makeEnv((k) => k === "store:" + SID);
  env._kv.set("line2store:" + UID, SID);
  env._kv.set("store2line:" + SID, UID);
  env._kv.set("store:" + SID, UNTOUCHED);
  env._kv.set("intake:" + UID, intake);
  const r = await bridge(env, "訪問看護です");
  check("the bridge answers 503 store_read_failed", r.status === 503 && r.body && r.body.error === "store_read_failed", r.status + " " + JSON.stringify(r.body).slice(0, 120));
  check("no new store or token, line2store still points at the existing store", env._puts.length === 0 && env._kv.get("line2store:" + UID) === SID && ![...env._kv.keys()].some((k) => k.startsWith("htok:")), env._puts.join(","));
  check("the existing store is not orphaned (intake kept for the next message)", env._kv.get("intake:" + UID) === intake && env._kv.get("store:" + SID) === UNTOUCHED);
}

console.log("\n4) the store reads once, then the re-read inside putStore fails (request path)");
{
  const intake = JSON.stringify({ state: "awaiting_industry", store_id: SID, asked_at: "2026-10-12T00:00:00Z", retries: 0 });
  const env = makeEnv((k, n) => k === "store:" + SID && n === 2);
  env._kv.set("line2store:" + UID, SID);
  env._kv.set("store:" + SID, UNTOUCHED);
  env._kv.set("intake:" + UID, intake);
  const r = await bridge(env, "訪問看護です");
  check("503 store_read_failed (not a 200 after a write that dropped the ledger, not a bare 500)", r.status === 503 && r.body && r.body.error === "store_read_failed", r.status + " " + JSON.stringify(r.body).slice(0, 120));
  check("store:<sid> not written (its _writes ledger kept)", !env._puts.includes("store:" + SID) && env._kv.get("store:" + SID) === UNTOUCHED, env._puts.join(","));
}

console.log("\n5) putStore: the saved store cannot be re-read");
{
  const saved = { store_id: "s-ledger", company: "A", autopilot: { _writes: [{ at: "2026-10-01T00:00:00Z", by: "seed" }], asked: [{ qid: "q_areas", at: "2026-10-02T00:00:00Z" }], pending: { qids: ["q_areas"], sent_at: "2026-10-02T00:00:00Z" } } };
  const env = makeEnv((k) => k === "store:s-ledger");
  env._kv.set("store:s-ledger", JSON.stringify(saved));
  let err = null;
  try { await AP.putStore(env, { store_id: "s-ledger", company: "A2", autopilot: {} }, "test"); } catch (e) { err = e; }
  check("it throws store_read_failed", !!err && err.code === "store_read_failed", err ? String(err.message) : "no throw");
  check("nothing written: _writes, asked and pending survive", !env._puts.length && env._kv.get("store:s-ledger") === JSON.stringify(saved), env._puts.join(","));
  const env2 = makeEnv();
  env2._kv.set("store:s-ledger", JSON.stringify(saved));
  await AP.putStore(env2, { store_id: "s-ledger", company: "A2", autopilot: {} }, "test");
  const w = JSON.parse(env2._kv.get("store:s-ledger"));
  guard("normal: the put merges the saved ledger", w.company === "A2" && w.autopilot._writes.length === 2 && w.autopilot.asked.length === 1 && w.autopilot._pending_overwritten.length === 1);
}

console.log("\n6) daily tick: one store cannot be re-read, the other is fine");
{
  const mk = (sid) => ({ store_id: sid, email: sid + "@example.invalid", company: "Co " + sid, industry: "nursing", verification: "verified", autopilot: { _writes: [{ at: "2026-10-01T00:00:00Z", by: "seed" }] } });
  const env = makeEnv((k) => k === "store:s-bad");
  const stores = [mk("s-bad"), mk("s-good")];
  for (const s of stores) {
    env._kv.set("store:" + s.store_id, JSON.stringify(s));
    env._kv.set("hearing:" + s.store_id, JSON.stringify({ profile: { industry: "nursing", company: s.company } }));
  }
  const savedBad = env._kv.get("store:s-bad");
  let log = null, err = null;
  try { log = await AP.runDailyTick(env, { listAllStores: async () => stores.map((s) => JSON.parse(JSON.stringify(s))) }); } catch (e) { err = e; }
  check("the tick does not stop and s-bad is not written", !err && !env._puts.includes("store:s-bad") && env._kv.get("store:s-bad") === savedBad, err ? String(err) : env._puts.filter((k) => k.startsWith("store:")).join(","));
  check("the skip is named in the log", !!log && log.skipped.includes("s-bad:store_read_failed"), log ? JSON.stringify(log.skipped) : "-");
  guard("the other store is still written", !!log && env._puts.includes("store:s-good"));
}

console.log("\n7) success path of the bridge is unchanged");
{
  const intake = JSON.stringify({ state: "awaiting_industry", store_id: SID, asked_at: "2026-10-12T00:00:00Z", retries: 0 });
  const env = makeEnv();
  env._kv.set("line2store:" + UID, SID);
  env._kv.set("store:" + SID, UNTOUCHED);
  env._kv.set("intake:" + UID, intake);
  const r = await bridge(env, "訪問看護です");
  const st = JSON.parse(env._kv.get("store:" + SID));
  guard("normal: 200, the existing store gets the industry, intake cleared", r.status === 200 && r.body.ok === true && st.industry === "nursing" && env._kv.get("line2store:" + UID) === SID && !env._kv.has("intake:" + UID), r.status + " " + st.industry);
  const env2 = makeEnv();
  const r2 = await bridge(env2, "よろしくお願いします");
  guard("normal: a first message with no industry asks for it and opens intake", r2.status === 200 && r2.body.ok === true && JSON.parse(env2._kv.get("intake:" + UID)).state === "awaiting_industry");
}

console.log("\n8) version");
{
  const r = await worker.fetch(new Request("https://hearing.example.dev/health"), makeEnv(), { waitUntil() {} });
  const j = await r.json();
  check("/health version is 2.3.2-rmw-20261013", j.version === "2.3.2-rmw-20261013", j.version);
}

fs.rmSync(TMP, { recursive: true, force: true });
console.log("\nchecks: " + checks + ", guards: " + guards + ", failed: " + fail);
const EXPECT = 14, EXPECT_GUARDS = 4;
if (checks < EXPECT || guards < EXPECT_GUARDS) { console.log("fewer checks than expected (" + EXPECT + " + " + EXPECT_GUARDS + " guards)"); fail++; }
if (fail) { console.log("落ちた: " + fail); process.exit(1); }
console.log("read_failure_bridge " + checks + "/" + checks + " 通過 (guard " + guards + ")");
