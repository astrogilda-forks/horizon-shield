// ops/no_swallowed_read.test.mjs
//
// ops/no_swallowed_read.mjs の試験。issue #13 の型 (読めなかった物を無かった物として書き戻す) の悪い例が
// 全部引っかかり、2026-10-13 に直した形 (readStatsRow, readRegistryForWrite, readOrder, kvFlag,
// kiraKvJsonStrict / ReadFailure, prevReadFailed の旗, removed = null の後の 503) が全部通ることを確かめる。
// 最後に、今の main を走査して終了コード 0 になることも確かめる。
//
//   node ops/no_swallowed_read.test.mjs
//
// 終了コード 0 = 全部通った、1 = どれかが落ちた。

import { reexecWithParser, analyzeSource, applyAllow } from "./no_swallowed_read.mjs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { writeFileSync, unlinkSync } from "node:fs";

reexecWithParser(import.meta.url);

const B = ["HS_VERIFY_KV", "US_ORDERS", "HS_HEARING_KV", "SEEN_STORE", "ORDERS", "KV"];

// ---------------------------------------------------------------- 悪い例 (引っかかること)
const BAD = [
  ["stats bump: {} default, then put (hs-us-report teardown before 4e315ccb)", ["a-catch", "b-parse"], `
async function bump(env, name, key) {
  let cur = {};
  try { cur = JSON.parse((await env.US_ORDERS.get(key)) || "{}") || {}; } catch { cur = {}; }
  cur[name] = (Number(cur[name]) || 0) + 1;
  await env.US_ORDERS.put(key, JSON.stringify(cur));
}`],
  ["history: swallowed read leaves prev null, then put replaces the history (hs-verify-gate before aab32d94)", ["a-catch"], `
async function recordHistory(env, key, entry) {
  let prev = null;
  try { prev = await env.HS_VERIFY_KV.get(key, "json"); } catch (_e) {}
  const entries = (prev && Array.isArray(prev.entries)) ? prev.entries : [];
  entries.push(entry);
  await env.HS_VERIFY_KV.put(key, JSON.stringify({ entries }));
}`],
  ["change feed: [] default declared before try, swallowed, then put", ["a-catch"], `
async function feed(env, item) {
  let changes = [];
  try { changes = (await env.HS_VERIFY_KV.get("changes:recent", "json")) || []; } catch (_e) {}
  changes.unshift(item);
  await env.HS_VERIFY_KV.put("changes:recent", JSON.stringify(changes));
}`],
  ["helper turns a failed read into {}, the caller writes the registry back (readRegistry before aab32d94)", ["a-helper"], `
const REGISTRY_KEY = "registry";
async function readRegistry(env) {
  try { return (await env.HS_VERIFY_KV.get(REGISTRY_KEY, "json")) || {}; }
  catch (_e) { return {}; }
}
async function writeRegistry(env, reg) { await env.HS_VERIFY_KV.put(REGISTRY_KEY, JSON.stringify(reg)); }
async function markDeclined(env, endpoint) {
  const reg = await readRegistry(env);
  reg[endpoint] = { ...(reg[endpoint] || {}), owner_declined_at: new Date().toISOString() };
  await writeRegistry(env, reg);
}`],
  [".catch(() => []) on a get, then put", ["a-dotcatch"], `
async function addItem(env, item) {
  const list = await env.KV.get("list", "json").catch(() => []);
  list.push(item);
  await env.KV.put("list", JSON.stringify(list));
}`],
  ["JSON.parse(get || \"{}\") in a try whose catch yields {} (readStats before 4e315ccb, no write)", ["b-parse"], `
async function readStats(env, days) {
  const out = [];
  for (const d of days) {
    let row = {};
    try { row = JSON.parse((await env.US_ORDERS.get("stats:" + d)) || "{}") || {}; } catch { row = {}; }
    out.push({ date: d, ...row });
  }
  return out;
}`],
  ["dedupe that fails open: a swallowed read inside the early exit, then put", ["a-catch"], `
async function ipn(env, txn) {
  try { if (await env.ORDERS.get("txn:" + txn)) return { duplicate: true }; } catch {}
  await env.ORDERS.put("txn:" + txn, "1");
  return { ok: true };
}`],
  ["helper returns null for both absent and failed, the absent branch writes a fresh record (hs-monitor getProspect)", ["a-helper"], `
async function getProspect(key, env) {
  try { const val = await env.SEEN_STORE.get(key); return val ? JSON.parse(val) : null; }
  catch { return null; }
}
async function scan(env, key, post) {
  const existing = await getProspect(key, env);
  if (existing && post.hot) {
    await env.SEEN_STORE.put(key, JSON.stringify({ ...existing, contactCount: existing.contactCount + 1 }));
  } else if (post.hot) {
    await env.SEEN_STORE.put(key, JSON.stringify({ firstTitle: post.title, contactCount: 1 }));
  }
}`],
  ["alias of a binding, null default, the absent branch creates a new store (hs-hearing startWithIndustry)", ["a-catch"], `
async function start(env, sid) {
  const kv = env.HS_HEARING_KV;
  let store = null;
  try { store = await kv.get("store:" + sid, "json"); } catch (_e) { store = null; }
  if (!store) {
    store = { store_id: "new" };
    await kv.put("store:new", JSON.stringify(store));
  }
}`],
  ["removed list: [] in catch, then put appends to it (hs-verify-gate before aab32d94)", ["a-catch"], `
async function remove(env, stone) {
  let removed = [];
  try { removed = (await env.HS_VERIFY_KV.get("removed", "json")) || []; } catch (_e) { removed = []; }
  removed.push(stone);
  await env.HS_VERIFY_KV.put("removed", JSON.stringify(removed));
}`],
];

// ---------------------------------------------------------------- 直した形 (通ること)
const GOOD = [
  ["readStatsRow: null is the failure mark, the caller skips the put (4e315ccb)", `
async function readStatsRow(env, day) {
  let raw;
  try { raw = await env.US_ORDERS.get("stats:" + day); } catch { return null; }
  try { return JSON.parse(raw || "{}") || {}; } catch { return null; }
}
async function bump(env, name, day) {
  const cur = await readStatsRow(env, day);
  if (cur === null) return;
  cur[name] = (Number(cur[name]) || 0) + 1;
  await env.US_ORDERS.put("stats:" + day, JSON.stringify(cur));
}`],
  ["recordHistory: the catch sets prevReadFailed and the put is under if (!prevReadFailed) (aab32d94)", `
async function recordHistory(env, key, entry) {
  let prev = null, prevReadFailed = false;
  try { prev = await env.HS_VERIFY_KV.get(key, "json"); } catch (_e) { prevReadFailed = true; }
  const entries = (prev && Array.isArray(prev.entries)) ? prev.entries : [];
  entries.push(entry);
  if (!prevReadFailed) {
    try { await env.HS_VERIFY_KV.put(key, JSON.stringify({ entries })); } catch (_e) {}
  }
}`],
  ["readRegistryForWrite: null on failure, {} when absent, the writer answers 503 (aab32d94)", `
const REGISTRY_KEY = "registry";
async function readRegistryForWrite(env) {
  if (!env || !env.HS_VERIFY_KV) return null;
  try { return (await env.HS_VERIFY_KV.get(REGISTRY_KEY, "json")) || {}; }
  catch (_e) { return null; }
}
async function writeRegistry(env, reg) { await env.HS_VERIFY_KV.put(REGISTRY_KEY, JSON.stringify(reg)); }
async function watch(env, ep) {
  const reg = await readRegistryForWrite(env);
  if (!reg) return new Response("registry_read_failed", { status: 503 });
  reg[ep] = { added_at: Date.now() };
  await writeRegistry(env, reg);
}`],
  ["removed list: null in catch, not an array answers 503 before the put (aab32d94)", `
async function remove(env, stone) {
  let removed;
  try { removed = (await env.HS_VERIFY_KV.get("removed", "json")) || []; } catch (_e) { removed = null; }
  if (!Array.isArray(removed)) return new Response("removed_list_read_failed", { status: 503 });
  removed.push(stone);
  await env.HS_VERIFY_KV.put("removed", JSON.stringify(removed));
}`],
  ["kvFlag: yes / no / failed, a failed read writes nothing (e2f77aa0)", `
async function kvFlag(env, key) {
  try { return (await env.SEEN_STORE.get(key)) ? "yes" : "no"; } catch (e) {
    console.log("[kv] read failed key=" + key);
    return "failed";
  }
}
async function promote(env, gid, uid) {
  const st = await kvFlag(env, "groupPartner:" + gid);
  if (st === "failed") return;
  if (st === "yes") await env.SEEN_STORE.put("partner:" + uid, "1");
}`],
  ["readOrder: { failed: true } is distinct from { absent: true }, the IPN answers 503 (4e315ccb)", `
const readOrder = async (env, id) => {
  let raw;
  try { raw = await env.US_ORDERS.get("order:" + id); } catch { return { failed: true }; }
  if (raw == null) return { absent: true };
  try { return { order: JSON.parse(raw) }; } catch { return { failed: true }; }
};
async function handleIpn(env, id, txn) {
  const rd = await readOrder(env, id);
  if (rd.failed) return new Response("order_read_failed", { status: 503 });
  let seen;
  try { seen = await env.US_ORDERS.get("txn:" + txn); } catch { return new Response("txn_read_failed", { status: 503 }); }
  if (seen) return new Response("duplicate");
  await env.US_ORDERS.put("txn:" + txn, rd.order ? rd.order.id : "");
}`],
  ["kiraKvJsonStrict: the reader throws ReadFailure, the read-modify-write never sees an empty list (b1297774)", `
class ReadFailure extends Error {}
async function kiraKvJsonStrict(env, key) {
  let raw;
  try { raw = await env.SEEN_STORE.get(key); } catch (e) { throw new ReadFailure(key); }
  return raw ? JSON.parse(raw) : null;
}
async function convAppend(env, key, msg) {
  const cur = (await kiraKvJsonStrict(env, key)) || [];
  cur.push(msg);
  await env.SEEN_STORE.put(key, JSON.stringify(cur));
}`],
  ["the put is inside the try: a failed read skips the whole block (hs-kira-line partner promote)", `
async function mark(env, uid, gid) {
  try {
    const rec = await env.SEEN_STORE.get("partner:" + uid);
    if (rec) await env.SEEN_STORE.put("groupPartner:" + gid, "1");
  } catch (_e) {}
}`],
  ["a read in one route that returns, a write in another route of the same fetch", `
export default { async fetch(request, env) {
  const path = new URL(request.url).pathname;
  if (path === "/public-profile") {
    let hp = null, done = false;
    try { const h = await env.HS_HEARING_KV.get("hearing:x", "json"); hp = h && h.profile; done = !!(h && h.completed); } catch (_e) {}
    return new Response(JSON.stringify({ hp, done }));
  }
  if (path === "/admin/mark") {
    await env.HS_HEARING_KV.put("mark", "1");
    return new Response("ok");
  }
} };`],
  ["null default guarded on the falsy side before the write (hs-hearing untouched store)", `
async function ask(env, sid) {
  let s0 = null;
  try { s0 = await env.HS_HEARING_KV.get("store:" + sid, "json"); } catch (_e) { s0 = null; }
  const untouched = s0 && !s0.industry;
  if (untouched) {
    await env.HS_HEARING_KV.put("intake:" + sid, JSON.stringify({ state: "awaiting_industry" }));
  }
}`],
];

let pass = 0, fail = 0;
const ok = (cond, label, extra) => {
  if (cond) { pass++; console.log("  ok   " + label); }
  else { fail++; console.log("  FAIL " + label + (extra ? "\n       " + extra : "")); }
};

console.log("bad snippets (must be flagged):");
let badFlagged = 0;
for (const [label, kinds, src] of BAD) {
  const hits = analyzeSource(src, { bindings: B });
  const got = new Set(hits.map((h) => h.kind));
  const all = kinds.every((k) => got.has(k));
  if (all) badFlagged++;
  ok(all, label, "expected " + kinds.join("+") + ", got " + JSON.stringify(hits.map((h) => h.kind + "@" + h.line)));
}

console.log("good snippets (fixed patterns, must pass):");
let goodPassed = 0;
for (const [label, src] of GOOD) {
  const hits = analyzeSource(src, { bindings: B });
  if (hits.length === 0) goodPassed++;
  ok(hits.length === 0, label, "unexpected " + JSON.stringify(hits.map((h) => h.kind + "@" + h.line + " " + h.why)));
}

console.log("allowlist:");
{
  const hit = { rel: "workers/x/src/a.js", fn: "f", kind: "a-catch", line: 3, src: "" };
  const r1 = applyAllow([hit], [{ file: "workers/x/src/a.js", fn: "f", kind: "a-catch" }]);
  ok(r1.remaining.length === 1 && r1.bad.length === 1, "an entry without a reason does not allow anything and is reported");
  const r2 = applyAllow([hit, { ...hit, line: 9 }], [{ file: "workers/x/src/a.js", fn: "f", kind: "a-catch", reason: "a reason long enough" }]);
  ok(r2.allowed.length === 1 && r2.remaining.length === 1, "one entry allows one hit; a second hit in the same function is new");
  const r3 = applyAllow([], [{ file: "workers/gone.js", fn: "f", kind: "a-catch", reason: "a reason long enough" }]);
  ok(r3.stale.length === 1, "an entry that matches nothing is reported as stale");
}

console.log("current tree:");
{
  const guard = path.join(path.dirname(fileURLToPath(import.meta.url)), "no_swallowed_read.mjs");
  const r = spawnSync(process.execPath, [guard], { encoding: "utf8" });
  ok(r.status === 0, "node ops/no_swallowed_read.mjs exits 0 on this tree with the allowlist", (r.stdout || "").split("\n").slice(0, 12).join("\n       "));
  // 未追跡の .js (手元に残った古い写し) は数えない。git 管理下の木でだけ確かめる。
  const root = path.resolve(path.dirname(guard), "..");
  const inGit = spawnSync("git", ["-C", root, "rev-parse", "--is-inside-work-tree"], { encoding: "utf8" }).stdout?.trim() === "true";
  if (inGit) {
    const tmp = path.join(root, "workers", "hs-monitor", "src", "zz_untracked_guard_probe_tmp.js");
    writeFileSync(tmp, BAD[0][2]);
    try {
      const r2 = spawnSync(process.execPath, [guard, "--list"], { encoding: "utf8" });
      const listed = (r2.stdout || "").includes("zz_untracked_guard_probe_tmp.js");
      ok(r2.status === 0 && !listed, "an untracked .js in workers/*/src is not scanned (CI and a local checkout agree)", (r2.stdout || "").split("\n").filter((l) => /zz_untracked|new$/.test(l)).join("\n       "));
    } finally { unlinkSync(tmp); }
  }
}

console.log(`\n=== bad flagged ${badFlagged}/${BAD.length}, good passed ${goodPassed}/${GOOD.length}, checks ${pass} ok, ${fail} failed ===`);
process.exit(fail ? 1 : 0);
