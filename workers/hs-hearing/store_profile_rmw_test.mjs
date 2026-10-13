/* 2026-10-13. ops/concurrency_audit_20261013.md, findings H2 and H3.
   H2: store:<sid> is read, changed and put back whole by the LINE and email webhooks, the daily autopilot and the
       operator. Two of them in flight at once: the later put wins whole, and a pending question or a needs_human flag
       set by the earlier one is gone. putStore named it (_pending_overwritten) and did not prevent it.
   H3: hearing:<sid> (the profile) is written whole by the form, the email or LINE reply, the estimate update and the
       operator. The same shape of loss: one channel's answers are overwritten by another channel's older copy.
   Fix under test: every write to those two keys goes through the per store Durable Object (DispatchGateDO, id
   rmw:<key>, path /rmw), which reads KV, applies a named mutation, writes KV and keeps the written copy as a floor.
   Offline: a copy of the real src, KV mocked, the DO class run on an in-memory state whose blockConcurrencyWhile is an
   async queue (one block at a time, like the real one). Nothing leaves this machine.
   Expected on the code before the fix: the two-writer cases lose one update, the stale-read case resurrects the older
   record, the fail-closed case writes anyway, /health has no store_writes mark. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRCDIR = path.join(HERE, "src");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hsrmw-"));
for (const f of fs.readdirSync(SRCDIR)) {
  if (!f.endsWith(".js")) continue;
  let body = fs.readFileSync(path.join(SRCDIR, f), "utf8");
  body = body.replace(/from "\.\/([a-z0-9_]+)\.js"/g, 'from "./$1.mjs"');
  fs.writeFileSync(path.join(TMP, f.replace(/\.js$/, ".mjs")), body);
}
const worker = (await import(path.join(TMP, "hearing.mjs"))).default;
const AP = await import(path.join(TMP, "autopilot.mjs"));
const DG = await import(path.join(TMP, "dispatch_do.mjs"));
globalThis.fetch = async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } });

let fail = 0, n = 0;
const ok = (c, msg, d = "") => { n++; console.log((c ? "ok   " : "FAIL ") + msg + (c ? "" : "  " + String(d).slice(0, 300))); if (!c) fail++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* KV mock. Two modes.
   barrier: every read of a key in `race` waits until two readers are inside (both read before either writes), which
            KV allows; a lone reader is released after 150 ms.
   stale:   a value written less than staleMs ago is not yet visible to get (KV is eventually consistent; the real
            bound is about 60 s, here 400 ms). */
function mockKV(opts = {}) {
  const race = new Set(opts.race || []);
  const staleMs = opts.staleMs || 0;
  const hist = new Map();   // key -> [{ v, t }]
  let waiting = [];
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= 2) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, 150);
  });
  const visible = (k) => {
    const h = hist.get(k) || [];
    const cut = Date.now() - staleMs;
    for (let i = h.length - 1; i >= 0; i--) if (h[i].t <= cut) return h[i].v;
    return null;
  };
  const parse = (v, type) => (v == null ? null : (type === "json" || (type && type.type === "json")) ? JSON.parse(v) : v);
  return {
    hist,
    latest(k) { const h = hist.get(k) || []; return h.length ? h[h.length - 1].v : null; },
    seed(k, v) { hist.set(k, [{ v: typeof v === "string" ? v : JSON.stringify(v), t: Date.now() - 10 * 60000 }]); },
    async get(k, type) { if (race.has(k)) await arrive(); return parse(visible(k), type); },
    async getWithMetadata(k) { return { value: visible(k), metadata: null }; },
    async put(k, v) { await Promise.resolve(); if (!hist.has(k)) hist.set(k, []); hist.get(k).push({ v: typeof v === "string" ? v : String(v), t: Date.now() }); },
    async delete(k) { hist.delete(k); },
    async list(o) { const p = (o && o.prefix) || ""; return { keys: [...hist.keys()].filter((k) => k.startsWith(p)).sort().map((name) => ({ name })), list_complete: true }; },
  };
}

/* In-memory Durable Object state. blockConcurrencyWhile is an async queue: one block at a time, the next starts when
   the previous settled. Storage reads and writes yield once so that nothing serialises by accident. */
function fakeState() {
  const map = new Map();
  let chain = Promise.resolve();
  const tick = () => new Promise((r) => setTimeout(r, 0));
  return {
    _map: map,
    storage: {
      get: async (k) => { await tick(); return map.has(k) ? map.get(k) : undefined; },
      put: async (k, v) => { await tick(); map.set(k, v); },
      delete: async (k) => { await tick(); map.delete(k); },
    },
    blockConcurrencyWhile: (fn) => { const next = chain.then(() => fn()); chain = next.then(() => {}, () => {}); return next; },
  };
}
// A DurableObjectNamespace stand in: one real DispatchGateDO per id, each on its own serialising state.
function fakeNamespace(envRef) {
  const dos = new Map(), states = new Map();
  return {
    _dos: dos, _states: states,
    idFromName: (name) => name,
    get: (id) => ({
      fetch: (u, init) => {
        if (!dos.has(id)) { const st = fakeState(); states.set(id, st); dos.set(id, new DG.DispatchGateDO(st, envRef.env)); }
        return dos.get(id).fetch(new Request(u, init));
      },
    }),
  };
}
const ADMIN = "test-admin";
function mkEnv(kvOpts, withDO = true) {
  const kv = mockKV(kvOpts);
  const ref = {};
  ref.env = { HS_HEARING_KV: kv, HEARING_ADMIN_SECRET: ADMIN };
  if (withDO) ref.env.DISPATCH_DO = fakeNamespace(ref);
  return { kv, env: ref.env };
}
const SID = "s1";
const baseStore = () => ({ store_id: SID, member_no: "No.001", company: "テスト工務店", status: "hearing", industry: "construction", autopilot: {} });
const readStore = (kv) => JSON.parse(kv.latest("store:" + SID));
const readHearing = (kv) => JSON.parse(kv.latest("hearing:" + SID));
const req = (env, url, init) => worker.fetch(new Request("https://hearing.example.dev" + url, init), env, { waitUntil() {} });
const adminPost = (env, p, body) => req(env, p, { method: "POST", headers: { "X-Admin-Key": ADMIN, "content-type": "application/json" }, body: JSON.stringify(body) });

/* 1. H2: the autopilot sets a pending question while a webhook sets needs_human on the same store. Both must stay. */
console.log("1. store: a pending question and a needs_human flag written at the same time");
{
  const { kv, env } = mkEnv({ race: ["store:" + SID] });
  kv.seed("store:" + SID, baseStore());
  await AP.putStore(env, readStore(kv), "seed");           // first write: from here on every copy carries the version stamp
  const A = readStore(kv), B = readStore(kv);
  A.autopilot.pending = { qids: ["q_areas"], text: "対応エリアを", sent_at: "2026-10-13T01:00:00.000Z", via: "followup" };
  A.autopilot.asked = [{ qid: "q_areas", at: "2026-10-13T01:00:00.000Z" }];
  B.autopilot.needs_human = { since: "2026-10-13T01:00:01.000Z", why: "金額の問い合わせ" };
  B.status = "hearing_done";
  const [ra, rb] = await Promise.allSettled([AP.putStore(env, A, "autopilot"), AP.putStore(env, B, "line")]);
  ok(ra.status === "fulfilled" && rb.status === "fulfilled", "both writes answered", (ra.reason || rb.reason));
  const s = readStore(kv);
  ok(!!(s.autopilot.pending && s.autopilot.pending.sent_at === "2026-10-13T01:00:00.000Z"), "the pending question survives", JSON.stringify(s.autopilot.pending));
  ok(!!(s.autopilot.needs_human && s.autopilot.needs_human.why === "金額の問い合わせ"), "the needs_human flag survives", JSON.stringify(s.autopilot.needs_human));
  ok(s.status === "hearing_done", "the status change survives", s.status);
  ok((s.autopilot.asked || []).length === 1, "asked ledger kept (as before)", JSON.stringify(s.autopilot.asked));
  ok(!(s.autopilot._pending_overwritten || []).length, "nothing had to be recorded as overwritten", JSON.stringify(s.autopilot._pending_overwritten));
  ok((s.autopilot._writes || []).length === 3, "three writes in the ledger (seed, autopilot, line)", JSON.stringify(s.autopilot._writes));
}

/* 2. H2: a reply clears the pending question while another writer touches an unrelated field. The clear must stand
      (the old detection could not tell a deliberate clear from a copy that never had the question). */
console.log("2. store: a cleared pending question is not put back by a concurrent unrelated write");
{
  const { kv, env } = mkEnv({ race: ["store:" + SID] });
  const st = baseStore();
  st.autopilot.pending = { qids: ["q_areas"], text: "対応エリアを", sent_at: "2026-10-13T01:00:00.000Z", via: "followup" };
  kv.seed("store:" + SID, st);
  await AP.putStore(env, readStore(kv), "seed");
  const A = readStore(kv), B = readStore(kv);
  A.autopilot.pending = null;            // the reply came; settlePendingOnAnswer does this
  A.autopilot.penalty = 0;
  B.autopilot.penalty = 2;               // the daily tick raised the penalty on its older copy
  B.autopilot.last_followup_at = "2026-10-13T02:00:00.000Z";
  await Promise.all([AP.putStore(env, A, "line"), AP.putStore(env, B, "runDailyTick")]);
  const s = readStore(kv);
  ok(!s.autopilot.pending, "pending stays cleared", JSON.stringify(s.autopilot.pending));
  ok(s.autopilot.last_followup_at === "2026-10-13T02:00:00.000Z", "the other writer's field survives", s.autopilot.last_followup_at);
  ok(s.autopilot.penalty === 2, "both changed penalty: the later writer wins and it is named", s.autopilot.penalty);
  ok(((s.autopilot._rmw_conflicts || [])[0] || { keys: [] }).keys.includes("autopilot.penalty"), "the conflict is recorded", JSON.stringify(s.autopilot._rmw_conflicts));
}

/* 3. H2: both writers set a pending question. The newer question wins, the older is not resurrected. */
console.log("3. store: two pending questions at once, the newer one stands");
{
  const { kv, env } = mkEnv({ race: ["store:" + SID] });
  kv.seed("store:" + SID, baseStore());
  await AP.putStore(env, readStore(kv), "seed");
  const A = readStore(kv), B = readStore(kv);
  A.autopilot.pending = { qids: ["q_areas"], sent_at: "2026-10-13T01:00:00.000Z" };
  B.autopilot.pending = { qids: ["q_story"], sent_at: "2026-10-13T01:00:05.000Z" };
  await Promise.all([AP.putStore(env, B, "b"), AP.putStore(env, A, "a")]);   // the older question is written last
  const s = readStore(kv);
  ok(s.autopilot.pending && s.autopilot.pending.qids[0] === "q_story", "the newer pending question wins", JSON.stringify(s.autopilot.pending));
}

/* 4. H3: the form and the operator write the profile at the same time. Both changes must stay. */
console.log("4. hearing: a form answer and a profile-patch at the same time");
{
  const { kv, env } = mkEnv({ race: ["hearing:" + SID] });
  kv.seed("store:" + SID, baseStore());
  kv.seed("htok:tok1", { store_id: SID, member_no: "No.001", company: "テスト工務店" });
  kv.seed("hearing:" + SID, { store_id: SID, profile: { store_id: SID, company: "テスト工務店", area: "平塚市", works: ["外壁塗装"], industry: "construction" }, completed: true });
  const form = req(env, "/h/tok1", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ company: "テスト工務店", area: "平塚市", works: ["外壁塗装"], story: "創業30年、平塚で外壁を塗ってきました。" }) });
  const patch = adminPost(env, "/admin/profile-patch", { store_id: SID, fields: { rep: "山田 太郎" } });
  const [rf, rp] = await Promise.all([form, patch]);
  ok(rf.status === 200, "form POST 200", rf.status + " " + (await rf.clone().text()).slice(0, 120));
  ok(rp.status === 200, "profile-patch 200", rp.status + " " + (await rp.clone().text()).slice(0, 120));
  const h = readHearing(kv);
  ok(h.profile.story === "創業30年、平塚で外壁を塗ってきました。", "the form's answer survives", JSON.stringify(h.profile.story));
  ok(h.profile.rep === "山田 太郎", "the operator's patch survives", JSON.stringify(h.profile.rep));
  ok(Array.isArray(h.profile.edits) && h.profile.edits.some((e) => (e.fields || []).includes("rep")), "the patch left its edit mark", JSON.stringify(h.profile.edits));
}

/* 5. H3: an estimate arrives while the operator resets the audit list; the LINE reply and the estimate overlap. */
console.log("5. hearing: two estimate updates at once (set-estimates and a second append)");
{
  const { kv, env } = mkEnv({ race: ["hearing:" + SID] });
  kv.seed("store:" + SID, baseStore());
  kv.seed("hearing:" + SID, { store_id: SID, profile: { store_id: SID, company: "テスト工務店", area: "平塚市", works: ["外壁塗装"], estimates_for_audit: [{ work: "古い", amount: "1" }] } });
  const a = adminPost(env, "/admin/set-estimates", { store_id: SID, estimates: [{ work: "外壁塗装", amount: "1200000" }] });
  const b = adminPost(env, "/admin/set-estimates", { store_id: SID, estimates: [{ work: "屋根塗装", amount: "800000" }] });
  const [ra, rb] = await Promise.all([a, b]);
  ok(ra.status === 200 && rb.status === 200, "both 200", ra.status + " " + rb.status);
  const h = readHearing(kv);
  const works = (h.profile.estimates_for_audit || []).map((e) => e.work).sort();
  ok(works.length === 2 && works.includes("外壁塗装") && works.includes("屋根塗装"), "both appended estimates are on the list", JSON.stringify(h.profile.estimates_for_audit));
  ok(!works.includes("古い"), "the reset removed the old one", works.join(","));
}

/* 6. The floor: a stale KV read right after a write must not bring the older record back. */
console.log("6. store: a stale KV read after a write does not resurrect the older record");
{
  const { kv, env } = mkEnv({ staleMs: 400 });
  kv.seed("store:" + SID, baseStore());
  await AP.putStore(env, readStore(kv), "seed");
  await sleep(450);                                  // the seed is visible now
  const A = JSON.parse(kv.latest("store:" + SID)), B = JSON.parse(kv.latest("store:" + SID));
  A.note = "a";
  await AP.putStore(env, A, "first");                // KV has it, but a get in the next 400 ms still returns the seed
  B.autopilot.penalty = 3;
  await AP.putStore(env, B, "second");               // reads KV stale: the floor in DO storage must win
  const s = readStore(kv);
  ok(s.note === "a", "the first write is still there after the second", JSON.stringify(s));
  ok(s.autopilot.penalty === 3, "the second write landed too", JSON.stringify(s.autopilot));
}

/* 7. Fail closed: when the gate is bound and does not answer, nothing is written. */
console.log("7. fail closed: the Durable Object errors, nothing is written, 503");
{
  const { kv, env } = mkEnv({});
  env.DISPATCH_DO = { idFromName: (x) => x, get: () => ({ fetch: async () => { throw new Error("DO down"); } }) };
  kv.seed("store:" + SID, baseStore());
  kv.seed("htok:tok1", { store_id: SID, company: "テスト工務店" });
  kv.seed("hearing:" + SID, { store_id: SID, profile: { store_id: SID, company: "テスト工務店", area: "平塚市", works: ["外壁塗装"] } });
  const before = kv.latest("store:" + SID), hbefore = kv.latest("hearing:" + SID);
  let threw = null;
  try { const c = readStore(kv); c.autopilot.penalty = 9; await AP.putStore(env, c, "x"); } catch (e) { threw = e; }
  ok(threw && threw.code === "rmw_failed", "putStore throws rmw_failed", threw && (threw.code + " " + threw.message));
  ok(kv.latest("store:" + SID) === before, "store unchanged");
  const rp = await adminPost(env, "/admin/profile-patch", { store_id: SID, fields: { rep: "x" } });
  ok(rp.status === 503, "profile-patch answers 503", rp.status);
  const rf = await req(env, "/h/tok1", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ company: "テスト工務店", area: "平塚市", works: ["外壁塗装"] }) });
  ok(rf.status === 503, "form POST answers 503", rf.status);
  ok(kv.latest("hearing:" + SID) === hbefore, "hearing unchanged");
  // a gate that does not know /rmw (a fake that answers something else) is the same as no answer
  env.DISPATCH_DO = { idFromName: (x) => x, get: () => ({ fetch: async () => new Response(JSON.stringify({ granted: true })) }) };
  threw = null;
  try { const c = readStore(kv); c.autopilot.penalty = 9; await AP.putStore(env, c, "x"); } catch (e) { threw = e; }
  ok(threw && threw.code === "rmw_failed" && /bad_reply/.test(threw.message), "a gate without /rmw: rmw_failed bad_reply, nothing written", threw && threw.message);
  ok(kv.latest("store:" + SID) === before, "store still unchanged");
}

/* 8. No binding (unit tests without the DO): the old direct path runs. */
console.log("8. no DISPATCH_DO: the direct path still writes");
{
  const { kv, env } = mkEnv({}, false);
  kv.seed("store:" + SID, baseStore());
  const c = readStore(kv); c.autopilot.penalty = 1;
  await AP.putStore(env, c, "direct");
  const s = readStore(kv);
  ok(s.autopilot.penalty === 1 && (s.autopilot._writes || []).length === 1, "written directly with the write ledger", JSON.stringify(s.autopilot));
  ok(!s._rmw, "no version stamp without the DO", JSON.stringify(s._rmw));
}

/* 9. The record a second writer reads carries the stamp; the DO keeps one instance per key, apart from the gate marks. */
console.log("9. the DO instance is per key and separate from the dispatch marks");
{
  const { kv, env } = mkEnv({});
  kv.seed("store:" + SID, baseStore());
  kv.seed("store:s2", { ...baseStore(), store_id: "s2" });
  await AP.putStore(env, readStore(kv), "a");
  await AP.putStore(env, JSON.parse(kv.latest("store:s2")), "b");
  const ids = [...env.DISPATCH_DO._dos.keys()];
  ok(ids.includes("rmw:store:s1") && ids.includes("rmw:store:s2") && !ids.includes("dispatch:s1"), "ids rmw:store:<sid>", ids.join(","));
  const st = env.DISPATCH_DO._states.get("rmw:store:s1");
  ok(st && st._map.get("seq") === 1 && st._map.has("v:1"), "the written copy is kept as the floor", JSON.stringify([...(st ? st._map.keys() : [])]));
  ok(readStore(kv)._rmw && readStore(kv)._rmw.seq === 1, "the KV record carries the version stamp", JSON.stringify(readStore(kv)._rmw));
}

/* 10. /health */
console.log("10. /health");
{
  const { env } = mkEnv({});
  const j = await (await req(env, "/health", {})).json();
  ok(j.store_writes === "do-serialized-20261013", "/health store_writes mark", JSON.stringify(j));
  ok(j.version === "2.3.2-rmw-20261013", "/health version", j.version);
}

fs.rmSync(TMP, { recursive: true, force: true });
const EXPECT = 34;
if (n < EXPECT) { console.log("fewer checks than expected (" + n + " < " + EXPECT + ")"); fail++; }
if (fail) { console.log("store_profile_rmw " + (n - fail) + "/" + n + " 通過、" + fail + " 不合格"); process.exit(1); }
console.log("store_profile_rmw " + n + "/" + n + " 通過");
