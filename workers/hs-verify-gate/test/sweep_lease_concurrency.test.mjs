// sweep_lease_concurrency: two sweeps that overlap must not both run (2026-10-13).
// ops/concurrency_audit_20261013.md, findings G4 and G5. The daily cron and the operator's POST /sweep both run the
// sweep; two that overlapped appended hist:<sha16> and changes:recent from two stale copies (one entry or change line
// lost, G4) and both opened the NENRIN window (two salts: the commitment filed on the ledger belongs to one, the rows
// derived from the other, G5). The fix is a lease in SweepLeaseDO (the real class, wrapped in an in-memory state whose
// blockConcurrencyWhile runs one block at a time, as the runtime does): the second sweep answers 409 sweep_in_progress
// (operator) or skips (cron) and writes nothing. Without the binding the sweep runs unleased as before (control).
// The KV mock holds every reader of the window state at a barrier until two readers are inside, which is the
// interleaving KV allows, so on the code before the fix the two sweeps provably made two salts.
// Offline: *.redteam.invalid never resolves, explorers and the ledger intake are stubbed to fail (legacy rule; the salt
// and its commitment are still created, which is what G5 is about).
// Run: node test/sweep_lease_concurrency.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";
import { SweepLeaseDO } from "../src/sweep_lease.js";   // worker.js re-exports it for the runtime; imported here by its own file so the test also loads against the old worker

globalThis.fetch = async () => new Response("", { status: 404 });
const TOKEN = "test-token";
const O = "https://gate.horizonshield.dev";
const AUTH = { "x-sweep-token": TOKEN, "content-type": "application/json" };

function racingKV(barrierPrefixes, parties = 2, waitMs = 150) {
  const store = new Map(), meta = new Map();
  let waiting = [];
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= parties) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, waitMs);
  });
  return {
    store,
    get: async (k, type) => {
      if (barrierPrefixes.some((p) => k.startsWith(p))) await arrive();
      const v = store.has(k) ? store.get(k) : null;
      return ((type === "json" || (type && type.type === "json")) && v !== null) ? JSON.parse(v) : v;
    },
    put: async (k, v, opts) => { await Promise.resolve(); store.set(k, typeof v === "string" ? v : JSON.stringify(v)); if (opts && opts.metadata) meta.set(k, structuredClone(opts.metadata)); else meta.delete(k); },
    delete: async (k) => { store.delete(k); meta.delete(k); },
    list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || "")).sort().map((name) => (meta.has(name) ? { name, metadata: meta.get(name) } : { name })), list_complete: true }),
  };
}

// In-memory Durable Object state: storage is a Map, blockConcurrencyWhile runs its blocks one after another.
function fakeState() {
  const m = new Map();
  let chain = Promise.resolve();
  return {
    storage: { get: async (k) => m.get(k), put: async (k, v) => { m.set(k, structuredClone(v)); }, delete: async (k) => { m.delete(k); } },
    blockConcurrencyWhile(fn) { const p = chain.then(() => fn()); chain = p.catch(() => {}); return p; },
  };
}
function fakeNamespace() {
  const inst = new Map();
  // answers: every /acquire as { holder, ok } in the order the DO answered them
  const calls = { acquire: 0, release: 0, names: [], answers: [] };
  return {
    calls,
    idFromName: (name) => { calls.names.push(name); return String(name); },
    get: (id) => {
      if (!inst.has(id)) inst.set(id, new SweepLeaseDO(fakeState(), {}));
      const o = inst.get(id);
      return { fetch: async (u, init) => {
        if (/release/.test(String(u))) calls.release++;
        const r = await o.fetch(new Request(u, init));
        if (/acquire/.test(String(u))) { calls.acquire++; const j = await r.clone().json(); calls.answers.push({ holder: JSON.parse(init.body).holder, ok: j.ok === true }); }
        return r;
      } };
    },
  };
}
const brokenNamespace = () => ({ idFromName: (n) => n, get: () => ({ fetch: async () => { throw new Error("DO unreachable (simulated)"); } }) });

function makeEnv(doNs, barrier) {
  const kv = racingKV(barrier || []);
  const env = { HS_VERIFY_KV: kv, SWEEP_TOKEN: TOKEN, GATE_COMMIT: "sweep-lease-local" };
  if (doNs) env.SWEEP_LEASE_DO = doNs;
  return { env, kv };
}
// A thrown sweep is reported as status 0 (on the old code two sweeps in one isolate share the module level sweepBudget;
// the first one's finally nulls it under the second, which then throws at the end and loses its whole record).
const sweep = (env, body) => worker.fetch(new Request(O + "/sweep", { method: "POST", headers: AUTH, body: JSON.stringify(body || { force: true }) }), env, { waitUntil() {} })
  .then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }), (e) => ({ status: 0, j: { thrown: String((e && e.message) || e) } }));
// The cron: scheduled() hands its work to ctx.waitUntil and logs a skip; its outcome is read from the lease log and KV.
const cron = (env) => { const ps = []; const ctx = { waitUntil(p) { ps.push(Promise.resolve(p).catch(() => null)); } }; worker.scheduled({ cron: "0 18 * * *" }, env, ctx); return Promise.all(ps); };
const later = (ms) => new Promise((r) => setTimeout(r, ms));
const windowKeys = (kv) => [...kv.store.keys()].filter((k) => k.startsWith("nenrin:window:"));

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 260)); } };

// 1. Two operator sweeps at the same time: one runs, the other is 409 and writes nothing.
{
  const ns = fakeNamespace(); const { env, kv } = makeEnv(ns, ["nenrin:window:"]);
  const [a, b] = await Promise.all([sweep(env), sweep(env)]);
  const ran = [a, b].filter((r) => r.status === 200 && r.j.ran === true);
  const busy = [a, b].filter((r) => r.status === 409 && r.j.ran === false && r.j.error === "sweep_in_progress");
  t("1 exactly one sweep ran (200, ran true) and one was refused (409 sweep_in_progress)", ran.length === 1 && busy.length === 1, JSON.stringify([[a.status, a.j.ran, a.j.error], [b.status, b.j.ran, b.j.error]]));
  t("1 the refusal names the holder and its start time", busy.length === 1 && busy[0].j.holder === "operator POST /sweep" && /^\d{4}-\d{2}-\d{2}T/.test(busy[0].j.started_at || ""), JSON.stringify(busy[0] && busy[0].j));
  const commitments = [...new Set([a, b].map((r) => r.j.coordinate && r.j.coordinate.commitment).filter(Boolean))];
  const wk = windowKeys(kv);
  const cur = ran.length === 1 && ran[0].j.coordinate ? ran[0].j.coordinate.window_id : null;
  const st = cur ? JSON.parse(kv.store.get("nenrin:window:" + cur) || "null") : null;
  t("1 one salt was made for the window (G5): one commitment reported, and it is the one stored", commitments.length === 1 && st && st.commitment === commitments[0], JSON.stringify({ commitments, stored: st && st.commitment, window_keys: wk.length }));
  t("1 the sweep that ran wrote sweep:last; the refused one did not replace it", (() => { const sl = JSON.parse(kv.store.get("sweep:last") || "null"); return sl && sl.ran === true && sl.at === ran[0].j.at; })(), String(kv.store.get("sweep:last")).slice(0, 120));
  t("1 the lease was taken on the one instance named sweep and released after the run", ns.calls.names.every((n) => n === "sweep") && ns.calls.acquire === 2 && ns.calls.release === 1, JSON.stringify(ns.calls));
  const again = await sweep(env);
  t("1 after the run a sequential sweep is admitted again (lease released)", again.status === 200 && again.j.ran === true, JSON.stringify([again.status, again.j.error]));
}

// 2. The cron fires while the operator's sweep holds the lease: the cron skips and writes nothing.
{
  const ns = fakeNamespace(); const { env, kv } = makeEnv(ns);
  const opP = sweep(env);
  await later(50);   // the operator's sweep has taken the lease by now (it is still running: 8 rows at 300 ms each)
  const crP = cron(env);
  const [op] = await Promise.all([opP, crP]);
  const ans = ns.calls.answers;
  t("2 the operator sweep ran (200, ran true)", op.status === 200 && op.j.ran === true, JSON.stringify([op.status, op.j.ran, op.j.error]));
  t("2 the cron asked for the lease and was told busy", ans.length === 2 && ans[0].holder === "operator POST /sweep" && ans[0].ok === true && ans[1].holder === "cron" && ans[1].ok === false, JSON.stringify(ans));
  t("2 sweep:last is the operator's run (the cron wrote nothing)", (() => { const sl = JSON.parse(kv.store.get("sweep:last") || "null"); return sl && sl.at === op.j.at; })(), String(kv.store.get("sweep:last")).slice(0, 100));
  await cron(env);
  t("2 the next cron takes the lease and runs (sweep:last moved)", ns.calls.answers.length === 3 && ns.calls.answers[2].holder === "cron" && ns.calls.answers[2].ok === true && JSON.parse(kv.store.get("sweep:last")).at !== op.j.at, JSON.stringify(ns.calls.answers));
}

// 3. Fail closed: the lease cannot be taken, so nothing is swept and nothing is written.
{
  const { env, kv } = makeEnv(brokenNamespace());
  const r = await sweep(env);
  t("3 a lease error answers 503 sweep_lease_unavailable, ran false", r.status === 503 && r.j.ran === false && r.j.error === "sweep_lease_unavailable", JSON.stringify([r.status, r.j]).slice(0, 200));
  t("3 and the sweep wrote nothing (no sweep:last, no history, no window)", kv.store.size === 0, JSON.stringify([...kv.store.keys()]));
  await cron(env);
  // the cron's other job (netFreeze, usage:netcount:<day>) is not the sweep and still runs
  t("3 the cron with a broken lease also skips and writes nothing of the sweep", [...kv.store.keys()].every((k) => k.startsWith("usage:")), JSON.stringify([...kv.store.keys()]));
}

// 4. Control: without the binding the sweep runs as before (unit tests, the GCP twin).
{
  const { env, kv } = makeEnv(null);
  const r = await sweep(env);
  t("4 no binding: POST /sweep runs (200, ran true) and writes sweep:last", r.status === 200 && r.j.ran === true && kv.store.has("sweep:last"), JSON.stringify([r.status, r.j.ran, r.j.error]));
}

// 5. The lease itself: expiry frees it, a foreign token cannot release it.
{
  const d = new SweepLeaseDO(fakeState(), {});
  const call = (path, body) => d.fetch(new Request("https://sweep-lease" + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).then((r) => r.json());
  const T0 = Date.parse("2026-10-13T18:00:00Z");
  const a = await call("/acquire", { holder: "cron", ttl_ms: 60000, now: T0 });
  const b = await call("/acquire", { holder: "operator", ttl_ms: 60000, now: T0 + 1000 });
  t("5 the second acquire within the ttl is busy with the holder's start", a.ok === true && b.ok === false && b.busy === true && b.holder === "cron" && b.started_at === new Date(T0).toISOString(), JSON.stringify([a, b]));
  const bad = await call("/release", { token: "not-the-token" });
  const c = await call("/acquire", { holder: "operator", ttl_ms: 60000, now: T0 + 2000 });
  t("5 a foreign token does not release it", bad.released === false && c.ok === false, JSON.stringify([bad, c]));
  const d2 = await call("/acquire", { holder: "operator", ttl_ms: 60000, now: T0 + 60001 });
  t("5 after the ttl the lease is free again and says whose lease expired", d2.ok === true && d2.replaced_expired && d2.replaced_expired.holder === "cron", JSON.stringify(d2));
  const rel = await call("/release", { token: d2.token });
  const e = await call("/acquire", { holder: "cron", ttl_ms: 60000, now: T0 + 60002 });
  t("5 the holder's release frees it at once", rel.released === true && e.ok === true && !e.replaced_expired, JSON.stringify([rel, e]));
  const peek = await call("/peek", { now: T0 + 60003 });
  t("5 peek shows the holder without the token", peek.lease && peek.lease.holder === "cron" && !("token" in peek.lease), JSON.stringify(peek));
}

console.log(`\n=== ${pass} / ${pass + fail} 合格 (sweep single flight, 2026-10-13) ===`);
process.exit(fail ? 1 : 0);
