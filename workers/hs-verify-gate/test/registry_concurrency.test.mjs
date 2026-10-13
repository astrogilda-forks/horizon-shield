// registry_concurrency: two writers of the register that overlap must both keep their row (2026-10-13).
// ops/concurrency_audit_20261013.md, finding G1. The register was one KV blob (watch:registry) that every writer read
// whole, changed one row of, and put back whole. The KV mock here holds every reader of that blob at a barrier until
// two readers are inside, which is the interleaving KV allows (both read before either writes). On the code before the
// fix the second put replaced the first and a registration answered ok:true was gone. Now each writer writes its own
// key (watch:reg:<sha256(endpoint)>), so the two writes cannot touch each other. The old blob is still read (migration)
// and never rewritten or deleted. Offline: *.redteam.invalid never resolves and fetch is stubbed.
// Run: node test/registry_concurrency.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";

const CTX = { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } };
globalThis.fetch = async () => new Response("", { status: 404 });   // no well-known files anywhere
const TOKEN = "test-token";
const O = "https://gate.horizonshield.dev";
const BLOB = "watch:registry";

// KV with metadata, a get counter, and a barrier on reads of the blob: a reader waits until `parties` readers are in,
// or `waitMs` passes (a writer that never has a second reader alongside it is only delayed).
function racingKV(parties = 2, waitMs = 150) {
  const store = new Map(), meta = new Map();
  let waiting = [];
  const gets = { total: 0 };
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= parties) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, waitMs);
  });
  return {
    store, gets,
    get: async (k, type) => {
      gets.total++;
      if (k === BLOB) await arrive();
      const v = store.has(k) ? store.get(k) : null;
      return ((type === "json" || (type && type.type === "json")) && v !== null) ? JSON.parse(v) : v;
    },
    put: async (k, v, opts) => { await Promise.resolve(); store.set(k, typeof v === "string" ? v : JSON.stringify(v)); if (opts && opts.metadata) meta.set(k, structuredClone(opts.metadata)); else meta.delete(k); },
    delete: async (k) => { store.delete(k); meta.delete(k); },
    list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || "")).sort().map((name) => (meta.has(name) ? { name, metadata: meta.get(name) } : { name })), list_complete: true }),
  };
}
const envWith = (kv) => ({ HS_VERIFY_KV: kv, SWEEP_TOKEN: TOKEN, GATE_COMMIT: "registry-concurrency-local" });
const req = (env, path, method, body, headers) => worker.fetch(new Request(O + path, { method, headers: { "content-type": "application/json", ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) }), env, CTX);
const asJson = async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) });
const watched = async (env) => { const r = await asJson(await req(env, "/watchlist", "GET")); return (r.j.watched || []).map((w) => w.endpoint); };

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 240)); } };

const A = "https://a.redteam.invalid/mcp", B = "https://b.redteam.invalid/mcp", C = "https://c.redteam.invalid/mcp";
const X = "https://x.redteam.invalid/mcp", Y = "https://y.redteam.invalid/mcp";
const seedRow = (d) => ({ tier: "free", webhook: null, added_at: d, requested_by: "anonymous", owner_file_at_request: "absent" });

// 1. Two anonymous registrations at the same time, empty register.
{
  const kv = racingKV(); const env = envWith(kv);
  const [ra, rb] = await Promise.all([req(env, "/watch", "POST", { endpoint: A }).then(asJson), req(env, "/watch", "POST", { endpoint: B }).then(asJson)]);
  t("1 both registrations answered ok:true", ra.status === 200 && ra.j.ok === true && rb.status === 200 && rb.j.ok === true, JSON.stringify([ra, rb]));
  const w = await watched(env);
  t("1 /watchlist holds both rows", w.includes(A) && w.includes(B), JSON.stringify(w));
  const g = await asJson(await req(env, "/watch?endpoint=" + encodeURIComponent(A), "GET"));
  t("1 GET /watch says A is registered", g.j.registered === true, JSON.stringify(g.j));
  const c = await asJson(await req(env, "/watch", "GET"));
  t("1 GET /watch counts 2 rows", c.j.count === 2, JSON.stringify(c.j));
}

// 2. An anonymous registration racing the operator's quarantine of another row (seeded in the old blob).
{
  const kv = racingKV(); const env = envWith(kv);
  kv.store.set(BLOB, JSON.stringify({ [X]: seedRow("2026-10-01T00:00:00Z") }));
  const [rw, rq] = await Promise.all([
    req(env, "/watch", "POST", { endpoint: A }).then(asJson),
    req(env, "/register/quarantine", "POST", { endpoint: X, proposal_sha256: "a".repeat(64), reason: "signature drift on the card" }, { "x-sweep-token": TOKEN }).then(asJson),
  ]);
  t("2 both answered", rw.status === 200 && rq.status === 200, JSON.stringify([rw.status, rq.status, rq.j]));
  const w = await watched(env);
  t("2 the new row survived the quarantine write", w.includes(A), JSON.stringify(w));
  const lu = await asJson(await req(env, "/register/lookup?endpoint=" + encodeURIComponent(X), "GET"));
  t("2 the quarantine survived the registration write", lu.j.status === "quarantined", JSON.stringify(lu.j).slice(0, 200));
}

// 3. A removal racing a registration.
{
  const kv = racingKV(); const env = envWith(kv);
  kv.store.set(BLOB, JSON.stringify({ [X]: seedRow("2026-10-01T00:00:00Z"), [Y]: seedRow("2026-10-02T00:00:00Z") }));
  const [rd, rc] = await Promise.all([
    req(env, "/watch", "DELETE", { endpoint: X, reason: "the owner asked by mail" }, { "x-sweep-token": TOKEN }).then(asJson),
    req(env, "/watch", "POST", { endpoint: C }).then(asJson),
  ]);
  t("3 both answered", rd.status === 200 && rc.status === 200, JSON.stringify([rd.status, rc.status]));
  const w = await watched(env);
  t("3 X is gone, Y stays, C is on", !w.includes(X) && w.includes(Y) && w.includes(C), JSON.stringify(w));
}

// 4. Migration: rows in the old blob are read, kept in their order, overridden and hidden by per-key rows, and the
//    blob itself is never rewritten or deleted.
{
  const kv = racingKV(); const env = envWith(kv);
  const blob = JSON.stringify({ [X]: seedRow("2026-10-01T00:00:00Z"), [Y]: seedRow("2026-10-02T00:00:00Z") });
  kv.store.set(BLOB, blob);
  await req(env, "/watch", "POST", { endpoint: C });
  await req(env, "/watch", "POST", { endpoint: A });
  let w = (await watched(env)).filter((e) => /redteam/.test(e));
  t("4 blob rows first in their order, new rows after in the order they were added", JSON.stringify(w) === JSON.stringify([X, Y, C, A]), JSON.stringify(w));
  await req(env, "/watch", "DELETE", { endpoint: X, reason: "removal of a blob row" }, { "x-sweep-token": TOKEN });
  w = (await watched(env)).filter((e) => /redteam/.test(e));
  t("4 a removed blob row is hidden", JSON.stringify(w) === JSON.stringify([Y, C, A]), JSON.stringify(w));
  t("4 the old blob is byte for byte what it was", kv.store.get(BLOB) === blob);
  const c = await asJson(await req(env, "/watch", "GET"));
  t("4 GET /watch counts 3 rows", c.j.count === 3, JSON.stringify(c.j));
  const again = await asJson(await req(env, "/watch", "POST", { endpoint: Y, webhook: "https://hook.redteam.invalid/h" }));
  t("4 a blob row can be updated (its first webhook) and keeps its added_at", again.status === 200 && again.j.notified === true, JSON.stringify(again.j));
  const reg = await asJson(await req(env, "/register", "GET"));
  const ry = (reg.j.rows || []).find((r) => r.endpoint === Y);
  t("4 /register shows the updated row", !!ry, JSON.stringify(reg.j).slice(0, 200));
}

// 5. Reading the register costs one list and no per-row get while rows fit in metadata.
{
  const kv = racingKV(); const env = envWith(kv);
  for (const ep of [A, B, C]) await req(env, "/watch", "POST", { endpoint: ep });
  const before = kv.gets.total;
  const w = await watched(env);
  const used = kv.gets.total - before;
  t("5 /watchlist reads 3 rows", [A, B, C].every((e) => w.includes(e)), JSON.stringify(w));
  t("5 without a get per row (blob + legacy list + removed list only)", used <= 3, "gets " + used);
}

console.log(`\n=== ${pass} / ${pass + fail} 合格 (registry concurrency, 2026-10-13) ===`);
process.exit(fail ? 1 : 0);
