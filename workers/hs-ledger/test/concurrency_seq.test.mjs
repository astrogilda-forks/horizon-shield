// test/concurrency_seq.test.mjs: two ledger appends that overlap must get two entry numbers (2026-10-13).
//
// Run: node test/concurrency_seq.test.mjs   (no network, no production; KV and the Durable Object are in memory)
//
// What this guards (ops/concurrency_audit_20261013.md, finding L1). Every append used to read seq, add 1 and write
// entry:<n>. The KV mock below holds every reader of "seq" at a barrier until two have arrived, which is exactly the
// interleaving KV allows (both read before either writes). On the code before the fix both appends then wrote
// entry:1, the second replaced the first, and the first caller had already been told 201 with n:1. With the fix the
// number comes from the sequencer inside AgreementDedupeDO (the real class, wrapped in an in-memory state whose
// blockConcurrencyWhile runs one block at a time, as the runtime does), so the second reader only arrives after the
// first append is written.

import { loadWorker, sha256Hex, checker } from "./load.mjs";
import { AgreementDedupeDO } from "../nenrin/agreement-v0/agreement_intake.mjs";
import { walkChain } from "../src/chain_v1.mjs";

const worker = await loadWorker("src/worker.js");
const chk = checker("hs-ledger concurrency (seq)");
const TOKEN = "test-token";
const B = "https://hs-ledger.example.dev";

// KV whose get("seq") waits until `parties` readers are inside, or `waitMs` passes (so a serialized caller, which
// never has a second reader alongside it, is only delayed, never stuck).
function racingKV(parties = 2, waitMs = 150) {
  const store = new Map();
  let waiting = [];
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= parties) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, waitMs);
  });
  return {
    store,
    binding: {
      get: async (k) => { if (k === "seq") await arrive(); return store.has(k) ? store.get(k) : null; },
      put: async (k, v) => { await Promise.resolve(); store.set(k, String(v)); },
      delete: async (k) => { store.delete(k); },
      list: async (opt) => {
        const pre = (opt && opt.prefix) || "";
        return { keys: [...store.keys()].filter((k) => k.startsWith(pre)).sort().map((name) => ({ name })), list_complete: true };
      },
    },
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
function fakeNamespace(envRef) {
  const inst = new Map();
  return {
    idFromName: (name) => String(name),
    get: (id) => {
      if (!inst.has(id)) inst.set(id, new AgreementDedupeDO(fakeState(), envRef));
      const o = inst.get(id);
      return { fetch: (u, init) => o.fetch(new Request(u, init)) };
    },
  };
}
function makeEnv(bindDo) {
  const kv = racingKV();
  const env = { LEDGER: kv.binding, LEDGER_ADMIN_TOKEN: TOKEN };
  if (bindDo) env.AGREEMENT_DEDUPE_DO = fakeNamespace(env);
  return { env, kv };
}
async function append(env, rec) {
  const h = await sha256Hex(rec);
  const r = await worker.fetch(new Request(B + "/ledger/append", {
    method: "POST", headers: { "content-type": "application/json", "x-ledger-key": TOKEN },
    body: JSON.stringify({ claim_sha256: h, record_canonical: rec, work: "w" }),
  }), env, { waitUntil() {} });
  return { status: r.status, body: await r.json(), h };
}
const entryOf = (kv, n) => { const v = kv.store.get("entry:" + n); return v ? JSON.parse(v) : null; };
const chainOk = async (kv) => walkChain(async (n) => entryOf(kv, n), Number(kv.store.get("seq") || 0));

// 1. Two different records appended at the same time, sequencer bound (production wiring).
{
  const { env, kv } = makeEnv(true);
  const [a, b] = await Promise.all([append(env, '{"t":"a"}'), append(env, '{"t":"b"}')]);
  chk("1 both answered 201", a.status === 201 && b.status === 201, JSON.stringify([a, b]));
  chk("1 two different entry numbers", a.body.n !== b.body.n && new Set([a.body.n, b.body.n]).size === 2, a.body.n + "," + b.body.n);
  chk("1 seq is 2", kv.store.get("seq") === "2", kv.store.get("seq"));
  chk("1 entry for a holds a's claim", entryOf(kv, a.body.n) && entryOf(kv, a.body.n).claim_sha256 === a.h);
  chk("1 entry for b holds b's claim", entryOf(kv, b.body.n) && entryOf(kv, b.body.n).claim_sha256 === b.h);
  chk("1 hash index points at the right entries", kv.store.get("hash:" + a.h) === String(a.body.n) && kv.store.get("hash:" + b.h) === String(b.body.n));
  const w = await chainOk(kv);
  chk("1 chain walks 1..2 with no hole", w.ok && w.n === 2, JSON.stringify(w));
  // The stored bytes are the shape the old code wrote: same keys, same order, n first.
  const e = entryOf(kv, 1);
  chk("1 stored entry keeps the old key order", JSON.stringify(Object.keys(e)) === JSON.stringify(["n", "work", "claim_sha256", "record_canonical", "schema", "created_at", "ots_status", "bitcoin_block", "block_time", "stamped_at"]), JSON.stringify(Object.keys(e)));
}

// 2. The same record twice at the same time: one entry, the other answer is the dedup of it.
{
  const { env, kv } = makeEnv(true);
  const [a, b] = await Promise.all([append(env, '{"t":"same"}'), append(env, '{"t":"same"}')]);
  const created = [a, b].filter((x) => x.status === 201), dedup = [a, b].filter((x) => x.body.dedup === true);
  chk("2 one created, one dedup", created.length === 1 && dedup.length === 1, JSON.stringify([a, b]));
  chk("2 dedup names the created entry", dedup[0] && created[0] && dedup[0].body.n === created[0].body.n);
  chk("2 seq is 1", kv.store.get("seq") === "1", kv.store.get("seq"));
}

// 3. An operator append racing the witness batch (the 00:30 cron's first step, here through POST /witness/anchor).
{
  const { env, kv } = makeEnv(true);
  const sha = "ab".repeat(32);
  kv.store.set("wit:pending:" + sha, JSON.stringify({ sha, purpose: "p", witness_name: "w", vantage: "v", signed: false, submitted_at: "2026-10-13T00:00:00Z" }));
  const anchor = worker.fetch(new Request(B + "/witness/anchor", { method: "POST", headers: { "x-ledger-key": TOKEN } }), env, { waitUntil() {} }).then(async (r) => ({ status: r.status, body: await r.json() }));
  const [x, y] = await Promise.all([append(env, '{"t":"op"}'), anchor]);
  chk("3 both written", x.status === 201 && y.status === 201, JSON.stringify([x, y]));
  chk("3 different entry numbers", x.body.n !== y.body.n, x.body.n + "," + y.body.n);
  chk("3 the witness record is anchored in the entry that lists it",
    (() => { const a = JSON.parse(kv.store.get("wit:anchored:" + sha) || "null"); const e = a && entryOf(kv, a.n); return !!(e && e.record_canonical.includes(sha)); })());
  const w = await chainOk(kv);
  chk("3 chain walks with no hole", w.ok && w.n === 2, JSON.stringify(w));
}

// 4. The hook is real: with the sequencer NOT bound (the fallback the unit tests use), the same race still loses an
//    entry. This is the behaviour every append had before the fix, and it is why production must keep the binding.
{
  const { env, kv } = makeEnv(false);
  const [a, b] = await Promise.all([append(env, '{"t":"a"}'), append(env, '{"t":"b"}')]);
  chk("4 unbound: both told 201 with the same n (the lost update this file exists for)", a.status === 201 && b.status === 201 && a.body.n === b.body.n, JSON.stringify([a.body, b.body]));
  chk("4 unbound: only one of the two records survives", kv.store.get("seq") === "1");
}

// 5. A sequencer that answers an error makes the append fail closed (503), and nothing is written.
{
  const kv = racingKV();
  const env = { LEDGER: kv.binding, LEDGER_ADMIN_TOKEN: TOKEN,
    AGREEMENT_DEDUPE_DO: { idFromName: (n) => n, get: () => ({ fetch: async () => new Response('{"error":"boom"}', { status: 500 }) }) } };
  const r = await append(env, '{"t":"x"}');
  chk("5 sequencer failure answers 503 ledger_append_unavailable", r.status === 503 && r.body.error === "ledger_append_unavailable", JSON.stringify(r));
  chk("5 nothing written", !kv.store.has("seq") && !kv.store.has("entry:1"));
}

// 6. The build says so on /health (ops/prod_fix_check.sh reads this).
{
  const { env } = makeEnv(true);
  const r = await worker.fetch(new Request(B + "/health"), env, { waitUntil() {} });
  const j = await r.json();
  chk("6 /health carries sequencer do-serialized-20261013", r.status === 200 && j.sequencer === "do-serialized-20261013", JSON.stringify(j.sequencer));
}

process.exit(chk.done() ? 1 : 0);
