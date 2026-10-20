// node --test test/pilot.test.mjs   (Node 20 or later: WebCrypto Ed25519)
// Checks the responder side of Issue #51 without the network: a mocked MCP server and block source, keys made here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import worker, { jcs, sha256hex, sign, verify, publicKeyHex, handleCall, handleVoid, Refusal, Occurrence,
  runTimings } from "../src/pilot.mjs";

const { RUN_SIGN_BY_MS, RUN_STALE_MS, RUN_TTL_S } = runTimings();

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const SEED_X = "11".repeat(32), SEED_B = "22".repeat(32);
const FIXTURE = { type: "horizon-shield.estimate-fixture.v0", lines: [
  { item: "外壁塗装 シリコン", qty: 180, unit: "㎡", unit_price: 3200 },
  { item: "足場設置 ㎡単価", qty: 240, unit: "㎡", unit_price: 900 }] };
const env = { RESPONDER_SEED: SEED_X, PRICE: "7000", UNIT: "JPY-testnet", MCP_URL: "mock://mcp", BLOCKS_URL: "mock://blocks" };

let mcpCalls = 0;
function mockFetch(url, init) {
  const text = (t) => ({ ok: true, status: 200, text: async () => t, json: async () => JSON.parse(t) });
  if (url === "mock://mcp") {
    mcpCalls++;
    const body = JSON.parse(init.body);
    const w = body.params.arguments.work;
    assert.equal(body.params.arguments.region, undefined);      // no region unless the caller gives one
    if (w === "足場設置 ㎡単価") return text(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { structuredContent: {
      work: w, ambiguous: true, candidates: [] } } }));          // the dataset gives no single reference
    return text(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { structuredContent: {
      work: w + " 単価", fair_range: { min: 1000, avg: 2000, max: 3000 }, verdict: "適正レンジを上回る", level: "high",
      provenance: { data_version: "2.2.0" },
      claim: { dataset_sha256: "85".repeat(32), ruleset: { id: "hs-audit-verdict", version: "1" } } } } }));
  }
  if (url === "mock://blocks/blocks/tip/height") return text("920000");
  if (url.startsWith("mock://blocks/block-height/")) return text("ab".repeat(32));
  throw new Error("unexpected fetch " + url);
}

async function build(over = {}) {
  const X = await publicKeyHex(SEED_X), B = await publicKeyHex(SEED_B);
  const task = { type: "musubi.ca2a.task.v0", service: "estimate-audit", amount: 7000, unit: "JPY-testnet", nonce: "cd".repeat(32), ...over.task };
  const request = { type: "musubi.ca2a.request.v0", caller: B, responder: X, lineage: ["sha256:" + "ef".repeat(32)],
    capability: "pay", occurrence_id: "pilot-call-0", task_sha256: await sha256hex(jcs(task)), ...over.request };
  const rs = await sha256hex(jcs(request));
  const payer = over.payerSeed ? await publicKeyHex(over.payerSeed) : B;
  const payment = await sign({ type: "musubi.ca2a.payment-receipt.v0", payer, payee: X, lineage: request.lineage,
    request_sha256: rs, amount: 7000, unit: "JPY-testnet", seen_block: { height: 919999, hash: "aa".repeat(32) },
    rail: { kind: "signed-test-transfer", receipt_sha256: "bb".repeat(32) }, ...over.payment }, over.payerSeed || SEED_B);
  return { body: { request, task, fixture: FIXTURE, payment }, request, payment, X, B, rs };
}

test("a well formed call returns a receipt the companion's rules accept", async () => {
  const b = await build();
  const out = await handleCall(b.body, env, mockFetch);
  assert.equal(out.request_sha256, b.rs);
  assert.equal(out.receipt.type, "musubi.ca2a.execution-receipt.v0");
  assert.equal(out.receipt.responder, b.X);
  assert.equal(out.receipt.caller, b.B);
  assert.deepEqual(out.receipt.lineage, b.request.lineage);
  assert.equal(out.receipt.request_sha256, b.rs);
  assert.deepEqual(out.receipt.seen_block, { height: 920000, hash: "ab".repeat(32) });
  assert.equal(out.receipt.outcome.kind, "result");
  assert.equal(out.receipt.outcome.response_sha256, await sha256hex(jcs(out.audit)));
  assert.equal(await verify(out.receipt, "responder"), true);
  assert.equal(out.audit.fixture_sha256, await sha256hex(jcs(FIXTURE)));   // the audit names its input by hash
  assert.equal(out.audit.lines.length, 2);
  assert.equal(out.audit.total, 180 * 3200 + 240 * 900);
  const [la, lb] = out.audit.lines;
  assert.deepEqual([la.amount, la.reference_amount, la.finding, la.dataset_sha256, la.ruleset],
    [180 * 3200, 180 * 2000, "above", "85".repeat(32), { id: "hs-audit-verdict", version: "1" }]);
  assert.deepEqual([lb.finding, lb.fair_range, lb.reference_amount, lb.matched_work], ["unmatched", null, null, null]);
  assert.equal(out.audit.reference_total, null);              // one line unmatched: no reference total
  assert.equal(out.audit.region, null);
});

test("the audit is a function of the inputs: same call, same bytes", async () => {
  const b = await build();
  const a = await handleCall(b.body, env, mockFetch), c = await handleCall(b.body, env, mockFetch);
  assert.equal(jcs(a.audit), jcs(c.audit));
  assert.equal(a.receipt.outcome.response_sha256, c.receipt.outcome.response_sha256);
});

async function refuses(over, code) {
  const b = await build(over);
  await assert.rejects(() => handleCall(b.body, env, mockFetch), (e) => e instanceof Refusal && e.code === code, code);
}

test("refusals: price, task binding, responder, payment binding, payer", async () => {
  await refuses({ task: { amount: 5000 } }, "not_the_price");
  await refuses({ request: { task_sha256: "00".repeat(32) } }, "request_does_not_commit_to_task");
  await refuses({ request: { responder: "cc".repeat(32) } }, "request_names_another_responder");
  await refuses({ payment: { amount: 5000 } }, "payment_not_for_task");
  await refuses({ payment: { payee: "cc".repeat(32) } }, "payment_not_to_this_responder");
  await refuses({ payerSeed: "33".repeat(32) }, "payment_not_by_caller");
});

test("a payment altered after signing is refused", async () => {
  const b = await build();
  b.body.payment.rail = { kind: "signed-test-transfer", receipt_sha256: "dd".repeat(32) };
  await assert.rejects(() => handleCall(b.body, env, mockFetch), (e) => e.code === "payment_signature_invalid");
});

test("jcs refuses floats and lone surrogates", () => {
  assert.throws(() => jcs({ a: 1.5 }), (e) => e.code === "number_not_in_profile");
  assert.throws(() => jcs({ a: "\ud800" }), (e) => e.code === "lone_surrogate");
  assert.equal(jcs({ b: [1, { z: null, a: "x" }], a: true }), '{"a":true,"b":[1,{"a":"x","z":null}]}');
});

// ---- state: one answer per occurrence, and the lost call (Issue #51)
// A KV namespace in memory, with expirationTtl against a clock (KV removes an expired key; get then returns null).
function fakeKV(clock = () => 0) {
  const m = new Map(), exp = new Map(), puts = [];
  const live = (k) => { if (exp.has(k) && clock() >= exp.get(k)) { m.delete(k); exp.delete(k); } return m.get(k); };
  return { m, puts,
    async get(k, type) { const v = live(k); return v === undefined ? null : type === "json" ? JSON.parse(v) : v; },
    async put(k, v, opts) {
      puts.push([k, opts || null]); m.set(k, v);
      if (opts && opts.expirationTtl) exp.set(k, clock() + opts.expirationTtl * 1000); else exp.delete(k);
    },
    async delete(k) { m.delete(k); exp.delete(k); } };
}
async function voidFor(b, seed = SEED_B) {
  const caller = await publicKeyHex(seed);
  return sign({ type: "musubi.ca2a.void-request.v0", caller, request_sha256: b.rs }, seed);
}

test("with state, a second call for an executed occurrence replays the stored receipt without auditing again", async () => {
  const b = await build(), senv = { ...env, STATE: fakeKV() };
  const a = await handleCall(b.body, senv, mockFetch);
  const n = mcpCalls;
  const c = await handleCall(b.body, senv, mockFetch);
  assert.equal(mcpCalls, n);                                   // nothing fetched the second time
  assert.equal(c.replay, true);
  assert.equal(jcs(c.receipt), jcs(a.receipt));                 // the same signed bytes, not a new receipt
  assert.equal(jcs(c.audit), jcs(a.audit));
  assert.equal(a.replay, undefined);
});

test("void after the call ran: the receipt comes back, nothing is voided", async () => {
  const b = await build(), senv = { ...env, STATE: fakeKV() };
  const a = await handleCall(b.body, senv, mockFetch);
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v.status, "executed");
  assert.equal(jcs(v.receipt), jcs(a.receipt));
  assert.equal(senv.STATE.m.has("void:" + b.rs), false);
  const again = await handleCall(b.body, senv, mockFetch);      // still answered, still the same receipt
  assert.equal(jcs(again.receipt), jcs(a.receipt));
});

test("void before any call: a signed non-execution statement, and the occurrence is never executed after", async () => {
  const b = await build(), senv = { ...env, STATE: fakeKV() };
  const vq = await voidFor(b);
  const v = await handleVoid({ request: b.request, void: vq }, senv, mockFetch);
  assert.equal(v.status, "not_executed");
  assert.equal(v.request_sha256, b.rs);
  const st = v.statement;
  assert.equal(st.type, "musubi.ca2a.non-execution.v0");
  assert.equal(st.responder, b.X);
  assert.equal(st.caller, b.B);
  assert.equal(st.request_sha256, b.rs);
  assert.deepEqual(st.outcome, { kind: "not_executed" });
  assert.deepEqual(st.seen_block, { height: 920000, hash: "ab".repeat(32) });
  assert.equal(st.void_request_sha256, await sha256hex(jcs(vq)));
  assert.equal(await verify(st, "responder"), true);
  const n = mcpCalls;
  await assert.rejects(() => handleCall(b.body, senv, mockFetch), (e) => e instanceof Refusal && e.code === "request_voided");
  assert.equal(mcpCalls, n);                                   // refused before any audit
  const v2 = await handleVoid({ request: b.request, void: vq }, senv, mockFetch);
  assert.equal(jcs(v2.statement), jcs(st));                     // asking twice returns the stored statement
});

test("void refusals: another signer, another request, a bad signature, no state", async () => {
  const b = await build(), senv = { ...env, STATE: fakeKV() };
  const rej = (body, e2, code) => assert.rejects(() => handleVoid(body, e2, mockFetch), (e) => e instanceof Refusal && e.code === code, code);
  await rej({ request: b.request, void: await voidFor(b, "33".repeat(32)) }, senv, "void_not_by_caller");
  const other = await sign({ type: "musubi.ca2a.void-request.v0", caller: b.B, request_sha256: "00".repeat(32) }, SEED_B);
  await rej({ request: b.request, void: other }, senv, "void_not_for_this_request");
  const forged = { ...(await voidFor(b)), signature: "00".repeat(64) };
  await rej({ request: b.request, void: forged }, senv, "void_signature_invalid");
  await rej({ request: b.request, void: await voidFor(b) }, env, "no_state");
  assert.equal(senv.STATE.m.size, 0);                           // none of them left a mark
});

// ---- the race between /call and /void (Issue #51, aeoess, 2026-10-21)
//
// The report: handleCall checked void: and rcpt: before awaiting the audit and never again, and handleVoid checked
// only rcpt:, so a /void sent while the audit ran signed not_executed and the call then signed a receipt for the
// same occurrence. These tests run the real handlers with a delayed audit and an in-memory store, then the Durable
// Object with a fake state whose blockConcurrencyWhile serializes strictly.

// An MCP server that holds the first audit line until release(); reached resolves when the audit has started.
function gated(onMcp) {
  const g = {};
  let entered;
  g.open = new Promise((r) => { g.release = r; });
  g.reached = new Promise((r) => { entered = r; });
  g.fetch = async (url, init) => {
    if (url === "mock://mcp") { entered(); if (onMcp) onMcp(); await g.open; }
    return mockFetch(url, init);
  };
  return g;
}
const ticks = async (n = 25) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };
function clockAt(t0 = 1_800_000_000_000) { const c = () => c.t; c.t = t0; return c; }
const isCode = (code) => (e) => e instanceof Refusal && e.code === code;

test("the reported interleaving: a void during a delayed audit answers in_progress, never not_executed, and the receipt follows", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  const g = gated();
  const pending = handleCall(b.body, senv, g.fetch);
  await g.reached;                                              // the call is inside the audit
  const run = JSON.parse(kv.m.get("run:" + b.rs));
  assert.equal(run.type, "hs-pilot.in-flight.v0");
  assert.equal(run.request_sha256, b.rs);
  assert.equal(run.started_at_ms, clock.t);
  assert.deepEqual(kv.puts.find(([k]) => k === "run:" + b.rs)[1], { expirationTtl: RUN_TTL_S });
  clock.t += 3000;
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v.status, "in_progress");
  assert.equal(v.request_sha256, b.rs);
  assert.equal(v.statement, undefined);                         // nothing signed
  assert.equal(v.retry_after_s, Math.ceil((RUN_STALE_MS - 3000) / 1000));
  assert.equal(kv.m.has("void:" + b.rs), false);                // nothing voided
  g.release();
  const out = await pending;
  assert.equal(await verify(out.receipt, "responder"), true);
  assert.equal(kv.m.has("rcpt:" + b.rs), true);
  assert.equal(kv.m.has("run:" + b.rs), false);                 // the marker goes once the receipt is stored
  const v2 = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v2.status, "executed");
  assert.equal(jcs(v2.receipt), jcs(out.receipt));
  assert.equal(kv.m.has("void:" + b.rs), false);
});

test("a void that lands while the call audits (a store that did not show the marker) stops the receipt at the recheck", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  // another location's view of KV: the same data, but the fresh marker has not reached it yet
  const elsewhere = { ...senv, STATE: { ...kv, get: (k, t) => (k.startsWith("run:") ? Promise.resolve(null) : kv.get(k, t)) } };
  const g = gated();
  const pending = handleCall(b.body, senv, g.fetch);
  await g.reached;
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, elsewhere, mockFetch);
  assert.equal(v.status, "not_executed");
  g.release();
  await assert.rejects(pending, isCode("request_voided"));
  assert.equal(kv.m.has("rcpt:" + b.rs), false);                // no receipt after a signed not_executed
  assert.equal(kv.m.has("run:" + b.rs), false);
  await assert.rejects(() => handleCall(b.body, senv, mockFetch), isCode("request_voided"));
});

test("a second call while the first runs is refused in_progress; the first call's receipt is the only one", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  const g = gated();
  const first = handleCall(b.body, senv, g.fetch);
  await g.reached;
  const n = mcpCalls;
  await assert.rejects(() => handleCall(b.body, senv, mockFetch), isCode("in_progress"));
  assert.equal(mcpCalls, n);                                   // refused before any audit
  assert.equal(kv.m.has("run:" + b.rs), true);                  // and the first call's marker is untouched
  g.release();
  const out = await first;
  const again = await handleCall(b.body, senv, mockFetch);
  assert.equal(again.replay, true);
  assert.equal(jcs(again.receipt), jcs(out.receipt));
});

test("a stale marker: a crashed call no longer blocks a void, and its occurrence is then refused", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  // a call that wrote its marker and died (no TTL, as in the Durable Object's storage): live until RUN_STALE_MS
  kv.m.set("run:" + b.rs, JSON.stringify({ type: "hs-pilot.in-flight.v0", request_sha256: b.rs, run_id: "00".repeat(16), started_at_ms: clock.t }));
  clock.t += RUN_STALE_MS - 1;
  const v1 = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v1.status, "in_progress");
  assert.equal(v1.retry_after_s, 1);
  await assert.rejects(() => handleCall(b.body, senv, mockFetch), isCode("in_progress"));
  clock.t += 1;
  const v2 = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v2.status, "not_executed");
  assert.equal(await verify(v2.statement, "responder"), true);
  await assert.rejects(() => handleCall(b.body, senv, mockFetch), isCode("request_voided"));
});

test("a marker removed by its KV expirationTtl no longer blocks a void", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  await kv.put("run:" + b.rs, JSON.stringify({ type: "hs-pilot.in-flight.v0", request_sha256: b.rs, run_id: "00".repeat(16), started_at_ms: clock.t }), { expirationTtl: RUN_TTL_S });
  clock.t += RUN_TTL_S * 1000;
  assert.equal(await kv.get("run:" + b.rs), null);              // gone from KV
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v.status, "not_executed");
});

test("a call that outlives its marker can never sign: refused call_expired, then void says not_executed", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  const g = gated();
  const pending = handleCall(b.body, senv, g.fetch);
  await g.reached;
  clock.t += RUN_STALE_MS;                                      // the call hangs: its marker is stale now
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v.status, "not_executed");
  g.release();                                                  // and the hung call wakes up afterwards
  await assert.rejects(pending, isCode("call_expired"));
  assert.equal(kv.m.has("rcpt:" + b.rs), false);
  // the same with no void: a slow audit past RUN_SIGN_BY_MS refuses, removes its marker, and leaves room for a void
  const b2 = await build({ request: { occurrence_id: "pilot-call-slow" } });
  const slow = gated(() => { clock.t += RUN_SIGN_BY_MS; });
  slow.release();
  await assert.rejects(() => handleCall(b2.body, senv, slow.fetch), isCode("call_expired"));
  assert.equal(kv.m.has("rcpt:" + b2.rs), false);
  assert.equal(kv.m.has("run:" + b2.rs), false);
  const v2 = await handleVoid({ request: b2.request, void: await voidFor(b2) }, senv, mockFetch);
  assert.equal(v2.status, "not_executed");
});

test("a failed audit removes its marker, so the caller can void at once", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), senv = { ...env, STATE: kv, CLOCK: clock };
  const down = async (url, init) => (url === "mock://mcp" ? { ok: false, status: 503 } : mockFetch(url, init));
  await assert.rejects(() => handleCall(b.body, senv, down), isCode("audit_unavailable"));
  assert.equal(kv.m.has("run:" + b.rs), false);
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v.status, "not_executed");
});

// ---- the Durable Object: strict serialization per occurrence

// A Durable Object state: storage in memory (get gives undefined for a missing key, as the platform does) and a
// blockConcurrencyWhile that runs one callback at a time and records whether a callback ever threw (which would
// reset a real object).
function fakeState() {
  const store = new Map();
  let chain = Promise.resolve();
  const st = { store, active: 0, maxActive: 0, blocks: 0, broken: false,
    storage: { async get(k) { return store.get(k); }, async put(k, v) { store.set(k, v); }, async delete(k) { store.delete(k); } },
    blockConcurrencyWhile(fn) {
      const p = chain.then(async () => {
        st.active++; st.blocks++; st.maxActive = Math.max(st.maxActive, st.active);
        try { return await fn(); } finally { st.active--; }
      });
      chain = p.then(() => {}, () => { st.broken = true; });
      return p;
    } };
  return st;
}
function object(state, oenv, fetchFn) { const o = new Occurrence(state, oenv); o.fetchFn = fetchFn; return o; }
const post = (path, body) => new Request("https://occurrence" + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

test("Durable Object: the reported interleaving is serialized; the void waits for the call and answers executed", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), st = fakeState();
  const g = gated();
  const o = object(st, { ...env, STATE: kv, CLOCK: clock }, g.fetch);
  const pc = o.fetch(post("/call", b.body));
  await g.reached;
  assert.equal(st.store.has("run:" + b.rs), true);              // the marker is in the object's storage
  assert.equal(kv.m.has("run:" + b.rs), false);                 // and only there
  let voidAnswered = false;
  const pv = o.fetch(post("/void", { request: b.request, void: await voidFor(b) })).then((r) => { voidAnswered = true; return r; });
  await ticks();
  assert.equal(voidAnswered, false);                            // the void waits behind the running call
  assert.equal(st.store.has("void:" + b.rs), false);
  g.release();
  const rc = await pc, rv = await pv;
  assert.equal(rc.status, 200);
  const call = await rc.json(), vd = await rv.json();
  assert.equal(vd.status, "executed");
  assert.equal(jcs(vd.receipt), jcs(call.receipt));
  assert.equal(await verify(call.receipt, "responder"), true);
  assert.equal(st.maxActive, 1);                                // never two at once
  assert.equal(st.blocks, 2);
  assert.equal(st.broken, false);
  assert.equal(st.store.has("run:" + b.rs), false);
  assert.equal(st.store.get("rcpt:" + b.rs), kv.m.get("rcpt:" + b.rs));   // written to KV too, the same bytes
  assert.equal(st.store.has("void:" + b.rs) || kv.m.has("void:" + b.rs), false);
});

test("Durable Object: void first, then call is refused request_voided; refusals never reset the object", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock), st = fakeState();
  const o = object(st, { ...env, STATE: kv, CLOCK: clock }, mockFetch);
  const vq = await voidFor(b);
  const v = await (await o.fetch(post("/void", { request: b.request, void: vq }))).json();
  assert.equal(v.status, "not_executed");
  assert.equal(st.store.get("void:" + b.rs), kv.m.get("void:" + b.rs));
  const n = mcpCalls;
  const r = await o.fetch(post("/call", b.body));
  assert.equal(r.status, 400);
  assert.equal((await r.json()).refused, "request_voided");
  assert.equal(mcpCalls, n);
  const v2 = await (await o.fetch(post("/void", { request: b.request, void: vq }))).json();
  assert.equal(jcs(v2.statement), jcs(v.statement));
  const bad = await o.fetch(post("/call", { ...b.body, extra: 1 }));
  assert.equal((await bad.json()).refused, "fields");
  assert.equal(st.broken, false);
});

test("Durable Object: answers recorded in KV before it existed (the earlier run) are still served", async () => {
  // a receipt and a void written by the KV-only worker, for two occurrences named like the earlier run's
  const clock = clockAt(), kv = fakeKV(clock);
  const bA = await build({ request: { occurrence_id: "hs51-musubi-A" } }), bB = await build({ request: { occurrence_id: "hs51-musubi-B" } });
  const legacyA = await handleCall(bA.body, { ...env, STATE: kv }, mockFetch);
  await handleVoid({ request: bB.request, void: await voidFor(bB) }, { ...env, STATE: kv }, mockFetch);
  const stA = fakeState(), stB = fakeState();
  const oA = object(stA, { ...env, STATE: kv, CLOCK: clock }, mockFetch), oB = object(stB, { ...env, STATE: kv, CLOCK: clock }, mockFetch);
  const n = mcpCalls;
  const replay = await (await oA.fetch(post("/call", bA.body))).json();
  assert.equal(replay.replay, true);
  assert.equal(jcs(replay.receipt), jcs(legacyA.receipt));      // the same signed bytes
  assert.equal(mcpCalls, n);                                   // nothing audited again
  const vA = await (await oA.fetch(post("/void", { request: bA.request, void: await voidFor(bA) }))).json();
  assert.equal(vA.status, "executed");
  assert.equal(jcs(vA.receipt), jcs(legacyA.receipt));
  assert.equal(kv.m.has("void:" + bA.rs), false);
  const rB = await (await oB.fetch(post("/call", bB.body))).json();
  assert.equal(rB.refused, "request_voided");
  assert.equal(stA.store.size + stB.store.size, 0);             // read through, nothing copied, nothing new
});

test("the worker forwards /call and /void to the object named by request_sha256, and refuses bad bodies without state", async () => {
  const b = await build(), clock = clockAt(), kv = fakeKV(clock);
  const objects = new Map();
  const ns = { idFromName: (name) => "id:" + name,
    get: (id) => ({ fetch: (u, init) => {
      if (!objects.has(id)) objects.set(id, { st: fakeState() });
      const e = objects.get(id);
      e.o = e.o || object(e.st, { ...env, STATE: kv, CLOCK: clock }, mockFetch);
      return e.o.fetch(new Request(u, init));
    } }) };
  const wenv = { ...env, STATE: kv, OCCURRENCE: ns };
  const req = (path, body) => new Request("https://hs-pilot.example" + path, { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) });
  const call = await (await worker.fetch(req("/call", b.body), wenv)).json();
  assert.equal(call.request_sha256, b.rs);
  assert.deepEqual([...objects.keys()], ["id:" + b.rs]);
  const again = await (await worker.fetch(req("/call", b.body), wenv)).json();
  assert.equal(again.replay, true);
  const v = await (await worker.fetch(req("/void", { request: b.request, void: await voidFor(b) }), wenv)).json();
  assert.equal(v.status, "executed");
  for (const [path, body, code] of [["/call", "{", "not_json"], ["/call", { task: b.body.task }, "fields"],
    ["/void", { request: { ...b.request, type: "x" }, void: {} }, "wrong_type"]]) {
    const r = await worker.fetch(req(path, body), wenv);
    assert.equal(r.status, 400);
    assert.equal((await r.json()).refused, code);
  }
  assert.equal(objects.size, 1);                                // no object was made for a body that did not check
  const info = await (await worker.fetch(new Request("https://hs-pilot.example/.well-known/pilot.json"), wenv)).json();
  assert.match(info.state, /not_executed is final/);
});

test("a store with only get and put (the payer's self-test server) still works: call, replay, void", async () => {
  const b = await build(), m = new Map();
  const STATE = { get: async (k, t) => (m.has(k) ? (t === "json" ? JSON.parse(m.get(k)) : m.get(k)) : null), put: async (k, v) => { m.set(k, v); } };
  const senv = { ...env, STATE };
  const a = await handleCall(b.body, senv, mockFetch);
  assert.equal(m.get("run:" + b.rs), "null");                   // no delete: the marker is overwritten with null
  assert.equal((await handleCall(b.body, senv, mockFetch)).replay, true);
  const v = await handleVoid({ request: b.request, void: await voidFor(b) }, senv, mockFetch);
  assert.equal(v.status, "executed");
  assert.equal(jcs(v.receipt), jcs(a.receipt));
  const b2 = await build({ request: { occurrence_id: "pilot-call-1" } });
  const v2 = await handleVoid({ request: b2.request, void: await voidFor(b2) }, senv, mockFetch);
  assert.equal(v2.status, "not_executed");
  await assert.rejects(() => handleCall(b2.body, senv, mockFetch), isCode("request_voided"));
});
