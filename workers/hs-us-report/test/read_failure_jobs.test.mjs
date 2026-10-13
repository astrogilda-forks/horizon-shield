// 2026-10-13. Issue #13 in the paths read_failure.test.mjs does not cover: the PayPal IPN, draft generation, the
// crons and the daily counts. A KV read that throws must not be handled as "no order" or "no counts": the IPN answers
// 503 so PayPal sends it again, a job skips the item, writes and sends nothing and logs it, and a counter does not
// overwrite the day's counts. Every check here fails on the code before this change.
import assert from "node:assert/strict";
import worker, { generateDraft, draftPending, sweep } from "../src/index.js";
import { dailyStats } from "../src/teardown.js";
import { kv, r2, outside } from "./mocks.mjs";
import { signPath } from "../src/sign.js";

const log = [];
globalThis.fetch = outside(log);
const SITE = "https://horizonshield.dev";
const W = "https://w.example";
const SECRET = "link-secret-for-tests";
const ctx = { waitUntil() {} };
const admin = { authorization: "Bearer admin-token-for-tests" };
const DAY = 86400000;

// A fresh KV per section. broken: every get of the key throws. failAfter: key -> reads that succeed before one throws.
function mkEnv() {
  const store = kv();
  const broken = new Set();
  const failAfter = new Map();
  const US_ORDERS = { m: store.m, meta: store.meta,
    async get(k) {
      if (broken.has(k)) throw new Error("KV get failed (simulated)");
      if (failAfter.has(k)) { const left = failAfter.get(k); if (left === 0) { failAfter.delete(k); throw new Error("KV get failed (simulated)"); } failAfter.set(k, left - 1); }
      return store.get(k);
    },
    put: (...a) => store.put(...a), delete: (...a) => store.delete(...a), list: (...a) => store.list(...a) };
  const env = { US_ORDERS, US_FILES: r2(), SITE_URL: SITE, PUBLIC_WORKER_URL: W, LINK_SECRET: SECRET, US_ADMIN_TOKEN: "admin-token-for-tests",
    PAYPAL_BUSINESS: "pay@example.com", RESEND_API_KEY: "x", LINE_CHANNEL_TOKEN: "x", LINE_USER_ID: "U1" };
  return { env, store, broken, failAfter };
}
const putOrder = (store, o) => store.put(`order:${o.id}`, JSON.stringify(o), { metadata: { status: o.status, paid_at: o.paid_at || null, created_at: o.created_at } });
const sent = () => log.filter((l) => /resend|line\.me/.test(l.url)).length;

// console.error is where a job records a skipped item (Workers logs); collect it here.
const errors = [];
const realError = console.error;
console.error = (...a) => { errors.push(a.join(" ")); };

let n = 0, fail = 0;
const chk = (name, fn) => { n++; try { fn(); console.log("PASS  " + name); } catch (e) { fail++; console.log("FAIL  " + name + "  <<< " + String(e.message).slice(0, 240)); } };

const ID = "US-20261013-PAYPAL";
const now = Date.now();
const iso = (t) => new Date(t).toISOString();

// ---- 1. PayPal IPN, order read fails
{
  const { env, store, broken } = mkEnv();
  await putOrder(store, { id: ID, plan: "quote_check", plan_name: "Quote Check", price: 39, email: "h@example.com", status: "awaiting_payment", created_at: iso(now) });
  const ipn = (o = {}) => worker.fetch(new Request(W + "/webhook/paypal", { method: "POST", body: new URLSearchParams({ payment_status: "Completed", receiver_email: "pay@example.com", mc_currency: "USD", mc_gross: "39.00", txn_id: "TXN1", custom: ID, payer_email: "p@example.com", ...o }).toString() }), env, ctx);
  broken.add(`order:${ID}`);
  const before = sent();
  let r = await ipn();
  const status1 = r.status;
  const body = await r.json();
  const skips = [...store.m.keys()].filter((k) => k.startsWith("ipn-skip:"));
  const statusDuring = JSON.parse(store.m.get(`order:${ID}`)).status;
  const sentDuring = sent() - before;
  broken.delete(`order:${ID}`);
  r = await ipn();                                  // PayPal sends it again once KV answers
  const body2 = await r.json();
  chk("IPN with the order unreadable: 503 order_read_failed (PayPal retries 5xx), no ipn-skip, nothing sent; the resent IPN marks it paid", () => {
    assert.equal(status1, 503, "not 200 'unknown order'");
    assert.equal(body.error, "order_read_failed");
    assert.deepEqual(skips, [], "no ipn-skip record");
    assert.equal(statusDuring, "awaiting_payment");
    assert.equal(sentDuring, 0, "no email or LINE");
    assert.equal(body2.order, ID);
    assert.equal(JSON.parse(store.m.get(`order:${ID}`)).status, "paid");
  });
}

// ---- 2. PayPal IPN, txn dedupe read fails
{
  const { env, store, broken } = mkEnv();
  await putOrder(store, { id: ID, plan: "quote_check", plan_name: "Quote Check", price: 39, email: "h@example.com", status: "awaiting_payment", created_at: iso(now) });
  broken.add("txn:TXN9");
  const r = await worker.fetch(new Request(W + "/webhook/paypal", { method: "POST", body: new URLSearchParams({ payment_status: "Completed", receiver_email: "pay@example.com", mc_currency: "USD", mc_gross: "39.00", txn_id: "TXN9", custom: ID }).toString() }), env, ctx);
  const body = await r.json();
  chk("IPN with the txn record unreadable: 503 txn_read_failed, order not marked paid", () => {
    assert.equal(r.status, 503);
    assert.equal(body.error, "txn_read_failed");
    assert.equal(JSON.parse(store.m.get(`order:${ID}`)).status, "awaiting_payment");
  });
}

// ---- 3. generateDraft and the admin /draft route
{
  const { env, store, broken, failAfter } = mkEnv();
  const DID = "US-20261013-DRAFTA";
  await putOrder(store, { id: DID, plan: "quote_check", price: 39, status: "paid", paid_at: iso(now), created_at: iso(now) });
  const snapshot = store.m.get(`order:${DID}`);
  broken.add(`order:${DID}`);
  let err = null;
  try { await generateDraft(env, DID); } catch (e) { err = e; }
  broken.delete(`order:${DID}`);
  let absentErr = null;
  try { await generateDraft(env, "US-20261013-NOSUCH"); } catch (e) { absentErr = e; }
  chk("generateDraft with the order unreadable: throws order_read_failed (not order not found) and writes nothing; absent still 'order not found'", () => {
    assert.ok(err, "it throws");
    assert.equal(err.code, "order_read_failed");
    assert.ok(!/not found/.test(err.message), err.message);
    assert.equal(store.m.get(`order:${DID}`), snapshot, "order untouched");
    assert.equal(absentErr && absentErr.message, "order not found");
  });

  failAfter.set(`order:${DID}`, 1);                  // the route's read succeeds, generateDraft's read fails
  const r = await worker.fetch(new Request(W + `/admin/orders/${DID}/draft?ask=0`, { method: "POST", headers: admin }), env, ctx);
  const body = await r.json();
  chk("admin POST /draft when the draft's own order read fails: 503 order_read_failed, not 500 'order not found'", () => {
    assert.equal(r.status, 503);
    assert.equal(body.error, "order_read_failed");
    assert.equal(store.m.get(`order:${DID}`), snapshot, "order untouched");
  });
}

// ---- 4. draftPending (cron, every minute)
for (const [label, o] of [
  ["awaiting_answers past the deadline", { id: "US-20261013-WAITAA", status: "awaiting_answers", paid_at: iso(now - 9 * 3600000), created_at: iso(now - 9 * 3600000), followup: { deadline: iso(now - 3600000), questions: [] } }],
  ["draft_failed due for a retry", { id: "US-20261013-RETRYA", status: "draft_failed", paid_at: iso(now - 3600000), created_at: iso(now - 3600000), drafting_since: iso(now - 30 * 60000), draft_attempts: 1 }],
  ["paid (read fails inside generateDraft)", { id: "US-20261013-PAIDAA", status: "paid", paid_at: iso(now - 60000), created_at: iso(now - 60000) }],
]) {
  const { env, store, broken } = mkEnv();
  await putOrder(store, o);
  const snapshot = store.m.get(`order:${o.id}`);
  broken.add(`order:${o.id}`);
  errors.length = 0;
  const before = sent();
  await draftPending(env, now);
  chk(`draftPending, ${label}, order unreadable: skipped and logged; nothing written or sent`, () => {
    assert.ok(errors.some((e) => e.includes("order_read_failed") && e.includes(o.id)), "the skip is logged: " + JSON.stringify(errors));
    assert.equal(store.m.get(`order:${o.id}`), snapshot, "order untouched");
    assert.equal(sent() - before, 0, "no email or LINE");
  });
}

// ---- 5. sweep (cron, hourly)
{
  const { env, store, broken } = mkEnv();
  const o = { id: "US-20261013-LATEAA", status: "draft_ready", paid_at: iso(now - 21 * 3600000), created_at: iso(now - 22 * 3600000) };
  await putOrder(store, o);
  const snapshot = store.m.get(`order:${o.id}`);
  broken.add(`order:${o.id}`);
  errors.length = 0;
  const before = sent();
  const s = await sweep(env, now);
  chk("sweep with an order unreadable: counted in read_failed and logged, not changed, no late alert", () => {
    assert.equal(s.read_failed, 1);
    assert.equal(s.late_alerts, 0);
    assert.ok(errors.some((e) => e.includes("order_read_failed") && e.includes(o.id)), JSON.stringify(errors));
    assert.equal(store.m.get(`order:${o.id}`), snapshot);
    assert.equal(sent() - before, 0);
  });
}

// ---- 6. daily counts
const today = new Date(now).toISOString().slice(0, 10);
{
  const { env, store, broken } = mkEnv();
  await store.put(`stats:${today}`, JSON.stringify({ land_x: 5, teardown_ok: 3 }));
  broken.add(`stats:${today}`);
  const r = await worker.fetch(new Request(W + "/event", { method: "POST", body: JSON.stringify({ event: "land_x" }), headers: { origin: SITE, "content-type": "text/plain" } }), env, ctx);
  chk("an event while the day's counts are unreadable: the counts are not overwritten with one event", () => {
    assert.equal(r.status, 200, "counting still never blocks the page");
    assert.deepEqual(JSON.parse(store.m.get(`stats:${today}`)), { land_x: 5, teardown_ok: 3 });
  });

  const r2 = await worker.fetch(new Request(W + "/admin/stats?days=1", { headers: admin }), env, ctx);
  const body = await r2.json();
  chk("/admin/stats with a day unreadable: 503 stats_read_failed, not a day of zeros", () => {
    assert.equal(r2.status, 503);
    assert.equal(body.error, "stats_read_failed");
  });
}
{
  const { env, store, broken } = mkEnv();
  const midnight = Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), new Date(now).getUTCDate() + 1, 0, 5);
  await store.put(`stats:${today}`, JSON.stringify({ land_x: 7 }));
  broken.add(`stats:${today}`);
  errors.length = 0;
  const before = sent();
  const res = await dailyStats(env, midnight);
  const markDuring = store.m.has(`stats_sent:${today}`);
  const sentDuring = sent() - before;
  broken.delete(`stats:${today}`);
  const res2 = await dailyStats(env, midnight + 60000);
  const lines = log.filter((l) => l.url.includes("line.me")).map((l) => JSON.parse(l.body).messages[0].text);
  chk("dailyStats with the day unreadable: sends nothing and sets no mark; once readable it sends the real counts", () => {
    assert.equal(res, false);
    assert.equal(markDuring, false, "no stats_sent mark");
    assert.equal(sentDuring, 0, "no zero report to LINE");
    assert.ok(errors.some((e) => e.includes("stats_read_failed")), JSON.stringify(errors));
    assert.ok(res2, "sent after the read recovers");
    assert.ok(lines.pop().includes("来た 7"), "the real count, not zero");
  });
}

console.error = realError;
if (fail) { console.log(`read_failure_jobs: ${fail} FAILURES of ${n}`); process.exit(1); }
console.log(`read_failure_jobs ok ${n}/${n}`);
