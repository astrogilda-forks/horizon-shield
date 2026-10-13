// 2026-10-13. ops/concurrency_audit_20261013.md, finding U1: a payment must not be lost to an overlapping write.
// The order is one KV value with several writers and KV has no compare-and-swap. The KV mock here can (a) hold every
// reader of an order at a barrier until two are inside (both read before either writes) and (b) hold the first put of
// an order until a second one lands, then apply them in the opposite order (the stale write lands last). Both are
// interleavings real KV allows. Every check marked "fails before" fails on the code before this change.
// Run: node test/payment_concurrency.test.mjs   (offline: PayPal, Resend and LINE are mocked)
import assert from "node:assert/strict";
import worker, { sweep } from "../src/index.js";
import { kv, r2, outside } from "./mocks.mjs";

const log = [];
globalThis.fetch = outside(log);
const W = "https://w.example";
const ctx = { waitUntil() {} };
const DAY = 86400000;
const now = Date.now();
const iso = (t) => new Date(t).toISOString();
const lines = () => log.filter((l) => /line\.me/.test(l.url)).map((l) => JSON.parse(l.body).messages[0].text);

function racingEnv({ barrier = false, reorder = false } = {}) {
  const store = kv();
  let waiting = [];
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= 2) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, 150);
  });
  let held = null;
  const US_ORDERS = { m: store.m, meta: store.meta,
    async get(k) { if (barrier && k.startsWith("order:")) await arrive(); return store.get(k); },
    async put(k, v, opts) {
      if (!(reorder && k.startsWith("order:"))) return store.put(k, v, opts);
      if (!held) {
        // first writer of an order: wait for a second, or 150 ms
        return new Promise((resolve) => {
          held = { k, v, opts, resolve };
          setTimeout(async () => { if (held && held.k === k && held.v === v) { const h = held; held = null; await store.put(h.k, h.v, h.opts); h.resolve(); } }, 150);
        });
      }
      const h = held; held = null;
      await store.put(k, v, opts);          // the later write lands first
      await store.put(h.k, h.v, h.opts);    // the earlier (stale) write lands last
      h.resolve();
    },
    delete: (...a) => store.delete(...a), list: (...a) => store.list(...a) };
  const env = { US_ORDERS, US_FILES: r2(), SITE_URL: "https://horizonshield.dev", PUBLIC_WORKER_URL: W, LINK_SECRET: "s", US_ADMIN_TOKEN: "a",
    PAYPAL_BUSINESS: "pay@example.com", RESEND_API_KEY: "x", LINE_CHANNEL_TOKEN: "x", LINE_USER_ID: "U1" };
  return { env, store };
}
const order = (id, extra = {}) => ({ id, plan: "quote_check", plan_name: "Quote Check", price: 39, email: "h@example.com", status: "awaiting_payment", created_at: iso(now), files: [], ...extra });
const putWithMeta = (store, o) => store.put(`order:${o.id}`, JSON.stringify(o), { metadata: { status: o.status, paid_at: o.paid_at || null, created_at: o.created_at } });
const ipn = (env, id, txn) => worker.fetch(new Request(W + "/webhook/paypal", { method: "POST", body: new URLSearchParams({ payment_status: "Completed", receiver_email: "pay@example.com", mc_currency: "USD", mc_gross: "39.00", txn_id: txn, custom: id, payer_email: "p@example.com" }).toString() }), env, ctx);
const read = (store, id) => JSON.parse(store.m.get(`order:${id}`) || "null");

let n = 0, fail = 0;
const chk = (name, fn) => { n++; try { fn(); console.log("PASS  " + name); } catch (e) { fail++; console.log("FAIL  " + name + "  <<< " + String(e.message).slice(0, 240)); } };

// 1. Two payments for one order at the same time. Both read "awaiting_payment", so neither saw the other: before the
//    fix the second overwrote the first txn and no one was told about the double payment.
{
  const ID = "US-20261013-DOUBLE";
  const { env, store } = racingEnv({ barrier: true });
  await putWithMeta(store, order(ID));
  log.length = 0;
  const [a, b] = await Promise.all([ipn(env, ID, "TXNA"), ipn(env, ID, "TXNB")]);
  chk("1 both IPNs answered 200", () => { assert.equal(a.status, 200); assert.equal(b.status, 200); });
  chk("1 both payments are kept, each in its own key (fails before)", () => {
    assert.ok(store.m.has(`pay:${ID}:TXNA`)); assert.ok(store.m.has(`pay:${ID}:TXNB`));
  });
  await sweep(env, now + 60000);
  chk("1 the hourly sweep raises the double payment with both txns (fails before)", () => {
    const hit = lines().filter((t) => t.includes("二重払い") && t.includes(ID));
    assert.equal(hit.length, 1, JSON.stringify(lines()));
    assert.ok(hit[0].includes("TXNA") && hit[0].includes("TXNB"), hit[0]);
  });
  log.length = 0;
  await sweep(env, now + 120000);
  chk("1 and only once", () => assert.equal(lines().filter((t) => t.includes("二重払い")).length, 0, JSON.stringify(lines())));
}

// 2. "paid" lost to a stale write: the sweep repairs the metadata of an order stored without it, from a copy it read
//    just before the IPN marked the order paid; its write lands last. Before the fix the order stayed
//    awaiting_payment for good (the draft cron never picks it up, the customer paid for nothing).
{
  const ID = "US-20261013-STALEW";
  const { env, store } = racingEnv({ barrier: true, reorder: true });
  await store.put(`order:${ID}`, JSON.stringify(order(ID)));   // no metadata: the sweep's repair path
  log.length = 0;
  const [r, s0] = await Promise.all([ipn(env, ID, "TXNS"), sweep(env, now + 60000)]);
  chk("2 IPN answered 200", () => assert.equal(r.status, 200));
  chk("2 a payment younger than the grace is not acted on (the IPN may still be writing)", () => assert.equal(s0.pay_repaired, 0));
  const s = await sweep(env, now + 61 * 60000);   // the next hourly sweep
  chk("2 the order ends paid with the payment's txn (fails before)", () => {
    const o = read(store, ID);
    assert.equal(o.status, "paid", JSON.stringify(o)); assert.equal(o.txn_id, "TXNS");
    assert.equal(store.meta.get(`order:${ID}`).status, "paid");
  });
  chk("2 the repair is reported on LINE and counted", () => {
    assert.ok(lines().some((t) => t.includes("入金の反映漏れを直した") && t.includes(ID)), JSON.stringify(lines()));
    assert.equal(s.pay_repaired, 1);
  });
}

// 3. The unpaid-order cleanup never deletes an order that has a payment, even when the order itself still reads
//    awaiting_payment (its "paid" was lost or is not visible yet). Before the fix the order and its files were deleted.
{
  const ID = "US-20261013-NODELE";
  const { env, store } = racingEnv();
  const created = now - 8 * DAY;
  await putWithMeta(store, order(ID, { created_at: iso(created), files: [{ key: `uploads/${ID}/1.pdf` }] }));
  await env.US_FILES.put(`uploads/${ID}/1.pdf`, "%PDF-1.4", { _uploaded: created });
  await store.put(`pay:${ID}:TXNL`, JSON.stringify({ order_id: ID, txn_id: "TXNL", gross: 39, currency: "USD", at: iso(now - 20 * 60000) }), { metadata: { order: ID, txn: "TXNL", at: iso(now - 20 * 60000) } });
  const s = await sweep(env, now);
  chk("3 the order is not deleted (fails before)", () => { assert.ok(store.m.has(`order:${ID}`)); assert.equal(s.unpaid_removed, 0); });
  chk("3 and is marked paid", () => assert.equal(read(store, ID).status, "paid"));
}

// 4. A payment whose order is gone is raised once, never silently dropped.
{
  const ID = "US-20261013-ORPHAN";
  const { env, store } = racingEnv();
  await store.put(`pay:${ID}:TXNO`, "{}", { metadata: { order: ID, txn: "TXNO", at: iso(now - 20 * 60000) } });
  log.length = 0;
  const s = await sweep(env, now);
  await sweep(env, now + 1000);
  chk("4 the orphan payment is raised once", () => { assert.equal(s.pay_orphans, 1); assert.equal(lines().filter((t) => t.includes(ID)).length, 1, JSON.stringify(lines())); });
}

// 5. /health says which build is live (ops/prod_fix_check.sh reads it).
{
  const { env } = racingEnv();
  const r = await worker.fetch(new Request(W + "/health"), env, ctx);
  const j = await r.json();
  chk("5 /health payments marker", () => assert.equal(j.payments, "pay-record-v1-20261013"));
}

console.log(fail ? `payment_concurrency FAILED ${fail}/${n}` : `payment_concurrency ok ${n}/${n}`);
process.exit(fail ? 1 : 0);
