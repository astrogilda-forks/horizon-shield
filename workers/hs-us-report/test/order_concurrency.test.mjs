// 2026-10-13. ops/concurrency_audit_20261013.md, findings U2 to U5 for hs-us-report.
//   U2 the homeowner's follow-up answers vs the draft cron writing the same order:<id> value
//   U3 the minute cron drafting one order twice because KV list metadata lags a put
//   U4 the hourly sweep deleting an unpaid order at the 7 day boundary while a payment is landing
//   U5 the board_index value shared by every publish of a card
// The KV mock can hold every reader of a key prefix at a barrier until two readers are inside (both read before
// either writes) and can answer list() from a stale snapshot (freezeList), both interleavings real KV allows.
// Every check marked "fails before" fails on the code before this change.
// Run: node test/order_concurrency.test.mjs   (offline: PayPal, Resend, LINE and the AI reader are stand-ins)
import assert from "node:assert/strict";
import * as us from "../src/index.js";
import * as td from "../src/teardown.js";
import { kv, r2, outside, jccdbService, EXTRACTED } from "./mocks.mjs";
import { resolveZip } from "../src/geo.js";
import { signPath } from "../src/sign.js";

const worker = us.default;
const { generateDraft, draftPending, sweep } = us;
const log = [];
globalThis.fetch = outside(log);
const W = "https://w.example";
const SITE = "https://horizonshield.dev";
const ctx = { waitUntil() {} };
const DAY = 86400000, MIN = 60000;
const now = Date.now();
const iso = (t) => new Date(t).toISOString();
const lines = () => log.filter((l) => /line\.me/.test(l.url)).map((l) => JSON.parse(l.body).messages[0].text);

// barrier: key prefixes whose get() waits until a second reader arrives, or 150 ms.
function mkEnv({ barrier = [], lagList = false } = {}) {
  const store = kv({ lagList });
  let waiting = [];
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= 2) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, 150);
  });
  const US_ORDERS = { m: store.m, meta: store.meta, freezeList: () => store.freezeList(), thawList: () => store.thawList(),
    async get(k) { if (barrier.some((p) => k.startsWith(p))) await arrive(); return store.get(k); },
    put: (...a) => store.put(...a), delete: (...a) => store.delete(...a), list: (...a) => store.list(...a) };
  const env = { US_ORDERS, US_FILES: r2(), JCCDB: jccdbService([]), BROWSER: {}, SITE_URL: SITE, PUBLIC_WORKER_URL: W, LINK_SECRET: "link-secret-for-tests",
    US_ADMIN_TOKEN: "admin-token-for-tests", PAYPAL_BUSINESS: "pay@example.com", ANTHROPIC_API_KEY: "x", RESEND_API_KEY: "x", LINE_CHANNEL_TOKEN: "x", LINE_USER_ID: "U1" };
  return { env, store };
}
const geo = resolveZip("78745");
const order = (id, extra = {}) => ({ id, plan: "quote_check", plan_name: "Quote Check", price: 39, currency: "USD", email: "h@example.com", name: "", contractor: "",
  zip: geo.zip, geo, text: "Roof quote lines", description: "", files: [], status: "awaiting_payment", created_at: iso(now), trade: "roof", ...extra });
const putWithMeta = (store, o) => store.put(`order:${o.id}`, JSON.stringify(o), { metadata: { status: o.status, paid_at: o.paid_at || null, created_at: o.created_at } });
const read = (store, id) => JSON.parse(store.m.get(`order:${id}`) || "null");
const ipn = (env, id, txn) => worker.fetch(new Request(W + "/webhook/paypal", { method: "POST", body: new URLSearchParams({ payment_status: "Completed", receiver_email: "pay@example.com", mc_currency: "USD", mc_gross: "39.00", txn_id: txn, custom: id, payer_email: "p@example.com" }).toString() }), env, ctx);
const pdfOk = async (e, htmls) => htmls.map((h) => new TextEncoder().encode(h));
const reportOf = (env, o) => JSON.parse(new TextDecoder().decode(env.US_FILES.m.get(`reports/${o.id}/${o.draft.sha256.slice(0, 16)}/report.json`).bytes));
const keysWith = (store, prefix) => [...store.m.keys()].filter((k) => k.startsWith(prefix));

let n = 0, fail = 0;
const chk = (name, fn) => { n++; try { fn(); console.log("PASS  " + name); } catch (e) { fail++; console.log("FAIL  " + name + "  <<< " + String(e.message).slice(0, 240)); } };

const INSIDE_CITY_Q = { id: "inside_city", text: "The quote includes a permit line. Is the property inside the city limits?", fields: [{ id: "inside_city", label: "Inside the city limits?", type: "select", options: [["yes", "Yes"], ["no", "No"], ["not_sure", "Not sure"]] }] };
const followup = (t) => ({ asked_at: iso(t - 9 * 3600000), deadline: iso(t - 3600000), questions: [INSIDE_CITY_Q], email_sent: true });

// ---------------------------------------------------------------- U2
// 1. The homeowner answers while the draft is being made (the PDF step is held open until the answer is saved). The
//    draft then writes its older copy of the order last. Before the fix the answers the homeowner was told "are in"
//    were gone and the order sat at draft_ready without them.
{
  const ID = "US-20261013-ANSWRA";
  const { env, store } = mkEnv();
  await putWithMeta(store, order(ID, { status: "awaiting_answers", paid_at: iso(now - 10 * 3600000), created_at: iso(now - 10 * 3600000),
    hearing: { version: "us-hearing-1.0", answers: { property_type: "single_family" }, ignored: [], answered_at: iso(now - 10 * 3600000) }, followup: followup(now), extracted_cache: EXTRACTED, draft_attempts: 0 }));
  let release, reached;
  const gate = new Promise((r) => { release = r; });
  const atPdf = new Promise((r) => { reached = r; });
  const draft = generateDraft(env, ID, { htmlToPdf: async (e, htmls) => { reached(); await gate; return pdfOk(e, htmls); } });
  await atPdf;
  log.length = 0;
  const link = await signPath(env.LINK_SECRET, `/answer/${ID}`, DAY);
  const r = await worker.fetch(new Request(W + link, { method: "POST", body: new URLSearchParams({ h_inside_city: "yes" }), headers: { "content-type": "application/x-www-form-urlencoded" } }), env, ctx);
  chk("1 the answer link answered 200 and said the answers are in", () => assert.equal(r.status, 200));
  chk("1 the answer set is its own write-once key ans:<id>:<ts> (fails before)", () => {
    const ks = keysWith(store, `ans:${ID}:`);
    assert.equal(ks.length, 1, JSON.stringify(ks));
    assert.equal(JSON.parse(store.m.get(ks[0])).answers.inside_city, "yes");
  });
  release();
  const after = await draft;
  chk("1 the draft that overlapped the answer is not shipped as draft_ready: the order is queued for a redraft (fails before)", () => {
    assert.equal(read(store, ID).status, "answered", JSON.stringify(read(store, ID).status));
    assert.equal(after.status, "answered");
    assert.ok(lines().some((t) => t.includes(ID) && t.includes("作り直す")), JSON.stringify(lines()));
  });
  chk("1 hearingAnswers (merged read) is exported (fails before)", () => assert.equal(typeof us.hearingAnswers, "function"));
  if (typeof us.hearingAnswers === "function") {
    const merged = await us.hearingAnswers(env, ID);
    chk("1 merged answers: blob answers plus the per-key set, after the stale write (fails before)", () => { assert.equal(merged.inside_city, "yes"); assert.equal(merged.property_type, "single_family"); });
  }
  log.length = 0;
  const redone = await generateDraft(env, ID, { htmlToPdf: pdfOk });
  chk("1 the redraft reads the answer into the report (fails before)", () => {
    assert.equal(redone.status, "draft_ready");
    const rep = reportOf(env, redone);
    const a = (rep.hearing && rep.hearing.answers || []).find((x) => x.id === "inside_city");
    assert.ok(a && a.value === "Yes", JSON.stringify(rep.hearing));
    assert.ok(lines().some((t) => t.includes("下書きができた") && t.includes(ID)));
  });
}

// 1b. The re-check of late answers after the PDF step fails (KV list error). "Could not read" is not "none": the order
//     must not be marked draft_ready over a copy that may already say "answered". It is marked draft_failed by the
//     usual failure path and remade on the next round from the answer keys (issue #13 guard, 2026-10-13).
{
  const ID = "US-20261013-ANSWRB";
  const { env, store } = mkEnv();
  await putWithMeta(store, order(ID, { status: "awaiting_answers", paid_at: iso(now - 10 * 3600000), created_at: iso(now - 10 * 3600000),
    hearing: { version: "us-hearing-1.0", answers: { property_type: "single_family" }, ignored: [], answered_at: iso(now - 10 * 3600000) }, followup: followup(now), extracted_cache: EXTRACTED, draft_attempts: 0 }));
  const realList = env.US_ORDERS.list;
  let armed = false;
  env.US_ORDERS.list = async (opts) => { if (armed && opts && String(opts.prefix || "").startsWith(`ans:${ID}:`)) throw new Error("kv list unavailable"); return realList(opts); };
  log.length = 0;
  let threw = null;
  try { await generateDraft(env, ID, { htmlToPdf: async (e, htmls) => { armed = true; return pdfOk(e, htmls); } }); } catch (e) { threw = e; }
  chk("1b a failed late-answers list does not ship the draft: generateDraft throws answers_read_failed", () => assert.ok(threw && /answers_read_failed/.test(String(threw.message)), String(threw && threw.message)));
  chk("1b the order is not draft_ready after the failed read", () => assert.notEqual(read(store, ID).status, "draft_ready", read(store, ID).status));
  chk("1b the order is queued for a retry (draft_failed, attempts counted)", () => { assert.equal(read(store, ID).status, "draft_failed"); assert.ok((read(store, ID).draft_attempts || 0) >= 1); });
  env.US_ORDERS.list = realList;
}

// 2. An order from before this change: its answers live only in the order value, no ans:* key. They are still read.
{
  const ID = "US-20261013-LEGACY";
  const { env, store } = mkEnv();
  await putWithMeta(store, order(ID, { status: "answered", paid_at: iso(now - 2 * 3600000), created_at: iso(now - 2 * 3600000),
    hearing: { version: "us-hearing-1.0", answers: { property_type: "single_family", inside_city: "no" }, ignored: [], answered_at: iso(now - 3600000) }, followup: { ...followup(now), answered_at: iso(now - 3600000), answered_fields: ["inside_city"] }, extracted_cache: EXTRACTED, draft_attempts: 0 }));
  const o = await generateDraft(env, ID, { htmlToPdf: pdfOk });
  chk("2 answers stored in the old place only are still in the report", () => {
    assert.equal(o.status, "draft_ready");
    const a = (reportOf(env, o).hearing.answers || []).find((x) => x.id === "inside_city");
    assert.ok(a && a.value === "No", JSON.stringify(reportOf(env, o).hearing));
    assert.equal(keysWith(store, `ans:${ID}:`).length, 0, "the draft writes no answer key of its own");
  });
}

// 3. The operator's PUT /admin/orders/<id>/hearing also writes its own key, and GET shows the merged answers.
{
  const ID = "US-20261013-OPERAT";
  const { env, store } = mkEnv();
  await putWithMeta(store, order(ID, { status: "draft_failed", paid_at: iso(now - 3600000), created_at: iso(now - 3600000), hearing: { version: "us-hearing-1.0", answers: { stories: 1 }, ignored: [] }, draft_attempts: 1 }));
  const admin = { authorization: "Bearer admin-token-for-tests", "content-type": "application/json" };
  const r = await worker.fetch(new Request(`${W}/admin/orders/${ID}/hearing`, { method: "PUT", body: JSON.stringify({ answers: { stories: 2, roof_squares: 30 } }), headers: admin }), env, ctx);
  chk("3 operator answers: one ans key, merged in the GET (fails before)", () => {
    assert.equal(r.status, 200);
    assert.equal(keysWith(store, `ans:${ID}:`).length, 1);
  });
  const g = await (await worker.fetch(new Request(`${W}/admin/orders/${ID}`, { headers: admin }), env, ctx)).json();
  chk("3 GET /admin/orders/<id> shows the merged answers", () => { assert.equal(g.hearing.answers.stories, "2"); assert.equal(g.hearing.answers.roof_squares, 30); });
}

// ---------------------------------------------------------------- U3
// 4. Minute 0 drafted the order; at minute 1 the list metadata still says "paid" (KV list lags a put by up to 60 s).
//    Before the fix the order was drafted again: double AI cost, two review links, the first one dead.
{
  const ID = "US-20261013-LAGLST";
  const { env, store } = mkEnv({ lagList: true });
  await putWithMeta(store, order(ID, { status: "paid", paid_at: iso(now - MIN), created_at: iso(now - 2 * MIN), extracted_cache: EXTRACTED }));
  store.freezeList();   // the list keeps saying "paid" from here on
  let drafts = 0;
  const deps = { htmlToPdf: pdfOk, extract: async () => { drafts++; return { extracted: EXTRACTED, gates: { pass: true, notes: [] } }; }, skipFollowup: true };
  log.length = 0;
  const a = await draftPending(env, now, deps);
  const told = () => lines().filter((t) => t.includes(ID)).length;   // every draft outcome is told on LINE
  const toldAfterFirst = told();
  const b = await draftPending(env, now + MIN, deps);
  chk("4 the first run drafted the order", () => { assert.deepEqual(a, [ID]); assert.ok(toldAfterFirst >= 1, JSON.stringify(lines())); });
  chk("4 the second run, fed stale list metadata, re-reads the order and does not draft it again (fails before)", () => {
    assert.deepEqual(b, [], JSON.stringify(b));
    assert.equal(told(), toldAfterFirst, "no second draft: " + JSON.stringify(lines()));
  });
  chk("4 the claim key is released after the draft so a redraft after new answers is not held up", () => assert.equal(keysWith(store, `draftclaim:${ID}`).length, 0));
}

// 5. Two cron runs overlap (a draft takes tens of seconds, the cron fires every minute). Both list the order as "paid"
//    and both read it before either writes. Before the fix both drafted it.
{
  const ID = "US-20261013-TWORUN";
  const { env, store } = mkEnv({ barrier: ["order:", "draftclaim:"] });
  await putWithMeta(store, order(ID, { status: "paid", paid_at: iso(now - MIN), created_at: iso(now - 2 * MIN), extracted_cache: EXTRACTED }));
  let drafts = 0;
  const deps = { htmlToPdf: pdfOk, extract: async () => { drafts++; return { extracted: EXTRACTED, gates: { pass: true, notes: [] } }; }, skipFollowup: true };
  log.length = 0;
  const [a, b] = await Promise.all([draftPending(env, now, deps), draftPending(env, now, deps)]);
  const made = lines().filter((t) => t.includes("下書きができた") && t.includes(ID)).length + lines().filter((t) => t.includes("下書きに失敗") && t.includes(ID)).length;
  chk("5 exactly one of two overlapping runs drafts the order (fails before)", () => {
    assert.equal([a, b].filter((x) => x.length).length, 1, JSON.stringify([a, b]));
    assert.equal(made, 1, JSON.stringify(lines()));
  });
}

// 6. The claim is fail closed: when the claim key cannot be read, nothing is drafted and the order is untouched.
{
  const ID = "US-20261013-CLAIMF";
  const { env, store } = mkEnv();
  await putWithMeta(store, order(ID, { status: "paid", paid_at: iso(now - MIN), created_at: iso(now - 2 * MIN), extracted_cache: EXTRACTED }));
  const snapshot = store.m.get(`order:${ID}`);
  const realGet = env.US_ORDERS.get.bind(env.US_ORDERS);
  env.US_ORDERS.get = async (k) => { if (k.startsWith("draftclaim:")) throw new Error("KV get failed (simulated)"); return realGet(k); };
  const errors = [];
  const realError = console.error;
  console.error = (...a) => errors.push(a.join(" "));
  const r = await draftPending(env, now, { htmlToPdf: pdfOk, skipFollowup: true });
  console.error = realError;
  chk("6 claim unreadable: skipped, logged, order untouched (fails before)", () => {
    assert.deepEqual(r, []);
    assert.equal(store.m.get(`order:${ID}`), snapshot);
    assert.ok(errors.some((e) => e.includes(ID)), JSON.stringify(errors));
  });
}

// ---------------------------------------------------------------- U4
// 7. An unpaid order crosses the 7 day line. The first sweep only marks it (delmark:<id>); the delete waits for a
//    later sweep, when the mark is older than an hour, no pay:<order>:* key exists and a fresh read still says unpaid.
//    Before the fix the first sweep deleted the order and its files at once.
{
  const ID = "US-20261013-UNPAID";
  const { env, store } = mkEnv();
  const created = now - 8 * DAY;
  await putWithMeta(store, order(ID, { created_at: iso(created), files: [{ key: `uploads/${ID}/1.pdf` }] }));
  await env.US_FILES.put(`uploads/${ID}/1.pdf`, "%PDF-1.4", { _uploaded: created });
  const s1 = await sweep(env, now);
  chk("7 first sweep: marked, not deleted (fails before)", () => {
    assert.ok(store.m.has(`order:${ID}`), "order still there");
    assert.ok(env.US_FILES.m.has(`uploads/${ID}/1.pdf`), "file still there");
    assert.ok(store.m.has(`delmark:${ID}`), "delmark written");
    assert.equal(s1.unpaid_removed, 0);
    assert.equal(s1.unpaid_marked, 1);
  });
  const s2 = await sweep(env, now + 30 * MIN);
  chk("7 a sweep 30 minutes later still does not delete (mark younger than an hour)", () => { assert.ok(store.m.has(`order:${ID}`)); assert.equal(s2.unpaid_removed, 0); });
  // the payment lands between the mark and the delete
  const r = await ipn(env, ID, "TXNU");
  chk("7 the IPN marks the order paid and clears the delete mark (fails before)", () => {
    assert.equal(r.status, 200);
    assert.equal(read(store, ID).status, "paid");
    assert.ok(!store.m.has(`delmark:${ID}`), "delmark cleared");
  });
  const s3 = await sweep(env, now + 2 * 3600000);
  chk("7 the sweep after the payment keeps the order and its file", () => { assert.ok(store.m.has(`order:${ID}`)); assert.ok(env.US_FILES.m.has(`uploads/${ID}/1.pdf`)); assert.equal(s3.unpaid_removed, 0); });
}

// 8. The same order, never paid: marked, then deleted by the sweep an hour later, with its file and its mark.
{
  const ID = "US-20261013-UNPDEL";
  const { env, store } = mkEnv();
  const created = now - 8 * DAY;
  await putWithMeta(store, order(ID, { created_at: iso(created), files: [{ key: `uploads/${ID}/1.pdf` }] }));
  await env.US_FILES.put(`uploads/${ID}/1.pdf`, "%PDF-1.4", { _uploaded: created });
  await sweep(env, now);
  const s = await sweep(env, now + 61 * MIN);
  chk("8 second pass an hour later: order, file and mark deleted", () => {
    assert.ok(!store.m.has(`order:${ID}`)); assert.ok(!env.US_FILES.m.has(`uploads/${ID}/1.pdf`)); assert.ok(!store.m.has(`delmark:${ID}`));
    assert.equal(s.unpaid_removed, 1);
  });
}

// 9. Marked, then a payment key appears while the order itself still reads awaiting_payment (the IPN's order write is
//    not visible here yet, or was lost). The second pass sees the pay key: no delete, the mark is cleared, and the
//    reconcile marks the order paid.
{
  const ID = "US-20261013-UNPPAY";
  const { env, store } = mkEnv();
  const created = now - 8 * DAY;
  await putWithMeta(store, order(ID, { created_at: iso(created), files: [{ key: `uploads/${ID}/1.pdf` }] }));
  await env.US_FILES.put(`uploads/${ID}/1.pdf`, "%PDF-1.4", { _uploaded: created });
  await sweep(env, now);
  const payAt = iso(now + 5 * MIN);
  await store.put(`pay:${ID}:TXNP`, JSON.stringify({ order_id: ID, txn_id: "TXNP", gross: 39, currency: "USD", at: payAt }), { metadata: { order: ID, txn: "TXNP", at: payAt } });
  const s = await sweep(env, now + 61 * MIN);
  chk("9 a payment key between mark and delete: not deleted, mark cleared, order repaired to paid", () => {
    assert.ok(store.m.has(`order:${ID}`)); assert.ok(env.US_FILES.m.has(`uploads/${ID}/1.pdf`));
    assert.equal(s.unpaid_removed, 0);
    assert.ok(!store.m.has(`delmark:${ID}`), "mark cleared");
    assert.equal(read(store, ID).status, "paid");
  });
}

// ---------------------------------------------------------------- U5
// 10. Two cards are published at the same moment; both publishes read board_index = [A] before either wrote it.
//     Before the fix one of them was dropped from the index (its card stayed at board:<id>, unreachable).
{
  const A = "td_aaaaaaaaaaaa", B = "td_bbbbbbbbbbbb", C = "td_cccccccccccc", D = "td_dddddddddddd";
  const { env, store } = mkEnv({ barrier: ["board_index"] });
  const card = (id, at) => ({ id, trade: "Roofing", trade_key: "roof", state: "TX", total: 1000, line_count: 3, kinds: [], flags: [], questions: [], labor: null, published_at: iso(at) });
  await store.put("board_index", JSON.stringify([A]));
  await store.put(`board:${A}`, JSON.stringify(card(A, now - 2 * DAY)));                  // published before this change: no metadata
  await store.put(`board:${D}`, JSON.stringify(card(D, now - DAY)));                      // dropped off the index by the old race: card only
  const pend = (id) => store.put(`board_pending:${id}`, JSON.stringify({ id, card: { trade: "Roofing", trade_key: "roof", state: "TX", total: 2000, line_count: 4, kinds: [], flags: [], questions: [], labor: null }, status: "pending", submitted_at: iso(now) }));
  await pend(B); await pend(C);
  const pub = async (id) => { const s = await signPath(env.LINK_SECRET, `/board/review/${id}`, DAY); return worker.fetch(new Request(W + s.replace(`/board/review/${id}?`, `/board/review/${id}/publish?`), { method: "POST" }), env, ctx); };
  const [rb, rc] = await Promise.all([pub(B), pub(C)]);
  chk("10 both publishes answered 200", () => { assert.equal(rb.status, 200); assert.equal(rc.status, 200); });
  td.boardCacheClear();
  const r = await worker.fetch(new Request(W + "/board", { headers: { origin: SITE } }), env, ctx);
  const body = await r.json();
  const ids = (body.cards || []).map((c) => c.id);
  chk("10 the board shows both new cards (fails before)", () => { assert.ok(ids.includes(B) && ids.includes(C), JSON.stringify(ids)); });
  chk("10 the board shows the card the old race had dropped off the index (fails before)", () => assert.ok(ids.includes(D), JSON.stringify(ids)));
  chk("10 same shape and order as before: newest first, the old index card last", () => {
    assert.equal(ids.length, 4, JSON.stringify(ids));
    assert.deepEqual(new Set(ids.slice(0, 2)), new Set([B, C]));
    assert.deepEqual(ids.slice(2), [D, A]);
    for (const c of body.cards) { assert.equal(typeof c.id, "string"); assert.equal(typeof c.published_at, "string"); assert.equal(c.trade, "Roofing"); }
  });
  chk("10 the old board_index value is read, never rewritten (fails before)", () => assert.equal(store.m.get("board_index"), JSON.stringify([A])));
  chk("10 each new card carries published_at in its key metadata, so the board lists without reading each card", () => {
    assert.ok(store.meta.get(`board:${B}`) && typeof store.meta.get(`board:${B}`).published_at === "string");
  });
  const one = await (await worker.fetch(new Request(`${W}/board?id=${C}`, { headers: { origin: SITE } }), env, ctx)).json();
  chk("10 GET /board?id= finds a per-key card", () => assert.equal(one.card && one.card.id, C));
}

// 10b. The board reads only what it shows: with 450 keyed cards the 200 newest are read, not all 450 (2026-10-13 review).
{
  const { env, store } = mkEnv();
  const card = (id, at) => ({ id, trade: "Roofing", trade_key: "roof", state: "TX", total: 1000, line_count: 3, kinds: [], flags: [], questions: [], labor: null, published_at: iso(at) });
  for (let i = 0; i < 450; i++) { const id = `td_many${String(i).padStart(8, "0")}`; await store.put(`board:${id}`, JSON.stringify(card(id, now - i * MIN)), { metadata: { published_at: iso(now - i * MIN) } }); }
  const realGet = env.US_ORDERS.get; let gets = 0;
  env.US_ORDERS.get = async (k) => { if (String(k).startsWith("board:")) gets++; return realGet(k); };
  td.boardCacheClear();
  const j = await (await worker.fetch(new Request(`${W}/board`, { headers: { origin: SITE } }), env, ctx)).json();
  chk("10b the board answers the 200 newest cards", () => { assert.equal(j.cards.length, 200); assert.equal(j.cards[0].id, "td_many00000000"); });
  chk("10b only the shown cards were read from KV (fails before: every card was read)", () => assert.ok(gets <= 200, `gets=${gets}`));
  env.US_ORDERS.get = realGet;
}

// 1c. Approve re-checks the answer keys against the draft. An answer set that arrived after the draft (not in
//     draft.answer_keys) stops delivery with 409, and the order goes back to "answered" so the cron redrafts; a failed
//     list stops delivery with 503. (2026-10-13 review: the in-draft re-check is a KV list and can be a minute stale.)
{
  const ID = "US-20261013-ANSWRC";
  const { env, store } = mkEnv();
  await putWithMeta(store, order(ID, { status: "awaiting_answers", paid_at: iso(now - 10 * 3600000), created_at: iso(now - 10 * 3600000),
    hearing: { version: "us-hearing-1.0", answers: { property_type: "single_family" }, ignored: [], answered_at: iso(now - 10 * 3600000) }, followup: followup(now), extracted_cache: EXTRACTED, draft_attempts: 0 }));
  const drafted = await generateDraft(env, ID, { htmlToPdf: pdfOk });
  chk("1c the draft records which answer sets it read", () => { assert.equal(drafted.status, "draft_ready"); assert.ok(Array.isArray(drafted.draft.answer_keys)); });
  const dir = drafted.draft.sha256.slice(0, 16);
  // an answer set lands after the draft (as the answer link writes it), while the order still says draft_ready
  await store.put(`ans:${ID}:${iso(now)}-late1`, JSON.stringify({ order_id: ID, answers: { inside_city: "no" }, at: iso(now), via: "customer", fields: ["inside_city"] }), { metadata: { at: iso(now), via: "customer" } });
  const rp = await signPath(env.LINK_SECRET, `/review/${ID}/${dir}`, DAY);
  log.length = 0;
  const r1 = await worker.fetch(new Request(W + rp.replace(`/review/${ID}/${dir}?`, `/review/${ID}/${dir}/approve?`), { method: "POST" }), env, ctx);
  chk("1c approve with a late answer set is refused (409) and nothing is sent (fails before)", () => { assert.equal(r1.status, 409); assert.ok(!log.some((l) => /resend\.com/.test(l.url)), "mail was sent"); });
  chk("1c the order is queued for a redraft (answered)", () => assert.equal(read(store, ID).status, "answered"));
  // the redraft reads the late set; approve then goes through
  const redone = await generateDraft(env, ID, { htmlToPdf: pdfOk });
  chk("1c the redraft includes the late set in answer_keys", () => assert.ok(redone.draft.answer_keys.some((k) => k.endsWith("-late1"))));
  const dir2 = redone.draft.sha256.slice(0, 16);
  const realList = env.US_ORDERS.list;
  env.US_ORDERS.list = async (opts) => { if (opts && String(opts.prefix || "").startsWith(`ans:${ID}:`)) throw new Error("kv list unavailable"); return realList(opts); };
  const rp2 = await signPath(env.LINK_SECRET, `/review/${ID}/${dir2}`, DAY);
  const r2 = await worker.fetch(new Request(W + rp2.replace(`/review/${ID}/${dir2}?`, `/review/${ID}/${dir2}/approve?`), { method: "POST" }), env, ctx);
  chk("1c approve when the answer list fails: 503, not sent, order still draft_ready", () => { assert.equal(r2.status, 503); assert.equal(read(store, ID).status, "draft_ready"); });
  env.US_ORDERS.list = realList;
  const r3 = await worker.fetch(new Request(W + rp2.replace(`/review/${ID}/${dir2}?`, `/review/${ID}/${dir2}/approve?`), { method: "POST" }), env, ctx);
  chk("1c approve with no late set goes through", () => assert.equal(r3.status, 200, String(r3.status)));
}

// 11. /health says which build is live (ops/prod_fix_check.sh reads it).
{
  const { env } = mkEnv();
  const j = await (await worker.fetch(new Request(W + "/health"), env, ctx)).json();
  chk("11 /health answers marker", () => assert.equal(j.answers, "ans-per-key-20261013"));
  chk("11 /health draft_claim marker", () => assert.equal(j.draft_claim, "claim-20261013"));
  chk("11 /health unpaid_delete marker", () => assert.equal(j.unpaid_delete, "two-phase-20261013"));
  chk("11 /health board_index marker", () => assert.equal(j.board_index, "per-key-20261013"));
}

console.log(fail ? `order_concurrency FAILED ${fail}/${n}` : `order_concurrency ok ${n}/${n}`);
process.exit(fail ? 1 : 0);
