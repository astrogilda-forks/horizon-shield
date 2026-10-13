// hs-us-report: the U.S. service of HORIZON SHIELD.
// Intake of one quote or one job description per order, PayPal payment in USD, AI reading,
// references from public data, English PDF documents, review by a person, delivery by email,
// and deletion of uploads within 30 days. The Japanese hs-pdf-gen is not touched.
//
// Routes
//   GET  /health
//   POST /intake                         multipart form from https://horizonshield.dev/ (CORS: SITE_URL, plus ALLOW_ORIGIN_EXTRA during the move)
//   POST /quick                          free Quick Estimate, JSON
//   POST /webhook/paypal                 PayPal IPN: marks the order paid, nothing else
//   GET  /files/<order>/<sha16>/<name>   signed customer download (12 months)
//   GET  /review/<order>/<sha16>         signed review page for TOshi (no customer data, no links)
//   POST /review/<order>/<sha16>/open    shows the draft links
//   POST /review/<order>/<sha16>/approve sends the documents to the customer
//   GET  /answer/<order>                 signed follow-up form for the customer (3 days)
//   POST /answer/<order>                 saves the answers and queues a new draft
//   /admin/...                           Bearer US_ADMIN_TOKEN
// Cron "* * * * *": draft one paid order per run. Cron "0 * * * *": sweep (deletions, late alerts).
// LINE messages to TOshi carry the order id, plan, price and status only, never customer details.
//
// The hearing (hearing.js): the order form asks job-specific questions; the answers feed the
// references (roof area, crew hours, permit rule) and the warning signs. After the AI reads the
// quote, a gap that only the homeowner can close becomes a short follow-up email with a signed
// answer link; the draft waits up to FOLLOWUP_WAIT and then proceeds with what the quote states.

import { resolveZip, placeLabel } from "./geo.js";
import { stripMetadata } from "./exif.js";
import { extract, gates } from "./extract.js";
import { buildInput, buildReport, tradeOf } from "./pipeline.js";
import { renderQuoteCheck, renderDetailedEstimate, renderQuestionsLetter, esc } from "./templates.js";
import { htmlToPdf } from "./pdf.js";
import { priceFor, PLAN_NAMES, checkoutUrl, verifyIpn, checkIpnAgainstOrder } from "./paypal.js";
import { sendEmail, lineToshi, emailReceived, emailDelivered, emailQuestions } from "./notify.js";
import { signPath, verifyPath, ctEqual } from "./sign.js";
import { TRADES, tradeKey } from "./trades.js";
import { wagesFor, LOADING_BY_STATE } from "./refs.js";
import { sourceTitles, sourceUrls } from "./sources.js";
import { FONTS } from "./fonts.js";
import { ENGINE_VERSION } from "./engine.js";
import { normalizeHearing, hearingText, followUpQuestions, followUpFieldIds, HEARING_VERSION } from "./hearing.js";
import { handleTeardown, handleBoardSubmit, handleBoard, handleBoardReview, handleEvent, readStats, dailyStats, BOARD_INDEX } from "./teardown.js";

const DAY = 86400000;
const FOLLOWUP_WAIT = 8 * 3600000;     // how long a draft waits for follow-up answers
const MAX_FILE = 5_000_000;            // per file: the AI reader's limit per image is 5 MB (decimal), so stay under it
const MAX_TOTAL = 12 * 1024 * 1024;    // per order: keeps the AI request and memory well inside limits
const MAX_FILES = 5;                   // pages of one quote, or photos of one job
const EMAIL_RE = /^[^\s@<>"']{1,64}@[^\s@<>"']{1,190}\.[a-z]{2,}$/i;
const ORDER_RE = /^US-\d{8}-[A-Z2-9]{6}$/;
const UPLOAD_TTL = 29 * DAY;           // the promise is "within 30 days"
const REPORT_TTL = 365 * DAY;
const UNPAID_TTL = 7 * DAY;
// Paid orders in these states past 20 hours are late for the one business day promise.
const LATE_STATES = ["paid", "drafting", "draft_ready", "draft_failed", "awaiting_answers", "answered"];

const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const html = (body, status = 200) => new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-robots-tag": "noindex" } });

function cors(env, request) {
  const origin = request.headers.get("origin") || "";
  const allowed = [env.SITE_URL].concat(env.ALLOW_ORIGIN_EXTRA ? [env.ALLOW_ORIGIN_EXTRA] : []);
  return allowed.includes(origin) ? { "access-control-allow-origin": origin, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type", vary: "origin" } : {};
}

function newOrderId() {
  const d = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const a = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const r = crypto.getRandomValues(new Uint8Array(6));
  return `US-${d}-${[...r].map((b) => a[b % a.length]).join("")}`;
}

// Per network and hour. Best effort: KV is not atomic, and a KV error never blocks a customer.
async function rateLimited(env, request, bucket, max) {
  try {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const key = `rl:${bucket}:${ip}:${new Date().toISOString().slice(0, 13)}`;
    const n = Number((await env.US_ORDERS.get(key)) || 0);
    if (n >= max) return true;
    await env.US_ORDERS.put(key, String(n + 1), { expirationTtl: 3700 });
  } catch { /* fall through */ }
  return false;
}

// 2026-10-13. Three outcomes: { order } when found, { absent: true } when KV has no such key, { failed: true } when the
// KV read threw or the stored value would not parse. Every order read goes through readOrder, so a failure is not
// reported as "not found". (2026-10-13: getOrder, which returned null for both, is gone; its last callers were the
// IPN, generateDraft and the crons.)
const readOrder = async (env, id) => {
  let raw;
  try { raw = await env.US_ORDERS.get(`order:${id}`); } catch { return { failed: true }; }
  if (raw == null) return { absent: true };
  try { return { order: JSON.parse(raw) }; } catch { return { failed: true }; }
};
// The status is kept in KV metadata so the cron can list orders without reading each one.
const putOrder = (env, o) => env.US_ORDERS.put(`order:${o.id}`, JSON.stringify(o), { metadata: { status: o.status, paid_at: o.paid_at || null, created_at: o.created_at } });
const sha16 = (o) => (o.draft && o.draft.sha256 ? o.draft.sha256.slice(0, 16) : null);

// 2026-10-13 (concurrency audit U1). One immutable key per verified payment, pay:<order id>:<txn id>, written by the
// IPN before it touches the order. The order is one KV value with several writers (the IPN, the hourly sweep, the
// draft cron, the homeowner's answer link, the operator), and KV has no compare-and-swap, so a payment could be lost
// from it: a second payment read a stale "awaiting_payment" copy and overwrote the first txn without the double-payment
// alert, or the sweep read a stale unpaid copy and deleted an order that had just been paid. The payment key is never
// read-modified-written, so it cannot be lost that way. The sweep never deletes an order that has one, and an hourly
// reconcile (reconcilePayments) puts a lost "paid" back and raises a double payment the IPN could not see.
// The metadata carries order, txn and at, so the reconcile lists without reading each key.
export const PAYMENT_RECORDS = "pay-record-v1-20261013";
const PAY_PREFIX = "pay:";
const payKey = (orderId, txnId) => `${PAY_PREFIX}${orderId}:${txnId}`;
const PAY_RECONCILE_LOOKBACK = 7 * DAY;
// The reconcile only repairs or raises a payment older than this. The IPN marks the order paid milliseconds after it
// writes the payment key, and a KV write is visible everywhere within about 60 s, so an order that still reads
// "awaiting_payment" 10 minutes after its payment really lost its "paid". Acting earlier could act on a stale copy
// of an order the IPN or the draft cron is still moving, and put an older copy back over it.
const PAY_REPAIR_GRACE = 10 * 60 * 1000;
async function recordPayment(env, orderId, txnId, gross) {
  if (await env.US_ORDERS.get(payKey(orderId, txnId))) return;   // PayPal resends the same txn: keep the first time
  const at = new Date().toISOString();
  await env.US_ORDERS.put(payKey(orderId, txnId), JSON.stringify({ order_id: orderId, txn_id: txnId, gross, currency: "USD", at }), { metadata: { order: orderId, txn: txnId, at } });
}
// Every payment key under one order (or all), as { order, txn, at }. Throws when KV throws.
async function listPayments(env, orderId) {
  const out = [];
  let cursor;
  do {
    const page = await env.US_ORDERS.list({ prefix: orderId ? `${PAY_PREFIX}${orderId}:` : PAY_PREFIX, cursor, limit: 1000 });
    for (const k of page.keys) {
      const m = k.metadata || {};
      const rest = k.name.slice(PAY_PREFIX.length), cut = rest.lastIndexOf(":");
      out.push({ order: m.order || rest.slice(0, cut), txn: m.txn || rest.slice(cut + 1), at: m.at || "" });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// 2026-10-13 (concurrency audit U2). Each set of hearing answers that arrives after the order was created is its own
// write-once key, ans:<order id>:<at>-<rand> (value: order_id, answers, at, via, fields; metadata: at, via). The order
// value is still written by the answer link, but the draft cron holds its copy of the order for tens of seconds and
// writes it last, so answers written only into the order could be overwritten by the draft's older copy and the report
// shipped without them. Every reader of the answers for a report (generateDraft, the review page, the admin GET, the
// answer form) merges the order's own answers (orders from before this change, and the intake answers) with all
// ans:<id>:* sets in order of arrival. A set is never read-modified-written, so it cannot be lost that way.
// The keys are deleted with the order's other customer content (the scrub at paid + 29 days, the unpaid delete) and
// carry a TTL as a backstop.
export const ANSWER_RECORDS = "ans-per-key-20261013";
const ANS_PREFIX = "ans:";
const ANS_TTL_S = 60 * 86400;
async function recordAnswers(env, orderId, answers, via) {
  const at = new Date().toISOString();
  const key = `${ANS_PREFIX}${orderId}:${at}-${crypto.randomUUID().slice(0, 8)}`;
  await env.US_ORDERS.put(key, JSON.stringify({ order_id: orderId, answers, at, via, fields: Object.keys(answers) }), { metadata: { at, via }, expirationTtl: ANS_TTL_S });
  return { key, at };
}
// Every answer set of one order, oldest first (the key carries the time). Throws when KV throws; a set that will not
// parse is skipped (the order value may still carry those answers).
async function listAnswerSets(env, orderId) {
  const names = [];
  let cursor;
  do {
    const page = await env.US_ORDERS.list({ prefix: `${ANS_PREFIX}${orderId}:`, cursor, limit: 1000 });
    for (const k of page.keys) names.push(k.name);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  names.sort();
  const sets = [];
  for (const name of names) {
    const raw = await env.US_ORDERS.get(name);
    if (raw == null) continue;
    try { const s = JSON.parse(raw); if (s && s.answers && typeof s.answers === "object") sets.push({ key: name, at: String(s.at || ""), via: s.via || "customer", answers: s.answers }); } catch { /* skipped */ }
  }
  return sets;
}
// Lays the per-key sets over the order's own answers, in place. The same fields the answer link and the admin route
// set on the order (hearing.answered_at, followup.answered_at, followup.answered_fields) are derived from the sets.
function applyAnswerSets(order, sets) {
  if (!sets.length) return order;
  order.hearing = order.hearing || { version: HEARING_VERSION, answers: {} };
  const merged = { ...(order.hearing.answers || {}) };
  for (const s of sets) Object.assign(merged, s.answers);
  order.hearing.answers = merged;
  const last = sets[sets.length - 1].at;
  if (!order.hearing.answered_at || order.hearing.answered_at < last) order.hearing.answered_at = last;
  if (order.followup) {
    const fromCustomer = sets.filter((s) => s.via === "customer");
    if (fromCustomer.length) {
      const lastC = fromCustomer[fromCustomer.length - 1].at;
      if (!order.followup.answered_at || order.followup.answered_at < lastC) order.followup.answered_at = lastC;
      order.followup.answered_fields = [...new Set([...(order.followup.answered_fields || []), ...fromCustomer.flatMap((s) => Object.keys(s.answers))])];
    } else if (!order.followup.answered_at) order.followup.answered_at = last;
  }
  return order;
}
// The merged answers of one order, for anything that reports them. Throws when KV throws.
export async function hearingAnswers(env, orderId) {
  const rd = await readOrder(env, orderId);
  if (rd.failed) throw new Error("order_read_failed");
  if (!rd.order) return null;
  const o = applyAnswerSets(rd.order, await listAnswerSets(env, orderId));
  return (o.hearing && o.hearing.answers) || {};
}
async function deleteAnswerSets(env, orderId) {
  let cursor;
  do {
    const page = await env.US_ORDERS.list({ prefix: `${ANS_PREFIX}${orderId}:`, cursor, limit: 1000 });
    for (const k of page.keys) await env.US_ORDERS.delete(k.name);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

// 2026-10-13 (concurrency audit U3). The minute cron picks its order from KV list metadata, which can lag a put by up
// to 60 s, so the run at minute 1 could draft the order minute 0 had just drafted (double AI cost, two review links,
// the first one dead). Before drafting, draftPending reads the order itself and skips it unless it still needs a
// draft, then claims it with a write-once key draftclaim:<id> (get, put, read back: the token read back must be its
// own). This worker has no Durable Object, so the claim is a KV key; its residual is KV's own propagation between
// locations (a put is visible in the location that made it at once and everywhere within about 60 s), which is also
// the window of the fresh read. The claim is deleted when the draft ends and expires after CLAIM_TTL_S if the run died.
export const DRAFT_CLAIMS = "claim-20261013";
const CLAIM_PREFIX = "draftclaim:";
const CLAIM_TTL_S = 15 * 60;   // the same 15 minutes after which a "drafting" order is retried

// 2026-10-13 (concurrency audit U4). The unpaid delete at the 7 day line is two sweeps apart: the first writes
// delmark:<id> (at), the delete happens on a later sweep only when the mark is older than DELMARK_AGE, no
// pay:<order>:* key exists and a fresh read of the order still says awaiting_payment. A payment landing between the
// mark and the delete clears the mark (the IPN and the reconcile delete it; the second pass also sees the pay key).
export const UNPAID_DELETE = "two-phase-20261013";
const DELMARK_PREFIX = "delmark:";
const DELMARK_AGE = 3600000;
const DELMARK_TTL_S = 3 * 86400;
const delmarkKey = (orderId) => `${DELMARK_PREFIX}${orderId}`;

// ---------------------------------------------------------------- intake

export async function handleIntake(request, env) {
  const h = cors(env, request);
  if (!env.PAYPAL_BUSINESS) return json({ ok: false, error: "Orders are not open yet. Email your quote to contact@the-horizons-innovation.com and we will reply." }, 503, h);
  const len = Number(request.headers.get("content-length") || 0);
  if (len > MAX_TOTAL + 200000) return json({ ok: false, error: "Files add up to more than 12 MB. Send fewer or smaller files." }, 413, h);
  if (await rateLimited(env, request, "intake", 10)) return json({ ok: false, error: "Too many uploads from this network. Try again in an hour." }, 429, h);
  let form;
  try { form = await request.formData(); } catch { return json({ ok: false, error: "Send the form as multipart/form-data." }, 400, h); }
  const plan = String(form.get("plan") || "quote_check");
  if (!PLAN_NAMES[plan]) return json({ ok: false, error: "Unknown plan." }, 400, h);
  if (String(form.get("agree") || "") !== "yes") return json({ ok: false, error: "Please agree to the Terms of Service to continue." }, 400, h);
  const email = String(form.get("email") || "").trim();
  if (!EMAIL_RE.test(email)) return json({ ok: false, error: "Enter the email address where we should send the report." }, 400, h);
  const geo = resolveZip(form.get("zip"));
  if (!geo.ok) return json({ ok: false, error: geo.error }, 400, h);
  const text = String(form.get("text") || "").slice(0, 20000);
  const description = String(form.get("description") || "").slice(0, 20000);
  const files = form.getAll("file").filter((f) => f && typeof f === "object" && f.size > 0);
  if (files.length > MAX_FILES) return json({ ok: false, error: `Send at most ${MAX_FILES} files: the pages of one quote, or the photos of one job.` }, 400, h);
  let total = 0;
  const kept = [];
  for (const f of files) {
    if (f.size > MAX_FILE) return json({ ok: false, error: `${f.name} is larger than 5 MB. A phone photo at a smaller size, or a PDF, works best.` }, 400, h);
    total += f.size;
    if (total > MAX_TOTAL) return json({ ok: false, error: "Files add up to more than 12 MB." }, 400, h);
    let clean;
    try { clean = stripMetadata(new Uint8Array(await f.arrayBuffer())); } catch { return json({ ok: false, error: `${f.name} looks damaged. Please export or photograph it again.` }, 400, h); }
    if (!clean.kind) return json({ ok: false, error: `${f.name}: send a PDF, JPG or PNG. iPhone photos are converted to JPG when you pick them in the browser.` }, 400, h);
    kept.push(clean);
  }
  if (plan === "quote_check" && !kept.length && text.trim().length < 20) return json({ ok: false, error: "Upload the quote or paste its lines." }, 400, h);
  if (plan === "detailed_estimate" && description.trim().length < 40) return json({ ok: false, error: "Describe the job and your measurements in a few sentences." }, 400, h);
  // The hearing: the job the homeowner chose and the answers to the questions for it.
  const tradeChoice = String(form.get("trade") || "");
  const trade = Object.prototype.hasOwnProperty.call(TRADES, tradeChoice) ? tradeChoice : "";
  const hearing = normalizeHearing((name) => { const all = form.getAll(name); return all.length > 1 ? all.map(String) : (all.length ? String(all[0]) : null); }, trade || "other");
  const id = newOrderId();
  const now = Date.now();
  const stored = [];
  for (let i = 0; i < kept.length; i++) {
    const k = kept[i];
    const key = `uploads/${id}/${i + 1}.${k.kind === "jpeg" ? "jpg" : k.kind}`;
    await env.US_FILES.put(key, k.bytes, { httpMetadata: { contentType: k.contentType }, customMetadata: { order: id, uploaded_at: String(now) } });
    stored.push({ key, kind: k.kind, contentType: k.contentType, size: k.bytes.length });
  }
  const order = {
    id, plan, plan_name: PLAN_NAMES[plan], price: priceFor(plan), currency: "USD",
    email, name: String(form.get("name") || "").slice(0, 120), contractor: String(form.get("contractor") || "").slice(0, 160),
    zip: geo.zip, geo, text, description, files: stored, status: "awaiting_payment", created_at: new Date(now).toISOString(),
    trade: trade || null,
    hearing: { version: HEARING_VERSION, answers: hearing.answers, ignored: hearing.ignored, answered_at: new Date(now).toISOString() },
  };
  await putOrder(env, order);
  return json({ ok: true, order_id: id, price: order.price, currency: "USD", checkout_url: checkoutUrl(order, env) }, 200, h);
}

// ---------------------------------------------------------------- Quick Estimate (free)

export async function handleQuick(request, env) {
  const h = cors(env, request);
  if (await rateLimited(env, request, "quick", 30)) return json({ ok: false, error: "Too many requests. Try again in an hour." }, 429, h);
  const body = await request.json().catch(() => ({}));
  const geo = resolveZip(body.zip);
  if (!geo.ok) return json({ ok: false, error: geo.error }, 400, h);
  const trade = TRADES[tradeKey(body.trade)];
  const loading = LOADING_BY_STATE[geo.state] || null;
  const factor = loading ? 1 + loading.parts.reduce((s, p) => s + p.rate, 0) : 1;
  const wages = [];
  const src = new Set(["geonames-postal-us", "census-cbsa-delineation"]);
  for (const occ of trade.occupations.slice(0, 3)) {
    let w;
    try { w = await wagesFor(env, geo, occ); } catch { return json({ ok: false, error: "The public data service is not available right now. Please try again in a few minutes." }, 503, h); }
    if (!w) { wages.push({ occupation: occ.label, soc: occ.soc, found: false }); continue; }
    src.add(w.source_id);
    if (loading) src.add(loading.source);
    wages.push({ occupation: occ.label, soc: occ.soc, found: true, area: w.geo_name, period: w.period, mean_usd_h: w.mean, p90_usd_h: w.p90,
      loaded_usd_h: loading ? [Math.round(w.mean * factor * 100) / 100, Math.round(w.p90 * factor * 100) / 100] : null,
      loading: loading ? { factor, rule: loading.parts.map((p) => `${p.rate} ${p.label}`).join(" + ") } : null });
  }
  const ids = [...src];
  return json({
    ok: true, place: placeLabel(geo), trade: trade.label, wages, checklist: trade.checklist,
    reading: loading
      ? "Public wage statistics for the trade in your area. With loading, they include the insurance, taxes and markup your state transportation department allows on public work. They are not residential billing rates or quotes."
      : "Public wage statistics for the trade in your area, before the contractor's insurance, taxes and markup, which we have no public rule for in your state. They are not residential billing rates or quotes.",
    sources: ids.map((id) => ({ id, title: sourceTitles([id])[id], url: sourceUrls([id])[id] })),
  }, 200, h);
}

// ---------------------------------------------------------------- PayPal IPN

export async function handleIpn(request, env, ctx, fetchImpl = fetch) {
  const raw = await request.text();
  if (!(await verifyIpn(raw, fetchImpl))) return json({ ok: false, error: "IPN not verified" }, 400);
  const params = new URLSearchParams(raw);
  const custom = params.get("custom") || params.get("item_number") || "";
  const orderId = ORDER_RE.test(custom) ? custom : "";
  const txnId = String(params.get("txn_id") || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 32);
  // 2026-10-13. A failed order read answers 503 so PayPal sends the IPN again. Before, it became "unknown order":
  // recorded as ipn-skip and answered 200, so a paid order was never marked paid.
  let order = null;
  if (orderId) {
    const rd = await readOrder(env, orderId);
    if (rd.failed) return json({ ok: false, error: "order_read_failed" }, 503);
    order = rd.order || null;
  }
  const chk = checkIpnAgainstOrder(params, order, env);
  if (!chk.ok) {
    // Not ours, or not matching: record it, and tell TOshi only when it concerns a real order of ours.
    await env.US_ORDERS.put(`ipn-skip:${txnId || crypto.randomUUID()}`, JSON.stringify({ at: new Date().toISOString(), reason: chk.reason, order: orderId || null }), { expirationTtl: 30 * 86400 });
    if (order && /amount|currency/.test(chk.reason)) await lineToshi(env, `【US】PayPal の入金が注文と合わない: ${chk.reason} / ${orderId} / txn ${txnId}。返金の要否を確かめる。`, fetchImpl);
    return json({ ok: true, skipped: chk.reason });
  }
  if (!txnId) return json({ ok: true, skipped: "no txn id" });
  await recordPayment(env, order.id, txnId, chk.gross);   // 2026-10-13 (U1): first, and never overwritten by another txn
  let seen;
  try { seen = await env.US_ORDERS.get(`txn:${txnId}`); } catch { return json({ ok: false, error: "txn_read_failed" }, 503); }   // 2026-10-13
  if (seen) return json({ ok: true, duplicate: true });
  if (order.status !== "awaiting_payment") {
    await env.US_ORDERS.put(`txn:${txnId}`, order.id);
    try { await env.US_ORDERS.put(`payalert:${order.id}`, String((await listPayments(env, order.id)).length)); } catch { /* the reconcile may alert once more; never blocks the IPN */ }
    await lineToshi(env, `【US】二重払いの疑い: ${order.id}(状態 ${order.status})に txn ${txnId} でもう一度 $${chk.gross}。PayPal で返金する。`, fetchImpl);
    return json({ ok: true, skipped: "already paid" });
  }
  order.status = "paid";
  order.paid_at = new Date().toISOString();
  order.txn_id = txnId;
  order.payer_email = chk.payerEmail;
  await putOrder(env, order);           // the order first, then the deduplication key
  await env.US_ORDERS.put(`txn:${txnId}`, order.id);
  // 2026-10-13 (U4). A delete mark from the hourly sweep is cleared by the payment; the pay key above guards the rest.
  try { await env.US_ORDERS.delete(delmarkKey(order.id)); } catch { /* the second pass sees the pay key */ }
  const m = emailReceived(order);
  await sendEmail(env, order.email, m.subject, m.html, fetchImpl);
  await lineToshi(env, `【US】入金 ${order.plan_name} $${order.price} / ${order.id}\n1 分以内に下書きを作り始める。できたら確認の連絡を送る。`, fetchImpl);
  return json({ ok: true, order: order.id });
}

// ---------------------------------------------------------------- draft generation (cron only)

async function loadFiles(env, order) {
  const out = [];
  for (const f of order.files || []) {
    const obj = await env.US_FILES.get(f.key);
    if (obj) out.push({ ...f, bytes: new Uint8Array(await obj.arrayBuffer()) });
  }
  return out;
}

export async function generateDraft(env, orderId, deps = {}) {
  // 2026-10-13. A failed read is not "order not found": it throws code order_read_failed and writes nothing.
  // The cron skips the order (the next run retries); the admin route answers 503.
  const rd = await readOrder(env, orderId);
  if (rd.failed) { const e = new Error("order_read_failed"); e.code = "order_read_failed"; throw e; }
  const order = rd.order;
  if (!order) throw new Error("order not found");
  // 2026-10-13 (U2). The answers the report must see: the order's own plus every ans:<id>:* set. A failed list is
  // handled like a failed order read: nothing written, the cron retries, the admin route answers 503.
  let answerSets;
  try { answerSets = await listAnswerSets(env, order.id); } catch { const e = new Error("answers_read_failed"); e.code = "order_read_failed"; throw e; }
  applyAnswerSets(order, answerSets);
  const seenAnswerKeys = new Set(answerSets.map((s) => s.key));
  const pdf = deps.htmlToPdf || htmlToPdf;
  const fetchImpl = deps.fetchImpl || fetch;
  try {
    order.status = "drafting";
    order.drafting_since = new Date().toISOString();
    order.draft_attempts = (order.draft_attempts || 0) + 1;
    await putOrder(env, order);
    // The AI reads the quote once per order; a redraft (new answers, a fixed extraction) reuses it.
    let extracted = order.extracted_override || order.extracted_cache || null;
    let g;
    if (!extracted) {
      const files = await loadFiles(env, order);
      const answers = (order.hearing && order.hearing.answers) || {};
      const hint = hearingText(answers, order.trade || "other");
      const own = order.plan === "detailed_estimate" ? order.description : order.text;
      const r = await (deps.extract || extract)(env, { mode: order.plan, files, text: [own, hint].filter(Boolean).join("\n\n") });
      extracted = r.extracted;
      g = r.gates;
      order.extracted_cache = extracted;
    } else {
      g = gates(extracted, order.plan);
    }
    if (!g.pass) throw new Error(`extraction gates failed: ${g.notes.join("; ")}`);
    // Follow-up: a gap only the homeowner can close. Asked once per order; the draft waits FOLLOWUP_WAIT.
    if (!order.followup && !deps.skipFollowup) {
      const tk = tradeOf(order, extracted);
      const fu = followUpQuestions(extracted, (order.hearing && order.hearing.answers) || {}, tk, order.plan);
      if (fu.length) {
        const link = await signPath(env.LINK_SECRET, `/answer/${order.id}`, 3 * DAY);
        const m = emailQuestions(order, fu, `${env.PUBLIC_WORKER_URL}${link}`, Math.round(FOLLOWUP_WAIT / 3600000));
        const sent = await sendEmail(env, order.email, m.subject, m.html, fetchImpl);
        order.followup = { asked_at: new Date().toISOString(), deadline: new Date(Date.now() + FOLLOWUP_WAIT).toISOString(), questions: fu.map((q) => ({ id: q.id, text: q.text, fields: q.fields })), email_sent: !!sent };
        if (sent) {
          order.status = "awaiting_answers";
          order.draft_attempts -= 1;   // asking is not an attempt
          await putOrder(env, order);
          await lineToshi(env, `【US】お客様に聞き返し中 ${order.plan_name} / ${order.id}: ${fu.map((q) => q.id).join(", ")}。${Math.round(FOLLOWUP_WAIT / 3600000)} 時間待って、返事が無ければそのまま下書きを作る。`);
          return order;
        }
        // The email could not be sent: proceed with what the quote states, and say so in the notes.
      }
    }
    const { input, notes } = await buildInput(env, order, extracted, order.geo);
    if (order.followup && !order.followup.answered_at) notes.push(`asked the homeowner about ${order.followup.questions.map((q) => q.id).join(", ")}; no answer ${order.followup.email_sent ? "yet" : "(email not sent)"}`);
    const built = await buildReport(input);
    const meta = { fonts: FONTS, order_id: order.id, date: new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "America/New_York" }),
      report_sha256: built.sha256, engine: built.engine, source_titles: sourceTitles(input.sources),
      contractor_name: order.contractor || (extracted.doc && extracted.doc.contractor) || null, customer_name: order.name || null,
      quote_ref: extracted.doc && extracted.doc.quote_no ? `no. ${extracted.doc.quote_no}` : null, job_address: placeLabel(order.geo) };
    const docs = order.plan === "detailed_estimate"
      ? [["detailed-estimate.pdf", "Detailed Estimate (PDF)", renderDetailedEstimate(built.report, meta)]]
      : [["quote-check-report.pdf", "Quote Check Report (PDF)", renderQuoteCheck(built.report, meta)], ["questions-letter.pdf", "Letter with questions for your contractor (PDF)", renderQuestionsLetter(built.report, meta)]];
    const pdfs = await pdf(env, docs.map((d) => d[2]));   // one browser for the whole draft
    if (pdfs.fallback) notes.push("PDF rendered without request interception (strict mode failed once); check the documents");
    const dir = `reports/${order.id}/${built.sha256.slice(0, 16)}`;
    const stored = [];
    for (let i = 0; i < docs.length; i++) {
      await env.US_FILES.put(`${dir}/${docs[i][0]}`, pdfs[i], { httpMetadata: { contentType: "application/pdf" }, customMetadata: { order: order.id, report_sha256: built.sha256 } });
      stored.push({ name: docs[i][0], label: docs[i][1] });
    }
    await env.US_FILES.put(`${dir}/report.json`, built.bytes, { httpMetadata: { contentType: "application/json" }, customMetadata: { order: order.id, report_sha256: built.sha256 } });
    stored.push({ name: "report.json", label: "Report file (JSON) to recompute the receipt" });
    order.extracted = extracted;
    order.draft = { sha256: built.sha256, engine: built.engine, docs: stored, gate_notes: g.notes, notes, created_at: new Date().toISOString(),
      answer_keys: [...seenAnswerKeys] };   // 2026-10-13 (U2): which answer sets this draft read; approve re-checks against it
    // 2026-10-13 (U2). Answers that arrived while this draft was being made are not in it. The answer link set the
    // order to "answered", and the write below would put this older copy over that; so the order is written as
    // "answered" here too, with the draft kept, and the cron makes the next draft from the merged answers. A failed
    // list is not "no late answers": the draft is not marked ready over an order that may say "answered"; it is
    // marked draft_failed (the catch below) and remade on the next round from the answer keys, which are safe.
    let late;
    try { late = (await listAnswerSets(env, order.id)).filter((s) => !seenAnswerKeys.has(s.key)); }
    catch (e) { throw new Error(`answers_read_failed: ans:${order.id}:* could not be re-checked after the draft (${String((e && e.message) || e).slice(0, 80)})`); }
    if (late.length) {
      applyAnswerSets(order, late);
      order.status = "answered";
      order.draft_attempts = 0;
      delete order.error;
      await putOrder(env, order);
      await lineToshi(env, `【US】下書き中にお客様の返答が届いた ${order.plan_name} / ${order.id}: ${[...new Set(late.flatMap((s) => Object.keys(s.answers)))].join(", ") || "空の返答"}。この下書きは送らず、次の巡回で作り直す。`);
      return order;
    }
    order.status = "draft_ready";
    delete order.error;
    await putOrder(env, order);
    const review = await signPath(env.LINK_SECRET, `/review/${order.id}/${built.sha256.slice(0, 16)}`, 3 * DAY);
    await lineToshi(env, `【US】下書きができた ${order.plan_name} / ${order.id}\n注意: ${[...g.notes, ...notes].join(" / ") || "なし"}\n確認して送る: ${env.PUBLIC_WORKER_URL}${review}`);
    return order;
  } catch (e) {
    order.status = "draft_failed";
    order.error = String((e && e.message) || e).slice(0, 300);
    await putOrder(env, order);
    await lineToshi(env, `【US】下書きに失敗 ${order.id}(${order.draft_attempts} 回目): ${order.error}\n3 回までは 10 分おきに作り直す。直すときは管理の口で extraction を直して /draft。`);
    throw e;
  }
}

// Whether an order, as read now, still needs a draft: the same rule draftPending applies to the list metadata.
function needsDraft(o, now) {
  if (!o) return false;
  if (o.status === "paid" || o.status === "answered") return true;
  if (o.status === "awaiting_answers") return !!(o.followup && o.followup.deadline && now >= new Date(o.followup.deadline).getTime());
  if (o.status === "drafting" || o.status === "draft_failed") {
    if ((o.draft_attempts || 0) >= 3) return false;
    const since = o.drafting_since ? new Date(o.drafting_since).getTime() : 0;
    return (o.status === "drafting" && now - since > 15 * 60000) || (o.status === "draft_failed" && now - since > 10 * 60000);
  }
  return false;
}

// 2026-10-13 (U3). Write-once claim: returns the token when this run holds draftclaim:<id>, null when another run
// does. Throws when KV throws (the caller then drafts nothing).
async function claimDraft(env, orderId, now) {
  const key = `${CLAIM_PREFIX}${orderId}`;
  if (await env.US_ORDERS.get(key)) return null;
  const token = crypto.randomUUID();
  await env.US_ORDERS.put(key, JSON.stringify({ token, at: new Date(now).toISOString() }), { expirationTtl: CLAIM_TTL_S });
  const again = await env.US_ORDERS.get(key);
  let held = null;
  try { held = JSON.parse(again).token; } catch { held = null; }
  return held === token ? token : null;
}

// One order per run, oldest paid first. Stuck and failed drafts are retried at most 3 times.
// 2026-10-13 (U3). The candidates come from list metadata, which can lag; each is read again before it is drafted and
// skipped unless it still needs a draft, then claimed (claimDraft). deps is passed to generateDraft (tests).
export async function draftPending(env, now = Date.now(), deps = {}) {
  const page = await env.US_ORDERS.list({ prefix: "order:", limit: 1000 });
  const cands = [];
  for (const k of page.keys) {
    const m = k.metadata || {};
    if (m.status === "paid" || m.status === "answered") cands.push({ id: k.name.slice(6), paid: m.paid_at || "" });
    else if (m.status === "awaiting_answers") {
      // Answers arrived (status goes back to "paid" in handleAnswer) or the wait is over.
      const rd = await readOrder(env, k.name.slice(6));
      if (rd.failed) { logReadFailed("draftPending", k.name); continue; }
      const o = rd.order;
      if (o && o.followup && o.followup.deadline && now >= new Date(o.followup.deadline).getTime()) cands.push({ id: o.id, paid: o.paid_at || "" });
    } else if (m.status === "drafting" || m.status === "draft_failed") {
      const rd = await readOrder(env, k.name.slice(6));
      if (rd.failed) { logReadFailed("draftPending", k.name); continue; }
      const o = rd.order;
      if (!o || (o.draft_attempts || 0) >= 3) continue;
      const since = o.drafting_since ? new Date(o.drafting_since).getTime() : 0;
      if ((o.status === "drafting" && now - since > 15 * 60000) || (o.status === "draft_failed" && now - since > 10 * 60000)) cands.push({ id: o.id, paid: o.paid_at || "" });
    }
  }
  if (!cands.length) return [];
  cands.sort((a, b) => a.paid.localeCompare(b.paid));
  for (const c of cands) {
    // Fresh read: the list said "needs a draft", the order itself decides.
    const rd = await readOrder(env, c.id);
    if (rd.failed) { logReadFailed("draftPending", `order:${c.id}`); continue; }
    if (!needsDraft(rd.order, now)) continue;
    let token;
    try { token = await claimDraft(env, c.id, now); }
    catch { console.error(`[hs-us-report] draft claim failed in draftPending: ${CLAIM_PREFIX}${c.id} could not be read or written; nothing drafted this run`); return []; }
    if (!token) continue;   // another run holds it
    try { await generateDraft(env, c.id, deps); } catch (e) {
      // Recorded on the order and sent to LINE, except a failed order read, which changed nothing and is retried.
      if (e && e.code === "order_read_failed") logReadFailed("draftPending", `order:${c.id}`);
    } finally {
      try { await env.US_ORDERS.delete(`${CLAIM_PREFIX}${c.id}`); } catch { /* expires after CLAIM_TTL_S */ }
    }
    return [c.id];
  }
  return [];
}

// 2026-10-13. A background job that could not read an order skips it, writes and sends nothing, and says so here
// (Workers logs) so the skip is not silent. The next run reads it again.
function logReadFailed(job, key) {
  console.error(`[hs-us-report] order_read_failed in ${job}: ${key} skipped, nothing written or sent; the next run retries`);
}

// ---------------------------------------------------------------- delivery and review

async function deliver(env, order, fetchImpl = fetch) {
  if (!order.draft) throw new Error("no draft");
  const dir = sha16(order);
  const links = [];
  for (const d of order.draft.docs) {
    const p = await signPath(env.LINK_SECRET, `/files/${order.id}/${dir}/${d.name}`, REPORT_TTL);
    links.push({ label: d.label, url: `${env.PUBLIC_WORKER_URL}${p}` });
  }
  const m = emailDelivered(order, links);
  const sent = await sendEmail(env, order.email, m.subject, m.html, fetchImpl);
  if (!sent) throw new Error("email not sent");
  order.status = "delivered";
  order.delivered_at = new Date().toISOString();
  await putOrder(env, order);
  return links;
}

function maskEmail(e) {
  const [u, d] = String(e || "").split("@");
  return u && d ? `${u.slice(0, 2)}***@${d}` : "***";
}

function reviewPage(order, base, qs, docLinks) {
  const notes = [...((order.draft && order.draft.gate_notes) || []), ...((order.draft && order.draft.notes) || [])].map((n) => `<li>${esc(n)}</li>`).join("") || "<li>なし</li>";
  const items = docLinks ? `<ul>${docLinks.map((l) => `<li><a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.label)}</a></li>`).join("")}</ul>` : `<form method="post" action="${esc(base)}/open?${esc(qs)}"><button style="font-size:16px;padding:10px 18px;border:1px solid #0a0a0a;background:#fff">下書きを開く</button></form>`;
  const approve = order.status === "draft_ready" ? `<form method="post" action="${esc(base)}/approve?${esc(qs)}" onsubmit="this.querySelector('button').disabled=true"><button style="font-size:16px;padding:10px 18px;background:#0a0a0a;color:#fff;border:0">この内容でお客様に送る</button></form>` : `<p>状態: ${esc(order.status)}。送る操作はできない。</p>`;
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(order.id)}</title>
<body style="font:16px/1.6 -apple-system,Helvetica,sans-serif;max-width:640px;margin:24px auto;padding:0 16px;color:#0a0a0a">
<h1 style="font-size:20px">${esc(order.plan_name)} / ${esc(order.id)}</h1>
<p>状態: ${esc(order.status)} / $${esc(order.price)} / ${esc((order.geo && order.geo.state) || "")} ${esc(order.zip || "")}<br>宛先: ${esc(maskEmail(order.email))}<br>下書きの指紋: ${esc(sha16(order) || "")}<br>ヒアリング: ${esc(String(Object.keys((order.hearing && order.hearing.answers) || {}).length))} 問に回答${order.followup ? ` / 聞き返し ${esc(order.followup.questions.map((q) => q.id).join(", "))}: ${order.followup.answered_at ? "返答あり" : "返答待ち(" + esc(order.followup.deadline || "") + " まで)"}` : ""}</p>
<h2 style="font-size:16px">下書き</h2>${items}
<h2 style="font-size:16px">注意</h2><ul>${notes}</ul>
${approve}
<p style="color:#737373;font-size:13px">直すときは管理の口で extraction を直して作り直す(DEPLOY_TOshi.md の 7)。作り直すと指紋が変わり、このリンクは使えなくなる。</p></body>`;
}

// ---------------------------------------------------------------- follow-up answers (customer)

const ANSWER_CSS = "font:16px/1.6 -apple-system,Helvetica,Arial,sans-serif;max-width:560px;margin:32px auto;padding:0 16px;color:#0a0a0a";

function answerField(f, current) {
  const name = `h_${f.id}`;
  const label = `<label style="display:block;margin:12px 0 4px;font-size:14px;color:#525252">${esc(f.label)}${f.unit ? ` (${esc(f.unit)})` : ""}</label>`;
  if (f.type === "select") return label + `<select name="${esc(name)}" style="font:inherit;min-height:44px;width:100%;border:1px solid #a3a3a3;padding:8px"><option value="">Choose</option>${f.options.map((o) => `<option value="${esc(o[0])}"${current === o[0] ? " selected" : ""}>${esc(o[1])}</option>`).join("")}</select>`;
  return label + `<input name="${esc(name)}" type="number" inputmode="decimal"${f.min != null ? ` min="${f.min}"` : ""}${f.max != null ? ` max="${f.max}"` : ""} step="${f.step || "any"}" value="${current != null ? esc(current) : ""}" style="font:inherit;min-height:44px;width:100%;border:1px solid #a3a3a3;padding:8px">`;
}

function answerPage(order, qs, state) {
  const answers = (order.hearing && order.hearing.answers) || {};
  let body;
  if (state === "saved") body = `<p>Thank you. Your answers are in, and the report is being updated with them. You will get an email when it is ready.</p>`;
  else if (state === "closed") body = `<p>This order's report has already been sent. If you would like it updated with new information, reply to the email you received and we will take care of it.</p>`;
  else {
    const blocks = order.followup.questions.map((q) => `<div style="border-top:1px solid #d4d4d4;padding:14px 0"><p style="margin:0 0 4px">${esc(q.text)}</p>${q.fields.map((f) => answerField(f, answers[f.id])).join("")}</div>`).join("");
    body = `<p>These answers change a number in your report. Leave blank anything you do not know.</p><form method="post" action="/answer/${esc(order.id)}?${esc(qs)}">${blocks}<button style="margin-top:18px;font:inherit;font-size:16px;padding:12px 20px;background:#0a0a0a;color:#fff;border:0">Send answers</button></form>`;
  }
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Your answers, order ${esc(order.id)}</title>
<body style="${ANSWER_CSS}"><div style="border-bottom:2px solid #0a0a0a;padding:0 0 8px;font-weight:600">HORIZON SHIELD <span style="font-size:11px;color:#737373">US</span></div>
<h1 style="font-size:20px;margin:18px 0 8px">${esc(order.plan_name)}, order ${esc(order.id)}</h1>${body}
<p style="color:#737373;font-size:12px;margin-top:28px">The HORIZONs Co., Ltd. Price benchmarking information only. Reply to our email with any question.</p></body></html>`;
}

async function handleAnswer(request, env, order, qs) {
  if (!order.followup) return html(answerPage(order, qs, "closed"), 409);
  if (["delivered", "delivering", "refunded"].includes(order.status)) return html(answerPage(order, qs, "closed"), 409);
  if (request.method === "GET") return html(answerPage(order, qs, "form"));
  let form;
  try { form = await request.formData(); } catch { return html("<p>Please send the form.</p>", 400); }
  const allowed = followUpFieldIds(order.followup.questions);
  const get = (name) => { const id = name.slice(2); if (!allowed.has(id)) return null; const v = form.get(name); return v == null ? null : String(v); };
  const tk = order.trade || "roof";
  const n = normalizeHearing(get, tk);
  // A follow-up field may belong to a trade other than the order's; accept it by its own definition.
  for (const q of order.followup.questions) for (const f of q.fields) {
    if (n.answers[f.id] != null) continue;
    const raw = form.get(`h_${f.id}`);
    if (raw == null || raw === "") continue;
    if (f.type === "number") { const v = Number(String(raw).replace(/[,\s]/g, "")); if (Number.isFinite(v) && (f.min == null || v >= f.min) && (f.max == null || v <= f.max)) n.answers[f.id] = v; }
    else if (f.type === "select" && f.options.some((o) => o[0] === String(raw))) n.answers[f.id] = String(raw);
  }
  // 2026-10-13 (U2). The answer set is written once to its own key before the order is touched; the order value is
  // still updated (status, and the merged answers for code that reads only the order), but losing that write to the
  // draft cron's older copy no longer loses the answers: every reader merges ans:<id>:* over the order.
  const rec = await recordAnswers(env, order.id, n.answers, "customer");
  order.hearing = order.hearing || { version: HEARING_VERSION, answers: {} };
  order.hearing.answers = { ...(order.hearing.answers || {}), ...n.answers };
  order.hearing.answered_at = rec.at;
  order.followup.answered_at = order.hearing.answered_at;
  order.followup.answered_fields = [...new Set([...(order.followup.answered_fields || []), ...Object.keys(n.answers)])];
  if (["awaiting_answers", "draft_ready", "draft_failed"].includes(order.status)) { order.status = "answered"; order.draft_attempts = 0; }
  await putOrder(env, order);
  await lineToshi(env, `【US】お客様から返答 ${order.plan_name} / ${order.id}: ${Object.keys(n.answers).join(", ") || "空の返答"}。下書きを作り直す。`);
  return html(answerPage(order, qs, "saved"));
}

// 2026-10-13 (U2). Lays the per-key answer sets over an order a route has just read, for display and for the merge
// the route writes back. Best effort: a failed list leaves the order's own answers (the draft reads fail closed).
// 2026-10-13 (U2). Answer sets the draft did not read. The re-check inside generateDraft is a KV list and can be up to
// a minute stale across locations; approve happens minutes to hours later, so this is where a late set is caught.
// Throws when the list fails (the caller must not deliver then). An old draft without answer_keys is checked against
// every set: it was made before answers had their own keys, so any set is later than it.
async function lateAnswerKeys(env, order) {
  const seen = new Set((order.draft && Array.isArray(order.draft.answer_keys)) ? order.draft.answer_keys : []);
  return (await listAnswerSets(env, order.id)).map((s) => s.key).filter((k) => !seen.has(k));
}
// Before delivering: refuse when answers arrived after the draft (the order goes back to "answered" so the cron redrafts),
// and refuse when that cannot be known. Returns null when delivery may go ahead, else { status, message }.
async function approveGuard(env, order) {
  let late;
  try { late = await lateAnswerKeys(env, order); } catch { return { status: 503, message: "answers could not be re-checked (KV list failed); not sent, try again" }; }
  if (!late.length) return null;
  order.status = "answered"; order.draft_attempts = 0; delete order.error;
  await putOrder(env, order);
  return { status: 409, message: `answers arrived after this draft (${late.length} set${late.length === 1 ? "" : "s"}); not sent, the next round redrafts with them` };
}

async function overlayAnswers(env, order) {
  try { applyAnswerSets(order, await listAnswerSets(env, order.id)); } catch { /* shown from the order value */ }
  return order;
}

// ---------------------------------------------------------------- sweep (hourly, own cron)

export async function sweep(env, now = Date.now()) {
  const out = { uploads_deleted: 0, reports_deleted: 0, unpaid_removed: 0, unpaid_marked: 0, scrubbed: 0, reduced: 0, late_alerts: 0, read_failed: 0 };
  for (const prefix of ["uploads/", "reports/"]) {
    let cursor;
    do {
      const page = await env.US_FILES.list({ prefix, cursor });
      for (const o of page.objects) {
        const age = now - new Date(o.uploaded).getTime();
        if ((prefix === "uploads/" && age > UPLOAD_TTL) || (prefix === "reports/" && age > REPORT_TTL)) {
          await env.US_FILES.delete(o.key);
          out[prefix === "uploads/" ? "uploads_deleted" : "reports_deleted"]++;
        }
      }
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
  }
  let cursor;
  do {
    const page = await env.US_ORDERS.list({ prefix: "order:", cursor, limit: 1000 });
    for (const k of page.keys) {
      const m = k.metadata || {};
      const created = m.created_at ? new Date(m.created_at).getTime() : 0;
      const paid = m.paid_at ? new Date(m.paid_at).getTime() : 0;
      const needs = !m.created_at || (m.status === "awaiting_payment" && now - created > UNPAID_TTL)
        || (paid && now - paid > UPLOAD_TTL) || (created && now - created > REPORT_TTL)
        || (LATE_STATES.includes(m.status) && paid && now - paid > 20 * 3600000);
      if (!needs) continue;
      // 2026-10-13. A failed read is counted and logged, not passed over as a missing order.
      const rd = await readOrder(env, k.name.slice(6));
      if (rd.failed) { out.read_failed++; logReadFailed("sweep", k.name); continue; }
      const o = rd.order;
      if (!o) continue;
      if (!m.created_at) { await putOrder(env, o); }   // repair missing metadata so the next run is cheap
      const oc = o.created_at ? new Date(o.created_at).getTime() : created;
      const op = o.paid_at ? new Date(o.paid_at).getTime() : paid;
      if (o.status === "awaiting_payment" && now - oc > UNPAID_TTL) {
        // 2026-10-13 (U1). A payment key means the order was paid and its "paid" was lost or is not visible yet here:
        // never delete it. reconcilePayments below marks it paid.
        const mk = delmarkKey(o.id);
        let pays;
        try { pays = await listPayments(env, o.id); } catch { out.read_failed++; logReadFailed("sweep", `${PAY_PREFIX}${o.id}:`); continue; }
        if (pays.length) { await env.US_ORDERS.delete(mk); continue; }
        // 2026-10-13 (U4). Two phase: mark now, delete on a later sweep when the mark is an hour old and the order
        // is still unpaid on a fresh read with no payment key. An IPN that lands in the KV visibility window of this
        // read (up to 60 s) therefore has the whole hour to become visible before anything is deleted.
        let mark;
        try { mark = await env.US_ORDERS.get(mk); } catch { out.read_failed++; logReadFailed("sweep", mk); continue; }
        let markedAt = 0;
        if (mark) { try { markedAt = new Date(JSON.parse(mark).at).getTime(); } catch { markedAt = 0; } }
        if (!(markedAt > 0)) {
          await env.US_ORDERS.put(mk, JSON.stringify({ at: new Date(now).toISOString() }), { expirationTtl: DELMARK_TTL_S });
          out.unpaid_marked++;
          continue;
        }
        if (now - markedAt < DELMARK_AGE) continue;
        const rd2 = await readOrder(env, o.id);
        if (rd2.failed) { out.read_failed++; logReadFailed("sweep", k.name); continue; }
        if (!rd2.order || rd2.order.status !== "awaiting_payment") { await env.US_ORDERS.delete(mk); continue; }
        try { pays = await listPayments(env, o.id); } catch { out.read_failed++; logReadFailed("sweep", `${PAY_PREFIX}${o.id}:`); continue; }
        if (pays.length) { await env.US_ORDERS.delete(mk); continue; }
        for (const f of rd2.order.files || []) await env.US_FILES.delete(f.key);
        await deleteAnswerSets(env, o.id);
        await env.US_ORDERS.delete(k.name);
        await env.US_ORDERS.delete(mk);
        out.unpaid_removed++;
        continue;
      }
      let changed = false;
      if (op && now - op > UPLOAD_TTL && !o.scrubbed_at) {
        // the customer's own content leaves the record with the uploads
        for (const key of ["text", "description", "extracted", "extracted_override", "extracted_cache", "name", "contractor", "hearing", "followup"]) delete o[key];
        for (const f of o.files || []) await env.US_FILES.delete(f.key);
        await deleteAnswerSets(env, o.id);   // 2026-10-13 (U2): the answers leave with the rest of the customer's content
        o.files = [];
        o.scrubbed_at = new Date(now).toISOString();
        changed = true; out.scrubbed++;
      }
      if (oc && now - oc > REPORT_TTL && !o.reduced_at) {
        for (const key of ["email", "payer_email", "geo", "zip", "draft", "error"]) delete o[key];
        o.reduced_at = new Date(now).toISOString();
        changed = true; out.reduced++;
      }
      if (LATE_STATES.includes(o.status) && op && now - op > 20 * 3600000 && !o.late_alerted) {
        o.late_alerted = true;
        changed = true; out.late_alerts++;
        await lineToshi(env, `【US】納期が近い: ${o.id} は入金から 20 時間。状態 ${o.status}。遅れると全額返金の対象。`);
      }
      if (changed) await putOrder(env, o);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  await reconcilePayments(env, now, out);
  return out;
}

// 2026-10-13 (U1). Payments of the last PAY_RECONCILE_LOOKBACK, grouped by order. An order still "awaiting_payment"
// with a payment older than PAY_REPAIR_GRACE is marked paid (from the earliest payment); an order with more than one txn is raised once per new txn
// (payalert:<id> holds how many were raised); a payment whose order is gone is raised once (payalert:<id>:orphan).
async function reconcilePayments(env, now, out) {
  out.pay_repaired = 0; out.double_pay_alerts = 0; out.pay_orphans = 0;
  let pays;
  try { pays = await listPayments(env); } catch { out.read_failed++; logReadFailed("sweep", `${PAY_PREFIX}*`); return; }
  const byOrder = new Map();
  for (const p of pays) {
    const t = p.at ? new Date(p.at).getTime() : 0;
    if (!(t > 0) || now - t > PAY_RECONCILE_LOOKBACK) continue;
    if (!byOrder.has(p.order)) byOrder.set(p.order, []);
    byOrder.get(p.order).push(p);
  }
  for (const [id, list] of byOrder) {
    list.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.txn < b.txn ? -1 : 1));
    const txns = [...new Set(list.map((p) => p.txn))];
    const settled = now - new Date(list[0].at).getTime() > PAY_REPAIR_GRACE;
    if (!settled && txns.length < 2) continue;   // too fresh to judge; the next hourly sweep looks again
    const rd = await readOrder(env, id);
    if (rd.failed) { out.read_failed++; logReadFailed("sweep", `order:${id}`); continue; }
    if (!rd.order) {
      if (!settled) continue;
      const mk = `payalert:${id}:orphan`;
      if (!(await env.US_ORDERS.get(mk))) {
        await env.US_ORDERS.put(mk, "1", { expirationTtl: 30 * 86400 });
        out.pay_orphans++;
        await lineToshi(env, `【US】入金の記録があるのに注文 ${id} が無い(txn ${txns.join(", ")})。返金か作り直しを決める。`);
      }
      continue;
    }
    const o = rd.order;
    if (o.status === "awaiting_payment" && settled) {
      o.status = "paid"; o.paid_at = list[0].at; o.txn_id = list[0].txn;
      await putOrder(env, o);
      try { await env.US_ORDERS.delete(delmarkKey(id)); } catch { /* 2026-10-13 (U4): the second pass also sees the pay key */ }
      out.pay_repaired++;
      await lineToshi(env, `【US】入金の反映漏れを直した: ${id} を paid にした(txn ${list[0].txn})。下書きは次の巡回で作る。`);
    }
    if (txns.length > 1) {
      const raised = Number((await env.US_ORDERS.get(`payalert:${id}`)) || 0);
      if (txns.length > raised) {
        await env.US_ORDERS.put(`payalert:${id}`, String(txns.length));
        out.double_pay_alerts++;
        await lineToshi(env, `【US】二重払いの疑い: ${id} に txn ${txns.length} 件(${txns.join(", ")})。PayPal で返金する。`);
      }
    }
  }
}

// ---------------------------------------------------------------- router

function isAdmin(request, env) {
  const a = request.headers.get("authorization") || "";
  return !!env.US_ADMIN_TOKEN && ctEqual(a.replace(/^Bearer\s+/i, ""), env.US_ADMIN_TOKEN);
}

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env, request) });
  if (p === "/health") return json({ ok: true, service: "hs-us-report", engine: ENGINE_VERSION, payments: PAYMENT_RECORDS, answers: ANSWER_RECORDS, draft_claim: DRAFT_CLAIMS, unpaid_delete: UNPAID_DELETE, board_index: BOARD_INDEX, bindings: { files: !!env.US_FILES, orders: !!env.US_ORDERS, browser: !!env.BROWSER, jccdb: !!env.JCCDB }, secrets: { paypal_business: !!env.PAYPAL_BUSINESS, anthropic: !!env.ANTHROPIC_API_KEY, resend: !!env.RESEND_API_KEY, line: !!env.LINE_CHANNEL_TOKEN && !!env.LINE_USER_ID, link: !!env.LINK_SECRET, admin: !!env.US_ADMIN_TOKEN } });
  if (p === "/intake" && request.method === "POST") return await handleIntake(request, env);
  if (p === "/quick" && request.method === "POST") return await handleQuick(request, env);
  if (p === "/webhook/paypal" && request.method === "POST") return await handleIpn(request, env, ctx);
  // Free Quote Teardown and the public board (teardown.js, 2026-10-09).
  if (p === "/teardown" && request.method === "POST") return await handleTeardown(request, env);
  if (p === "/board/submit" && request.method === "POST") return await handleBoardSubmit(request, env);
  if (p === "/board" && request.method === "GET") return await handleBoard(request, env);
  if (p === "/event" && request.method === "POST") return await handleEvent(request, env);
  {
    const bm = p.match(/^\/board\/review\/(td_[a-z2-9]{12})(\/publish|\/reject)?$/);
    if (bm) return await handleBoardReview(request, env, bm[1], bm[2] || "");
  }

  let m = p.match(/^\/files\/(US-\d{8}-[A-Z2-9]{6})\/([0-9a-f]{16})\/([a-z0-9.-]+)$/);
  if (m && request.method === "GET") {
    if (!(await verifyPath(env.LINK_SECRET, p, url.searchParams.get("exp"), url.searchParams.get("sig")))) return new Response("This link has expired or is not valid.", { status: 403 });
    const obj = await env.US_FILES.get(`reports/${m[1]}/${m[2]}/${m[3]}`);
    if (!obj) return new Response("Not found", { status: 404 });
    return new Response(obj.body, { headers: { "content-type": (obj.httpMetadata && obj.httpMetadata.contentType) || "application/octet-stream", "content-disposition": `inline; filename="HORIZON_SHIELD_${m[1]}_${m[3]}"`, "cache-control": "private, max-age=3600", "x-robots-tag": "noindex" } });
  }

  m = p.match(/^\/review\/(US-\d{8}-[A-Z2-9]{6})\/([0-9a-f]{16})(\/open|\/approve)?$/);
  if (m) {
    const base = `/review/${m[1]}/${m[2]}`;
    const qs = `exp=${encodeURIComponent(url.searchParams.get("exp") || "")}&sig=${encodeURIComponent(url.searchParams.get("sig") || "")}`;
    if (!(await verifyPath(env.LINK_SECRET, base, url.searchParams.get("exp"), url.searchParams.get("sig")))) return html("<p>expired or invalid</p>", 403);
    const rd = await readOrder(env, m[1]);
    if (rd.failed) return html("<p>注文を読めなかった(KV の読み取り失敗)。注文が無いという意味ではない。時間をおいて開き直す。</p>", 503);
    const order = rd.order;
    if (!order) return html("<p>not found</p>", 404);
    if (sha16(order) !== m[2]) return html(`<p>この下書きは作り直されている(今の指紋 ${esc(sha16(order) || "なし")})。新しいリンクは LINE に届いている。</p>`, 409);
    await overlayAnswers(env, order);   // 2026-10-13 (U2): the answer count on the page is the merged one
    if (m[3] === "/approve") {
      if (request.method !== "POST") return html("<p>POST only</p>", 405);
      if (order.status !== "draft_ready") return html(`<p>状態が ${esc(order.status)} なので送らない</p>`, 409);
      const g = await approveGuard(env, order);
      if (g) return html(`<p>${esc(g.message)}</p>`, g.status);
      order.status = "delivering";
      await putOrder(env, order);
      try { await deliver(env, order); } catch (e) { order.status = "draft_ready"; await putOrder(env, order); return html(`<p>送れなかった: ${esc(String(e.message || e))}</p>`, 500); }
      await lineToshi(env, `【US】お客様に送った ${order.id}`);
      return html(`<p style="font:16px sans-serif;margin:24px">送った: ${esc(order.id)}</p>`);
    }
    let docLinks = null;
    if (m[3] === "/open" && request.method === "POST") {
      docLinks = [];
      for (const d of (order.draft && order.draft.docs) || []) docLinks.push({ label: d.label, url: `${env.PUBLIC_WORKER_URL}${await signPath(env.LINK_SECRET, `/files/${order.id}/${m[2]}/${d.name}`, DAY)}` });
    }
    return html(reviewPage(order, base, qs, docLinks));
  }

  m = p.match(/^\/answer\/(US-\d{8}-[A-Z2-9]{6})$/);
  if (m && (request.method === "GET" || request.method === "POST")) {
    const qs = `exp=${encodeURIComponent(url.searchParams.get("exp") || "")}&sig=${encodeURIComponent(url.searchParams.get("sig") || "")}`;
    if (!(await verifyPath(env.LINK_SECRET, p, url.searchParams.get("exp"), url.searchParams.get("sig")))) return html("<p style=\"font:16px sans-serif;margin:24px\">This link has expired. Reply to our email and we will send a new one.</p>", 403);
    const rd = await readOrder(env, m[1]);
    if (rd.failed) return html("<p style=\"font:16px sans-serif;margin:24px\">We could not load your order just now. This is a temporary problem on our side, not a missing order. Please try this link again in a few minutes.</p>", 503);
    const order = rd.order;
    if (!order) return html("<p>Not found</p>", 404);
    await overlayAnswers(env, order);   // 2026-10-13 (U2): the form shows, and the merge keeps, every set so far
    return await handleAnswer(request, env, order, qs);
  }

  if (p.startsWith("/admin/")) {
    if (!isAdmin(request, env)) return json({ error: "unauthorized" }, 401);
    if (p === "/admin/stats" && request.method === "GET") {
      // 2026-10-13. A day that could not be read is not a day of zeros.
      try { return json({ days: await readStats(env, Math.min(60, Math.max(1, Number(url.searchParams.get("days") || 7)))) }); }
      catch { return json({ error: "stats_read_failed", note: "The counts could not be read from KV. This is a read failure, not a day with no events." }, 503); }
    }
    if (p === "/admin/orders" && request.method === "GET") {
      const list = await env.US_ORDERS.list({ prefix: "order:", limit: 1000 });
      const rows = list.keys.map((k) => ({ id: k.name.slice(6), ...(k.metadata || {}) })).filter((r) => !url.searchParams.get("status") || r.status === url.searchParams.get("status"));
      rows.sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
      return json({ orders: rows.slice(0, 200), total: rows.length });
    }
    m = p.match(/^\/admin\/orders\/(US-\d{8}-[A-Z2-9]{6})(\/[a-z]+)?$/);
    if (!m) return json({ error: "not found" }, 404);
    const rd = await readOrder(env, m[1]);
    if (rd.failed) return json({ error: "order_read_failed", note: "The order could not be read from KV. This is a read failure, not a statement that the order does not exist." }, 503);
    const order = rd.order;
    if (!order) return json({ error: "order not found" }, 404);
    const action = m[2] || "";
    if (!action && request.method === "GET") return json(await overlayAnswers(env, order));   // 2026-10-13 (U2)
    if (action === "/extraction" && request.method === "PUT") {
      const ex = await request.json();
      const g = gates(ex, order.plan);
      if (!g.pass) return json({ error: "gates failed", notes: g.notes }, 400);
      order.extracted_override = ex;
      order.draft_attempts = 0;
      await putOrder(env, order);
      return json({ ok: true, notes: g.notes });
    }
    if (action === "/hearing" && request.method === "PUT") {
      // Body: {"answers": {...}} in the page's field ids (without the h_ prefix). Merged, validated.
      const body = await request.json().catch(() => ({}));
      const src = (body && body.answers) || {};
      const n = normalizeHearing((name) => { const v = src[name.slice(2)]; return v == null ? null : (Array.isArray(v) ? v.map(String) : String(v)); }, order.trade || "other");
      // 2026-10-13 (U2). The operator's set is its own key too, and the order gets the merge of every set so far.
      const rec = await recordAnswers(env, order.id, n.answers, "operator");
      await overlayAnswers(env, order);
      order.hearing = order.hearing || { version: HEARING_VERSION, answers: {} };
      order.hearing.answers = { ...(order.hearing.answers || {}), ...n.answers };
      order.hearing.answered_at = rec.at;
      if (order.followup && !order.followup.answered_at) order.followup.answered_at = order.hearing.answered_at;
      order.draft_attempts = 0;
      await putOrder(env, order);
      return json({ ok: true, answers: order.hearing.answers, ignored: n.ignored });
    }
    // POST /draft asks the homeowner first when the quote leaves a gap; /draft?ask=0 drafts right away.
    if (action === "/draft" && request.method === "POST") {
      try { return json({ ok: true, order: await generateDraft(env, order.id, { skipFollowup: url.searchParams.get("ask") === "0" }) }); }
      catch (e) {
        // 2026-10-13. generateDraft reads the order again; a failure there used to surface as 500 "order not found".
        if (e && e.code === "order_read_failed") return json({ error: "order_read_failed", note: "The order could not be read from KV. Nothing was written. Try again." }, 503);
        throw e;
      }
    }
    if (action === "/approve" && request.method === "POST") {
      if (order.status !== "draft_ready") return json({ error: `status ${order.status}` }, 409);
      const g = await approveGuard(env, order);
      if (g) return json({ error: g.message }, g.status);
      order.status = "delivering"; await putOrder(env, order);
      try { return json({ ok: true, links: await deliver(env, order) }); } catch (e) { order.status = "draft_ready"; await putOrder(env, order); return json({ error: String(e.message || e) }, 500); }
    }
    if (action === "/refunded" && request.method === "POST") { order.status = "refunded"; order.refunded_at = new Date().toISOString(); await putOrder(env, order); return json({ ok: true }); }
    if (action === "/links" && request.method === "GET") { const dir = sha16(order); if (!dir) return json({ error: "no draft" }, 404); const links = []; for (const d of order.draft.docs) links.push({ label: d.label, url: `${env.PUBLIC_WORKER_URL}${await signPath(env.LINK_SECRET, `/files/${order.id}/${dir}/${d.name}`, DAY)}` }); return json({ links }); }
    return json({ error: "not found" }, 404);
  }
  return json({ error: "not found" }, 404);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      const h = cors(env, request);
      return json({ ok: false, error: "Something went wrong on our side. Nothing was charged. Please try again or email contact@the-horizons-innovation.com.", detail: String((e && e.message) || e).slice(0, 200) }, 500, h);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      if (event.cron === "0 * * * *") {
        try { await dailyStats(env); } catch { /* the count report never blocks the sweep */ }
        try { await sweep(env); } catch (e) { await lineToshi(env, `【US】削除の巡回に失敗: ${String(e.message || e).slice(0, 200)}。R2 の lifecycle が控え。`); }
        return;
      }
      try { await draftPending(env); } catch (e) { await lineToshi(env, `【US】下書きの巡回に失敗: ${String(e.message || e).slice(0, 200)}`); }
    })());
  },
};
