// End to end with stand-ins: intake, PayPal IPN, cron draft, review, delivery, download,
// double payment, retries, scrubbing and cleanup.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import worker, { handleIntake, handleIpn, generateDraft, sweep, draftPending } from "../src/index.js";
import { kv, r2, jccdbService, outside, EXTRACTED } from "./mocks.mjs";

const log = [];
globalThis.fetch = outside(log);
const jcalls = [];
const env = { US_ORDERS: kv(), US_FILES: r2(), JCCDB: jccdbService(jcalls), BROWSER: {}, SITE_URL: "https://shield.the-horizons-innovation.com",
  PUBLIC_WORKER_URL: "https://hs-us-report.example.workers.dev", PAYPAL_BUSINESS: "pay@example.com", ANTHROPIC_API_KEY: "x", RESEND_API_KEY: "x",
  LINE_CHANNEL_TOKEN: "x", LINE_USER_ID: "U1", LINK_SECRET: "link-secret-for-tests", US_ADMIN_TOKEN: "admin-token-for-tests" };
const ctx = { waitUntil() {} };
const site = { origin: "https://shield.the-horizons-innovation.com", "cf-connecting-ip": "203.0.113.9" };
const W = "https://hs-us-report.example.workers.dev";
const lineTexts = () => log.filter((l) => l.url.includes("line.me")).map((l) => JSON.parse(l.body).messages[0].text);
let extractCalls = 0;
const pdfDeps = { extract: async () => { extractCalls++; return { extracted: EXTRACTED, gates: { pass: true, notes: [] } }; }, htmlToPdf: async (e, htmls) => htmls.map((h) => new TextEncoder().encode(h)) };

// 1. intake with a photo that carries GPS and a second appended JPEG, plus the hearing answers
const fd = new FormData();
fd.set("plan", "quote_check"); fd.set("zip", "78745"); fd.set("email", "homeowner@example.com"); fd.set("agree", "yes"); fd.set("name", "Pat Example");
fd.set("trade", "roof"); fd.set("h_property_type", "single_family"); fd.set("h_stories", "2"); fd.set("h_year_built", "pre_1978"); fd.set("h_insurance_claim", "yes");
fd.set("h_contact_origin", "door"); fd.set("h_quotes_count", "1"); fd.set("h_deposit_pct", "50"); fd.append("h_pressure", "today_only"); fd.append("h_pressure", "waive_deductible");
fd.set("h_layers", "1"); fd.set("h_pitch", "medium"); fd.set("h_roof_area_known", "no"); fd.set("h_crew_told", "no"); fd.set("h_penetrations", "999"); fd.set("h_bogus", "x");
fd.append("file", new File([readFileSync(new URL("./fixtures/gps_appended.jpg", import.meta.url))], "quote.jpg", { type: "image/jpeg" }));
fd.append("file", new File([readFileSync(new URL("./fixtures/text.png", import.meta.url))], "page2.png", { type: "image/png" }));
let res = await handleIntake(new Request(W + "/intake", { method: "POST", body: fd, headers: site }), env);
let body = await res.json();
assert.equal(res.status, 200, JSON.stringify(body));
assert.equal(res.headers.get("access-control-allow-origin"), site.origin);
const id = body.order_id;
assert.match(id, /^US-\d{8}-[A-Z2-9]{6}$/);
assert.equal(body.price, 39, "one quote per order, whatever the page count");
assert.match(body.checkout_url, /paypal\.com.*amount=39\.00.*currency_code=USD/);
const up = env.US_FILES.m.get(`uploads/${id}/1.jpg`);
assert.ok(up && !Buffer.from(up.bytes).includes(Buffer.from("Exif")) && !Buffer.from(up.bytes).includes(Buffer.from("secret-app3")), "stored photo has no metadata");
{
  const o1 = JSON.parse(await env.US_ORDERS.get(`order:${id}`));
  assert.equal(o1.trade, "roof");
  assert.deepEqual(o1.hearing.answers.pressure, ["today_only", "waive_deductible"]);
  assert.equal(o1.hearing.answers.deposit_pct, 50);
  assert.equal(o1.hearing.answers.penetrations, undefined, "out-of-range number dropped");
  assert.deepEqual(o1.hearing.ignored, ["penetrations"]);
  assert.equal(o1.hearing.answers.bogus, undefined, "unknown field dropped");
}

// refused cases
const bad = new FormData(); bad.set("plan", "quote_check"); bad.set("zip", "78745"); bad.set("email", "a@b.co"); bad.set("text", "x".repeat(30));
res = await handleIntake(new Request(W + "/intake", { method: "POST", body: bad, headers: site }), env);
assert.equal(res.status, 400); assert.match((await res.json()).error, /Terms/);
const heic = new FormData(); heic.set("plan", "quote_check"); heic.set("zip", "78745"); heic.set("email", "a@b.co"); heic.set("agree", "yes");
heic.append("file", new File([readFileSync(new URL("./fixtures/not_supported.heic", import.meta.url))], "q.heic"));
res = await handleIntake(new Request(W + "/intake", { method: "POST", body: heic, headers: site }), env);
assert.equal(res.status, 400); assert.match((await res.json()).error, /PDF, JPG or PNG/);
const damaged = new FormData(); damaged.set("plan", "quote_check"); damaged.set("zip", "78745"); damaged.set("email", "a@b.co"); damaged.set("agree", "yes");
damaged.append("file", new File([new Uint8Array([0xff, 0xd8, 0xff, 0xe1, 0x00])], "q.jpg", { type: "image/jpeg" }));
res = await worker.fetch(new Request(W + "/intake", { method: "POST", body: damaged, headers: site }), env, ctx);
assert.equal(res.status, 400); assert.match((await res.json()).error, /damaged/);
res = await worker.fetch(new Request(W + "/intake", { method: "POST", body: bad, headers: { ...site, "content-length": String(50 * 1024 * 1024) } }), env, ctx);
assert.equal(res.status, 413, "oversize body refused before parsing");
res = await handleIntake(new Request(W + "/intake", { method: "POST", body: bad, headers: { origin: "https://evil.example" } }), env);
assert.equal(res.headers.get("access-control-allow-origin"), null, "no CORS for other sites");
res = await handleIntake(new Request(W + "/intake", { method: "POST", body: bad, headers: site }), { ...env, PAYPAL_BUSINESS: "" });
assert.equal(res.status, 503, "no orders while PayPal is not configured");
res = await worker.fetch(new Request(W + "/quick", { method: "POST", body: JSON.stringify({ trade: "constructor", zip: "78745" }), headers: site }), env, ctx);
assert.equal(res.status, 200, "prototype names are harmless");

// 2. PayPal: wrong amount skipped (LINE told), unverified refused, right amount marks paid once, duplicate ignored
const ipnBody = (o) => new URLSearchParams({ payment_status: "Completed", receiver_email: "pay@example.com", mc_currency: "USD", mc_gross: "39.00", txn_id: "TXN1", custom: id, payer_email: "p@example.com", ...o }).toString();
res = await handleIpn(new Request(W + "/webhook/paypal", { method: "POST", body: ipnBody({ mc_gross: "1.00", txn_id: "TXN0" }) }), env, ctx);
assert.match((await res.json()).skipped, /amount/);
assert.equal(JSON.parse(await env.US_ORDERS.get(`order:${id}`)).status, "awaiting_payment");
assert.ok(lineTexts().pop().includes("合わない"));
res = await handleIpn(new Request(W + "/webhook/paypal", { method: "POST", body: ipnBody({ custom: "<b>phish</b>", txn_id: "TXNX" }) }), env, ctx);
assert.match((await res.json()).skipped, /unknown/);
assert.ok(!lineTexts().some((t) => t.includes("phish")), "foreign custom text never reaches LINE");
globalThis.fetch = outside(log, { ipn: "INVALID" });
res = await handleIpn(new Request(W + "/webhook/paypal", { method: "POST", body: ipnBody({}) }), env, ctx);
assert.equal(res.status, 400);
globalThis.fetch = outside(log);
res = await handleIpn(new Request(W + "/webhook/paypal", { method: "POST", body: ipnBody({}) }), env, ctx);
assert.equal((await res.json()).ok, true);
let o = JSON.parse(await env.US_ORDERS.get(`order:${id}`));
assert.equal(o.status, "paid"); assert.ok(o.paid_at);
assert.equal(env.US_ORDERS.meta.get(`order:${id}`).status, "paid", "status in KV metadata");
res = await handleIpn(new Request(W + "/webhook/paypal", { method: "POST", body: ipnBody({}) }), env, ctx);
assert.equal((await res.json()).duplicate, true);
assert.ok(log.some((l) => l.url.includes("resend") && String(l.body).includes("We received your order")), "receipt email sent");
assert.equal(log.filter((l) => l.url.includes("api.anthropic.com")).length, 0, "the IPN never calls the AI");

// 3. cron draft: first attempt fails (no AI stand-in), gets retried later, then succeeds with the stand-in
let done = await draftPending(env);
assert.deepEqual(done, [id]);
o = JSON.parse(await env.US_ORDERS.get(`order:${id}`));
assert.equal(o.status, "draft_failed"); assert.equal(o.draft_attempts, 1);
assert.deepEqual(await draftPending(env), [], "not retried within 10 minutes");
assert.deepEqual(await draftPending(env, Date.now() + 11 * 60000), [id], "retried after 10 minutes");

// 3b. the hearing's follow-up: the quote has a permit line and the homeowner did not say whether
// the property is inside the city limits, so the draft asks first and waits
let order = await generateDraft(env, id, pdfDeps);
assert.equal(order.status, "awaiting_answers");
assert.equal(order.draft_attempts, 2, "asking is not an attempt");
assert.deepEqual(order.followup.questions.map((q) => q.id), ["inside_city"]);
assert.equal(extractCalls, 1);
const askMail = log.filter((l) => l.url.includes("resend")).pop();
assert.match(JSON.parse(askMail.body).subject, /One quick question/);
const answerUrl = String(JSON.parse(askMail.body).html).match(/href="([^"]+\/answer\/[^"]+)"/)[1].replace(/&amp;/g, "&");
assert.ok(answerUrl.startsWith(W + "/answer/" + id + "?exp="), answerUrl);
assert.ok(lineTexts().pop().includes("聞き返し中"));
assert.deepEqual(await draftPending(env), [], "waits for the answer");
assert.deepEqual(await draftPending(env, Date.now() + 9 * 3600000), [id], "drafts anyway after the wait");
res = await worker.fetch(new Request(answerUrl), env, ctx);
assert.equal(res.status, 200);
let page = await res.text();
assert.ok(page.includes('name="h_inside_city"') && !page.includes("homeowner@example.com"), "answer form shows the question, no customer data");
res = await worker.fetch(new Request(answerUrl.replace(/sig=[0-9a-f]{4}/, "sig=0000")), env, ctx);
assert.equal(res.status, 403, "tampered answer link refused");
const ans = new URLSearchParams({ h_inside_city: "yes", h_roof_squares: "30", h_email: "x" });
res = await worker.fetch(new Request(answerUrl, { method: "POST", body: ans, headers: { "content-type": "application/x-www-form-urlencoded" } }), env, ctx);
assert.equal(res.status, 200);
o = JSON.parse(await env.US_ORDERS.get(`order:${id}`));
assert.equal(o.status, "answered");
assert.equal(o.hearing.answers.inside_city, "yes");
assert.equal(o.hearing.answers.roof_squares, undefined, "only the asked fields are accepted");
assert.ok(lineTexts().pop().includes("返答"));
assert.deepEqual(await draftPending(env), [id], "answered orders are drafted at once");
order = await generateDraft(env, id, pdfDeps);
assert.equal(order.status, "draft_ready");
assert.equal(extractCalls, 1, "the AI read the quote once; the redraft reused it");
const dir = order.draft.sha256.slice(0, 16);
const report = JSON.parse(new TextDecoder().decode(env.US_FILES.m.get(`reports/${id}/${dir}/report.json`).bytes));
const byItem = Object.fromEntries(report.lines.map((l) => [l.item, l]));
assert.deepEqual(byItem["Architectural shingles, 26 squares"].reference_usd, [2120, 2304]);
assert.equal(byItem["Architectural shingles, 26 squares"].status, "above_floor");
assert.deepEqual(byItem["Labor, 3 roofers x 3 days"].reference_usd, [3121, 4308], "SOC filter picked Roofers May 2025, not helpers or 2024");
assert.match(byItem["Labor, 3 roofers x 3 days"].basis.hours_basis, /8-hour day assumed/);
assert.equal(byItem["Permit"].status, "ask_permit_exemption", "inside the city limits: the Austin exemption applies");
assert.equal(byItem["Overhead and profit 20%"].status, "overlaps_reference_markups");
assert.equal(report.quote_total, 19872);
assert.equal(report.geo.cbsa, "12420");
assert.deepEqual(report.flags.map((f) => f.id), ["cooling_off", "today_only", "deductible_tx", "adjuster_tx", "deposit_large", "one_quote"]);
assert.ok(report.flags.every((f) => report.sources.includes(f.source)), "every warning sign cites a listed source");
assert.equal(report.hearing.answers.find((a) => a.id === "inside_city").value, "Yes");
assert.equal(report.questions.length, 9, "6 line questions + deductible + adjuster scope + payment schedule");
assert.ok(jcalls.filter((c) => c.includes("Roofers")).every((c) => !c.includes("state=")), "metro data found for roofers, no state fallback");
assert.deepEqual(order.draft.docs.map((d) => d.name), ["quote-check-report.pdf", "questions-letter.pdf", "report.json"]);
const qcHtml = new TextDecoder().decode(env.US_FILES.m.get(`reports/${id}/${dir}/quote-check-report.pdf`).bytes);
assert.ok(qcHtml.includes(order.draft.sha256), "receipt printed");
assert.ok(qcHtml.includes("8-hour day assumed"));
assert.ok(!/[‒-―−]/.test(qcHtml.replace(/data:font[^)]*\)/g, "")), "no dash characters in the document");
const reviewUrl = lineTexts().pop().match(/https:\/\/\S+\/review\/\S+/)[0];
assert.ok(reviewUrl.includes(`/review/${id}/${dir}?`), "review link pinned to the draft hash");

// 4. review page: no customer data, links only after POST, approve only by POST, once
res = await worker.fetch(new Request(reviewUrl), env, ctx);
assert.equal(res.status, 200);
page = await res.text();
assert.ok(!page.includes("homeowner@example.com") && page.includes("ho***@example.com"), "email masked");
assert.ok(!page.includes("/files/"), "no file links on GET");
const openAction = page.match(/action="([^"]+\/open[^"]*)"/)[1].replace(/&amp;/g, "&");
res = await worker.fetch(new Request(W + openAction, { method: "POST" }), env, ctx);
page = await res.text();
assert.ok(page.includes("/files/" + id + "/" + dir + "/quote-check-report.pdf"), "links after POST open");
const approve = page.match(/action="([^"]+\/approve[^"]*)"/)[1].replace(/&amp;/g, "&");
res = await worker.fetch(new Request(W + approve), env, ctx);
assert.equal(res.status, 405, "GET cannot approve");
res = await worker.fetch(new Request(W + approve, { method: "POST" }), env, ctx);
assert.equal(res.status, 200);
assert.equal(JSON.parse(await env.US_ORDERS.get(`order:${id}`)).status, "delivered");
const mail = log.filter((l) => l.url.includes("resend")).pop();
const links = [...String(JSON.parse(mail.body).html).matchAll(/href="([^"]+)"/g)].map((x) => x[1].replace(/&amp;/g, "&"));
assert.equal(links.length, 3);
res = await worker.fetch(new Request(links[0]), env, ctx);
assert.equal(res.status, 200); assert.equal(res.headers.get("content-type"), "application/pdf");
res = await worker.fetch(new Request(links[0].replace(/sig=[0-9a-f]{4}/, "sig=0000")), env, ctx);
assert.equal(res.status, 403, "tampered link refused");
res = await worker.fetch(new Request(W + approve, { method: "POST" }), env, ctx);
assert.equal(res.status, 409, "second approval refused");
const mailsBefore = log.filter((l) => l.url.includes("resend")).length;
res = await handleIpn(new Request(W + "/webhook/paypal", { method: "POST", body: ipnBody({ txn_id: "TXN2" }) }), env, ctx);
assert.match((await res.json()).skipped, /already paid/);
assert.equal(JSON.parse(await env.US_ORDERS.get(`order:${id}`)).status, "delivered", "a second payment does not reset the order");
assert.equal(log.filter((l) => l.url.includes("resend")).length, mailsBefore, "no second receipt email");
assert.ok(lineTexts().pop().includes("二重払い"));
// a redrafted order invalidates the old review link
await env.US_ORDERS.put(`order:${id}`, JSON.stringify({ ...JSON.parse(await env.US_ORDERS.get(`order:${id}`)), draft: { ...order.draft, sha256: "f".repeat(64) } }), { metadata: { status: "delivered" } });
res = await worker.fetch(new Request(reviewUrl), env, ctx);
assert.equal(res.status, 409);

// 5. admin needs the token; list comes from metadata
res = await worker.fetch(new Request(W + "/admin/orders"), env, ctx);
assert.equal(res.status, 401);
res = await worker.fetch(new Request(W + "/admin/orders", { headers: { authorization: "Bearer admin-token-for-tests" } }), env, ctx);
assert.equal((await res.json()).orders[0].status, "delivered");

// 6. quick estimate
res = await worker.fetch(new Request(W + "/quick", { method: "POST", body: JSON.stringify({ trade: "roof", zip: "78745" }), headers: site }), env, ctx);
body = await res.json();
assert.equal(body.wages[0].mean_usd_h, 24.08);
assert.deepEqual(body.wages[0].loaded_usd_h, [43.34, 59.83]);
assert.ok(body.checklist.length > 5);

// 7. sweep: uploads and the customer's text scrubbed after 29 days, unpaid removed after 7 days, reports kept
const fd2 = new FormData(); fd2.set("plan", "detailed_estimate"); fd2.set("zip", "10001"); fd2.set("email", "b@example.com"); fd2.set("agree", "yes"); fd2.set("description", "Replace 12 windows, each about 36 by 48 inches, double hung, vinyl, second floor.");
res = await handleIntake(new Request(W + "/intake", { method: "POST", body: fd2, headers: site }), env);
const unpaid = (await res.json()).order_id;
const s = await sweep(env, Date.now() + 31 * 86400000);
assert.equal(s.uploads_deleted, 2); assert.equal(s.reports_deleted, 0); assert.equal(s.scrubbed, 1);
// 2026-10-13 (concurrency audit U4): the unpaid delete is two sweeps apart. The first marks, the next one an hour or more later deletes.
assert.equal(s.unpaid_marked, 1); assert.equal(s.unpaid_removed, 0);
assert.ok(await env.US_ORDERS.get(`order:${unpaid}`), "marked, not yet deleted");
const s1b = await sweep(env, Date.now() + 31 * 86400000 + 61 * 60000);
assert.equal(s1b.unpaid_removed, 1);
assert.equal(await env.US_ORDERS.get(`order:${unpaid}`), null);
o = JSON.parse(await env.US_ORDERS.get(`order:${id}`));
assert.equal(o.extracted, undefined); assert.equal(o.name, undefined); assert.deepEqual(o.files, []); assert.ok(o.email, "email kept for 12 months of support");
assert.ok(env.US_FILES.m.has(`reports/${id}/${dir}/report.json`));
const s2 = await sweep(env, Date.now() + 400 * 86400000);
assert.equal(s2.reports_deleted, 3); assert.equal(s2.reduced, 1);
o = JSON.parse(await env.US_ORDERS.get(`order:${id}`));
assert.equal(o.email, undefined); assert.equal(o.status, "delivered");

// 8. unloaded wages outside Texas: reference shown, no verdict, not counted
const { computeReport, summarize } = await import("../src/engine.js");
const ny = computeReport({ trade: "roof replacement", place: "New York, NY 10001", data_version: "x", sources: [], source_urls: {}, lines: [{ item: "Labor", quoted: 9000, kind: "labor", labor: { hours: 72, wage_mean_usd_h: 40, wage_p90_usd_h: 60 } }] });
assert.equal(ny.lines[0].status, "wages_only"); assert.equal(summarize(ny).above_count, 0);
console.log("flow ok", id, dir);
