// Free Quote Teardown and the public board (EHN for the United States), 2026-10-09.
//
// POST /teardown        multipart from https://horizonshield.dev/teardown/: one quote (up to 3 files, or pasted text), optional ZIP and trade.
//                       The AI only reads the lines (extract.js). Everything the homeowner sees is computed here from
//                       those lines and, when a ZIP is given, from public wage data (refs.js). Nothing is stored except
//                       an anonymous card (trade, state, total, line kinds and our own flags) for 24 hours, so the
//                       homeowner can choose to put it on the board. The files and the line text are never stored.
// POST /board/submit    {teardown_id, claim, consent:true}: the card goes to TOshi for review (LINE, signed link).
// GET  /board           published cards. GET /board/card?id= one card.
// GET|POST /board/review/<id>[/publish|/reject]   signed links for TOshi.
// POST /event           {event}: counts page opens and clicks by name only. No IP, no text is kept.
// Daily at 00:00 UTC (09:00 JST) the previous UTC day's counts go to TOshi on LINE.

import { resolveZip } from "./geo.js";
import { stripMetadata } from "./exif.js";
import { extract } from "./extract.js";
import { TRADES, tradeKey } from "./trades.js";
import { wagesFor, LOADING_BY_STATE } from "./refs.js";
import { sourceTitles, sourceUrls } from "./sources.js";
import { lineToshi } from "./notify.js";
import { signPath, verifyPath } from "./sign.js";
import { esc } from "./templates.js";

const DAY = 86400000;
const MAX_FILE = 5_000_000;
const MAX_FILES = 3;
const CARD_TTL_S = 86400;
const ID_RE = /^td_[a-z2-9]{12}$/;
export const TEARDOWN_PER_HOUR = 3;       // per network
export const TEARDOWN_PER_DAY_ALL = 200;  // whole service, to cap the AI cost
export const SOURCES_OK = ["direct", "home", "x", "threads", "reply", "series", "guide", "share", "board", "reddit", "fb", "other"];
export const EVENTS = [
  ...SOURCES_OK.map((s) => "land_" + s),
  "teardown_ok", "teardown_fail", "board_submit", "board_publish", "cta_check", "share_x", "share_copy",
];

const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const html = (body, status = 200) => new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-robots-tag": "noindex" } });

function cors(env, request, methods = "POST, OPTIONS") {
  const origin = request.headers.get("origin") || "";
  const allowed = [env.SITE_URL].concat(env.ALLOW_ORIGIN_EXTRA ? [env.ALLOW_ORIGIN_EXTRA] : []);
  return allowed.includes(origin) ? { "access-control-allow-origin": origin, "access-control-allow-methods": methods, "access-control-allow-headers": "content-type", vary: "origin" } : {};
}
const siteOrigin = (env, request) => {
  const origin = request.headers.get("origin") || "";
  return [env.SITE_URL].concat(env.ALLOW_ORIGIN_EXTRA ? [env.ALLOW_ORIGIN_EXTRA] : []).includes(origin);
};

function newId() {
  const a = "abcdefghjkmnpqrstuvwxyz23456789";
  const r = crypto.getRandomValues(new Uint8Array(12));
  return "td_" + [...r].map((b) => a[b % a.length]).join("");
}
const utcDay = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);

// Best effort counters in KV (not atomic). A KV error never blocks the homeowner.
async function bump(env, name, t = Date.now()) {
  try {
    if (!EVENTS.includes(name)) return;
    const key = `stats:${utcDay(t)}`;
    let cur = {};
    try { cur = JSON.parse((await env.US_ORDERS.get(key)) || "{}") || {}; } catch { cur = {}; }
    cur[name] = (Number(cur[name]) || 0) + 1;
    await env.US_ORDERS.put(key, JSON.stringify(cur), { expirationTtl: 400 * 86400 });
  } catch { /* counting never blocks */ }
}

async function underCap(env, key, max, ttl) {
  try {
    const n = Number((await env.US_ORDERS.get(key)) || 0);
    if (n >= max) return false;
    await env.US_ORDERS.put(key, String(n + 1), { expirationTtl: ttl });
  } catch { /* fall through */ }
  return true;
}

// ---------------------------------------------------------------- the teardown, from the extracted lines

const VAGUE_RE = /\b(misc\.?|miscellaneous|lump[- ]sum|allowance|general conditions|supplies|labor and materials?|materials? and labor|as needed|tbd|etc\.?|various|package|complete job|turn[- ]?key)\b/i;
const money = (n) => "$" + Math.round(n).toLocaleString("en-US");
const pct = (a, b) => (b > 0 ? Math.round((a / b) * 1000) / 10 : 0);

export function laborHours(lines) {
  let h = 0, known = false;
  for (const l of lines) {
    const lb = l.labor || {};
    if (typeof lb.hours === "number" && lb.hours > 0) { h += lb.hours; known = true; }
    else if (typeof lb.workers === "number" && typeof lb.days === "number" && lb.workers > 0 && lb.days > 0) { h += lb.workers * lb.days * 8; known = true; }
  }
  return known ? h : null;
}

// Pure: no network. wage is {mean, p90, geo_name, period, source_id} or null; loading is LOADING_BY_STATE[state] or null.
export function buildTeardown(ex, { tk, geo, wage, loading } = {}) {
  const lines = (ex.lines || []).filter((l) => l && typeof l.item === "string");
  const priced = lines.filter((l) => typeof l.amount === "number");
  const sumLines = priced.reduce((s, l) => s + l.amount, 0);
  const total = ex.doc && typeof ex.doc.total === "number" && ex.doc.total > 0 ? ex.doc.total : sumLines;
  const trade = TRADES[tk] || TRADES.other;
  const kinds = {};
  for (const l of priced) kinds[l.kind] = (kinds[l.kind] || 0) + l.amount;
  const flags = [];
  const questions = [];
  const add = (code, text, q) => { flags.push({ code, text }); if (q) questions.push(q); };

  // 1. One line carrying a large share with no quantity or unit.
  for (const l of priced) {
    const lb = l.labor || {};
    const crewStated = (typeof lb.hours === "number" && lb.hours > 0) || (typeof lb.workers === "number" && typeof lb.days === "number");
    if (total > 0 && l.amount / total >= 0.25 && l.qty == null && !l.unit && !crewStated) {
      add("big_lump", `One line carries ${pct(l.amount, total)}% of the total with no quantity or unit.`, `What quantity and unit is "${String(l.item).slice(0, 60)}" priced on, and what does it include?`);
      break;
    }
  }
  // 2. Vague wording.
  const vague = lines.filter((l) => VAGUE_RE.test(l.item));
  if (vague.length) add("vague", `${vague.length} line${vague.length > 1 ? "s use" : " uses"} wording like "lump sum", "misc" or "allowance" that cannot be checked.`, "Break each lump-sum or allowance line into items with quantities and unit prices.");
  // 3. Overhead and profit on top.
  const oh = kinds.overhead || 0;
  if (oh > 0 && total - oh > 0) {
    const r = pct(oh, total - oh);
    if (r >= 15) add("overhead", `Overhead and profit adds ${r}% on top of the other lines.`, "Is overhead already included in the labor rate? If so, why is it charged again as a separate line?");
  }
  // 4. Labor without crew size, days or hours.
  const labor = priced.filter((l) => l.kind === "labor");
  const hours = laborHours(lines);
  if (labor.length && hours == null) add("labor_hidden", "Labor is priced without a crew size, days or hours.", "How many people, for how many days, are behind the labor line?");
  if (!labor.length && priced.length) add("labor_folded", "No line is labor alone, so labor is folded into other lines.", "How much of the price is labor, and how many crew hours does it assume?");
  // 5. Roofing: squares.
  if (tk === "roof" && !lines.some((l) => l.material && typeof l.material.squares === "number")) add("no_squares", "The roof area in squares is not stated.", "How many squares is the roof, and what waste percentage is included?");
  // 6. Permit.
  if (!lines.some((l) => l.kind === "permit")) questions.push("Does this job need a permit, who pulls it, and is the fee included?");
  // 7. Lines that do not add up.
  if (ex.doc && typeof ex.doc.total === "number" && priced.length) {
    const tol = Math.max(5, Math.abs(ex.doc.total) * 0.01);
    if (Math.abs(sumLines - ex.doc.total) > tol) add("sum_mismatch", `The lines add up to ${money(sumLines)}, but the total says ${money(ex.doc.total)}.`, "What explains the difference between the line items and the total (tax, discount, a missing line)?");
  }

  // Public reference: loaded wage, and labor dollars when hours are known.
  let reference = null;
  if (wage) {
    const factor = loading ? 1 + loading.parts.reduce((s, p) => s + p.rate, 0) : 1;
    const lo = Math.round(wage.mean * factor * 100) / 100, hi = Math.round(wage.p90 * factor * 100) / 100;
    reference = {
      occupation: trade.occupations[0].label, area: wage.geo_name, period: wage.period,
      wage_usd_h: [wage.mean, wage.p90], loaded_usd_h: loading ? [lo, hi] : null, loading_rule: loading ? loading.parts.map((p) => `${p.rate} ${p.label}`).join(" + ") : null,
      sources: [wage.source_id].concat(loading ? [loading.source] : []),
    };
    const laborSum = labor.reduce((s, l) => s + l.amount, 0);
    if (hours != null && labor.length) {
      const r0 = Math.round(hours * lo), r1 = Math.round(hours * hi);
      reference.labor = { hours, range_usd: [r0, r1], quoted_usd: laborSum, status: laborSum > r1 ? "above" : laborSum < r0 ? "below" : "within" };
      if (laborSum > r1) add("labor_above", `The labor line is ${money(laborSum - r1)} above ${hours} crew hours at the top public wage for the area.`, "What, besides crew hours, is included in the labor line?");
    }
  }

  const checklist = trade.checklist.slice(0, 4);
  return {
    trade: trade.label, trade_key: tk, total, total_from: ex.doc && typeof ex.doc.total === "number" ? "quote" : "sum of lines",
    line_count: lines.length, priced_count: priced.length,
    kinds: Object.entries(kinds).map(([k, v]) => ({ kind: k, usd: Math.round(v), share: pct(v, total) })).sort((a, b) => b.usd - a.usd),
    lines: lines.slice(0, 60).map((l) => ({ item: String(l.item).slice(0, 140), kind: l.kind, amount: typeof l.amount === "number" ? l.amount : null, qty: l.qty ?? null, unit: l.unit ?? null, vague: VAGUE_RE.test(l.item) })),
    flags, questions: [...new Set(questions)].slice(0, 6), checklist, reference,
    place: geo && geo.ok ? { state: geo.state || null, metro: geo.metro_name_delineation || null } : null,
    note: "A teardown reads the lines and asks what is missing. It is not a fairness verdict, an inspection or a bid.",
  };
}

// The card that may go on the board: no line text, no ZIP, no contractor, no names. Only our own wording.
export function cardOf(t) {
  return {
    trade: t.trade, trade_key: t.trade_key, state: t.place && t.place.state ? t.place.state : null,
    total: Math.round(t.total || 0), line_count: t.line_count,
    kinds: t.kinds.map((k) => ({ kind: k.kind, share: k.share })),
    flags: t.flags.map((f) => ({ code: f.code, text: f.text.replace(/"[^"]*"/g, "a line") })),
    questions: t.questions.filter((q) => !q.includes('"')).slice(0, 4),
    labor: t.reference && t.reference.labor ? { status: t.reference.labor.status } : null,
  };
}

// ---------------------------------------------------------------- handlers

export async function handleTeardown(request, env, deps = {}) {
  const h = cors(env, request);
  if (!siteOrigin(env, request)) return json({ ok: false, error: "forbidden" }, 403, h);
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const hourKey = `rl:teardown:${ip}:${new Date().toISOString().slice(0, 13)}`;
  if (!(await underCap(env, hourKey, TEARDOWN_PER_HOUR, 3700))) return json({ ok: false, error: "You have used the free teardowns for this hour. Try again later, or order a full Quote Check." }, 429, h);
  if (!(await underCap(env, `cap:teardown:${utcDay()}`, Number(env.TEARDOWN_PER_DAY_ALL || TEARDOWN_PER_DAY_ALL), 2 * 86400))) return json({ ok: false, error: "The free teardown is at today's limit. Try again tomorrow, or order a full Quote Check." }, 429, h);
  const len = Number(request.headers.get("content-length") || 0);
  if (len > MAX_FILES * MAX_FILE + 200000) return json({ ok: false, error: "Files add up to more than 15 MB." }, 413, h);
  let form;
  try { form = await request.formData(); } catch { return json({ ok: false, error: "Send the form as multipart/form-data." }, 400, h); }
  const text = String(form.get("text") || "").slice(0, 20000);
  const files = form.getAll("file").filter((f) => f && typeof f === "object" && f.size > 0);
  if (files.length > MAX_FILES) return json({ ok: false, error: `Send at most ${MAX_FILES} pages of one quote.` }, 400, h);
  const kept = [];
  for (const f of files) {
    if (f.size > MAX_FILE) return json({ ok: false, error: `${f.name} is larger than 5 MB. A smaller photo or a PDF works best.` }, 400, h);
    let clean;
    try { clean = stripMetadata(new Uint8Array(await f.arrayBuffer())); } catch { return json({ ok: false, error: `${f.name} looks damaged.` }, 400, h); }
    if (!clean.kind) return json({ ok: false, error: `${f.name}: send a PDF, JPG or PNG.` }, 400, h);
    kept.push(clean);
  }
  if (!kept.length && text.trim().length < 20) return json({ ok: false, error: "Upload the quote or paste its lines." }, 400, h);
  let geo = null;
  const zipRaw = String(form.get("zip") || "").trim();
  if (zipRaw) { geo = resolveZip(zipRaw); if (!geo.ok) return json({ ok: false, error: geo.error }, 400, h); }

  let ex;
  try {
    const model = env.TEARDOWN_MODEL || "claude-haiku-4-5-20251001";
    const r = await (deps.extract || extract)({ ...env, ANTHROPIC_MODEL: model }, { mode: "quote_check", files: kept, text });
    ex = r.extracted;
  } catch (e) {
    await bump(env, "teardown_fail");
    return json({ ok: false, error: "We could not read this quote. A sharper photo or a PDF usually works." }, 422, h);
  }
  if (!ex || !Array.isArray(ex.lines) || !ex.lines.length) { await bump(env, "teardown_fail"); return json({ ok: false, error: "No priced lines were found. Is this a contractor quote?" }, 422, h); }

  const chosen = String(form.get("trade") || "");
  const tk = Object.prototype.hasOwnProperty.call(TRADES, chosen) && chosen !== "other" ? chosen : tradeKey((ex.doc && ex.doc.trade) || chosen);
  let wage = null, loading = null;
  if (geo && geo.ok) {
    loading = LOADING_BY_STATE[geo.state] || null;
    try { wage = await wagesFor(env, geo, (TRADES[tk] || TRADES.other).occupations[0]); } catch { wage = null; }
  }
  const t = buildTeardown(ex, { tk, geo, wage, loading });
  if (t.reference) t.reference.sources = t.reference.sources.map((id) => ({ id, title: sourceTitles([id])[id] || id, url: sourceUrls([id])[id] || null }));
  const id = newId();
  const claim = crypto.randomUUID();
  await env.US_ORDERS.put(`td:${id}`, JSON.stringify({ claim, card: cardOf(t), created_at: new Date().toISOString() }), { expirationTtl: CARD_TTL_S });
  await bump(env, "teardown_ok");
  return json({ ok: true, teardown_id: id, claim, teardown: t }, 200, h);
}

export async function handleBoardSubmit(request, env) {
  const h = cors(env, request);
  if (!siteOrigin(env, request)) return json({ ok: false, error: "forbidden" }, 403, h);
  const b = await request.json().catch(() => ({}));
  if (!b || !ID_RE.test(String(b.teardown_id || "")) || typeof b.claim !== "string") return json({ ok: false, error: "Run a teardown first." }, 400, h);
  if (b.consent !== true) return json({ ok: false, error: "Please confirm that the card may be shown publicly." }, 400, h);
  const raw = await env.US_ORDERS.get(`td:${b.teardown_id}`);
  if (!raw) return json({ ok: false, error: "This teardown has expired (24 hours). Run it again to post." }, 410, h);
  const td = JSON.parse(raw);
  if (td.claim !== b.claim) return json({ ok: false, error: "forbidden" }, 403, h);
  const rec = { id: b.teardown_id, card: td.card, status: "pending", submitted_at: new Date().toISOString() };
  await env.US_ORDERS.put(`board_pending:${rec.id}`, JSON.stringify(rec), { expirationTtl: 30 * 86400 });
  await env.US_ORDERS.delete(`td:${b.teardown_id}`);   // one teardown, one post
  await bump(env, "board_submit");
  let link = "";
  try { link = `${env.PUBLIC_WORKER_URL}${await signPath(env.LINK_SECRET, `/board/review/${rec.id}`, 7 * DAY)}`; } catch { link = "(LINK_SECRET 未設定)"; }
  await lineToshi(env, `【US 掲示板】新しい投稿 ${rec.card.trade} / ${rec.card.state || "州なし"} / $${rec.card.total.toLocaleString("en-US")}\n赤旗 ${rec.card.flags.length} 件。確認して載せる: ${link}`);
  return json({ ok: true, message: "Thanks. Your card will appear on the board after a quick review." }, 200, h);
}

let _boardCache = { at: 0, cards: null };
export function boardCacheClear() { _boardCache = { at: 0, cards: null }; }

// 2026-10-13. Reads board_index: an array when read (an absent key is []), null when the KV read threw or the
// value would not parse. Before this, a failure became [], which readBoard cached for 30 s as an empty board and
// the publish route wrote back as a one-card index.
async function readBoardIndex(env) {
  let raw;
  try { raw = await env.US_ORDERS.get("board_index"); } catch { return null; }
  if (raw == null) return [];
  try { const ids = JSON.parse(raw); return Array.isArray(ids) ? ids : null; } catch { return null; }
}

// 2026-10-13. Throws when the index or a card cannot be read from KV; nothing is cached then. A card that reads
// but will not parse is still skipped, as before.
export async function readBoard(env) {
  if (_boardCache.cards && Date.now() - _boardCache.at < 30000) return _boardCache.cards;
  const ids = await readBoardIndex(env);
  if (ids === null) throw new Error("board_index could not be read");
  const cards = (await Promise.all(ids.slice(0, 200).map(async (id) => {
    let raw;
    try { raw = await env.US_ORDERS.get(`board:${id}`); } catch { throw new Error("board card could not be read"); }
    try { return JSON.parse(raw || "null"); } catch { return null; }
  }))).filter(Boolean);
  _boardCache = { at: Date.now(), cards };
  return cards;
}

export async function handleBoard(request, env) {
  const h = cors(env, request, "GET, OPTIONS");
  const url = new URL(request.url);
  const one = url.searchParams.get("id");
  let cards;
  try { cards = await readBoard(env); }
  catch {
    // 2026-10-13. A failed read is not an empty board and not a missing card.
    return json({ ok: false, error: "board_unavailable", note: "The board could not be read just now. This is a read failure, not an empty board." }, 503, { ...h, "cache-control": "no-store" });
  }
  if (one) { const c = cards.find((x) => x.id === one); return c ? json({ ok: true, card: c }, 200, h) : json({ ok: false, error: "not found" }, 404, h); }
  return json({ ok: true, cards }, 200, { ...h, "cache-control": "public, max-age=30" });
}

function reviewHtml(rec, base, qs) {
  const c = rec.card;
  const li = (a) => a.map((x) => `<li>${esc(typeof x === "string" ? x : x.text)}</li>`).join("");
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>US board review</title>
<body style="font:15px/1.6 -apple-system,sans-serif;max-width:640px;margin:24px auto;padding:0 16px;color:#0a0a0a">
<p style="color:#737373">US 掲示板の確認 ${esc(rec.id)} / ${esc(rec.status)}</p>
<h2 style="margin:0">${esc(c.trade)} / ${esc(c.state || "州なし")} / $${esc(c.total.toLocaleString("en-US"))}</h2>
<p>行数 ${esc(c.line_count)}。内訳: ${esc(c.kinds.map((k) => `${k.kind} ${k.share}%`).join(", "))}</p>
<h3>Flags</h3><ul>${li(c.flags) || "<li>なし</li>"}</ul><h3>Questions</h3><ul>${li(c.questions) || "<li>なし</li>"}</ul>
<p style="color:#737373">載るのは上の内容だけ(行の文、ZIP、業者名、氏名は保存していない)。</p>
${rec.status === "pending" ? `<form method="post" action="${base}/publish?${qs}" style="display:inline"><button style="font:15px sans-serif;padding:10px 18px;background:#0a0a0a;color:#fff;border:0">載せる</button></form>
<form method="post" action="${base}/reject?${qs}" style="display:inline;margin-left:12px"><button style="font:15px sans-serif;padding:10px 18px;background:#fff;border:1px solid #0a0a0a">載せない</button></form>` : ""}
</body>`;
}

export async function handleBoardReview(request, env, id, action) {
  const url = new URL(request.url);
  const base = `/board/review/${id}`;
  if (!(await verifyPath(env.LINK_SECRET, base, url.searchParams.get("exp"), url.searchParams.get("sig")))) return html("<p>expired or invalid</p>", 403);
  const qs = `exp=${encodeURIComponent(url.searchParams.get("exp") || "")}&sig=${encodeURIComponent(url.searchParams.get("sig") || "")}`;
  const raw = await env.US_ORDERS.get(`board_pending:${id}`);
  if (!raw) return html("<p>not found (済み、または期限切れ)</p>", 404);
  const rec = JSON.parse(raw);
  if (!action) return html(reviewHtml(rec, base, qs));
  if (request.method !== "POST") return html("<p>POST only</p>", 405);
  if (rec.status !== "pending") return html(`<p>状態 ${esc(rec.status)}</p>`, 409);
  if (action === "/reject") {
    rec.status = "rejected"; rec.decided_at = new Date().toISOString();
    await env.US_ORDERS.put(`board_pending:${id}`, JSON.stringify(rec), { expirationTtl: 7 * 86400 });
    return html(`<p style="font:16px sans-serif;margin:24px">載せない: ${esc(id)}</p>`);
  }
  // 2026-10-13. Read the index before writing anything. A failed read used to become [], and the index was then
  // overwritten with this one card, dropping every card already published.
  const ids = await readBoardIndex(env);
  if (ids === null) return html("<p>board_index を読めなかった(KV の読み取り失敗)。何も書いていない。時間をおいてもう一度押す。</p>", 503);
  const card = { id, ...rec.card, published_at: new Date().toISOString() };
  await env.US_ORDERS.put(`board:${id}`, JSON.stringify(card));
  if (!ids.includes(id)) ids.unshift(id);
  await env.US_ORDERS.put("board_index", JSON.stringify(ids.slice(0, 1000)));
  rec.status = "published"; rec.decided_at = card.published_at;
  await env.US_ORDERS.put(`board_pending:${id}`, JSON.stringify(rec), { expirationTtl: 7 * 86400 });
  boardCacheClear();
  await bump(env, "board_publish");
  return html(`<p style="font:16px sans-serif;margin:24px">載せた: ${esc(id)} / <a href="${esc(env.SITE_URL)}/board/#${esc(id)}">掲示板</a></p>`);
}

export async function handleEvent(request, env) {
  const h = cors(env, request);
  if (!siteOrigin(env, request)) return json({ ok: false, error: "forbidden" }, 403, h);
  const raw = await request.text().catch(() => "");
  if (raw.length > 200) return json({ ok: false, error: "too_long" }, 400, h);
  let b = null;
  try { b = JSON.parse(raw); } catch { return json({ ok: false, error: "bad_json" }, 400, h); }
  const ev = b && typeof b.event === "string" ? b.event : "";
  if (!EVENTS.includes(ev) || ev.startsWith("teardown_") || ev.startsWith("board_")) return json({ ok: false, error: "unknown_event" }, 400, h);
  if (!(await underCap(env, `rl:event:${Math.floor(Date.now() / 60000)}`, 120, 120))) return json({ ok: false, error: "rate limited" }, 429, h);
  await bump(env, ev);
  return json({ ok: true }, 200, h);
}

export async function readStats(env, days = 7, now = Date.now()) {
  const out = [];
  for (let i = 0; i < days; i++) {
    const d = utcDay(now - i * DAY);
    let row = {};
    try { row = JSON.parse((await env.US_ORDERS.get(`stats:${d}`)) || "{}") || {}; } catch { row = {}; }
    out.push({ date: d, ...row });
  }
  return out;
}

export function statsText(day, row) {
  const n = (k) => Number(row[k]) || 0;
  const land = SOURCES_OK.map((s) => [s, n("land_" + s)]).filter(([, v]) => v > 0);
  return `【US EHN】${day}(UTC)\n来た ${land.reduce((s, [, v]) => s + v, 0)}${land.length ? "(" + land.map(([k, v]) => `${k} ${v}`).join("、") + ")" : ""}\n解剖 ${n("teardown_ok")}(読めず ${n("teardown_fail")})\n掲示板へ ${n("board_submit")} / 載せた ${n("board_publish")}\n$39 へ ${n("cta_check")} / 送った X ${n("share_x")}・コピー ${n("share_copy")}`;
}

// Called from the hourly cron. At 00:xx UTC, sends yesterday's counts once.
export async function dailyStats(env, now = Date.now()) {
  if (new Date(now).getUTCHours() !== 0) return false;
  const day = utcDay(now - DAY);
  const mark = `stats_sent:${day}`;
  if (await env.US_ORDERS.get(mark)) return false;
  let row = {};
  try { row = JSON.parse((await env.US_ORDERS.get(`stats:${day}`)) || "{}") || {}; } catch { row = {}; }
  await env.US_ORDERS.put(mark, "1", { expirationTtl: 3 * 86400 });
  return await lineToshi(env, statsText(day, row));
}
