// slot_log_copy: NENRIN keeps an outside copy of an issuer's daily slot log.
//
// Why. invinoveritas stamps a daily snapshot of every decision-receipt slot to Bitcoin (decision-receipt SPEC v0.4,
// slot log). Its SPEC says two divergent logs are attributable to the issuer "through where they were served and
// through outside witnesses that keep copies (for example a daily slot witness)". Its author asked for this copy on
// 2026-10-11: a second party holding the day files, keyed by log_root, with each .ots refreshed until it confirms.
//
// What this does, once a day (and on POST /evidence/slot-log/refresh, at most once an hour):
//   1. reads the issuer's index of snapshots (GET .../decision-receipt/slots/log);
//   2. for a date it does not hold yet, fetches the day file, checks it against the index (file_sha256, log_root) and
//      on its own (the SPEC's rules: canonical lines, sorted slots, n_slots, Merkle root, cutoff, log_root =
//      sha256(JCS(header))) and against the copy of the day before (prev_root chain, every slot stays, only new
//      conflicts appended), keeps the exact bytes, and writes a copy record that goes into the daily slot witness
//      batch, so the copy itself is stamped to Bitcoin by this ledger;
//   3. if the index later shows another file or log_root for a date it already holds, keeps the second file as well
//      and writes a copy record saying so: two snapshots for one date is what the SPEC calls provable divergence;
//   4. keeps each distinct .ots the issuer serves for a held date (pending, then upgraded) until one is fetched while
//      the index says confirmed.
// It reads the issuer and keeps what it served. It does not judge the slots, and it holds no key of the issuer's.
import { jcs } from "../trace-pin-v0/trace_pin_v0.mjs";

export const COPY_SCHEMA = "nenrin-slot-log-copy-v0";
export const LOG_SCHEMA = "invinoveritas.decision_receipt.slot_log.v1";
export const ISSUER = { name: "invinoveritas", log_url: "https://api.babyblueviper.com/decision-receipt/slots/log" };
export const GENESIS = "0".repeat(64);
export const MAX_INDEX_BYTES = 1 << 20;
export const MAX_FILE_BYTES = 8 << 20;
export const MAX_OTS_BYTES = 1 << 16;
export const NEW_DAYS_PER_RUN = 3;
export const REFRESH_MIN_SECONDS = 3600;
// The copy reaches the issuer over the network, so it runs only where the deployment says so
// (wrangler.jsonc vars: SLOT_LOG_COPY = "on"). A test env, or any env without the flag, fetches nothing
// and writes nothing; otherwise a test run on a machine with network would copy live days into its pool.
export const COPY_FLAG = "SLOT_LOG_COPY";
export const copyEnabled = (env) => !!env && env[COPY_FLAG] === "on";
const LINE_KEYS = ["claim_sha256", "conflicts", "decider_sig", "event_ids", "scope", "slot", "taken_at"];
const HEX64 = /^[0-9a-f]{64}$/, DATE = /^\d{4}-\d{2}-\d{2}$/;
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256hex = async (s) => hex(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s));
const iso = (sec) => new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const isInt = (x) => typeof x === "number" && Number.isInteger(x);
const b64 = (bytes) => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const j = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" } });

const DAY = (date) => "slotlog:day:" + date;
const FILE = (sha) => "slotlog:file:" + sha;
const OTS = (sha) => "slotlog:ots:" + sha;
const RUN = "slotlog:last_run";
const PENDING = (sha) => "slotw:pending:" + sha;     // the slot witness pool: copy records are batched with observations

// ---- the day file, by the SPEC's rules (written from the SPEC, as the issuer's slot_log_check.py is) -------------
export async function checkDayFile(bytes) {
  const problems = [];
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (_e) { return { problems: ["not_utf8"] }; }
  if (!text.endsWith("\n")) return { problems: ["not_newline_terminated"] };
  const raw = text.split("\n").slice(0, -1);
  if (!raw.length) return { problems: ["empty_file"] };
  let header;
  try { header = JSON.parse(raw[0]); } catch (_e) { return { problems: ["header_not_json"] }; }
  if (!isObj(header) || jcs(header) !== raw[0]) return { problems: ["header_not_canonical"] };
  if (header.schema !== LOG_SCHEMA) problems.push("unknown_schema");
  const lines = [];
  for (const r of raw.slice(1)) {
    let x;
    try { x = JSON.parse(r); } catch (_e) { problems.push("line_not_json"); break; }
    if (!isObj(x) || jcs(x) !== r) { problems.push("line_not_canonical"); break; }
    if (JSON.stringify(Object.keys(x).sort()) !== JSON.stringify(LINE_KEYS) || typeof x.slot !== "string" || !HEX64.test(x.slot) || !["account", "decider"].includes(x.scope)) { problems.push("malformed_line"); break; }
    lines.push(x);
  }
  if (problems.length) return { header, problems };
  const slots = lines.map((x) => x.slot);
  for (let i = 1; i < slots.length; i++) if (!(slots[i - 1] < slots[i])) { problems.push("slots_not_strictly_sorted"); break; }
  if (header.n_slots !== lines.length) problems.push("n_slots_differs");
  let level = await Promise.all(raw.slice(1).map((r) => sha256hex(r)));
  if (!level.length) level = [await sha256hex(LOG_SCHEMA + "|empty")];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(await sha256hex(level[i] + (i + 1 < level.length ? level[i + 1] : level[i])));
    level = next;
  }
  if (level[0] !== header.merkle_root) problems.push("merkle_root_differs");
  if (!isInt(header.cutoff) || lines.some((x) => !isInt(x.taken_at) || x.taken_at >= header.cutoff)) problems.push("slot_taken_after_cutoff");
  return { header, lines, log_root: await sha256hex(raw[0]), problems };
}

// the copy of the day before: prev_root chains, every slot stays with the same line, only new conflicts appended
export function chainProblems(prev, cur) {
  const out = [];
  if (cur.header.prev_root !== prev.log_root) out.push("prev_root_is_not_the_previous_copy_log_root");
  if (!(prev.header.date < cur.header.date)) out.push("previous_copy_is_not_an_earlier_day");
  const now = new Map(cur.lines.map((x) => [x.slot, x]));
  for (const p of prev.lines) {
    const x = now.get(p.slot);
    if (!x) { out.push("slot_of_the_previous_day_missing"); break; }
    const fixed = (l) => jcs(Object.fromEntries(LINE_KEYS.filter((k) => k !== "conflicts").map((k) => [k, l[k]])));
    if (fixed(p) !== fixed(x) || jcs(x.conflicts.slice(0, p.conflicts.length)) !== jcs(p.conflicts)) { out.push("slot_changed_since_the_previous_day"); break; }
  }
  return out;
}

async function getCapped(fetchImpl, url, cap) {
  const r = await fetchImpl(url, { method: "GET", redirect: "manual", headers: { "user-agent": "nenrin-slot-log-copy/0 (+https://ledger.horizonshield.dev/evidence/slot-log)" }, signal: AbortSignal.timeout(15000) });
  if (r.status !== 200) throw new Error("http_" + r.status);
  const reader = r.body ? r.body.getReader() : null;
  if (!reader) { const b = new Uint8Array(await r.arrayBuffer()); if (b.length > cap) throw new Error("too_large"); return b; }
  const parts = []; let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > cap) { try { await reader.cancel(); } catch (_e) {} throw new Error("too_large"); }
    parts.push(value);
  }
  const out = new Uint8Array(n); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}

async function getJSON(env, key) { const v = await env.LEDGER.get(key); if (!v) return null; try { return JSON.parse(v); } catch (_e) { return null; } }

async function writeCopyRecord(env, rec) {
  const record_jcs = jcs(rec);
  const sha = await sha256hex(record_jcs);
  await env.LEDGER.put(PENDING(sha), JSON.stringify({ sha, record_jcs, request_slot: null, receipt_event_id: null, verdict: "slot_log_copy", observed_at: rec.copied_at, response_sha256: rec.file_sha256 }));
  return sha;
}

// ---- the daily run --------------------------------------------------------------------------------------------
export async function copySlotLog(env, nowSec = Math.floor(Date.now() / 1000), fetchImpl = (u, i) => fetch(u, i)) {
  const out = { new_days: [], divergent: [], ots_kept: [], problems: [] };
  if (!copyEnabled(env)) return { off: true, note: COPY_FLAG + ' is not "on" here; nothing fetched, nothing written', ...out };
  let index;
  try { index = JSON.parse(new TextDecoder().decode(await getCapped(fetchImpl, ISSUER.log_url, MAX_INDEX_BYTES))); }
  catch (e) { out.problems.push("index_unreadable: " + String(e && e.message || e)); return out; }
  const snaps = (Array.isArray(index && index.snapshots) ? index.snapshots : [])
    .filter((s) => isObj(s) && typeof s.date === "string" && DATE.test(s.date) && typeof s.file_sha256 === "string" && HEX64.test(s.file_sha256) && typeof s.log_root === "string" && HEX64.test(s.log_root))
    .sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  let added = 0;
  for (const s of snaps) {
    const held = await getJSON(env, DAY(s.date));
    const differs = held && (held.file_sha256 !== s.file_sha256 || held.log_root !== s.log_root);
    if (held && !differs) continue;
    if (added >= NEW_DAYS_PER_RUN) break;
    if (differs && (held.divergent || []).some((d) => d.file_sha256 === s.file_sha256 && d.log_root === s.log_root)) continue;
    let bytes;
    try { bytes = await getCapped(fetchImpl, ISSUER.log_url + "/" + s.date, MAX_FILE_BYTES); }
    catch (e) { out.problems.push(s.date + ": file_unreadable: " + String(e && e.message || e)); continue; }
    added++;
    const file_sha256 = await sha256hex(bytes);
    const chk = await checkDayFile(bytes);
    const problems = [...chk.problems];
    if (file_sha256 !== s.file_sha256) problems.push("file_sha256_differs_from_index");
    if (chk.log_root && chk.log_root !== s.log_root) problems.push("log_root_differs_from_index");
    if (chk.header && chk.header.date !== s.date) problems.push("header_date_differs");
    // the copy of the day before, if this ledger holds it
    const prevDate = snaps.filter((x) => x.date < s.date).map((x) => x.date).pop();
    let prevCopy = null;
    if (prevDate) {
      const pd = await getJSON(env, DAY(prevDate));
      if (pd && pd.problems.length === 0) {
        const pB64 = await env.LEDGER.get(FILE(pd.file_sha256));
        if (pB64 !== null) { const pc = await checkDayFile(unb64(pB64)); if (!pc.problems.length) prevCopy = pc; }
      }
    } else if (chk.header && chk.header.prev_root !== GENESIS) problems.push("first_day_without_genesis_prev_root");
    if (prevCopy && chk.lines && !chk.problems.length) problems.push(...chainProblems(prevCopy, chk));
    await env.LEDGER.put(FILE(file_sha256), b64(bytes));
    const rec = {
      schema: COPY_SCHEMA, issuer: ISSUER.name, index_url: ISSUER.log_url, file_url: ISSUER.log_url + "/" + s.date, date: s.date,
      copied_at: iso(nowSec), file_sha256, file_bytes: bytes.length, log_root: chk.log_root || null,
      prev_root: chk.header ? chk.header.prev_root ?? null : null, n_slots: chk.header ? chk.header.n_slots ?? null : null,
      index_entry: { file_sha256: s.file_sha256, log_root: s.log_root, ots_status: s.ots_status ?? null },
      checked_against_previous_copy: prevCopy ? prevDate : null,
      problems, divergent_from_earlier_copy: differs ? { file_sha256: held.file_sha256, log_root: held.log_root, copied_at: held.copied_at } : null,
    };
    const record_sha = await writeCopyRecord(env, rec);
    if (differs) {
      held.divergent = [...(held.divergent || []), { file_sha256, log_root: chk.log_root || null, copied_at: rec.copied_at, record_sha, problems }];
      await env.LEDGER.put(DAY(s.date), JSON.stringify(held));
      out.divergent.push(s.date);
    } else {
      await env.LEDGER.put(DAY(s.date), JSON.stringify({ date: s.date, file_sha256, log_root: chk.log_root || null, prev_root: rec.prev_root, n_slots: rec.n_slots, copied_at: rec.copied_at, record_sha, problems, ots: [], divergent: [] }));
      out.new_days.push(s.date);
    }
  }
  // the .ots of each held day, until one is kept while the index says confirmed
  for (const s of snaps) {
    const held = await getJSON(env, DAY(s.date));
    if (!held || held.ots.some((o) => o.issuer_ots_status === "confirmed")) continue;
    let bytes;
    try { bytes = await getCapped(fetchImpl, ISSUER.log_url + "/" + s.date + ".ots", MAX_OTS_BYTES); }
    catch (e) { out.problems.push(s.date + ".ots: unreadable: " + String(e && e.message || e)); continue; }
    const sha = await sha256hex(bytes);
    const known = held.ots.find((o) => o.sha256 === sha);
    if (known) { if (s.ots_status === "confirmed" && known.issuer_ots_status !== "confirmed") { known.issuer_ots_status = "confirmed"; await env.LEDGER.put(DAY(s.date), JSON.stringify(held)); } continue; }
    await env.LEDGER.put(OTS(sha), b64(bytes));
    held.ots.push({ sha256: sha, bytes: bytes.length, fetched_at: iso(nowSec), issuer_ots_status: s.ots_status ?? null });
    await env.LEDGER.put(DAY(s.date), JSON.stringify(held));
    out.ots_kept.push(s.date + ":" + sha.slice(0, 12));
  }
  await env.LEDGER.put(RUN, String(nowSec));
  return out;
}

// ---- the routes ----------------------------------------------------------------------------------------------
export const ESTABLISHES = [
  "at copied_at this ledger fetched the issuer's day file itself and keeps exactly those bytes (file_sha256)",
  "problems lists every way the file failed the SPEC's rules, the issuer's index, or the copy of the day before; an empty list means it passed all of them",
  "each copy record is in a daily slot witness batch stamped to Bitcoin by this ledger, so the copy existed before that block",
  "every distinct .ots the issuer served for the day is kept, so the stamp can be checked from here with the standard client",
];
export const DOES_NOT_ESTABLISH = [
  "that the issuer's slots are true; the file is the issuer's record, this ledger keeps it",
  "that the issuer served the same file to anyone else; only what it served this ledger, when",
  "anything about a day this ledger did not copy",
];

export async function handleSlotLog(p, request, url, env, origin, nowSec = Math.floor(Date.now() / 1000), fetchImpl = (u, i) => fetch(u, i)) {
  if (p !== "/evidence/slot-log" && !p.startsWith("/evidence/slot-log/")) return null;
  if (p === "/evidence/slot-log/refresh") {
    if (request.method !== "POST") return j({ error: "method_not_allowed" }, 405);
    if (!copyEnabled(env)) return j({ error: "copy_off", note: COPY_FLAG + ' is not "on" on this deployment' }, 503);
    const last = Number((await env.LEDGER.get(RUN)) || 0);
    if (nowSec - last < REFRESH_MIN_SECONDS) return j({ error: "too_soon", retry_after_seconds: REFRESH_MIN_SECONDS - (nowSec - last) }, 429);
    return j(await copySlotLog(env, nowSec, fetchImpl));
  }
  if (request.method !== "GET") return j({ error: "method_not_allowed" }, 405);
  if (p === "/evidence/slot-log") {
    const days = [];
    let cursor;
    do {
      const r = await env.LEDGER.list({ prefix: "slotlog:day:", cursor });
      for (const k of r.keys) { const d = await getJSON(env, k.name); if (d) days.push(d); }
      cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
    days.sort((a, b) => (a.date < b.date ? -1 : 1));
    return j({
      schema: COPY_SCHEMA, what: "an outside copy of " + ISSUER.name + "'s daily slot log: the day files and .ots proofs exactly as the issuer served them to this ledger, checked and stamped here",
      issuer: ISSUER, copies: days.map((d) => ({ ...d, file: origin + "/evidence/slot-log/" + d.date, ots: d.ots.length ? origin + "/evidence/slot-log/" + d.date + ".ots" : null, record: origin + "/evidence/slot/" + d.record_sha + "?format=raw" })),
      refresh: { url: origin + "/evidence/slot-log/refresh", method: "POST", at_most_every_seconds: REFRESH_MIN_SECONDS }, schedule: "daily at 00:30 UTC, before the slot witness batch",
      check: "python3 slot_log_check.py <date>.jsonl --prev <previous>.jsonl (the issuer's checker), then ots verify -d <log_root> <date>.ots; or slot_check.py --log-copy <date>",
      establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
    });
  }
  const rest = p.slice("/evidence/slot-log/".length);
  const m = /^(\d{4}-\d{2}-\d{2})(\.ots|\.json)?$/.exec(rest);
  if (!m) return j({ error: "not_found" }, 404);
  const d = await getJSON(env, DAY(m[1]));
  if (!d) return j({ error: "not_found", date: m[1], note: "this ledger holds no copy of that day" }, 404);
  if (m[2] === ".json") return j(d);
  if (m[2] === ".ots") {
    const want = url.searchParams.get("sha256");
    const pick = want ? d.ots.find((o) => o.sha256 === want) : (d.ots.find((o) => o.issuer_ots_status === "confirmed") || d.ots[d.ots.length - 1]);
    if (!pick) return j({ error: "not_found", note: "no .ots kept for that day" }, 404);
    const v = await env.LEDGER.get(OTS(pick.sha256));
    return new Response(unb64(v), { status: 200, headers: { "content-type": "application/octet-stream", "x-ots-sha256": pick.sha256, "x-issuer-ots-status": String(pick.issuer_ots_status), "access-control-allow-origin": "*" } });
  }
  const want = url.searchParams.get("file_sha256") || d.file_sha256;
  if (want !== d.file_sha256 && !d.divergent.some((x) => x.file_sha256 === want)) return j({ error: "not_found" }, 404);
  const v = await env.LEDGER.get(FILE(want));
  return new Response(unb64(v), { status: 200, headers: { "content-type": "text/plain; charset=utf-8", "x-file-sha256": want, "cache-control": "public, max-age=86400", "access-control-allow-origin": "*" } });
}
