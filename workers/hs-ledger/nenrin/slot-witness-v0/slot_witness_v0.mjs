// slot-witness-v0: NENRIN as an outside reader of an issuer's one-receipt-per-request record.
//
// Why. invinoveritas decision receipts (decision-receipt SPEC, uniqueness section, since 2026-10-10) carry a request
// slot: one receipt per (holder, decider.request_id), and GET /decision-receipt/slot/{request_slot} lists the receipt
// that holds it. That guarantee rests on the issuer's own record. Its author keeps the slot log on his side ("the
// guarantee is ours to give") and asked for NENRIN to read the slot endpoint as a witness. This intake does that:
//   1. anyone POSTs a signed receipt (the NIP-01 event); the ledger checks the event id and the BIP-340 signature
//      under the issuer key pinned here, and reads request_slot from the signed content;
//   2. the ledger itself fetches the issuer's slot endpoint (the submitter's word is not used), keeps the response
//      bytes and their sha256, and records what they say about this receipt: unique, listed with others, not listed,
//      not taken, unreadable, or fetch failed;
//   3. it observes the same slot again daily for 30 days, each observation linked to the previous one, so a slot that
//      later lists a different or a second receipt is visible next to what it listed before;
//   4. observations go oldest first into a daily nenrin-slot-witness-batch-v0 ledger entry stamped to Bitcoin, and
//      slot_check.py recomputes all of it offline.
// It reads the issuer; it does not hold the slot log and makes no uniqueness claim of its own.
import { jcs, Refusal } from "../trace-pin-v0/trace_pin_v0.mjs";
import { nostrEventCheck, schnorrVerify, hexToBytes } from "./bip340.mjs";
import { appendEntry } from "../../src/ledger_append.mjs";

// v0.1 (2026-10-11): an observation also reads the slot's decider claim and its conflicts (decider-scoped slots,
// decision-receipt SPEC v0.4) and keeps up to 64 KiB of the response. v0 observations stay as written and are checked
// by the v0 rule (slot_check.py reads both).
// v0.2 (2026-10-11): also reads the slot's log object, the slot's line in the issuer's daily Bitcoin-stamped slot log
// (SPEC v0.4, slot log), and records whether its Merkle proof holds and the line agrees with the slot bytes (issuer_log).
export const OBS_SCHEMA_V0 = "nenrin-slot-observation-v0";
export const OBS_SCHEMA_V01 = "nenrin-slot-observation-v0.1";
export const OBS_SCHEMA = "nenrin-slot-observation-v0.2";
export const LOG_SCHEMA = "invinoveritas.decision_receipt.slot_log.v1";
export const MAX_MERKLE_PATH = 64;
export const BATCH_SCHEMA = "nenrin-slot-witness-batch-v0";
export const MAX_BYTES = 65536;
export const MAX_RESPONSE_BYTES_V0 = 16384;
export const MAX_RESPONSE_BYTES = 65536;
export const MAX_CONFLICTS_READ = 64;
export const FETCH_TIMEOUT_MS = 10000;
export const MIN_INTERVAL_SECONDS = 6 * 3600;
export const WATCH_DAYS = 30;
export const WATCH_EVERY_SECONDS = 20 * 3600;
export const WATCH_MAX_PER_RUN = 50;
export const DAILY_GLOBAL = 200;
export const DAILY_PER_NETWORK = 20;
export const BATCH_MAX = 200;
export const USER_AGENT = "nenrin-slot-witness/0.1 (+https://ledger.horizonshield.dev/evidence/slot)";
export const CHECKER_URL = "https://raw.githubusercontent.com/ogasurfproject-jpg/horizon-shield/main/workers/hs-ledger/nenrin/slot-witness-v0/slot_check.py";

// Issuers read in v0, by x-only BIP-340 key. The key is invinoveritas's verifier key as its proofs and
// https://api.babyblueviper.com/.well-known/verifier-keys.json publish it; a key not listed here is refused by name.
export const ISSUERS = {
  "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7": {
    name: "invinoveritas",
    slot_url_prefix: "https://api.babyblueviper.com/decision-receipt/slot/",
    spec: "https://github.com/babyblueviper1/invinoveritas/blob/main/examples/decision-receipt/SPEC.md",
  },
};
export const SLOT_RE = /^[A-Za-z0-9_:.-]{16,160}$/;
export const VERDICTS = ["unique", "listed_with_others", "not_listed", "not_taken", "slot_mismatch", "unreadable", "fetch_failed"];

const PENDING = (sha) => "slotw:pending:" + sha;
const ANCHORED = (sha) => "slotw:anchored:" + sha;
const LAST = (slotSha, evId) => "slotw:last:" + slotSha + ":" + evId;
const BY_SLOT = (slotSha, at, sha) => "slotw:slot:" + slotSha + ":" + at + ":" + sha;
const PENDING_PREFIX = "slotw:pending:";
const LAST_PREFIX = "slotw:last:";
const enc = new TextEncoder();
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export const sha256hex = async (s) => hex(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s));
const b64 = (bytes) => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };
const iso = (sec) => new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

// ---- the receipt ------------------------------------------------------------------------------------------
// Checks a receipt event and returns what the observation needs. Refuses by name.
export async function readReceipt(ev) {
  if (!isObj(ev)) throw new Refusal("not_an_event", "event must be a NIP-01 event object");
  const issuer = ISSUERS[ev.pubkey];
  if (!issuer) throw new Refusal("issuer_not_read", "the event's pubkey is not an issuer this intake reads (v0: " + Object.values(ISSUERS).map((i) => i.name).join(", ") + ")");
  const c = await nostrEventCheck(ev);
  if (!c.ok) throw new Refusal("bad_event", c.why);
  let content;
  try { content = JSON.parse(ev.content); } catch (_e) { throw new Refusal("content_not_json", "the signed content is not JSON"); }
  if (!isObj(content)) throw new Refusal("content_not_json", "the signed content is not a JSON object");
  const slot = content.request_slot;
  if (slot === undefined || slot === null) throw new Refusal("no_request_slot", "the receipt carries no request_slot, so it makes no uniqueness claim to witness (decision-receipt SPEC: no request_id or an x402 call means no slot)");
  if (typeof slot !== "string" || !SLOT_RE.test(slot)) throw new Refusal("bad_request_slot", "request_slot is not a URL-safe string of 16 to 160 characters");
  return { issuer, slot, content, content_schema: typeof content.schema === "string" ? content.schema : null, event_jcs: jcs(ev) };
}

// ---- the observation: what the issuer's slot endpoint said, judged against this receipt ----------------------
// Pure: the same function decides in slot_check.py (judge()), from the stored response bytes.
export function judge(httpStatus, bodyBytes, slot, eventId) {
  if (httpStatus === null) return { verdict: "fetch_failed", event_ids_seen: null };
  if (httpStatus !== 200) return { verdict: "unreadable", event_ids_seen: null };
  let b;
  try { b = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes)); } catch (_e) { return { verdict: "unreadable", event_ids_seen: null }; }
  if (!isObj(b)) return { verdict: "unreadable", event_ids_seen: null };
  if (b.slot !== slot) return { verdict: "slot_mismatch", event_ids_seen: null };
  if (b.taken !== true) return { verdict: "not_taken", event_ids_seen: Array.isArray(b.event_ids) && b.event_ids.every((x) => typeof x === "string") ? b.event_ids : null };
  if (!Array.isArray(b.event_ids) || !b.event_ids.every((x) => typeof x === "string")) return { verdict: "unreadable", event_ids_seen: null };
  const ids = b.event_ids;
  if (ids.length === 1 && ids[0] === eventId) return { verdict: "unique", event_ids_seen: ids };
  if (ids.includes(eventId)) return { verdict: "listed_with_others", event_ids_seen: ids };
  return { verdict: "not_listed", event_ids_seen: ids };
}

// v0.1: what the kept bytes say about the decider. A decider-scoped slot (SPEC v0.4) carries the decider_claim that
// holds it with decider_sig, and conflicts: other claims the decider key signed for the same request_id, which the
// issuer refused. Each signature is BIP-340 by decider_pubkey over sha256(JCS(decider_claim)). This reads them; it
// does not decide which claim was the decider's real choice. Returns null when the bytes carry no decider claim
// (an account-scoped slot, or bytes that are not a slot object).
//   pubkey              the decider key the signed receipt names (content.decider_pubkey), else the slot's claim's
//   holder_claim        the claim holding the slot, checked in this order: "malformed" (no usable key), "other_key"
//                       (it names another key), "other_slot" (another slot), "bad_signature", "not_the_receipts_claim"
//                       (validly signed by this key for this slot, but not the claim this receipt carries), "verifies"
//   conflicts_listed    entries in conflicts (at most MAX_CONFLICTS_READ are read)
//   conflicts_verified  entries whose claim names this pubkey and this slot, differs from the holder's claim, and whose
//                       signature verifies under pubkey
//   equivocation        at least two different claims for this slot verify under pubkey, counting the holder's claim,
//                       the listed conflicts and the claim the receipt itself carries (content.decider_claim/decider_sig)
const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/;
async function claimSigOk(claim, sig, pubkey) {
  if (!isObj(claim) || typeof sig !== "string" || !HEX128.test(sig) || typeof pubkey !== "string" || !HEX64.test(pubkey)) return false;
  try { return await schnorrVerify(hexToBytes(pubkey), new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(jcs(claim)))), hexToBytes(sig)); }
  catch (_e) { return false; }
}
export async function deciderReading(httpStatus, bodyBytes, slot, receiptContent) {
  if (httpStatus !== 200) return null;
  let b;
  try { b = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes)); } catch (_e) { return null; }
  if (!isObj(b) || !isObj(b.decider_claim)) return null;
  const dc = b.decider_claim;
  const rc = isObj(receiptContent) ? receiptContent : {};
  const pubkey = typeof rc.decider_pubkey === "string" ? rc.decider_pubkey : (typeof dc.decider_pubkey === "string" ? dc.decider_pubkey : null);
  const usable = pubkey !== null && HEX64.test(pubkey);
  const names = (c) => isObj(c) && c.decider_pubkey === pubkey && c.request_slot === slot;
  const valid = new Set();
  let holder = "malformed";
  if (usable) {
    if (dc.decider_pubkey !== pubkey) holder = "other_key";
    else if (dc.request_slot !== slot) holder = "other_slot";
    else if (!(await claimSigOk(dc, b.decider_sig, pubkey))) holder = "bad_signature";
    else { valid.add(jcs(dc)); holder = isObj(rc.decider_claim) && jcs(rc.decider_claim) !== jcs(dc) ? "not_the_receipts_claim" : "verifies"; }
  }
  const list = Array.isArray(b.conflicts) ? b.conflicts : [];
  let verified = 0;
  const holderJcs = jcs(dc);
  if (usable) {
    for (const c of list.slice(0, MAX_CONFLICTS_READ)) {
      if (!isObj(c) || !names(c.decider_claim) || jcs(c.decider_claim) === holderJcs) continue;
      if (await claimSigOk(c.decider_claim, c.decider_sig, pubkey)) { verified++; valid.add(jcs(c.decider_claim)); }
    }
    if (names(rc.decider_claim) && (await claimSigOk(rc.decider_claim, rc.decider_sig, pubkey))) valid.add(jcs(rc.decider_claim));
  }
  return { pubkey, holder_claim: holder, conflicts_listed: list.length, conflicts_verified: verified, equivocation: valid.size >= 2 };
}

// v0.2: what the kept bytes say about the issuer's slot log. The slot's "log" object carries the slot's line in the
// latest daily snapshot, its Merkle path, the snapshot header and log_root = sha256(JCS(header)), the digest the issuer
// stamps to Bitcoin. null when the bytes are not a 200 slot object; otherwise { status, date, log_root, disagreements }:
//   absent | not_yet_in_a_snapshot | malformed | proof_fails (leaf, path or log_root do not recompute)
//   | line_disagrees (the proof holds, the line says something else than the slot bytes) | included
// It does not check the stamp; slot_check.py --log-anchor reads the issuer's .ots for that.
const g = (o, k) => (isObj(o) && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : null);
const isInt = (x) => typeof x === "number" && Number.isInteger(x);
export async function issuerLogReading(httpStatus, bodyBytes, slot) {
  if (httpStatus !== 200) return null;
  let b;
  try { b = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes)); } catch (_e) { return null; }
  if (!isObj(b)) return null;
  const out = { status: "absent", date: null, log_root: null, disagreements: [] };
  if (!Object.prototype.hasOwnProperty.call(b, "log")) return out;
  const lg = b.log;
  if (isObj(lg) && lg.status === "not_yet_in_a_snapshot" && !Object.prototype.hasOwnProperty.call(lg, "line")) return { ...out, status: "not_yet_in_a_snapshot" };
  const h = g(lg, "header"), path = g(lg, "merkle_path");
  const shape = isObj(lg) && isObj(g(lg, "line")) && HEX64.test(String(g(lg, "leaf"))) && typeof g(lg, "leaf") === "string"
    && typeof g(lg, "log_root") === "string" && HEX64.test(lg.log_root) && isObj(h)
    && g(h, "schema") === LOG_SCHEMA && typeof g(h, "date") === "string" && isInt(g(h, "cutoff")) && typeof g(h, "merkle_root") === "string" && HEX64.test(h.merkle_root)
    && Array.isArray(path) && path.length <= MAX_MERKLE_PATH
    && path.every((st) => isObj(st) && (g(st, "side") === "L" || g(st, "side") === "R") && typeof g(st, "hash") === "string" && HEX64.test(st.hash));
  if (!shape) return { ...out, status: "malformed" };
  const o2 = { ...out, date: h.date, log_root: lg.log_root };
  const leaf = await sha256hex(jcs(lg.line));
  let node = leaf;
  for (const st of path) node = st.side === "R" ? await sha256hex(node + st.hash) : await sha256hex(st.hash + node);
  if (leaf !== lg.leaf || node !== h.merkle_root || (await sha256hex(jcs(h))) !== lg.log_root) return { ...o2, status: "proof_fails" };
  const ln = lg.line, dis = [];
  if (g(ln, "slot") !== slot || g(b, "slot") !== slot) dis.push("slot");
  for (const k of ["scope", "event_ids", "taken_at"]) if (jcs(g(ln, k)) !== jcs(g(b, k))) dis.push(k);
  const dc = g(b, "decider_claim");
  if (jcs(g(ln, "claim_sha256")) !== jcs(isObj(dc) ? await sha256hex(jcs(dc)) : null)) dis.push("claim_sha256");
  if (jcs(g(ln, "decider_sig")) !== jcs(isObj(dc) ? g(b, "decider_sig") : null)) dis.push("decider_sig");
  if (!(isInt(g(ln, "taken_at")) && ln.taken_at < h.cutoff)) dis.push("taken_at_not_before_cutoff");
  const lc = g(ln, "conflicts"), bc = Object.prototype.hasOwnProperty.call(b, "conflicts") ? b.conflicts : [];
  if (!Array.isArray(lc) || !Array.isArray(bc) || lc.length > MAX_CONFLICTS_READ || bc.length > MAX_CONFLICTS_READ) dis.push("conflicts_unreadable");
  else {
    const shown = new Set(), before = new Set();
    for (const c of bc) {
      if (!isObj(c) || !isObj(g(c, "decider_claim"))) continue;
      const e = jcs({ claim_sha256: await sha256hex(jcs(c.decider_claim)), decider_sig: g(c, "decider_sig"), received_at: g(c, "received_at") });
      shown.add(e);
      if (isInt(g(c, "received_at")) && c.received_at < h.cutoff) before.add(e);
    }
    const logged = new Set(lc.map((c) => jcs(c)));
    if ([...before].some((e) => !logged.has(e))) dis.push("conflict_shown_by_slot_missing_from_log");
    if ([...logged].some((e) => !shown.has(e))) dis.push("conflict_in_log_not_shown_by_slot");
  }
  return { ...o2, status: dis.length ? "line_disagrees" : "included", disagreements: dis };
}

async function readCapped(resp, cap) {
  const reader = resp.body ? resp.body.getReader() : null;
  if (!reader) return { bytes: new Uint8Array(await resp.arrayBuffer()).slice(0, cap), truncated: false };
  const parts = []; let n = 0, truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (n + value.length > cap) { parts.push(value.slice(0, cap - n)); n = cap; truncated = true; try { await reader.cancel(); } catch (_e) {} break; }
    parts.push(value); n += value.length;
  }
  const out = new Uint8Array(n); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; }
  return { bytes: out, truncated };
}

export async function observe(ev, rc, { nowSec, fetchImpl, trigger, previous, version = "0.2" }) {
  const v0 = version === "0", v01 = version === "0.1";
  const cap = v0 ? MAX_RESPONSE_BYTES_V0 : MAX_RESPONSE_BYTES;
  const url = rc.issuer.slot_url_prefix + encodeURIComponent(rc.slot);
  let status = null, ctype = null, bytes = new Uint8Array(0), truncated = false, fetchError = null;
  try {
    const r = await fetchImpl(url, { method: "GET", redirect: "manual", headers: { accept: "application/json", "user-agent": USER_AGENT }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    status = r.status; ctype = r.headers.get("content-type");
    ({ bytes, truncated } = await readCapped(r, cap));
  } catch (e) { status = null; fetchError = String((e && e.name) || "error"); }
  const j0 = truncated ? { verdict: "unreadable", event_ids_seen: null } : judge(status, bytes, rc.slot, ev.id);
  const dec = v0 || truncated ? null : await deciderReading(status, bytes, rc.slot, rc.content);
  const prevDec = previous && Object.prototype.hasOwnProperty.call(previous, "decider") ? previous.decider : undefined;
  const il = v0 || v01 || truncated ? null : await issuerLogReading(status, bytes, rc.slot);
  const prevIl = previous && Object.prototype.hasOwnProperty.call(previous, "issuer_log") ? previous.issuer_log : undefined;
  const obs = {
    schema: v0 ? OBS_SCHEMA_V0 : v01 ? OBS_SCHEMA_V01 : OBS_SCHEMA,
    issuer: rc.issuer.name, issuer_pubkey: ev.pubkey,
    receipt_event_id: ev.id, receipt_created_at: ev.created_at, receipt_content_schema: rc.content_schema,
    request_slot: rc.slot, slot_url: url,
    observed_at: iso(nowSec), trigger,
    http_status: status, response_content_type: ctype, response_bytes: bytes.length, response_truncated: truncated,
    response_sha256: await sha256hex(bytes), response_b64: b64(bytes), fetch_error: fetchError,
    verdict: j0.verdict, event_ids_seen: j0.event_ids_seen,
    previous_observation: previous ? { sha: previous.sha, observed_at: previous.observed_at, verdict: previous.verdict, event_ids_seen: previous.event_ids_seen } : null,
    changed_since_previous: previous ? JSON.stringify(previous.event_ids_seen) !== JSON.stringify(j0.event_ids_seen) || previous.verdict !== j0.verdict
      || (!v0 && prevDec !== undefined && JSON.stringify(prevDec) !== JSON.stringify(dec))
      || (!v0 && !v01 && prevIl !== undefined && JSON.stringify(prevIl) !== JSON.stringify(il)) : null,
    receipt_event: JSON.parse(rc.event_jcs),
  };
  if (!v0) obs.decider = dec;
  if (!v0 && !v01) obs.issuer_log = il;
  return obs;
}

export const ESTABLISHES = [
  "the receipt event's id recomputes (NIP-01) and its BIP-340 signature verifies under the issuer key pinned in this intake",
  "at observed_at this ledger fetched the issuer's slot endpoint for the receipt's request_slot itself, and response_b64 is exactly the bytes it got (response_sha256)",
  "the verdict is what those bytes say about this receipt: unique when the slot is taken and lists exactly this event id",
  "from v0.1, decider says what the same bytes show about the decider key: whether the claim holding the slot verifies, how many conflicting claims the issuer lists, how many of them verify under the same decider key, and equivocation when two valid decider signatures name one slot",
  "from v0.2, issuer_log says whether the same bytes carry the slot's line in the issuer's daily slot log with a Merkle proof that recomputes to the stamped log_root, and whether that line agrees with the slot bytes beside it (event ids, claim hash, signature, conflicts before the cutoff)",
  "observations of one slot form a chain (previous_observation), so a slot that later lists a different or a second receipt is visible next to what it listed before",
  "once the daily batch that lists an observation is stamped, that observation existed before that Bitcoin block",
];
export const DOES_NOT_ESTABLISH = [
  "that only one receipt was issued for the request; the slot is the issuer's record, this ledger only reads it",
  "that the request_id behind the slot is the decider's own id; the SPEC leaves that to the relying party",
  "that the decision the receipt commits to was the decider's real choice; it stays caller-reported",
  "which of two conflicting decider claims was the real decision, or that the decider key belongs to any particular person; only that the key signed both",
  "that the log_root was stamped to Bitcoin, or when; issuer_log checks the proof against the header in the same bytes, and slot_check.py --log-anchor checks the issuer's .ots",
  "what the endpoint served between observations, or to anyone else; only what it served this ledger, when",
  "that the issuer's key was not compromised",
];

export function selfDescription(origin) {
  return {
    schema: OBS_SCHEMA,
    what: "A third-party reader of an issuer's one-receipt-per-request record: the ledger verifies a decision receipt, fetches the issuer's slot endpoint itself, keeps the response bytes, re-reads the slot daily for " + WATCH_DAYS + " days, and anchors every observation to Bitcoin",
    post: { url: origin + "/evidence/slot", body: { event: "<the receipt's signed NIP-01 event (kind, content with request_slot, sig)>" } },
    read: { observation: origin + "/evidence/slot/{sha}", raw_bytes: origin + "/evidence/slot/{sha}?format=raw", by_slot: origin + "/evidence/slot/s/{request_slot}", pending: origin + "/evidence/slot/pending" },
    issuers_read: Object.entries(ISSUERS).map(([k, v]) => ({ name: v.name, pubkey: k, slot_endpoint: v.slot_url_prefix + "{request_slot}", spec: v.spec })),
    verdicts: VERDICTS,
    checks_at_intake: [
      "the event is NIP-01: its id recomputes from [0, pubkey, created_at, kind, tags, content]",
      "sig is a BIP-340 signature over the id under pubkey, and pubkey is an issuer listed here",
      "the signed content is JSON with a request_slot",
      "the slot endpoint is fetched by this ledger, no redirects followed, " + FETCH_TIMEOUT_MS / 1000 + " s timeout, at most " + MAX_RESPONSE_BYTES + " bytes kept",
      "when the slot holds a decider claim (decider-scoped slot), its decider_sig and up to " + MAX_CONFLICTS_READ + " listed conflicts are checked: BIP-340 by the receipt's decider_pubkey over sha256(JCS(decider_claim)); the result is the observation's decider field",
      "when the slot carries its log object (the issuer's daily slot log), the line's Merkle path is recomputed to the header and log_root, and the line is compared with the slot bytes; the result is the observation's issuer_log field",
    ],
    schemas_read: [OBS_SCHEMA_V0 + " (until 2026-10-11: no decider field, at most " + MAX_RESPONSE_BYTES_V0 + " bytes kept)",
      OBS_SCHEMA_V01 + " (2026-10-11: decider field, no issuer_log field)", OBS_SCHEMA],
    watch: "each (slot, receipt) is observed again about daily for " + WATCH_DAYS + " days after its first observation, at most " + WATCH_MAX_PER_RUN + " per run, oldest first",
    caps: { max_bytes: MAX_BYTES, min_interval_seconds_per_receipt: MIN_INTERVAL_SECONDS, daily_global: DAILY_GLOBAL, daily_per_network: DAILY_PER_NETWORK },
    anchor_policy: "observations are bundled oldest first into a " + BATCH_SCHEMA + " ledger entry daily at 00:30 UTC; the Bitcoin stamp follows on the operator's stamping run",
    establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
    verify_offline: CHECKER_URL,
  };
}

// ---- storage ----------------------------------------------------------------------------------------------
const j = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*", ...extra } });

async function networkLane(request, day) {
  const s = (request.headers.get("cf-connecting-ip") || "unknown").trim();
  let pre = s;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) pre = s.split(".").slice(0, 3).join(".");
  else if (s.indexOf(":") >= 0) pre = s.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase().split(":").slice(0, 3).join(":");
  return "slotw:net:" + day + ":" + (await sha256hex(day + "|" + pre)).slice(0, 16);
}

async function listAll(env, prefix, max = 20000) {
  const out = []; let cursor;
  do {
    const r = await env.LEDGER.list({ prefix, cursor });
    out.push(...r.keys);
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor && out.length < max);
  return out;
}

async function store(env, obs) {
  const record_jcs = jcs(obs);
  const sha = await sha256hex(record_jcs);
  const slotSha = await sha256hex(obs.request_slot);
  const stored = { sha, record_jcs, request_slot: obs.request_slot, receipt_event_id: obs.receipt_event_id, verdict: obs.verdict, observed_at: obs.observed_at, response_sha256: obs.response_sha256 };
  await env.LEDGER.put(PENDING(sha), JSON.stringify(stored));
  const dk = Object.prototype.hasOwnProperty.call(obs, "decider") ? { decider: obs.decider } : {};
  if (Object.prototype.hasOwnProperty.call(obs, "issuer_log")) dk.issuer_log = obs.issuer_log;
  await env.LEDGER.put(BY_SLOT(slotSha, obs.observed_at, sha), JSON.stringify({ sha, receipt_event_id: obs.receipt_event_id, verdict: obs.verdict, event_ids_seen: obs.event_ids_seen, observed_at: obs.observed_at, ...dk }));
  const lastKey = LAST(slotSha, obs.receipt_event_id);
  const prevRaw = await env.LEDGER.get(lastKey);
  let first = obs.observed_at;
  if (prevRaw) { try { first = JSON.parse(prevRaw).first_observed_at || first; } catch (_e) {} }
  await env.LEDGER.put(lastKey, JSON.stringify({ sha, observed_at: obs.observed_at, verdict: obs.verdict, event_ids_seen: obs.event_ids_seen, first_observed_at: first, event: obs.receipt_event, ...dk }));
  return sha;
}

async function lastOf(env, slot, evId) {
  const raw = await env.LEDGER.get(LAST(await sha256hex(slot), evId));
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_e) { return null; }
}

async function handlePost(request, env, origin, nowSec, fetchImpl) {
  const text = await request.text();
  if (text.length > MAX_BYTES * 2) return j({ error: "too_large", max_bytes: MAX_BYTES }, 413);
  let body = null; try { body = JSON.parse(text); } catch (_e) { body = null; }
  if (!isObj(body) || !("event" in body)) return j({ error: "body must be a JSON object with an event member", help: origin + "/evidence/slot" }, 400);
  const ev = body.event;
  let rc;
  try { rc = await readReceipt(ev); }
  catch (e) { if (e instanceof Refusal) return j({ error: "refused", reason_code: e.code, why: e.message, help: origin + "/evidence/slot" }, e.status); throw e; }
  const prev = await lastOf(env, rc.slot, ev.id);
  if (prev && nowSec - Math.floor(Date.parse(prev.observed_at) / 1000) < MIN_INTERVAL_SECONDS)
    return j({ sha: prev.sha, status: "recent", dedup: true, note: "this receipt's slot was observed less than " + MIN_INTERVAL_SECONDS / 3600 + " hours ago; it is re-read on the daily watch", observed_at: prev.observed_at, verdict: prev.verdict, url: origin + "/evidence/slot/" + prev.sha, by_slot: origin + "/evidence/slot/s/" + encodeURIComponent(rc.slot) });
  const day = iso(nowSec).slice(0, 10);
  const gKey = "slotw:count:" + day;
  const g = Number((await env.LEDGER.get(gKey)) || 0);
  if (g >= DAILY_GLOBAL) return j({ error: "daily_global_cap_reached", cap: DAILY_GLOBAL }, 429);
  const nKey = await networkLane(request, day);
  const nc = Number((await env.LEDGER.get(nKey)) || 0);
  if (nc >= DAILY_PER_NETWORK) return j({ error: "daily_per_network_cap_reached", cap: DAILY_PER_NETWORK }, 429);
  await env.LEDGER.put(gKey, String(g + 1), { expirationTtl: 90000 });
  await env.LEDGER.put(nKey, String(nc + 1), { expirationTtl: 90000 });
  const obs = await observe(ev, rc, { nowSec, fetchImpl, trigger: "submitted", previous: prev });
  const sha = await store(env, obs);
  return j({
    sha, status: "pending", url: origin + "/evidence/slot/" + sha, by_slot: origin + "/evidence/slot/s/" + encodeURIComponent(rc.slot),
    issuer: obs.issuer, receipt_event_id: obs.receipt_event_id, request_slot: obs.request_slot,
    observed_at: obs.observed_at, http_status: obs.http_status, verdict: obs.verdict, event_ids_seen: obs.event_ids_seen,
    changed_since_previous: obs.changed_since_previous, decider: obs.decider ?? null, issuer_log: obs.issuer_log ?? null,
    establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
  }, 201);
}

async function storedOf(env, sha) {
  const aRaw = await env.LEDGER.get(ANCHORED(sha));
  if (aRaw) { try { const a = JSON.parse(aRaw); return { stored: a.stored, n: a.n }; } catch (_e) {} }
  const pRaw = await env.LEDGER.get(PENDING(sha));
  if (pRaw) { try { return { stored: JSON.parse(pRaw), n: null }; } catch (_e) {} }
  return null;
}

async function anchorOf(env, origin, n) {
  if (n === null) return null;
  try { const e = JSON.parse(await env.LEDGER.get("entry:" + n)); return { ledger_entry: n, batch_sha256: e.claim_sha256, ots_status: e.ots_status || null, block: e.bitcoin_block ?? null, block_time: e.block_time || null, ots: origin + "/ledger/" + n + "/ots", batch_raw: origin + "/ledger/" + n + "?format=raw" }; } catch (_e) { return null; }
}

async function handleGetOne(sha, url, env, origin) {
  const s = await storedOf(env, sha);
  if (!s) return j({ error: "not_found", sha, note: "no slot observation is held under this sha" }, 404);
  if (url.searchParams.get("format") === "raw")
    return new Response(s.stored.record_jcs, { status: 200, headers: { "content-type": "application/json; charset=utf-8", "x-record-sha256": sha, "cache-control": "public, max-age=31536000, immutable", "access-control-allow-origin": "*" } });
  let obs = null; try { obs = JSON.parse(s.stored.record_jcs); } catch (_e) {}
  return j({ sha, status: s.n !== null ? "anchored" : "pending", anchor: await anchorOf(env, origin, s.n), raw_url: origin + "/evidence/slot/" + sha + "?format=raw", by_slot: obs && typeof obs.request_slot === "string" ? origin + "/evidence/slot/s/" + encodeURIComponent(obs.request_slot) : null, observation: obs, establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH });
}

async function handleBySlot(slotEnc, env, origin) {
  let slot; try { slot = decodeURIComponent(slotEnc); } catch (_e) { return j({ error: "bad_slot_encoding" }, 400); }
  if (!SLOT_RE.test(slot)) return j({ error: "bad_slot" }, 400);
  const keys = await listAll(env, "slotw:slot:" + (await sha256hex(slot)) + ":");
  const obs = [];
  for (const k of keys) {
    try {
      const x = JSON.parse(await env.LEDGER.get(k.name));
      const s = await storedOf(env, x.sha);
      obs.push({ ...x, status: s && s.n !== null ? "anchored" : "pending", anchor: s ? await anchorOf(env, origin, s.n) : null, url: origin + "/evidence/slot/" + x.sha });
    } catch (_e) {}
  }
  obs.sort((a, b) => (a.observed_at < b.observed_at ? -1 : a.observed_at > b.observed_at ? 1 : a.sha < b.sha ? -1 : 1));
  if (!obs.length) return j({ request_slot: slot, count: 0, observations: [], note: "this ledger has not observed this slot" }, 404);
  const seen = [...new Set(obs.map((o) => JSON.stringify(o.event_ids_seen)))];
  const receipts = [...new Set(obs.map((o) => o.receipt_event_id))];
  return j({
    request_slot: slot, count: obs.length, observations: obs,
    distinct_event_id_lists_seen: seen.map((s) => JSON.parse(s)),
    slot_listing_changed: seen.length > 1,
    decider_equivocation_seen: obs.some((o) => o.decider && o.decider.equivocation === true),
    issuer_log_statuses_seen: [...new Set(obs.filter((o) => o.issuer_log).map((o) => o.issuer_log.status))],
    receipts_submitted_for_this_slot: receipts,
    note: "every observation of this slot, oldest first. slot_listing_changed is true when the issuer's endpoint listed different receipts at different times; two receipts submitted for one slot means two signed receipts name the same request slot",
  });
}

async function handlePending(env, origin) {
  const keys = await listAll(env, PENDING_PREFIX);
  const out = [];
  for (const k of keys) { try { const s = JSON.parse(await env.LEDGER.get(k.name)); out.push({ sha: s.sha, request_slot: s.request_slot, verdict: s.verdict, observed_at: s.observed_at, url: origin + "/evidence/slot/" + s.sha }); } catch (_e) {} }
  out.sort((a, b) => (a.observed_at < b.observed_at ? -1 : a.observed_at > b.observed_at ? 1 : a.sha < b.sha ? -1 : 1));
  return j({ count: out.length, pending: out, note: "queued oldest first for the daily batch at 00:30 UTC" });
}

export async function handleSlotWitness(p, request, url, env, origin, nowSec = Math.floor(Date.now() / 1000), fetchImpl = (u, i) => fetch(u, i)) {
  if (p !== "/evidence/slot" && !p.startsWith("/evidence/slot/")) return null;
  if (p === "/evidence/slot") {
    if (request.method === "GET") return j(selfDescription(origin));
    if (request.method === "POST") return handlePost(request, env, origin, nowSec, fetchImpl);
    return j({ error: "method_not_allowed" }, 405);
  }
  if (request.method !== "GET") return j({ error: "method_not_allowed" }, 405);
  const rest = p.slice("/evidence/slot/".length);
  if (rest === "pending") return handlePending(env, origin);
  if (rest.startsWith("s/")) return handleBySlot(rest.slice(2), env, origin);
  const sha = rest.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) return j({ error: "sha_must_be_64_hex" }, 400);
  return handleGetOne(sha, url, env, origin);
}

// ---- the daily watch: re-read slots first observed in the last WATCH_DAYS, oldest observation first ------------
export async function watchSlots(env, nowSec = Math.floor(Date.now() / 1000), fetchImpl = (u, i) => fetch(u, i)) {
  const keys = await listAll(env, LAST_PREFIX);
  const due = [];
  for (const k of keys) {
    try {
      const x = JSON.parse(await env.LEDGER.get(k.name));
      const first = Math.floor(Date.parse(x.first_observed_at) / 1000), last = Math.floor(Date.parse(x.observed_at) / 1000);
      if (nowSec - first <= WATCH_DAYS * 86400 && nowSec - last >= WATCH_EVERY_SECONDS) due.push(x);
    } catch (_e) {}
  }
  due.sort((a, b) => (a.observed_at < b.observed_at ? -1 : a.observed_at > b.observed_at ? 1 : 0));
  const done = [];
  for (const x of due.slice(0, WATCH_MAX_PER_RUN)) {
    let rc; try { rc = await readReceipt(x.event); } catch (_e) { continue; }
    const obs = await observe(x.event, rc, { nowSec, fetchImpl, trigger: "watch", previous: x });
    done.push({ sha: await store(env, obs), verdict: obs.verdict, changed: obs.changed_since_previous });
  }
  return { observed: done.length, due: due.length, changed: done.filter((d) => d.changed).length };
}

// ---- daily anchor, oldest first over every KV page (the R3-2 fix the vouch intake started with) ---------------
export async function anchorSlotWitnessPool(env, origin, trigger, nowIso = new Date().toISOString()) {
  const keys = await listAll(env, PENDING_PREFIX);
  if (!keys.length) return { status: 200, body: { ok: true, anchored: 0, note: "slot witness pool is empty" } };
  const all = [];
  for (const k of keys) {
    const raw = await env.LEDGER.get(k.name);
    if (!raw) continue;
    try { const s = JSON.parse(raw); if (s && /^[0-9a-f]{64}$/.test(s.sha)) all.push(s); } catch (_e) {}
  }
  all.sort((a, b) => (a.observed_at < b.observed_at ? -1 : a.observed_at > b.observed_at ? 1 : a.sha < b.sha ? -1 : 1));
  const items = all.slice(0, BATCH_MAX);
  const batch = {
    schema: BATCH_SCHEMA, anchored_at: nowIso, count: items.length,
    records: items.map((s) => ({ sha: s.sha, request_slot: s.request_slot, receipt_event_id: s.receipt_event_id, verdict: s.verdict, observed_at: s.observed_at, response_sha256: s.response_sha256 })),
  };
  const canonical = JSON.stringify(batch);
  const h = (await sha256hex(canonical)).toLowerCase();
  const dup = await env.LEDGER.get("hash:" + h);
  if (dup) return { status: 200, body: { n: Number(dup), url: origin + "/ledger/" + dup, dedup: true } };
  const entry = { n: 0, work: "NENRIN slot witness batch (" + items.length + " observations)", claim_sha256: h, record_canonical: canonical, schema: "v0-plain", created_at: nowIso, ots_status: "unstamped", bitcoin_block: null, block_time: null, stamped_at: null, anchored_by: trigger };
  const ap = await appendEntry(env, h, entry);   // 2026-10-13 (concurrency audit L1): the sequencer assigns n
  if (ap.dedup) return { status: 200, body: { n: ap.n, url: origin + "/ledger/" + ap.n, dedup: true } };
  const n = ap.n;
  for (const s of items) {
    await env.LEDGER.put(ANCHORED(s.sha), JSON.stringify({ n, stored: s }));
    await env.LEDGER.delete(PENDING(s.sha));
  }
  return { status: 201, body: { n, url: origin + "/ledger/" + n, anchored: items.length, remaining: all.length - items.length, trigger } };
}
