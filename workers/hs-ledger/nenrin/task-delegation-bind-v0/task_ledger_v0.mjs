// task_ledger_v0.mjs : additive NENRIN ledger face for A2A task-bound conduct observations (bind-v0).
//
// Workers-native crypto (Web Crypto, no Node built-in): deploys without the nodejs_compat flag and changes
// nothing about the ledger worker's runtime. evidence_id is byte-identical to bind.mjs (same simplified-JCS
// canonical + SHA-256), so the offline reference impl and this live face agree on every hash.
//
// Parallel to the existing endpoint-keyed witness path; touches none of it. It anchors evidence on the
// A2A Task `id` (a2a.task.id, aligned to A2A issues #1769 / #2103), so a verifier can ask "who did what on
// THIS delegated task, observed by whom" instead of "this agent failed once".
//
// Content invariants (always): R1 independence, R2 recompute, R3 chain continuity, R4 non-suppression.
// Attribution (optional, verified when present): witness_sig (Ed25519 by the witness over canonical(preimage))
// makes the verdict attributable; edge_sig (Ed25519 by hop.from over canonical({task_id,hop})) makes the
// delegation edge party-attested. Keys resolve from did:key with no network (self-contained, offline byte-match).
// A present-but-invalid signature is REJECTED (422); an absent signature is accepted (unsigned, content-only).
//
// record-privacy-v1 (2026-09-28, workers/hs-verify-gate/ext/RECORD_PRIVACY_v1.md). A task observation names two
// parties (hop.from, hop.to) and what one did for the other. It is published in full only when each party either is a
// public surface (an https origin on a public host: what an operator published for machines, class P, the same as a
// witness walk) or signed consent to publication. A did:key party is a private identity until it consents:
// consent = [{ party, sig }], each sig Ed25519 by that party's did:key over
// canonical({ purpose: "nenrin-task-publication-consent-v0", task_id, hop, publication: "public" }). consent is a
// derived field (outside the evidence_id preimage), so adding it later changes neither evidence_id nor witness_sig.
// Without both consents the ledger keeps a commitment only: the evidence_id and the receipt time, anchored in the
// daily batch with nothing else. Nothing that names the task, the parties, the witness or the verdict is stored or
// served. Re-POST the same observation with both consents to publish it; the anchored commitment then proves it
// existed at the earlier time. A present-but-invalid consent is refused (422). Observations filed before this rule
// stay as filed (their batch entries are in the append-only ledger).
//
// Routes (additive):
//   POST /witness/task              body = a WitnessObservation (evidence_id present; witness_sig/edge_sig optional)
//   GET  /witness/task?task_id=..   [&hop=<seq>]  -> full set + per-hop aggregate (R4) + chain check (R3)
//   GET  /trust-signal?task_id=..   -> consumable task-bound conduct signal (counts and verdicts, never a score)
//
// KV layout (all under nenrin:task:, disjoint from every existing key):
//   nenrin:task:obs:<evidence_id>                 -> canonical bytes of the observation
//   nenrin:task:<task_id>:<hop.seq>:<witness_id>  -> <evidence_id>   (index, one per independent witness)

const enc = new TextEncoder();

import { parseStrict, checkCanonicalInput } from "./strict_json.mjs";
import { appendEntry } from "../../src/ledger_append.mjs";

export async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Canonical form, pinned (SPEC.md). Same bytes as bind.mjs; input outside the rule is refused, never hashed.
function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
export function canonical(v) {
  checkCanonicalInput(v);
  return canon(v);
}

const DERIVED_FIELDS = ["evidence_id", "witness_sig", "edge_sig", "consent"];
export const CONSENT_PURPOSE = "nenrin-task-publication-consent-v0";
export function consentMessage(obs) {
  return canonical({ purpose: CONSENT_PURPOSE, task_id: obs.task_id, hop: obs.hop, publication: "public" });
}
function preimage(obs) {
  const b = Object.assign({}, obs);
  for (const k of DERIVED_FIELDS) delete b[k];
  return b;
}
export async function evidenceId(obs) {
  return sha256hex(canonical(preimage(obs)));
}

function witnessIndependent(obs) {
  return obs.witness_id !== obs.hop.from && obs.witness_id !== obs.hop.to;
}
async function recomputeOk(obs) {
  return typeof obs.evidence_id === "string" && obs.evidence_id === (await evidenceId(obs));
}
async function verifyObservation(obs) {
  if (!witnessIndependent(obs)) return { ok: false, reason: "witness_not_independent" };
  if (!(await recomputeOk(obs))) return { ok: false, reason: "recompute_mismatch" };
  return { ok: true };
}
async function chainContinuous(observations) {
  const ord = observations.slice().sort((a, b) => a.hop.seq - b.hop.seq);
  for (let i = 0; i < ord.length; i++) {
    const o = ord[i];
    if (o.hop.seq !== i) return { ok: false, reason: "seq_gap", at: i };
    if (i === 0) {
      if (o.prev_evidence_id !== null) return { ok: false, reason: "root_prev_not_null", at: i };
    } else if (o.prev_evidence_id !== (await evidenceId(ord[i - 1]))) {
      return { ok: false, reason: "broken_link", at: i };
    }
  }
  return { ok: true };
}
function aggregateVerdict(observationsForHop) {
  const verdicts = [...new Set(observationsForHop.map((o) => o.conduct.verdict))];
  if (verdicts.length === 0) return "no_evidence";
  if (verdicts.length > 1) return "disagreement";
  return verdicts[0];
}

// ---- attribution: did:key (Ed25519) resolution + signature verification, all offline (Web Crypto) ----
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const ch of s) { if (ch === "1") bytes.unshift(0); else break; }
  return new Uint8Array(bytes);
}
function pubFromDidKey(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) return null;
  const dec = b58decode(did.slice("did:key:z".length));
  if (!dec || dec.length !== 34 || dec[0] !== 0xed || dec[1] !== 0x01) return null; // multicodec ed25519-pub
  return dec.slice(2);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
async function ed25519Verify(pubRaw, sigB64, msg) {
  try {
    const key = await crypto.subtle.importKey("raw", pubRaw, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, b64ToBytes(sigB64), enc.encode(msg));
  } catch { return false; }
}
// Verify present signatures. Returns {ok} or {ok:false, reason}. Absent signatures are allowed (content-only).
async function verifySignatures(obs) {
  if (typeof obs.witness_sig === "string") {
    const pub = pubFromDidKey(obs.witness_id);
    if (!pub) return { ok: false, reason: "witness_id_not_did_key" };
    if (!(await ed25519Verify(pub, obs.witness_sig, canonical(preimage(obs))))) return { ok: false, reason: "witness_sig_invalid" };
  }
  if (typeof obs.edge_sig === "string") {
    const pub = pubFromDidKey(obs.hop.from);
    if (!pub) return { ok: false, reason: "hop_from_not_did_key" };
    if (!(await ed25519Verify(pub, obs.edge_sig, canonical({ task_id: obs.task_id, hop: obs.hop })))) return { ok: false, reason: "edge_sig_invalid" };
  }
  return { ok: true };
}

// record-privacy-v1: which hop parties validly consented. Absent consent is fine (commitment only);
// a consent entry that is present but malformed or does not verify is refused, like witness_sig and edge_sig.
async function verifyConsent(obs) {
  if (obs.consent === undefined) return { ok: true, parties: [] };
  if (!Array.isArray(obs.consent)) return { ok: false, reason: "consent_not_a_list" };
  const want = [obs.hop.from, obs.hop.to];
  const got = new Set();
  const msg = consentMessage(obs);
  for (const c of obs.consent) {
    if (!c || typeof c !== "object" || typeof c.party !== "string" || typeof c.sig !== "string") return { ok: false, reason: "consent_entry_malformed" };
    if (!want.includes(c.party)) return { ok: false, reason: "consent_from_non_party" };
    const pub = pubFromDidKey(c.party);
    if (!pub) return { ok: false, reason: "consent_party_not_did_key" };
    if (!(await ed25519Verify(pub, c.sig, msg))) return { ok: false, reason: "consent_sig_invalid" };
    got.add(c.party);
  }
  return { ok: true, parties: [...got] };
}
// class P: an https origin on a public host. localhost, bare IPs, userinfo and non-https schemes are not public surfaces.
export function isPublicSurface(party) {
  if (typeof party !== "string") return false;
  let u; try { u = new URL(party); } catch { return false; }
  if (u.protocol !== "https:" || u.username || u.password) return false;
  const h = u.hostname.toLowerCase();
  if (!h.includes(".") || h === "localhost" || h.endsWith(".localhost") || h.startsWith("[") || /^[0-9.]+$/.test(h)) return false;
  return true;
}
function publicationBasis(obs, consentParties) {
  const one = (d) => (isPublicSurface(d) ? "public_surface" : (consentParties.includes(d) ? "consent" : null));
  return { from: one(obs.hop.from), to: one(obs.hop.to) };
}

const OBS_KEY = (eid) => "nenrin:task:obs:" + eid;
const COMMIT_KEY = (eid) => "nenrin:task:commit:" + eid;  // record-privacy-v1: { evidence_id, received_at } and nothing else
const IDX_KEY = (tid, seq, wid) => "nenrin:task:" + tid + ":" + seq + ":" + wid;
const IDX_PREFIX = (tid) => "nenrin:task:" + tid + ":";
const PENDING_KEY = (eid) => "nenrin:tw:pending:" + eid;   // daily Bitcoin anchor pool (disjoint from the nenrin:task: index)
const ANCHORED_KEY = (eid) => "nenrin:tw:anchored:" + eid; // { n, obs } once bundled into an anchored batch
const PENDING_PREFIX = "nenrin:tw:pending:";
const TASK_BATCH_MAX = 500;
// 2026-10-08 (FIX_LIST 5): caps on POST /witness/task, stated in the refusal. Body size and field lengths are
// checked before anything is parsed or hashed; the daily caps count new writes only (a repeat is free).
const TASK_MAX_BYTES = 32768;
const TASK_FIELD_MAX = { task_id: 256, "hop.from": 512, "hop.to": 512, witness_id: 512 };
const TASK_DAILY_GLOBAL = 2000;
const TASK_DAILY_PER_IP = 200;
async function taskCapKeys(request) {
  const day = new Date().toISOString().slice(0, 10);
  const ip = (request.headers && request.headers.get && request.headers.get("cf-connecting-ip")) || "unknown";
  return { g: "nenrin:tw:cap:" + day, i: "nenrin:tw:cap:" + day + ":" + (await sha256hex(ip)).slice(0, 16) };
}
function fieldTooLong(obs) {
  const vals = { task_id: obs.task_id, "hop.from": obs.hop.from, "hop.to": obs.hop.to, witness_id: obs.witness_id };
  for (const k of Object.keys(TASK_FIELD_MAX)) if (typeof vals[k] === "string" && vals[k].length > TASK_FIELD_MAX[k]) return k;
  if (!Number.isSafeInteger(obs.hop.seq) || obs.hop.seq < 0 || obs.hop.seq > 1000) return "hop.seq";
  return null;
}
async function taskCapHit(request, env) {
  const k = await taskCapKeys(request);
  const g = Number((await env.LEDGER.get(k.g)) || 0), i = Number((await env.LEDGER.get(k.i)) || 0);
  if (g >= TASK_DAILY_GLOBAL) return { error: "daily_global_cap_reached", cap: TASK_DAILY_GLOBAL };
  if (i >= TASK_DAILY_PER_IP) return { error: "daily_per_ip_cap_reached", cap: TASK_DAILY_PER_IP };
  return null;
}
async function taskCapCount(request, env) {
  const k = await taskCapKeys(request);
  const g = Number((await env.LEDGER.get(k.g)) || 0), i = Number((await env.LEDGER.get(k.i)) || 0);
  await env.LEDGER.put(k.g, String(g + 1), { expirationTtl: 90000 });
  await env.LEDGER.put(k.i, String(i + 1), { expirationTtl: 90000 });
}

function j(o, status = 200) {
  return new Response(JSON.stringify(o), {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
  });
}

function shapeError(obs) {
  if (!obs || typeof obs !== "object") return "not_an_object";
  if (typeof obs.task_id !== "string" || obs.task_id === "") return "task_id_missing";
  if (!obs.hop || typeof obs.hop.seq !== "number" || typeof obs.hop.from !== "string" || typeof obs.hop.to !== "string") return "hop_missing";
  if (!("prev_evidence_id" in obs) || (obs.prev_evidence_id !== null && typeof obs.prev_evidence_id !== "string")) return "prev_evidence_id_missing";
  if (!obs.conduct || typeof obs.conduct.verdict !== "string") return "conduct_verdict_missing";
  if (typeof obs.witness_id !== "string" || obs.witness_id === "") return "witness_id_missing";
  if (typeof obs.evidence_id !== "string" || obs.evidence_id === "") return "evidence_id_missing";
  return null;
}

export async function handleTaskWitnessPost(request, env) {
  let obs;
  // strict parse: duplicate keys, floats, unsafe integers and non-ASCII keys are refused before anything is hashed
  try {
    if (typeof request.text === "function") {
      const text = await request.text();
      if (text.length > TASK_MAX_BYTES) return j({ ok: false, error: "too_large", max_bytes: TASK_MAX_BYTES }, 413);
      obs = parseStrict(text);
    } else { obs = await request.json(); checkCanonicalInput(obs); }
  } catch (e) { return j({ ok: false, error: e && e.code ? e.code : "bad_json", at: e && e.at != null ? e.at : undefined }, 400); }
  const se = shapeError(obs);
  if (se) return j({ ok: false, error: se, need: "task_id, hop{seq,from,to}, prev_evidence_id, conduct{verdict}, witness_id, evidence_id" }, 400);
  const tl = fieldTooLong(obs);
  if (tl) return j({ ok: false, error: "field_too_long", field: tl, max: TASK_FIELD_MAX[tl] === undefined ? "0..1000 integer" : TASK_FIELD_MAX[tl] }, 400);
  const v = await verifyObservation(obs); // R1 independence + R2 recompute
  if (!v.ok) return j({ ok: false, error: v.reason }, 422);
  const s = await verifySignatures(obs); // optional attribution; present-but-invalid is rejected
  if (!s.ok) return j({ ok: false, error: s.reason }, 422);
  const cs = await verifyConsent(obs); // record-privacy-v1; present-but-invalid is rejected
  if (!cs.ok) return j({ ok: false, error: cs.reason }, 422);
  const eid = obs.evidence_id;
  const seen = (await env.LEDGER.get(OBS_KEY(eid))) || (await env.LEDGER.get(COMMIT_KEY(eid)));
  if (!seen) {
    const cap = await taskCapHit(request, env);
    if (cap) return j({ ok: false, ...cap, note: "new observations per UTC day; try tomorrow" }, 429);
    await taskCapCount(request, env);
  }
  const basis = publicationBasis(obs, cs.parties);
  if (!basis.from || !basis.to) {
    // Commitment only. Never downgrade an observation that is already public.
    if (await env.LEDGER.get(OBS_KEY(eid))) return j({ ok: true, stored: "public", already: true, evidence_id: eid, note: "this observation was already published with both parties' consent; nothing changed" });
    const missing = [basis.from ? null : "hop.from", basis.to ? null : "hop.to"].filter(Boolean);
    if (!(await env.LEDGER.get(COMMIT_KEY(eid)))) await env.LEDGER.put(COMMIT_KEY(eid), JSON.stringify({ evidence_id: eid, received_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z") }));
    if (!(await env.LEDGER.get(ANCHORED_KEY(eid))) && !(await env.LEDGER.get(PENDING_KEY(eid)))) await env.LEDGER.put(PENDING_KEY(eid), canonical({ evidence_id: eid, commitment: true }));
    return j({
      ok: true, stored: "commitment", evidence_id: eid,
      consent_missing_from: missing.length === 2 ? "both parties" : missing[0],
      why: "record-privacy-v1: a task observation names two parties and what one did for the other, so it is published only when each party is a public surface (an https origin) or signed consent. Until then the ledger keeps the evidence_id and the receipt time, anchored daily, and nothing else",
      how_to_publish: "each party signs canonical({purpose: \"" + CONSENT_PURPOSE + "\", task_id, hop, publication: \"public\"}) with its did:key; POST the same observation with consent: [{party, sig}, {party, sig}]. evidence_id and witness_sig do not change",
      policy: "https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/workers/hs-verify-gate/ext/RECORD_PRIVACY_v1.md",
    });
  }
  await env.LEDGER.put(OBS_KEY(eid), canonical(obs));
  await env.LEDGER.put(IDX_KEY(obs.task_id, obs.hop.seq, obs.witness_id), eid);
  // enqueue for the daily Bitcoin anchor batch, unless this evidence is already in an anchored batch
  if (!(await env.LEDGER.get(ANCHORED_KEY(eid)))) await env.LEDGER.put(PENDING_KEY(eid), canonical(obs));
  return j({
    ok: true, stored: "public", publication_basis: basis, task_id: obs.task_id, hop_seq: obs.hop.seq, witness_id: obs.witness_id,
    evidence_id: eid, witness_sig: typeof obs.witness_sig === "string", edge_sig: typeof obs.edge_sig === "string",
  });
}

export async function handleTaskWitnessGet(url, env) {
  const tid = url.searchParams.get("task_id");
  if (!tid) return j({ ok: false, error: "task_id_required" }, 400);
  const hopFilter = url.searchParams.get("hop");

  const listed = await env.LEDGER.list({ prefix: IDX_PREFIX(tid) });
  const seen = new Set();
  const obs = [];
  for (const entry of (listed.keys || [])) {
    const eid = await env.LEDGER.get(entry.name);
    if (!eid || seen.has(eid)) continue;
    seen.add(eid);
    const raw = await env.LEDGER.get(OBS_KEY(eid));
    if (!raw) continue;
    let o;
    try { o = JSON.parse(raw); } catch { continue; }
    obs.push(o);
  }

  const byHop = {};
  for (const o of obs) (byHop[o.hop.seq] = byHop[o.hop.seq] || []).push(o);
  let hops = Object.keys(byHop).map(Number).sort((a, b) => a - b).map((seq) => ({
    hop_seq: seq,
    from: byHop[seq][0].hop.from,
    to: byHop[seq][0].hop.to,
    witnesses: byHop[seq].length,
    signed_witnesses: byHop[seq].filter((o) => typeof o.witness_sig === "string").length,
    edge_attested: byHop[seq].some((o) => typeof o.edge_sig === "string"),
    verdict: aggregateVerdict(byHop[seq]),
    evidence_ids: byHop[seq].map((o) => o.evidence_id).sort(),
  }));

  const repr = hops.map((h) => byHop[h.hop_seq][0]);
  const chain = await chainContinuous(repr);

  if (hopFilter !== null) hops = hops.filter((h) => h.hop_seq === Number(hopFilter));

  return j({
    ok: true,
    task_id: tid,
    hops_observed: hops.length,
    chain_continuous: chain.ok,
    chain_reason: chain.ok ? undefined : chain.reason,
    hops,
    honest: "verdict per hop aggregates the FULL witness set; disagreement is preserved, never the favorable one. Signatures prove who asserted and linkage (attributable, non-repudiable), not that the assertion is true.",
    recompute: "evidence_id = sha256(canonical(observation minus derived fields)). witness_sig is Ed25519 over the same canonical preimage; the key is inside witness_id (did:key). Recompute and verify yourself.",
    anchoring: "each observation is enqueued on receipt and bundled daily into a nenrin-task-witness-batch-v1 ledger entry anchored to Bitcoin via OpenTimestamps; find the batch listing an evidence_id and GET /ledger/{n} for its bytes and OTS proof.",
    aligns_to: "A2A Task id (a2a.task.id); A2A issues #1769, #2103",
  });
}

// ---- task-bound trust signal (additive read surface) ----
// The same content as GET /witness/task, shaped as a consumable signal: counts and verdicts only, never a
// score; adverse hops are named, never hidden; disclosure (issuer_is_party) and recompute travel with it.
async function collectTaskObservations(env, tid) {
  const listed = await env.LEDGER.list({ prefix: IDX_PREFIX(tid) });
  const seen = new Set();
  const obs = [];
  for (const entry of (listed.keys || [])) {
    const eid = await env.LEDGER.get(entry.name);
    if (!eid || seen.has(eid)) continue;
    seen.add(eid);
    const raw = await env.LEDGER.get(OBS_KEY(eid));
    if (!raw) continue;
    let o; try { o = JSON.parse(raw); } catch { continue; }
    obs.push(o);
  }
  return obs;
}

// GET /trust-signal?task_id=<id> : task-bound conduct signal. Returns null for any other shape so the
// existing endpoint-keyed /trust-signal handler is reached untouched.
export async function handleTaskTrustSignal(p, request, url, env) {
  if (p !== "/trust-signal" || request.method !== "GET") return null;
  const tid = url.searchParams.get("task_id");
  if (!tid) return null;

  const obs = await collectTaskObservations(env, tid);
  const byHop = {};
  for (const o of obs) (byHop[o.hop.seq] = byHop[o.hop.seq] || []).push(o);
  const seqs = Object.keys(byHop).map(Number).sort((a, b) => a - b);
  const delegation = seqs.map((seq) => {
    const set = byHop[seq];
    const signed = set.filter((o) => typeof o.witness_sig === "string").length;
    return {
      hop_seq: seq,
      from: set[0].hop.from,
      to: set[0].hop.to,
      verdict: aggregateVerdict(set),
      witnesses: set.length,
      signed_witnesses: signed,
      edge_attested: set.some((o) => typeof o.edge_sig === "string"),
      attributable: signed > 0,
      witness_distinct_from_parties: true,
      evidence_ids: set.map((o) => o.evidence_id).sort(),
    };
  });
  const repr = seqs.map((seq) => byHop[seq][0]);
  const chain = await chainContinuous(repr);
  const adverse_hops = delegation.filter((h) => h.verdict === "FAIL" || h.verdict === "disagreement").map((h) => h.hop_seq);
  const as_of = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const issuer = url.origin.replace(/\/$/, "");

  return j({
    ok: true,
    signal: "task-conduct-trust-signal-v0",
    task_id: tid,
    as_of,
    issuer,
    issuer_is_party: false,
    hops_observed: delegation.length,
    chain_continuous: chain.ok,
    chain_reason: chain.ok ? undefined : chain.reason,
    delegation,
    adverse_hops,
    independence: "witness_distinct_from_parties attests R1 by key (witness_id equals neither hop party). It does NOT attest operator-independence: a self-witness, where one operator holds both a hop key and the witness key, still satisfies R1. Whether the witness is a genuine third party is judged from its did:key identity, not from this field.",
    honest: "verdict per hop aggregates the FULL witness set; disagreement is preserved, never the favorable one. Signatures prove who asserted and the delegation edge, not that the assertion is true.",
    recompute: "GET " + issuer + "/witness/task?task_id=" + encodeURIComponent(tid) + " for the full observation set; evidence_id = sha256(canonical(obs minus derived fields)); witness_sig/edge_sig are Ed25519 over the canonical preimage and canonical({task_id,hop}), the key is inside the did:key. Recompute and verify yourself.",
    not_a_score: "counts and verdicts only; this signal never emits a numeric trustworthiness score.",
    anchoring: "each observation is bundled daily into a nenrin-task-witness-batch-v1 ledger entry anchored to Bitcoin (OpenTimestamps); verify via GET /ledger/{n} for the batch listing the evidence_id.",
    aligns_to: "A2A Task id (a2a.task.id); A2A issues #1769, #2103",
  });
}

// GET /witness/task/evidence/<evidence_id> : one task observation with its anchor status, for a consumer
// (e.g. the agreement intake) that pins a specific evidence_id and must confirm it is real, attributable, and
// whether it sits in a Bitcoin-anchored batch. Read-only; recompute the evidence_id and the batch hash yourself.
// 404 when no observation with this id exists (a pin that names no stored evidence is a claim, not evidence).
export async function handleTaskEvidence(p, request, url, env) {
  const PFX = "/witness/task/evidence/";
  if (!p.startsWith(PFX) || request.method !== "GET") return null;
  const eid = p.slice(PFX.length).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(eid)) return j({ ok: false, error: "evidence_id_must_be_64_hex" }, 400);
  const obsRaw = await env.LEDGER.get(OBS_KEY(eid));
  const anchRaw = await env.LEDGER.get(ANCHORED_KEY(eid));
  const pendRaw = await env.LEDGER.get(PENDING_KEY(eid));
  let obs = null;
  if (obsRaw) { try { obs = JSON.parse(obsRaw); } catch (e) {} }
  let anchored = null, bitcoin = null;
  if (anchRaw) {
    try { const a = JSON.parse(anchRaw); if (typeof a.n === "number") anchored = { ledger_entry: a.n }; if (!obs && a.obs) obs = a.obs; } catch (e) {}
    if (anchored) {
      try {
        const eRaw = await env.LEDGER.get("entry:" + anchored.ledger_entry);
        if (eRaw) { const e = JSON.parse(eRaw); bitcoin = { ots_status: e.ots_status || null, block: e.bitcoin_block != null ? e.bitcoin_block : null, block_time: e.block_time || null, batch_sha256: e.claim_sha256 || null }; }
      } catch (e) {}
    }
  }
  if (!obs) {
    const commitRaw = await env.LEDGER.get(COMMIT_KEY(eid));
    if (commitRaw || anchored || pendRaw) {
      let c = null; try { c = commitRaw ? JSON.parse(commitRaw) : null; } catch (e) {}
      return j({
        ok: true, evidence_id: eid, commitment_only: true, recompute_ok: null,
        received_at: c && c.received_at || null,
        status: anchored ? "anchored" : (pendRaw ? "pending" : "stored"), anchored, bitcoin,
        note: "record-privacy-v1: the ledger holds a commitment to this observation, not its content, because both parties have not consented to publication. It proves an observation with this evidence_id existed by the anchor time; whoever holds the bytes can show they hash to it",
      });
    }
    return j({ ok: false, error: "not_found", evidence_id: eid, note: "no task observation with this evidence_id; a pin that names no stored evidence is a claim, not an observation" }, 404);
  }
  const recomputed = await evidenceId(obs);
  return j({
    ok: true,
    evidence_id: eid,
    recompute_ok: recomputed === eid,
    task_id: obs.task_id,
    hop_seq: obs.hop.seq,
    hop: obs.hop,
    witness_id: obs.witness_id,
    verdict: obs.conduct && obs.conduct.verdict,
    witness_sig: typeof obs.witness_sig === "string",
    edge_sig: typeof obs.edge_sig === "string",
    status: anchored ? "anchored" : (pendRaw ? "pending" : "stored"),
    anchored,
    bitcoin,
    recompute: "evidence_id = sha256(canonical(observation minus derived fields)); witness_sig/edge_sig are Ed25519, the key is inside the did:key. When anchored, GET /ledger/{anchored.ledger_entry} for the batch bytes and OTS proof.",
  });
}

// Daily Bitcoin anchor for task observations, mirroring the ledger's anchorWitnessPool. Bundles the pending
// pool into a nenrin-task-witness-batch-v1 ledger entry whose hash fixes the existence time of every
// observation listed (the Bitcoin stamp follows on the operator's stamping run), then moves each to
// nenrin:tw:anchored:<evidence_id>. The observation bytes stay served by GET /witness/task.
export async function anchorTaskWitnessPool(env, origin, trigger) {
  const listed = await env.LEDGER.list({ prefix: PENDING_PREFIX });
  const keys = (listed.keys || []).slice(0, TASK_BATCH_MAX);
  if (!keys.length) return { status: 200, body: { ok: true, anchored: 0, note: "task witness pool is empty" } };
  const items = [];
  for (const k of keys) {
    const raw = await env.LEDGER.get(k.name);
    if (!raw) continue;
    let o; try { o = JSON.parse(raw); } catch { continue; }
    if (o && o.evidence_id) items.push(o);
  }
  items.sort((a, b) => (a.evidence_id < b.evidence_id ? -1 : 1));
  const batch = {
    schema: "nenrin-task-witness-batch-v1",
    anchored_at: new Date().toISOString(),
    count: items.length,
    records: items.map((o) => (o.commitment === true ? { evidence_id: o.evidence_id, commitment: true } : {
      evidence_id: o.evidence_id, task_id: o.task_id, hop_seq: o.hop.seq, witness_id: o.witness_id,
      verdict: o.conduct.verdict, witness_sig: typeof o.witness_sig === "string", edge_sig: typeof o.edge_sig === "string",
    })),
  };
  const batchCanonical = JSON.stringify(batch);
  const h = (await sha256hex(batchCanonical)).toLowerCase();
  const dup = await env.LEDGER.get("hash:" + h);
  if (dup) return { status: 200, body: { n: Number(dup), url: origin + "/ledger/" + dup, dedup: true } };
  const entry = { n: 0, work: "NENRIN task-witness batch (" + items.length + " records)", claim_sha256: h, record_canonical: batchCanonical, schema: "v0-plain", created_at: new Date().toISOString(), ots_status: "unstamped", bitcoin_block: null, block_time: null, stamped_at: null, anchored_by: trigger };
  const ap = await appendEntry(env, h, entry);   // 2026-10-13 (concurrency audit L1): the sequencer assigns n
  if (ap.dedup) return { status: 200, body: { n: ap.n, url: origin + "/ledger/" + ap.n, dedup: true } };
  const n = ap.n;
  for (const o of items) {
    await env.LEDGER.put(ANCHORED_KEY(o.evidence_id), JSON.stringify(o.commitment === true ? { n, obs: null, commitment: true } : { n, obs: o }));
    await env.LEDGER.delete(PENDING_KEY(o.evidence_id));
  }
  return { status: 201, body: { n, url: origin + "/ledger/" + n, anchored: items.length, trigger, note: "the batch anchor fixes the existence time of every task observation listed; the Bitcoin stamp follows on the operator stamping run" } };
}

// Additive dispatcher for the ledger worker. Returns null when the path is not ours (no interference).
export async function handleTaskWitness(p, request, url, env) {
  if (p !== "/witness/task") return null;
  try {
    if (request.method === "POST") return await handleTaskWitnessPost(request, env);
    if (request.method === "GET") return await handleTaskWitnessGet(url, env);
    return j({ ok: false, error: "method_not_allowed" }, 405);
  } catch (e) {
    // Additive module must never crash the shared ledger worker: handle() has no outer try/catch, so an
    // internal throw here would surface as a Cloudflare 1101 (non-JSON). Convert it to a clean JSON 500
    // that also reports the cause, so a client sees a diagnosable error instead of a dead worker.
    return j({ ok: false, error: "task_witness_internal", detail: String((e && e.message) || e).slice(0, 200) }, 500);
  }
}
