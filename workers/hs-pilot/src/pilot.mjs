// hs-pilot: the responder side of horizon-shield Issue #51, a metered call of HORIZON SHIELD's estimate audit.
//
// What it is. One priced service for the pilot on ourselves: the caller sends a request occurrence, the task the
// occurrence commits to, the fixture (a quote, line by line) and its payer-signed payment receipt. The worker
// checks that they name each other, audits every line of the quote through the public MCP server's
// audit_estimate (free, the same function homeowners use), hashes the assembled audit, and returns an execution
// receipt of the MUSUBI companion profile (musubi.ca2a.execution-receipt.v0) signed with the responder key, with
// the block it had seen at that moment. The payment rail is not settled here: the payment receipt is checked
// for shape, binding and price, and carried by digest; the rail's own confirmation is the rail's job.
//
// What it does not do. It does not log anything: the caller logs the use, the payment and the receipt with the
// log operator, which is a separate role. It does not refund, and it does not decide the budget: the issuer's
// budget is judged afterwards by pilot_v0.py.
//
// State. One KV namespace (binding STATE) holds, per request occurrence, the receipt the worker signed for it
// and, for an occurrence the caller voided before any execution, the signed non-execution statement. With it
// the worker answers the same occurrence once: a second /call for an executed occurrence returns the stored
// receipt and audit (nothing is audited or signed again), and a /call for a voided occurrence is refused. The
// statement exists for the case of a lost call (Issue #51, aeoess): a caller whose call got no answer asks
// the worker whether that occurrence ran; the worker either returns the receipt it had already signed, or signs
// that it did not run and will not, so the payer's hold can be released and a new occurrence id used instead.
//
// The race between /call and /void (Issue #51, aeoess, 2026-10-21). Before this change handleCall checked void:
// and rcpt: before the slow audit and never again, and handleVoid checked only rcpt:, so a /void that arrived while
// a /call was auditing signed not_executed and the call then finished and issued a receipt for the same
// occurrence. Two layers close it.
//   1. In the handlers, whatever the store: a /call writes an in-flight marker (run:<request_sha256>, with its
//      start time and a run id) before the audit, and right before signing it rechecks that it is still within
//      RUN_SIGN_BY_MS of its start, that no void exists, that no other receipt exists, and that the marker is still
//      its own; otherwise it refuses and signs nothing. A /void reads the marker, then the receipt, then the void,
//      and signs not_executed only when there is no receipt and no live marker; while a live marker exists it
//      answers {status: "in_progress"}, unsigned, and voids nothing. A marker older than RUN_STALE_MS is from a call
//      that can no longer sign (it would refuse call_expired), so it no longer blocks a void. On KV the marker also
//      carries expirationTtl RUN_TTL_S so a crashed call's marker is removed.
//   2. Atomicity: with the OCCURRENCE binding (a SQLite-backed Durable Object, class Occurrence, one object per
//      request_sha256) the worker forwards /call and /void to that object, which runs them one at a time under
//      state.blockConcurrencyWhile, with its own transactional storage as the authority for rcpt:, void: and run:.
//      A /void sent during a /call for the same occurrence waits for it and answers executed. Answers recorded in
//      KV before this change (the receipts of the earlier run) are still read from STATE when the object has none,
//      and rcpt: and void: are still written to STATE first, so existing readers keep working.
// Without the OCCURRENCE binding only layer 1 applies: KV is eventually consistent across locations (up to about
// a minute), so two places can still race inside that window. Without STATE the worker keeps no state and refuses
// /void with no_state.
//
// Routes
//   GET  /.well-known/pilot.json   the responder key, the price, the unit, the fixture digest, the profile
//   POST /call                     {request, task, fixture, payment} -> {receipt, audit, request_sha256}
//   POST /void                     {request, void} -> {status: "executed", receipt, audit} or
//                                  {status: "not_executed", statement} or
//                                  {status: "in_progress", request_sha256, retry_after_s} (unsigned, voids nothing);
//                                  void is a caller-signed musubi.ca2a.void-request.v0 naming the occurrence by digest
//
// Secrets, vars and bindings (wrangler): RESPONDER_SEED (32-byte hex Ed25519 seed; TOshi sets it), PRICE, UNIT,
//   MCP_URL (default https://mcp.horizonshield.dev/mcp), BLOCKS_URL (default https://mempool.space/api),
//   STATE (KV namespace), OCCURRENCE (Durable Object namespace, class Occurrence).

const enc = new TextEncoder();
const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;
const TEXT = /^[\x21-\x7e]{1,128}$/;
const SAFE = Number.MAX_SAFE_INTEGER;
const T_REQUEST = "musubi.ca2a.request.v0";
const T_TASK = "musubi.ca2a.task.v0";
const T_PAYMENT = "musubi.ca2a.payment-receipt.v0";
const T_RECEIPT = "musubi.ca2a.execution-receipt.v0";
const T_VOID = "musubi.ca2a.void-request.v0";
const T_NONEXEC = "musubi.ca2a.non-execution.v0";
const T_FIXTURE = "horizon-shield.estimate-fixture.v0";
const SERVICE = "estimate-audit";
const T_RUN = "hs-pilot.in-flight.v0";
// A call that has not reached signing RUN_SIGN_BY_MS after it started refuses call_expired and signs nothing. It is
// under the 30 s a Durable Object allows inside blockConcurrencyWhile, so the handler refuses before the platform
// resets the object. A marker older than RUN_STALE_MS belongs to a call that can no longer sign, so it no longer
// blocks a /void (the margin between the two covers the receipt's write and clock skew between machines).
// RUN_TTL_S is the marker's KV expirationTtl (KV's minimum is 60), longer than RUN_STALE_MS so a live marker never
// expires first. (Not exported as constants: every export of a Worker's main module must be a function or a
// handler, so the tests read them through runTimings().)
const RUN_SIGN_BY_MS = 25000;
const RUN_STALE_MS = 60000;
const RUN_TTL_S = 120;
export function runTimings() { return { RUN_SIGN_BY_MS, RUN_STALE_MS, RUN_TTL_S }; }
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

export class Refusal extends Error {
  constructor(code, detail) { super(code + (detail ? ": " + detail : "")); this.code = code; this.detail = detail || ""; }
}

// ---- RFC 8785 (the profile's data model has no floats; a non-integer number is refused)
export function jcs(v, depth = 0, path = "$") {
  if (depth > 64) throw new Refusal("too_deep", path);
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > SAFE) throw new Refusal("number_not_in_profile", path);
    return JSON.stringify(v);
  }
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new Refusal("lone_surrogate", path);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map((x, i) => jcs(x, depth + 1, path + "[" + i + "]")).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => {
      if (LONE_SURROGATE.test(k)) throw new Refusal("lone_surrogate", path);
      return JSON.stringify(k) + ":" + jcs(v[k], depth + 1, path + "." + k);
    }).join(",") + "}";
  }
  throw new Refusal("not_json", path);
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
export async function sha256hex(s) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(s))); }

async function importPublic(hexKey) {
  return crypto.subtle.importKey("raw", unhex(hexKey), { name: "Ed25519" }, true, ["verify"]);
}
async function importPrivate(seedHex) {
  // PKCS#8 wrapper for an Ed25519 seed: fixed 16-byte prefix (RFC 8410) then the 32-byte seed
  const prefix = unhex("302e020100300506032b657004220420");
  const pkcs8 = new Uint8Array(prefix.length + 32);
  pkcs8.set(prefix); pkcs8.set(unhex(seedHex), prefix.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
}
export async function publicKeyHex(seedHex) {
  const priv = await importPrivate(seedHex);
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
  return hex(Uint8Array.from(atob(b64 + "=".repeat((4 - b64.length % 4) % 4)), (c) => c.charCodeAt(0)));
}
export async function sign(obj, seedHex) {
  const body = {}; for (const k of Object.keys(obj)) if (k !== "signature" && k !== "anchor") body[k] = obj[k];
  const key = await importPrivate(seedHex);
  body.signature = hex(await crypto.subtle.sign({ name: "Ed25519" }, key, enc.encode(jcs(body))));
  return body;
}
export async function verify(obj, keyField) {
  const body = {}; for (const k of Object.keys(obj)) if (k !== "signature" && k !== "anchor") body[k] = obj[k];
  if (!HEX32.test(obj[keyField] || "") || !HEX64.test(obj.signature || "")) return false;
  try {
    const key = await importPublic(obj[keyField]);
    return crypto.subtle.verify({ name: "Ed25519" }, key, unhex(obj.signature), enc.encode(jcs(body)));
  } catch (_e) { return false; }
}

// ---- shapes (the same exact field sets as companion_v0 / pilot_v0)
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
function fields(obj, required, optional, what) {
  if (!isObj(obj)) throw new Refusal("not_an_object", what);
  const keys = Object.keys(obj);
  const missing = required.filter((k) => !keys.includes(k));
  const unknown = keys.filter((k) => !required.includes(k) && !optional.includes(k));
  if (missing.length || unknown.length) throw new Refusal("fields", what + " missing=" + missing.join(",") + " unknown=" + unknown.join(","));
}
const nonneg = (v) => Number.isInteger(v) && v >= 0 && v <= SAFE;

export async function checkTask(task) {
  fields(task, ["type", "service", "amount", "unit", "nonce"], [], "task");
  if (task.type !== T_TASK) throw new Refusal("wrong_type", "task");
  if (!TEXT.test(task.service) || !nonneg(task.amount) || !TEXT.test(task.unit) || !HEX32.test(task.nonce)) throw new Refusal("bad_task");
  return sha256hex(jcs(task));
}
export async function checkRequest(req) {
  fields(req, ["type", "caller", "responder", "lineage", "capability", "occurrence_id", "task_sha256"], ["session_id"], "request");
  if (req.type !== T_REQUEST) throw new Refusal("wrong_type", "request");
  if (!HEX32.test(req.caller) || !HEX32.test(req.responder)) throw new Refusal("bad_key", "request");
  if (!Array.isArray(req.lineage) || req.lineage.length < 1 || req.lineage.length > 64 || !req.lineage.every((d) => /^sha256:[0-9a-f]{64}$/.test(d))) throw new Refusal("bad_lineage");
  if (!TEXT.test(req.capability) || !TEXT.test(req.occurrence_id) || !HEX32.test(req.task_sha256)) throw new Refusal("bad_request");
  return sha256hex(jcs(req));
}
export function checkFixture(fx) {
  fields(fx, ["type", "lines"], [], "fixture");
  if (fx.type !== T_FIXTURE) throw new Refusal("wrong_type", "fixture");
  if (!Array.isArray(fx.lines) || fx.lines.length < 1 || fx.lines.length > 64) throw new Refusal("bad_fixture", "1 to 64 lines");
  for (const l of fx.lines) {
    fields(l, ["item", "qty", "unit", "unit_price"], [], "line");
    if (typeof l.item !== "string" || !l.item || l.item.length > 128 || !nonneg(l.qty) || typeof l.unit !== "string" || !nonneg(l.unit_price)) throw new Refusal("bad_line");
  }
}
export async function checkPayment(p, { requestSha, task, responder }) {
  fields(p, ["type", "payer", "payee", "lineage", "request_sha256", "amount", "unit", "seen_block", "rail", "signature"], [], "payment");
  if (p.type !== T_PAYMENT) throw new Refusal("wrong_type", "payment");
  if (!(await verify(p, "payer"))) throw new Refusal("payment_signature_invalid");
  if (p.request_sha256 !== requestSha) throw new Refusal("payment_not_for_this_request");
  if (p.payee !== responder) throw new Refusal("payment_not_to_this_responder");
  if (p.amount !== task.amount || p.unit !== task.unit) throw new Refusal("payment_not_for_task", p.amount + " " + p.unit);
  fields(p.rail, ["kind", "receipt_sha256"], [], "rail");
  if (!TEXT.test(p.rail.kind) || (p.rail.receipt_sha256 !== null && !HEX32.test(p.rail.receipt_sha256))) throw new Refusal("bad_rail");
  fields(p.seen_block, ["height", "hash"], [], "seen_block");
  if (!nonneg(p.seen_block.height) || !HEX32.test(p.seen_block.hash)) throw new Refusal("bad_seen_block", "payment");
}

// ---- the audit: every line through the public MCP server, assembled deterministically
export async function auditFixture(fx, region, mcpUrl, fetchFn) {
  const lines = [];
  for (let i = 0; i < fx.lines.length; i++) {
    const l = fx.lines[i];
    const body = { jsonrpc: "2.0", id: i + 1, method: "tools/call",
      params: { name: "audit_estimate", arguments: region === null ? { work: l.item, quoted_price: l.unit_price }
        : { work: l.item, quoted_price: l.unit_price, region } } };
    const res = await fetchFn(mcpUrl, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(body) });
    if (!res.ok) throw new Refusal("audit_unavailable", "mcp " + res.status);
    const j = await res.json();
    const sc = j && j.result && j.result.structuredContent;
    if (!isObj(sc)) throw new Refusal("audit_unavailable", "no structuredContent for line " + i);
    // keep only the fields that are a function of the dataset version and the inputs. A line the dataset
    // cannot match on one work item (ambiguous or unknown) has no reference: finding "unmatched"
    const fr = isObj(sc.fair_range) && [sc.fair_range.min, sc.fair_range.avg, sc.fair_range.max].every(nonneg) ? sc.fair_range : null;
    const claim = isObj(sc.claim) ? sc.claim : {};
    const amount = l.qty * l.unit_price;
    let finding = "unmatched";
    if (fr) finding = l.unit_price > fr.max ? "above" : l.unit_price < fr.min ? "below" : "within";
    lines.push({ item: l.item, qty: l.qty, unit: l.unit, unit_price: l.unit_price, amount,
      matched_work: fr && typeof sc.work === "string" ? sc.work : null,
      fair_range: fr ? { min: fr.min, avg: fr.avg, max: fr.max } : null,
      reference_amount: fr ? l.qty * fr.avg : null,
      finding,
      verdict: fr && typeof sc.verdict === "string" ? sc.verdict : null,
      level: fr && typeof sc.level === "string" ? sc.level : null,
      unit_mismatch: sc.unit_mismatch === true,
      data_version: isObj(sc.provenance) && typeof sc.provenance.data_version === "string" ? sc.provenance.data_version : null,
      dataset_sha256: HEX32.test(claim.dataset_sha256) ? claim.dataset_sha256 : null,
      ruleset: isObj(claim.ruleset) && typeof claim.ruleset.id === "string" && typeof claim.ruleset.version === "string"
        ? { id: claim.ruleset.id, version: claim.ruleset.version } : null });
  }
  const total = fx.lines.reduce((a, l) => a + l.qty * l.unit_price, 0);
  const reference_total = lines.every((x) => x.reference_amount !== null) ? lines.reduce((a, x) => a + x.reference_amount, 0) : null;
  return { type: "horizon-shield.estimate-audit.v0", fixture_sha256: await sha256hex(jcs(fx)), region, lines, total, reference_total };
}

export async function seenBlock(blocksUrl, fetchFn) {
  const h = await (await fetchFn(blocksUrl + "/blocks/tip/height")).text();
  const height = parseInt(h, 10);
  const hash = (await (await fetchFn(blocksUrl + "/block-height/" + height)).text()).trim();
  if (!nonneg(height) || !HEX32.test(hash)) throw new Refusal("blocks_unavailable");
  return { height, hash };
}

export async function handleCall(body, env, fetchFn) {
  fields(body, ["request", "task", "fixture", "payment"], ["region"], "call");
  const responder = await publicKeyHex(env.RESPONDER_SEED);
  const taskSha = await checkTask(body.task);
  if (body.task.service !== SERVICE) throw new Refusal("not_this_service", body.task.service);
  if (body.task.amount !== Number(env.PRICE) || body.task.unit !== env.UNIT) throw new Refusal("not_the_price", env.PRICE + " " + env.UNIT);
  const requestSha = await checkRequest(body.request);
  if (body.request.task_sha256 !== taskSha) throw new Refusal("request_does_not_commit_to_task");
  if (body.request.responder !== responder) throw new Refusal("request_names_another_responder");
  checkFixture(body.fixture);
  await checkPayment(body.payment, { requestSha, task: body.task, responder });
  if (body.payment.payer !== body.request.caller) throw new Refusal("payment_not_by_caller");
  const region = typeof body.region === "string" && body.region.length <= 32 ? body.region : null;
  const execute = async () => {
    const audit = await auditFixture(body.fixture, region, env.MCP_URL || "https://mcp.horizonshield.dev/mcp", fetchFn);
    const seen = await seenBlock(env.BLOCKS_URL || "https://mempool.space/api", fetchFn);
    return { audit, seen };
  };
  const signReceipt = async ({ audit, seen }) => {
    const receipt = await sign({ type: T_RECEIPT, responder, caller: body.request.caller, lineage: body.request.lineage,
      capability: body.request.capability, request_sha256: requestSha, seen_block: seen,
      outcome: { kind: "result", stage: "audited", response_sha256: await sha256hex(jcs(audit)) },
      attestation_sha256: null }, env.RESPONDER_SEED);
    return { request_sha256: requestSha, receipt, audit };
  };
  if (!env.STATE) return signReceipt(await execute());
  // one answer per occurrence: a voided occurrence is never executed; an executed one is answered from state
  const S = env.STATE;
  if (await S.get("void:" + requestSha)) throw new Refusal("request_voided", requestSha);
  const prior = await S.get("rcpt:" + requestSha, "json");
  if (prior) return { ...prior, replay: true };
  const started = nowMs(env);
  const running = await S.get("run:" + requestSha, "json");
  if (runIsLive(running, started)) throw new Refusal("in_progress", "another call for this occurrence is running; ask again");
  // the in-flight marker: written before the slow work, so a /void sent meanwhile does not sign not_executed
  const run = { type: T_RUN, request_sha256: requestSha, run_id: hex(crypto.getRandomValues(new Uint8Array(16))), started_at_ms: started };
  await S.put("run:" + requestSha, JSON.stringify(run), { expirationTtl: RUN_TTL_S });
  try {
    const done = await execute();
    // the recheck, right before signing: nothing below awaits anything slow
    const age = nowMs(env) - started;
    if (!(age >= 0 && age < RUN_SIGN_BY_MS)) throw new Refusal("call_expired", "the audit took " + age + " ms; no receipt was signed; ask /void, then use a new occurrence");
    if (await S.get("void:" + requestSha)) throw new Refusal("request_voided", requestSha);
    const raced = await S.get("rcpt:" + requestSha, "json");
    if (raced) return { ...raced, replay: true };
    const mine = await S.get("run:" + requestSha, "json");
    if (!isObj(mine) || mine.run_id !== run.run_id) throw new Refusal("in_progress", "this call's in-flight marker was replaced; no receipt was signed; ask again");
    const out = await signReceipt(done);
    await S.put("rcpt:" + requestSha, JSON.stringify(out));
    return out;
  } finally {
    // the marker goes only after the receipt is stored (or nothing was signed), and only if it is still this call's.
    // A store with no delete (an in-memory KV of a self-test) gets JSON null, which reads as no marker.
    const cur = await S.get("run:" + requestSha, "json");
    if (isObj(cur) && cur.run_id === run.run_id) {
      if (typeof S.delete === "function") await S.delete("run:" + requestSha);
      else await S.put("run:" + requestSha, "null");
    }
  }
}

const nowMs = (env) => (typeof env.CLOCK === "function" ? env.CLOCK() : Date.now());   // env.CLOCK: tests only
// live: written by a call that may still sign or store its receipt. A marker without a start time, or with one
// RUN_STALE_MS or more away from now in either direction, is not live.
function runIsLive(run, now) {
  if (!isObj(run) || !Number.isFinite(run.started_at_ms)) return false;
  const age = now - run.started_at_ms;
  return age > -RUN_STALE_MS && age < RUN_STALE_MS;
}

// ---- the lost call: did this occurrence run? Answered from state, signed by the responder when it did not.
//
// The caller (the request's caller key) signs a void request naming the occurrence by digest. If the worker holds
// a receipt for that occurrence, the call ran: the receipt and audit are returned and nothing is voided. Otherwise
// the worker signs a non-execution statement and stores it: this responder has issued no execution receipt for
// request_sha256 as of seen_block, and will issue none (every later /call for it is refused request_voided). The statement carries the digest of the void request it answers. Asking twice returns the same
// stored statement. Only the caller can void, so no third party can block an occurrence it does not own.
export async function handleVoid(body, env, fetchFn) {
  fields(body, ["request", "void"], [], "void-call");
  const responder = await publicKeyHex(env.RESPONDER_SEED);
  const requestSha = await checkRequest(body.request);
  if (body.request.responder !== responder) throw new Refusal("request_names_another_responder");
  const v = body.void;
  fields(v, ["type", "caller", "request_sha256", "signature"], [], "void");
  if (v.type !== T_VOID) throw new Refusal("wrong_type", "void");
  if (v.caller !== body.request.caller) throw new Refusal("void_not_by_caller");
  if (v.request_sha256 !== requestSha) throw new Refusal("void_not_for_this_request");
  if (!(await verify(v, "caller"))) throw new Refusal("void_signature_invalid");
  if (!env.STATE) throw new Refusal("no_state", "this deployment keeps no state and cannot say whether an occurrence ran");
  const S = env.STATE;
  // What is already settled for this occurrence. The marker is read before the receipt: a call removes its marker
  // only after its receipt is stored, so "no live marker, then no receipt" cannot miss a call that signed.
  const settled = async () => {
    const running = await S.get("run:" + requestSha, "json");
    const prior = await S.get("rcpt:" + requestSha, "json");
    if (prior) return { status: "executed", ...prior };
    const stored = await S.get("void:" + requestSha, "json");
    if (stored) return { status: "not_executed", request_sha256: requestSha, statement: stored };
    const now = nowMs(env);
    if (runIsLive(running, now)) {
      return { status: "in_progress", request_sha256: requestSha,
        retry_after_s: Math.max(1, Math.ceil((RUN_STALE_MS - (now - running.started_at_ms)) / 1000)) };
    }
    return null;
  };
  const first = await settled();
  if (first) return first;
  const seen = await seenBlock(env.BLOCKS_URL || "https://mempool.space/api", fetchFn);
  const again = await settled();          // again after the block fetch, so the check and the write are adjacent
  if (again) return again;
  const statement = await sign({ type: T_NONEXEC, responder, caller: body.request.caller, lineage: body.request.lineage,
    capability: body.request.capability, request_sha256: requestSha, seen_block: seen,
    outcome: { kind: "not_executed" }, void_request_sha256: await sha256hex(jcs(v)) }, env.RESPONDER_SEED);
  await S.put("void:" + requestSha, JSON.stringify(statement));
  return { status: "not_executed", request_sha256: requestSha, statement };
}

// ---- atomicity: one Durable Object per request occurrence (binding OCCURRENCE, class Occurrence, SQLite-backed)
//
// The store the handlers see inside the object. Its own storage is the authority. rcpt: and void: fall back to the
// KV namespace when the object holds nothing (answers recorded before the object existed, such as the receipts of
// the earlier run), and are written to KV first and then to the object, so a write cut half way is still seen
// through that fallback and KV readers keep working. run: lives only in the object (no TTL there; its age decides).
export function occurrenceStore(storage, kv) {
  const local = (k) => k.startsWith("run:") || !kv;
  return {
    async get(k, type) {
      let raw = await storage.get(k);
      if (raw === undefined && !local(k)) {
        const legacy = await kv.get(k);
        if (legacy !== null) raw = legacy;
      }
      if (raw === undefined || raw === null) return null;
      return type === "json" ? JSON.parse(raw) : raw;
    },
    async put(k, v) {
      if (!local(k)) await kv.put(k, v);
      await storage.put(k, v);
    },
    async delete(k) { await storage.delete(k); }    // only run: is ever deleted
  };
}

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });

// One POST /call or /void, answered as a Response. It never throws: inside blockConcurrencyWhile a throw resets the object.
async function answer(path, raw, env, fetchFn) {
  try {
    if (raw.length > 65536) throw new Refusal("too_large");
    let body;
    try { body = JSON.parse(raw); } catch (_e) { throw new Refusal("not_json"); }
    return json(await (path === "/call" ? handleCall : handleVoid)(body, env, fetchFn));
  } catch (e) {
    if (e instanceof Refusal) return json({ refused: e.code, detail: e.detail }, 400);
    return json({ refused: "internal" }, 500);
  }
}

export class Occurrence {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.fetchFn = (u, init) => fetch(u, init);   // the tests replace it with a mock
  }
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method !== "POST" || (path !== "/call" && path !== "/void")) return json({ refused: "no_such_route" }, 404);
    const raw = await request.text();
    const env = { ...this.env, STATE: occurrenceStore(this.state.storage, this.env.STATE) };
    // one request at a time for this occurrence, from the first read to the last write, including the audit
    return this.state.blockConcurrencyWhile(() => answer(path, raw, env, this.fetchFn));
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/.well-known/pilot.json") {
        return json({ profile: "musubi.ca2a.pilot.v0", service: SERVICE, responder: await publicKeyHex(env.RESPONDER_SEED),
          price: Number(env.PRICE), unit: env.UNIT, issue: "ogasurfproject-jpg/horizon-shield#51",
          state: !env.STATE ? "none" : "one answer per occurrence; POST /void asks whether an occurrence ran"
            + (env.OCCURRENCE ? "; /call and /void for one occurrence run one at a time; not_executed is final" : ""),
          what: "POST /call with {request, task, fixture, payment}; returns the signed execution receipt and the audit. "
            + "POST /void with {request, void}; returns the stored receipt, a signed non-execution statement, "
            + "or in_progress (unsigned) while a call for that occurrence is still running" });
      }
      if (request.method === "POST" && (url.pathname === "/call" || url.pathname === "/void")) {
        const raw = await request.text();
        if (env.OCCURRENCE && raw.length <= 65536) {
          // the request occurrence names the object; a body whose request does not check is answered here, with
          // no state at all, so it is refused exactly as before and touches nothing
          let requestSha = null;
          try {
            const body = JSON.parse(raw);
            requestSha = isObj(body) ? await checkRequest(body.request) : null;
          } catch (e) {
            if (!(e instanceof Refusal) && !(e instanceof SyntaxError)) throw e;
          }
          if (requestSha === null) {
            const { STATE: _s, OCCURRENCE: _o, ...bare } = env;
            return answer(url.pathname, raw, bare, fetch);
          }
          const stub = env.OCCURRENCE.get(env.OCCURRENCE.idFromName(requestSha));
          return stub.fetch("https://occurrence" + url.pathname, { method: "POST", headers: { "content-type": "application/json" }, body: raw });
        }
        return answer(url.pathname, raw, env, fetch);
      }
      return json({ refused: "no_such_route" }, 404);
    } catch (e) {
      if (e instanceof Refusal) return json({ refused: e.code, detail: e.detail }, 400);
      return json({ refused: "internal" }, 500);
    }
  }
};
