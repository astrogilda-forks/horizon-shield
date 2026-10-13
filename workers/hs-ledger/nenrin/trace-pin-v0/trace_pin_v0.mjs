// nenrin-trace-pin-v0 (2026-09-29): pin a TRACE Trust Record to the NENRIN ledger by its sha, so the exact
// bytes outlive TRACE's own 24 hour freshness window and carry a clock the issuer does not hold.
//
// Why this exists. A TRACE Trust Record (agentrust-io/trace-spec v0.2, Linux Foundation) answers "what ran,
// where, under which policy": an Ed25519 signature by the key in cnf.jwk over the RFC 8785 form of the record.
// Its time is iat, which the issuer writes. Spec 3.2.2 has verifiers reject a record older than 24 hours by
// default, so a record that proved something today cannot be checked by a conformant verifier next month, and
// nothing in the record bounds iat from outside. The ledger adds the missing half: it checks the signature at
// intake, keeps the exact bytes, and anchors their sha in the daily batch that is stamped to Bitcoin. After
// that, anyone holding the record can show these bytes existed before a block the issuer could not choose,
// and that a verifier found the signature valid while the record was fresh.
//
// What it is not, stated in every answer: it does not make any claim inside the record true (TRACE says the
// same of its own signature), it does not establish that the key belongs to the subject (the key is the one
// the record carries; compare key_thumbprint with a key you already trust), and it performs no revocation
// check. It reads the embedded-signature form only; enveloped JWS or COSE records are refused by name.
//
// The module is additive and self contained: Web Crypto only (no node: imports, the Worker has no nodejs_compat),
// its own KV prefix tpin:, and one dispatcher that returns null for any path that is not its own.

import { appendEntry } from "../../src/ledger_append.mjs";
export const PIN_SCHEMA = "nenrin-trace-pin-v0";
export const BATCH_SCHEMA = "nenrin-trace-pin-batch-v0";
export const TRACE_PROFILE_V0_2 = "tag:agentrust-io.com,2026:trace-v0.2";
export const TRACE_PROFILE_V0_1 = "tag:agentrust.io,2026:trace-v0.1";
// The ten members the TRACE v0.2 JSON Schema lists as required (schema/trace-v0.2.json in agentrust-trace).
// This ledger checks that they are present and reads the ones it uses; it does not validate the full schema.
export const TRACE_REQUIRED = ["eat_profile", "iat", "subject", "model", "runtime", "policy", "data_class", "build_provenance", "appraisal", "cnf"];
export const MAX_RECORD_BYTES = 65536;
export const FUTURE_SKEW_SECONDS = 300;      // TRACE 3.2.2 default clock-skew tolerance
export const TRACE_MAX_AGE_SECONDS = 86400;  // TRACE 3.2.2 default maximum record age
export const DAILY_GLOBAL = 200;
export const DAILY_PER_NETWORK = 20;
export const BATCH_MAX = 200;
const MAX_DEPTH = 64;
const JCS_SAFE_INTEGER = 9007199254740991;

const PENDING = (sha) => "tpin:pending:" + sha;
const ANCHORED = (sha) => "tpin:anchored:" + sha;
const PENDING_PREFIX = "tpin:pending:";
const enc = new TextEncoder();

export class Refusal extends Error {
  constructor(code, why, status = 422) { super(why); this.code = code; this.status = status; }
}

// ---- RFC 8785 (JCS) -------------------------------------------------------------------------------------
// For the values JSON can carry, ECMAScript's own serializers are the JCS rules: JSON.stringify on a number is
// the ES Number-to-String form RFC 8785 3.2.2.3 names, JSON.stringify on a string escapes exactly what RFC 8259
// requires with lowercase \u00xx, and the default Array sort orders keys by UTF-16 code unit (RFC 8785 3.2.3).
// What JCS has no form for is refused rather than guessed: lone surrogates, non-finite numbers, integers
// outside the safe range (JSON.parse has already rounded them, so any digest would name a different value).
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
export function jcs(v, depth = 0, path = "$") {
  if (depth > MAX_DEPTH) throw new Refusal("too_deep", path + " nests deeper than " + MAX_DEPTH + " levels");
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Refusal("non_finite_number", path + " is not a finite number");
    if (Number.isInteger(v) && Math.abs(v) > JCS_SAFE_INTEGER)
      throw new Refusal("unsafe_integer", path + " is outside the IEEE 754 safe integer range; JSON.parse rounded it before this ledger saw it, so a digest would name another value. Carry it as a string");
    return JSON.stringify(v);
  }
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new Refusal("lone_surrogate", path + " holds a lone UTF-16 surrogate, which has no UTF-8 form");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map((x, i) => jcs(x, depth + 1, path + "[" + i + "]")).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => {
      if (LONE_SURROGATE.test(k)) throw new Refusal("lone_surrogate", path + " has a member name with a lone surrogate");
      return JSON.stringify(k) + ":" + jcs(v[k], depth + 1, path + "." + k);
    }).join(",") + "}";
  }
  throw new Refusal("not_json", path + " is not a JSON value");
}

// ---- small helpers --------------------------------------------------------------------------------------
async function sha256hexBytes(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export const sha256hex = (s) => sha256hexBytes(enc.encode(s));
function b64urlEncode(bytes) {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// Canonical unpadded base64url only (RFC 4648 section 5, unused bits zero), so one byte string has one spelling.
// agentrust-trace refuses the same set; a lenient decoder here would pin a record its own verifier rejects.
export function b64urlDecodeCanonical(s, field) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Refusal("bad_base64url", field + " is not unpadded base64url");
  if (s.length % 4 === 1) throw new Refusal("bad_base64url", field + " has a length no byte string has");
  const pad = s + "=".repeat((4 - (s.length % 4)) % 4);
  let bin;
  try { bin = atob(pad.replace(/-/g, "+").replace(/_/g, "/")); } catch (_e) { throw new Refusal("bad_base64url", field + " does not decode"); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (b64urlEncode(out) !== s) throw new Refusal("bad_base64url", field + " is not canonical base64url (the unused bits of its last character are not zero)");
  return out;
}
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);

// RFC 7638 JWK thumbprint for an OKP key: sha256 over {"crv","kty","x"} in that order, no whitespace, base64url.
// Same value agentrust_trace.jwk_thumbprint returns, which is what a TRACE revocation list names a key by.
export async function jwkThumbprint(jwk) {
  const m = '{"crv":' + JSON.stringify(jwk.crv) + ',"kty":' + JSON.stringify(jwk.kty) + ',"x":' + JSON.stringify(jwk.x) + "}";
  const d = await crypto.subtle.digest("SHA-256", enc.encode(m));
  return b64urlEncode(new Uint8Array(d));
}

// ---- the check ------------------------------------------------------------------------------------------
// Pure apart from Web Crypto. nowSec is injected so a test reproduces the outcome from retained facts.
export async function checkTraceRecord(record, nowSec) {
  if (!isObj(record)) throw new Refusal("record_not_object", "record must be a JSON object (a TRACE Trust Record is always one)");
  const recordJcs = jcs(record);
  const bytes = enc.encode(recordJcs);
  if (bytes.length > MAX_RECORD_BYTES) throw new Refusal("too_large", "the RFC 8785 form is " + bytes.length + " bytes; the cap is " + MAX_RECORD_BYTES, 413);

  // A cMCP RuntimeClaim (cmcp_version, trace, gateway, signature) is valid TRACE carried in an envelope whose signature
  // is the gateway's. v0 reads only a bare Trust Record with an embedded signature, so the envelope is refused by name
  // rather than reported as a wrong profile (trace-tests vector valid_cmcp_runtime.json).
  if ("cmcp_version" in record && "trace" in record && !("eat_profile" in record))
    throw new Refusal("enveloped_form", "this is a cMCP RuntimeClaim envelope; it is valid TRACE, but v0 of this ledger reads only a bare Trust Record with an embedded signature. Submit the inner record if it carries its own signature");
  const prof = record.eat_profile;
  if (prof === TRACE_PROFILE_V0_1) throw new Refusal("superseded_profile", "eat_profile is the v0.1 identifier, which TRACE v0.2 requires verifiers to reject (spec, Changes from v0.1)");
  if (prof !== TRACE_PROFILE_V0_2) throw new Refusal("unsupported_profile", "eat_profile must be " + TRACE_PROFILE_V0_2 + "; this ledger checks no other profile");
  const missing = TRACE_REQUIRED.filter((k) => !(k in record));
  if (missing.length) throw new Refusal("missing_required", "missing required TRACE v0.2 members: " + missing.join(", "));
  if (!Number.isInteger(record.iat) || record.iat < 1700000000) throw new Refusal("bad_iat", "iat must be an integer of Unix epoch seconds (TRACE schema minimum 1700000000)");
  if (typeof record.subject !== "string" || !record.subject) throw new Refusal("bad_subject", "subject must be a non-empty string");

  if (!("signature" in record)) throw new Refusal("no_embedded_signature", "no embedded signature. Enveloped forms (JWS, COSE, cMCP RuntimeClaim) are valid TRACE but v0 of this ledger reads only the embedded signature; submit the record with its signature member");
  const sig = b64urlDecodeCanonical(record.signature, "signature");
  if (sig.length !== 64) throw new Refusal("bad_signature_length", "an Ed25519 signature is 64 bytes; this one is " + sig.length);
  const jwk = isObj(record.cnf) && isObj(record.cnf.jwk) ? record.cnf.jwk : null;
  if (!jwk) throw new Refusal("no_confirmation_key", "cnf.jwk is required and must be an object");
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new Refusal("unsupported_key_type", "v0 verifies OKP / Ed25519 confirmation keys only; got kty " + JSON.stringify(jwk.kty) + ", crv " + JSON.stringify(jwk.crv));
  const pub = b64urlDecodeCanonical(jwk.x, "cnf.jwk.x");
  if (pub.length !== 32) throw new Refusal("bad_key_length", "an Ed25519 public key is 32 bytes; this one is " + pub.length);

  const body = {}; for (const k of Object.keys(record)) if (k !== "signature") body[k] = record[k];
  const bodyJcs = jcs(body);
  let ok = false;
  try {
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, enc.encode(bodyJcs));
  } catch (_e) { ok = false; }
  if (!ok) throw new Refusal("signature_invalid", "the signature does not verify under cnf.jwk over the RFC 8785 form of the record without its signature member");

  if (record.iat > nowSec + FUTURE_SKEW_SECONDS)
    throw new Refusal("iat_in_future", "iat is " + (record.iat - nowSec) + " seconds after this ledger's clock; TRACE 3.2.2 rejects past " + FUTURE_SKEW_SECONDS + ". Pinning a postdated record would let the anchor seem to confirm a time the issuer chose");

  const age = nowSec - record.iat;
  return {
    sha: await sha256hexBytes(bytes),
    record_jcs: recordJcs,
    profile: prof,
    iat: record.iat,
    subject: record.subject,
    key_thumbprint: await jwkThumbprint(jwk),
    transparency: typeof record.transparency === "string" ? record.transparency : null,
    age_seconds_at_intake: age,
    fresh_at_intake: age <= TRACE_MAX_AGE_SECONDS,
  };
}

// ---- registered TRACE producers ---------------------------------------------------------------------------
// The producer keys agentrust-io/trace-registry lists under producers/, as of the commit named here (registry data
// CC BY 4.0). This is the TRACE ecosystem's own public list of which key belongs to which producer, and this ledger
// already mirrors and Bitcoin-witnesses that registry (ogasurfproject-jpg/trace-registry-mirror). When a pinned
// record's key thumbprint is one of these, the answer names the producer and where the binding was published, so a
// reader does not have to take "the key the record carries" on faith. It is a lookup, not a judgement: the registry
// could be wrong, a listed key could be stolen, and a key that is not listed is not thereby suspect.
// To refresh: copy producers/*.json from the registry, recompute each thumbprint (RFC 7638) and file sha256, and bump
// TRACE_PRODUCERS_SOURCE.commit. trace_pin_v0.test.mjs recomputes every thumbprint from its x.
export const TRACE_PRODUCERS_SOURCE = {
  repository: "https://github.com/agentrust-io/trace-registry",
  commit: "58850e9d0f7113be2a4c89b3c2e7b03447f2dcce",
  path: "producers/",
  license: "CC BY 4.0 (registry data)",
};
export const TRACE_PRODUCERS = [
  { producer_id: "bernstein/3.20.0", key_thumbprint: "eXGZiAH6OxMgiUzqcTgubU9pYlSIP3-u6WdQ0w2nxL8", x: "ff3LjX7m5f7vj3YD5NS_LqtEzEa_wkD5ZnNPBpSD3o8", active_since: "2026-09-20T17:02:42Z", file: "producers/bernstein-3.20.0.json" },
  { producer_id: "cmcp-gateway/0.1.0", key_thumbprint: "USN7TcX0GDCWDXb2H2ekb4KDthrGK8bTQxk8I4FfPgg", x: "ToB3lvrNHGjbh8ZPnK0Ogh0zTxLNURCt1rjk5L_M18Q", active_since: "2026-06-12T00:00:00Z", file: "producers/cmcp-gateway-0.1.0.json" },
  { producer_id: "verifiable-agent-summit-demo/0.1.0", key_thumbprint: "4PXGQSwQS0Wt33I0I0g7weN1lEupfL8rQRKMEzs1OFU", x: "MlMDcC9FD2XTwcHx_cMV7aTqq8sfXlTcyFNSDkqsgSE", active_since: "2026-08-20T19:34:17Z", file: "producers/verifiable-agent-summit-demo-0.1.0.json" },
];
export function registeredProducer(thumbprint) {
  const p = TRACE_PRODUCERS.find((x) => x.key_thumbprint === thumbprint);
  if (!p) return null;
  return { producer_id: p.producer_id, active_since: p.active_since, listed_in: TRACE_PRODUCERS_SOURCE.repository + "/blob/" + TRACE_PRODUCERS_SOURCE.commit + "/" + p.file };
}
export const PRODUCER_NOTE = "registered_producer names the producer whose key agentrust-io/trace-registry lists with this thumbprint (producers/, at the commit linked). It says the TRACE registry published this key as that producer's; it does not say the record's claims are true, that the key was not stolen, or anything about a record whose key is not listed";

// ---- what every answer says -----------------------------------------------------------------------------
export const ESTABLISHES = [
  "the ledger received exactly these bytes (the RFC 8785 form of the record as submitted) and their sha256 is the pinned sha",
  "at intake the Ed25519 signature verified under the key in cnf.jwk over the RFC 8785 form of the record without its signature member, the eat_profile was TRACE v0.2, and iat was not more than 300 seconds after the ledger's clock",
  "once the daily batch that lists the sha is stamped, the bytes existed before that Bitcoin block, a clock the issuer does not hold; that bounds iat from above",
];
export const DOES_NOT_ESTABLISH = [
  "that any claim in the record is true (model, measurement, policy, data class, tools); TRACE says the same of its own signature, and appraising those claims is the verifier's work, not this ledger's",
  "that the key belongs to the subject: the key is the one the record carries, so a valid signature shows internal consistency, not authenticity. Compare key_thumbprint (RFC 7638) with a key you already trust",
  "that the key was not revoked: no revocation check was performed",
  "that the transparency receipt resolves on any log; the ledger does not fetch it",
  "that iat is the true time of issue; only that it is not later than the anchor",
  "who submitted the record; pinning is open to anyone who holds one",
];
export function selfDescription(origin) {
  return {
    schema: PIN_SCHEMA,
    what: "Pin a TRACE Trust Record (agentrust-io/trace-spec v0.2) by the sha256 of its RFC 8785 form, so the exact bytes outlive TRACE's 24 hour freshness window and carry a Bitcoin-anchored upper bound on iat",
    post: { url: origin + "/evidence/trace", body: { record: "<the signed TRACE Trust Record, a JSON object with its embedded signature>" } },
    read: { record: origin + "/evidence/trace/{sha}", raw_bytes: origin + "/evidence/trace/{sha}?format=raw", pending: origin + "/evidence/trace/pending", registered_producers: origin + "/evidence/trace/producers" },
    registered_producers: "a pinned record whose key thumbprint agentrust-io/trace-registry lists under producers/ is answered with registered_producer (the producer id and the registry file at a fixed commit); see /evidence/trace/producers",
    link_to_nenrin_records: "a nenrin-trace-bind-v0 record (workers/hs-ledger/nenrin/trace-bind-v0/SPEC.md) signed by the actor links a NENRIN or MUSUBI record to a pinned TRACE record by sha; npx nenrin-trace-verify bind, or pip install nenrin-verify, checks it offline",
    checks_at_intake: [
      "eat_profile is " + TRACE_PROFILE_V0_2 + " (the v0.1 identifier is refused, as TRACE v0.2 requires)",
      "the ten members the TRACE v0.2 schema requires are present (the full schema is not validated here; run agentrust_trace.validate_json yourself)",
      "signature is canonical unpadded base64url of 64 bytes, cnf.jwk is OKP / Ed25519 with a 32 byte key, and the signature verifies over RFC 8785 of the record without its signature member",
      "iat is an integer no more than " + FUTURE_SKEW_SECONDS + " seconds after the ledger's clock",
      "every number is a finite value inside the safe integer range and every string has a UTF-8 form, so the RFC 8785 bytes are the same in any language",
    ],
    not_read_in_v0: ["enveloped signatures (JWS, COSE, cMCP RuntimeClaim)", "confirmation keys other than OKP / Ed25519", "revocation bundles", "SCITT receipts"],
    caps: { max_record_bytes: MAX_RECORD_BYTES, daily_global: DAILY_GLOBAL, daily_per_network: DAILY_PER_NETWORK },
    anchor_policy: "accepted records are bundled into a " + BATCH_SCHEMA + " ledger entry daily at 00:30 UTC by the ledger's schedule when the pool is not empty; the Bitcoin stamp follows on the operator's stamping run",
    publication: "a pinned record is public: its bytes are served to anyone. Do not pin a record you are not entitled to publish",
    establishes: ESTABLISHES,
    does_not_establish: DOES_NOT_ESTABLISH,
    how_to_verify: "GET /evidence/trace/{sha}?format=raw and confirm sha256(body) == sha; verify the signature yourself (agentrust_trace.verify_record with a key you trust, or Ed25519 over RFC 8785 of the record minus signature); once anchored, GET /ledger/{n}?format=raw, confirm sha256 == the entry's claim and that sha is listed in records[], then GET /ledger/{n}/ots and run ots verify",
  };
}

// ---- routes ---------------------------------------------------------------------------------------------
const j = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*", ...extra } });

async function networkLane(request, day) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const s = ip.trim();
  let pre = s;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) pre = s.split(".").slice(0, 3).join(".");
  else if (s.indexOf(":") >= 0) pre = s.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase().split(":").slice(0, 3).join(":");
  return "tpin:net:" + day + ":" + (await sha256hex(day + "|" + pre)).slice(0, 16);
}

async function handlePost(request, env, origin, nowSec) {
  const text = await request.text();
  if (text.length > MAX_RECORD_BYTES * 2) return j({ error: "too_large", max_record_bytes: MAX_RECORD_BYTES }, 413);
  let body = null;
  try { body = JSON.parse(text); } catch (_e) { body = null; }
  if (!isObj(body) || !("record" in body)) return j({ error: "body must be a JSON object with a record member", help: origin + "/evidence/trace" }, 400);
  let c;
  try { c = await checkTraceRecord(body.record, nowSec); }
  catch (e) {
    if (e instanceof Refusal) return j({ error: "refused", reason_code: e.code, why: e.message, help: origin + "/evidence/trace" }, e.status);
    throw e;
  }
  const dupP = await env.LEDGER.get(PENDING(c.sha));
  const dupA = await env.LEDGER.get(ANCHORED(c.sha));
  if (dupP || dupA) return j({ sha: c.sha, status: dupA ? "anchored" : "pending", dedup: true, url: origin + "/evidence/trace/" + c.sha });

  const day = new Date(nowSec * 1000).toISOString().slice(0, 10);
  const gKey = "tpin:count:" + day;
  const g = Number((await env.LEDGER.get(gKey)) || 0);
  if (g >= DAILY_GLOBAL) return j({ error: "daily_global_cap_reached", cap: DAILY_GLOBAL }, 429);
  const nKey = await networkLane(request, day);
  const nc = Number((await env.LEDGER.get(nKey)) || 0);
  if (nc >= DAILY_PER_NETWORK) return j({ error: "daily_per_network_cap_reached", cap: DAILY_PER_NETWORK }, 429);

  const stored = { schema: PIN_SCHEMA, ...c, received_at: new Date(nowSec * 1000).toISOString() };
  await env.LEDGER.put(PENDING(c.sha), JSON.stringify(stored));
  await env.LEDGER.put(gKey, String(g + 1), { expirationTtl: 90000 });
  await env.LEDGER.put(nKey, String(nc + 1), { expirationTtl: 90000 });
  return j({
    sha: c.sha, status: "pending", url: origin + "/evidence/trace/" + c.sha,
    key_thumbprint: c.key_thumbprint, registered_producer: registeredProducer(c.key_thumbprint), producer_note: PRODUCER_NOTE,
    iat: c.iat, fresh_at_intake: c.fresh_at_intake,
    establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
  }, 201);
}

async function handleGetOne(sha, url, env, origin) {
  const pRaw = await env.LEDGER.get(PENDING(sha));
  const aRaw = await env.LEDGER.get(ANCHORED(sha));
  let stored = null, n = null;
  if (aRaw) { try { const a = JSON.parse(aRaw); stored = a.stored; n = a.n; } catch (_e) {} }
  if (!stored && pRaw) { try { stored = JSON.parse(pRaw); } catch (_e) {} }
  if (!stored) return j({ error: "not_found", sha, note: "no TRACE record is pinned under this sha" }, 404);
  if (url.searchParams.get("format") === "raw")
    return new Response(stored.record_jcs, { status: 200, headers: { "content-type": "application/json; charset=utf-8", "x-record-sha256": sha, "cache-control": "public, max-age=31536000, immutable", "access-control-allow-origin": "*" } });
  let bitcoin = null;
  if (n !== null) {
    try { const e = JSON.parse(await env.LEDGER.get("entry:" + n)); bitcoin = { ledger_entry: n, batch_sha256: e.claim_sha256, ots_status: e.ots_status || null, block: e.bitcoin_block ?? null, block_time: e.block_time || null, ots: origin + "/ledger/" + n + "/ots" }; } catch (_e) {}
  }
  let record = null; try { record = JSON.parse(stored.record_jcs); } catch (_e) {}
  return j({
    schema: PIN_SCHEMA, sha, status: n !== null ? "anchored" : "pending",
    received_at: stored.received_at, profile: stored.profile, iat: stored.iat, subject: stored.subject,
    key_thumbprint: stored.key_thumbprint, registered_producer: registeredProducer(stored.key_thumbprint), producer_note: PRODUCER_NOTE,
    transparency: stored.transparency,
    age_seconds_at_intake: stored.age_seconds_at_intake, fresh_at_intake: stored.fresh_at_intake,
    anchor: bitcoin, raw_url: origin + "/evidence/trace/" + sha + "?format=raw", record,
    establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
  });
}

async function handlePending(env, origin) {
  const listed = await env.LEDGER.list({ prefix: PENDING_PREFIX });
  const out = [];
  for (const k of listed.keys.slice(0, BATCH_MAX)) {
    try { const s = JSON.parse(await env.LEDGER.get(k.name)); out.push({ sha: s.sha, iat: s.iat, subject: s.subject, key_thumbprint: s.key_thumbprint, registered_producer: (registeredProducer(s.key_thumbprint) || {}).producer_id || null, received_at: s.received_at, url: origin + "/evidence/trace/" + s.sha }); } catch (_e) {}
  }
  out.sort((a, b) => (a.sha < b.sha ? -1 : 1));
  return j({ count: out.length, pending: out, note: "queued for the daily batch at 00:30 UTC" });
}

// Additive dispatcher. Returns null for any path that is not ours.
export async function handleTracePin(p, request, url, env, origin, nowSec = Math.floor(Date.now() / 1000)) {
  if (p !== "/evidence/trace" && !p.startsWith("/evidence/trace/")) return null;
  if (p === "/evidence/trace") {
    if (request.method === "GET") return j(selfDescription(origin));
    if (request.method === "POST") return handlePost(request, env, origin, nowSec);
    return j({ error: "method_not_allowed" }, 405);
  }
  if (request.method !== "GET") return j({ error: "method_not_allowed" }, 405);
  const rest = p.slice("/evidence/trace/".length);
  if (rest === "pending") return handlePending(env, origin);
  if (rest === "producers") return j({ source: TRACE_PRODUCERS_SOURCE, producers: TRACE_PRODUCERS, note: PRODUCER_NOTE, how_to_check: "fetch each listed file at the commit, compute the RFC 7638 thumbprint of public_key_jwk (sha256 over {\"crv\",\"kty\",\"x\"} in that order, base64url), and compare it with key_thumbprint" });
  const sha = rest.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) return j({ error: "sha_must_be_64_hex" }, 400);
  return handleGetOne(sha, url, env, origin);
}

// ---- daily anchor, mirroring anchorAgreementPool --------------------------------------------------------
export async function anchorTracePinPool(env, origin, trigger, nowIso = new Date().toISOString()) {
  const listed = await env.LEDGER.list({ prefix: PENDING_PREFIX });
  const keys = listed.keys.slice(0, BATCH_MAX);
  if (!keys.length) return { status: 200, body: { ok: true, anchored: 0, note: "TRACE pin pool is empty" } };
  const items = [];
  for (const k of keys) {
    const raw = await env.LEDGER.get(k.name);
    if (!raw) continue;
    try { const s = JSON.parse(raw); if (s && /^[0-9a-f]{64}$/.test(s.sha)) items.push(s); } catch (_e) {}
  }
  items.sort((a, b) => (a.sha < b.sha ? -1 : 1));
  const batch = {
    schema: BATCH_SCHEMA,
    anchored_at: nowIso,
    count: items.length,
    records: items.map((s) => ({ sha: s.sha, iat: s.iat, subject: s.subject, key_thumbprint: s.key_thumbprint, fresh_at_intake: s.fresh_at_intake })),
  };
  const canonical = JSON.stringify(batch);
  const h = (await sha256hex(canonical)).toLowerCase();
  const dup = await env.LEDGER.get("hash:" + h);
  if (dup) return { status: 200, body: { n: Number(dup), url: origin + "/ledger/" + dup, dedup: true } };
  const entry = { n: 0, work: "NENRIN TRACE pin batch (" + items.length + " records)", claim_sha256: h, record_canonical: canonical, schema: "v0-plain", created_at: nowIso, ots_status: "unstamped", bitcoin_block: null, block_time: null, stamped_at: null, anchored_by: trigger };
  const ap = await appendEntry(env, h, entry);   // 2026-10-13 (concurrency audit L1): the sequencer assigns n
  if (ap.dedup) return { status: 200, body: { n: ap.n, url: origin + "/ledger/" + ap.n, dedup: true } };
  const n = ap.n;
  for (const s of items) {
    await env.LEDGER.put(ANCHORED(s.sha), JSON.stringify({ n, stored: s }));
    await env.LEDGER.delete(PENDING(s.sha));
  }
  return { status: 201, body: { n, url: origin + "/ledger/" + n, anchored: items.length, trigger, note: "the batch anchor covers every TRACE record listed; the Bitcoin stamp follows on the operator's stamping run" } };
}
