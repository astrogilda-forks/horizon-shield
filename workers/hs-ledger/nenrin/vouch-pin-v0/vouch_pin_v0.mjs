// vouch-pin-v0: pin a Vouch Protocol credential (W3C VC 2.0, Data Integrity eddsa-jcs-2022) on the NENRIN ledger, so
// the exact signed bytes outlive the issuer's own hosting and carry a Bitcoin-anchored upper bound on when they existed.
//
// Why. A Vouch credential says who acted and under whose authority; its time (validFrom, proof.created) is the
// issuer's own clock. Vouch's accountability module leaves a slot for exactly this: a third-party timestamp_anchor
// {method, reference, recomputeCmd, establishes} on an OutcomeCommitmentCredential, and says a consumer concludes
// commit-before-outcome only when it confirms the stamped time precedes the settlement time (vouch/accountability.py).
// This intake fills that slot with an anchor nobody, including this ledger's operator, can move:
//   1. the issuer builds the commitment with anchorEntry(credential id) in its anchor list and signs it;
//   2. it POSTs the signed credential here; the ledger checks the proof and pins sha256 of its RFC 8785 bytes;
//   3. the daily batch lists the sha and is stamped to Bitcoin; vouch_check.py recomputes all of it offline.
// Because the reference is the credential id, two different credentials pinned under one id by one issuer are both
// listed at /evidence/vouch/id/<id>: an issuer who commits twice and later shows the winner is visible.
//
// Read in v0: issuers did:key (Ed25519) and did:web (Ed25519 in publicKeyMultibase or publicKeyJwk), the W3C hashData
// signing input, and Vouch's pre-alignment single digest (vouch/data_integrity.py legacy_proof_digest), recorded as
// such. The verification method must belong to the issuer. Not read: ML-DSA hybrid proofs, JOSE/COSE, status lists.
import { jcs, Refusal } from "../trace-pin-v0/trace_pin_v0.mjs";
import { ed25519PointOk } from "../../src/ed25519_point.mjs";
import { appendEntry } from "../../src/ledger_append.mjs";

export const PIN_SCHEMA = "nenrin-vouch-pin-v0";
export const BATCH_SCHEMA = "nenrin-vouch-pin-batch-v0";
export const ANCHOR_METHOD = "nenrin-opentimestamps";
export const MAX_BYTES = 65536;
export const FUTURE_SKEW_SECONDS = 300;
export const DAILY_GLOBAL = 200;
export const DAILY_PER_NETWORK = 20;
export const BATCH_MAX = 200;
export const CHECKER_URL = "https://raw.githubusercontent.com/ogasurfproject-jpg/horizon-shield/main/workers/hs-ledger/nenrin/vouch-pin-v0/vouch_check.py";

const PENDING = (sha) => "vpin:pending:" + sha;
const ANCHORED = (sha) => "vpin:anchored:" + sha;
const BY_ID = (idsha, sha) => "vpin:id:" + idsha + ":" + sha;
const PENDING_PREFIX = "vpin:pending:";
const enc = new TextEncoder();
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
export const sha256hex = async (s) => hex(await sha256(typeof s === "string" ? enc.encode(s) : s));
const b64 = (bytes) => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };

// ---- base58btc and Multikey ------------------------------------------------------------------------------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58decode(s) {
  if (typeof s !== "string" || !s.length) throw new Refusal("bad_base58", "empty base58btc");
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Refusal("bad_base58", "not base58btc"); n = n * 58n + BigInt(i); }
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 255n)); n >>= 8n; }
  for (const c of s) { if (c !== "1") break; out.unshift(0); }
  return new Uint8Array(out);
}
function b64urlDecode(s, field) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Refusal("bad_key", field + " is not base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
// Ed25519 Multikey: "z" + base58btc(0xed 0x01 || 32 byte key). Anything else is refused by name.
export function multikeyEd25519(mk, field) {
  if (typeof mk !== "string" || mk[0] !== "z") throw new Refusal("bad_multikey", field + " is not a base58btc Multikey");
  const b = b58decode(mk.slice(1));
  if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new Refusal("unsupported_key_type", field + " is not an Ed25519 Multikey (0xed01 prefix, 32 bytes)");
  return b.slice(2);
}

// ---- DID resolution (did:key offline, did:web over https) -------------------------------------------------
export function didWebUrl(did) {
  const m = /^did:web:([a-z0-9.-]+)$/.exec(did);
  if (!m) throw new Refusal("did_web_form_not_read_in_v0", "v0 reads did:web:<host> only (no port, no path): " + did);
  const host = m[1];
  if (host.startsWith(".") || host.endsWith(".") || !host.includes(".") || /^[0-9.]+$/.test(host) || host === "localhost" || host.endsWith(".local") || host.endsWith(".internal"))
    throw new Refusal("did_web_host_not_public", "did:web host must be a public DNS name: " + host);
  return "https://" + host + "/.well-known/did.json";
}

async function resolveKey(did, vm, fetchImpl) {
  if (did.startsWith("did:key:")) {
    const mk = did.slice("did:key:".length);
    return { method: "did:key", raw: multikeyEd25519(mk, "did:key"), did_document_sha256: null, assertion_method_listed: null };
  }
  if (did.startsWith("did:web:")) {
    const url = didWebUrl(did);
    if (!fetchImpl) throw new Refusal("did_web_unreachable", "no fetch available to resolve " + did);
    let res;
    try { res = await fetchImpl(url, { redirect: "manual", headers: { accept: "application/did+json, application/json" } }); }
    catch (e) { throw new Refusal("did_web_unreachable", "could not fetch " + url + ": " + String(e && e.message || e).slice(0, 120), 424); }
    if (!res || res.status !== 200) throw new Refusal("did_web_unreachable", url + " answered " + (res && res.status) + " (redirects are not followed)", 424);
    const body = new Uint8Array(await res.arrayBuffer());
    if (body.length > MAX_BYTES) throw new Refusal("did_web_too_large", url + " is over " + MAX_BYTES + " bytes", 424);
    let doc; try { doc = JSON.parse(new TextDecoder().decode(body)); } catch (_e) { throw new Refusal("did_web_not_json", url + " is not JSON", 424); }
    if (!isObj(doc) || doc.id !== did) throw new Refusal("did_document_id_mismatch", "the document at " + url + " names id " + JSON.stringify(isObj(doc) ? doc.id : null) + ", not " + did);
    const full = (id) => (typeof id === "string" && id.startsWith("#") ? did + id : id);
    const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
    const m = vms.find((x) => isObj(x) && full(x.id) === vm);
    if (!m) throw new Refusal("verification_method_not_in_document", vm + " is not listed in " + url);
    let raw;
    if (typeof m.publicKeyMultibase === "string") raw = multikeyEd25519(m.publicKeyMultibase, "publicKeyMultibase");
    else if (isObj(m.publicKeyJwk) && m.publicKeyJwk.kty === "OKP" && m.publicKeyJwk.crv === "Ed25519") raw = b64urlDecode(m.publicKeyJwk.x, "publicKeyJwk.x");
    else throw new Refusal("unsupported_key_type", vm + " carries no Ed25519 key this ledger reads");
    if (raw.length !== 32) throw new Refusal("bad_key_length", "an Ed25519 key is 32 bytes");
    const am = Array.isArray(doc.assertionMethod) ? doc.assertionMethod.map((x) => full(isObj(x) ? x.id : x)) : null;
    if (am && !am.includes(vm)) throw new Refusal("not_an_assertion_method", vm + " is in the document but not under assertionMethod");
    return { method: "did:web", raw, did_document_url: url, did_document_sha256: await sha256hex(body), assertion_method_listed: am ? true : null };
  }
  throw new Refusal("did_method_not_read_in_v0", "v0 resolves did:key and did:web issuers; got " + did.split(":").slice(0, 2).join(":"));
}

// ---- eddsa-jcs-2022 ---------------------------------------------------------------------------------------
// W3C VC-DI-EDDSA 3.3: hashData = SHA-256(JCS(proof config)) || SHA-256(JCS(document without proof)), where the
// proof config is the proof without proofValue carrying the document's @context. Vouch also accepts its own
// pre-alignment input, SHA-256(JCS(document with the unsigned proof)); that is read and recorded as such.
export async function signingInputs(cred) {
  const doc = {}; for (const k of Object.keys(cred)) if (k !== "proof") doc[k] = cred[k];
  const unsigned = {}; for (const k of Object.keys(cred.proof)) if (k !== "proofValue") unsigned[k] = cred.proof[k];
  const config = { ...unsigned }; if ("@context" in doc) config["@context"] = doc["@context"];
  const w3c = new Uint8Array(64);
  w3c.set(await sha256(enc.encode(jcs(config))), 0);
  w3c.set(await sha256(enc.encode(jcs(doc))), 32);
  const legacy = await sha256(enc.encode(jcs({ ...doc, proof: unsigned })));
  return { w3c, legacy };
}

const typesOf = (t) => (typeof t === "string" ? [t] : Array.isArray(t) ? t.filter((x) => typeof x === "string") : []);
const issuerOf = (c) => (typeof c.issuer === "string" ? c.issuer : isObj(c.issuer) && typeof c.issuer.id === "string" ? c.issuer.id : null);
const isoSec = (s) => { if (typeof s !== "string") return null; const t = Date.parse(s); return Number.isFinite(t) ? Math.floor(t / 1000) : null; };

// Pure apart from Web Crypto and the did:web fetch. nowSec is injected so a test reproduces the outcome.
export async function checkVouchCredential(cred, { nowSec, fetchImpl } = {}) {
  if (!isObj(cred)) throw new Refusal("credential_not_object", "credential must be a JSON object");
  const credJcs = jcs(cred);
  const bytes = enc.encode(credJcs);
  if (bytes.length > MAX_BYTES) throw new Refusal("too_large", "the RFC 8785 form is " + bytes.length + " bytes; the cap is " + MAX_BYTES, 413);
  const types = typesOf(cred.type);
  if (!types.includes("VerifiableCredential")) throw new Refusal("not_a_verifiable_credential", "type must include VerifiableCredential");
  const p = cred.proof;
  if (!isObj(p)) throw new Refusal("no_proof", "a single embedded proof object is required (proof sets and chains are not read in v0)");
  if (p.type !== "DataIntegrityProof" || p.cryptosuite !== "eddsa-jcs-2022")
    throw new Refusal("unsupported_cryptosuite", "v0 reads DataIntegrityProof with cryptosuite eddsa-jcs-2022; got " + JSON.stringify([p.type, p.cryptosuite]));
  if (typeof p.proofValue !== "string" || p.proofValue[0] !== "z") throw new Refusal("bad_proof_value", "proofValue must be base58btc with a z prefix");
  const sig = b58decode(p.proofValue.slice(1));
  if (sig.length !== 64) throw new Refusal("bad_signature_length", "an Ed25519 signature is 64 bytes; this one is " + sig.length);
  const vm = p.verificationMethod;
  if (typeof vm !== "string" || !vm.startsWith("did:")) throw new Refusal("bad_verification_method", "verificationMethod must be a DID URL");
  const did = vm.split("#")[0];
  const issuer = issuerOf(cred);
  if (issuer !== did) throw new Refusal("verification_method_not_issuer", "the proof is made by " + did + " but the credential's issuer is " + JSON.stringify(issuer) + "; a pin would let one party's key speak for another");
  const key = await resolveKey(did, vm, fetchImpl);
  if (!ed25519PointOk(key.raw)) throw new Refusal("weak_key", "the issuer key is not a canonical point of the prime-order subgroup (small or mixed order keys let anyone forge a signature)");
  const { w3c, legacy } = await signingInputs(cred);
  const pk = await crypto.subtle.importKey("raw", key.raw, { name: "Ed25519" }, false, ["verify"]);
  let rule = null;
  if (await crypto.subtle.verify({ name: "Ed25519" }, pk, sig, w3c)) rule = "w3c-vc-di-eddsa-hashdata";
  else if (await crypto.subtle.verify({ name: "Ed25519" }, pk, sig, legacy)) rule = "vouch-pre-alignment-digest";
  if (!rule) throw new Refusal("signature_invalid", "the proof does not verify under " + vm + " over the eddsa-jcs-2022 signing input (nor Vouch's pre-alignment digest)");
  const created = isoSec(p.created);
  if (nowSec !== undefined && created !== null && created > nowSec + FUTURE_SKEW_SECONDS)
    throw new Refusal("created_in_future", "proof.created is " + (created - nowSec) + " seconds after this ledger's clock; pinning a postdated credential would let the anchor seem to confirm a time the issuer chose");
  const id = typeof cred.id === "string" && cred.id.length <= 512 ? cred.id : null;
  const anchors = ((((cred.credentialSubject || {}).commitment) || {}).anchor);
  const own = Array.isArray(anchors) ? anchors.filter((a) => isObj(a) && a.method === ANCHOR_METHOD) : [];
  return {
    sha: await sha256hex(bytes), record_jcs: credJcs,
    credential_id: id, credential_id_sha256: id ? await sha256hex(id) : null,
    issuer, verification_method: vm, did_method: key.method, public_key_b64: b64(key.raw),
    did_document_url: key.did_document_url || null, did_document_sha256: key.did_document_sha256,
    proof_rule: rule, proof_created: typeof p.created === "string" ? p.created : null,
    valid_from: typeof cred.validFrom === "string" ? cred.validFrom : null, types,
    names_this_ledger_as_anchor: own.length > 0, anchor_establishes: own.map((a) => a.establishes || "existence-only"),
  };
}

// The entry an issuer puts in a commitment's anchor list before signing it (vouch.accountability.timestamp_anchor
// accepts it as is). establishes defaults to existence-only, as Vouch's does.
export function anchorEntry(credentialId, { origin = "https://ledger.horizonshield.dev", establishes = "existence-only" } = {}) {
  if (typeof credentialId !== "string" || !credentialId) throw new Error("the credential id is the reference; give the id you will sign");
  return {
    method: ANCHOR_METHOD,
    reference: origin + "/evidence/vouch/id/" + encodeURIComponent(credentialId),
    recomputeCmd: "curl -sO " + CHECKER_URL + " && python3 vouch_check.py --ledger " + origin + " --credential <this credential as JSON> --outcome-time <the settlement time>",
    establishes,
  };
}

export const ESTABLISHES = [
  "the ledger received exactly these bytes (the RFC 8785 form of the credential as submitted) and their sha256 is the pinned sha",
  "at intake the eddsa-jcs-2022 proof verified under the issuer's own key (did:key, or did:web resolved at intake with the document's sha256 recorded), the key was a prime-order point, and proof.created was not more than 300 seconds after the ledger's clock",
  "once the daily batch that lists the sha is stamped, the credential existed before that Bitcoin block, a clock neither the issuer nor this ledger holds",
  "every credential pinned under one id is listed at /evidence/vouch/id/<id>, so one issuer pinning two different credentials under one id is visible",
];
export const DOES_NOT_ESTABLISH = [
  "that any claim in the credential is true, or that the outcome it commits to happened",
  "that the issuer's key was not stolen or revoked; no status list is read",
  "that a did:web document served the same key before or after intake; only its sha256 at intake is recorded",
  "that the stamped time precedes an outcome; that is the reader's comparison of the Bitcoin block time with the settlement time (vouch_check.py --outcome-time)",
  "who submitted the credential; pinning is open to anyone who holds one, and a pinned credential is public",
];

export function selfDescription(origin) {
  return {
    schema: PIN_SCHEMA,
    what: "Pin a Vouch Protocol credential (W3C VC, Data Integrity eddsa-jcs-2022) by the sha256 of its RFC 8785 form, so the signed bytes outlive the issuer's hosting and carry a Bitcoin-anchored upper bound on when they existed",
    post: { url: origin + "/evidence/vouch", body: { credential: "<the signed credential, a JSON object with its proof>" } },
    read: { record: origin + "/evidence/vouch/{sha}", raw_bytes: origin + "/evidence/vouch/{sha}?format=raw", by_credential_id: origin + "/evidence/vouch/id/{url-encoded id}", pending: origin + "/evidence/vouch/pending" },
    vouch_anchor_entry: anchorEntry("urn:uuid:<the id you will sign>", { origin }),
    how_to_use_with_vouch: "put the entry above in commit_outcome(anchor=...) with the id you pass as credential_id, sign, then POST the signed credential here. With establishes pre-outcome-ordering, a reader confirms the Bitcoin block time of the batch that lists it precedes the settlement time",
    checks_at_intake: [
      "type includes VerifiableCredential; one DataIntegrityProof with cryptosuite eddsa-jcs-2022",
      "the verification method's DID is the credential's issuer",
      "the issuer key resolves offline (did:key) or from https://<host>/.well-known/did.json (did:web, no redirects, the document's sha256 recorded) and is a prime-order Ed25519 point",
      "the proof verifies over the W3C hashData, or over Vouch's pre-alignment digest (recorded as proof_rule)",
      "proof.created is no more than " + FUTURE_SKEW_SECONDS + " seconds after the ledger's clock",
    ],
    not_read_in_v0: ["ML-DSA and hybrid proofs", "proof sets and proof chains", "JOSE and COSE secured credentials", "status lists and revocation", "did methods other than did:key and did:web"],
    caps: { max_bytes: MAX_BYTES, daily_global: DAILY_GLOBAL, daily_per_network: DAILY_PER_NETWORK },
    anchor_policy: "accepted credentials are bundled oldest first into a " + BATCH_SCHEMA + " ledger entry daily at 00:30 UTC; the Bitcoin stamp follows on the operator's stamping run",
    establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
    verify_offline: CHECKER_URL,
  };
}

// ---- routes ---------------------------------------------------------------------------------------------
const j = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*", ...extra } });

async function networkLane(request, day) {
  const s = (request.headers.get("cf-connecting-ip") || "unknown").trim();
  let pre = s;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) pre = s.split(".").slice(0, 3).join(".");
  else if (s.indexOf(":") >= 0) pre = s.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase().split(":").slice(0, 3).join(":");
  return "vpin:net:" + day + ":" + (await sha256hex(day + "|" + pre)).slice(0, 16);
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

async function handlePost(request, env, origin, nowSec, fetchImpl) {
  const text = await request.text();
  if (text.length > MAX_BYTES * 2) return j({ error: "too_large", max_bytes: MAX_BYTES }, 413);
  let body = null; try { body = JSON.parse(text); } catch (_e) { body = null; }
  if (!isObj(body) || !("credential" in body)) return j({ error: "body must be a JSON object with a credential member", help: origin + "/evidence/vouch" }, 400);
  let c;
  try { c = await checkVouchCredential(body.credential, { nowSec, fetchImpl }); }
  catch (e) { if (e instanceof Refusal) return j({ error: "refused", reason_code: e.code, why: e.message, help: origin + "/evidence/vouch" }, e.status); throw e; }
  const dupP = await env.LEDGER.get(PENDING(c.sha));
  const dupA = await env.LEDGER.get(ANCHORED(c.sha));
  if (dupP || dupA) return j({ sha: c.sha, status: dupA ? "anchored" : "pending", dedup: true, url: origin + "/evidence/vouch/" + c.sha });
  const day = new Date(nowSec * 1000).toISOString().slice(0, 10);
  const gKey = "vpin:count:" + day;
  const g = Number((await env.LEDGER.get(gKey)) || 0);
  if (g >= DAILY_GLOBAL) return j({ error: "daily_global_cap_reached", cap: DAILY_GLOBAL }, 429);
  const nKey = await networkLane(request, day);
  const nc = Number((await env.LEDGER.get(nKey)) || 0);
  if (nc >= DAILY_PER_NETWORK) return j({ error: "daily_per_network_cap_reached", cap: DAILY_PER_NETWORK }, 429);
  const stored = { schema: PIN_SCHEMA, ...c, received_at: new Date(nowSec * 1000).toISOString() };
  await env.LEDGER.put(PENDING(c.sha), JSON.stringify(stored));
  if (c.credential_id_sha256) await env.LEDGER.put(BY_ID(c.credential_id_sha256, c.sha), JSON.stringify({ sha: c.sha, issuer: c.issuer, received_at: stored.received_at }));
  await env.LEDGER.put(gKey, String(g + 1), { expirationTtl: 90000 });
  await env.LEDGER.put(nKey, String(nc + 1), { expirationTtl: 90000 });
  const others = c.credential_id_sha256 ? (await listAll(env, "vpin:id:" + c.credential_id_sha256 + ":")).map((k) => k.name.split(":").pop()).filter((s) => s !== c.sha) : [];
  return j({
    sha: c.sha, status: "pending", url: origin + "/evidence/vouch/" + c.sha,
    credential_id: c.credential_id, issuer: c.issuer, did_method: c.did_method, proof_rule: c.proof_rule,
    other_credentials_pinned_under_this_id: others,
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
  if (!s) return j({ error: "not_found", sha, note: "no Vouch credential is pinned under this sha" }, 404);
  if (url.searchParams.get("format") === "raw")
    return new Response(s.stored.record_jcs, { status: 200, headers: { "content-type": "application/json; charset=utf-8", "x-record-sha256": sha, "cache-control": "public, max-age=31536000, immutable", "access-control-allow-origin": "*" } });
  const st = s.stored; let credential = null; try { credential = JSON.parse(st.record_jcs); } catch (_e) {}
  return j({
    schema: PIN_SCHEMA, sha, status: s.n !== null ? "anchored" : "pending", received_at: st.received_at,
    credential_id: st.credential_id, issuer: st.issuer, verification_method: st.verification_method, did_method: st.did_method,
    public_key_b64: st.public_key_b64, did_document_url: st.did_document_url, did_document_sha256: st.did_document_sha256,
    proof_rule: st.proof_rule, proof_created: st.proof_created, valid_from: st.valid_from, types: st.types,
    names_this_ledger_as_anchor: st.names_this_ledger_as_anchor, anchor_establishes: st.anchor_establishes,
    anchor: await anchorOf(env, origin, s.n), raw_url: origin + "/evidence/vouch/" + sha + "?format=raw", credential,
    establishes: ESTABLISHES, does_not_establish: DOES_NOT_ESTABLISH,
  });
}

async function handleById(idEnc, env, origin) {
  let id; try { id = decodeURIComponent(idEnc); } catch (_e) { return j({ error: "bad_id_encoding" }, 400); }
  const idsha = await sha256hex(id);
  const keys = await listAll(env, "vpin:id:" + idsha + ":");
  const pins = [];
  for (const k of keys) {
    const sha = k.name.split(":").pop();
    const s = await storedOf(env, sha);
    if (!s) continue;
    pins.push({ sha, issuer: s.stored.issuer, received_at: s.stored.received_at, proof_created: s.stored.proof_created, status: s.n !== null ? "anchored" : "pending", anchor: await anchorOf(env, origin, s.n), url: origin + "/evidence/vouch/" + sha });
  }
  pins.sort((a, b) => (a.received_at < b.received_at ? -1 : a.received_at > b.received_at ? 1 : a.sha < b.sha ? -1 : 1));
  const byIssuer = {};
  for (const x of pins) (byIssuer[x.issuer] = byIssuer[x.issuer] || []).push(x.sha);
  const equivocating = Object.entries(byIssuer).filter(([, v]) => v.length > 1).map(([k]) => k);
  if (!pins.length) return j({ credential_id: id, count: 0, pins: [], note: "nothing is pinned under this id" }, 404);
  return j({ credential_id: id, credential_id_sha256: idsha, count: pins.length, pins, issuers_with_more_than_one_credential_under_this_id: equivocating,
             note: "every credential pinned under this id, oldest first. More than one from one issuer means that issuer signed different credentials under one id; a reader should not accept either as the commitment without asking why" });
}

async function handlePending(env, origin) {
  const keys = await listAll(env, PENDING_PREFIX);
  const out = [];
  for (const k of keys) { try { const s = JSON.parse(await env.LEDGER.get(k.name)); out.push({ sha: s.sha, issuer: s.issuer, credential_id: s.credential_id, received_at: s.received_at, url: origin + "/evidence/vouch/" + s.sha }); } catch (_e) {} }
  out.sort((a, b) => (a.received_at < b.received_at ? -1 : a.received_at > b.received_at ? 1 : a.sha < b.sha ? -1 : 1));
  return j({ count: out.length, pending: out, note: "queued oldest first for the daily batch at 00:30 UTC" });
}

export async function handleVouchPin(p, request, url, env, origin, nowSec = Math.floor(Date.now() / 1000), fetchImpl = (u, i) => fetch(u, i)) {
  if (p !== "/evidence/vouch" && !p.startsWith("/evidence/vouch/")) return null;
  if (p === "/evidence/vouch") {
    if (request.method === "GET") return j(selfDescription(origin));
    if (request.method === "POST") return handlePost(request, env, origin, nowSec, fetchImpl);
    return j({ error: "method_not_allowed" }, 405);
  }
  if (request.method !== "GET") return j({ error: "method_not_allowed" }, 405);
  const rest = p.slice("/evidence/vouch/".length);
  if (rest === "pending") return handlePending(env, origin);
  if (rest.startsWith("id/")) return handleById(rest.slice(3), env, origin);
  const sha = rest.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) return j({ error: "sha_must_be_64_hex" }, 400);
  return handleGetOne(sha, url, env, origin);
}

// ---- daily anchor: oldest first over every KV page (the 2026-10-09 red team found lexicographic batching could
// postpone a record forever, R3-2; this intake starts with the fix) ------------------------------------------
export async function anchorVouchPinPool(env, origin, trigger, nowIso = new Date().toISOString()) {
  const keys = await listAll(env, PENDING_PREFIX);
  if (!keys.length) return { status: 200, body: { ok: true, anchored: 0, note: "Vouch pin pool is empty" } };
  const all = [];
  for (const k of keys) {
    const raw = await env.LEDGER.get(k.name);
    if (!raw) continue;
    try { const s = JSON.parse(raw); if (s && /^[0-9a-f]{64}$/.test(s.sha)) all.push(s); } catch (_e) {}
  }
  all.sort((a, b) => (a.received_at < b.received_at ? -1 : a.received_at > b.received_at ? 1 : a.sha < b.sha ? -1 : 1));
  const items = all.slice(0, BATCH_MAX);
  const batch = {
    schema: BATCH_SCHEMA, anchored_at: nowIso, count: items.length,
    records: items.map((s) => ({ sha: s.sha, issuer: s.issuer, credential_id_sha256: s.credential_id_sha256, proof_created: s.proof_created, received_at: s.received_at })),
  };
  const canonical = JSON.stringify(batch);
  const h = (await sha256hex(canonical)).toLowerCase();
  const dup = await env.LEDGER.get("hash:" + h);
  if (dup) return { status: 200, body: { n: Number(dup), url: origin + "/ledger/" + dup, dedup: true } };
  const entry = { n: 0, work: "NENRIN Vouch credential pin batch (" + items.length + " credentials)", claim_sha256: h, record_canonical: canonical, schema: "v0-plain", created_at: nowIso, ots_status: "unstamped", bitcoin_block: null, block_time: null, stamped_at: null, anchored_by: trigger };
  const ap = await appendEntry(env, h, entry);   // 2026-10-13 (concurrency audit L1): the sequencer assigns n
  if (ap.dedup) return { status: 200, body: { n: ap.n, url: origin + "/ledger/" + ap.n, dedup: true } };
  const n = ap.n;
  for (const s of items) {
    await env.LEDGER.put(ANCHORED(s.sha), JSON.stringify({ n, stored: s }));
    await env.LEDGER.delete(PENDING(s.sha));
  }
  return { status: 201, body: { n, url: origin + "/ledger/" + n, anchored: items.length, remaining: all.length - items.length, trigger } };
}
