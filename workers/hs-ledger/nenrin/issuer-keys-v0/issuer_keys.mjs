// issuer_keys.mjs : a dated, outside record of which signing keys an identity provider served, so that a reader of an
// idp-bind-v0 binding can decide whether the JWKS shipped next to it is the issuer's, without fetching it again later.
//
// Why this exists. trusted_identity.mjs (idp-bind-v0) names an issuer and subject as fact only when the JWKS digest is
// one the reader trusts, because anyone can mint a key, sign a token with any `iss`, and ship the matching JWKS beside
// it. A reader checking a binding months later cannot fetch the issuer's keys of that day: issuers rotate keys. And the
// digest of the JWKS bytes is not stable even while the keys are: Google served the same two keys on 2026-10-15 and
// 2026-10-16 with different bytes (sha256 5488d26f... and c863d760...), because the order of keys and members changes
// between fetches. So this records keys, not bytes: each key's RFC 7638 thumbprint, under the issuer whose discovery
// document named the jwks_uri it came from, with the first and last day it was seen. The raw bytes are kept too.
//
//   observe({ issuers, fetch, now })                    -> { observations, raw: {sha256: text} }   one run, no I/O but fetch
//   mergeIndex(index, observations)                     -> index                                   first_seen / last_seen per key
//   checkJwks({ index, issuer, document, at, windowDays }) -> { ok, keys: [...], trust }          the reader's question
//
// What a record here establishes: that on that UTC day, fetching `<issuer>/.well-known/openid-configuration` returned
// a document whose `issuer` is exactly that string and whose `jwks_uri` served keys with these thumbprints. What it does
// not: that the observer's network was not intercepted (TLS was checked by the runtime, nothing more), that a key was
// not compromised, or anything about keys on days nobody fetched. The OpenTimestamps proof next to each day's file says
// when the file existed, not that it is true.
import { createHash } from "node:crypto";

const enc = new TextEncoder();
export const sha256 = (s) => createHash("sha256").update(typeof s === "string" ? enc.encode(s) : s).digest("hex");
const b64u = (buf) => Buffer.from(buf).toString("base64url");

// RFC 7638: the required members only, in lexicographic order, no whitespace.
const REQUIRED = { RSA: ["e", "kty", "n"], EC: ["crv", "kty", "x", "y"], OKP: ["crv", "kty", "x"] };
export function thumbprint(jwk) {
  const req = jwk && REQUIRED[jwk.kty];
  if (!req) return null;
  const o = {};
  for (const m of req) { if (typeof jwk[m] !== "string" || !jwk[m]) return null; o[m] = jwk[m]; }
  return b64u(createHash("sha256").update(JSON.stringify(o, req)).digest());
}

function keysOf(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return { error: "jwks_not_json" }; }
  if (!doc || !Array.isArray(doc.keys)) return { error: "jwks_without_keys" };
  const keys = [];
  for (const k of doc.keys) {
    const t = thumbprint(k);
    if (t) keys.push({ kid: typeof k.kid === "string" ? k.kid : null, kty: k.kty, alg: typeof k.alg === "string" ? k.alg : null, thumbprint: t });
  }
  keys.sort((a, b) => (a.thumbprint < b.thumbprint ? -1 : a.thumbprint > b.thumbprint ? 1 : 0));
  return { keys, skipped: doc.keys.length - keys.length };
}

// fetch(url) -> { status, text }. Never throws for an HTTP status; a transport failure is a status of 0.
export async function observe({ issuers, fetch, now = new Date() }) {
  const at = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  const observations = [], raw = {};
  for (const iss of issuers) {
    const row = { name: iss.name, issuer: iss.issuer, fetched_at: at };
    const durl = iss.issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration";
    row.discovery_url = durl;
    const d = await fetch(durl);
    row.discovery_status = d.status;
    if (d.status !== 200) { row.error = "discovery_status"; observations.push(row); continue; }
    row.discovery_sha256 = sha256(d.text);
    let disc;
    try { disc = JSON.parse(d.text); } catch { row.error = "discovery_not_json"; observations.push(row); continue; }
    // The discovery document must name the issuer exactly (OpenID Connect Discovery 1.0, section 4.3). A mismatch is
    // recorded, not followed: keys from a document that names another issuer are not that issuer's keys.
    if (disc.issuer !== iss.issuer) { row.error = "discovery_names_another_issuer"; row.discovery_issuer = String(disc.issuer); observations.push(row); continue; }
    if (typeof disc.jwks_uri !== "string" || !disc.jwks_uri.startsWith("https://")) { row.error = "jwks_uri_not_https"; observations.push(row); continue; }
    row.jwks_uri = disc.jwks_uri;
    const j = await fetch(disc.jwks_uri);
    row.jwks_status = j.status;
    if (j.status !== 200) { row.error = "jwks_status"; observations.push(row); continue; }
    row.jwks_sha256 = sha256(j.text);
    const k = keysOf(j.text);
    if (k.error) { row.error = k.error; observations.push(row); continue; }
    row.keys = k.keys;
    if (k.skipped) row.keys_skipped = k.skipped;
    raw[row.jwks_sha256] = j.text;
    observations.push(row);
  }
  return { observations, raw };
}

// index: { "<issuer>": { "<thumbprint>": { kid, kty, alg, first_seen, last_seen, days } } }, days = distinct UTC days seen
export function mergeIndex(index, observations) {
  const out = JSON.parse(JSON.stringify(index || {}));
  for (const o of observations) {
    if (!o.keys) continue;
    const day = o.fetched_at.slice(0, 10);
    const per = (out[o.issuer] = out[o.issuer] || {});
    for (const k of o.keys) {
      const e = per[k.thumbprint];
      if (!e) { per[k.thumbprint] = { kid: k.kid, kty: k.kty, alg: k.alg, first_seen: day, last_seen: day, days: 1 }; continue; }
      if (day < e.first_seen) { e.first_seen = day; e.days++; }
      else if (day > e.last_seen) { e.last_seen = day; e.days++; }
    }
  }
  return out;
}

const DAY = 86400000;
// The reader's question: is every key in this JWKS document one the issuer was observed serving within windowDays of
// `at` (the binding's bound_at)? All keys, not only the one that signed: trusted_identity trusts a document digest, and
// a document with one extra key of somebody else's would let that somebody's tokens through under the same trust.
export function checkJwks({ index, issuer, document, at, windowDays = 7 }) {
  const per = (index || {})[issuer];
  const k = keysOf(document);
  if (k.error) return { ok: false, code: k.error, keys: [] };
  if (k.skipped) return { ok: false, code: "jwks_has_keys_without_thumbprint", keys: k.keys };
  if (!per) return { ok: false, code: "issuer_never_observed", keys: k.keys };
  const t = Date.parse(at);
  if (!Number.isFinite(t)) return { ok: false, code: "at_not_a_time", keys: k.keys };
  const keys = k.keys.map((x) => {
    const e = per[x.thumbprint];
    if (!e) return { ...x, observed: false };
    const lo = Date.parse(e.first_seen + "T00:00:00Z") - windowDays * DAY, hi = Date.parse(e.last_seen + "T23:59:59Z") + windowDays * DAY;
    return { ...x, observed: true, first_seen: e.first_seen, last_seen: e.last_seen, within_window: t >= lo && t <= hi };
  });
  const ok = keys.length > 0 && keys.every((x) => x.observed && x.within_window);
  return { ok, code: ok ? "every_key_observed" : keys.some((x) => !x.observed) ? "key_not_observed" : "observed_outside_window",
           keys, trust: ok ? issuer + "=" + sha256(document) : null };
}
