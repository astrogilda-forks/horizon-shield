// idp-bind-v0 : bind an identity an outside identity provider issued (an OIDC / OAuth 2.0 JWT: Microsoft Entra
// Agent ID, Entra ID, any issuer with a JWKS) to the Ed25519 key a NENRIN actor signs with, in a record a third
// party can check offline, outside the provider's own tenant, with the provider's public keys pinned by digest.
//
// Why: NENRIN records say WHICH KEY asserted (did:key). An enterprise says which AGENT acted, by its identity
// provider's subject. This record is the hinge between the two: "the holder of this provider-issued identity, at this
// time, declared this did:key as its NENRIN actor key, and proved possession of that key". After it, every NENRIN
// record signed by that did:key is attributable to that provider subject, by anyone who can recompute this file.
//
// Honest line: a JWT is a BEARER credential. The binding proves (a) possession of the NENRIN key (actor_sig over the
// binding) and (b) that the token is genuine and was live at bound_at (the issuer's signature, iss/sub/aud, exp/nbf).
// It proves possession of the provider identity only as far as holding the token does: whoever holds a live token
// can bind it to any key. A token whose audience is the relying party that accepts the binding, and that is short
// lived, limits that to its own lifetime; a token with a cnf claim (RFC 7800) that names the actor key proves
// possession and the binding then says so (finding: cnf_bound). Nothing here reaches the network: the JWKS bytes come
// in with the input and are pinned by sha256, so the check is the same tomorrow as today.
//
// Record (idp-bind-v0/binding). Derived fields (outside the preimage): binding_id, actor_sig.
//   schema        "idp-bind-v0/binding"
//   actor_id      did:key of the NENRIN actor (Ed25519)
//   idp           { issuer, subject, audience, kid, alg }   what the token must say, copied here so the binding is
//                 readable without decoding the token, and checked against the token
//   token_sha256  sha256 of the compact JWT's ASCII bytes
//   token         the compact JWT (carried; a verifier needs it to check the issuer's signature)
//   bound_at      RFC3339 UTC "...Z"; must lie inside [nbf, exp] of the token
//   nonce         caller chosen string
// Input to verify(): { binding, jwks: { sha256, document }, now? } where document is the issuer's JWKS text as
// fetched (its sha256 must equal jwks.sha256, which the relying party pins when it accepts the binding).
import { createHash, createPublicKey, verify as nodeVerify, sign as nodeSign, generateKeyPairSync } from "node:crypto";
import { canonical, sha256hex, withoutDerived, sigBytes } from "../task-delegation-bind-v0/bind.mjs";
import { isRfc3339Utc } from "../task-execution-bind-v0/bind_exec.mjs";
import { publicKeyFromDidKey, didKeyEncode } from "../task-delegation-bind-v0/verify_fixture.mjs";

export const IDP_BIND_VERSION = "0.1.0";
export const SCHEMA = "idp-bind-v0/binding";
const DERIVED = ["binding_id", "actor_sig"];
const ALGS = { RS256: { type: "rsa", hash: "sha256" }, ES256: { type: "ec", hash: "sha256", crv: "P-256" } };

export const bindingPreimage = (b) => withoutDerived(b, DERIVED);
export const bindingId = (b) => sha256hex(canonical(bindingPreimage(b)));

const b64u = (s) => Buffer.from(s, "base64url");
const B64U = /^[A-Za-z0-9_-]+$/;

// parseJwt(token): the three segments, decoded strictly (base64url without padding, JSON objects), or null.
export function parseJwt(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((p) => p.length > 0 && B64U.test(p))) return null;
  let header, payload;
  try {
    header = JSON.parse(b64u(parts[0]).toString("utf8"));
    payload = JSON.parse(b64u(parts[1]).toString("utf8"));
  } catch (e) { return null; }
  if (!header || typeof header !== "object" || Array.isArray(header)) return null;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  // the signature segment must round-trip (canonical base64url, no stray bits)
  const sig = b64u(parts[2]);
  if (sig.toString("base64url") !== parts[2]) return null;
  return { header, payload, signingInput: parts[0] + "." + parts[1], signature: sig };
}

// jwkFromJwks(document, kid, alg): the one key the header names, as a KeyObject, or null with a reason.
export function jwkFromJwks(document, kid, alg) {
  let doc;
  try { doc = JSON.parse(document); } catch (e) { return { key: null, reason: "jwks_not_json" }; }
  if (!doc || !Array.isArray(doc.keys)) return { key: null, reason: "jwks_without_keys" };
  const matches = doc.keys.filter((k) => k && k.kid === kid);
  if (matches.length !== 1) return { key: null, reason: matches.length ? "kid_ambiguous" : "key_not_in_jwks" };
  const jwk = matches[0];
  if (jwk.use != null && jwk.use !== "sig") return { key: null, reason: "key_not_for_signing" };
  if (jwk.alg != null && jwk.alg !== alg) return { key: null, reason: "key_alg_mismatch" };
  const want = ALGS[alg];
  if (!want) return { key: null, reason: "alg_unsupported" };
  if (want.type === "rsa" && jwk.kty !== "RSA") return { key: null, reason: "key_type_mismatch" };
  if (want.type === "ec" && (jwk.kty !== "EC" || jwk.crv !== want.crv)) return { key: null, reason: "key_type_mismatch" };
  try {
    const pub = want.type === "rsa" ? { kty: "RSA", n: jwk.n, e: jwk.e } : { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
    return { key: createPublicKey({ key: pub, format: "jwk" }), reason: null };
  } catch (e) { return { key: null, reason: "key_unusable" }; }
}

function verifyJwtSignature(parsed, key, alg) {
  const want = ALGS[alg];
  if (!want) return false;
  try {
    if (want.type === "rsa") return nodeVerify("sha256", Buffer.from(parsed.signingInput, "ascii"), { key, padding: 1 }, parsed.signature);
    // ES256: JOSE signatures are raw r||s (64 bytes)
    if (parsed.signature.length !== 64) return false;
    return nodeVerify("sha256", Buffer.from(parsed.signingInput, "ascii"), { key, dsaEncoding: "ieee-p1363" }, parsed.signature);
  } catch (e) { return false; }
}

const audMatches = (aud, want) => (Array.isArray(aud) ? aud.includes(want) : aud === want);
const isInt = (v) => typeof v === "number" && Number.isInteger(v) && Number.isFinite(v);

// verify(input): the report. verdict accepted only when every check passes; refusals are codes, in the order found.
export function verify(input) {
  const refusals = [], findings = [], establishes = [], does_not_establish = [];
  const refuse = (code, why) => refusals.push({ code, why });
  const find = (code, why) => findings.push({ code, why });
  const b = input && input.binding;
  if (!b || typeof b !== "object" || Array.isArray(b)) {
    refuse("binding_not_object", "input.binding is not an object");
    return report(refusals, findings, establishes, does_not_establish, null);
  }
  if (b.schema !== SCHEMA) refuse("bad_schema", "schema must be " + SCHEMA);
  const idp = b.idp;
  const idpOk = idp && typeof idp === "object" && !Array.isArray(idp)
    && ["issuer", "subject", "audience", "kid", "alg"].every((k) => typeof idp[k] === "string" && idp[k].length > 0);
  if (!idpOk) refuse("bad_idp", "idp must carry issuer, subject, audience, kid and alg as non-empty strings");
  if (typeof b.nonce !== "string" || !b.nonce) refuse("bad_nonce", "nonce must be a non-empty string");
  if (!isRfc3339Utc(b.bound_at)) refuse("bad_bound_at", "bound_at must be a strict RFC3339 UTC instant");

  // 1. the binding is what its id says, and the actor signed it
  let id = null;
  try { id = bindingId(b); } catch (e) { refuse("canonical_refused", String(e.message || e)); }
  if (id !== null) {
    if (b.binding_id !== id) refuse("binding_recompute_mismatch", "binding_id is not sha256 of the canonical preimage");
    let pub = null;
    try { pub = publicKeyFromDidKey(b.actor_id); } catch (e) { refuse("actor_id_unresolvable", "actor_id is not a usable Ed25519 did:key"); }
    const sig = sigBytes(b.actor_sig);
    if (pub && !sig) refuse("actor_sig_malformed", "actor_sig is not canonical base64 of 64 bytes");
    if (pub && sig) {
      let ok = false;
      try { ok = nodeVerify(null, Buffer.from(canonical(bindingPreimage(b)), "utf8"), pub, sig); } catch (e) { ok = false; }
      if (!ok) refuse("actor_sig_invalid", "actor_sig does not verify under actor_id over the canonical preimage");
      else establishes.push("the holder of the private key of " + b.actor_id + " signed this binding (possession of the NENRIN actor key)");
    }
  }

  // 2. the token is the one the binding names, and it is a well formed JWT
  if (typeof b.token !== "string" || sha256hex(b.token) !== b.token_sha256) refuse("token_digest_mismatch", "token_sha256 is not sha256 of token");
  const jwt = parseJwt(b.token);
  if (!jwt) refuse("token_malformed", "token is not a compact JWS with three base64url segments and JSON header and payload");
  let claimsOk = false;
  if (jwt && idpOk) {
    const h = jwt.header, p = jwt.payload;
    const before = refusals.length;
    if (h.alg !== idp.alg || h.kid !== idp.kid) refuse("header_mismatch", "token header alg/kid differ from idp.alg/idp.kid");
    if (!ALGS[idp.alg]) refuse("alg_unsupported", "idp.alg must be RS256 or ES256");
    if (p.iss !== idp.issuer) refuse("issuer_mismatch", "token iss differs from idp.issuer");
    if (p.sub !== idp.subject) refuse("subject_mismatch", "token sub differs from idp.subject");
    if (!audMatches(p.aud, idp.audience)) refuse("audience_mismatch", "token aud does not contain idp.audience");
    if (!isInt(p.exp)) refuse("token_without_exp", "token has no integer exp");
    if (p.nbf != null && !isInt(p.nbf)) refuse("bad_nbf", "token nbf is not an integer");
    if (isRfc3339Utc(b.bound_at) && isInt(p.exp) && (p.nbf == null || isInt(p.nbf))) {
      const t = Math.floor(Date.parse(b.bound_at) / 1000);
      const nbf = p.nbf != null ? p.nbf : (isInt(p.iat) ? p.iat : null);
      if (t > p.exp || (nbf != null && t < nbf)) refuse("outside_token_window", "bound_at is not inside the token's [nbf (or iat), exp]");
    }
    claimsOk = refusals.length === before;
    // cnf (RFC 7800): if the issuer bound the token to a key, it must be this actor key
    if (p.cnf != null) {
      const cnf = p.cnf && typeof p.cnf === "object" ? p.cnf : {};
      const named = typeof b.actor_id === "string" && (cnf.kid === b.actor_id || cnf.did === b.actor_id);
      if (!named) refuse("cnf_mismatch", "token cnf names a key other than actor_id");
      else find("cnf_bound", "the issuer bound this token to the actor key (RFC 7800 cnf), so the identity side is possession-proven");
    } else {
      find("bearer_only", "the token carries no cnf: it binds whoever held it while it was live, within its audience and lifetime");
    }
  }

  // 3. the issuer signed the token, under a key in the pinned JWKS
  const jwks = input.jwks;
  const jwksOk = jwks && typeof jwks === "object" && typeof jwks.document === "string" && typeof jwks.sha256 === "string";
  if (!jwksOk) refuse("jwks_missing", "input.jwks must carry the issuer's JWKS document and its pinned sha256");
  else if (sha256hex(jwks.document) !== jwks.sha256) refuse("jwks_digest_mismatch", "the JWKS document is not the pinned bytes");
  else if (jwt && idpOk) {
    const { key, reason } = jwkFromJwks(jwks.document, idp.kid, idp.alg);
    if (!key) refuse(reason, "no usable signing key for kid " + idp.kid + " in the pinned JWKS (" + reason + ")");
    else if (!verifyJwtSignature(jwt, key, idp.alg)) refuse("idp_signature_invalid", "the token signature does not verify under the pinned JWKS key");
    else if (claimsOk) establishes.push("the issuer " + idp.issuer + " signed a token for subject " + idp.subject + " (audience " + idp.audience + ") that was live at " + b.bound_at + ", under a key in the JWKS pinned at " + jwks.sha256.slice(0, 16));
  }

  does_not_establish.push("that the subject performed any action: this binds a key to an identity, nothing more");
  does_not_establish.push("that the identity provider's statement about the subject is true; only that it made it");
  if (!findings.some((f) => f.code === "cnf_bound")) does_not_establish.push("possession of the provider identity beyond holding a live bearer token at bound_at");
  return report(refusals, findings, establishes, does_not_establish, id);
}

function report(refusals, findings, establishes, does_not_establish, id) {
  return { schema: "idp-bind-v0/report", version: IDP_BIND_VERSION, verdict: refusals.length ? "refused" : "accepted",
    binding_id: id, refusals, findings, establishes, does_not_establish };
}

// ---- making one (the agent's side; test and demo use) ----
export function makeBinding({ actorPrivateKey, actorId, token, issuer, subject, audience, kid, alg, boundAt, nonce }) {
  const b = { schema: SCHEMA, actor_id: actorId, idp: { issuer, subject, audience, kid, alg },
    token_sha256: sha256hex(token), token, bound_at: boundAt, nonce };
  b.binding_id = bindingId(b);
  b.actor_sig = nodeSign(null, Buffer.from(canonical(bindingPreimage(b)), "utf8"), actorPrivateKey).toString("base64");
  return b;
}

// signJwt(header, payload, privateKey, alg): a compact JWS (RS256 or ES256), for a mock issuer.
export function signJwt(header, payload, privateKey, alg) {
  const enc = (o) => Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
  const signingInput = enc(header) + "." + enc(payload);
  const want = ALGS[alg];
  const sig = want.type === "rsa"
    ? nodeSign("sha256", Buffer.from(signingInput, "ascii"), { key: privateKey, padding: 1 })
    : nodeSign("sha256", Buffer.from(signingInput, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + sig.toString("base64url");
}

export function newActorKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  return { privateKey, actorId: didKeyEncode(raw) };
}

export { didKeyEncode, sha256hex, canonical };
