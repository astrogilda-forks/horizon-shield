// make_fixtures.mjs : the frozen idp-bind-v0 fixtures. Every key is derived from a public label (the keys are test
// keys and protect nothing), so the keys, the claims and the bindings regenerate; the ES256 signatures do not (ECDSA
// draws a random nonce), so the files on disk are the frozen artifacts, pinned by SHA256SUMS, and --check verifies
// that they are the pinned bytes and that the reference gives every expected verdict signature on them.
//
// The mock issuer is shaped like Microsoft Entra ID v2.0 (issuer https://login.microsoftonline.com/<tenant>/v2.0,
// claims aud/iss/iat/nbf/exp/sub/oid/tid/azp/ver, JWKS with kty/use/kid/x5t) but signs ES256 with a P-256 key
// derived from a label, because an RSA key cannot be derived from a seed deterministically. The verifier takes RS256
// too (idp_bind.test.mjs exercises it with a key generated at run time). Nothing here was issued by Microsoft.
//
//   node make_fixtures.mjs            writes fixtures/*.json, expected.json, SHA256SUMS
//   node make_fixtures.mjs --check    SHA256SUMS against the files, and the reference against expected.json
import { createHash, createPrivateKey, createECDH, sign as nodeSign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { makeBinding, signJwt, didKeyEncode, verify, sha256hex } from "./idp_bind.mjs";

const HERE = new URL("./", import.meta.url);
const seed = (label) => createHash("sha256").update("nenrin idp-bind-v0 test key: " + label, "utf8").digest();

function ed25519From(label) {
  const s = seed(label);
  // PKCS#8 for Ed25519: fixed 16-byte prefix + 32-byte seed
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), s]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const raw = Buffer.from(priv.export({ format: "jwk" }).x, "base64url");
  return { privateKey: priv, actorId: didKeyEncode(raw) };
}
function p256From(label) {
  const d = seed(label);
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();              // 0x04 || x || y
  const x = pub.subarray(1, 33).toString("base64url"), y = pub.subarray(33, 65).toString("base64url");
  const jwk = { kty: "EC", crv: "P-256", x, y, d: d.toString("base64url") };
  return { privateKey: createPrivateKey({ key: jwk, format: "jwk" }), x, y };
}

const TENANT = "3f1d2b6e-7c5a-4b1e-9d2f-0a8c6e4b2d11";                          // a made-up tenant id
const ISS = "https://login.microsoftonline.com/" + TENANT + "/v2.0";
const AUD = "api://nenrin-idp-bind/relying-party-1";
const SUB = "c2d9e0a1-5b7f-4c3e-8a2d-1f0e9b8c7d6a";                               // the agent's object id, as Entra would give it
const KID = "test-kid-2026-10";
const issuer = p256From("issuer signing key");
const JWKS = JSON.stringify({ keys: [{ kty: "EC", use: "sig", kid: KID, crv: "P-256", x: issuer.x, y: issuer.y,
  x5t: createHash("sha1").update(issuer.x + issuer.y).digest("base64url") }] });
const JWKS_SHA = sha256hex(JWKS);
const actor = ed25519From("actor");
const otherActor = ed25519From("other actor");
const otherIssuer = p256From("other issuer signing key");

// times: the token lives 2026-10-15T00:00:00Z .. 01:00:00Z; the binding is made at 00:30:00Z
const IAT = 1792022400, NBF = IAT, EXP = IAT + 3600, BOUND_AT = "2026-10-15T00:30:00Z";
const header = { typ: "JWT", alg: "ES256", kid: KID };
const claims = (o) => Object.assign({ aud: AUD, iss: ISS, iat: IAT, nbf: NBF, exp: EXP, sub: SUB, oid: SUB, tid: TENANT,
  azp: "0f6b1c2d-agent-app-id", ver: "2.0", xms_agent_type: "agent-identity" }, o);
const token = (o, key, h) => signJwt(h || header, claims(o || {}), key || issuer.privateKey, (h || header).alg);

function bind(tok, o) {
  return makeBinding(Object.assign({ actorPrivateKey: actor.privateKey, actorId: actor.actorId, token: tok, issuer: ISS,
    subject: SUB, audience: AUD, kid: KID, alg: "ES256", boundAt: BOUND_AT, nonce: "n-0001" }, o || {}));
}

function cases() {
  const out = [];
  const add = (name, binding, jwks, intent, refusals, findings) => out.push({ name, input: { binding, jwks }, intent,
    expect: { verdict: refusals.length ? "refused" : "accepted", refusals: [...refusals].sort(), findings: [...findings].sort() } });
  const J = { sha256: JWKS_SHA, document: JWKS };

  add("b00_bound", bind(token()), J, "a live Entra-shaped token for the subject, bound to the actor key at 00:30Z inside the token's hour; accepted, bearer_only (no cnf)", [], ["bearer_only"]);
  add("b01_cnf_bound", bind(token({ cnf: { kid: actor.actorId } })), J, "the same with a cnf claim naming the actor key (RFC 7800): accepted, cnf_bound", [], ["cnf_bound"]);
  const b02 = bind(token()); b02.nonce = "n-0002";
  add("b02_binding_changed_after_signing", b02, J, "nonce changed after signing: binding_id does not recompute and actor_sig does not verify", ["binding_recompute_mismatch", "actor_sig_invalid"], ["bearer_only"]);
  add("b03_signed_by_other_actor", bind(token(), { actorPrivateKey: otherActor.privateKey }), J, "the binding names actor_id A but is signed by key B: actor_sig_invalid (a lifted binding)", ["actor_sig_invalid"], ["bearer_only"]);
  add("b04_token_from_other_issuer_key", bind(token({}, otherIssuer.privateKey)), J, "the token is signed by a key that is not in the pinned JWKS: idp_signature_invalid", ["idp_signature_invalid"], ["bearer_only"]);
  add("b05_jwks_not_pinned_bytes", bind(token()), { sha256: JWKS_SHA, document: JWKS + "\n" }, "the JWKS document differs from the pinned digest by one byte: jwks_digest_mismatch (the issuer key is not trusted from these bytes)", ["jwks_digest_mismatch"], ["bearer_only"]);
  add("b06_subject_differs", bind(token({ sub: "someone-else", oid: "someone-else" })), J, "the token is for another subject than idp.subject says: subject_mismatch", ["subject_mismatch"], ["bearer_only"]);
  add("b07_audience_differs", bind(token({ aud: "api://another-relying-party" })), J, "the token was issued for another audience: audience_mismatch (a token for one relying party cannot bind at another)", ["audience_mismatch"], ["bearer_only"]);
  add("b08_bound_after_expiry", bind(token(), { boundAt: "2026-10-15T01:00:01Z" }), J, "bound_at one second after exp: outside_token_window", ["outside_token_window"], ["bearer_only"]);
  add("b09_bound_before_nbf", bind(token(), { boundAt: "2026-10-14T23:59:59Z" }), J, "bound_at one second before nbf: outside_token_window", ["outside_token_window"], ["bearer_only"]);
  add("b10_cnf_names_other_key", bind(token({ cnf: { kid: otherActor.actorId } })), J, "the issuer bound the token to another key: cnf_mismatch", ["cnf_mismatch"], []);
  add("b11_kid_not_in_jwks", bind(token({}, issuer.privateKey, { typ: "JWT", alg: "ES256", kid: "rotated-away" }), { kid: "rotated-away" }), J, "the token names a kid the pinned JWKS does not hold: key_not_in_jwks (a rotated key needs a new pin)", ["key_not_in_jwks"], ["bearer_only"]);
  add("b12_alg_none", bind(token().split(".").slice(0, 2).map((s, i) => i === 0 ? Buffer.from(JSON.stringify({ typ: "JWT", alg: "none", kid: KID }), "utf8").toString("base64url") : s).join(".") + ".AA", { alg: "none" }), J, "alg none with an empty signature: header says none, which is not a supported algorithm; refused twice (alg_unsupported, key lookup)", ["alg_unsupported"], ["bearer_only"]);
  add("b13_token_digest_differs", (() => { const b = bind(token()); b.token = token({ jti: "x" }); return b; })(), J, "the carried token is not the one the signed binding digests: token_digest_mismatch, and the binding no longer recomputes", ["token_digest_mismatch", "binding_recompute_mismatch", "actor_sig_invalid"], ["bearer_only"]);
  return out;
}

function main() {
  const check = process.argv.includes("--check");
  const fx = new URL("fixtures/", HERE);
  const list = cases();
  const expected = { schema: "idp-bind-v0/expected", version: "0.1.0",
    note: "verdict signature per fixture: verdict, sorted refusal codes, sorted finding codes. Keys derive from public labels in make_fixtures.mjs; the issuer is a mock in Microsoft Entra ID v2.0 shape (ES256), nothing here was issued by Microsoft",
    jwks_sha256: JWKS_SHA, cases: {} };
  const files = {};
  for (const c of list) {
    files["fixtures/" + c.name + ".json"] = JSON.stringify(c.input, null, 2) + "\n";
    expected.cases[c.name] = { intent: c.intent, expect: c.expect };
    // self-check: the reference must give the expected signature
    const r = verify(c.input);
    const got = { verdict: r.verdict, refusals: [...new Set(r.refusals.map((x) => x.code))].sort(), findings: [...new Set(r.findings.map((x) => x.code))].sort() };
    if (JSON.stringify(got) !== JSON.stringify(c.expect)) { console.error("REFERENCE DISAGREES on " + c.name + ": " + JSON.stringify(got)); process.exit(1); }
  }
  files["expected.json"] = JSON.stringify(expected, null, 2) + "\n";
  const sums = Object.keys(files).sort().map((n) => sha256hex(files[n]) + "  " + n).join("\n") + "\n";
  files["SHA256SUMS"] = sums;
  if (check) {
    let bad = 0;
    const sumsOnDisk = readFileSync(new URL("SHA256SUMS", HERE), "utf8").trim().split("\n").map((l) => l.split("  "));
    for (const [h, n] of sumsOnDisk) {
      const p = new URL(n, HERE);
      if (!existsSync(p) || sha256hex(readFileSync(p, "utf8")) !== h) { console.error("NOT THE PINNED BYTES: " + n); bad++; }
    }
    const exp = JSON.parse(readFileSync(new URL("expected.json", HERE), "utf8"));
    const names = Object.keys(exp.cases);
    if (names.length !== list.length || sumsOnDisk.length !== list.length + 1) { console.error("case count differs from the generator"); bad++; }
    for (const name of names) {
      const input = JSON.parse(readFileSync(new URL("fixtures/" + name + ".json", HERE), "utf8"));
      const r = verify(input);
      const got = { verdict: r.verdict, refusals: [...new Set(r.refusals.map((x) => x.code))].sort(), findings: [...new Set(r.findings.map((x) => x.code))].sort() };
      if (JSON.stringify(got) !== JSON.stringify(exp.cases[name].expect)) { console.error("REFERENCE DISAGREES on " + name + ": " + JSON.stringify(got)); bad++; }
    }
    console.log(bad ? bad + " problems" : "fixtures are the pinned bytes and the reference reproduces " + names.length + "/" + names.length + " verdict signatures");
    process.exit(bad ? 1 : 0);
  }
  mkdirSync(fx, { recursive: true });
  for (const [n, body] of Object.entries(files)) writeFileSync(new URL(n, HERE), body);
  console.log("wrote " + list.length + " fixtures, expected.json, SHA256SUMS; jwks sha256 " + JWKS_SHA);
}
main();
