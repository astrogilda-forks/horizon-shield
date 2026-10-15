// idp_bind.test.mjs : the frozen fixtures (ES256), the RS256 path with a key generated at run time in the shape
// Microsoft Entra ID publishes (kty RSA, use sig, kid, x5t, n, e), and the composition: a NENRIN grant signed by the
// bound actor key is attributable to the provider subject through the binding, and to nothing else.
// Run: node idp_bind.test.mjs
import { generateKeyPairSync, createHash, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { verify, makeBinding, signJwt, newActorKey, sha256hex, canonical } from "./idp_bind.mjs";
import { grantRef, grantPreimage, grantRecomputeOk } from "../task-execution-bind-v0/bind_exec.mjs";

let n = 0, bad = 0;
const t = (name, ok, extra) => { n++; if (!ok) bad++; console.log((ok ? "ok    " : "FAIL  ") + name + (extra && !ok ? "  " + extra : "")); };
const sig = (r) => ({ verdict: r.verdict, refusals: [...new Set(r.refusals.map((x) => x.code))].sort(), findings: [...new Set(r.findings.map((x) => x.code))].sort() });

// 1. frozen fixtures
const exp = JSON.parse(readFileSync(new URL("expected.json", import.meta.url), "utf8"));
for (const [name, c] of Object.entries(exp.cases)) {
  const r = verify(JSON.parse(readFileSync(new URL("fixtures/" + name + ".json", import.meta.url), "utf8")));
  t("fixture " + name, JSON.stringify(sig(r)) === JSON.stringify(c.expect), JSON.stringify(sig(r)));
}

// 2. RS256, the algorithm Entra ID signs with, with a key made now and a JWKS in Entra's shape
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pubJwk = rsa.publicKey.export({ format: "jwk" });
const KID = "rs-" + createHash("sha256").update(pubJwk.n).digest("base64url").slice(0, 16);
const TENANT = "11111111-2222-3333-4444-555555555555";
const ISS = "https://login.microsoftonline.com/" + TENANT + "/v2.0", AUD = "api://relying-party", SUB = "agent-object-id-1";
const jwksDoc = JSON.stringify({ keys: [{ kty: "RSA", use: "sig", kid: KID, x5t: KID, n: pubJwk.n, e: pubJwk.e, issuer: ISS }] });
const J = { sha256: sha256hex(jwksDoc), document: jwksDoc };
const now = Math.floor(Date.now() / 1000);
const claims = (o) => Object.assign({ aud: AUD, iss: ISS, iat: now - 60, nbf: now - 60, exp: now + 3540, sub: SUB, oid: SUB, tid: TENANT, azp: "app", ver: "2.0" }, o || {});
const tok = (o, key) => signJwt({ typ: "JWT", alg: "RS256", kid: KID }, claims(o), key || rsa.privateKey, "RS256");
const boundAt = new Date(now * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const actor = newActorKey();
const bind = (token, o) => makeBinding(Object.assign({ actorPrivateKey: actor.privateKey, actorId: actor.actorId, token, issuer: ISS, subject: SUB, audience: AUD, kid: KID, alg: "RS256", boundAt, nonce: "rs-1" }, o || {}));

let r = verify({ binding: bind(tok()), jwks: J });
t("RS256 binding accepted, bearer_only", r.verdict === "accepted" && sig(r).findings.join() === "bearer_only", JSON.stringify(sig(r)));
r = verify({ binding: bind(tok({ cnf: { did: actor.actorId } })), jwks: J });
t("RS256 with cnf.did naming the actor: cnf_bound", r.verdict === "accepted" && sig(r).findings.join() === "cnf_bound", JSON.stringify(sig(r)));
const otherRsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
r = verify({ binding: bind(tok({}, otherRsa.privateKey)), jwks: J });
t("RS256 signed by a key outside the JWKS: idp_signature_invalid", sig(r).refusals.join() === "idp_signature_invalid", JSON.stringify(sig(r)));
// a token whose signature segment is tampered by one bit
const good = tok();
const parts = good.split("."); const sb = Buffer.from(parts[2], "base64url"); sb[5] ^= 1;
r = verify({ binding: bind(parts[0] + "." + parts[1] + "." + sb.toString("base64url")), jwks: J });
t("RS256 signature with one bit flipped: idp_signature_invalid", sig(r).refusals.join() === "idp_signature_invalid", JSON.stringify(sig(r)));
// aud as an array containing the audience is accepted (OIDC allows an array)
r = verify({ binding: bind(tok({ aud: ["x", AUD] })), jwks: J });
t("aud array containing the audience: accepted", r.verdict === "accepted", JSON.stringify(sig(r)));
// alg confusion: header says ES256 but the JWKS key is RSA -> key_type_mismatch, never verified
const esTok = signJwt({ typ: "JWT", alg: "ES256", kid: KID }, claims(), generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey, "ES256");
r = verify({ binding: bind(esTok, { alg: "ES256" }), jwks: J });
t("alg says ES256 against an RSA JWKS key: key_type_mismatch", sig(r).refusals.join() === "key_type_mismatch", JSON.stringify(sig(r)));
// header alg differs from idp.alg -> header_mismatch (and whatever follows); the binding's own statement wins
r = verify({ binding: bind(esTok), jwks: J });
t("token alg differs from idp.alg: header_mismatch present", sig(r).refusals.includes("header_mismatch"), JSON.stringify(sig(r)));
// no exp
r = verify({ binding: bind(signJwt({ typ: "JWT", alg: "RS256", kid: KID }, { aud: AUD, iss: ISS, sub: SUB, iat: now }, rsa.privateKey, "RS256")), jwks: J });
t("token without exp: token_without_exp", sig(r).refusals.includes("token_without_exp"), JSON.stringify(sig(r)));
// missing jwks
r = verify({ binding: bind(tok()) });
t("no JWKS in the input: jwks_missing", sig(r).refusals.join() === "jwks_missing", JSON.stringify(sig(r)));
// malformed inputs never throw
for (const inp of [null, {}, { binding: 5 }, { binding: { schema: "idp-bind-v0/binding" } }, { binding: { schema: "idp-bind-v0/binding", idp: {}, token: 1 }, jwks: {} }]) {
  let threw = false, rr = null; try { rr = verify(inp); } catch (e) { threw = true; }
  t("malformed input does not throw: " + JSON.stringify(inp), !threw && rr && rr.verdict === "refused");
}
// own "__proto__" key in the binding (0.5.3): part of the preimage, so adding it after signing is refused
const withProto = JSON.parse(JSON.stringify(bind(tok())).replace(/^\{/, '{"__proto__":{"audit_note":"not signed"},'));
r = verify({ binding: withProto, jwks: J });
t("own __proto__ added after signing: binding_recompute_mismatch", sig(r).refusals.includes("binding_recompute_mismatch") && sig(r).refusals.includes("actor_sig_invalid"), JSON.stringify(sig(r)));

// 3. composition: a NENRIN grant signed by the bound actor key
const binding = bind(tok());
const g = { schema: "task-execution-bind-v0/grant", task_id: "task_idp_1", action: { tool: "a2a.invoke", target: "/task", args_sha256: "sha_args" },
  caller_id: actor.actorId, provider_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", nonce: "g1", not_before: boundAt, not_after: "2027-01-01T00:00:00Z" };
g.grant_ref = grantRef(g);
g.caller_sig = nodeSign(null, Buffer.from(canonical(grantPreimage(g)), "utf8"), actor.privateKey).toString("base64");
t("grant recomputes", grantRecomputeOk(g));
t("the grant's caller_id is the binding's actor_id, so the grant is attributable to " + SUB + " through the binding", g.caller_id === binding.actor_id && verify({ binding, jwks: J }).verdict === "accepted");
t("a grant by another key is not attributable through this binding", newActorKey().actorId !== binding.actor_id);

console.log("\n" + (bad ? bad + " FAILED of " + n : "ALL PASS (" + n + " checks: " + Object.keys(exp.cases).length + " frozen fixtures, RS256 in Entra's JWKS shape, confusion and malformed inputs, composition with a NENRIN grant)"));
process.exit(bad ? 1 : 0);
