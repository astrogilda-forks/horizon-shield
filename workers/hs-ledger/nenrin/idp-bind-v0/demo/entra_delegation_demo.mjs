// entra_delegation_demo.mjs : the demonstration SPEC.md ends with, end to end, in one process.
//
//   Two agents with provider identities (here a mock issuer in Microsoft Entra ID v2.0 shape; see --issuer below for
//   the real one) each bind their NENRIN actor key to their identity (idp-bind-v0). Agent A then delegates an action
//   to agent B as a NENRIN grant; B executes and signs a receipt (task-execution-bind-v0). A reader with NO provider
//   credential, holding only the two bindings, the pinned JWKS bytes and the two records, verifies all four and
//   prints what is established: which provider subject authorized what, which provider subject executed it, and
//   that the execution matched the authorization.
//
//   node entra_delegation_demo.mjs                 mock tenant, everything generated here, writes out/ next to this file
//   node entra_delegation_demo.mjs --verify out/   the reader alone: re-verifies what a previous run wrote
//
// With a real tenant the only things that change are the two tokens and the JWKS: each agent obtains its token
// from https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token (client credentials, scope <audience>/.default)
// and the relying party fetches https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys once and pins its
// sha256. Pass them with --token-a <file> --token-b <file> --jwks <file> (and --audience <uri> when the binding should
// name an audience other than the token's aud); nothing else in this file reads the network, and the reader step is
// identical. A real Entra token for a custom API is a v2.0 token (iss .../v2.0) only when the API app registration sets
// requestedAccessTokenVersion = 2; otherwise iss is https://sts.windows.net/<tenant>/, and the kid is in the same JWKS.
// No claim about Entra's behaviour is made beyond the published token format; the mock issuer signs RS256 like Entra.
import { generateKeyPairSync, createHash, sign as nodeSign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { verify as verifyBinding, makeBinding, signJwt, newActorKey, sha256hex, canonical } from "../idp_bind.mjs";
import { grantRef, receiptId, grantPreimage, receiptPreimage } from "../../task-execution-bind-v0/bind_exec.mjs";
import { verifyProvenance, didKeyResolver } from "../../sdk/nenrin_verify.mjs";

const args = process.argv.slice(2);
const arg = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const OUT = new URL((arg("--verify") || "out") + "/", import.meta.url);
const now = Math.floor(Date.now() / 1000);
const iso = (s) => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

function mockTenant() {
  const tenant = "7a1c3e55-0b2d-4f6e-9a8c-2d4f6e8a0b1c";
  const iss = "https://login.microsoftonline.com/" + tenant + "/v2.0";
  const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pub = key.publicKey.export({ format: "jwk" });
  const kid = createHash("sha256").update(pub.n).digest("base64url").slice(0, 20);
  const jwks = JSON.stringify({ keys: [{ kty: "RSA", use: "sig", kid, x5t: kid, n: pub.n, e: pub.e, issuer: iss }] });
  const token = (sub, aud, appId) => signJwt({ typ: "JWT", alg: "RS256", kid },
    { aud, iss, iat: now - 30, nbf: now - 30, exp: now + 3570, sub, oid: sub, tid: tenant, azp: appId, ver: "2.0", xms_agent_type: "agent-identity" }, key.privateKey, "RS256");
  return { iss, kid, jwks, token };
}

function run() {
  mkdirSync(OUT, { recursive: true });
  const T = mockTenant();
  const payloadOf = (tok) => JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString());
  const realA = arg("--token-a") ? readFileSync(arg("--token-a"), "utf8").trim() : null;
  const realB = arg("--token-b") ? readFileSync(arg("--token-b"), "utf8").trim() : null;
  // the relying party both agents present to: given, or read from a real token's aud (string or first element), or the mock's
  const AUD = arg("--audience") || (realA ? [].concat(payloadOf(realA).aud)[0] : "api://nenrin-relying-party");
  const A = { sub: "0a9f1c2e-agent-a-object-id", app: "app-a", key: newActorKey() };
  const B = { sub: "5b3d7e1f-agent-b-object-id", app: "app-b", key: newActorKey() };
  const boundAt = iso(now);
  const tokA = realA || T.token(A.sub, AUD, A.app);
  const tokB = realB || T.token(B.sub, AUD, B.app);
  const jwksDoc = arg("--jwks") ? readFileSync(arg("--jwks"), "utf8") : T.jwks;
  if (realA) { A.sub = payloadOf(realA).sub; B.sub = payloadOf(tokB).sub; }
  const jwks = { sha256: sha256hex(jwksDoc), document: jwksDoc };
  const kid = JSON.parse(Buffer.from(tokA.split(".")[0], "base64url").toString()).kid;
  const iss = JSON.parse(Buffer.from(tokA.split(".")[1], "base64url").toString()).iss;
  const bind = (ag, tok) => makeBinding({ actorPrivateKey: ag.key.privateKey, actorId: ag.key.actorId, token: tok, issuer: iss,
    subject: JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString()).sub, audience: AUD, kid, alg: "RS256", boundAt, nonce: ag.app + "-1" });
  const bindingA = bind(A, tokA), bindingB = bind(B, tokB);

  // A delegates to B: a NENRIN grant signed by A's actor key, naming B's actor key as the executor
  const task = "task_entra_demo_" + now;
  const action = { tool: "a2a.invoke", target: "/invoices/pay", args_sha256: sha256hex(canonical({ invoice: "INV-2026-1015", amount_jpy: 120000 })) };
  const grant = { schema: "task-execution-bind-v0/grant", task_id: task, action, caller_id: A.key.actorId, provider_id: B.key.actorId,
    nonce: "g-1", not_before: iso(now - 60), not_after: iso(now + 3600) };
  grant.grant_ref = grantRef(grant);
  grant.caller_sig = nodeSign(null, Buffer.from(canonical(grantPreimage(grant)), "utf8"), A.key.privateKey).toString("base64");
  // B executes and signs the receipt, committing to the grant by hash
  const receipt = { schema: "task-execution-bind-v0/receipt", task_id: task, grant_ref: grant.grant_ref, executed_action: action,
    outcome: { status: "completed", result_sha256: sha256hex("payment-reference-77f2"), evidence: { kind: "ledger_record", ref: "f".repeat(64), system: "ledger.horizonshield.dev" } },
    provider_id: B.key.actorId, executed_at: iso(now + 5) };
  receipt.receipt_id = receiptId(receipt);
  receipt.provider_sig = nodeSign(null, Buffer.from(canonical(receiptPreimage(receipt)), "utf8"), B.key.privateKey).toString("base64");

  const w = (n, o) => writeFileSync(new URL(n, OUT), JSON.stringify(o, null, 2) + "\n");
  w("binding_a.json", bindingA); w("binding_b.json", bindingB); w("jwks.json", jwks);
  w("bundle.json", { task_id: task, grant, receipt });
  console.log("wrote " + OUT.pathname + ": binding_a.json, binding_b.json, jwks.json (sha256 " + jwks.sha256.slice(0, 16) + "), bundle.json");
  console.log("A = " + A.key.actorId + " <-> " + iss + " / " + A.sub);
  console.log("B = " + B.key.actorId + " <-> " + iss + " / " + B.sub + "\n");
  reader();
}

// The reader: no key of its own, no credential, no network. Four files in, one verdict out.
function reader() {
  const r = (n) => JSON.parse(readFileSync(new URL(n, OUT), "utf8"));
  const bindingA = r("binding_a.json"), bindingB = r("binding_b.json"), jwks = r("jwks.json"), bundle = r("bundle.json");
  const ra = verifyBinding({ binding: bindingA, jwks }), rb = verifyBinding({ binding: bindingB, jwks });
  const rp = verifyProvenance(Object.assign({}, bundle, { resolve: didKeyResolver }));
  const sig = (p) => p.verdict + " " + JSON.stringify([...new Set(p.refusals.map((x) => x.code))].sort()) + " " + JSON.stringify([...new Set(p.findings.map((x) => x.code))].sort());
  console.log("reader:");
  console.log("  binding A: " + sig(ra));
  console.log("  binding B: " + sig(rb));
  console.log("  NENRIN grant + receipt: " + sig(rp));
  const g = bundle.grant, rc = bundle.receipt;
  const ok = ra.verdict === "accepted" && rb.verdict === "accepted" && rp.verdict === "accepted"
    && g.caller_id === bindingA.actor_id && g.provider_id === bindingB.actor_id && rc.provider_id === bindingB.actor_id;
  if (!ok) { console.log("\nNOT ESTABLISHED: one of the four checks refused, or the keys do not line up"); process.exit(1); }
  console.log("\nestablished, by anyone holding these four files and no Microsoft credential:");
  console.log("  " + bindingA.idp.issuer + " / " + bindingA.idp.subject + " (as " + g.caller_id.slice(0, 20) + "...) authorized " + g.action.tool + " " + g.action.target + " for " + g.task_id + ", window " + g.not_before + " .. " + g.not_after);
  console.log("  " + bindingB.idp.issuer + " / " + bindingB.idp.subject + " (as " + rc.provider_id.slice(0, 20) + "...) reported executing that action at " + rc.executed_at + ", receipt bound to grant " + g.grant_ref.slice(0, 16) + "...");
  console.log("  the executed action equals the authorized one (E1), the receipt commits to the grant by hash (E3), the executor is the one the grant named");
  console.log("not established: that the payment happened in the world (a signature proves who asserted); whether the subjects are who the tenant says (only that the issuer said so); and, without cnf, possession of the provider identity beyond holding a live token (findings: " + JSON.stringify([...new Set(ra.findings.concat(rb.findings).map((f) => f.code))]) + ")");
}

if (arg("--verify")) reader(); else run();
