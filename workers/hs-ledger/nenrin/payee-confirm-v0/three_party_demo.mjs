// three_party_demo.mjs : payer, executor and payee, each with an identity its provider issued, each binding its own
// NENRIN key (idp-bind-v0). The payer grants "pay invoice INV-2026-1015, 120,000 JPY", the executor signs the receipt,
// the payee signs the confirmation (payee-confirm-v0). A reader with no credential checks all of it.
//
//   node three_party_demo.mjs --out out/                         a mock issuer in GitHub Actions' token shape
//   node three_party_demo.mjs --out out/ --token-a a --token-b b --token-c c --jwks jwks.txt   real tokens
//   node three_party_demo.mjs --verify out/ [--trust <issuer>=<jwks sha256>]   the reader alone, offline
//
// The reader names a party's identity only for an issuer whose JWKS digest it is told to trust (--trust); the
// jwks.json in the folder is the bundle's own copy and cannot vouch for itself. Without --trust the roles are reported
// self-pinned. With the mock issuer, --trust its digest to see the bound report.
//
// In GitHub Actions the three tokens come from three jobs in three environments, so the three subjects are three
// different workflow identities (repo:<owner>/<repo>:environment:<name>). Nothing else in this file reads the network.
import { generateKeyPairSync, createHash, sign as nodeSign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseTrust } from "../idp-bind-v0/trusted_identity.mjs";
import { parseStrict } from "../sdk/nenrin_verify.mjs";
import { makeBinding, signJwt, newActorKey, sha256hex, canonical } from "../idp-bind-v0/idp_bind.mjs";
import { grantRef, receiptId, grantPreimage, receiptPreimage } from "../task-execution-bind-v0/bind_exec.mjs";
import { makeConfirmation, verify } from "./payee_confirm.mjs";

const iso = (s) => new Date(s * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const payloadOf = (tok) => JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString());
const headerOf = (tok) => JSON.parse(Buffer.from(tok.split(".")[0], "base64url").toString());

export function mockIssuer(now) {
  const iss = "https://token.actions.githubusercontent.com";
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pub = rsa.publicKey.export({ format: "jwk" });
  const kid = createHash("sha256").update(pub.n).digest("hex").slice(0, 40).toUpperCase();
  const jwks = JSON.stringify({ keys: [{ kty: "RSA", alg: "RS256", use: "sig", kid, n: pub.n, e: pub.e }] });
  const token = (env, aud) => signJwt({ typ: "JWT", alg: "RS256", kid }, { iss, aud, iat: now - 5, nbf: now - 5, exp: now + 295,
    sub: "repo:example/repo:environment:" + env, repository: "example/repo", environment: env, workflow: "demo", run_id: "0" }, rsa.privateKey, "RS256");
  return { jwks, token };
}

// buildRun: the four parties' records from three tokens and the issuer's JWKS text
export function buildRun({ tokA, tokB, tokC, jwksDoc, now }) {
  const at = iso(now);
  const parties = { payer: { tok: tokA }, executor: { tok: tokB }, payee: { tok: tokC } };
  const bindings = {};
  for (const [role, p] of Object.entries(parties)) {
    p.key = newActorKey();
    const pl = payloadOf(p.tok), hd = headerOf(p.tok);
    bindings[role] = makeBinding({ actorPrivateKey: p.key.privateKey, actorId: p.key.actorId, token: p.tok, issuer: pl.iss, subject: pl.sub,
      audience: [].concat(pl.aud)[0], kid: hd.kid, alg: hd.alg, boundAt: at, nonce: role + "-1" });
  }
  const invoice = { invoice: "INV-2026-1015", amount_jpy: 120000 };
  const task = "task_three_party_" + now;
  const action = { tool: "a2a.invoke", target: "/invoices/pay", args_sha256: sha256hex(canonical(invoice)) };
  const grant = { schema: "task-execution-bind-v0/grant", task_id: task, action, caller_id: parties.payer.key.actorId,
    provider_id: parties.executor.key.actorId, nonce: "g-1", not_before: iso(now - 60), not_after: iso(now + 3600) };
  grant.grant_ref = grantRef(grant);
  grant.caller_sig = nodeSign(null, Buffer.from(canonical(grantPreimage(grant)), "utf8"), parties.payer.key.privateKey).toString("base64");
  const receipt = { schema: "task-execution-bind-v0/receipt", task_id: task, grant_ref: grant.grant_ref, executed_action: action,
    outcome: { status: "completed", result_sha256: sha256hex("transfer-request-accepted") }, provider_id: parties.executor.key.actorId, executed_at: iso(now + 2) };
  receipt.receipt_id = receiptId(receipt);
  receipt.provider_sig = nodeSign(null, Buffer.from(canonical(receiptPreimage(receipt)), "utf8"), parties.executor.key.privateKey).toString("base64");
  const confirmation = makeConfirmation({ payeePrivateKey: parties.payee.key.privateKey, payeeId: parties.payee.key.actorId, grant, receipt, invoice,
    rail: "bank_transfer", receivedAt: iso(now + 4), nonce: "c-1" });
  return { bindings, jwks: { sha256: sha256hex(jwksDoc), document: jwksDoc }, bundle: { task_id: task, grant, receipt }, confirmation };
}

export function readerReport(run, trusted) {
  return verify({ confirmation: run.confirmation, grant: run.bundle.grant, receipt: run.bundle.receipt, bindings: run.bindings, jwks: run.jwks, trusted });
}

function write(dir, run) {
  mkdirSync(dir, { recursive: true });
  const w = (n, o) => writeFileSync(join(dir, n), JSON.stringify(o, null, 2) + "\n");
  w("binding_payer.json", run.bindings.payer); w("binding_executor.json", run.bindings.executor); w("binding_payee.json", run.bindings.payee);
  w("jwks.json", run.jwks); w("bundle.json", run.bundle); w("confirmation.json", run.confirmation);
}

function read(dir) {
  const j = (n) => parseStrict(readFileSync(join(dir, n), "utf8"));
  return { bindings: { payer: j("binding_payer.json"), executor: j("binding_executor.json"), payee: j("binding_payee.json") },
    jwks: j("jwks.json"), bundle: j("bundle.json"), confirmation: j("confirmation.json") };
}

function print(r) {
  const lines = ["## payee-confirm-v0: three parties", "", "verdict: **" + r.verdict + "** " + JSON.stringify(r.refusals.map((x) => x.code)) + " " + JSON.stringify(r.findings.map((x) => x.code)), "",
    "Established, by anyone holding these six files and no credential from the issuer:", ...r.establishes.map((s) => "- " + s), "",
    "Not established:", ...r.does_not_establish.map((s) => "- " + s)];
  console.log(lines.join("\n"));
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join("\n") + "\n", { flag: "a" });
}

const args = process.argv.slice(2);
const arg = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const trusted = parseTrust(args.flatMap((a, i) => (a === "--trust" ? [args[i + 1]] : [])));
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (arg("--verify")) { const r = readerReport(read(arg("--verify")), trusted); print(r); process.exit(r.verdict === "accepted" ? 0 : 1); }
  const now = Math.floor(Date.now() / 1000);
  let tokA, tokB, tokC, jwksDoc;
  if (arg("--token-a")) {
    [tokA, tokB, tokC] = ["--token-a", "--token-b", "--token-c"].map((k) => readFileSync(arg(k), "utf8").trim());
    jwksDoc = readFileSync(arg("--jwks"), "utf8");
  } else {
    const M = mockIssuer(now);
    [tokA, tokB, tokC] = ["payer", "executor", "payee"].map((e) => M.token("nenrin-" + e, "nenrin-payee-confirm"));
    jwksDoc = M.jwks;
  }
  const run = buildRun({ tokA, tokB, tokC, jwksDoc, now });
  const dir = arg("--out") || "out";
  write(dir, run);
  const r = readerReport(read(dir), trusted);
  console.log("issuer JWKS sha256: " + run.jwks.sha256);
  print(r);
  process.exit(r.verdict === "accepted" ? 0 : 1);
}
