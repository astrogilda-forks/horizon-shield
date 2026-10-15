// payee_confirm.test.mjs : node payee_confirm.test.mjs
import { sign as nodeSign } from "node:crypto";
import { mockIssuer, buildRun, readerReport } from "./three_party_demo.mjs";
import { makeConfirmation, verify, confirmationId, confirmationPreimage } from "./payee_confirm.mjs";
import { newActorKey, canonical, makeBinding } from "../idp-bind-v0/idp_bind.mjs";

let fail = 0, n = 0;
const chk = (name, c, x = "") => { n++; console.log((c ? "PASS  " : "FAIL  ") + name + (c ? "" : "  <<< " + String(x).slice(0, 300))); if (!c) fail++; };
const codes = (r) => r.refusals.map((x) => x.code);
const clone = (o) => JSON.parse(JSON.stringify(o));
const now = Math.floor(Date.parse("2026-10-15T15:30:00Z") / 1000);
const M = mockIssuer(now);
const tok = (e) => M.token("nenrin-" + e, "nenrin-payee-confirm");
const run = buildRun({ tokA: tok("payer"), tokB: tok("executor"), tokC: tok("payee"), jwksDoc: M.jwks, now });
const trusted = { "https://token.actions.githubusercontent.com": [run.jwks.sha256] };
const base = () => ({ confirmation: clone(run.confirmation), grant: clone(run.bundle.grant), receipt: clone(run.bundle.receipt), bindings: clone(run.bindings), jwks: run.jwks, trusted });

{
  const r = readerReport(run, trusted);
  chk("three parties: accepted", r.verdict === "accepted", JSON.stringify(r.refusals));
  const self = readerReport(run);
  chk("three parties, no trusted keys: accepted but every role self_pinned, and no identity named", self.verdict === "accepted" && ["payer", "executor", "payee"].every((k) => self.findings.some((f) => f.code === k + "_self_pinned")) && !self.establishes.join(" ").includes("environment:nenrin"));
  chk("three parties: payer, executor and payee bound to three workflow subjects", ["payer_bound", "executor_bound", "payee_bound"].every((c) => r.findings.some((f) => f.code === c)));
  chk("three parties: no rail evidence is said, and 'money moved' is not established", r.findings.some((f) => f.code === "no_rail_evidence") && r.does_not_establish[0].startsWith("that money moved"));
  chk("three parties: the payee line names the amount", r.establishes[2].includes("120000 JPY"));
  const nb = verify({ confirmation: run.confirmation, grant: run.bundle.grant, receipt: run.bundle.receipt });
  chk("without bindings: accepted on keys alone", nb.verdict === "accepted" && !nb.findings.some((f) => /_bound$/.test(f.code)));
}

// the payee re-signs after a change: id and signature right, content wrong
const resign = (c, key) => { c.confirmation_id = confirmationId(c); c.payee_sig = nodeSign(null, Buffer.from(canonical(confirmationPreimage(c)), "utf8"), key).toString("base64"); return c; };
const payeeKey = newActorKey();
const own = (() => { const g = run.bundle.grant, r = run.bundle.receipt;
  return makeConfirmation({ payeePrivateKey: payeeKey.privateKey, payeeId: payeeKey.actorId, grant: g, receipt: r, invoice: { invoice: "INV-2026-1015", amount_jpy: 120000 }, rail: "bank_transfer", receivedAt: "2026-10-15T15:30:04Z", nonce: "c-2" }); })();
const cases = [
  ["confirmation_id", (i) => { i.confirmation.confirmation_id = "0".repeat(64); }, "confirmation_recompute_mismatch"],
  ["amount, id recomputed, signature stale", (i) => { i.confirmation.received.amount = 12000; i.confirmation.confirmation_id = confirmationId(i.confirmation); }, "payee_sig_invalid"],
  ["amount, re-signed by the payee", (i) => { i.confirmation = clone(own); i.confirmation.received.amount = 12000; resign(i.confirmation, payeeKey.privateKey); }, "amount_mismatch"],
  ["invoice terms other than the grant's, re-signed", (i) => { i.confirmation = clone(own); i.confirmation.invoice.amount_jpy = 12000; i.confirmation.received.amount = 12000; resign(i.confirmation, payeeKey.privateKey); }, "invoice_not_granted"],
  ["received before execution, re-signed", (i) => { i.confirmation = clone(own); i.confirmation.received_at = "2026-10-15T15:29:00Z"; resign(i.confirmation, payeeKey.privateKey); }, "received_before_execution"],
  ["names another receipt", (i) => { i.confirmation = clone(own); i.confirmation.receipt_id = "a".repeat(64); resign(i.confirmation, payeeKey.privateKey); }, "names_other_records"],
  ["the executor signs as payee", (i) => { const g = i.grant; i.confirmation = clone(own); i.confirmation.payee_id = g.provider_id; i.confirmation.confirmation_id = confirmationId(i.confirmation); }, "payee_is_party"],
  ["rail unknown", (i) => { i.confirmation = clone(own); i.confirmation.rail = "cash"; resign(i.confirmation, payeeKey.privateKey); }, "rail_unknown"],
  ["receipt tampered", (i) => { i.receipt.executed_at = "2026-10-15T15:31:00Z"; }, "grant_receipt_refused"],
  ["receipt says failed", (i) => { i.receipt.outcome.status = "failed"; }, "receipt_not_completed"],
  ["payee binding of another key", (i) => { i.bindings.payee = clone(run.bindings.executor); }, "binding_other_key_payee"],
  ["JWKS bytes other than pinned", (i) => { i.jwks = { sha256: run.jwks.sha256, document: run.jwks.document + " " }; }, "binding_refused_payer"],
];
for (const [what, f, want] of cases) {
  const i = base(); if (!["binding_refused_payer", "binding_other_key_payee", "grant_receipt_refused", "receipt_not_completed", "confirmation_recompute_mismatch", "payee_sig_invalid"].includes(want)) delete i.bindings; f(i);
  const c = codes(verify(i));
  chk("refuse: " + what + " -> " + want, c.includes(want), c.join(","));
}
{
  // one provider subject in two roles
  const i = base();
  const k = newActorKey();
  const t = tok("payer");
  const pl = JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()), hd = JSON.parse(Buffer.from(t.split(".")[0], "base64url").toString());
  i.confirmation = clone(own); i.bindings.payee = makeBinding({ actorPrivateKey: payeeKey.privateKey, actorId: payeeKey.actorId, token: t, issuer: pl.iss, subject: pl.sub, audience: pl.aud, kid: hd.kid, alg: hd.alg, boundAt: "2026-10-15T15:30:00Z", nonce: "x" });
  chk("refuse: one provider subject as payer and payee -> one_identity_two_roles", codes(verify(i)).includes("one_identity_two_roles"), codes(verify(i)).join(","));
}
{
  // rail evidence: pointer, lookup
  const ev = { kind: "document_sha256", ref: "b".repeat(64), system: "bank statement PDF held by the payee" };
  const c = makeConfirmation({ payeePrivateKey: payeeKey.privateKey, payeeId: payeeKey.actorId, grant: run.bundle.grant, receipt: run.bundle.receipt, invoice: { invoice: "INV-2026-1015", amount_jpy: 120000 }, rail: "bank_transfer", evidence: ev, receivedAt: "2026-10-15T15:30:04Z", nonce: "c-3" });
  const i = { confirmation: c, grant: run.bundle.grant, receipt: run.bundle.receipt };
  chk("evidence: bound, unchecked without a lookup", verify(i).findings.some((f) => f.code === "rail_evidence_unchecked"));
  let asked = null;
  const ok = verify(Object.assign({ lookup: (q) => { asked = q; return { found: true, matches: true }; } }, i));
  chk("evidence: the lookup is asked about the whole payment (amount, currency, payee, invoice), not just the pointer", asked && asked.amount === 120000 && asked.currency === "JPY" && asked.payee_id === c.payee_id && asked.invoice.invoice === "INV-2026-1015" && asked.evidence.ref === ev.ref);
  chk("evidence: a lookup that confirms -> rail_evidence_confirmed, and 'money moved' drops out of does_not_establish", ok.findings.some((f) => f.code === "rail_evidence_confirmed") && !ok.does_not_establish.some((s) => s.startsWith("that money moved")));
  chk("evidence: a lookup that does not find it -> rail_evidence_not_found", codes(verify(Object.assign({ lookup: () => ({ found: false }) }, i))).includes("rail_evidence_not_found"));
  chk("evidence: a throwing lookup is not a confirmation", codes(verify(Object.assign({ lookup: () => { throw new Error("x"); } }, i))).includes("rail_evidence_not_found"));
  const bad = clone(c); bad.evidence.ref = "short"; resign(bad, payeeKey.privateKey);
  chk("evidence: a malformed pointer is refused", codes(verify({ confirmation: bad, grant: run.bundle.grant, receipt: run.bundle.receipt })).includes("evidence_ref_malformed"));
}

console.log("\n" + (n - fail) + "/" + n + " passed");
process.exit(fail ? 1 : 0);
