// payee-confirm-v0 : the third signature on a delegated payment. Agent A authorizes "pay this invoice" (a NENRIN grant),
// agent B reports executing it (a NENRIN receipt), and the PAYEE, a party neither A nor B controls, signs that it
// received exactly the invoiced amount for exactly that grant and receipt. Checkable offline, with each party's key
// optionally bound to an identity its own provider issued (idp-bind-v0).
//
// Why: a receipt from the executor says "I paid". It is the party with the most reason to say so. The payee is the
// party that can say "I was paid", and its statement is only worth something if it commits to the same task, the same
// grant, the same receipt and the same amount the payer authorized. This record makes that commitment checkable:
// the invoice terms the payee discloses must hash to the args_sha256 the payer's grant signed.
//
// Honest line: three signatures agreeing is not money moving. A payment rail can be pointed at (outcome-evidence kinds:
// a Bitcoin txid, a ledger record, a document or url digest) and an injected lookup can confirm the pointer, and the
// report says whether one ran. Without it, the record proves that three keys, and the identities bound to them, made
// statements that agree with each other; that is a fact about the statements, not about the bank.
//
// Record (payee-confirm-v0/confirmation). Derived fields (outside the preimage): confirmation_id, payee_sig.
//   schema        "payee-confirm-v0/confirmation"
//   payee_id      did:key of the payee (Ed25519)
//   task_id, grant_ref, receipt_id     the grant and receipt it confirms, by id
//   invoice       the invoice terms as the grant committed to them: canonical(invoice) hashes to grant.action.args_sha256
//   received      { currency: "JPY", amount: <integer yen> }   must equal invoice.amount_jpy
//   rail          "bank_transfer" | "card" | "bitcoin" | "other"
//   evidence?     { kind, ref, system }  an outcome-evidence pointer (task-execution-bind-v0/outcome_evidence.mjs)
//   received_at   RFC3339 UTC; not before the receipt's executed_at
//   nonce         caller chosen string
import { sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { canonical, sha256hex, withoutDerived, sigBytes } from "../task-delegation-bind-v0/bind.mjs";
import { isRfc3339Utc } from "../task-execution-bind-v0/bind_exec.mjs";
import { evidenceWellFormed } from "../task-execution-bind-v0/outcome_evidence.mjs";
import { publicKeyFromDidKey } from "../task-delegation-bind-v0/verify_fixture.mjs";
import { verifyProvenance, didKeyResolver } from "../sdk/nenrin_verify.mjs";
import { checkIdentity } from "../idp-bind-v0/trusted_identity.mjs";

export const PAYEE_CONFIRM_VERSION = "0.1.0";
export const SCHEMA = "payee-confirm-v0/confirmation";
export const RAILS = ["bank_transfer", "card", "bitcoin", "other"];
const DERIVED = ["confirmation_id", "payee_sig"];
export const AUDIENCE = "nenrin-payee-confirm";

export const confirmationPreimage = (c) => withoutDerived(c, DERIVED);
export const confirmationId = (c) => sha256hex(canonical(confirmationPreimage(c)));

export function makeConfirmation({ payeePrivateKey, payeeId, grant, receipt, invoice, rail, evidence, receivedAt, nonce }) {
  const c = { schema: SCHEMA, payee_id: payeeId, task_id: grant.task_id, grant_ref: grant.grant_ref, receipt_id: receipt.receipt_id,
    invoice, received: { currency: "JPY", amount: invoice.amount_jpy }, rail };
  if (evidence) c.evidence = evidence;
  c.received_at = receivedAt; c.nonce = nonce;
  c.confirmation_id = confirmationId(c);
  c.payee_sig = nodeSign(null, Buffer.from(canonical(confirmationPreimage(c)), "utf8"), payeePrivateKey).toString("base64");
  return c;
}

// input: { confirmation, grant, receipt, bindings?: { payer, executor, payee }, jwks?: { payer, executor, payee } | {sha256, document},
//          trusted?: { "<issuer>": ["<jwks sha256>"] }, lookup?: ({ evidence, amount, currency, payee_id, invoice, received_at }) => { found, matches } }
// trusted is the reader's own choice; a role whose binding only verifies against JWKS bytes the bundle supplied is
// reported self-pinned and its identity is not stated. The lookup is asked about the whole payment, not just a pointer.
export function verify(input) {
  const refusals = [], findings = [], establishes = [], does_not_establish = [];
  const refuse = (code, why) => refusals.push({ code, why });
  const find = (code, why) => findings.push({ code, why });
  const c = input && input.confirmation, g = input && input.grant, r = input && input.receipt;
  if (!c || typeof c !== "object" || Array.isArray(c)) { refuse("confirmation_not_object", "input.confirmation is not an object"); return report(refusals, findings, establishes, does_not_establish, null); }
  if (!g || !r) { refuse("grant_or_receipt_missing", "the grant and the receipt being confirmed are required"); return report(refusals, findings, establishes, does_not_establish, null); }
  if (c.schema !== SCHEMA) refuse("bad_schema", "schema must be " + SCHEMA);
  if (!isRfc3339Utc(c.received_at)) refuse("bad_received_at", "received_at must be a strict RFC3339 UTC instant");
  if (typeof c.nonce !== "string" || !c.nonce) refuse("bad_nonce", "nonce must be a non-empty string");
  if (!RAILS.includes(c.rail)) refuse("rail_unknown", "rail must be one of " + RAILS.join(", "));

  // 1. the confirmation is what its id says, and the payee signed it
  let id = null;
  try { id = confirmationId(c); } catch (e) { refuse("canonical_refused", String(e.message || e)); }
  if (id !== null) {
    if (c.confirmation_id !== id) refuse("confirmation_recompute_mismatch", "confirmation_id is not sha256 of the canonical preimage");
    let pub = null;
    try { pub = publicKeyFromDidKey(c.payee_id); } catch (e) { refuse("payee_id_unresolvable", "payee_id is not a usable Ed25519 did:key"); }
    const sig = sigBytes(c.payee_sig);
    if (pub && !sig) refuse("payee_sig_malformed", "payee_sig is not canonical base64 of 64 bytes");
    if (pub && sig) {
      let ok = false;
      try { ok = nodeVerify(null, Buffer.from(canonical(confirmationPreimage(c)), "utf8"), pub, sig); } catch (e) { ok = false; }
      if (!ok) refuse("payee_sig_invalid", "payee_sig does not verify under payee_id over the canonical preimage");
    }
  }

  // 2. the grant and receipt verify on their own, and the confirmation names them
  const rp = verifyProvenance({ task_id: g.task_id, grant: g, receipt: r, resolve: didKeyResolver });
  if (rp.verdict !== "accepted") refuse("grant_receipt_refused", "the grant and receipt do not verify: " + rp.refusals.map((x) => x.code).join(","));
  if (c.task_id !== g.task_id || c.grant_ref !== g.grant_ref || c.receipt_id !== r.receipt_id) refuse("names_other_records", "task_id, grant_ref or receipt_id differ from the records given");
  if (!r.outcome || r.outcome.status !== "completed") refuse("receipt_not_completed", "the receipt does not report a completed execution (outcome.status " + JSON.stringify(r.outcome && r.outcome.status) + ")");
  const act = g.action || {};

  // 3. the payee's invoice terms are the ones the payer's grant committed to, and the amount is that amount
  let invOk = false;
  try { invOk = c.invoice && typeof c.invoice === "object" && !Array.isArray(c.invoice) && sha256hex(canonical(c.invoice)) === (g.action && g.action.args_sha256); } catch (e) { invOk = false; }
  if (!invOk) refuse("invoice_not_granted", "canonical(invoice) does not hash to the grant's action.args_sha256");
  const rc = c.received || {};
  if (rc.currency !== "JPY" || !Number.isInteger(rc.amount) || rc.amount <= 0) refuse("bad_received", "received must be a positive integer amount in JPY");
  else if (invOk && rc.amount !== c.invoice.amount_jpy) refuse("amount_mismatch", "received.amount differs from the invoiced amount_jpy");
  if (isRfc3339Utc(c.received_at) && isRfc3339Utc(r.executed_at) && Date.parse(c.received_at) < Date.parse(r.executed_at))
    refuse("received_before_execution", "received_at is earlier than the receipt's executed_at");

  // 4. the payee is a third party
  if (c.payee_id === g.caller_id || c.payee_id === g.provider_id) refuse("payee_is_party", "the payee key is the payer's or the executor's key: no third signature");

  // 5. a payment-rail pointer, if any
  if (c.evidence == null) find("no_rail_evidence", "the payee points at no payment-rail record; the confirmation is its statement alone");
  else {
    const w = evidenceWellFormed(c.evidence);
    if (!w.ok) refuse(w.reason, "evidence is not a well formed outcome-evidence pointer");
    else if (typeof input.lookup !== "function") find("rail_evidence_unchecked", "the payee points at " + c.evidence.kind + " " + c.evidence.ref.slice(0, 16) + " in " + c.evidence.system + "; no lookup ran here");
    else {
      let res = null;
      try { res = input.lookup({ evidence: c.evidence, amount: rc.amount, currency: rc.currency, payee_id: c.payee_id, invoice: c.invoice, received_at: c.received_at }); } catch (e) { res = null; }
      if (!res || res.found !== true) refuse("rail_evidence_not_found", "the injected lookup did not find the pointer");
      else if (res.matches !== true) refuse("rail_evidence_does_not_match", "the injected lookup found the pointer but it does not match");
      else find("rail_evidence_confirmed", "the injected lookup confirmed, in " + c.evidence.system + ", a payment of " + rc.amount + " " + rc.currency + " to the payee for that invoice");
    }
  }

  // 6. identities, when bindings are given
  const B = input.bindings || {};
  const roles = { payer: g.caller_id, executor: g.provider_id, payee: c.payee_id };
  const who = {};
  for (const role of Object.keys(roles)) {
    if (!B[role]) continue;
    const jw = input.jwks && input.jwks.document ? input.jwks : input.jwks && input.jwks[role];
    const id = checkIdentity({ binding: B[role], jwks: jw, trusted: input.trusted, audience: AUDIENCE, actorId: roles[role] });
    if (!id.ok) refuse(id.code + "_" + role, "the " + role + "'s binding: " + id.why);
    else if (id.vouched) { who[role] = id.label; find(role + "_bound", role + " is " + id.label + ", under issuer keys this reader trusts"); }
    else find(role + "_self_pinned", "the " + role + "'s binding verifies only against JWKS bytes the bundle supplied; " + id.label + " is not established");
  }
  const subs = Object.keys(roles).filter((k) => B[k] && B[k].idp).map((k) => B[k].idp.issuer + "|" + B[k].idp.subject);
  if (new Set(subs).size !== subs.length) refuse("one_identity_two_roles", "two roles are bound to the same provider subject");

  if (!refusals.length) {
    const name = (role) => who[role] ? who[role] + " (" + roles[role].slice(0, 20) + "...)" : roles[role].slice(0, 28) + "...";
    establishes.push("payer " + name("payer") + " authorized " + act.tool + " " + act.target + " with the invoice terms " + JSON.stringify(c.invoice) + " for " + g.task_id);
    establishes.push("executor " + name("executor") + " reported completing that action at " + r.executed_at);
    establishes.push("payee " + name("payee") + ", a third key, confirmed receiving " + rc.amount + " JPY by " + c.rail + " for that grant and receipt at " + c.received_at);
    if (findings.some((f) => f.code === "rail_evidence_confirmed")) establishes.push("the payee's payment-rail pointer was confirmed by the lookup this reader ran");
  }
  if (!findings.some((f) => f.code === "rail_evidence_confirmed")) does_not_establish.push("that money moved: three agreeing signatures are statements, and no payment-rail lookup confirmed them here");
  does_not_establish.push("that the parties are who their providers say; only that the providers said so (and only for the roles that carry a binding)");
  does_not_establish.push("that the invoice was owed or the price fair: this records that the parties agree, not that they should");
  return report(refusals, findings, establishes, does_not_establish, id);
}

function report(refusals, findings, establishes, does_not_establish, id) {
  return { schema: "payee-confirm-v0/report", version: PAYEE_CONFIRM_VERSION, verdict: refusals.length ? "refused" : "accepted",
    confirmation_id: id, refusals, findings, establishes, does_not_establish };
}
