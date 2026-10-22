#!/usr/bin/env node
// a2a-approval-v3 in a second runtime: the twin of approval_v3.py, which is the reference (APPROVAL_V3.md).
//
// Same fields, same signed bytes, same reasons in the same order. Every pattern is anchored so that it means what the
// Python \Z means: no trailing newline is accepted anywhere. max_amount is compared as a BigInt, so an 18 digit amount
// is read exactly. approval_v3.test.mjs runs fixtures/approval_v3/vectors.json through this file, and
// approval_v3.py --selftest runs that test, so the two runtimes are held to one set of vectors.
import { canonical } from "./canonical_v0.mjs";
import { utf8, isInt, b64Raw, ed25519Verify, contractSha256, approvers, limitFor, verifyApproverApproval as v2Rule } from "./clause_eval_v0.mjs";

export const APPROVAL = "a2a-approval-v3";
const ENTRY_KEYS = ["action", "approval", "approver", "by", "max_amount", "nonce", "sig_b64", "single_use", "unit", "valid_until_height"];
const HEX32 = /^[0-9a-f]{32}$/;          // JavaScript $ does not match before a final newline: the same reading as Python \Z
const AMOUNT = /^(0|[1-9][0-9]{0,17})$/;
const UNIT = /^[\x21-\x7e]{1,64}$/;
export const REASONS = ["not_a_v3_approval", "malformed", "approver_not_pinned", "action_not_permitted_for_approver",
  "malformed_key_or_signature", "bad_signature", "action_has_no_limit", "unit_differs_from_limit"];

const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
export const isV3 = (e) => isObj(e) && e.approval === APPROVAL;

export function approvalV3Bytes(contract, e, approverKeyB64) {
  return Buffer.concat([utf8("a2a-approval-v3\n"), utf8(canonical({
    contract_sha256: contractSha256(contract), action: e.action ?? null, approver_key: approverKeyB64,
    max_amount: e.max_amount ?? null, unit: e.unit ?? null, valid_until_height: e.valid_until_height ?? null,
    nonce: e.nonce ?? null, single_use: e.single_use ?? null }))]);
}

function shapeOk(e) {
  const keys = Object.keys(e).sort();
  return keys.length === ENTRY_KEYS.length && keys.every((k, i) => k === ENTRY_KEYS[i])
    && typeof e.action === "string" && e.action !== ""
    && typeof e.approver === "string"
    && typeof e.max_amount === "string" && AMOUNT.test(e.max_amount)
    && typeof e.unit === "string" && UNIT.test(e.unit)
    && Number.isSafeInteger(e.valid_until_height) && e.valid_until_height >= 0
    && typeof e.nonce === "string" && HEX32.test(e.nonce)
    && typeof e.single_use === "boolean"
    && typeof e.sig_b64 === "string";
}

export function verifyApprovalV3(contract, e) {
  if (!isV3(e) || e.by !== "approver") return ["approval_unverified", "not_a_v3_approval"];
  if (!shapeOk(e)) return ["approval_unverified", "malformed"];
  const pin = approvers(contract).find((a) => a.name === e.approver);
  if (!pin) return ["approval_unverified", "approver_not_pinned"];
  if (!(pin.actions || []).includes(e.action)) return ["approval_unverified", "action_not_permitted_for_approver"];
  if (b64Raw(pin.public_key_ed25519_b64, 32) === null || b64Raw(e.sig_b64, 64) === null) return ["approval_unverified", "malformed_key_or_signature"];
  if (!ed25519Verify(pin.public_key_ed25519_b64, e.sig_b64, approvalV3Bytes(contract, e, pin.public_key_ed25519_b64))) return ["approval_unverified", "bad_signature"];
  const lim = limitFor(contract, e.action);
  if (lim === null) return ["approval_unverified", "action_has_no_limit"];
  if (lim.unit !== e.unit) return ["approval_unverified", "unit_differs_from_limit"];
  return ["approved", null];
}

// The v2 approver rule read the way babyblueviper1's reference reads it since bcf6592: a nonce with a trailing newline
// is malformed. (clause_eval_v0.mjs keeps the published $ reading, as clause_eval_v0.py does.)
export function verifyApprovalV2Strict(contract, e) {
  if (!isObj(e) || e.by !== "approver") return ["approval_unverified", "not_an_approver_approval"];
  const vu = e.valid_until_height, nonce = e.nonce, su = e.single_use;
  if (!(typeof e.action === "string" && isInt(vu) && vu >= 0 && typeof nonce === "string" && HEX32.test(nonce) && typeof su === "boolean"))
    return ["approval_unverified", "malformed"];
  return v2Rule(contract, e);
}

export const verifyApproverAny = (contract, e) => (isV3(e) ? verifyApprovalV3(contract, e) : verifyApprovalV2Strict(contract, e));

export function covers(e, amount) {
  if (!isV3(e) || !Number.isSafeInteger(amount) || amount < 0 || typeof e.max_amount !== "string" || !AMOUNT.test(e.max_amount)) return false;
  return BigInt(e.max_amount) >= BigInt(amount);
}
