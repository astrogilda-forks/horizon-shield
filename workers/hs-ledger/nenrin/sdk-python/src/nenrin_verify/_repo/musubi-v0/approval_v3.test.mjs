#!/usr/bin/env node
// approval_v3.test.mjs: fixtures/approval_v3/vectors.json through the JavaScript twin (approval_v3.mjs). The Python
// reference writes and reads the same file (approval_v3.py --selftest, which also runs this test).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { verifyApprovalV3, verifyApproverAny, covers, isV3, REASONS } from "./approval_v3.mjs";
import { verifyApproverApproval, contractSha256 } from "./clause_eval_v0.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(path.join(HERE, "fixtures", "approval_v3", "vectors.json"), "utf8"));
const C = F.contract;
let ok = 0, bad = [];
const same = (got, want) => got[0] === want.result && got[1] === want.reason;
if (contractSha256(C) !== F.contract_sha256) bad.push("contract_sha256");
for (const v of F.vectors) {
  if (!same(verifyApprovalV3(C, v.approval), v.expect)) bad.push(v.id + ": " + JSON.stringify(verifyApprovalV3(C, v.approval)));
  else if (isV3(v.approval) && !same(verifyApproverAny(C, v.approval), v.expect)) bad.push(v.id + " (any)");
  else ok++;
}
const seen = new Set(F.vectors.map((v) => v.expect.reason).filter((r) => r !== null));
for (const r of REASONS) if (!seen.has(r)) bad.push("reason never reached: " + r);
for (const v of F.v2_vectors) {
  if (!same(verifyApproverAny(C, v.approval), v.expect_v1_13)) bad.push(v.id + " v1.13: " + JSON.stringify(verifyApproverAny(C, v.approval)));
  else if (!same(verifyApproverApproval(C, v.approval), v.expect_v0)) bad.push(v.id + " v0: " + JSON.stringify(verifyApproverApproval(C, v.approval)));
  else ok++;
}
const g = F.vectors[0].approval;
for (const c of F.covers) { if (covers({ ...g, max_amount: c.max_amount }, c.amount) !== c.covers) bad.push("covers " + JSON.stringify(c)); else ok++; }
if (covers(g, true) || covers(g, -1) || covers(g, null) || covers({ ...g, approval: "x" }, 1)) bad.push("covers accepts a non amount");
if (bad.length) { console.log("FAIL\n  " + bad.join("\n  ")); process.exit(1); }
console.log(`PASS ${ok}/${F.vectors.length + F.v2_vectors.length + F.covers.length} (approval_v3.mjs agrees with the vectors the Python reference wrote)`);
