// node --test test/pilot.test.mjs   (Node 20 or later: WebCrypto Ed25519)
// Checks the responder side of Issue #51 without the network: a mocked MCP server and block source, keys made here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { jcs, sha256hex, sign, verify, publicKeyHex, handleCall, Refusal } from "../src/pilot.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const SEED_X = "11".repeat(32), SEED_B = "22".repeat(32);
const FIXTURE = { type: "horizon-shield.estimate-fixture.v0", lines: [
  { item: "外壁塗装 シリコン", qty: 180, unit: "㎡", unit_price: 3200 },
  { item: "足場設置 ㎡単価", qty: 240, unit: "㎡", unit_price: 900 }] };
const env = { RESPONDER_SEED: SEED_X, PRICE: "7000", UNIT: "JPY-testnet", MCP_URL: "mock://mcp", BLOCKS_URL: "mock://blocks" };

function mockFetch(url, init) {
  const text = (t) => ({ ok: true, status: 200, text: async () => t, json: async () => JSON.parse(t) });
  if (url === "mock://mcp") {
    const body = JSON.parse(init.body);
    const w = body.params.arguments.work;
    assert.equal(body.params.arguments.region, undefined);      // no region unless the caller gives one
    if (w === "足場設置 ㎡単価") return text(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { structuredContent: {
      work: w, ambiguous: true, candidates: [] } } }));          // the dataset gives no single reference
    return text(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { structuredContent: {
      work: w + " 単価", fair_range: { min: 1000, avg: 2000, max: 3000 }, verdict: "適正レンジを上回る", level: "high",
      provenance: { data_version: "2.2.0" },
      claim: { dataset_sha256: "85".repeat(32), ruleset: { id: "hs-audit-verdict", version: "1" } } } } }));
  }
  if (url === "mock://blocks/blocks/tip/height") return text("920000");
  if (url.startsWith("mock://blocks/block-height/")) return text("ab".repeat(32));
  throw new Error("unexpected fetch " + url);
}

async function build(over = {}) {
  const X = await publicKeyHex(SEED_X), B = await publicKeyHex(SEED_B);
  const task = { type: "musubi.ca2a.task.v0", service: "estimate-audit", amount: 7000, unit: "JPY-testnet", nonce: "cd".repeat(32), ...over.task };
  const request = { type: "musubi.ca2a.request.v0", caller: B, responder: X, lineage: ["sha256:" + "ef".repeat(32)],
    capability: "pay", occurrence_id: "pilot-call-0", task_sha256: await sha256hex(jcs(task)), ...over.request };
  const rs = await sha256hex(jcs(request));
  const payer = over.payerSeed ? await publicKeyHex(over.payerSeed) : B;
  const payment = await sign({ type: "musubi.ca2a.payment-receipt.v0", payer, payee: X, lineage: request.lineage,
    request_sha256: rs, amount: 7000, unit: "JPY-testnet", seen_block: { height: 919999, hash: "aa".repeat(32) },
    rail: { kind: "signed-test-transfer", receipt_sha256: "bb".repeat(32) }, ...over.payment }, over.payerSeed || SEED_B);
  return { body: { request, task, fixture: FIXTURE, payment }, request, payment, X, B, rs };
}

test("a well formed call returns a receipt the companion's rules accept", async () => {
  const b = await build();
  const out = await handleCall(b.body, env, mockFetch);
  assert.equal(out.request_sha256, b.rs);
  assert.equal(out.receipt.type, "musubi.ca2a.execution-receipt.v0");
  assert.equal(out.receipt.responder, b.X);
  assert.equal(out.receipt.caller, b.B);
  assert.deepEqual(out.receipt.lineage, b.request.lineage);
  assert.equal(out.receipt.request_sha256, b.rs);
  assert.deepEqual(out.receipt.seen_block, { height: 920000, hash: "ab".repeat(32) });
  assert.equal(out.receipt.outcome.kind, "result");
  assert.equal(out.receipt.outcome.response_sha256, await sha256hex(jcs(out.audit)));
  assert.equal(await verify(out.receipt, "responder"), true);
  assert.equal(out.audit.fixture_sha256, await sha256hex(jcs(FIXTURE)));   // the audit names its input by hash
  assert.equal(out.audit.lines.length, 2);
  assert.equal(out.audit.total, 180 * 3200 + 240 * 900);
  const [la, lb] = out.audit.lines;
  assert.deepEqual([la.amount, la.reference_amount, la.finding, la.dataset_sha256, la.ruleset],
    [180 * 3200, 180 * 2000, "above", "85".repeat(32), { id: "hs-audit-verdict", version: "1" }]);
  assert.deepEqual([lb.finding, lb.fair_range, lb.reference_amount, lb.matched_work], ["unmatched", null, null, null]);
  assert.equal(out.audit.reference_total, null);              // one line unmatched: no reference total
  assert.equal(out.audit.region, null);
});

test("the audit is a function of the inputs: same call, same bytes", async () => {
  const b = await build();
  const a = await handleCall(b.body, env, mockFetch), c = await handleCall(b.body, env, mockFetch);
  assert.equal(jcs(a.audit), jcs(c.audit));
  assert.equal(a.receipt.outcome.response_sha256, c.receipt.outcome.response_sha256);
});

async function refuses(over, code) {
  const b = await build(over);
  await assert.rejects(() => handleCall(b.body, env, mockFetch), (e) => e instanceof Refusal && e.code === code, code);
}

test("refusals: price, task binding, responder, payment binding, payer", async () => {
  await refuses({ task: { amount: 5000 } }, "not_the_price");
  await refuses({ request: { task_sha256: "00".repeat(32) } }, "request_does_not_commit_to_task");
  await refuses({ request: { responder: "cc".repeat(32) } }, "request_names_another_responder");
  await refuses({ payment: { amount: 5000 } }, "payment_not_for_task");
  await refuses({ payment: { payee: "cc".repeat(32) } }, "payment_not_to_this_responder");
  await refuses({ payerSeed: "33".repeat(32) }, "payment_not_by_caller");
});

test("a payment altered after signing is refused", async () => {
  const b = await build();
  b.body.payment.rail = { kind: "signed-test-transfer", receipt_sha256: "dd".repeat(32) };
  await assert.rejects(() => handleCall(b.body, env, mockFetch), (e) => e.code === "payment_signature_invalid");
});

test("jcs refuses floats and lone surrogates", () => {
  assert.throws(() => jcs({ a: 1.5 }), (e) => e.code === "number_not_in_profile");
  assert.throws(() => jcs({ a: "\ud800" }), (e) => e.code === "lone_surrogate");
  assert.equal(jcs({ b: [1, { z: null, a: "x" }], a: true }), '{"a":true,"b":[1,{"a":"x","z":null}]}');
});
