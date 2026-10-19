// ae_challenge (2026-10-03): draft-schrock-ae-challenge-08 over HORIZON SHIELD fair-price receipts.
// The receipt below is a real verify_fair_price answer of 2026-10-03; its hash recomputes as SHA-256(JSON.stringify(claim)).
// No network: the receipt store is a stub. Run: node test/ae_challenge.test.mjs
import worker from "../src/worker.js";
import { issueChallenge, evaluate, challengeProblems, POLICY, digestOf, PROBLEM_TYPE } from "../src/ae_challenge.js";

const CLAIM = { work: "外壁塗装 30坪 一式（シリコン）", unit: "一式", fair_min: 700000, fair_avg: 900000, fair_max: 1150000, source: "HORIZON SHIELD souba-db", issued_at: "2026-10-03T13:23:38.529Z" };
const HASH = "eb13e05b296badc97463e3d05d23d2a0261b6aeb3dcd4bc9fdbedb91cb8b99e3";
const STORE = { [HASH]: { claim: CLAIM, claim_sha256: HASH, bitcoin_block: 949356, issued_at: CLAIM.issued_at } };
const T0 = Date.parse(CLAIM.issued_at);
const ACTION = { kind: "renovation-payment", work: CLAIM.work, payee: "example-contractor", amount_jpy: 1100000 };
const read = async (h) => STORE[h] || null;
let fail = 0, n = 0;
const ok = (c, m) => { n++; console.log((c ? "ok   " : "FAIL ") + m); if (!c) fail++; };

const prob = await issueChallenge({ action: ACTION, audience: "https://agent.example", now: T0, id: "c-1" });
const ch = prob.evidence_challenge;
ok(prob.type === PROBLEM_TYPE && prob.status === 403, "problem type and status follow section 3");
ok(challengeProblems(ch).length === 0, "issued challenge has every required member in the right form: " + challengeProblems(ch).join(","));
ok(/^[A-Za-z0-9_-]{22}$/.test(ch.nonce), "nonce is 16 random octets in base64url (22 chars)");
ok(ch.policy_digest === (await digestOf(POLICY)), "policy_digest is the digest of the served policy");

const ev = async (over) => (await evaluate({ challenge: ch, action: ACTION, presentation: { claim_sha256: HASH }, readReceipt: read, now: T0 + 600e3, id: "e-1", ...over })).lineage;
let L = await ev({});
ok(L.outcome === "SATISFIED" && L.reason_ids.length === 0, "real receipt, fresh, same action: SATISFIED");
ok(L.predecessor_challenge_digest === (await digestOf(ch)) && L.action_digest === ch.action_digest && L.policy_digest === ch.policy_digest, "lineage carries the challenge, action and policy digests (section 2.4)");
const need = ["@version","evaluation_id","issuer","presenter","predecessor_challenge_digest","presentation_profile","presentation_digest","evaluation_profile","evaluation_profile_digest","evaluated_at","action_profile","action_digest","policy_id","policy_digest","outcome","reason_ids"];
ok(need.every((k) => k in L), "lineage has every required member");

L = await ev({ readReceipt: async () => ({ claim: { ...CLAIM, fair_max: 1500000 }, claim_sha256: HASH }) });
ok(L.outcome === "UNSATISFIED" && L.reason_ids.includes("evidence_not_verified"), "a receipt whose claim was altered fails the recomputation");
const T31 = T0 + 31 * 24 * 3600e3;
const chLate = (await issueChallenge({ action: ACTION, now: T31 - 60e3, id: "c-late" })).evidence_challenge;
L = await ev({ challenge: chLate, now: T31 });
ok(L.reason_ids.includes("stale_evidence"), "a receipt older than max_age_sec is stale");
L = await ev({ action: { ...ACTION, amount_jpy: 2000000 } });
ok(L.reason_ids.includes("action_not_matched"), "a different action does not match the challenge");
// policy v2 (2026-10-19): the receipt must price the work the action names
for (const [why, act] of [["a receipt for other work", { ...ACTION, work: "屋根塗装 30坪" }], ["the user's own wording, not the receipt's", { ...ACTION, work: "外壁塗装 30坪" }], ["an action that names no work", { kind: "renovation-payment", payee: "example-contractor", amount_jpy: 1100000 }]]) {
  const c = (await issueChallenge({ action: act, now: T0, id: "c-w" })).evidence_challenge;
  const LL = (await evaluate({ challenge: c, action: act, presentation: { claim_sha256: HASH }, readReceipt: read, now: T0 + 600e3, id: "e-w" })).lineage;
  ok(LL.outcome === "UNSATISFIED" && LL.reason_ids.length === 1 && LL.reason_ids[0] === "action_not_matched", "v2: " + why + " does not satisfy the challenge (action_not_matched)");
}
L = await ev({ presentation: {} });
ok(L.reason_ids.includes("missing_evidence"), "no claim_sha256 is missing evidence");
L = await ev({ presentation: { claim_sha256: "a".repeat(64) } });
ok(L.reason_ids.includes("evidence_not_verified"), "a hash the issuer never recorded is not verified");
L = await ev({ readReceipt: async () => { throw new Error("down"); } });
ok(L.outcome === "UNSATISFIED" && L.reason_ids.length === 1 && L.reason_ids[0] === "evaluation_unavailable", "store unreachable: incomplete evaluation, not a guess");
L = await ev({ now: T0 + 3600e3 * 2 });
ok(L.reason_ids.includes("evidence_not_accepted"), "an expired challenge is not accepted");
L = await ev({ challenge: { ...ch, policy_digest: "sha256:" + "0".repeat(64) } });
ok(L.reason_ids.includes("policy_unsatisfied"), "a challenge carrying another policy digest is refused");

L = await ev({ action: { ...ACTION, amount_jpy: 2000000 }, readReceipt: async () => { throw new Error("down"); } });
ok(L.reason_ids.length === 1 && L.reason_ids[0] === "action_not_matched", "a mismatched action is reported even when the store is down (not masked as unavailable)");

const CTX = { waitUntil() {} };
const O = "https://gate.horizonshield.dev";
let r = await worker.fetch(new Request(O + "/ae/challenge", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: ACTION }) }), {}, CTX);
ok(r.status === 403 && r.headers.get("content-type") === "application/problem+json" && r.headers.get("cache-control") === "no-store", "POST /ae/challenge: 403, application/problem+json, no-store");
const body = await r.json();
ok(challengeProblems(body.evidence_challenge).length === 0, "the served challenge is well formed");
r = await worker.fetch(new Request(O + "/ae"), {}, CTX);
ok(r.status === 200 && (await r.json()).routes, "GET /ae documents the routes");
r = await worker.fetch(new Request(O + "/ae/policy/fair-price-before-payment-v2"), {}, CTX);
const pol = await r.json();
ok(pol.policy_digest === body.evidence_challenge.policy_digest && body.evidence_challenge.policy_id.endsWith("-v2"), "the served v2 policy has the digest the challenge carries");
r = await worker.fetch(new Request(O + "/ae/policy/fair-price-before-payment-v1"), {}, CTX);
const pol1 = await r.json();
ok(r.status === 200 && pol1.superseded_by && pol1.policy_digest !== pol.policy_digest, "the v1 policy is still served, marked superseded, with its own digest");
let called = "";
const ENV_SVC = { MCP_SVC: { fetch: async (u) => { called = String(u); return new Response(JSON.stringify(STORE[HASH]), { status: 200, headers: { "content-type": "application/json" } }); } } };
const ch2 = body.evidence_challenge;
r = await worker.fetch(new Request(O + "/ae/evaluate", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ challenge: ch2, action: ACTION, presentation: { claim_sha256: HASH } }) }), ENV_SVC, CTX);
const evr = await r.json();
ok(called.endsWith("/ledger/" + HASH) && evr.lineage.reason_ids.indexOf("evaluation_unavailable") < 0, "the evaluation reads the receipt through the MCP_SVC binding");
r = await worker.fetch(new Request(O + "/ae/challenge", { method: "POST", body: "{}" }), {}, CTX);
ok(r.status === 400, "a challenge request without an action is a 400");

if (fail) { console.log("落ちた: " + fail + " / " + n); process.exit(1); }
console.log("ae_challenge " + n + "/" + n + " 通過");
