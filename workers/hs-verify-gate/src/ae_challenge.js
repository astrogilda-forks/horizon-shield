// ae_challenge.js (gate 0.5.0, 2026-10-03)
// An implementation of draft-schrock-ae-challenge-08 ("An Authorization Evidence Challenge for High-Risk Agent
// Actions", individual Internet-Draft, 2026-09-28) with HORIZON SHIELD evidence behind it.
//
// The situation it serves: an agent is about to pay for Japanese renovation work. A relying party that wants the
// price checked first answers with 403 and a machine-readable challenge naming the evidence it lacks: a HORIZON SHIELD
// fair-price receipt (the verify_fair_price tool) no older than a stated age. The agent obtains one, presents its
// claim_sha256, and this gate evaluates it and answers with an AE-EVALUATION-LINEAGE-v1 record.
//
// What the gate does and does not claim:
//   - It fetches the receipt that the issuing server recorded under that hash (https://mcp.horizonshield.dev/ledger/
//     <claim_sha256>), recomputes SHA-256(JSON.stringify(claim)) and compares it with the hash, and checks that the
//     receipt's issued_at is younger than max_age_sec. It does not re-judge the price.
//   - The receipt store is the issuer's own record, not the hash-chained JIDEC ledger. Anchoring each receipt in JIDEC
//     is on the roadmap and is not claimed here. Anyone can repeat the recomputation without trusting this gate.
//   - Challenges are stateless. The evaluator recomputes every digest from what is presented; a challenge that was
//     altered no longer matches its own predecessor digest in the lineage record.
//   - If the ledger cannot be read, the outcome is UNSATISFIED with reason evaluation_unavailable, never a guess.
//
// Canonical form for every digest here: canonicalUtf8 (sorted keys, UTF-8, no insignificant whitespace), the same
// canon the gate already uses for witness records. Digests are "sha256:" + 64 lowercase hex.
import { canonicalUtf8, sha256Hex } from "./witness.js";

export const AE_VERSION = "AE-CHALLENGE-v1";
export const AE_LINEAGE_VERSION = "AE-EVALUATION-LINEAGE-v1";
export const PROBLEM_TYPE = "https://iana.org/assignments/http-problem-types#ae-required";
const GATE = "https://gate.horizonshield.dev";
export const ACTION_PROFILE = GATE + "/ae/action/renovation-payment-v1";
// v2 (2026-10-19): the receipt must be for the work the action names. Under v1 any fresh receipt satisfied any payment,
// whatever work it priced, so an agent could present the receipt of one job before paying for another.
export const POLICY_ID = GATE + "/ae/policy/fair-price-before-payment-v2";
const POLICY_V1_ID = GATE + "/ae/policy/fair-price-before-payment-v1";
export const EVIDENCE_TYPE = GATE + "/ae/e/hs-fair-price-receipt-v1";
export const EVIDENCE_PROFILE = GATE + "/ae/p/claim-sha256-v1";
export const PRESENT_AS = GATE + "/ae/p/claim-sha256-v1";
export const EVALUATION_PROFILE = GATE + "/ae/eval/receipt-recompute-v2";
export const PREDICATE_RECORDED = GATE + "/ae/pred/receipt-recorded-by-issuer";
export const PREDICATE_RECOMPUTES = GATE + "/ae/pred/claim-hash-recomputes";
const RECEIPT_STORE = "https://mcp.horizonshield.dev/ledger/";
const OBTAIN_MCP = "https://mcp.horizonshield.dev/mcp";
export const MAX_AGE_SEC = 30 * 24 * 3600;
const TTL_SEC = 15 * 60;

export const POLICY = {
  policy_id: POLICY_ID,
  title: "Fair-price evidence before paying for Japanese renovation work",
  applies_to: ACTION_PROFILE,
  requires: [{
    requirement_id: "fair-price-verdict",
    type: EVIDENCE_TYPE,
    meaning: "A HORIZON SHIELD fair-price receipt (verify_fair_price) recorded by the issuer under its claim_sha256, whose hash recomputes from the claim, issued no more than max_age_sec before evaluation, for the work the action names: the action's work is exactly the receipt's claim.work (copy it from the receipt).",
    max_age_sec: MAX_AGE_SEC,
  }],
  supersedes: POLICY_V1_ID,
  not_claimed: "The verdict is reference evidence about price, not an approval of the contractor or a guarantee of the work. The amount of the payment is not compared with the fair range; the receipt says what the work should cost, the payer decides.",
};

// The v1 policy, still served so that its digest can be recomputed; challenges are no longer issued under it.
export const POLICY_V1 = {
  policy_id: POLICY_V1_ID,
  title: "Fair-price evidence before paying for Japanese renovation work",
  applies_to: ACTION_PROFILE,
  requires: [{
    requirement_id: "fair-price-verdict",
    type: EVIDENCE_TYPE,
    meaning: "A HORIZON SHIELD fair-price receipt (verify_fair_price) for the quoted work, recorded by the issuer under its claim_sha256, whose hash recomputes from the claim, issued no more than max_age_sec before evaluation.",
    max_age_sec: MAX_AGE_SEC,
  }],
  not_claimed: "The verdict is reference evidence about price, not an approval of the contractor or a guarantee of the work.",
  superseded_by: POLICY_ID,
  superseded_because: "v1 did not compare the receipt's work with the action's, so a fresh receipt for any work satisfied any payment",
};

const HEX64 = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const isAbsUri = (s) => typeof s === "string" && /^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$/.test(s);
export async function digestOf(v) { return "sha256:" + (await sha256Hex(canonicalUtf8(v))); }
const b64url = (u8) => { let s = ""; for (const b of u8) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

// The action is whatever the agent is about to do, as a JSON object. Only its digest travels in the challenge.
export function validAction(a) { return a && typeof a === "object" && !Array.isArray(a) && Object.keys(a).length > 0; }

export async function issueChallenge({ action, audience, now = Date.now(), random = (n) => crypto.getRandomValues(new Uint8Array(n)), id }) {
  if (!validAction(action)) throw new Error("action must be a non-empty JSON object");
  const challenge = {
    "@version": AE_VERSION,
    challenge_id: id || crypto.randomUUID(),
    nonce: b64url(random(16)),
    action_digest: await digestOf(action),
    action_profile: ACTION_PROFILE,
    audience: (typeof audience === "string" && audience) ? audience : "urn:x-hs:unspecified-audience",
    policy_id: POLICY_ID,
    policy_digest: await digestOf(POLICY),
    required_evidence: [{
      requirement_id: "fair-price-verdict",
      type: EVIDENCE_TYPE,
      profiles: [EVIDENCE_PROFILE],
      proof_predicates: [PREDICATE_RECORDED, PREDICATE_RECOMPUTES],
      max_age_sec: MAX_AGE_SEC,
      status: "current",
    }],
    present_as: [PRESENT_AS],
    obtain_hints: [{ requirement_id: "fair-price-verdict", mechanism: GATE + "/ae/m/mcp-verify-fair-price", uri: OBTAIN_MCP }],
    expires_at: iso(now + TTL_SEC * 1000),
  };
  return {
    type: PROBLEM_TYPE,
    title: "Authorization Evidence Required",
    status: 403,
    detail: "A HORIZON SHIELD fair-price receipt for this work is required before this payment.",
    evidence_challenge: challenge,
  };
}

// Shape check of a challenge against section 2.1 of the draft (members, types, formats).
export function challengeProblems(c) {
  const p = [];
  if (!c || typeof c !== "object") return ["challenge is not an object"];
  if (c["@version"] !== AE_VERSION) p.push("@version");
  if (typeof c.challenge_id !== "string" || !c.challenge_id) p.push("challenge_id");
  if (typeof c.nonce !== "string" || !/^[A-Za-z0-9_-]{22,128}$/.test(c.nonce)) p.push("nonce");
  if (!DIGEST.test(c.action_digest || "")) p.push("action_digest");
  if (!isAbsUri(c.action_profile)) p.push("action_profile");
  if (typeof c.audience !== "string" || !c.audience) p.push("audience");
  if (!isAbsUri(c.policy_id)) p.push("policy_id");
  if (!DIGEST.test(c.policy_digest || "")) p.push("policy_digest");
  if (!Array.isArray(c.required_evidence) || !c.required_evidence.length) p.push("required_evidence");
  else c.required_evidence.forEach((r, i) => {
    if (typeof r.requirement_id !== "string" || !r.requirement_id) p.push("required_evidence[" + i + "].requirement_id");
    if (!isAbsUri(r.type)) p.push("required_evidence[" + i + "].type");
    if (!Array.isArray(r.profiles) || !r.profiles.every(isAbsUri)) p.push("required_evidence[" + i + "].profiles");
    if (!Array.isArray(r.proof_predicates) || !r.proof_predicates.every(isAbsUri)) p.push("required_evidence[" + i + "].proof_predicates");
    if (!Number.isInteger(r.max_age_sec) || r.max_age_sec < 0) p.push("required_evidence[" + i + "].max_age_sec");
    if (typeof r.status !== "string" || !r.status) p.push("required_evidence[" + i + "].status");
  });
  if (!Array.isArray(c.present_as) || !c.present_as.length || !c.present_as.every(isAbsUri)) p.push("present_as");
  if (typeof c.expires_at !== "string" || isNaN(Date.parse(c.expires_at))) p.push("expires_at");
  return p;
}

// Evaluate a presentation. readReceipt(claim) returns the stored receipt object, null when none is recorded, or throws.
export async function evaluate({ challenge, action, presentation, readReceipt, now = Date.now(), id, issuer = GATE + "/" }) {
  const reasons = [];
  let incomplete = null;
  const shape = challengeProblems(challenge);
  const req = (challenge && challenge.required_evidence && challenge.required_evidence[0]) || {};
  if (shape.length) reasons.push("evidence_not_evaluated");
  if (!shape.length && Date.parse(challenge.expires_at) < now) reasons.push("evidence_not_accepted");
  if (!validAction(action) || (!shape.length && (await digestOf(action)) !== challenge.action_digest)) reasons.push("action_not_matched");
  if (!shape.length && (challenge.policy_id !== POLICY_ID || challenge.policy_digest !== (await digestOf(POLICY)))) reasons.push("policy_unsatisfied");
  const claim = presentation && typeof presentation.claim_sha256 === "string" ? presentation.claim_sha256.toLowerCase() : "";
  if (!HEX64.test(claim)) reasons.push("missing_evidence");
  let receipt = null;
  // Only go to the receipt store when nothing above has already decided the outcome. A mismatched action or an
  // expired challenge is a complete UNSATISFIED; it must not be masked by an unreachable store.
  if (HEX64.test(claim) && reasons.length === 0) {
    let got;
    try { got = await readReceipt(claim); } catch (_e) { incomplete = "evaluation_unavailable"; }
    if (!incomplete) {
      if (!got || typeof got.claim !== "object" || got.claim === null) reasons.push("evidence_not_verified");
      else {
        receipt = got;
        if ((await sha256Hex(JSON.stringify(got.claim))) !== claim) reasons.push("evidence_not_verified");
        // v2: the receipt is evidence for this action only when it prices the work the action names.
        if (typeof action.work !== "string" || action.work !== got.claim.work) reasons.push("action_not_matched");
        const issued = Date.parse(got.claim.issued_at || got.issued_at || "");
        const age = (now - issued) / 1000;
        const maxAge = Number.isInteger(req.max_age_sec) ? req.max_age_sec : MAX_AGE_SEC;
        if (!(age >= 0) || age > maxAge) reasons.push("stale_evidence");
      }
    }
  }
  const uniq = [...new Set(incomplete ? [incomplete] : reasons)];
  const lineage = {
    "@version": AE_LINEAGE_VERSION,
    evaluation_id: GATE + "/ae/evaluation/" + (id || crypto.randomUUID()),
    issuer,
    presenter: presentation && isAbsUri(presentation.presenter) ? presentation.presenter : "urn:x-hs:anonymous-presenter",
    predecessor_challenge_digest: await digestOf(challenge || {}),
    presentation_profile: PRESENT_AS,
    presentation_digest: await digestOf(presentation || {}),
    evaluation_profile: EVALUATION_PROFILE,
    evaluation_profile_digest: await digestOf({ profile: EVALUATION_PROFILE, receipt_store: RECEIPT_STORE, predicates: [PREDICATE_RECORDED, PREDICATE_RECOMPUTES] }),
    evaluated_at: iso(now),
    action_profile: (challenge && challenge.action_profile) || ACTION_PROFILE,
    action_digest: (challenge && challenge.action_digest) || "sha256:" + "0".repeat(64),
    policy_id: (challenge && challenge.policy_id) || POLICY_ID,
    policy_digest: (challenge && challenge.policy_digest) || (await digestOf(POLICY)),
    outcome: uniq.length ? "UNSATISFIED" : "SATISFIED",
    reason_ids: uniq,
  };
  if (receipt) lineage.presentation_ref = RECEIPT_STORE + claim;
  return { lineage, receipt, shape_problems: shape };
}

export const AE_USAGE = {
  spec: "draft-schrock-ae-challenge-08 (individual Internet-Draft, 2026-09-28, no IETF standing)",
  what: "Authorization Evidence Challenge for paying for Japanese renovation work, backed by HORIZON SHIELD fair-price receipts that anyone can recompute.",
  routes: {
    "GET /ae": "this document",
    "GET /ae/policy/fair-price-before-payment-v1": "the policy whose digest every challenge carries",
    "POST /ae/challenge": "{action: {...}, audience?: string} -> 403 application/problem+json with evidence_challenge",
    "POST /ae/evaluate": "{challenge, action, presentation: {claim_sha256, presenter?}} -> 200 {lineage: AE-EVALUATION-LINEAGE-v1, receipt}",
  },
  obtain_evidence: "Call verify_fair_price on " + OBTAIN_MCP + ", put its fair_price_claim.work into the action as action.work, and present verification.claim_sha256 from its answer.",
  action: "A JSON object. action.work must be exactly the receipt's claim.work, or the evaluation is action_not_matched (policy v2, 2026-10-19; under v1 the work was not compared).",
  limits: "Stateless challenges, no capacity bounds or anti-abuse budgets (the draft's section 5 items). The gate checks that the issuer recorded the receipt, that its hash recomputes, its age, and that it prices the work the action names; it does not re-judge the price or compare the payment's amount with the fair range. From 2026-10-19 the issuer's receipts of each UTC day are listed in one JIDEC ledger entry the next day; the gate does not yet require a receipt to be in such an entry (a fresh receipt is usually not in one yet).",
};

export async function aeRoute(request, url, env, helpers) {
  const { json, problem } = helpers;
  const path = url.pathname;
  if (path === "/ae" || path === "/ae/") return json(AE_USAGE);
  if (path === "/ae/policy/fair-price-before-payment-v2") return json({ ...POLICY, policy_digest: await digestOf(POLICY) });
  if (path === "/ae/policy/fair-price-before-payment-v1") return json({ ...POLICY_V1, policy_digest: await digestOf(POLICY_V1) });
  if (path === "/ae/challenge" && request.method === "POST") {
    let body; try { body = await request.json(); } catch (_e) { return json({ error: "body must be JSON" }, 400); }
    if (!validAction(body && body.action)) return json({ error: "action must be a non-empty JSON object" }, 400);
    return problem(await issueChallenge({ action: body.action, audience: body.audience }));
  }
  if (path === "/ae/evaluate" && request.method === "POST") {
    let body; try { body = await request.json(); } catch (_e) { return json({ error: "body must be JSON" }, 400); }
    const base = (env && env.AE_RECEIPT_STORE) || RECEIPT_STORE;
    const readReceipt = async (h) => {
      // hs-mcp sits on a route in the same zone, which a Worker cannot reach with a plain fetch. Use the service
      // binding MCP_SVC (wrangler.jsonc) when present; the URL is kept so the request looks the same to hs-mcp.
      const f = (env && env.MCP_SVC && typeof env.MCP_SVC.fetch === "function") ? env.MCP_SVC.fetch.bind(env.MCP_SVC) : fetch;
      const r = await f(base + h, { headers: { "user-agent": "hs-verify-gate-ae/1", accept: "application/json" } });
      if (r.status === 404) return null;
      if (!r.ok) throw new Error("receipt store " + r.status);
      return r.json();
    };
    const out = await evaluate({ challenge: body && body.challenge, action: body && body.action, presentation: body && body.presentation, readReceipt });
    return json(out);
  }
  return json({ error: "not found", see: GATE + "/ae" }, 404);
}
