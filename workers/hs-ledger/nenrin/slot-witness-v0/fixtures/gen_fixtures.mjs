// gen_fixtures.mjs: deterministic observations for slot_check.py to recompute, so the JS intake and the Python
// checker are tested against the same bytes. A test issuer key (BIP-340 vector 0's secret key, 3) signs receipt
// events with a fixed aux; the slot endpoint is a fake. Run: node nenrin/slot-witness-v0/fixtures/gen_fixtures.mjs > slot_fixtures.json
// (in workers/hs-ledger). The test asserts the committed file regenerates byte for byte.
// slot_fixtures.json holds v0 observations (written with version "0", as the intake wrote them until 2026-10-11).
// With --v01 it writes slot_fixtures_v01.json: v0.1 observations of decider-scoped slots (decision-receipt SPEC v0.4),
// where a test decider key (secret key 5) signs decider claims. The equivocation case has the shape of the first
// live one (2026-10-10): the slot holds one claim and lists one conflicting claim, both signed by the decider key.
// With --v02 it writes slot_fixtures_v02.json: v0.2 observations whose slot bytes carry the issuer's slot log object
// (SPEC v0.4: the slot's line in a daily snapshot, its Merkle path, the header, log_root), built here by the SPEC's rules,
// and the snapshot file itself (snapshot_jsonl) so a reader can check the file and the proof against each other.
import { ISSUERS, readReceipt, observe } from "../slot_witness_v0.mjs";
import { schnorrSign, hexToBytes, nostrEventId, xOnlyPub } from "../bip340.mjs";
import { jcs } from "../../trace-pin-v0/trace_pin_v0.mjs";

export const TEST_SK = "0000000000000000000000000000000000000000000000000000000000000003";
export const TEST_PUB = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
export const TEST_PREFIX = "https://issuer.test/decision-receipt/slot/";
export const NOW = 1791600000; // 2026-10-10T02:40:00Z
const hex = (b) => Buffer.from(b).toString("hex");

export function addTestIssuer() { ISSUERS[TEST_PUB] = { name: "test-issuer", slot_url_prefix: TEST_PREFIX, spec: "fixtures only" }; }

export async function receipt({ slot, choice = "approve", created_at = NOW - 120, extra = {} }) {
  const content = jcs({ schema: "invinoveritas.decision_receipt.v0", request_slot: slot, choice_commitment: "c".repeat(64), ...extra });
  const ev = { pubkey: TEST_PUB, created_at, kind: 30078, tags: [["d", "decision-receipt"]], content };
  ev.id = await nostrEventId(ev);
  ev.sig = hex(await schnorrSign(hexToBytes(TEST_SK), hexToBytes(ev.id), new Uint8Array(32)));
  return ev;
}

export const slotFetch = (bodyFor) => async (u, init) => {
  if (init && init.redirect !== "manual") return new Response("redirects must not be followed", { status: 500 });
  const slot = decodeURIComponent(u.slice(TEST_PREFIX.length));
  const r = bodyFor(slot, u);
  if (r instanceof Response) return r;
  return new Response(typeof r === "string" ? r : JSON.stringify(r), { status: 200, headers: { "content-type": "application/json" } });
};

export const DECIDER_SK = "0000000000000000000000000000000000000000000000000000000000000005";
export const OTHER_DECIDER_SK = "0000000000000000000000000000000000000000000000000000000000000007";
const enc = new TextEncoder();
const sha = async (s) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));

export async function deciderClaim(sk, { request_id = "req-1", choice = "approve", claimed_at = NOW - 120 } = {}) {
  const pub = hex(await xOnlyPub(hexToBytes(sk)));
  const slot = await sha("invinoveritas.decision_receipt.slot.decider.v1|" + pub + "|" + request_id);
  const claim = { schema: "invinoveritas.decision_claim.v1", request_slot: slot, decider_pubkey: pub, claimed_at,
    choice_commitment: await sha("choice|" + choice), question_commitment: await sha("question|" + request_id) };
  const sig = hex(await schnorrSign(hexToBytes(sk), new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(jcs(claim)))), new Uint8Array(32)));
  return { pub, slot, claim, sig };
}

async function mainV01() {
  addTestIssuer();
  const A = await deciderClaim(DECIDER_SK);                                              // the claim that holds the slot
  const B = await deciderClaim(DECIDER_SK, { choice: "deny", claimed_at: NOW - 100 });   // same key, same request_id, other choice
  const O = await deciderClaim(OTHER_DECIDER_SK);                                       // another decider key
  const rcA = { decider_pubkey: A.pub, decider_claim: A.claim, decider_sig: A.sig, slot_scope: "decider" };
  const rcB = { decider_pubkey: B.pub, decider_claim: B.claim, decider_sig: B.sig, slot_scope: "decider" };
  const evA = await receipt({ slot: A.slot, extra: rcA });
  const evB = await receipt({ slot: B.slot, created_at: NOW - 100, extra: { ...rcB, choice_commitment: "d".repeat(64) } });
  const flip = (sig) => (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  const slotBody = (ev, holder, conflicts) => ({ slot: A.slot, taken: true, event_ids: [ev.id], scope: "decider",
    decider_claim: holder.claim, decider_sig: holder.sig, ...(conflicts ? { conflicts } : {}) });
  const cases = [];
  const add = async (name, ev, body, expect_decider) => {
    const rc = await readReceipt(ev);
    const obs = await observe(ev, rc, { nowSec: NOW, fetchImpl: slotFetch(() => body), trigger: "submitted", previous: null, version: "0.1" });
    cases.push({ name, record_jcs: jcs(obs), expect_verdict: obs.verdict, expect_decider: obs.decider === null ? null : obs.decider[expect_decider[0]] === expect_decider[1] ? expect_decider : ["MISMATCH", obs.decider] });
  };
  await add("account_scoped_no_decider_claim", evA, { slot: A.slot, taken: true, event_ids: [evA.id] }, null);
  await add("holder_verifies_no_conflicts", evA, slotBody(evA, A, []), ["holder_claim", "verifies"]);
  await add("equivocation_one_conflict", evA, slotBody(evA, A, [{ decider_claim: B.claim, decider_sig: B.sig, received_at: NOW - 100 }]), ["equivocation", true]);
  await add("conflict_with_bad_signature", evA, slotBody(evA, A, [{ decider_claim: B.claim, decider_sig: flip(B.sig) }]), ["conflicts_verified", 0]);
  await add("conflict_by_another_key", evA, slotBody(evA, A, [{ decider_claim: O.claim, decider_sig: O.sig }]), ["conflicts_verified", 0]);
  const X = await deciderClaim(DECIDER_SK, { request_id: "req-2" });                    // same key, another request_id: another slot
  await add("conflict_for_another_slot", evA, slotBody(evA, A, [{ decider_claim: X.claim, decider_sig: X.sig }]), ["conflicts_verified", 0]);
  await add("conflict_repeats_the_holder", evA, slotBody(evA, A, [{ decider_claim: A.claim, decider_sig: A.sig }]), ["equivocation", false]);
  await add("holder_bad_signature", evA, slotBody(evA, { claim: A.claim, sig: flip(A.sig) }, [{ decider_claim: B.claim, decider_sig: B.sig }]), ["holder_claim", "bad_signature"]);
  await add("slot_held_by_the_other_claim", evB, { ...slotBody(evA, A, [{ decider_claim: B.claim, decider_sig: B.sig }]), event_ids: [evA.id] }, ["holder_claim", "not_the_receipts_claim"]);
  await add("holder_names_another_key", evA, slotBody(evA, O, []), ["holder_claim", "other_key"]);
  for (const c of cases) if (c.expect_decider && c.expect_decider[0] === "MISMATCH") throw new Error(c.name + ": " + JSON.stringify(c.expect_decider[1]));
  process.stdout.write(JSON.stringify({ schema: "nenrin-slot-witness-fixtures-v0.1", test_issuer_pubkey: TEST_PUB, test_slot_url_prefix: TEST_PREFIX, now: NOW, decider_pubkey: A.pub, cases }, null, 1) + "\n");
}

// the slot log, by decision-receipt SPEC v0.4: leaf = sha256(line), pairs sha256(left_hex + right_hex), an odd last node
// paired with itself, log_root = sha256(JCS(header))
export const LOG_SCHEMA_ID = "invinoveritas.decision_receipt.slot_log.v1";
export async function slotLog(lines, { date, cutoff, prev_root = "0".repeat(64) }) {
  const sorted = [...lines].sort((a, b) => (a.slot < b.slot ? -1 : 1));
  const raw = sorted.map((l) => jcs(l));
  let level = await Promise.all(raw.map((r) => sha(r)));
  const leaves = [...level];
  if (!level.length) level = [await sha(LOG_SCHEMA_ID + "|empty")];
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(await sha(level[i] + (i + 1 < level.length ? level[i + 1] : level[i])));
    levels.push(next); level = next;
  }
  const header = { schema: LOG_SCHEMA_ID, date, cutoff, prev_root, n_slots: sorted.length, merkle_root: level[0], rules: "fixture built by gen_fixtures.mjs from SPEC v0.4" };
  const log_root = await sha(jcs(header));
  const proof = (slot) => {
    let idx = sorted.findIndex((l) => l.slot === slot);
    const path = [];
    for (const lv of levels.slice(0, -1)) {
      const sib = idx % 2 === 0 ? (idx + 1 < lv.length ? lv[idx + 1] : lv[idx]) : lv[idx - 1];
      path.push({ side: idx % 2 === 0 ? "R" : "L", hash: sib });
      idx = Math.floor(idx / 2);
    }
    const i = sorted.findIndex((l) => l.slot === slot);
    return { line: sorted[i], leaf: leaves[i], merkle_path: path, header, log_root };
  };
  return { file: [jcs(header), ...raw].join("\n") + "\n", header, log_root, proof };
}

async function mainV02() {
  addTestIssuer();
  const A = await deciderClaim(DECIDER_SK);
  const B = await deciderClaim(DECIDER_SK, { choice: "deny", claimed_at: NOW - 100 });
  const rcA = { decider_pubkey: A.pub, decider_claim: A.claim, decider_sig: A.sig, slot_scope: "decider" };
  const evA = await receipt({ slot: A.slot, extra: rcA });
  const CUTOFF = Date.UTC(2026, 9, 11) / 1000;           // end of 2026-10-10 UTC
  const claimSha = async (c) => sha(jcs(c));
  const conflictB = { decider_claim: B.claim, decider_sig: B.sig, received_at: NOW - 100 };
  const lineConflictB = { claim_sha256: await claimSha(B.claim), decider_sig: B.sig, received_at: NOW - 100 };
  const lineA = (conflicts, extra = {}) => ({ slot: A.slot, scope: "decider", event_ids: [evA.id], taken_at: NOW - 120, claim_sha256: null, decider_sig: A.sig, conflicts, ...extra });
  const filler = (k) => ({ slot: k.repeat(64), scope: "account", event_ids: [k.repeat(64)], taken_at: NOW - 3600, claim_sha256: null, decider_sig: null, conflicts: [] });
  const body = (conflicts, log) => ({ slot: A.slot, taken: true, event_ids: [evA.id], pending: false, taken_at: NOW - 120, scope: "decider",
    decider_claim: A.claim, decider_sig: A.sig, conflicts, ...(log === undefined ? {} : { log }) });
  const snap = async (line) => slotLog([filler("1"), filler("e"), line, filler("f")], { date: "2026-10-10", cutoff: CUTOFF });
  const cases = [];
  const add = async (name, b, expect_status, extra = {}) => {
    const rc = await readReceipt(evA);
    const obs = await observe(evA, rc, { nowSec: NOW, fetchImpl: slotFetch(() => b), trigger: "submitted", previous: null });
    if (obs.issuer_log === null || obs.issuer_log.status !== expect_status) throw new Error(name + ": " + JSON.stringify(obs.issuer_log));
    cases.push({ name, record_jcs: jcs(obs), expect_verdict: obs.verdict, expect_issuer_log_status: expect_status, ...extra });
  };
  const good = await snap(lineA([], { claim_sha256: await claimSha(A.claim) }));
  const withB = await snap(lineA([lineConflictB], { claim_sha256: await claimSha(A.claim) }));
  await add("log_absent", body([]), "absent");
  await add("log_not_yet_in_a_snapshot", body([], { status: "not_yet_in_a_snapshot", detail: "the slot log is snapshotted once per UTC day" }), "not_yet_in_a_snapshot");
  await add("included", body([], good.proof(A.slot)), "included", { snapshot_jsonl: good.file });
  await add("included_with_a_conflict", body([conflictB], withB.proof(A.slot)), "included", { snapshot_jsonl: withB.file });
  await add("conflict_after_the_cutoff_not_yet_logged", body([{ ...conflictB, received_at: CUTOFF + 10 }], good.proof(A.slot)), "included");
  await add("conflict_shown_but_missing_from_the_log", body([conflictB], good.proof(A.slot)), "line_disagrees");
  await add("conflict_in_the_log_not_shown", body([], withB.proof(A.slot)), "line_disagrees");
  const other = await snap(lineA([], { claim_sha256: await claimSha(A.claim), event_ids: ["0".repeat(64)] }));
  await add("line_lists_another_event", body([], other.proof(A.slot)), "line_disagrees");
  const pf = good.proof(A.slot);
  await add("path_altered", body([], { ...pf, merkle_path: pf.merkle_path.map((st, i) => (i === 0 ? { ...st, hash: "0".repeat(64) } : st)) }), "proof_fails");
  await add("log_root_altered", body([], { ...pf, log_root: "1".repeat(64) }), "proof_fails");
  await add("header_edited", body([], { ...pf, header: { ...pf.header, n_slots: 99 } }), "proof_fails");
  await add("header_without_cutoff", body([], { ...pf, header: Object.fromEntries(Object.entries(pf.header).filter(([k]) => k !== "cutoff")) }), "malformed");
  process.stdout.write(JSON.stringify({ schema: "nenrin-slot-witness-fixtures-v0.2", test_issuer_pubkey: TEST_PUB, test_slot_url_prefix: TEST_PREFIX, now: NOW, cutoff: CUTOFF, cases }, null, 1) + "\n");
}

async function main() {
  addTestIssuer();
  const slotA = "a".repeat(64), slotB = "b".repeat(64);
  const evA = await receipt({ slot: slotA });
  const evA2 = await receipt({ slot: slotA, choice: "deny", created_at: NOW - 60, extra: { choice_commitment: "d".repeat(64) } });
  const evB = await receipt({ slot: slotB });
  const cases = [];
  const add = async (name, ev, body, trigger = "submitted") => {
    const rc = await readReceipt(ev);
    const obs = await observe(ev, rc, { nowSec: NOW, fetchImpl: slotFetch(() => body), trigger, previous: null, version: "0" });
    const record_jcs = jcs(obs);
    cases.push({ name, record_jcs, expect_verdict: obs.verdict });
  };
  await add("unique", evA, { slot: slotA, taken: true, event_ids: [evA.id] });
  await add("listed_with_others", evA, { slot: slotA, taken: true, event_ids: [evA.id, evA2.id] });
  await add("not_listed", evA2, { slot: slotA, taken: true, event_ids: [evA.id] });
  await add("not_taken", evB, { slot: slotB, taken: false, event_ids: [] });
  await add("slot_mismatch", evB, { slot: slotA, taken: true, event_ids: [evB.id] });
  await add("unreadable_status", evB, new Response("gone", { status: 503 }));
  await add("unreadable_body", evB, "<html>not json</html>");
  process.stdout.write(JSON.stringify({ schema: "nenrin-slot-witness-fixtures-v0", test_issuer_pubkey: TEST_PUB, test_slot_url_prefix: TEST_PREFIX, now: NOW, cases }, null, 1) + "\n");
}

if (import.meta.url === "file://" + process.argv[1]) await (process.argv.includes("--v02") ? mainV02() : process.argv.includes("--v01") ? mainV01() : main());
