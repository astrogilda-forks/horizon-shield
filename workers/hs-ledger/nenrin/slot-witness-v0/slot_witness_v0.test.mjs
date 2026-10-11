// slot_witness_v0.test.mjs: BIP-340 against its own test vectors and a real invinoveritas event, then the slot
// witness intake on a fake KV and a fake issuer endpoint: each verdict, no redirects, size cap, dedup, caps, the
// daily watch catching a changed listing, the per-slot history, and the batch oldest first. v0.1: the decider reading
// on the first live decider-scoped slot's bytes and on generated ones, v0 observations still written as v0.
// Offline. Run: node nenrin/slot-witness-v0/slot_witness_v0.test.mjs   (in workers/hs-ledger)   exit 1 on any failure.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { schnorrVerify, schnorrSign, hexToBytes, nostrEventCheck } from "./bip340.mjs";
import { ISSUERS, readReceipt, judge, observe, deciderReading, issuerLogReading, handleSlotWitness, watchSlots, anchorSlotWitnessPool, BATCH_MAX, MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES_V0, OBS_SCHEMA, OBS_SCHEMA_V0, WATCH_DAYS } from "./slot_witness_v0.mjs";
import { Refusal } from "../trace-pin-v0/trace_pin_v0.mjs";
import { addTestIssuer, receipt, slotFetch, deciderClaim, slotLog, DECIDER_SK, TEST_PUB, TEST_PREFIX, NOW } from "./fixtures/gen_fixtures.mjs";

const R = [];
const t = (name, ok, detail = "") => R.push({ name, ok: !!ok, detail: String(detail) });
const sha = (s) => createHash("sha256").update(typeof s === "string" ? Buffer.from(s, "utf8") : s).digest("hex");
const HERE = new URL(".", import.meta.url).pathname;

// ---- BIP-340: the BIP's own vectors, and a real event the invinoveritas key signed ---------------------------
{
  const rows = readFileSync(HERE + "fixtures/bip340_test_vectors.csv", "utf8").trim().split("\n").slice(1).map((l) => l.split(","));
  // the BIP's file (bitcoin/bips bip-0340/test-vectors.csv, sha256 34c9d1d9..., CRLF line ends) with its line ends made LF,
  // because git am drops the CR; with every LF made CRLF again it is the BIP's bytes
  const csv = readFileSync(HERE + "fixtures/bip340_test_vectors.csv");
  t("bip340_test_vectors.csv is the BIP's file, line ends LF (sha256 01c8cabba63b4c9b2f44c975902990086a4fe56eee9d265b187d1e2c1d98ccfb), CRLF again gives the BIP's sha256 34c9d1d9...", sha(csv) === "01c8cabba63b4c9b2f44c975902990086a4fe56eee9d265b187d1e2c1d98ccfb" && sha(Buffer.from(csv.toString("latin1").replace(/\n/g, "\r\n"), "latin1")) === "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d");
  let v = 0, s = 0, sTotal = 0;
  for (const [i, sk, pk, aux, msg, sig, res] of rows) {
    if ((await schnorrVerify(hexToBytes(pk), hexToBytes(msg), hexToBytes(sig))) === (res === "TRUE")) v++; else t("BIP-340 vector " + i, false, "verify disagrees");
    if (sk) { sTotal++; if (Buffer.from(await schnorrSign(hexToBytes(sk), hexToBytes(msg), hexToBytes(aux))).toString("hex").toUpperCase() === sig) s++; }
  }
  t("BIP-340 verify agrees with all " + rows.length + " test vectors (valid and invalid)", v === rows.length, v + "/" + rows.length);
  t("BIP-340 sign reproduces every vector that has a secret key", s === sTotal && sTotal > 0, s + "/" + sTotal);
  const real = JSON.parse(readFileSync(HERE + "fixtures/invinoveritas_event.json", "utf8")).event;
  const c = await nostrEventCheck(real);
  t("a real invinoveritas event: NIP-01 id recomputes and the BIP-340 signature verifies", c.ok && c.id === real.id, JSON.stringify(c));
  t("the same event with one character of content changed fails on the id", !(await nostrEventCheck({ ...real, content: real.content.replace("reject", "rejecT") })).ok);
  const flipped = real.sig.slice(0, 127) + (real.sig[127] === "0" ? "1" : "0");
  t("the same event with one bit of the signature changed fails", !(await nostrEventCheck({ ...real, sig: flipped })).ok);
  const r = await readReceipt(real).then(() => null, (e) => (e instanceof Refusal ? e.code : "THREW " + e.message));
  t("readReceipt on that real event (a verdict proof, no request_slot): the issuer key is read, the receipt is refused as no_request_slot", r === "no_request_slot", r);
}

addTestIssuer();
const SLOT = "a".repeat(64), SLOT2 = "b".repeat(64);
const evA = await receipt({ slot: SLOT });
const evA2 = await receipt({ slot: SLOT, created_at: NOW - 60, extra: { choice_commitment: "d".repeat(64) } });
const code = (p) => p.then(() => null, (e) => (e instanceof Refusal ? e.code : "THREW " + e.message));

// ---- readReceipt refusals ------------------------------------------------------------------------------------
{
  t("an unknown issuer key is refused by name", (await code(readReceipt({ ...evA, pubkey: "1".repeat(64) }))) === "issuer_not_read");
  t("a bad signature is refused", (await code(readReceipt({ ...evA, sig: "0".repeat(128) }))) === "bad_event");
  t("a non-object is refused", (await code(readReceipt("x"))) === "not_an_event");
  const noSlot = await receipt({ slot: null });
  t("a receipt with request_slot null is refused as no_request_slot", (await code(readReceipt(noSlot))) === "no_request_slot");
  const badSlot = await receipt({ slot: "../../admin?x=1" });
  t("a request_slot that is not URL-safe is refused", (await code(readReceipt(badSlot))) === "bad_request_slot");
  const rc = await readReceipt(evA);
  t("a good receipt yields its slot and content schema", rc.slot === SLOT && rc.content_schema === "invinoveritas.decision_receipt.v0");
}

// ---- judge: every verdict ------------------------------------------------------------------------------------
{
  const b = (o) => new TextEncoder().encode(typeof o === "string" ? o : JSON.stringify(o));
  const id = evA.id, other = evA2.id;
  const cases = [
    ["unique", judge(200, b({ slot: SLOT, taken: true, event_ids: [id] }), SLOT, id)],
    ["listed_with_others", judge(200, b({ slot: SLOT, taken: true, event_ids: [other, id] }), SLOT, id)],
    ["not_listed", judge(200, b({ slot: SLOT, taken: true, event_ids: [other] }), SLOT, id)],
    ["not_taken", judge(200, b({ slot: SLOT, taken: false, event_ids: [] }), SLOT, id)],
    ["slot_mismatch", judge(200, b({ slot: SLOT2, taken: true, event_ids: [id] }), SLOT, id)],
    ["unreadable", judge(404, b({}), SLOT, id)],
    ["unreadable", judge(200, b("[1,2]"), SLOT, id)],
    ["unreadable", judge(200, b({ slot: SLOT, taken: true, event_ids: "x" }), SLOT, id)],
    ["unreadable", judge(200, new Uint8Array([0xff, 0xfe]), SLOT, id)],
    ["fetch_failed", judge(null, new Uint8Array(0), SLOT, id)],
  ];
  for (const [want, got] of cases) t("judge: " + want, got.verdict === want, got.verdict);
  t("judge: taken true with an empty list is not_listed, never unique", judge(200, b({ slot: SLOT, taken: true, event_ids: [] }), SLOT, id).verdict === "not_listed");
  t("judge: the same id twice is listed_with_others, not unique", judge(200, b({ slot: SLOT, taken: true, event_ids: [id, id] }), SLOT, id).verdict === "listed_with_others");
}

// ---- the HTTP surface ----------------------------------------------------------------------------------------
function fakeEnv() {
  const m = new Map();
  return { m, LEDGER: {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
    async list({ prefix = "", cursor } = {}) {
      const all = [...m.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0, page = all.slice(start, start + 1000);
      const done = start + 1000 >= all.length;
      return { keys: page.map((name) => ({ name })), list_complete: done, cursor: done ? undefined : String(start + 1000) };
    },
  } };
}
const ORIGIN = "https://ledger.horizonshield.dev";
let listing = { [SLOT]: [evA.id], [SLOT2]: [] };
const seen = [];
const issuerFetch = slotFetch((slot, u) => { seen.push(u); return { slot, taken: (listing[slot] || []).length > 0, event_ids: listing[slot] || [] }; });
const call = async (env, method, path, body, now = NOW, ip = "203.0.113.7", f = issuerFetch) => {
  const url = new URL(ORIGIN + path);
  const req = new Request(url, { method, headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: body ? JSON.stringify(body) : undefined });
  const res = await handleSlotWitness(url.pathname, req, url, env, ORIGIN, now, f);
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch (_e) {}
  return { status: res.status, json, text, headers: res.headers };
};

{
  const env = fakeEnv();
  const d = await call(env, "GET", "/evidence/slot");
  t("GET /evidence/slot describes the intake, its issuers and its limits", d.status === 200 && d.json.issuers_read.some((i) => i.name === "invinoveritas") && d.json.does_not_establish.length >= 4);
  t("the route ignores other paths", (await handleSlotWitness("/evidence/vouch", new Request(ORIGIN), new URL(ORIGIN), env, ORIGIN)) === null);
  const a = await call(env, "POST", "/evidence/slot", { event: evA });
  t("POST a receipt: 201, verdict unique, the ledger fetched the slot endpoint itself", a.status === 201 && a.json.verdict === "unique" && seen.at(-1) === TEST_PREFIX + SLOT, JSON.stringify(a.json).slice(0, 200));
  const raw = await call(env, "GET", "/evidence/slot/" + a.json.sha + "?format=raw");
  const obs = JSON.parse(raw.text);
  t("?format=raw serves the record bytes whose sha256 is the sha", sha(raw.text) === a.json.sha && raw.headers.get("x-record-sha256") === a.json.sha);
  t("the record keeps the response bytes and their sha256", sha(Buffer.from(obs.response_b64, "base64")) === obs.response_sha256 && obs.response_bytes === Buffer.from(obs.response_b64, "base64").length);
  t("the record carries the signed receipt itself and no previous observation", obs.receipt_event.id === evA.id && obs.previous_observation === null && obs.changed_since_previous === null);
  const again = await call(env, "POST", "/evidence/slot", { event: evA }, NOW + 3600);
  t("the same receipt again within 6 hours: dedup, no second fetch", again.status === 200 && again.json.dedup && again.json.sha === a.json.sha && seen.length === 1);
  const refused = await call(env, "POST", "/evidence/slot", { event: { ...evA, sig: "0".repeat(128) } });
  t("a bad signature: 422 refused with a reason code", refused.status === 422 && refused.json.reason_code === "bad_event");
  t("a body without event: 400", (await call(env, "POST", "/evidence/slot", { credential: 1 })).status === 400);
  t("PUT: 405", (await call(env, "PUT", "/evidence/slot", {})).status === 405);

  // the second receipt for the same slot: the issuer still lists only the first
  const b2 = await call(env, "POST", "/evidence/slot", { event: evA2 }, NOW + 60);
  t("a second receipt naming the same slot, while the issuer lists the first: not_listed", b2.status === 201 && b2.json.verdict === "not_listed", b2.json && b2.json.verdict);
  // the watch, a day later, after the issuer's listing changed to two receipts
  listing = { [SLOT]: [evA.id, evA2.id], [SLOT2]: [] };
  const w = await watchSlots(env, NOW + 21 * 3600, issuerFetch);
  t("the daily watch re-reads both (slot, receipt) pairs and sees the change", w.observed === 2 && w.changed === 2, JSON.stringify(w));
  const hist = await call(env, "GET", "/evidence/slot/s/" + SLOT);
  t("the slot history lists 4 observations oldest first and says the listing changed", hist.status === 200 && hist.json.count === 4 && hist.json.slot_listing_changed === true && hist.json.receipts_submitted_for_this_slot.length === 2, JSON.stringify(hist.json).slice(0, 300));
  const latest = hist.json.observations.filter((o) => o.receipt_event_id === evA.id).at(-1);
  const latestRec = JSON.parse((await call(env, "GET", "/evidence/slot/" + latest.sha + "?format=raw")).text);
  t("the watch observation of the first receipt is listed_with_others and links to the first observation", latestRec.verdict === "listed_with_others" && latestRec.previous_observation.sha === a.json.sha && latestRec.changed_since_previous === true && latestRec.trigger === "watch");
  const w2 = await watchSlots(env, NOW + 22 * 3600, issuerFetch);
  t("the watch does not re-read a pair it read less than 20 hours ago", w2.observed === 0);
  const w3 = await watchSlots(env, NOW + (WATCH_DAYS + 1) * 86400, issuerFetch);
  t("the watch stops " + WATCH_DAYS + " days after the first observation", w3.observed === 0 && w3.due === 0);
  t("an unknown slot: 404", (await call(env, "GET", "/evidence/slot/s/" + "c".repeat(64))).status === 404);
  t("a bad slot in the path: 400", (await call(env, "GET", "/evidence/slot/s/" + encodeURIComponent("../x"))).status === 400);

  // fetch failure, redirect, oversized body
  const evB = await receipt({ slot: SLOT2 });
  const f1 = await call(env, "POST", "/evidence/slot", { event: evB }, NOW, "198.51.100.1", async () => { throw new Error("down"); });
  t("the endpoint does not answer: verdict fetch_failed, still recorded", f1.status === 201 && f1.json.verdict === "fetch_failed" && f1.json.http_status === null);
  const evC = await receipt({ slot: "c".repeat(64) });
  const f2 = await call(env, "POST", "/evidence/slot", { event: evC }, NOW, "198.51.100.2", slotFetch(() => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } })));
  t("a redirect is not followed: verdict unreadable with status 302", f2.json.verdict === "unreadable" && f2.json.http_status === 302);
  const evD = await receipt({ slot: "d".repeat(64) });
  const f3 = await call(env, "POST", "/evidence/slot", { event: evD }, NOW, "198.51.100.3", slotFetch((slot) => JSON.stringify({ slot, taken: true, event_ids: [evD.id], pad: "x".repeat(MAX_RESPONSE_BYTES) })));
  const r3 = JSON.parse((await call(env, "GET", "/evidence/slot/" + f3.json.sha + "?format=raw")).text);
  t("a response over " + MAX_RESPONSE_BYTES + " bytes is cut there and judged unreadable", r3.verdict === "unreadable" && r3.response_truncated === true && r3.response_bytes === MAX_RESPONSE_BYTES);

  // per-network cap
  const env2 = fakeEnv();
  let capped = null;
  for (let i = 0; i < 21; i++) {
    const ev = await receipt({ slot: ("e" + String(i).padStart(2, "0")).padEnd(64, "0") });
    const r = await call(env2, "POST", "/evidence/slot", { event: ev }, NOW, "192.0.2.9");
    if (r.status === 429) { capped = i; break; }
  }
  t("one network is capped at 20 new observations a day", capped === 20, capped);

  // anchoring
  const an = await anchorSlotWitnessPool(env, ORIGIN, "test", "2026-10-11T00:30:00Z");
  const entry = JSON.parse(env.m.get("entry:" + an.body.n));
  const batch = JSON.parse(entry.record_canonical);
  t("the batch lists every pending observation, oldest first, and is the entry's claim", an.status === 201 && batch.schema === "nenrin-slot-witness-batch-v0" && batch.count === batch.records.length && batch.records.every((r, i, a) => i === 0 || a[i - 1].observed_at <= r.observed_at) && entry.claim_sha256 === sha(entry.record_canonical));
  const one = await call(env, "GET", "/evidence/slot/" + a.json.sha);
  t("after the batch an observation reads as anchored with its ledger entry", one.json.status === "anchored" && one.json.anchor.ledger_entry === an.body.n);
  t("the pending list is empty after the batch", (await call(env, "GET", "/evidence/slot/pending")).json.count === 0);
  const envB = fakeEnv();
  for (let i = 0; i < BATCH_MAX + 1; i++) {
    const s = sha("obs" + i);
    envB.m.set("slotw:pending:" + s, JSON.stringify({ sha: s, request_slot: "x".repeat(64), receipt_event_id: "0".repeat(64), verdict: "unique", observed_at: new Date(Date.UTC(2026, 9, 10, 0, 0, BATCH_MAX + 1 - i)).toISOString(), response_sha256: "0".repeat(64) }));
  }
  const anB = await anchorSlotWitnessPool(envB, ORIGIN, "test", "2026-10-11T00:30:00Z");
  t("a batch of " + BATCH_MAX + " oldest first, the newest left for the next day", anB.body.anchored === BATCH_MAX && anB.body.remaining === 1 && envB.m.has("slotw:pending:" + sha("obs0")));
}

// ---- v0.1: the decider reading -----------------------------------------------------------------------------------
{
  const L = JSON.parse(readFileSync(HERE + "fixtures/invinoveritas_slot_decider_20261010.json", "utf8"));
  const body = new Uint8Array(Buffer.from(L.response_b64, "base64"));
  t("the live slot bytes are the ones the ledger kept (sha256)", sha(body) === L.response_sha256);
  const rc = L.receipt_content_decider;
  const d = await deciderReading(200, body, rc.request_slot, rc);
  t("the live slot (2026-10-10): the holder's claim verifies, one conflict listed and it verifies under the same decider key: equivocation", JSON.stringify(d) === JSON.stringify(L.expect_decider), JSON.stringify(d));
  const j = JSON.parse(Buffer.from(body).toString("utf8"));
  const mut = (f) => { const x = JSON.parse(JSON.stringify(j)); f(x); return new TextEncoder().encode(JSON.stringify(x)); };
  const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1);
  const d1 = await deciderReading(200, mut((x) => { x.conflicts[0].decider_sig = flip(x.conflicts[0].decider_sig); }), rc.request_slot, rc);
  t("the same bytes with the conflict's signature altered: listed 1, verified 0, no equivocation", d1.conflicts_listed === 1 && d1.conflicts_verified === 0 && d1.equivocation === false);
  const d2 = await deciderReading(200, mut((x) => { x.conflicts[0].decider_claim.choice_commitment = "0".repeat(64); }), rc.request_slot, rc);
  t("a conflict whose claim was edited after signing does not verify", d2.conflicts_verified === 0 && d2.equivocation === false);
  const d3 = await deciderReading(200, mut((x) => { x.conflicts = [x.conflicts[0], x.conflicts[0]]; }), rc.request_slot, rc);
  t("the same conflict listed twice is still one other claim: equivocation, and both entries counted as listed", d3.conflicts_listed === 2 && d3.equivocation === true);
  const d4 = await deciderReading(200, mut((x) => { x.conflicts = [{ decider_claim: x.decider_claim, decider_sig: x.decider_sig }]; }), rc.request_slot, rc);
  t("a conflict that repeats the holder's own claim is not another claim: no equivocation", d4.conflicts_verified === 0 && d4.equivocation === false);
  const d5 = await deciderReading(200, mut((x) => { x.conflicts[0].decider_claim.request_slot = "f".repeat(64); }), rc.request_slot, rc);
  t("a conflict naming another slot is not counted", d5.conflicts_verified === 0);
  t("an account-scoped slot (no decider_claim) reads as null", (await deciderReading(200, mut((x) => { delete x.decider_claim; }), rc.request_slot, rc)) === null);
  t("a non-200 answer or bytes that are not JSON read as null", (await deciderReading(503, body, rc.request_slot, rc)) === null && (await deciderReading(200, new Uint8Array([0xff]), rc.request_slot, rc)) === null);

  // the intake, end to end, on a generated decider-scoped slot whose conflict appears a day later
  const A = await deciderClaim(DECIDER_SK, { request_id: "e2e" });
  const B = await deciderClaim(DECIDER_SK, { request_id: "e2e", choice: "deny", claimed_at: NOW - 30 });
  const ev = await receipt({ slot: A.slot, extra: { decider_pubkey: A.pub, decider_claim: A.claim, decider_sig: A.sig } });
  let conflicts = [];
  const f = slotFetch((slot) => ({ slot, taken: true, event_ids: [ev.id], scope: "decider", decider_claim: A.claim, decider_sig: A.sig, conflicts }));
  const env = fakeEnv();
  const p = await call(env, "POST", "/evidence/slot", { event: ev }, NOW, "203.0.113.50", f);
  t("POST a decider-scoped receipt: v0.1 observation, the holder verifies, no conflicts yet", p.status === 201 && p.json.decider && p.json.decider.holder_claim === "verifies" && p.json.decider.equivocation === false, JSON.stringify(p.json && p.json.decider));
  const rec = JSON.parse((await call(env, "GET", "/evidence/slot/" + p.json.sha + "?format=raw")).text);
  t("the record says " + OBS_SCHEMA + " and carries the decider field", rec.schema === OBS_SCHEMA && rec.decider && rec.decider.pubkey === A.pub);
  conflicts = [{ decider_claim: B.claim, decider_sig: B.sig, received_at: NOW - 30 }];
  const w = await watchSlots(env, NOW + 21 * 3600, f);
  t("the watch a day later: the event list is the same, the new conflict is a change", w.observed === 1 && w.changed === 1, JSON.stringify(w));
  const h = await call(env, "GET", "/evidence/slot/s/" + A.slot);
  t("the slot history shows equivocation seen, while the listing itself did not change", h.json.decider_equivocation_seen === true && h.json.slot_listing_changed === false && h.json.observations.at(-1).decider.equivocation === true);

  // v0 observations stay as written
  const ev0 = await receipt({ slot: A.slot, extra: { decider_pubkey: A.pub, decider_claim: A.claim, decider_sig: A.sig } });
  const rc0 = await readReceipt(ev0);
  const o0 = await observe(ev0, rc0, { nowSec: NOW, fetchImpl: f, trigger: "submitted", previous: null, version: "0" });
  t("version 0: schema " + OBS_SCHEMA_V0 + " and no decider field", o0.schema === OBS_SCHEMA_V0 && !("decider" in o0));
  const big = slotFetch((slot) => JSON.stringify({ slot, taken: true, event_ids: [ev0.id], pad: "x".repeat(MAX_RESPONSE_BYTES_V0) }));
  const o0b = await observe(ev0, rc0, { nowSec: NOW, fetchImpl: big, trigger: "submitted", previous: null, version: "0" });
  const o1b = await observe(ev0, rc0, { nowSec: NOW, fetchImpl: big, trigger: "submitted", previous: null });
  t("a response a little over " + MAX_RESPONSE_BYTES_V0 + " bytes: cut under v0, kept whole and read under v0.1", o0b.response_truncated === true && o0b.response_bytes === MAX_RESPONSE_BYTES_V0 && o1b.response_truncated === false && o1b.verdict === "unique");
}

// ---- v0.2: the issuer's slot log ------------------------------------------------------------------------------
{
  const A = await deciderClaim(DECIDER_SK, { request_id: "log-e2e" });
  const ev = await receipt({ slot: A.slot, extra: { decider_pubkey: A.pub, decider_claim: A.claim, decider_sig: A.sig } });
  const line = { slot: A.slot, scope: "decider", event_ids: [ev.id], taken_at: NOW - 120, claim_sha256: null, decider_sig: A.sig, conflicts: [] };
  let log = { status: "not_yet_in_a_snapshot" };
  const f = slotFetch((slot) => ({ slot, taken: true, event_ids: [ev.id], taken_at: NOW - 120, scope: "decider", decider_claim: A.claim, decider_sig: A.sig, conflicts: [], log }));
  const env = fakeEnv();
  const p = await call(env, "POST", "/evidence/slot", { event: ev }, NOW, "203.0.113.60", f);
  t("POST: a v0.2 observation, issuer_log not_yet_in_a_snapshot", p.status === 201 && p.json.issuer_log && p.json.issuer_log.status === "not_yet_in_a_snapshot", JSON.stringify(p.json && p.json.issuer_log));
  // the snapshot appears: the same slot, now with its line and proof (claim_sha256 is filled from the claim the slot holds)
  const { jcs } = await import("../trace-pin-v0/trace_pin_v0.mjs");
  const line2 = { ...line, claim_sha256: createHash("sha256").update(jcs(A.claim)).digest("hex") };
  const lg2 = await slotLog([line2, { ...line2, slot: "f".repeat(64), event_ids: ["f".repeat(64)] }], { date: "2026-10-10", cutoff: Date.UTC(2026, 9, 11) / 1000 });
  log = lg2.proof(A.slot);
  const w = await watchSlots(env, NOW + 21 * 3600, f);
  t("the watch a day later: the line appeared in the issuer's log, counted as a change", w.observed === 1 && w.changed === 1, JSON.stringify(w));
  const h = await call(env, "GET", "/evidence/slot/s/" + A.slot);
  t("the slot history lists the statuses seen, oldest first: not_yet_in_a_snapshot, then included", JSON.stringify(h.json.issuer_log_statuses_seen) === JSON.stringify(["not_yet_in_a_snapshot", "included"]), JSON.stringify(h.json.issuer_log_statuses_seen));
  const b = (o) => new TextEncoder().encode(JSON.stringify(o));
  const base = { slot: A.slot, taken: true, event_ids: [ev.id], taken_at: NOW - 120, scope: "decider", decider_claim: A.claim, decider_sig: A.sig, conflicts: [] };
  const REAL = JSON.parse(readFileSync(HERE + "fixtures/invinoveritas_slot_log_20261010.json", "utf8"));
  t("the live slot after the issuer's 2026-10-10 snapshot: its log reads as included under log_root 9214af3a...",
    JSON.stringify(await issuerLogReading(200, new TextEncoder().encode(REAL.body), REAL.slot)) === JSON.stringify(REAL.expect_issuer_log));
  t("issuerLogReading: an edited line no longer reaches the root", (await issuerLogReading(200, b({ ...base, log: { ...log, line: { ...log.line, taken_at: 1 } } }), A.slot)).status === "proof_fails");
  t("issuerLogReading: a claim that is not the one in the line disagrees on claim_sha256", (await issuerLogReading(200, b({ ...base, decider_claim: { ...A.claim, claimed_at: 1 }, log }), A.slot)).disagreements.includes("claim_sha256"));
  t("issuerLogReading: a merkle path longer than 64 steps is malformed", (await issuerLogReading(200, b({ ...base, log: { ...log, merkle_path: Array(65).fill(log.merkle_path[0]) } }), A.slot)).status === "malformed");
  t("issuerLogReading: a header with another schema is malformed", (await issuerLogReading(200, b({ ...base, log: { ...log, header: { ...log.header, schema: "x" } } }), A.slot)).status === "malformed");
  t("issuerLogReading: no log is absent; a non-200 answer is null", (await issuerLogReading(200, b(base), A.slot)).status === "absent" && (await issuerLogReading(404, b(base), A.slot)) === null);
}

// ---- the fixtures slot_check.py reads regenerate byte for byte -------------------------------------------------
{
  const out = execFileSync(process.execPath, [HERE + "fixtures/gen_fixtures.mjs"], { encoding: "utf8" });
  t("fixtures/slot_fixtures.json (v0) regenerates byte for byte", out === readFileSync(HERE + "fixtures/slot_fixtures.json", "utf8"));
  const out1 = execFileSync(process.execPath, [HERE + "fixtures/gen_fixtures.mjs", "--v01"], { encoding: "utf8" });
  t("fixtures/slot_fixtures_v01.json regenerates byte for byte", out1 === readFileSync(HERE + "fixtures/slot_fixtures_v01.json", "utf8"));
  const out2 = execFileSync(process.execPath, [HERE + "fixtures/gen_fixtures.mjs", "--v02"], { encoding: "utf8" });
  t("fixtures/slot_fixtures_v02.json regenerates byte for byte", out2 === readFileSync(HERE + "fixtures/slot_fixtures_v02.json", "utf8"));
}

// ---- the outside copy of the issuer's slot log (slot_log_copy.mjs) ------------------------------------------------
{
  const { copySlotLog, handleSlotLog, checkDayFile, ISSUER, COPY_SCHEMA } = await import("./slot_log_copy.mjs");
  const enc8 = (s) => new TextEncoder().encode(s);
  const D9 = await slotLog([], { date: "2026-10-09", cutoff: Date.UTC(2026, 9, 10) / 1000 });
  const line = { slot: "a".repeat(64), scope: "decider", event_ids: ["e".repeat(64)], taken_at: Date.UTC(2026, 9, 10, 11) / 1000, claim_sha256: "c".repeat(64), decider_sig: "d".repeat(128), conflicts: [] };
  const D10 = await slotLog([line], { date: "2026-10-10", cutoff: Date.UTC(2026, 9, 11) / 1000, prev_root: D9.log_root });
  const lineC = { ...line, conflicts: [{ claim_sha256: "f".repeat(64), decider_sig: "9".repeat(128), received_at: Date.UTC(2026, 9, 11, 3) / 1000 }] };
  const D11 = await slotLog([lineC, { ...line, slot: "b".repeat(64) }], { date: "2026-10-11", cutoff: Date.UTC(2026, 9, 12) / 1000, prev_root: D10.log_root });
  const D11gone = await slotLog([{ ...line, slot: "b".repeat(64) }], { date: "2026-10-11", cutoff: Date.UTC(2026, 9, 12) / 1000, prev_root: D10.log_root });
  const ots = (tag) => enc8("OTS-" + tag);   // the copy keeps .ots bytes as served; reading them is the checker's
  const site = { files: { "2026-10-09": D9.file, "2026-10-10": D10.file }, ots: { "2026-10-09": ots("9-confirmed"), "2026-10-10": ots("10-pending") }, status: { "2026-10-09": "confirmed", "2026-10-10": "pending" } };
  const index = async () => ({ snapshots: await Promise.all(Object.keys(site.files).map(async (d) => ({ date: d, file_sha256: sha(Buffer.from(site.files[d])), log_root: (await checkDayFile(enc8(site.files[d]))).log_root, ots_status: site.status[d] }))) });
  const otsAsked = [];
  let lieAbout = null;
  const fx = async (u) => {
    if (u === ISSUER.log_url) { const ix = await index(); for (const sn of ix.snapshots) if (sn.date === lieAbout) sn.file_sha256 = "0".repeat(64); return new Response(JSON.stringify(ix), { status: 200 }); }
    if (u.endsWith(".ots")) otsAsked.push(u.slice(-14, -4));
    const m = /\/slots\/log\/(\d{4}-\d{2}-\d{2})(\.ots)?$/.exec(u);
    if (m && m[2] && site.ots[m[1]]) return new Response(site.ots[m[1]], { status: 200 });
    if (m && !m[2] && site.files[m[1]]) return new Response(site.files[m[1]], { status: 200 });
    return new Response("no", { status: 404 });
  };
  const off = fakeEnv();
  let offAsked = 0;
  const r0 = await copySlotLog(off, NOW, async (u) => { offAsked++; return fx(u); });
  const base0 = "https://ledger.horizonshield.dev/evidence/slot-log/refresh";
  const rr0 = await handleSlotLog("/evidence/slot-log/refresh", new Request(base0, { method: "POST" }), new URL(base0), off, "https://ledger.horizonshield.dev", NOW, async (u) => { offAsked++; return fx(u); });
  t("without SLOT_LOG_COPY=on the copy fetches nothing and writes nothing; refresh says 503 copy_off", r0.off === true && offAsked === 0 && off.m.size === 0 && rr0.status === 503 && (await rr0.json()).error === "copy_off", JSON.stringify(r0));
  const env = fakeEnv();
  env.SLOT_LOG_COPY = "on";
  const r1 = await copySlotLog(env, NOW, fx);
  t("slot log copy: both days copied, each .ots kept, nothing to report", JSON.stringify(r1.new_days) === JSON.stringify(["2026-10-09", "2026-10-10"]) && r1.ots_kept.length === 2 && r1.problems.length === 0 && r1.divergent.length === 0, JSON.stringify(r1));
  const day10 = JSON.parse(env.m.get("slotlog:day:2026-10-10"));
  t("the 10/10 copy passed every check, the chain to 10/09 included", day10.problems.length === 0 && day10.prev_root === D9.log_root && day10.log_root === D10.log_root);
  const rec = JSON.parse(JSON.parse(env.m.get("slotw:pending:" + day10.record_sha)).record_jcs);
  t("its copy record waits in the slot witness pool for the daily batch", rec.schema === COPY_SCHEMA && rec.checked_against_previous_copy === "2026-10-09" && rec.file_sha256 === sha(Buffer.from(D10.file)));
  const base = "https://ledger.horizonshield.dev";
  const get = async (path, method = "GET", now = NOW) => { const url = new URL(base + path); return handleSlotLog(url.pathname, new Request(url, { method }), url, env, base, now, fx); };
  const f10 = await get("/evidence/slot-log/2026-10-10");
  t("GET /evidence/slot-log/2026-10-10 serves the day file byte for byte", (await f10.text()) === D10.file && f10.headers.get("x-file-sha256") === sha(Buffer.from(D10.file)));
  const o10 = await get("/evidence/slot-log/2026-10-10.ots");
  t("GET .../2026-10-10.ots serves the kept .ots", Buffer.from(await o10.arrayBuffer()).toString() === "OTS-10-pending" && o10.headers.get("x-issuer-ots-status") === "pending");
  const idx = await (await get("/evidence/slot-log")).json();
  t("GET /evidence/slot-log lists the copies with their files, proofs and records", idx.copies.length === 2 && idx.copies[1].record.endsWith(day10.record_sha + "?format=raw"));
  // the next day: 10/10's .ots upgrades, 10/11 appears
  site.ots["2026-10-10"] = ots("10-confirmed"); site.status["2026-10-10"] = "confirmed"; site.files["2026-10-11"] = D11.file; site.ots["2026-10-11"] = ots("11-pending"); site.status["2026-10-11"] = "pending";
  const r2 = await copySlotLog(env, NOW + 86400, fx);
  const d10b = JSON.parse(env.m.get("slotlog:day:2026-10-10"));
  t("a day later: 10/11 copied (a new conflict appended is allowed), 10/10's confirmed .ots kept beside the pending one", JSON.stringify(r2.new_days) === JSON.stringify(["2026-10-11"]) && JSON.parse(env.m.get("slotlog:day:2026-10-11")).problems.length === 0 && d10b.ots.length === 2 && d10b.ots[1].issuer_ots_status === "confirmed", JSON.stringify(r2));
  t("the confirmed .ots is the one served by default", Buffer.from(await (await get("/evidence/slot-log/2026-10-10.ots")).arrayBuffer()).toString() === "OTS-10-confirmed");
  otsAsked.length = 0;
  const r3 = await copySlotLog(env, NOW + 2 * 86400, fx);
  t("once a confirmed .ots is kept, that day's .ots is not asked for again", !otsAsked.includes("2026-10-09") && !otsAsked.includes("2026-10-10") && otsAsked.includes("2026-10-11") && r3.new_days.length === 0, JSON.stringify(otsAsked));
  // the issuer serves another 10/11: a slot of 10/10 is gone
  site.files["2026-10-11"] = D11gone.file;
  const r4 = await copySlotLog(env, NOW + 3 * 86400, fx);
  const d11 = JSON.parse(env.m.get("slotlog:day:2026-10-11"));
  t("another file for a date already held: kept beside the first, recorded as divergent, with the chain problem named", JSON.stringify(r4.divergent) === JSON.stringify(["2026-10-11"]) && d11.divergent.length === 1 && d11.divergent[0].problems.includes("slot_of_the_previous_day_missing"), JSON.stringify(d11.divergent));
  const both = [await (await get("/evidence/slot-log/2026-10-11")).text(), await (await get("/evidence/slot-log/2026-10-11?file_sha256=" + d11.divergent[0].file_sha256)).text()];
  t("both 10/11 files are served by their sha256", both[0] === D11.file && both[1] === D11gone.file);
  const r5 = await copySlotLog(env, NOW + 4 * 86400, fx);
  t("the same divergent file is not recorded twice", r5.divergent.length === 0);
  // an index entry whose file_sha256 is not the file's
  site.files["2026-10-12"] = (await slotLog([lineC, { ...line, slot: "b".repeat(64) }], { date: "2026-10-12", cutoff: Date.UTC(2026, 9, 13) / 1000, prev_root: D11.log_root })).file;
  lieAbout = "2026-10-12";
  await copySlotLog(env, NOW + 4 * 86400 + 2000, fx);
  t("an index whose file_sha256 is not the file served: named in the copy's problems", JSON.parse(env.m.get("slotlog:day:2026-10-12")).problems.includes("file_sha256_differs_from_index"));
  // the day file on its own
  const bad = async (text) => (await checkDayFile(enc8(text))).problems;
  t("checkDayFile: a file whose index sha differs is caught by the copy, and the file rules on their own", (await bad(D10.file.replace("\n", " \n"))).length > 0 && (await bad(D10.file.slice(0, -1))).includes("not_newline_terminated"));
  const tampered = D10.file.replace('"n_slots":1', '"n_slots":2');
  t("checkDayFile: n_slots edited is caught (and the log_root moves)", (await bad(tampered)).includes("n_slots_differs"));
  t("checkDayFile: the empty day (10/09) passes, its root is the SPEC's empty tree", (await bad(D9.file)).length === 0);
  // refresh: at most once an hour
  t("POST /evidence/slot-log/refresh within the hour: 429", (await get("/evidence/slot-log/refresh", "POST", NOW + 4 * 86400 + 60)).status === 429);
  t("POST /evidence/slot-log/refresh after the hour runs the copy", (await get("/evidence/slot-log/refresh", "POST", NOW + 4 * 86400 + 6000)).status === 200);
  t("an unknown day is 404, other methods 405", (await get("/evidence/slot-log/2026-01-01")).status === 404 && (await get("/evidence/slot-log", "POST")).status === 405);
}

delete ISSUERS[TEST_PUB];
const bad = R.filter((r) => !r.ok);
for (const r of R) console.log((r.ok ? "ok    " : "FAIL  ") + r.name + (r.ok ? "" : "  [" + r.detail + "]"));
console.log("\n" + (R.length - bad.length) + "/" + R.length + " passed");
process.exit(bad.length ? 1 : 0);
