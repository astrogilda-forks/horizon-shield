// RUN_ALL: library  v2.4 の攻めの入力 (red team R2-1 と R5-F1)。採点は witness_v24_test.mjs、Python の写しは recovery_twin_test.py
//
// 2026-10-22. 2026-10-09 の社内 red team の 2 件を、入力として固定する。
//   R2-1: 引いた証人の署名つき観測を、別の事故の定足数に使い回せた。抽選の記録は依頼を hash でしか持たないので、前の
//         事故の依頼の hash を書けば、前の観測がそのまま数えられた。k を方針より大きくすれば、使い回したい証人が
//         籤に入るまで籤を広げられた。
//   R5-F1: 先に台帳に打つ約束が主題だけを固め、池を固めていなかった。beacon を見てから池を選び直せた。
// 事故 B は fixture の事故 A と同じ扉で、実行の時刻だけが違う (07:58、A の観測 08:04 より前)。鍵は fixture の決定的な鍵。
// 各 case は { name, records, quorum, old, new } で、old は直す前 (0.3.1) の検証器の答え、new は 0.4.0 の答え
// ({ ok, codes } の codes は含まれるべき code)。quorum は JSON にできる物だけ (Python の写しにもそのまま渡す)。
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { buildFixture } from "./recovery_fixture_build.mjs";
import { seal, sign } from "./recovery_verify.mjs";
import { SCHEMAS } from "./recovery_schema.mjs";
import { draw, drawField, drawFieldV24, poolSha256, commitmentClaimText, commitmentClaimTextV2 } from "./witness_draw.mjs";
import { buildRequest, requestSha256 } from "./witness_request.mjs";
import { buildPool, buildBeacon, fixtureKey, WITNESS_FIXTURE_FILE, ORIGIN, OWN_HOST } from "./witness_fixture_build.mjs";
import { sha256Hex } from "./recovery_verify.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const clone = (x) => JSON.parse(JSON.stringify(x));

async function observe(domain, keyUrl, requestHash, expectedAfter, at) {
  const k = await fixtureKey(domain);
  const observed = {};
  for (const [surface, exp] of Object.entries(expectedAfter)) observed[surface] = { status: "200", ...exp, vantage_note: "measured from " + domain };
  return sign({
    schema: SCHEMAS.observation, recorded_at: at, witness: { name: domain, vantage: "fixture witness with a deterministic key; not a real agent" }, prev: null,
    endpoint: ORIGIN, observed, request_sha256: requestHash,
    source: { kind: "external_witness", signed_domain: domain, key_url: keyUrl },
    establishes: ["at recorded_at this witness saw the observed state of the listed surfaces of endpoint"],
    does_not_establish: ["that this witness is a real independent agent: the key is a fixture seed", "why the surfaces are in this state", "anything about surfaces not listed in observed"],
  }, k.privKey, k.pubRaw);
}

async function commitV1(subject) {
  return { subject_sha256: subject, ledger_entry: "0", ledger_url: "https://ledger.horizonshield.dev/ledger/0", claim_sha256: await sha256Hex(commitmentClaimText(subject)), anchor: { kind: "fixture_not_bitcoin", height: "0", hash: await sha256Hex("tsugi fixture anchor 2026-09-20") } };
}
async function commitV2(subject, poolHash, k) {
  return { subject_sha256: subject, pool_sha256: poolHash, k_requested: String(k), ledger_entry: "0", ledger_url: "https://ledger.horizonshield.dev/ledger/0", claim_sha256: await sha256Hex(commitmentClaimTextV2(subject, poolHash, String(k))), anchor: { kind: "fixture_not_bitcoin", height: "0", hash: await sha256Hex("tsugi fixture anchor 2026-09-20") } };
}

// 事故 B: 実行の時刻を 07:58 にした別の実行。drift、提案、許可は A と同じ。
async function incidentB(base) {
  const { record_sha256: _h, ...exe } = base[5];
  const execution = await seal({ ...exe, recorded_at: "2026-09-20T07:58:00Z" });
  return { execution, head: [...base.slice(0, 5), execution] };
}
async function verifyFor(base, execution, drawObj, external, at) {
  const { record_sha256: _h, ...body } = base[6];
  return seal({ ...body, recorded_at: at || "2026-09-20T08:06:00Z", prev: execution.record_sha256, execution_sha256: execution.record_sha256, draw: drawObj, external });
}

export async function buildV24Cases() {
  const fx = JSON.parse(readFileSync(path.join(HERE, WITNESS_FIXTURE_FILE), "utf8"));   // 事故 A (v2.2 の形、署名つき観測 2 つ)
  const base = await buildFixture();
  const pool = await buildPool();
  const beacon = await buildBeacon();
  const pHash = await poolSha256(pool);
  const byDomain = new Map(pool.entries.map((e) => [e.signed_domain, e]));
  const expAfter = base[6].expected_after;
  const aObs = fx.records[6].external.filter((e) => e.record);           // A の依頼に答えた、署名つきの観測
  const aRequest = fx.request, aReqHash = fx.records[6].draw.request_sha256;
  const { execution: exB, head: headB } = await incidentB(base);
  const subB = exB.record_sha256;
  const cases = [];
  const P = { q: "2", pool, k: "3" };

  // 0. A (v2.2 の形) は読めるまま。印が付く。v2.4 を要る方針では断る。
  cases.push({ name: "legacy v2.2 fixture still verifies, marked", records: fx.records, quorum: { q: fx.q, pool, beaconHash: beacon.hash, k: "3" }, old: { ok: true }, new: { ok: true, forms: ["k_not_recorded", "request_not_carried", "pool_not_committed"] } });
  cases.push({ name: "legacy v2.2 fixture under requireV24 is refused", records: fx.records, quorum: { q: fx.q, pool, beaconHash: beacon.hash, k: "3", requireV24: true }, old: { ok: true }, new: { ok: false, codes: ["draw_request_absent", "draw_k_unrecorded", "draw_pool_uncommitted"] } });

  // 1. 正直な v2.4 の事故 B: 依頼の本文、k_requested、v2 の約束、B の依頼に答えた観測。
  const reqB = buildRequest({ origin: ORIGIN, subjectSha256: subB, poolSha256: pHash, beacon, requestedAt: "2026-09-20T08:03:30Z" });
  const reqBHash = await requestSha256(reqB);
  const dB = await draw({ pool, beaconHash: beacon.hash, subjectSha256: subB, k: 3, excludeHost: OWN_HOST });
  const obsB = [];
  for (let n = 0; n < dB.drawn.length - 1; n++) obsB.push({ signed_domain: dB.drawn[n], answered: true, record: await observe(dB.drawn[n], byDomain.get(dB.drawn[n]).key_url, reqBHash, expAfter, "2026-09-20T08:04:1" + n + "Z") });
  const honest = await verifyFor(base, exB, drawFieldV24(dB, beacon, subB, reqB, reqBHash, await commitV2(subB, pHash, 3)), obsB);
  cases.push({ name: "honest v2.4 incident B verifies under requireV24", records: [...headB, honest], quorum: { ...P, beaconHash: beacon.hash, requireV24: true, requireCommitment: true }, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: true, forms: [] } });

  // 2. R2-1 (v2.2 の形): A の依頼の hash と A の観測を B に使い回し、k を 5 に広げて A の証人を籤に入れる。
  const d5 = await draw({ pool, beaconHash: beacon.hash, subjectSha256: subB, k: 5, excludeHost: OWN_HOST });
  const reuse = await verifyFor(base, exB, drawField(d5, beacon, subB, aReqHash, await commitV1(subB)), clone(aObs));
  cases.push({ name: "R2-1: A's observations reused for B by naming A's request and widening k to 5", records: [...headB, reuse], quorum: P, old: { ok: true }, new: { ok: false, codes: ["draw_k_mismatch"] } });
  cases.push({ name: "R2-1: the same reuse with no k in the policy is still marked as the old form", records: [...headB, reuse], quorum: { q: "2", pool }, old: { ok: true }, new: { ok: true, forms: ["k_not_recorded", "request_not_carried", "pool_not_committed"] } });
  cases.push({ name: "R2-1: the same reuse under requireV24 is refused", records: [...headB, reuse], quorum: { q: "2", pool, requireV24: true }, old: { ok: true }, new: { ok: false, codes: ["draw_request_absent"] } });

  // 3. R2-1 (v2.4 の形を装う): A の依頼の本文を B の籤に載せる。本文は A の主題を名指すので結び付かない。
  const fake = drawFieldV24(d5, beacon, subB, aRequest, aReqHash, await commitV2(subB, pHash, 5));
  const reuse24 = await verifyFor(base, exB, fake, clone(aObs));
  cases.push({ name: "R2-1: A's request body carried in B's draw", records: [...headB, reuse24], quorum: { q: "2", pool }, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: false, codes: ["draw_request_unbound"] } });

  // 4. R5-F1 (v1 の約束): beacon を見てから、A で答えなかった証人を池から外した池 2 で引き直す。
  const noAnswer = fx.records[6].external.find((e) => e.answered === false && e.signed_domain).signed_domain;
  const pool2 = { entries: pool.entries.filter((e) => e.signed_domain !== noAnswer) };
  const p2Hash = await poolSha256(pool2);
  const reqB2 = buildRequest({ origin: ORIGIN, subjectSha256: subB, poolSha256: p2Hash, beacon, requestedAt: "2026-09-20T08:03:30Z" });
  const reqB2Hash = await requestSha256(reqB2);
  const dP2 = await draw({ pool: pool2, beaconHash: beacon.hash, subjectSha256: subB, k: 3, excludeHost: OWN_HOST });
  const obsP2 = [];
  for (const dom of dP2.drawn) obsP2.push({ signed_domain: dom, answered: true, record: await observe(dom, byDomain.get(dom).key_url, reqB2Hash, expAfter, "2026-09-20T08:04:30Z") });
  const regrind = await verifyFor(base, exB, drawField(dP2, beacon, subB, reqB2Hash, await commitV1(subB)), obsP2);
  cases.push({ name: "R5-F1: pool chosen after the beacon, v1 commitment, marked pool_not_committed", records: [...headB, regrind], quorum: { q: "2", pool: pool2, k: "3", requireCommitment: true }, old: { ok: true }, new: { ok: true, forms: ["k_not_recorded", "request_not_carried", "pool_not_committed"] } });
  cases.push({ name: "R5-F1: the same under requireV24 is refused", records: [...headB, regrind], quorum: { q: "2", pool: pool2, k: "3", requireCommitment: true, requireV24: true }, old: { ok: true }, new: { ok: false, codes: ["draw_pool_uncommitted"] } });
  // v2 の約束は池 1 を固めた。籤は池 2 で引いた。
  const regrind24 = await verifyFor(base, exB, drawFieldV24(dP2, beacon, subB, reqB2, reqB2Hash, await commitV2(subB, pHash, 3)), obsP2);
  cases.push({ name: "R5-F1: v2 commitment fixed pool 1, the draw used pool 2", records: [...headB, regrind24], quorum: { q: "2", pool: pool2, k: "3", requireCommitment: true }, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: false, codes: ["commitment_pool_mismatch"] } });

  // 5. 時刻: beacon のブロックより前、依頼より前の観測は数えない。
  const early = await verifyFor(base, exB, drawFieldV24(dB, beacon, subB, reqB, reqBHash, await commitV2(subB, pHash, 3)), obsB);
  cases.push({ name: "an observation before the beacon block time is refused", records: [...headB, early], quorum: { ...P, beaconTime: "2026-09-20T08:05:00Z" }, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: false, codes: ["witness_before_beacon"] } });
  const obsEarly = [];
  for (let n = 0; n < dB.drawn.length - 1; n++) obsEarly.push({ signed_domain: dB.drawn[n], answered: true, record: await observe(dB.drawn[n], byDomain.get(dB.drawn[n]).key_url, reqBHash, expAfter, "2026-09-20T08:03:0" + n + "Z") });
  const beforeReq = await verifyFor(base, exB, drawFieldV24(dB, beacon, subB, reqB, reqBHash, await commitV2(subB, pHash, 3)), obsEarly);
  cases.push({ name: "an observation before its own request was made is refused", records: [...headB, beforeReq], quorum: P, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: false, codes: ["witness_before_request"] } });
  // 5b. 依頼の本文を書き換え (hash は元のまま)、約束が固めた k と籤の k が違う。
  const edited = await verifyFor(base, exB, drawFieldV24(dB, beacon, subB, { ...reqB, requested_at: "2026-09-20T08:03:31Z" }, reqBHash, await commitV2(subB, pHash, 3)), obsB);
  cases.push({ name: "R2-1: a request body that does not hash to request_sha256 is refused", records: [...headB, edited], quorum: P, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: false, codes: ["draw_request_mismatch"] } });
  const kOff = await verifyFor(base, exB, drawFieldV24(dB, beacon, subB, reqB, reqBHash, await commitV2(subB, pHash, 4)), obsB);
  cases.push({ name: "R5-F1: the commitment fixed k 4, the draw requested 3", records: [...headB, kOff], quorum: P, old: { ok: false, why: "0.3.1 reads only v1 commitments (commitment_claim_mismatch): a v2.4 record is not readable before the fix" }, new: { ok: false, codes: ["commitment_k_mismatch"] } });
  // 6. 時刻 (v2.2 の形): A の観測 08:04 は、読む側が自分で取った beacon の時刻 08:04:30 より前。直す前は beacon の時刻を見ていなかった。
  cases.push({ name: "v2.2 form: observations before the beacon block time the reader fetched are refused", records: fx.records, quorum: { q: fx.q, pool, k: "3", beaconTime: "2026-09-20T08:04:30Z" }, old: { ok: true }, new: { ok: false, codes: ["witness_before_beacon"] } });
  return cases;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const out = process.argv[2];
  const cases = await buildV24Cases();
  const text = JSON.stringify({ note: "v2.4 attack and control cases for the TSUGI witness draw (red team R2-1, R5-F1); built by witness_v24_cases.mjs", cases }, null, 1) + "\n";
  if (out) (await import("node:fs")).writeFileSync(out, text); else process.stdout.write(text);
}
