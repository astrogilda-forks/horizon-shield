// mirror_records.test.mjs: 偽の扉で mirror_records.mjs を叩く。網には出ん。
// 走らせ方: node mirror_records.test.mjs
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { mirror, sha256hex, slugOf, UA } from "./mirror_records.mjs";

let pass = 0, fail = 0;
const t = (name, ok, d) => { ok ? pass++ : fail++; console.log((ok ? "ok   " : "NG   ") + name + (ok || d === undefined ? "" : "  <<< " + d)); };

const G = "https://gate.example";
const good = Buffer.from('{"a":1,"status":"pending"}');
const good2 = Buffer.from('{"b":"日本"}'); // non-ASCII: bytes must be kept as served
const SHA_GOOD = sha256hex(good), SHA_GOOD2 = sha256hex(good2);
const SHA_OLD = "a".repeat(64), SHA_LIE = "b".repeat(64), SHA_ERR = "c".repeat(64);
const EP1 = "https://mcp.example.com/mcp", EP2 = "https://Other.Example/x/Y";
const seenUA = [];
const routes = {
  "/register": { status: 200, body: JSON.stringify({ rows: [{ endpoint: EP1 }, { endpoint: EP2 }] }) },
  ["/history?endpoint=" + encodeURIComponent(EP1)]: { status: 200, body: JSON.stringify({ entries: [
    { at: "2026-09-01T18:00:00Z", status: "pending", record_sha256: SHA_OLD },
    { at: "2026-09-20T18:00:00Z", status: "pending", record_sha256: SHA_GOOD },
    { at: "2026-09-21T18:00:00Z", status: "pending", record_sha256: SHA_LIE },
    { at: "2026-09-22T18:00:00Z", status: "pending", record_sha256: SHA_ERR },
    { at: "2026-09-23T18:00:00Z", status: "pending" }
  ] }) },
  ["/history?endpoint=" + encodeURIComponent(EP2)]: { status: 200, body: JSON.stringify({ entries: [{ at: "2026-09-24T18:00:00Z", status: "verified", record_sha256: SHA_GOOD2 }] }) },
  ["/record/" + SHA_OLD]: { status: 404, body: '{"error":"not_stored"}' },
  ["/record/" + SHA_GOOD]: { status: 200, body: good },
  ["/record/" + SHA_GOOD2]: { status: 200, body: good2 },
  ["/record/" + SHA_LIE]: { status: 200, body: Buffer.from('{"tampered":true}') },
  ["/record/" + SHA_ERR]: { status: 500, body: "{}" }
};
let calls = 0;
const fakeFetch = async (url, init) => {
  calls++; seenUA.push(init && init.headers && init.headers["user-agent"]);
  const r = routes[url.slice(G.length)];
  if (!r) return { status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
  const b = Buffer.isBuffer(r.body) ? r.body : Buffer.from(r.body);
  return { status: r.status, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) };
};

const out = mkdtempSync(path.join(tmpdir(), "mirror-"));
const m = await mirror({ gate: G, out, fetchImpl: fakeFetch, now: () => "2026-09-27T00:00:00Z" });
const f1 = path.join(out, slugOf(EP1), SHA_GOOD + ".json");
const f2 = path.join(out, slugOf(EP2), SHA_GOOD2 + ".json");
t("slug follows the rings rule", slugOf(EP2) === "other-example-x-y", slugOf(EP2));
t("a record whose bytes hash to its name is written", existsSync(f1));
t("the written bytes are exactly the served bytes (non-ASCII kept)", existsSync(f2) && Buffer.compare(readFileSync(f2), good2) === 0);
t("the written file hashes to its file name", sha256hex(readFileSync(f1)) === SHA_GOOD);
t("tampered bytes are not written", !existsSync(path.join(out, slugOf(EP1), SHA_LIE + ".json")));
t("tampered bytes are recorded as hash_mismatch with the sha actually received", m.entries.some((e) => e.record_sha256 === SHA_LIE && e.result === "hash_mismatch" && e.got_sha256 === sha256hex(Buffer.from('{"tampered":true}'))));
t("a 404 is recorded as not_stored_by_gate, not as a failure of the record", m.entries.some((e) => e.record_sha256 === SHA_OLD && e.result === "not_stored_by_gate" && e.file === null));
t("a 500 is fetch_failed and writes nothing", m.entries.some((e) => e.record_sha256 === SHA_ERR && e.result === "fetch_failed") && !existsSync(path.join(out, slugOf(EP1), SHA_ERR + ".json")));
t("an entry without a sha is skipped silently (nothing to mirror)", m.entries.filter((e) => e.endpoint === EP1).length === 4);
t("counts add up", JSON.stringify(m.counts) === JSON.stringify({ mirrored_new: 2, already_mirrored: 0, not_stored_by_gate: 1, hash_mismatch: 1, fetch_failed: 1 }), JSON.stringify(m.counts));
t("manifest is written with establishes and does_not_establish", (() => { const j = JSON.parse(readFileSync(path.join(out, "MIRROR_MANIFEST.json"), "utf8")); return j.schema === "gate-record-mirror-v0" && j.establishes.length >= 2 && j.does_not_establish.length >= 4; })());
t("every request names itself with the mirror user agent", seenUA.every((u) => u === UA));

const callsBefore = calls;
const m2 = await mirror({ gate: G, out, fetchImpl: fakeFetch });
t("second run is idempotent: existing good files are not refetched", m2.counts.already_mirrored === 2 && m2.counts.mirrored_new === 0 && calls - callsBefore === 3 + 3, JSON.stringify(m2.counts) + " calls " + (calls - callsBefore));
writeFileSync(f1, "corrupted");
const m3 = await mirror({ gate: G, out, fetchImpl: fakeFetch });
t("a corrupted local copy is replaced by the verified bytes", m3.counts.mirrored_new === 1 && sha256hex(readFileSync(f1)) === SHA_GOOD);
const m4 = await mirror({ gate: G, out: mkdtempSync(path.join(tmpdir(), "mirror-")), only: EP2, fetchImpl: fakeFetch });
t("--endpoint limits the run to one row", m4.endpoints === 1 && m4.counts.mirrored_new === 1);

// 0.1.1: retries on network failure (waits set to 0 so the test runs fast)
{
  let n = 0;
  const flaky = async (url, init) => { n++; if (url.endsWith("/register") && n === 1) throw new TypeError("fetch failed"); return fakeFetch(url, init); };
  const mf = await mirror({ gate: G, out: mkdtempSync(path.join(tmpdir(), "mirror-")), fetchImpl: flaky, waits: [0, 0, 0], sleep: async () => {} });
  t("a network failure on /register once is retried and the run completes", mf.endpoints === 2 && mf.counts.mirrored_new === 2, JSON.stringify(mf.counts));
  let k = 0;
  const flaky503 = async (url, init) => { if (url.includes("/record/" + SHA_GOOD) && k++ < 2) return { status: 503, arrayBuffer: async () => new ArrayBuffer(0) }; return fakeFetch(url, init); };
  const m5 = await mirror({ gate: G, out: mkdtempSync(path.join(tmpdir(), "mirror-")), fetchImpl: flaky503, waits: [0, 0, 0], sleep: async () => {} });
  t("503 twice then 200 is retried and the record is mirrored", m5.counts.mirrored_new === 2 && k === 3, JSON.stringify(m5.counts) + " k " + k);
  const deadHistory = async (url, init) => { if (url.includes("/history?endpoint=" + encodeURIComponent(EP1))) throw new TypeError("fetch failed"); return fakeFetch(url, init); };
  const m6 = await mirror({ gate: G, out: mkdtempSync(path.join(tmpdir(), "mirror-")), fetchImpl: deadHistory, waits: [0, 0, 0], sleep: async () => {} });
  t("a /history that keeps failing is history_failed for that row and the other rows still run", m6.entries.some((e) => e.endpoint === EP1 && e.result === "history_failed" && /fetch failed/.test(e.reason)) && m6.counts.mirrored_new === 1, JSON.stringify(m6.counts));
  let rejected = false;
  try { await mirror({ gate: G, out: mkdtempSync(path.join(tmpdir(), "mirror-")), fetchImpl: async () => { throw new TypeError("fetch failed"); }, waits: [0, 0, 0], sleep: async () => {} }); } catch (e) { rejected = /fetch failed/.test(e.message); }
  t("a /register that keeps failing still fails the run (after 4 tries)", rejected);
}

console.log("");
console.log("=== " + pass + " / " + (pass + fail) + (fail ? " 不合格あり" : " 合格") + " (evidence mirror v0) ===");
process.exit(fail ? 1 : 0);
