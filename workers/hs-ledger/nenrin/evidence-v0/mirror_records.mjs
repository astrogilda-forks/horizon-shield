// mirror_records.mjs (2026-09-27): 扉の判定バイトを、扉の外にもう一つ置く。
//
// なぜ要るか。GET /record/<sha> が配るバイトは Cloudflare KV の rec:<sha> にしか無い。hash は台帳にも
// 履歴にも載るが、hash が指すバイトそのものの置き場は一つ。Cloudflare の口座が止まれば、hash は
// 「もう誰も持っとらんバイトの名前」になる。外部の批判が「証拠の可用性」と呼んだ穴はここや。
//
// やる事は公開の読みだけ: /register の全行 → 行ごとの /history → 各 record_sha256 の /record/<sha>。
// 取ったバイトの SHA-256 が path の sha と一致した物だけを <out>/<slug>/<sha>.json に、取ったバイトのまま
// 書く (整形も再直列化もせん)。一致せん物は書かずに hash_mismatch と記録する。404 not_stored は
// 「扉がそのバイトを持っとらん」事実として not_stored_by_gate と記録する (0.4.1 より前の判定と
// POST /check の判定は、そもそも保存されとらん)。既に在って hash が合うファイルは触らん (冪等)。
// 鍵も token も要らん。どこで走らせても同じ物が出る。
//
// 書いた物を公開 repo (例: mcp-conduct-register) に commit すれば第二の置き場になり、Software Heritage が
// その repo を保存すれば、扉とも GitHub とも別の組織が持つ第三の置き場になる。
//
//   node mirror_records.mjs [--gate https://gate.horizonshield.dev] [--out ./records] [--endpoint <url>]
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const MIRROR_SCHEMA = "gate-record-mirror-v0";
export const MIRROR_VERSION = "0.1.1";
// Python urllib の既定 UA は扉の前段で 403 になる (KNOWN_UA_LIMITATION)。名乗って取る。
export const UA = "hs-evidence-mirror/" + MIRROR_VERSION + " (+https://gate.horizonshield.dev/openapi.json)";

export const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");
// conduct-v1 の rings と同じ slug 規則: https:// を落とし、小文字、[a-z0-9] 以外の連なりを 1 つのハイフン、両端のハイフンを落とす。
export const slugOf = (endpoint) => String(endpoint).replace(/^https?:\/\//i, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

// 0.1.1 (2026-10-27): the run of 2026-10-26 22:51Z failed as a whole on one network error ("fetch failed") on /register or
// /history. A thrown network error and 502/503/504 are now retried up to 3 times with a wait. Nothing else changes: the
// bytes received are still checked against their name.
export const RETRY_WAITS_MS = [2000, 5000, 10000];
const RETRY_STATUS = new Set([502, 503, 504]);
async function getBytes(fetchImpl, url, { waits = RETRY_WAITS_MS, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let last;
  for (let i = 0; i <= waits.length; i++) {
    try {
      const r = await fetchImpl(url, { headers: { "user-agent": UA, accept: "application/json" }, signal: AbortSignal.timeout(30000) });
      const buf = Buffer.from(await r.arrayBuffer());
      if (!RETRY_STATUS.has(r.status) || i === waits.length) return { status: r.status, buf, attempts: i + 1 };
      last = new Error("status " + r.status);
    } catch (err) { last = err; if (i === waits.length) throw err; }
    await sleep(waits[i]);
  }
  throw last;
}

export async function mirror({ gate = "https://gate.horizonshield.dev", out, only = null, fetchImpl = globalThis.fetch, now = () => new Date().toISOString(), waits = RETRY_WAITS_MS, sleep }) {
  const get = (url) => getBytes(fetchImpl, url, { waits, ...(sleep ? { sleep } : {}) });
  const reg = await get(gate + "/register");
  if (reg.status !== 200) throw new Error("register answered " + reg.status);
  const rows = JSON.parse(reg.buf.toString("utf8")).rows || [];
  const endpoints = rows.map((r) => r.endpoint).filter((e) => typeof e === "string" && (!only || e === only));
  const entries = [];
  const counts = { mirrored_new: 0, already_mirrored: 0, not_stored_by_gate: 0, hash_mismatch: 0, fetch_failed: 0 };
  for (const ep of endpoints) {
    let h;
    try { h = await get(gate + "/history?endpoint=" + encodeURIComponent(ep)); } catch (err) { entries.push({ endpoint: ep, result: "history_failed", reason: String(err && err.message || err) }); counts.fetch_failed++; continue; }
    if (h.status !== 200) { entries.push({ endpoint: ep, result: "history_failed", status: h.status }); counts.fetch_failed++; continue; }
    const hist = JSON.parse(h.buf.toString("utf8")).entries || [];
    for (const e of hist) {
      const sha = e && e.record_sha256;
      if (typeof sha !== "string" || !/^[0-9a-f]{64}$/.test(sha)) continue;
      const file = path.join(out, slugOf(ep), sha + ".json");
      const base = { endpoint: ep, at: e.at || null, status: e.status || null, record_sha256: sha, file: path.relative(out, file) };
      if (existsSync(file) && sha256hex(readFileSync(file)) === sha) { entries.push({ ...base, result: "already_mirrored" }); counts.already_mirrored++; continue; }
      let r;
      try { r = await get(gate + "/record/" + sha); } catch (err) { entries.push({ ...base, file: null, result: "fetch_failed", reason: String(err && err.message || err) }); counts.fetch_failed++; continue; }
      if (r.status === 404) { entries.push({ ...base, file: null, result: "not_stored_by_gate" }); counts.not_stored_by_gate++; continue; }
      if (r.status !== 200) { entries.push({ ...base, file: null, result: "fetch_failed", status: r.status }); counts.fetch_failed++; continue; }
      const got = sha256hex(r.buf);
      if (got !== sha) { entries.push({ ...base, file: null, result: "hash_mismatch", got_sha256: got }); counts.hash_mismatch++; continue; }
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, r.buf);
      entries.push({ ...base, result: "mirrored_new" }); counts.mirrored_new++;
    }
  }
  const manifest = {
    schema: MIRROR_SCHEMA, mirror_version: MIRROR_VERSION, gate, taken_at: now(),
    register_sha256: sha256hex(reg.buf), endpoints: endpoints.length, counts, entries,
    establishes: [
      "each file named <sha>.json holds bytes whose SHA-256 is <sha>, as served by the gate at taken_at",
      "a second copy of those bytes now exists outside the gate's storage"
    ],
    does_not_establish: [
      "that any verdict is correct",
      "anything about verdicts the gate did not store (not_stored_by_gate): only their hash survives",
      "that the gate served the same bytes to anyone else",
      "that this mirror is complete beyond the rows the register listed at taken_at"
    ]
  };
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, "MIRROR_MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}

async function main(argv) {
  const arg = (k, d) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : d; };
  const out = path.resolve(arg("--out", "./records"));
  const m = await mirror({ gate: arg("--gate", "https://gate.horizonshield.dev"), out, only: arg("--endpoint", null) });
  console.log("endpoints " + m.endpoints + "  " + Object.entries(m.counts).map(([k, v]) => k + " " + v).join("  "));
  console.log("wrote " + path.join(out, "MIRROR_MANIFEST.json"));
  if (m.counts.hash_mismatch) { console.error("hash_mismatch present: the gate served bytes that do not hash to their name. Nothing mismatched was written."); process.exit(2); }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main(process.argv.slice(2)).catch((e) => { console.error(e.message); process.exit(1); });
