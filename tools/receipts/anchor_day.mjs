#!/usr/bin/env node
// tools/receipts/anchor_day.mjs: anchor one UTC day of HORIZON SHIELD fair-price receipts in the JIDEC ledger (2026-10-19).
//
// A fair-price receipt (verify_fair_price, create_ap2_fairness_attestation) is a claim whose SHA-256 anyone can
// recompute, kept by hs-mcp at https://mcp.horizonshield.dev/ledger/<sha>. Until now nothing outside that server said
// when a receipt existed, so its issued_at rested on the issuer's word. This reads the day's list from
// GET /ledger/day/<date>, fetches every receipt and recomputes SHA-256(JSON.stringify(claim)), keeps a copy of the
// receipts in ops/receipts/<date>.json, and appends one ledger entry whose bytes list every receipt that recomputed:
//   {"schema":"hs-fair-price-receipt-batch-v1","date":...,"count":n,"store":...,"records":[{"sha":...},...],"note":...}
// The ledger's stamping run takes that entry to Bitcoin, which bounds every listed receipt from above.
//
//   node tools/receipts/anchor_day.mjs [--date YYYY-MM-DD] [--append] [--out ops/receipts]
// Default date: yesterday (UTC). --append needs LEDGER_URL and LEDGER_ADMIN_TOKEN in the environment.
// Exit 0: done (or a day with no receipts). Exit 1: the list could not be read, a receipt did not recompute, or the
// append failed. A read failure is never written down as "no receipts".
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export const STORE = "https://mcp.horizonshield.dev/ledger/";
export const BATCH_SCHEMA = "hs-fair-price-receipt-batch-v1";
const UA = "hs-receipt-anchor/1 (+https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/tools/receipts)";
export const sha256 = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

export function yesterday(now = new Date()) { return new Date(now.getTime() - 86400000).toISOString().slice(0, 10); }

export async function collect(date, fetchImpl = globalThis.fetch) {
  const r = await fetchImpl(STORE + "day/" + date, { headers: { "user-agent": UA, accept: "application/json" } });
  if (r.status !== 200) throw new Error("GET " + STORE + "day/" + date + " answered " + r.status);
  const day = await r.json();
  if (!day || day.schema !== "hs-fair-price-receipt-day-v1" || day.date !== date || !Array.isArray(day.receipts)) throw new Error("the day list is not an hs-fair-price-receipt-day-v1 for " + date);
  if (day.complete !== true) throw new Error("the day list says it is not complete");
  const good = [], refused = [];
  for (const h of [...new Set(day.receipts)].sort()) {
    if (!/^[0-9a-f]{64}$/.test(h)) { refused.push({ sha: h, why: "not a sha256" }); continue; }
    const g = await fetchImpl(STORE + h, { headers: { "user-agent": UA, accept: "application/json" } });
    if (g.status !== 200) { refused.push({ sha: h, why: "the store answered " + g.status }); continue; }
    let rec;
    try { rec = await g.json(); } catch (_e) { refused.push({ sha: h, why: "not JSON" }); continue; }
    if (!rec || typeof rec.claim !== "object" || rec.claim === null) { refused.push({ sha: h, why: "no claim" }); continue; }
    if (sha256(JSON.stringify(rec.claim)) !== h) { refused.push({ sha: h, why: "SHA-256(JSON.stringify(claim)) does not match" }); continue; }
    if (String(rec.claim.issued_at || "").slice(0, 10) !== date) { refused.push({ sha: h, why: "issued_at is not on " + date }); continue; }
    good.push({ sha: h, record: rec });
  }
  return { good, refused };
}

export function batchBytes(date, shas) {
  return JSON.stringify({ schema: BATCH_SCHEMA, date, count: shas.length, store: STORE, records: shas.map((sha) => ({ sha })),
    note: "Each sha is the SHA-256(JSON.stringify(claim)) of a HORIZON SHIELD fair-price receipt issued on this UTC day, served at store + sha and copied in horizon-shield ops/receipts/<date>.json. This entry's Bitcoin anchor bounds every listed receipt from above. It says the receipt existed; it does not say the price is right." });
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
  const date = opt("--date", yesterday());
  const out = opt("--out", "ops/receipts");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) { console.error("bad --date"); process.exit(1); }
  const { good, refused } = await collect(date);
  console.log(date + ": " + good.length + " receipts recompute, " + refused.length + " refused");
  for (const x of refused) console.log("  refused " + x.sha + ": " + x.why);
  if (!good.length && !refused.length) { console.log("no receipts on " + date + "; nothing to anchor"); return 0; }
  mkdirSync(out, { recursive: true });
  const copy = { schema: "hs-fair-price-receipt-day-copy-v1", date, store: STORE, count: good.length, receipts: good, refused };
  writeFileSync(join(out, date + ".json"), JSON.stringify(copy, null, 1) + "\n");
  let rc = refused.length ? 1 : 0;
  if (good.length && args.includes("--append")) {
    const url = (process.env.LEDGER_URL || "").replace(/\/$/, ""), tok = (process.env.LEDGER_ADMIN_TOKEN || "").trim();
    if (!url || !tok) { console.error("--append needs LEDGER_URL and LEDGER_ADMIN_TOKEN"); return 1; }
    const rcanon = batchBytes(date, good.map((x) => x.sha));
    const claim = sha256(rcanon);
    const r = await fetch(url + "/ledger/append", { method: "POST", headers: { "content-type": "application/json", "x-ledger-key": tok, "user-agent": UA },
      body: JSON.stringify({ work: "HORIZON SHIELD fair-price receipts " + date + " (" + good.length + ")", claim_sha256: claim, record_canonical: rcanon }) });
    const j = await r.json().catch(() => null);
    if (!(r.status === 201 || r.status === 200) || !j || j.n == null) { console.error("append failed: HTTP " + r.status + " " + JSON.stringify(j).slice(0, 300)); return 1; }
    console.log("anchored as ledger entry " + j.n + (j.dedup ? " (already there)" : "") + ", claim " + claim);
    const ip = join(out, "index.json");
    const idx = existsSync(ip) ? JSON.parse(readFileSync(ip, "utf8")) : { schema: "hs-fair-price-receipt-index-v1", days: {} };
    idx.days[date] = { ledger_entry: j.n, claim_sha256: claim, count: good.length };
    writeFileSync(ip, JSON.stringify(idx, null, 1) + "\n");
  }
  return rc;
}

if (import.meta.url === "file://" + process.argv[1]) main().then((c) => process.exit(c), (e) => { console.error("FAIL: " + (e && e.message || e)); process.exit(1); });
