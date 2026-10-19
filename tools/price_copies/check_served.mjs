#!/usr/bin/env node
// tools/price_copies/check_served.mjs: the souba-db copies that production serves from R2 must be the bytes of
// data/souba-db.json (2026-10-19).
//
// On 2026-10-19 both R2 copies were still souba-db 2.1.0 while the release was 2.3.0: the paid PDF diagnosis
// (hs-pdf-gen, bucket hs-pdfs) and the reference gateway that KIRA on LINE and the reverse estimate read (bucket
// hs-reference-data). Nothing compared them. This reads what each one serves and compares its SHA-256 with the file.
//   hs-pdf-gen   GET https://hs-pdf-gen.oga-surf-project.workers.dev/souba-dataset   (public: version and sha256)
//   gateway      GET https://hs-reference-gateway.oga-surf-project.workers.dev/reference/souba-db.json
//                (needs X-Gateway-Token; without GATEWAY_TOKEN in the environment it is reported as not measured)
// Exit 1 when a copy that could be read differs, or hs-pdf-gen cannot be read. The fix is to put the file into R2:
//   npx wrangler r2 object put <bucket>/souba-db.json --remote --file data/souba-db.json --content-type application/json
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const UA = "hs-price-copies/1 (+https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/tools/price_copies)";
export const PDF_URL = "https://hs-pdf-gen.oga-surf-project.workers.dev/souba-dataset";
export const GATEWAY_URL = "https://hs-reference-gateway.oga-surf-project.workers.dev/reference/souba-db.json";
const sha = (b) => createHash("sha256").update(b).digest("hex");

export async function measure(fileBytes, fetchImpl = globalThis.fetch, gatewayToken = "") {
  const want = sha(fileBytes);
  const rows = [];
  try {
    const r = await fetchImpl(PDF_URL, { headers: { "user-agent": UA } });
    const j = r.status === 200 ? await r.json() : null;
    rows.push(j && j.sha256 ? { copy: "hs-pdf-gen (R2 hs-pdfs)", version: j.version, sha256: j.sha256, same: j.sha256 === want } : { copy: "hs-pdf-gen (R2 hs-pdfs)", read_failed: "HTTP " + r.status });
  } catch (e) { rows.push({ copy: "hs-pdf-gen (R2 hs-pdfs)", read_failed: String(e && e.message || e) }); }
  if (!gatewayToken) rows.push({ copy: "reference gateway (R2 hs-reference-data)", not_measured: "GATEWAY_TOKEN is not set here" });
  else {
    try {
      const r = await fetchImpl(GATEWAY_URL, { headers: { "user-agent": UA, "x-gateway-token": gatewayToken } });
      const b = r.status === 200 ? Buffer.from(await r.arrayBuffer()) : null;
      rows.push(b ? { copy: "reference gateway (R2 hs-reference-data)", version: r.headers.get("x-reference-version"), sha256: sha(b), same: sha(b) === want } : { copy: "reference gateway (R2 hs-reference-data)", read_failed: "HTTP " + r.status });
    } catch (e) { rows.push({ copy: "reference gateway (R2 hs-reference-data)", read_failed: String(e && e.message || e) }); }
  }
  return { want, rows, red: rows.some((x) => x.same === false || (x.read_failed && x.copy.startsWith("hs-pdf-gen"))) };
}

async function main() {
  const file = readFileSync(join(ROOT, "data/souba-db.json"));
  const version = JSON.parse(file.toString("utf8"))._meta.version;
  const { want, rows, red } = await measure(file, globalThis.fetch, (process.env.GATEWAY_TOKEN || "").trim());
  console.log("data/souba-db.json  " + version + "  " + want.slice(0, 16));
  for (const x of rows) {
    if (x.read_failed) console.log("READ FAILED  " + x.copy + ": " + x.read_failed);
    else if (x.not_measured) console.log("not measured " + x.copy + ": " + x.not_measured);
    else console.log((x.same ? "same         " : "DIFFERS      ") + x.copy + "  " + x.version + "  " + x.sha256.slice(0, 16));
  }
  if (rows.some((x) => x.same === false)) console.log("A copy differs from data/souba-db.json: put the file into that bucket (see the head of this script).");
  else if (red) console.log("hs-pdf-gen could not be read, so nothing is said about its copy; run again, then check the worker.");
  return red ? 1 : 0;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().then((c) => process.exit(c), (e) => { console.error(e); process.exit(1); });
