// observe.mjs : one observation run. Fetches each issuer's discovery document and JWKS, writes
//   <out>/observations/<YYYY-MM-DD>.json   what was fetched today (one file per UTC day; a second run the same day replaces it)
//   <out>/jwks/<sha256>.json               the raw JWKS bytes, once per distinct digest, checked against the name
//   <out>/keys.json                        every key per issuer with first_seen / last_seen
// and prints a summary. Exits 1 when no issuer could be observed, so a run that saw nothing is red, not silent.
//
//   node observe.mjs --out workers/hs-ledger/nenrin/issuer-keys-v0/log [--issuers ISSUERS.json]
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { observe, mergeIndex, sha256 } from "./issuer_keys.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf("--" + k); return i > 0 ? process.argv[i + 1] : d; };
const out = arg("out", path.join(HERE, "log"));
const issuers = JSON.parse(readFileSync(arg("issuers", path.join(HERE, "ISSUERS.json")), "utf8")).issuers;

async function fetchText(url) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": "nenrin-issuer-keys/0 (+https://github.com/ogasurfproject-jpg/horizon-shield)" }, redirect: "error" });
    return { status: r.status, text: await r.text() };
  } catch (e) {
    return { status: 0, text: "", error: String(e && e.message || e) };
  }
}

const { observations, raw } = await observe({ issuers, fetch: fetchText, now: new Date() });
mkdirSync(path.join(out, "observations"), { recursive: true });
mkdirSync(path.join(out, "jwks"), { recursive: true });
for (const [h, text] of Object.entries(raw)) {
  if (sha256(text) !== h) throw new Error("raw JWKS bytes do not match their digest " + h);
  const p = path.join(out, "jwks", h + ".json");
  if (!existsSync(p)) writeFileSync(p, text);
}
const day = observations[0].fetched_at.slice(0, 10);
const file = { kind: "nenrin-issuer-keys-v0", day, observer: "GitHub Actions, " + (process.env.GITHUB_REPOSITORY || "local") + (process.env.GITHUB_RUN_ID ? " run " + process.env.GITHUB_RUN_ID : ""), observations };
writeFileSync(path.join(out, "observations", day + ".json"), JSON.stringify(file, null, 2) + "\n");
const ip = path.join(out, "keys.json");
const prev = existsSync(ip) ? JSON.parse(readFileSync(ip, "utf8")).issuers : {};
writeFileSync(ip, JSON.stringify({ kind: "nenrin-issuer-keys-index-v0", updated: day, issuers: mergeIndex(prev, observations) }, null, 2) + "\n");

let seen = 0;
for (const o of observations) {
  if (o.keys) seen++;
  console.log((o.keys ? "ok    " : "FAIL  ") + o.name.padEnd(16) + (o.keys ? o.keys.length + " keys, jwks sha256 " + o.jwks_sha256.slice(0, 16) : o.error + " (discovery " + o.discovery_status + (o.jwks_status !== undefined ? ", jwks " + o.jwks_status : "") + ")"));
}
console.log(day + ": " + seen + " of " + observations.length + " issuers observed");
process.exit(seen ? 0 : 1);
