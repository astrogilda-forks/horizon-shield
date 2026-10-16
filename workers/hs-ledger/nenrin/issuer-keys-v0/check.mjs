// check.mjs : the reader's side. Given the JWKS shipped with an idp-bind-v0 binding, the binding's issuer and its
// bound_at, says whether every key in that JWKS is one the issuer was observed serving within the window, and if so
// prints the --trust argument for trusted_identity.mjs. Offline: it reads keys.json, nothing else.
//
//   node check.mjs --binding ../idp-bind-v0/real-issuers/google-2026-10-15/binding_a.json \
//                  --jwks ../idp-bind-v0/real-issuers/google-2026-10-15/jwks.json [--log log] [--window-days 7]
//   node check.mjs --issuer https://accounts.google.com --at 2026-10-15T11:20:50Z --jwks some_jwks.json
//
// --jwks takes either the idp-bind-v0 form { "sha256": ..., "document": "<text>" } or the raw JWKS text.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkJwks, sha256 } from "./issuer_keys.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf("--" + k); return i > 0 ? process.argv[i + 1] : d; };
const index = JSON.parse(readFileSync(path.join(arg("log", path.join(HERE, "log")), "keys.json"), "utf8")).issuers;
const jtext = readFileSync(arg("jwks"), "utf8");
let document = jtext;
try { const j = JSON.parse(jtext); if (j && typeof j.document === "string") { document = j.document; if (j.sha256 && j.sha256 !== sha256(document)) { console.log("REFUSED  the jwks file's sha256 does not match its document"); process.exit(2); } } } catch { /* raw text, parsed by checkJwks */ }
let issuer = arg("issuer"), at = arg("at");
const bp = arg("binding");
if (bp) {
  const b = JSON.parse(readFileSync(bp, "utf8"));
  issuer = issuer || (b.idp && b.idp.issuer);
  at = at || b.bound_at;
}
if (!issuer || !at) { console.log("usage: --binding FILE --jwks FILE, or --issuer ISS --at TIME --jwks FILE"); process.exit(2); }
const r = checkJwks({ index, issuer, document, at, windowDays: Number(arg("window-days", "7")) });
console.log((r.ok ? "OBSERVED " : "NOT VOUCHED ") + issuer + " at " + at + ": " + r.code);
for (const k of r.keys) console.log("  kid " + String(k.kid).padEnd(44) + " " + k.thumbprint + "  " + (k.observed ? "seen " + k.first_seen + " .. " + k.last_seen + (k.within_window ? "" : "  (outside the window)") : "never seen at this issuer"));
if (r.trust) console.log("--trust " + r.trust);
process.exit(r.ok ? 0 : 1);
