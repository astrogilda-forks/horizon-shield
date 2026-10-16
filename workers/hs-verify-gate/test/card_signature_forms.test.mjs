// card_signature_forms (2026-10-16): /.well-known/agent-card-signatures.json names which signature on the card covers
// which bytes, and every value it states is recomputed here from the served card and JWKS, never taken from it.
//
// Why. The card carries two ES256 signatures by one key since 0.4.15 and said nothing about which was which. Sankalp
// Gilda walked this card with his own verifier and key (probityai/agent-evidence-vectors#55, 2026-10-15): signature 0
// verified over RFC 8785 of the served card, signature 1 did not, and he had to ask what it was over. The answer was
// right but lived only in this repository. This suite holds the published answer to the bytes.
//
// test/fixtures_live_card/sdk_form_payload.json is canonicalizeAgentCard(@a2a-js/sdk 1.1.0) of fixtures_live_card/card.json
// with signatures removed: 6,410 bytes, sha256 093ed47a1c1d... It is the payload signature 1 is over. No network.
// Run: node test/card_signature_forms.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const O = "https://gate.horizonshield.dev";
const CTX = { waitUntil() {} };
let pass = 0, fail = 0;
const t = (name, ok, detail) => { ok ? pass++ : fail++; console.log((ok ? "ok   " : "NG   ") + name + (ok || detail === undefined ? "" : "  <<< " + detail)); };
const res = (p, origin = O) => worker.fetch(new Request(origin + p), {}, CTX);
const sha = (b) => createHash("sha256").update(b).digest("hex");
// RFC 8785 for what an agent card holds (strings, integers, booleans, null, arrays, objects): keys in UTF-16 order,
// ECMAScript string and number serialisation. Written here so the check does not reuse the code under test.
const jcs = (v) => Array.isArray(v) ? "[" + v.map(jcs).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}"
  : JSON.stringify(v);
const b64u = (s) => Buffer.from(s).toString("base64url");
const verifies = (sig, payload, jwk) => verify("sha256", Buffer.from(sig.protected + "." + b64u(payload)),
  { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(sig.signature, "base64url"));

const r = await res("/.well-known/agent-card-signatures.json");
t("served on the canonical origin with 200", r.status === 200, r.status);
const doc = await r.json();
const card = await (await res("/.well-known/agent-card.json")).json();
const jwks = await (await res("/.well-known/jwks.json")).json();
const jwk = (jwks.keys || []).find((k) => k.kid === doc.kid);

t("kind is agent-card-signature-forms-v1", doc.kind === "agent-card-signature-forms-v1", doc.kind);
t("names the card and the JWKS it is about", doc.card === O + "/.well-known/agent-card.json" && doc.jwks === O + "/.well-known/jwks.json", doc.card + " " + doc.jwks);
t("one entry per signature on the card, in the card's order", Array.isArray(doc.signatures) && doc.signatures.length === card.signatures.length &&
  doc.signatures.every((s, i) => s.index === i), JSON.stringify((doc.signatures || []).map((s) => [s.index, s.form])));
t("the key it names is in the JWKS", !!jwk, doc.kid);

const served = doc.signatures.find((s) => s.form === "served-rfc8785");
const sdk = doc.signatures.find((s) => s.form === "a2a-sdk-proto");
t("both forms are named", !!served && !!sdk, JSON.stringify(doc.signatures.map((s) => s.form)));

const bare = Object.assign({}, card); delete bare.signatures;
const servedPayload = jcs(bare);
t("served-rfc8785: the stated digest is sha256 of RFC 8785 of the served card without signatures", served && served.payload_sha256 === sha(servedPayload),
  served && served.payload_sha256 + " vs " + sha(servedPayload));
t("served-rfc8785: the signature at its index verifies over that payload", served && verifies(card.signatures[served.index], servedPayload, jwk));
t("served-rfc8785: the other signature does not (it is over other bytes)", served && sdk && !verifies(card.signatures[sdk.index], servedPayload, jwk));

const fixtureCard = JSON.parse(readFileSync(path.join(HERE, "fixtures_live_card", "card.json"), "utf8"));
const sdkPayload = readFileSync(path.join(HERE, "fixtures_live_card", "sdk_form_payload.json"));
t("fixture: the SDK-form payload is the 6,410 bytes the card's SDK digest names", sdkPayload.length === 6410 && sha(sdkPayload) === "093ed47a1c1d9f559dd4f616d46cf35661c9d166de09372d1495db15b8090b20", sdkPayload.length + " " + sha(sdkPayload));
if (jcs(fixtureCard) === jcs(card)) {
  t("a2a-sdk-proto: the stated digest is sha256 of the SDK-form payload", sdk && sdk.payload_sha256 === sha(sdkPayload), sdk && sdk.payload_sha256);
  t("a2a-sdk-proto: the signature at its index verifies over that payload", sdk && verifies(card.signatures[sdk.index], sdkPayload.toString("utf8"), jwk));
  t("a2a-sdk-proto: the served-form signature does not", sdk && served && !verifies(card.signatures[served.index], sdkPayload.toString("utf8"), jwk));
  const drop = ["url", "protocolVersion", "preferredTransport", "securityRequirements", "compensation"];
  const sdkObj = JSON.parse(sdkPayload.toString("utf8"));
  t("a2a-sdk-proto: the members the document says are not covered are absent from the payload",
    drop.every((k) => k in bare && !(k in sdkObj)) && !("legalEntity" in (sdkObj.provider || {})), JSON.stringify(drop.filter((k) => k in sdkObj)));
} else {
  // The card changed and was re-signed: regenerate sdk_form_payload.json from the new card with @a2a-js/sdk and the
  // three checks above come back. Printed, not skipped silently.
  console.log("note the served card differs from fixtures_live_card/card.json; the SDK-form checks need a regenerated fixture");
}

const r2 = await res("/.well-known/agent-card-signatures.json", "https://hs-verify-gate.example.workers.dev");
t("another origin, which serves the card unsigned, answers 404 rather than an empty document", r2.status === 404, r2.status);

const oa = await (await res("/openapi.json")).json();
t("OpenAPI lists the path", !!(oa.paths && oa.paths["/.well-known/agent-card-signatures.json"]), Object.keys(oa.paths || {}).filter((p) => p.includes("well-known")).join(" "));

console.log("");
console.log("=== " + pass + " / " + (pass + fail) + (fail ? " 不合格あり" : " 合格") + " (card signature forms) ===");
process.exit(fail ? 1 : 0);
