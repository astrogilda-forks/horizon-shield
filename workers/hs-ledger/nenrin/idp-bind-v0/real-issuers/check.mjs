// check.mjs : re-verifies the real-issuer runs in this folder, offline, with no credential from either issuer.
//
//   node check.mjs
//
// For each run: every file present is the bytes pinned in SHA256SUMS; both bindings verify against the pinned JWKS
// (idp-bind-v0); the NENRIN grant and receipt verify (provenance verifier, did:key resolver); and the keys line up (the
// grant's caller is binding A's actor, the grant's provider and the receipt's provider are binding B's actor).
// The Entra run's two bindings are not in the repository (see README.md): GitHub push protection classifies the Entra
// access tokens inside them as live secrets even after expiry. Without them that run checks the grant and receipt and
// the pinned digests only; with them (placed in entra-2026-10-15/) it checks everything, the same as the Google run.
// Nothing here reads the network or the clock: a binding is checked against the token's own nbf/exp window at bound_at.
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { verify as verifyBinding } from "../idp_bind.mjs";
import { verifyProvenance, didKeyResolver } from "../../sdk/nenrin_verify.mjs";

const HERE = new URL("./", import.meta.url);
const has = (p) => existsSync(new URL(p, HERE));
const read = (p) => readFileSync(new URL(p, HERE), "utf8");
const codes = (xs) => JSON.stringify([...new Set(xs.map((x) => x.code))].sort());
let bad = 0;

for (const line of read("SHA256SUMS").trim().split("\n")) {
  const [h, name] = line.split("  ");
  if (!has(name)) { console.log("withheld: " + name + " (sha256 " + h.slice(0, 16) + "...)"); continue; }
  if (createHash("sha256").update(read(name), "utf8").digest("hex") !== h) { console.log("NOT THE PINNED BYTES: " + name); bad++; }
}

for (const run of ["google-2026-10-15", "entra-2026-10-15"]) {
  const j = (n) => JSON.parse(read(run + "/" + n));
  const jwks = j("jwks.json"), bundle = j("bundle.json");
  const rp = verifyProvenance(Object.assign({}, bundle, { resolve: didKeyResolver }));
  const full = has(run + "/binding_a.json") && has(run + "/binding_b.json");
  if (!full) {
    const ok = rp.verdict === "accepted";
    console.log(run + ": grant + receipt " + rp.verdict + " " + codes(rp.refusals) + " " + codes(rp.findings) + "; bindings withheld, provider subjects not checked here");
    if (!ok) bad++;
    continue;
  }
  const a = j("binding_a.json"), b = j("binding_b.json");
  const ra = verifyBinding({ binding: a, jwks }), rb = verifyBinding({ binding: b, jwks });
  const lined = bundle.grant.caller_id === a.actor_id && bundle.grant.provider_id === b.actor_id && bundle.receipt.provider_id === b.actor_id;
  const ok = ra.verdict === "accepted" && rb.verdict === "accepted" && rp.verdict === "accepted" && lined;
  console.log(run + ": " + (ok ? "established" : "NOT ESTABLISHED"));
  console.log("  issuer " + a.idp.issuer + ", alg " + a.idp.alg + ", kid " + a.idp.kid + ", jwks sha256 " + jwks.sha256.slice(0, 16));
  console.log("  binding A " + ra.verdict + " " + codes(ra.refusals) + " " + codes(ra.findings) + "  subject " + a.idp.subject);
  console.log("  binding B " + rb.verdict + " " + codes(rb.refusals) + " " + codes(rb.findings) + "  subject " + b.idp.subject);
  console.log("  grant + receipt " + rp.verdict + " " + codes(rp.refusals) + " " + codes(rp.findings) + "  keys line up: " + lined);
  if (!ok) bad++;
}
process.exit(bad ? 1 : 0);
