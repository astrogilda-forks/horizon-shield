// issuer_keys.test.mjs : no network. The fake issuer serves the real Google keys from the 2026-10-15 run, reordered
// the way Google reorders them between fetches, so the digest moves and the thumbprints do not.
//   node issuer_keys.test.mjs
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { thumbprint, observe, mergeIndex, checkJwks, sha256 } from "./issuer_keys.mjs";
import { checkIdentity, parseTrust } from "../idp-bind-v0/trusted_identity.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const t = (name, ok, detail) => { ok ? pass++ : fail++; console.log((ok ? "ok   " : "NG   ") + name + (ok || detail === undefined ? "" : "  <<< " + detail)); };

// RFC 7638 section 3.1, the worked example.
t("RFC 7638 example thumbprint", thumbprint({ kty: "RSA", e: "AQAB", alg: "RS256", kid: "2011-04-29",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" })
  === "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
t("a key with a missing required member has no thumbprint", thumbprint({ kty: "RSA", e: "AQAB" }) === null);

const RUN = path.join(HERE, "..", "idp-bind-v0", "real-issuers", "google-2026-10-15");
const pinned = JSON.parse(readFileSync(path.join(RUN, "jwks.json"), "utf8"));
const binding = JSON.parse(readFileSync(path.join(RUN, "binding_a.json"), "utf8"));
const G = "https://accounts.google.com";
const doc = JSON.parse(pinned.document);
// What a later fetch looks like: same keys, other order, other member order, other whitespace.
const reordered = JSON.stringify({ keys: doc.keys.slice().reverse().map((k) => Object.fromEntries(Object.entries(k).reverse())) });
t("the reordered document is other bytes", sha256(reordered) !== pinned.sha256);

const issuerFetch = (jwksText, discIssuer = G, jwksUri = "https://www.googleapis.com/oauth2/v3/certs") => async (url) => {
  if (url === G + "/.well-known/openid-configuration") return { status: 200, text: JSON.stringify({ issuer: discIssuer, jwks_uri: jwksUri }) };
  if (url === jwksUri) return { status: 200, text: jwksText };
  return { status: 404, text: "" };
};
const ISS = [{ name: "google", issuer: G }];
const day1 = await observe({ issuers: ISS, fetch: issuerFetch(reordered), now: new Date("2026-10-16T03:00:00Z") });
const o = day1.observations[0];
t("observation records the discovery and jwks digests and two keys", o.discovery_sha256 && o.jwks_sha256 === sha256(reordered) && o.keys.length === 2, JSON.stringify(o).slice(0, 200));
t("the raw bytes are kept under their digest", day1.raw[o.jwks_sha256] === reordered);
const pinnedThumbs = doc.keys.map(thumbprint).sort();
t("thumbprints equal those of the pinned 2026-10-15 document", JSON.stringify(o.keys.map((k) => k.thumbprint)) === JSON.stringify(pinnedThumbs));

const bad = await observe({ issuers: ISS, fetch: issuerFetch(reordered, "https://evil.example"), now: new Date("2026-10-16T03:00:00Z") });
t("a discovery document naming another issuer records no keys", bad.observations[0].error === "discovery_names_another_issuer" && !bad.observations[0].keys && !Object.keys(bad.raw).length);
const plain = await observe({ issuers: ISS, fetch: issuerFetch(reordered, G, "http://www.googleapis.com/oauth2/v3/certs"), now: new Date("2026-10-16T03:00:00Z") });
t("a jwks_uri that is not https records no keys", plain.observations[0].error === "jwks_uri_not_https");
const down = await observe({ issuers: ISS, fetch: async () => ({ status: 0, text: "" }), now: new Date("2026-10-16T03:00:00Z") });
t("an unreachable issuer is an error row, not an empty key list", down.observations[0].error === "discovery_status" && !("keys" in down.observations[0]));

let index = mergeIndex({}, day1.observations);
const day3 = await observe({ issuers: ISS, fetch: issuerFetch(pinned.document), now: new Date("2026-10-18T03:00:00Z") });
index = mergeIndex(index, day3.observations);
const e = index[G][pinnedThumbs[0]];
t("first_seen and last_seen span the two runs", e.first_seen === "2026-10-16" && e.last_seen === "2026-10-18", JSON.stringify(e));

const r = checkJwks({ index, issuer: G, document: pinned.document, at: binding.bound_at });
t("the binding's pinned JWKS: every key observed within 7 days of bound_at", r.ok && r.code === "every_key_observed", JSON.stringify(r).slice(0, 200));
t("the trust it prints is the pinned document's digest", r.trust === G + "=" + pinned.sha256, r.trust);
const id = checkIdentity({ binding, jwks: pinned, trusted: parseTrust([r.trust]), audience: binding.idp.audience, actorId: binding.actor_id });
t("trusted_identity then names the Google subject as vouched", id.ok && id.vouched === true, JSON.stringify(id));
const idSelf = checkIdentity({ binding, jwks: pinned, trusted: {}, audience: binding.idp.audience, actorId: binding.actor_id });
t("without it the same binding is only self-pinned", idSelf.ok && idSelf.vouched === false);

const extra = JSON.stringify({ keys: doc.keys.concat([{ kty: "RSA", e: "AQAB", kid: "attacker", n: "sXchYxmY2EqKvTq7aMU8v3cCvm9xEd8BB3lQkWwB5aRY1nPfEfBt1nCKA3Kmtk8a3P07pAZ9Dzk7PwYfgk8a" }]) });
const rx = checkJwks({ index, issuer: G, document: extra, at: binding.bound_at });
t("one extra key not served by the issuer: not vouched, no trust printed", !rx.ok && rx.code === "key_not_observed" && rx.trust === null, rx.code);
const rw = checkJwks({ index, issuer: G, document: pinned.document, at: "2026-09-01T00:00:00Z" });
t("observed, but far from bound_at: outside the window", !rw.ok && rw.code === "observed_outside_window", rw.code);
const ri = checkJwks({ index, issuer: "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0", document: pinned.document, at: binding.bound_at });
t("an issuer never observed is said so", !ri.ok && ri.code === "issuer_never_observed");
const rs = checkJwks({ index, issuer: "https://accounts.google.com/", document: pinned.document, at: binding.bound_at });
t("issuer strings are compared exactly (a trailing slash is another issuer)", !rs.ok && rs.code === "issuer_never_observed");

console.log("");
console.log("=== " + pass + " / " + (pass + fail) + (fail ? " 不合格あり" : " 合格") + " (issuer-keys-v0) ===");
process.exit(fail ? 1 : 0);
