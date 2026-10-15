// trusted_identity.mjs : one rule for every record that names "who" through an idp-bind-v0 binding.
//
// A binding verifies against the JWKS bytes it is given. If those bytes come from the same bundle as the binding, the
// pin is the bundle vouching for itself: anyone can mint an RSA key, sign a token with iss set to any issuer, and
// ship the matching JWKS next to it. So a reader only NAMES the issuer and subject as fact when the JWKS sha256 is one
// the reader itself trusts for that issuer (it fetched the issuer's keys, or took the digest from somewhere it
// trusts). Otherwise the binding is reported as self-pinned and the identity is not stated.
//
// checkIdentity({ binding, jwks, trusted, audience, actorId }) ->
//   { ok: false, code, why }                        refuse: the binding does not verify, binds another key, or another audience
//   { ok: true, vouched: true, label }              the issuer is trusted at that JWKS digest; label = "issuer / subject"
//   { ok: true, vouched: false, label }             verifies, but only against JWKS bytes the bundle supplied itself
// trusted: { "<issuer>": ["<jwks sha256 hex>", ...] }, chosen by the reader, never read from the bundle.
import { verify as verifyBinding } from "./idp_bind.mjs";

export function checkIdentity({ binding, jwks, trusted, audience, actorId }) {
  const vb = verifyBinding({ binding, jwks });
  if (vb.verdict !== "accepted") return { ok: false, code: "binding_refused", why: vb.refusals.map((x) => x.code).join(",") };
  if (binding.actor_id !== actorId) return { ok: false, code: "binding_other_key", why: "the binding binds a different key" };
  if (audience != null && binding.idp.audience !== audience) return { ok: false, code: "binding_other_audience", why: "the binding's audience is " + binding.idp.audience + ", not " + audience };
  const label = binding.idp.issuer + " / " + binding.idp.subject;
  const pins = trusted && Object.prototype.hasOwnProperty.call(trusted, binding.idp.issuer) ? trusted[binding.idp.issuer] : null;
  const vouched = Array.isArray(pins) && pins.includes(jwks.sha256);
  return { ok: true, vouched, label };
}

// parseTrust(list): ["<issuer>=<sha256>", ...] from the command line into the trusted map
export function parseTrust(list) {
  const t = {};
  for (const s of list) {
    const i = s.lastIndexOf("=");
    if (i < 1 || !/^[0-9a-f]{64}$/.test(s.slice(i + 1))) throw new Error("--trust takes <issuer>=<sha256 of the issuer's JWKS bytes>");
    (t[s.slice(0, i)] = t[s.slice(0, i)] || []).push(s.slice(i + 1));
  }
  return t;
}
