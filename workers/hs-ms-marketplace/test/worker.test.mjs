// test/worker.test.mjs: hs-ms-marketplace offline. Microsoft's token endpoint, JWKS, resolve, activate and
// operations APIs are replaced by a fake that checks every request the worker makes.
// Run: node test/worker.test.mjs
import { generateKeyPairSync, createSign, randomUUID } from "node:crypto";
import worker from "../src/worker.js";

let bad = 0, n = 0;
const chk = (name, ok, info = "") => { n++; if (!ok) bad++; console.log((ok ? "PASS  " : "FAIL  ") + name + (ok ? "" : "  " + info)); };

const TENANT = "11111111-2222-3333-4444-555555555555";
const API_APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const LOGIN_APP = "99999999-8888-7777-6666-555555555555";
const BUYER_TID = "12345678-1234-1234-1234-123456789012";
const RESOURCE = "20e940b3-4c77-4b0b-9a53-9e16a1b010a7";
const SUB = randomUUID(), OP = randomUUID();

// One RSA key plays Microsoft's signing key; another is an impostor.
function rsa(kid) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, use: "sig" } };
}
const MS = rsa("ms-1"), EVIL = rsa("ms-1");
const b64u = (b) => Buffer.from(b).toString("base64url");
function jwt(claims, key = MS, alg = "RS256") {
  const h = b64u(JSON.stringify({ alg, typ: "JWT", kid: key.kid }));
  const p = b64u(JSON.stringify(claims));
  const s = createSign("RSA-SHA256").update(h + "." + p).sign(key.privateKey);
  return h + "." + p + "." + b64u(s);
}
const now = () => Math.floor(Date.now() / 1000);

// KV
function kv() {
  const m = new Map();
  return { m, binding: {
    get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => { m.set(k, v); }, delete: async (k) => { m.delete(k); },
    list: async ({ prefix }) => ({ keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }),
  } };
}

// Fake Microsoft.
const calls = [];
let resolveStatus = 200, activateStatus = 200, opAction = "Suspend";
async function fakeFetch(url, init = {}) {
  const u = String(url);
  calls.push({ u, init });
  const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
  if (u === `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`) {
    const b = new URLSearchParams(init.body);
    if (b.get("client_id") !== API_APP || b.get("client_secret") !== "s3cret" || b.get("scope") !== RESOURCE + "/.default" || b.get("grant_type") !== "client_credentials") return J({ error: "invalid_client" }, 401);
    return J({ access_token: "PUBLISHER", expires_in: 3599 });
  }
  if (u === "https://login.microsoftonline.com/common/discovery/v2.0/keys" || u === `https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`) return J({ keys: [MS.jwk] });
  const authOk = (init.headers || {}).authorization === "Bearer PUBLISHER";
  if (u.startsWith("https://marketplaceapi.microsoft.com/api/saas/subscriptions/resolve?api-version=2018-08-31")) {
    if (!authOk) return J({}, 401);
    if (init.headers["x-ms-marketplace-token"] !== "ab+cd/ef") return J({ error: "bad token" }, 400);
    if (resolveStatus !== 200) return J({}, resolveStatus);
    return J({ id: SUB, subscriptionName: "Contoso HS", offerId: "horizon-shield-verification", planId: "endpoint-report", quantity: null,
      subscription: { id: SUB, saasSubscriptionStatus: "PendingFulfillmentStart", purchaser: { emailId: "buyer@contoso.com" }, beneficiary: { emailId: "ops@contoso.com" }, isTest: true } });
  }
  if (u === `https://marketplaceapi.microsoft.com/api/saas/subscriptions/${SUB}/activate?api-version=2018-08-31`) {
    if (!authOk || init.method !== "POST") return J({}, 401);
    return new Response("", { status: activateStatus });
  }
  if (u === `https://marketplaceapi.microsoft.com/api/saas/subscriptions/${SUB}/operations/${OP}?api-version=2018-08-31`) {
    if (!authOk) return J({}, 401);
    return J({ id: OP, action: opAction, status: "Succeeded", planId: "endpoint-report", quantity: null });
  }
  return J({ error: "unexpected " + u }, 404);
}

const store = kv();
const env = { MS_TENANT_ID: TENANT, MS_API_APP_ID: API_APP, MS_LOGIN_APP_ID: LOGIN_APP, MS_API_CLIENT_SECRET: "s3cret", ADMIN_TOKEN: "adm1n-token-value", MS_SUBS: store.binding };
const ORIGIN = "https://marketplace.horizonshield.dev";
const call = (path, init = {}, e = env) => worker.fetch(new Request(ORIGIN + path, init), e, {}, fakeFetch);
const form = (o) => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(o).toString() });

// 0. health and configuration
let r = await call("/health");
chk("health reports configured without values", r.status === 200 && (await r.json()).configured === true);
r = await call("/landing?token=x", {}, { ...env, MS_API_CLIENT_SECRET: "" });
chk("unconfigured worker refuses to run the flow", r.status === 503);

// 1. landing without token explains; with token redirects to Microsoft sign-in with state and nonce
r = await call("/landing");
chk("landing without token: explanation page", r.status === 200 && (await r.text()).includes("Configure account"));
r = await call("/landing?token=ab%2Bcd%2Fef");
const loc = new URL(r.headers.get("location") || "https://x/");
const state = loc.searchParams.get("state"), nonce = loc.searchParams.get("nonce");
chk("landing with token: 302 to common authorize, form_post, id_token", r.status === 302 && loc.host === "login.microsoftonline.com" && loc.pathname === "/common/oauth2/v2.0/authorize" && loc.searchParams.get("response_mode") === "form_post" && loc.searchParams.get("response_type") === "id_token" && loc.searchParams.get("client_id") === LOGIN_APP && loc.searchParams.get("redirect_uri") === ORIGIN + "/auth/callback");
chk("purchase token kept server side, decoded", JSON.parse(store.m.get("st:" + state)).token === "ab+cd/ef");

const idt = (over = {}, key = MS) => jwt({ aud: LOGIN_APP, iss: `https://login.microsoftonline.com/${BUYER_TID}/v2.0`, tid: BUYER_TID, nonce, exp: now() + 600, iat: now(), name: "Pat Buyer", preferred_username: "pat@contoso.com", oid: randomUUID(), ...over }, key);

// 2. callback refusals
r = await call("/auth/callback", form({ id_token: idt(), state: "deadbeef" }));
chk("unknown state refused", r.status === 400);
r = await call("/landing?token=ab%2Bcd%2Fef"); let st2 = new URL(r.headers.get("location")).searchParams.get("state");
r = await call("/auth/callback", form({ id_token: idt({}, EVIL), state: st2 }));
chk("id_token signed by an impostor key refused", r.status === 401);
r = await call("/auth/callback", form({ id_token: idt(), state: st2 }));
chk("state is single use", r.status === 400);
for (const [label, over] of [["wrong audience", { aud: API_APP }], ["issuer not matching tid", { iss: "https://login.microsoftonline.com/common/v2.0" }], ["wrong nonce", { nonce: "x" }], ["expired", { exp: now() - 3600 }]]) {
  r = await call("/landing?token=ab%2Bcd%2Fef"); const s = new URL(r.headers.get("location")).searchParams;
  const tok = jwt({ aud: LOGIN_APP, iss: `https://login.microsoftonline.com/${BUYER_TID}/v2.0`, tid: BUYER_TID, nonce: s.get("nonce"), exp: now() + 600, ...over });
  r = await call("/auth/callback", form({ id_token: tok, state: s.get("state") }));
  chk("id_token refused: " + label, r.status === 401);
}

// 3. happy path: sign in, resolve, confirm page, activate
r = await call("/landing?token=ab%2Bcd%2Fef"); let s3 = new URL(r.headers.get("location")).searchParams;
const tok3 = jwt({ aud: LOGIN_APP, iss: `https://login.microsoftonline.com/${BUYER_TID}/v2.0`, tid: BUYER_TID, nonce: s3.get("nonce"), exp: now() + 600, preferred_username: "pat@contoso.com" });
r = await call("/auth/callback", form({ id_token: tok3, state: s3.get("state") }));
let html = await r.text();
const c = (html.match(/name="c" value="([0-9a-f]{48})"/) || [])[1];
chk("confirm page shows plan, purchaser and an Activate form", r.status === 200 && html.includes("endpoint-report") && html.includes("buyer@contoso.com") && html.includes("pat@contoso.com") && !!c);
chk("resolve was called with the publisher token and decoded purchase token", calls.some((x) => x.u.includes("/resolve?") && x.init.headers["x-ms-marketplace-token"] === "ab+cd/ef"));
chk("not activated before the buyer presses Activate", !calls.some((x) => x.u.includes("/activate?")) && !store.m.has("sub:" + SUB));
r = await call("/activate", form({ c }));
chk("activate: 200 page, subscription stored as Subscribed", r.status === 200 && JSON.parse(store.m.get("sub:" + SUB)).status === "Subscribed");
r = await call("/activate", form({ c }));
chk("confirmation is single use", r.status === 400);

// 4. resolve errors
resolveStatus = 400;
r = await call("/landing?token=ab%2Bcd%2Fef"); s3 = new URL(r.headers.get("location")).searchParams;
r = await call("/auth/callback", form({ id_token: jwt({ aud: LOGIN_APP, iss: `https://login.microsoftonline.com/${BUYER_TID}/v2.0`, tid: BUYER_TID, nonce: s3.get("nonce"), exp: now() + 600 }), state: s3.get("state") }));
chk("expired purchase token: Microsoft's wording", r.status === 400 && (await r.text()).includes("Configure Account or Manage Account"));
resolveStatus = 200;

// 5. webhook
const hook = (claims, body = { id: OP, subscriptionId: SUB, action: "Suspend", status: "Succeeded" }, key = MS) =>
  call("/webhook", { method: "POST", headers: { authorization: "Bearer " + jwt({ iss: `https://sts.windows.net/${TENANT}/`, tid: TENANT, aud: API_APP, appid: RESOURCE, exp: now() + 600, ...claims }, key), "content-type": "application/json" }, body: JSON.stringify(body) });
r = await call("/webhook", { method: "POST", body: "{}" });
chk("webhook without bearer: 401", r.status === 401);
for (const [label, claims, key] of [["impostor key", {}, EVIL], ["wrong tenant", { tid: BUYER_TID }], ["wrong audience", { aud: LOGIN_APP }], ["caller not the marketplace", { appid: API_APP }], ["foreign issuer", { iss: "https://sts.windows.net/" + BUYER_TID + "/" }], ["expired", { exp: now() - 3600 }]]) {
  r = await hook(claims, undefined, key);
  chk("webhook refused: " + label, r.status === 401);
}
r = await hook({});
chk("webhook Suspend: verified, confirmed with Operations API, stored", r.status === 200 && JSON.parse(store.m.get("sub:" + SUB)).status === "Suspended" && calls.some((x) => x.u.includes(`/operations/${OP}?`)));
r = await hook({ appid: undefined, azp: RESOURCE, iss: `https://login.microsoftonline.com/${TENANT}/v2.0` });
chk("webhook accepts v2 tokens that carry azp instead of appid", r.status === 200);
r = await hook({}, { id: OP, subscriptionId: SUB, action: "Unsubscribe" });
chk("payload action that disagrees with the operation is refused", r.status === 400);
opAction = "Unsubscribe";
r = await hook({}, { id: OP, subscriptionId: SUB, action: "Unsubscribe" });
chk("Unsubscribe recorded", r.status === 200 && JSON.parse(store.m.get("sub:" + SUB)).status === "Unsubscribed");
r = await hook({}, { id: "not-a-guid", subscriptionId: SUB });
chk("non-GUID ids refused", r.status === 400);

// 6. admin list
r = await call("/admin/subscriptions");
chk("admin list without token: 401", r.status === 401);
r = await call("/admin/subscriptions", { headers: { authorization: "Bearer adm1n-token-value" } });
const al = await r.json();
chk("admin list with token: the subscription and its events", r.status === 200 && al.count === 1 && al.subscriptions[0].events.length >= 3);

// 7. the client secret never reaches any URL or page
chk("client secret only ever sent to the token endpoint body", calls.every((x) => !x.u.includes("s3cret") && (x.u.endsWith("/oauth2/v2.0/token") || !String(x.init.body || "").includes("s3cret"))));

console.log(`\nhs-ms-marketplace: ${bad ? "FAIL " + bad + " of " + n : "ALL PASS (" + n + ")"}`);
process.exit(bad ? 1 : 0);
