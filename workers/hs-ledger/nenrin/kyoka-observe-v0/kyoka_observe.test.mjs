// kyoka_observe.test.mjs : node kyoka_observe.test.mjs
// The extractor over the fixtures (register shape, invented content), making and verifying observations, every
// refusal the spec names on a one-field change, the privacy rule (no person's name leaves the response bytes), and the
// composition with an identity binding (a mock issuer in GitHub Actions' token shape).
import { readFileSync } from "node:fs";
import { generateKeyPairSync, createHash } from "node:crypto";
import { extractList, resultFor, requestBody, queryProblem, makeObservation, verify, observationId } from "./kyoka_observe.mjs";
import { makeBinding, signJwt, newActorKey, sha256hex } from "../idp-bind-v0/idp_bind.mjs";

let fail = 0, n = 0;
const chk = (name, c, x = "") => { n++; console.log((c ? "PASS  " : "FAIL  ") + name + (c ? "" : "  <<< " + String(x).slice(0, 300))); if (!c) fail++; };
const fx = (f) => readFileSync(new URL("fixtures/" + f, import.meta.url));
const codes = (r) => r.refusals.map((x) => x.code);
const clone = (o) => JSON.parse(JSON.stringify(o));
const AT = "2026-10-15T15:00:00Z";
const K = newActorKey();
const obs = (query, file, extra = {}) => makeObservation(Object.assign({ observerPrivateKey: K.privateKey, observerId: K.actorId, query, responseBytes: fx(file), observedAt: AT, nonce: "n-1" }, extra));

// ---- the extractor ----
{
  const e = extractList(fx("minister_listed.bin"));
  chk("extract: minister page reads 2 rows", e.ok && e.rows.length === 2, JSON.stringify(e));
  chk("extract: row fields are authority, license_no, trade_name, office, address", e.ok && Object.keys(e.rows[0]).join() === "authority,license_no,trade_name,office,address");
  chk("extract: full-width text survives Shift_JIS", e.ok && e.rows[0].trade_name === "（株）見本建設" && e.rows[1].address === "神奈川県横浜市中区見本通４－５", JSON.stringify(e.rows));
  chk("extract: the representative's name is not in any row", e.ok && !JSON.stringify(e.rows).includes("見本 一郎") && !JSON.stringify(e.rows).includes("見本　一郎"));
  chk("extract: a page quoting 「保険加入状況」 has no register message", e.ok && e.register_message === "");
  const nl = extractList(fx("not_listed.bin"));
  chk("extract: the no-data page reads as zero rows with the register's message", nl.ok && nl.rows.length === 0 && nl.register_message === "該当するデータが存在しません。", JSON.stringify(nl));
  chk("extract: changed columns are refused, not guessed", extractList(fx("changed_columns.bin")).reason === "unexpected_columns");
  chk("extract: UTF-8 bytes that are not Shift_JIS are refused", !extractList(Buffer.from("\xff\xfe\xfd", "latin1")).ok);
  chk("extract: an unrelated page is refused", extractList(Buffer.from("<html>maintenance</html>")).reason === "no_result_table");
  chk("extract: the register's total is read", e.ok && e.total === 2);
  const en = extractList(fx("entities.bin"));
  chk("extract: entities decode once (&amp;lt; stays &lt;), numeric entities read", en.ok && en.rows[0].trade_name === "見本&lt;建設あ", JSON.stringify(en.rows));
  const be = extractList(fx("bad_entity.bin"));
  chk("extract: a numeric entity outside Unicode is refused, not thrown", be.ok === false && be.reason === "extractor_refused", JSON.stringify(be));
  chk("extract: a page without the register's result count is refused", extractList(Buffer.from(Buffer.from(fx("minister_listed.bin")).toString("latin1").replace("resultCount", "resultCnt"), "latin1")).reason === "no_result_count");
}

// ---- query -> request -> result ----
{
  chk("query: minister ok", queryProblem({ kind: "minister", license_no: "004321" }) === null);
  chk("query: governor needs a prefecture", queryProblem({ kind: "governor", license_no: "012345" }) === "prefecture_unknown");
  chk("query: five digits refused", queryProblem({ kind: "minister", license_no: "04321" }) === "license_no_malformed");
  chk("query: extra fields refused", queryProblem({ kind: "minister", license_no: "004321", x: 1 }) === "query_extra_fields");
  chk("query: a prefecture key on a minister query is refused, even null (one query, one encoding)", queryProblem({ kind: "minister", license_no: "004321", prefecture: null }) === "prefecture_on_minister");
  chk("request: a governor query sets kenCode to the prefecture", requestBody({ kind: "governor", license_no: "012345", prefecture: "神奈川県" }).includes("kenCode=14&") && requestBody({ kind: "minister", license_no: "004321" }).includes("kenCode=&"));
  const b = requestBody({ kind: "governor", license_no: "012345", prefecture: "神奈川県" });
  chk("request: ASCII only, number without leading zeros, governor class", /^[\x20-\x7e]+$/.test(b) && b.includes("licenseNoKbn=01&licenseNoFrom=12345&licenseNoTo=12345"), b);
  const g = resultFor({ kind: "governor", license_no: "012345", prefecture: "神奈川県" }, extractList(fx("governor_shared_number.bin")));
  chk("result: a governor number shared by three prefectures keeps only the queried one", g.status === "listed" && g.rows.length === 1 && g.rows[0].trade_name === "例示工務店", JSON.stringify(g));
  const g2 = resultFor({ kind: "governor", license_no: "012345", prefecture: "東京都" }, extractList(fx("governor_shared_number.bin")));
  chk("result: the same number in another prefecture is not_listed", g2.status === "not_listed" && g2.rows.length === 0);
  const m = resultFor({ kind: "minister", license_no: "004321" }, extractList(fx("minister_listed.bin")));
  chk("result: a minister licence keeps rows under a regional bureau", m.status === "listed" && m.rows.length === 2 && m.rows_truncated === false);
  const t = resultFor({ kind: "minister", license_no: "004321" }, extractList(fx("minister_truncated.bin")));
  chk("result: more rows than one page -> listed with rows_truncated", t.status === "listed" && t.rows_truncated === true);
  const gf = resultFor({ kind: "governor", license_no: "012345", prefecture: "神奈川県" }, extractList(fx("governor_page_full.bin")));
  chk("result: a full page without the queried prefecture is unreadable, never not_listed", gf.status === "unreadable" && gf.rows.length === 0, JSON.stringify(gf));
}

// ---- making and verifying ----
const QM = { kind: "minister", license_no: "004321" };
const QG = { kind: "governor", license_no: "012345", prefecture: "神奈川県" };
const o1 = obs(QM, "minister_listed.bin");
{
  const r = verify({ observation: o1, response_bytes: fx("minister_listed.bin") });
  chk("verify: accepted with the bytes, extraction reproduced", r.verdict === "accepted" && r.findings.some((f) => f.code === "extraction_reproduced"), JSON.stringify(r.refusals));
  chk("verify: says what it establishes and what it does not", r.establishes.length === 2 && r.does_not_establish.length === 4);
  const r2 = verify({ observation: o1 });
  chk("verify: accepted without the bytes, with finding response_not_supplied", r2.verdict === "accepted" && r2.findings.some((f) => f.code === "response_not_supplied"));
  chk("verify: without the bytes the rows are the observer's record, not 'in those bytes'", r2.establishes[1].startsWith("the observer records that") && r.establishes[1].startsWith("in those bytes, re-read here"));
  const og = obs(QG, "governor_shared_number.bin");
  chk("verify: governor observation accepted", verify({ observation: og, response_bytes: fx("governor_shared_number.bin") }).verdict === "accepted");
  const on = obs({ kind: "governor", license_no: "999999", prefecture: "東京都" }, "not_listed.bin");
  const rn = verify({ observation: on, response_bytes: fx("not_listed.bin") });
  chk("verify: a not_listed observation is a record too", rn.verdict === "accepted" && on.result.status === "not_listed" && /no business/.test(rn.establishes[1]));
  const ou = obs(QM, "changed_columns.bin");
  chk("verify: an unreadable page is recorded as unreadable, not as not_listed", ou.result.status === "unreadable" && verify({ observation: ou, response_bytes: fx("changed_columns.bin") }).verdict === "accepted");
}

// ---- refusals, one change at a time ----
const resign = (o) => { o.observation_id = observationId(o); return o; };   // id recomputed, signature left stale
const mutations = [
  ["schema", (o) => { o.schema = "x"; }, "bad_schema"],
  ["observation_id", (o) => { o.observation_id = "0".repeat(64); }, "observation_recompute_mismatch"],
  ["a row's trade name", (o) => { o.result.rows[0].trade_name = "（株）別会社"; }, "observation_recompute_mismatch"],
  ["a row's trade name, id recomputed", (o) => { o.result.rows[0].trade_name = "（株）別会社"; resign(o); }, "observer_sig_invalid"],
  ["observer_sig", (o) => { o.observer_sig = "AAAA"; }, "observer_sig_malformed"],
  ["observer_id", (o) => { o.observer_id = "did:key:zNope"; resign(o); }, "observer_id_unresolvable"],
  ["request body", (o) => { o.request.body = o.request.body.replace("dispCount=50", "dispCount=10"); resign(o); }, "request_body_mismatch"],
  ["request url", (o) => { o.request.url = "https://example.com/"; resign(o); }, "request_target_mismatch"],
  ["request digest", (o) => { o.request.body_sha256 = "0".repeat(64); resign(o); }, "request_digest_mismatch"],
  ["status listed with no rows", (o) => { o.result.rows = []; resign(o); }, "status_rows_disagree"],
  ["a person's name added to a row", (o) => { o.result.rows[0].representative = "見本 一郎"; resign(o); }, "row_fields"],
  ["observed_at", (o) => { o.observed_at = "2026-10-15 15:00"; resign(o); }, "bad_observed_at"],
  ["query licence number", (o) => { o.query.license_no = "4321"; resign(o); }, "license_no_malformed"],
  ["a row for another licence", (o) => { o.result.rows[0].license_no = "009999"; resign(o); }, "row_not_for_query"],
  ["a row under a prefecture on a minister query", (o) => { o.result.rows[0].authority = "東京都"; resign(o); }, "row_not_for_query"],
  ["rows_truncated missing", (o) => { delete o.result.rows_truncated; resign(o); }, "bad_result"],
  ["response descriptor", (o) => { o.response.extractor = "other"; resign(o); }, "bad_response_descriptor"],
];
for (const [what, f, want] of mutations) {
  const o = clone(o1); f(o);
  const c = codes(verify({ observation: o, response_bytes: fx("minister_listed.bin") }));
  chk("refuse: " + what + " -> " + want, c.includes(want), c.join(","));
}
{
  const c = codes(verify({ observation: o1, response_bytes: fx("governor_shared_number.bin") }));
  chk("refuse: other response bytes -> response_digest_mismatch", c.includes("response_digest_mismatch"), c.join(","));
  // the observer signs a reading the bytes do not support: digest right, rows wrong
  const lie = makeObservation({ observerPrivateKey: K.privateKey, observerId: K.actorId, query: QG, responseBytes: fx("governor_shared_number.bin"), observedAt: AT, nonce: "n-2" });
  lie.result.rows[0].trade_name = "（株）立派建設"; lie.observation_id = observationId(lie);
  const { sign } = await import("node:crypto");
  const { canonical } = await import("../task-delegation-bind-v0/bind.mjs");
  const { observationPreimage } = await import("./kyoka_observe.mjs");
  lie.observer_sig = sign(null, Buffer.from(canonical(observationPreimage(lie)), "utf8"), K.privateKey).toString("base64");
  chk("refuse: a signed reading the bytes do not support -> extraction_mismatch", codes(verify({ observation: lie, response_bytes: fx("governor_shared_number.bin") })).includes("extraction_mismatch"));
  chk("accept without bytes: the same lie passes when the bytes are withheld (which is why the finding says so)", verify({ observation: lie }).verdict === "accepted");
}

// ---- with an identity: a mock issuer in GitHub Actions' token shape ----
{
  const iss = "https://token.actions.githubusercontent.com";
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pub = rsa.publicKey.export({ format: "jwk" });
  const kid = createHash("sha256").update(pub.n).digest("hex").slice(0, 40).toUpperCase();
  const doc = JSON.stringify({ keys: [{ kty: "RSA", alg: "RS256", use: "sig", kid, n: pub.n, e: pub.e }] });
  const jwks = { sha256: sha256hex(doc), document: doc };
  const now = Math.floor(Date.parse(AT) / 1000);
  const sub = "repo:ogasurfproject-jpg/horizon-shield:environment:nenrin-observer";
  const tok = signJwt({ typ: "JWT", alg: "RS256", kid }, { iss, sub, aud: "nenrin-kyoka-observe", iat: now - 10, nbf: now - 10, exp: now + 290,
    repository: "ogasurfproject-jpg/horizon-shield", workflow: "kyoka-observe", run_id: "1", sha: "0".repeat(40), environment: "nenrin-observer" }, rsa.privateKey, "RS256");
  const binding = makeBinding({ actorPrivateKey: K.privateKey, actorId: K.actorId, token: tok, issuer: iss, subject: sub, audience: "nenrin-kyoka-observe", kid, alg: "RS256", boundAt: AT, nonce: "b-1" });
  const trusted = { [iss]: [jwks.sha256] };
  const r = verify({ observation: o1, response_bytes: fx("minister_listed.bin"), binding, jwks, trusted });
  chk("bound: with the issuer's keys trusted by the reader, observer_bound names the workflow subject", r.verdict === "accepted" && r.findings.some((f) => f.code === "observer_bound" && f.why.includes(sub)), JSON.stringify(r.refusals));
  chk("bound: the establishes line names the issuer and subject", r.establishes[0].includes(iss) && r.establishes[0].includes(sub));
  const self = verify({ observation: o1, response_bytes: fx("minister_listed.bin"), binding, jwks });
  chk("bound: the same binding with JWKS only the bundle vouches for is observer_self_pinned, and names no identity", self.verdict === "accepted" && self.findings.some((f) => f.code === "observer_self_pinned") && !self.findings.some((f) => f.code === "observer_bound") && !self.establishes[0].includes(sub));
  const otherPin = verify({ observation: o1, binding, jwks, trusted: { [iss]: ["0".repeat(64)] } });
  chk("bound: trusted keys at another digest -> self pinned, not bound", otherPin.findings.some((f) => f.code === "observer_self_pinned"));
  const tokAud = signJwt({ typ: "JWT", alg: "RS256", kid }, { iss, sub, aud: "nenrin-payee-confirm", iat: now - 10, nbf: now - 10, exp: now + 290 }, rsa.privateKey, "RS256");
  const bAud = makeBinding({ actorPrivateKey: K.privateKey, actorId: K.actorId, token: tokAud, issuer: iss, subject: sub, audience: "nenrin-payee-confirm", kid, alg: "RS256", boundAt: AT, nonce: "b-3" });
  chk("bound: a token for another audience -> binding_other_audience", codes(verify({ observation: o1, binding: bAud, jwks, trusted })).includes("binding_other_audience"));
  const other = newActorKey();
  const b2 = makeBinding({ actorPrivateKey: other.privateKey, actorId: other.actorId, token: tok, issuer: iss, subject: sub, audience: "nenrin-kyoka-observe", kid, alg: "RS256", boundAt: AT, nonce: "b-2" });
  chk("bound: a binding of another key -> binding_other_key", codes(verify({ observation: o1, binding: b2, jwks, trusted })).includes("binding_other_key"));
  const docB = doc.replace(/"n":"./, '"n":"A');
  chk("bound: a JWKS other than the pinned bytes -> binding_refused", codes(verify({ observation: o1, binding, jwks: { sha256: jwks.sha256, document: docB } })).includes("binding_refused"));
}

console.log("\n" + (n - fail) + "/" + n + " passed");
process.exit(fail ? 1 : 0);
