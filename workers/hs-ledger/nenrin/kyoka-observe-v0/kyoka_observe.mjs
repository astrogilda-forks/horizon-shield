// kyoka-observe-v0 : a signed, offline-checkable record that an observer asked Japan's public register of licensed
// construction businesses (国土交通省 建設業者・宅建業者等企業情報検索システム, etsuran2.mlit.go.jp) about one
// construction business licence number (建設業許可番号), and what the register answered.
//
// Why: "this contractor is licensed" is the first question a homeowner should ask and the one most often answered by
// the contractor itself. The register is public, but a screenshot proves nothing and a link shows today's answer, not
// the answer on the day the contract was signed. This record pins the day's answer: the exact request, the sha256 of
// the exact response bytes, the rows the register listed for that number, and who asked, signed by the observer's
// NENRIN key. Bound to an identity (idp-bind-v0, for example a GitHub Actions run), "who asked" is a public workflow at
// a public commit, not a claim by HORIZON SHIELD.
//
// Honest line: the record proves what the OBSERVER says it received. TLS does not sign content, so nothing here proves
// the register served those bytes; independent observers asking the same question are how that is approached, and
// the record is built so two of them can be compared byte for byte (same request, same extractor). It does not prove
// that the person at the door is the business on the register, that the licence covers the work in question (the list
// page carries no trade or expiry; that is v0.2, from the detail page), or that the register is current (MLIT updates
// it twice a month). The representative's name on the list page is never copied into the record: it is a person's
// name, and for a sole proprietor it is the business; it stays inside the hashed response bytes only.
//
// Record (kyoka-observe-v0/observation). Derived fields (outside the preimage): observation_id, observer_sig.
//   schema         "kyoka-observe-v0/observation"
//   observer_id    did:key of the observer (Ed25519)
//   query          { kind: "minister" | "governor", license_no: "011915" (6 digits), prefecture?: "富山県" (governor only) }
//   request        { url, method: "POST", body, body_sha256 }  body is requestBody(query), exactly
//   response       { sha256, length, charset: "Shift_JIS", extractor: "mlit-etsuran-list-v0" }
//   result         { status: "listed" | "not_listed" | "unreadable", rows: [ { authority, license_no, trade_name,
//                    office, address } ], register_message }   rows are the register rows for the queried licence
//   observed_at    RFC3339 UTC "...Z"
//   nonce          caller chosen string
import { createHash, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { canonical, sha256hex, withoutDerived, sigBytes } from "../task-delegation-bind-v0/bind.mjs";
import { isRfc3339Utc } from "../task-execution-bind-v0/bind_exec.mjs";
import { publicKeyFromDidKey } from "../task-delegation-bind-v0/verify_fixture.mjs";
import { checkIdentity } from "../idp-bind-v0/trusted_identity.mjs";

export const KYOKA_OBSERVE_VERSION = "0.1.0";
export const SCHEMA = "kyoka-observe-v0/observation";
export const EXTRACTOR = "mlit-etsuran-list-v0";
export const REGISTER_URL = "https://etsuran2.mlit.go.jp/TAKKEN/kensetuKensaku.do";
const DERIVED = ["observation_id", "observer_sig"];

export const PREFECTURES = ["北海道", "青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県", "茨城県", "栃木県", "群馬県",
  "埼玉県", "千葉県", "東京都", "神奈川県", "新潟県", "富山県", "石川県", "福井県", "山梨県", "長野県", "岐阜県", "静岡県",
  "愛知県", "三重県", "滋賀県", "京都府", "大阪府", "兵庫県", "奈良県", "和歌山県", "鳥取県", "島根県", "岡山県", "広島県",
  "山口県", "徳島県", "香川県", "愛媛県", "高知県", "福岡県", "佐賀県", "長崎県", "熊本県", "大分県", "宮崎県", "鹿児島県",
  "沖縄県"];
// a minister's licence (国土交通大臣許可) is administered by a regional bureau, which is what the register prints
export const MINISTER_AUTHORITIES = ["北海道開発局", "東北地方整備局", "関東地方整備局", "北陸地方整備局", "中部地方整備局",
  "近畿地方整備局", "中国地方整備局", "四国地方整備局", "九州地方整備局", "沖縄総合事務局"];

export const observationPreimage = (o) => withoutDerived(o, DERIVED);
export const observationId = (o) => sha256hex(canonical(observationPreimage(o)));

// ---- the query and the one request it maps to ----
export function queryProblem(q) {
  if (!q || typeof q !== "object" || Array.isArray(q)) return "query_not_object";
  if (q.kind !== "minister" && q.kind !== "governor") return "query_kind_unknown";
  if (typeof q.license_no !== "string" || !/^\d{6}$/.test(q.license_no)) return "license_no_malformed";
  if (q.kind === "governor" && !PREFECTURES.includes(q.prefecture)) return "prefecture_unknown";
  if (q.kind === "minister" && Object.prototype.hasOwnProperty.call(q, "prefecture")) return "prefecture_on_minister";
  const extra = Object.keys(q).filter((k) => !["kind", "license_no", "prefecture"].includes(k));
  if (extra.length) return "query_extra_fields";
  return null;
}

// requestBody(query): the form body, ASCII only, in a fixed order. The register matches the number without leading
// zeros. A governor's number repeats across prefectures, so a governor query also sets kenCode to the prefecture (a
// governor's licence covers offices in that prefecture only), and the extractor still keeps only rows whose authority
// is the queried prefecture. The form was checked by hand against the live register on 2026-10-15.
export function requestBody(q) {
  const n = String(parseInt(q.license_no, 10));
  const kbn = q.kind === "minister" ? "00" : "01";
  const ken = q.kind === "governor" ? String(PREFECTURES.indexOf(q.prefecture) + 1).padStart(2, "0") : "";
  return ["CMD=search", "caller=KS", "rdoSelect=1", "rdoSelectJoken=1", "licenseNoKbn=" + kbn, "licenseNoFrom=" + n,
    "licenseNoTo=" + n, "choice=2", "kenCode=" + ken, "gyosyu=", "gyosyuType=", "keyWord=", "sortValue=1", "rdoSelectSort=1",
    "dispCount=50", "dispPage=1", "resultCount=0", "pageCount=0", "comNameKanaOnly=", "comNameKanjiOnly="].join("&");
}

// ---- the extractor: response bytes in, rows out. Pure, no DOM, the same in every runtime ----
// entities in one pass, so "&amp;lt;" stays "&lt;"; a numeric entity outside Unicode throws, and the caller refuses
const ENT = { nbsp: " ", amp: "&", lt: "<", gt: ">", quot: "\"", copy: "\u00a9" };
const decodeEntities = (s) => s.replace(/&(#\d{1,7}|[a-z]+);/g, (m, e) => e[0] === "#" ? String.fromCodePoint(+e.slice(1)) : (ENT[e] != null ? ENT[e] : m));
const cellText = (html) => decodeEntities(html.replace(/<[^>]*>/g, "")).replace(/[\s　]+/g, " ").trim();

export function extractList(bytes) {
  try { return extractListUnsafe(bytes); } catch (e) { return { ok: false, reason: "extractor_refused", register_message: "" }; }
}
function extractListUnsafe(bytes) {
  let html;
  try { html = new TextDecoder("shift_jis", { fatal: true }).decode(bytes); } catch (e) { return { ok: false, reason: "not_shift_jis" }; }
  // the register's own status line; the result page also quotes other phrases in 「」, so only this one is kept
  const msg = html.includes("「該当するデータが存在しません。」") ? "該当するデータが存在しません。" : "";
  const t = html.match(/<table[^>]*class="re_disp"[^>]*>([\s\S]*?)<\/table>/i);
  if (!t) {
    if (msg === "該当するデータが存在しません。") return { ok: true, rows: [], register_message: msg };
    return { ok: false, reason: "no_result_table", register_message: msg };
  }
  const trs = t[1].match(/<tr[^>]*>[\s\S]*?<\/tr>/gi) || [];
  const head = trs.length ? (trs[0].match(/<th[^>]*>[\s\S]*?<\/th>/gi) || []).map(cellText) : [];
  const WANT = ["No.", "許可行政庁", "許可番号", "商号又は名称", "代表者名", "営業所名", "所在地"];
  if (head.join("|") !== WANT.join("|")) return { ok: false, reason: "unexpected_columns", register_message: msg };
  const rows = [];
  for (const tr of trs.slice(1)) {
    const td = (tr.match(/<td[^>]*>[\s\S]*?<\/td>/gi) || []).map(cellText);
    if (td.length !== 7) return { ok: false, reason: "unexpected_row", register_message: msg };
    const m = td[2].match(/^第(\d{6})号$/);
    if (!m) return { ok: false, reason: "unexpected_license_cell", register_message: msg };
    // td[4] is the representative's name: read to keep the column count honest, never copied out
    rows.push({ authority: td[1], license_no: m[1], trade_name: td[3], office: td[5], address: td[6] });
  }
  // the register states how many rows matched in total; one page holds 50
  const tc = html.match(/<input[^>]*name="resultCount"[^>]*>/i);
  const total = tc && /value="(\d+)"/.test(tc[0]) ? +tc[0].match(/value="(\d+)"/)[1] : null;
  if (total === null) return { ok: false, reason: "no_result_count", register_message: msg };
  return { ok: true, rows, total, register_message: msg };
}

// result(query, extracted): the register rows for the queried licence, and a status
// A row on page one is enough to say "listed". When more rows matched than one page holds, the record says so
// (rows_truncated), and an empty page one is "unreadable", never "not_listed".
export const rowMatches = (q, r) => r.license_no === q.license_no
  && (q.kind === "minister" ? MINISTER_AUTHORITIES.includes(r.authority) : r.authority === q.prefecture);
export function resultFor(q, ex) {
  if (!ex.ok) return { status: "unreadable", rows: [], rows_truncated: false, register_message: ex.register_message || "" };
  const keep = ex.rows.filter((r) => rowMatches(q, r));
  const truncated = ex.total != null && ex.total > ex.rows.length;
  const status = keep.length ? "listed" : truncated ? "unreadable" : "not_listed";
  return { status, rows: keep, rows_truncated: truncated, register_message: ex.register_message || "" };
}

// ---- making one (the observer's side) ----
export function makeObservation({ observerPrivateKey, observerId, query, responseBytes, observedAt, nonce }) {
  const p = queryProblem(query);
  if (p) throw new Error(p);
  const body = requestBody(query);
  const ex = extractList(responseBytes);
  const res = resultFor(query, ex);
  const o = { schema: SCHEMA, observer_id: observerId, query,
    request: { url: REGISTER_URL, method: "POST", body, body_sha256: sha256hex(body) },
    response: { sha256: createHash("sha256").update(responseBytes).digest("hex"), length: responseBytes.length, charset: "Shift_JIS", extractor: EXTRACTOR },
    result: { status: res.status, rows: res.rows, rows_truncated: res.rows_truncated, register_message: res.register_message },
    observed_at: observedAt, nonce };
  o.observation_id = observationId(o);
  o.observer_sig = nodeSign(null, Buffer.from(canonical(observationPreimage(o)), "utf8"), observerPrivateKey).toString("base64");
  return o;
}

// ---- verification (offline) ----
export const AUDIENCE = "nenrin-kyoka-observe";
// input: { observation, response_bytes?, binding?, jwks?, trusted?: { "<issuer>": ["<jwks sha256>"] } }
// trusted is the reader's own choice of issuer keys; a JWKS that only the bundle vouches for is reported as such.
export function verify(input) {
  const refusals = [], findings = [], establishes = [], does_not_establish = [];
  const refuse = (code, why) => refusals.push({ code, why });
  const find = (code, why) => findings.push({ code, why });
  const o = input && input.observation;
  if (!o || typeof o !== "object" || Array.isArray(o)) {
    refuse("observation_not_object", "input.observation is not an object");
    return report(refusals, findings, establishes, does_not_establish, null);
  }
  if (o.schema !== SCHEMA) refuse("bad_schema", "schema must be " + SCHEMA);
  const qp = queryProblem(o.query);
  if (qp) refuse(qp, "the query is not a well formed licence query");
  if (!isRfc3339Utc(o.observed_at)) refuse("bad_observed_at", "observed_at must be a strict RFC3339 UTC instant");
  if (typeof o.nonce !== "string" || !o.nonce) refuse("bad_nonce", "nonce must be a non-empty string");

  // 1. the record is what its id says, and the observer signed it
  let id = null;
  try { id = observationId(o); } catch (e) { refuse("canonical_refused", String(e.message || e)); }
  if (id !== null) {
    if (o.observation_id !== id) refuse("observation_recompute_mismatch", "observation_id is not sha256 of the canonical preimage");
    let pub = null;
    try { pub = publicKeyFromDidKey(o.observer_id); } catch (e) { refuse("observer_id_unresolvable", "observer_id is not a usable Ed25519 did:key"); }
    const sig = sigBytes(o.observer_sig);
    if (pub && !sig) refuse("observer_sig_malformed", "observer_sig is not canonical base64 of 64 bytes");
    if (pub && sig) {
      let ok = false;
      try { ok = nodeVerify(null, Buffer.from(canonical(observationPreimage(o)), "utf8"), pub, sig); } catch (e) { ok = false; }
      if (!ok) refuse("observer_sig_invalid", "observer_sig does not verify under observer_id over the canonical preimage");
    }
  }

  // 2. the request is the one the query maps to, at the register
  const rq = o.request || {};
  if (!qp) {
    if (rq.url !== REGISTER_URL || rq.method !== "POST") refuse("request_target_mismatch", "request must be POST to " + REGISTER_URL);
    if (rq.body !== requestBody(o.query)) refuse("request_body_mismatch", "request.body is not requestBody(query)");
    if (rq.body_sha256 !== sha256hex(String(rq.body))) refuse("request_digest_mismatch", "request.body_sha256 is not sha256 of request.body");
  }
  const rs = o.response || {};
  if (rs.extractor !== EXTRACTOR || rs.charset !== "Shift_JIS" || !/^[0-9a-f]{64}$/.test(String(rs.sha256)) || !Number.isInteger(rs.length))
    refuse("bad_response_descriptor", "response must name sha256, length, Shift_JIS and " + EXTRACTOR);
  const R = o.result || {};
  if (!["listed", "not_listed", "unreadable"].includes(R.status) || !Array.isArray(R.rows)) refuse("bad_result", "result.status and result.rows are required");
  else if ((R.status === "listed") !== (R.rows.length > 0)) refuse("status_rows_disagree", "status listed iff rows are present");
  if (typeof R.rows_truncated !== "boolean") refuse("bad_result", "result.rows_truncated must be a boolean");
  if (R.status === "not_listed" && R.rows_truncated === true) refuse("status_rows_disagree", "a truncated page cannot say not_listed");
  if (Array.isArray(R.rows) && R.rows.some((r) => !r || typeof r !== "object" || Object.keys(r).sort().join() !== "address,authority,license_no,office,trade_name"))
    refuse("row_fields", "a row carries exactly authority, license_no, trade_name, office, address (no person's name)");
  else if (!qp && Array.isArray(R.rows) && R.rows.some((r) => !rowMatches(o.query, r)))
    refuse("row_not_for_query", "a row is for another licence number or another authority than the query");

  // 3. with the response bytes: they are the bytes named, and the extractor gives the same rows
  const bytes = input.response_bytes;
  if (bytes == null) find("response_not_supplied", "the response bytes were not supplied: the rows are the observer's reading, not rechecked here");
  else {
    const buf = Buffer.from(bytes);
    if (createHash("sha256").update(buf).digest("hex") !== rs.sha256 || buf.length !== rs.length) refuse("response_digest_mismatch", "the supplied bytes are not the response the record names");
    else if (!qp) {
      const again = resultFor(o.query, extractList(buf));
      const same = again.status === R.status && canonical(again.rows) === canonical(R.rows) && again.register_message === R.register_message;
      if (!same) refuse("extraction_mismatch", "re-extracting the supplied bytes does not give the recorded result");
      else find("extraction_reproduced", "re-extracting the response bytes gives exactly the recorded rows");
    }
  }

  // 4. with an identity binding: who the observer is, named only when the reader trusts the issuer's keys
  let who = null;
  if (input.binding != null) {
    const id = checkIdentity({ binding: input.binding, jwks: input.jwks, trusted: input.trusted, audience: AUDIENCE, actorId: o.observer_id });
    if (!id.ok) refuse(id.code, "the observer's identity binding: " + id.why);
    else if (id.vouched) { who = id.label; find("observer_bound", "observer_id is bound to " + id.label + ", under issuer keys this reader trusts"); }
    else find("observer_self_pinned", "the binding verifies only against JWKS bytes the bundle itself supplied; the claimed identity (" + id.label + ") is not established");
  }

  if (!refusals.length) {
    const reproduced = findings.some((f) => f.code === "extraction_reproduced");
    establishes.push("the holder of " + o.observer_id + (who ? " (" + who + ")" : "")
      + " signed that it asked the register about " + label(o.query) + " at " + o.observed_at + " and received " + rs.length + " bytes (sha256 " + rs.sha256.slice(0, 16) + ")");
    const said = reproduced ? "in those bytes, re-read here, the register listed" : "the observer records that the register listed";
    establishes.push(R.status === "listed"
      ? said + " " + R.rows.length + " row(s) for that licence" + (R.rows_truncated ? " on the first page of more" : "") + ": " + [...new Set(R.rows.map((r) => r.trade_name))].join(", ")
      : R.status === "not_listed" ? (reproduced ? "in those bytes, re-read here, the register listed" : "the observer records that the register listed") + " no business under that licence"
      : "the observer records that the register's answer could not be read as its list page");
  }
  does_not_establish.push("that the register served those bytes: TLS does not sign content, so this is what the observer says it received");
  does_not_establish.push("that the person or company you are dealing with is the business on the register");
  does_not_establish.push("the licensed trades or the licence's expiry: the list page does not carry them (v0.2 reads the detail page)");
  does_not_establish.push("that the register is current: MLIT updates it about twice a month");
  return report(refusals, findings, establishes, does_not_establish, id);
}

const label = (q) => (q && q.kind === "minister" ? "国土交通大臣許可" : (q && q.prefecture) + "知事許可") + " 第" + (q && q.license_no) + "号";

function report(refusals, findings, establishes, does_not_establish, id) {
  return { schema: "kyoka-observe-v0/report", version: KYOKA_OBSERVE_VERSION, verdict: refusals.length ? "refused" : "accepted",
    observation_id: id, refusals, findings, establishes, does_not_establish };
}
