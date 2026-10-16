// kyoka_detail.mjs : the register's detail page for one licence (ksGaiyo.do), read for what the list page does not
// carry: which trades the licence covers (一般 or 特定 for each) and the period of validity. Added in kyoka-observe 0.2.0.
//
// The request is fixed: POST https://etsuran2.mlit.go.jp/TAKKEN/ksGaiyo.do with body
// "CMD=&caller=KS&sv_licenseNo=<authority code><6-digit number>", where the authority code is 00 for a minister's
// licence and the prefecture's two-digit code (神奈川県 = 14) for a governor's. That is the value the list page passes to
// its own js_ShowDetail(); the register answered this minimal body with the same detail page on 2026-10-16.
//
// The extractor (mlit-etsuran-detail-v0) decodes Shift_JIS strictly and refuses rather than guesses. It reads:
//   table re_summ    許可番号 (must be the queried licence) and 商号又は名称 (the phonetic line is dropped)
//   table re_summ_3  the first one: 29 trade columns in the register's fixed order, the value row 1 (一般) / 2 (特定) / empty
//   table re_summ_4  the grant dates (許可年月), in the register's order
//   table re_summ_5  許可の有効期間 of the grant the page shows (the first), converted from 令和/平成 to ISO dates
// It never reads the representative's name or the telephone number out of the page: they stay inside the hashed bytes.
import { createHash } from "node:crypto";
import { PREFECTURES } from "./kyoka_observe.mjs";

export const DETAIL_URL = "https://etsuran2.mlit.go.jp/TAKKEN/ksGaiyo.do";
export const DETAIL_EXTRACTOR = "mlit-etsuran-detail-v0";

// The 29 trades of the Construction Business Act, in the order the register prints them, with the register's one-letter
// header. タイル is printed with U+5915 (夕), not katakana タ: that is what the register serves, and it is matched as served.
export const TRADES = [
  ["土", "土木一式工事"], ["建", "建築一式工事"], ["大", "大工工事"], ["左", "左官工事"], ["と", "とび・土工・コンクリート工事"],
  ["石", "石工事"], ["屋", "屋根工事"], ["電", "電気工事"], ["管", "管工事"], ["夕", "タイル・れんが・ブロック工事"],
  ["鋼", "鋼構造物工事"], ["筋", "鉄筋工事"], ["舗", "舗装工事"], ["しゅ", "しゅんせつ工事"], ["板", "板金工事"],
  ["ガ", "ガラス工事"], ["塗", "塗装工事"], ["防", "防水工事"], ["内", "内装仕上工事"], ["機", "機械器具設置工事"],
  ["絶", "熱絶縁工事"], ["通", "電気通信工事"], ["園", "造園工事"], ["井", "さく井工事"], ["具", "建具工事"],
  ["水", "水道施設工事"], ["消", "消防施設工事"], ["清", "清掃施設工事"], ["解", "解体工事"],
];

export function detailCode(q) {
  return (q.kind === "minister" ? "00" : String(PREFECTURES.indexOf(q.prefecture) + 1).padStart(2, "0")) + q.license_no;
}
export const detailRequestBody = (q) => "CMD=&caller=KS&sv_licenseNo=" + detailCode(q);
export const licenseLabel = (q) => (q.kind === "minister" ? "国土交通大臣許可" : q.prefecture + "知事許可") + "　第" + q.license_no + "号";

const ENT = { nbsp: " ", amp: "&", lt: "<", gt: ">", quot: "\"", copy: "©" };
const decodeEntities = (s) => s.replace(/&(#\d{1,7}|[a-z]+);/g, (m, e) => e[0] === "#" ? String.fromCodePoint(+e.slice(1)) : (ENT[e] != null ? ENT[e] : m));
// text: tags out (a <br> inside a cell, as in し<br>ゅ, joins), entities once, runs of space (U+3000 included) to one
const text = (html) => decodeEntities(html.replace(/<br\s*\/?>/gi, "").replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim();
const bare = (s) => s.replace(/\s/g, "");
const tables = (html, cls) => [...html.matchAll(new RegExp('<table[^>]*class="' + cls + '"[^>]*>([\\s\\S]*?)</table>', "gi"))].map((m) => m[1]);
const rowsOf = (t) => (t.match(/<tr[^>]*>[\s\S]*?<\/tr>/gi) || []);
const cells = (tr, tag) => (tr.match(new RegExp("<" + tag + "[^>]*>[\\s\\S]*?</" + tag + ">", "gi")) || []);

// 令和 y = 2018 + y, 平成 y = 1988 + y. "R08年11月24日" -> "2026-11-24"; anything else -> null
export function wareki(s) {
  const m = String(s).match(/^([RH])(\d{2})年(\d{2})月(\d{2})日$/) || String(s).match(/^([RH])(\d{2})\/(\d{2})\/(\d{2})$/);
  if (!m) return null;
  const y = (m[1] === "R" ? 2018 : 1988) + +m[2], mo = +m[3], d = +m[4];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return null;
  return dt.toISOString().slice(0, 10);
}

export function extractDetail(bytes, q) {
  try { return extractDetailUnsafe(bytes, q); } catch (e) { return { ok: false, reason: "extractor_refused" }; }
}
function extractDetailUnsafe(bytes, q) {
  let html;
  try { html = new TextDecoder("shift_jis", { fatal: true }).decode(bytes); } catch (e) { return { ok: false, reason: "not_shift_jis" }; }
  const summ = tables(html, "re_summ")[0];
  if (!summ) return { ok: false, reason: "no_summary_table" };
  const field = {};
  for (const tr of rowsOf(summ)) {
    const th = cells(tr, "th"), td = cells(tr, "td");
    if (th.length === 1 && td.length === 1) field[bare(text(th[0]))] = td[0];
  }
  if (!("許可番号" in field) || !("商号又は名称" in field)) return { ok: false, reason: "unexpected_summary" };
  const lic = text(field["許可番号"]);
  if (bare(lic) !== bare(licenseLabel(q))) return { ok: false, reason: "detail_for_another_licence" };
  const trade_name = text(field["商号又は名称"].replace(/<p[^>]*class="phonetic"[^>]*>[\s\S]*?<\/p>/i, ""));

  const t3 = tables(html, "re_summ_3")[0];
  if (!t3) return { ok: false, reason: "no_trade_table" };
  const r3 = rowsOf(t3);
  if (r3.length !== 2) return { ok: false, reason: "unexpected_trade_table" };
  const head = cells(r3[0], "td").map((c) => bare(text(c))), vals = cells(r3[1], "td").map((c) => bare(text(c)));
  if (head.join("|") !== TRADES.map((x) => x[0]).join("|")) return { ok: false, reason: "unexpected_trade_columns" };
  if (vals.length !== TRADES.length || vals.some((v) => !["", "1", "2"].includes(v))) return { ok: false, reason: "unexpected_trade_values" };
  const trades = vals.flatMap((v, i) => (v ? [{ trade: TRADES[i][1], class: v === "1" ? "一般" : "特定" }] : []));

  const t4 = tables(html, "re_summ_4")[0];
  const grants = t4 ? rowsOf(t4).map((tr) => bare(text(cells(tr, "td")[0] || ""))).filter(Boolean) : [];
  const gdates = grants.map(wareki);
  if (!grants.length || gdates.some((d) => d === null)) return { ok: false, reason: "unexpected_grant_dates" };

  const t5 = tables(html, "re_summ_5")[0];
  let validity = null;
  if (t5) for (const tr of rowsOf(t5)) {
    const th = cells(tr, "th"), td = cells(tr, "td");
    if (th.length === 1 && bare(text(th[0])) === "許可の有効期間" && td.length === 1) {
      const m = bare(text(td[0])).match(/^([RH]\d{2}年\d{2}月\d{2}日)から([RH]\d{2}年\d{2}月\d{2}日)まで$/);
      if (m && wareki(m[1]) && wareki(m[2])) validity = { from: wareki(m[1]), to: wareki(m[2]) };
    }
  }
  if (!validity) return { ok: false, reason: "unexpected_validity" };
  if (validity.from !== gdates[0]) return { ok: false, reason: "validity_not_for_first_grant" };
  return { ok: true, license_label: lic, trade_name, trades, grants: gdates, validity };
}

// What goes into the observation (inside the signed preimage)
export function detailRecord(q, bytes) {
  const body = detailRequestBody(q);
  const ex = extractDetail(bytes, q);
  return {
    request: { url: DETAIL_URL, method: "POST", body, body_sha256: createHash("sha256").update(body).digest("hex") },
    response: { sha256: createHash("sha256").update(bytes).digest("hex"), length: bytes.length, charset: "Shift_JIS", extractor: DETAIL_EXTRACTOR },
    result: ex.ok ? { status: "read", trade_name: ex.trade_name, trades: ex.trades, grants: ex.grants, validity: ex.validity }
                  : { status: "unreadable", reason: ex.reason },
  };
}
