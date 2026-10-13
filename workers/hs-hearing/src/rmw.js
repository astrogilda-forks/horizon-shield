// rmw.js
// store:<sid> と hearing:<sid> の「読む・直す・書く」を、店ごとに 1 本にする (2026-10-13、concurrency audit H2 と H3)。
//
// 何が起きとったか。
//   store:<sid>   は LINE と メールの webhook、日次の巡回、管理の口が、それぞれ読んで、直して、丸ごと書き戻す。
//   hearing:<sid> は 用紙の答え、メールや LINE の返事、見積の追加、管理の直しが、同じ事をする。
//   KV に取引は無い。読んでから書くまでの間に別の経路が同じ鍵を書けば、後に書いた方が丸ごと勝つ。
//   putStore は asked(台帳)を合併して守っとったが、返事待ち(pending)と人送りの印(needs_human)は
//   「上書きされた」と名前を残すだけで(_pending_overwritten)、防いではおらんかった。hearing: 側には合併すら無かった。
//
// どう閉じるか。
//   書き込みを Durable Object に通す。DispatchGateDO(生成の合図の関所、dispatch_do.js)に /rmw の口を足し、
//   鍵ごとに別の DO の id(rmw:<key>)を使う。DO は id ごとに 1 本しか実行せんから、同じ鍵への二本は必ず順番になる。
//   DO の中で KV を読み、直し(op)を当て、KV に書き、書いた写しを DO の storage にも残す(床)。
//   KV は結果整合で、書いた直後の読みが古い写しを返す事がある。DO の storage は強整合やから、
//   KV の写しが DO の床より古い(seq が小さい)うちは、DO の写しを「今」として使う。古い写しが蘇らん。
//
// 直し(op)は名前で渡す。関数は DO の境界を越えられんし、DO の中で動く規則は、DO を立てずに試験できる純関数で
// あるべきやからや。OPS の中身は全部 (current, args, ctx) => { record, result } の形。record が null なら書かん。
//
//   store.put                 putStore の丸ごと書き込み。読んだ時の版(_rmw.seq)を床の写しから引いて三方合併する。
//                             自分が触っとらん欄は保存側(別の経路が書いた物)を残す。両方が触った欄は自分が勝つ。
//                             ただし pending と needs_human は、両方が触ったら新しい方(sent_at / since)が勝ち、
//                             片方が消しとったら残しとる方が勝つ。衝突は autopilot._rmw_conflicts に名前を残す。
//                             読んだ時の版が分からん写し(配備前に読んだ物、床から落ちた古い版)は、これまで通りの
//                             二方合併(台帳は合併、他は自分が勝つ、_pending_overwritten に名前)。
//   hearing.merge_answer      返事(メール / LINE / 用紙)の取り込み。mergeProfiles を保存側の「今」に当てる。
//   hearing.append_estimates  審査用の見積の追加。保存側の「今」に足す。
//   hearing.set_estimates_clear  管理の口 set-estimates の「空にしてから足す」の前半。
//   hearing.profile_patch     管理の口 profile-patch。検査も中で行う(検査は保存側の「今」に対して意味を持つ)。
//
// 関所が繋がっとらん時(env.DISPATCH_DO が無い = 単体試験)は、同じ op を KV に直接当てる(これまでの経路)。
// 繋がっとるのに DO が答えん・誤る時は、何も書かずに投げる(fail-closed)。KV に直接書く逃げ道は作らん。
//
// 古い記録はそのまま読める。足したのは記録の先頭の _rmw: { seq, at } だけで、読む側は全部それを無視する。
// 巻き戻し(この版より前の code に戻す)の注意: 前の code は _rmw を知らんが、丸ごと読んで丸ごと書くので
// _rmw を運び続ける(seq が止まる)。DO の床は 120 秒(STALE_WINDOW_MS)で効力を失うので、
// 戻した code の書き込みは次の DO 書き込みで「外から書かれた新しい写し」として採られる。

import * as AP from "./autopilot.js";
import * as IND from "./industry.js";
import * as VIS from "./visibility.js";

export const STORE_WRITES_MARK = "do-serialized-20261013";   // GET /health の store_writes。ops/prod_fix_check.sh が読む
export const RMW_PREFIXES = ["store:", "hearing:"];
export const KEEP_VERSIONS = 8;            // DO の storage に残す版の数(三方合併の底に使う)
export const STALE_WINDOW_MS = 120000;     // KV の反映は 60 秒まで遅れる。その倍までは DO の床を「今」とする

const nowIso = () => new Date().toISOString();
const safeStr = (v, max = 400) => (v == null ? "" : String(v)).slice(0, max);

export function rmwFailed(key, why) {
  const e = new Error("rmw_failed: " + key + " (" + why + ")");
  e.code = "rmw_failed";
  e.key = key;
  e.why = why;
  return e;
}

export function stampSeq(rec) {
  const n = rec && rec._rmw && Number(rec._rmw.seq);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/* ------------------------------ store.put の合併 ------------------------------ */

const LEDGERS = ["_writes", "_asked_recovered", "_pending_overwritten", "_rmw_conflicts"];

function same(a, b) {
  return JSON.stringify(a === undefined ? null : a) === JSON.stringify(b === undefined ? null : b);
}

function unionLedger(saved, mine) {
  const merged = [...(saved || []), ...(mine || [])];
  const seen = new Set(), out = [];
  for (const e of merged) {
    const key = String(e && e.at) + "|" + String(e && e.by) + "|" + JSON.stringify(e || {});
    if (seen.has(key)) continue;
    seen.add(key); out.push(e);
  }
  return out.slice(-20);
}

// 両方が触った pending / needs_human。片方が消しとったら残っとる方。両方残っとったら新しい方。同時なら自分。
function pickNewer(mine, theirs, field) {
  if (mine == null) return theirs;
  if (theirs == null) return mine;
  const m = String((mine && mine[field]) || ""), t = String((theirs && theirs[field]) || "");
  return t > m ? theirs : mine;
}

// theirs: 保存側の今。base: 自分が読んだ時の版(無ければ null)。mine: 書きに来た写し。
// 戻す物は新しい記録。mine は触らん(呼ぶ側が後で syncInto で写す)。
export function mergeStoreWrite(theirs, base, mine, by, at) {
  const out = { ...mine };
  const ap = { ...(mine.autopilot || {}) };
  const sap = (theirs && theirs.autopilot) || null;
  const conflicts = [];
  const threeWay = !!(base && theirs);

  if (threeWay) {
    const bap = base.autopilot || {};
    for (const k of new Set([...Object.keys(base), ...Object.keys(mine), ...Object.keys(theirs)])) {
      if (k === "autopilot" || k === "_rmw") continue;
      if (same(mine[k], base[k])) {
        // 自分は触っとらん。保存側(別の経路が書いた物)を残す。
        if (theirs[k] === undefined) delete out[k]; else out[k] = theirs[k];
      } else if (!same(theirs[k], base[k]) && !same(theirs[k], mine[k])) {
        conflicts.push(k);   // 両方が触った。自分が勝つ(これまでと同じ)。名前は残す。
      }
    }
    for (const k of new Set([...Object.keys(bap), ...Object.keys(ap), ...(sap ? Object.keys(sap) : [])])) {
      if (LEDGERS.includes(k) || k === "asked") continue;
      const m = ap[k], b = bap[k], t = sap ? sap[k] : undefined;
      if (same(m, b)) { if (t === undefined) delete ap[k]; else ap[k] = t; continue; }
      if (same(t, b) || same(t, m)) continue;
      // 両方が触った。
      if (k === "pending") ap[k] = pickNewer(m, t, "sent_at");
      else if (k === "needs_human") ap[k] = pickNewer(m, t, "since");
      if (ap[k] == null) delete ap[k];
      conflicts.push("autopilot." + k + (same(ap[k], m) ? "" : ":theirs"));
    }
  }

  if (sap) {
    // 台帳は、書きに来た写しが持っていなくても引き継ぐ(2026-08-24 の手当て、そのまま)。
    for (const k of LEDGERS) {
      const merged = unionLedger(sap[k], ap[k]);
      if (merged.length) ap[k] = merged;
    }
    const before = (ap.asked || []).length;
    ap.asked = AP.mergeAsked(sap.asked, ap.asked);
    const kept = ap.asked.length - before;
    if (kept > 0) {
      ap._asked_recovered = [...(ap._asked_recovered || []), { at, by: String(by || "?"), kept }].slice(-10);
    }
    if (!threeWay) {
      // 読んだ時の版が分からん。これまで通り、起きた事を名前で残す(直さん。消込まで巻き戻す恐れがある)。
      const mine = ap.pending && ap.pending.sent_at ? String(ap.pending.sent_at) : "";
      const theirsAt = sap.pending && sap.pending.sent_at ? String(sap.pending.sent_at) : "";
      if (theirsAt && theirsAt > mine) {
        ap._pending_overwritten = [...(ap._pending_overwritten || []), {
          at, by: String(by || "?"),
          lost_qids: (sap.pending.qids || []).slice(0, 8),
          lost_sent_at: theirsAt,
          mine_sent_at: mine || null,
        }].slice(-10);
      }
    }
  }
  if (conflicts.length) {
    ap._rmw_conflicts = [...(ap._rmw_conflicts || []), { at, by: String(by || "?"), keys: conflicts.slice(0, 12) }].slice(-10);
  }
  ap._writes = [...(ap._writes || []), { at, by: String(by || "?") }].slice(-20);
  out.autopilot = ap;
  return out;
}

// DO が書いた記録を、呼ぶ側が持っとる store(と、その autopilot への参照)に写す。
// 入れ替えずに中身を写すんは、呼ぶ側が `const ap = store.autopilot` を握ったまま続きを書くからや。
export function syncInto(target, record) {
  if (!target || !record) return target;
  for (const k of Object.keys(target)) if (!(k in record)) delete target[k];
  for (const k of Object.keys(record)) {
    if (k === "autopilot" && target.autopilot && typeof target.autopilot === "object" && record.autopilot) {
      for (const j of Object.keys(target.autopilot)) if (!(j in record.autopilot)) delete target.autopilot[j];
      Object.assign(target.autopilot, record.autopilot);
    } else {
      target[k] = record[k];
    }
  }
  return target;
}

/* ------------------------------ hearing.* の直し ------------------------------ */

const eKey = (e) => safeStr(e && e.work, 80) + "|" + safeStr(e && e.amount, 20);

function knownQids(profile) {
  const known = new Set();
  for (const k of Object.keys(AP.QUESTION_BANK)) {
    const v = AP.QUESTION_BANK[k];
    if (v && typeof v === "object" && !v.text) for (const q of Object.keys(v)) known.add(q);
    else known.add(k);
  }
  for (const q of Object.keys(IND.industryBank(profile.industry) || {})) known.add(q);
  for (const q of VIS.visibilityQids()) known.add(q);
  for (const q of Object.keys(AP.ENRICH_BANK || {})) known.add(q);
  known.add("_unsorted");
  return known;
}

/* 名前つきの直し。全部 (current, args, ctx) => { record, result }。record が null なら何も書かん。
   ctx.getVersion(seq) は DO の床から過去の版を引く(無ければ undefined)。ctx.at は書く時刻(ISO)。 */
export const OPS = {
  "store.put": async (current, args, ctx) => {
    const mine = args && args.store;
    if (!mine || !mine.store_id) return { record: null, result: { error: "no_store" } };
    const mineSeq = stampSeq(mine);
    let base = null;
    if (current && mineSeq > 0) {
      base = mineSeq === stampSeq(current) ? current : ((await ctx.getVersion(mineSeq)) || null);
    }
    return { record: mergeStoreWrite(current, base, mine, args.by, ctx.at), result: { three_way: !!(base && current) } };
  },

  // args: { incoming, extra_patch, fields: { token?, source, ground? }, now, require_core }
  "hearing.merge_answer": async (current, args) => {
    const f = (args && args.fields) || {};
    const profile = AP.mergeProfiles(current && current.profile, args.incoming || {});
    const patch = (args && args.extra_patch) || {};
    if (Object.keys(patch).length) profile.extra = { ...(profile.extra || {}), ...patch };
    if (args.require_core && (!profile.company || !profile.area || !(profile.works && profile.works.length))) {
      return { record: null, result: { reason: "missing-required" } };
    }
    const record = {};
    if (f.token) record.token = f.token;
    record.store_id = args.store_id;
    record.profile = profile;
    record.answered_at = args.now;
    record.completed = true;
    record.source = f.source;
    if (f.ground !== undefined) record.ground = f.ground;
    return { record, result: {} };
  },

  // args: { store_id, norm, now }
  "hearing.append_estimates": async (current, args) => {
    const profile = (current && current.profile) || { store_id: args.store_id };
    const ests = Array.isArray(profile.estimates_for_audit) ? profile.estimates_for_audit.slice() : [];
    const seen = new Set(ests.map(eKey));
    let added = 0;
    for (const e of (args.norm || [])) { const k = eKey(e); if (!seen.has(k)) { seen.add(k); ests.push(e); added++; } }
    profile.estimates_for_audit = ests.slice(0, 12);
    return { record: { ...(current || {}), store_id: args.store_id, profile, estimate_updated_at: args.now },
             result: { added, total: profile.estimates_for_audit.length } };
  },

  // args: { store_id, to_count, now }
  "hearing.set_estimates_clear": async (current, args) => {
    const profile = (current && current.profile) || { store_id: args.store_id };
    const before = Array.isArray(profile.estimates_for_audit) ? profile.estimates_for_audit : [];
    const beforeKeys = before.map(eKey);
    profile.edits = [...(profile.edits || []),
      { at: args.now, by: "admin", op: "set-estimates",
        from_count: before.length, to_count: args.to_count,
        from_keys: beforeKeys.slice(0, 20) }].slice(-20);
    profile.estimates_for_audit = [];
    return { record: { ...(current || {}), store_id: args.store_id, profile }, result: { before_count: before.length } };
  },

  // args: { fields, extra, now, now_ms }。検査に落ちたら record は null で result.error に理由。
  // hearing.js の /admin/profile-patch から移した本体(2026-10-13)。中の規則の由来:
  //   2026-08-23 直せる欄を増やした(エリアも業種も直せなかった)。2026-08-25 extra(設問への答え)も直せる。空文字で消す。
  //   知らない qid は受け取らない。2026-09-10 値に {text, at} を渡せる。at を渡したら legacy_confirmed の印
  //   (いつ答えたかを、印を押すときに潰さない)。2026-09-11 _unsorted は消すことだけ許す。
  "hearing.profile_patch": async (current, args) => {
    const rec = current;
    if (!rec || !rec.profile) return { record: null, result: { error: "not_found" } };
    const ALLOW = ["rep", "license", "contact", "hours", "ng", "story", "strengths", "trust",
                   "company", "area", "industry"];
    const ALLOW_ARR = ["areas_served", "works", "cases"];
    const fields = (args.fields && typeof args.fields === "object") ? args.fields : {};
    const applied = {};
    for (const k of ALLOW) {
      if (!Object.prototype.hasOwnProperty.call(fields, k)) continue;
      const to = safeStr(fields[k], 2000);
      applied[k] = { from: safeStr(rec.profile[k], 2000), to };
      rec.profile[k] = to;
    }
    for (const k of ALLOW_ARR) {
      if (!Object.prototype.hasOwnProperty.call(fields, k)) continue;
      if (!Array.isArray(fields[k])) return { record: null, result: { error: "must_be_array", field: k } };
      const to = fields[k].map((x) => safeStr(x, 120)).filter(Boolean).slice(0, 40);
      applied[k] = { from: (rec.profile[k] || []).slice(0, 40), to };
      rec.profile[k] = to;
    }
    const extraIn = (args.extra && typeof args.extra === "object" && !Array.isArray(args.extra)) ? args.extra : null;
    if (extraIn) {
      rec.profile.extra = rec.profile.extra || {};
      const known = knownQids(rec.profile);
      const bad = Object.keys(extraIn).filter((q) => !known.has(q));
      if (bad.length) return { record: null, result: { error: "unknown_qid", unknown: bad } };
      if (Object.prototype.hasOwnProperty.call(extraIn, "_unsorted")) {
        const u = extraIn._unsorted;
        const uStr = safeStr(u && typeof u === "object" ? u.text : u, 3000).trim();
        if (uStr) return { record: null, result: { error: "unsorted_is_delete_only",
          note: "_unsorted は当て先の決まっていない返事の置き場。手で書く物ではない。正しい qid に当て直してから、空文字で消すこと。" } };
      }
      const ea = {};
      for (const q of Object.keys(extraIn)) {
        const before = rec.profile.extra[q];
        const raw = extraIn[q];
        const isObj = raw && typeof raw === "object" && !Array.isArray(raw);
        const to = safeStr(isObj ? raw.text : raw, 3000).trim();
        if (!to) {
          delete rec.profile.extra[q];
          ea[q] = { from: before || null, to: null, note: "消した" };
          continue;
        }
        let at = args.now, mark = "admin";
        if (isObj && raw.at) {
          const t = Date.parse(raw.at);
          if (!Number.isFinite(t)) return { record: null, result: { error: "bad_at", qid: q, at: raw.at } };
          if (t > args.now_ms + 60000) return { record: null, result: { error: "at_in_future", qid: q, at: raw.at } };
          at = new Date(t).toISOString();
          mark = "legacy_confirmed";
        }
        rec.profile.extra[q] = { text: to, at, attributed: mark, with: [] };
        ea[q] = { from: before || null, to: rec.profile.extra[q] };
      }
      applied.extra = ea;
    }
    if (!Object.keys(applied).length) {
      return { record: null, result: { error: "no_allowed_field", allow: ALLOW, allow_array: ALLOW_ARR,
               allow_extra: "b.extra に {qid: 文字列} を渡す。空文字でその qid を消す。" } };
    }
    rec.profile.edits = [...(rec.profile.edits || []),
      { at: args.now, by: "admin", fields: Object.keys(applied) }].slice(-20);
    return { record: rec, result: { applied } };
  },
};

/* ------------------------------ DO の中で動く本体 ------------------------------ */

// storage: DO の storage。kv: HS_HEARING_KV。body: { key, op, args, now? }。
// blockConcurrencyWhile の中から呼ぶ(dispatch_do.js)。戻す物はそのまま応答の JSON になる。
export async function rmwApply(storage, kv, body, nowMs) {
  const key = typeof (body && body.key) === "string" ? body.key : "";
  if (!RMW_PREFIXES.some((p) => key.startsWith(p) && key.length > p.length)) return { rmw: true, error: "bad_key" };
  const op = OPS[body.op];
  if (!op) return { rmw: true, error: "unknown_op" };
  if (!kv || typeof kv.get !== "function") return { rmw: true, error: "no_kv" };
  const now = Number.isFinite(Number(nowMs)) ? Number(nowMs) : Date.now();

  let kvRec;
  try { kvRec = await kv.get(key, "json"); } catch (_e) { return { rmw: true, error: "kv_read_failed" }; }
  if (kvRec === undefined) kvRec = null;
  const doSeq = Number(await storage.get("seq")) || 0;
  const lastAt = Number(await storage.get("last_at")) || 0;
  const kvSeq = stampSeq(kvRec);

  // 床。KV の写しが DO の床より古く、床を書いたのが KV の反映の窓の内なら、それは古い読みや。DO の写しを「今」にする。
  // 窓を過ぎとったら、KV の写しは外から書かれた本物(前の code、手直し)として採る。
  let current = kvRec, floor = false;
  if (doSeq > 0 && kvSeq < doSeq && (now - lastAt) < STALE_WINDOW_MS) {
    const v = await storage.get("v:" + doSeq);
    if (v !== undefined) { current = v; floor = true; }
  }
  const curSeq = stampSeq(current);

  const ctx = {
    at: new Date(now).toISOString(),
    getVersion: async (seq) => (seq > 0 ? await storage.get("v:" + seq) : undefined),
  };
  let out;
  try { out = await op(current, body.args || {}, ctx); } catch (e) { return { rmw: true, error: "op_threw", why: String(e && e.message || e).slice(0, 200) }; }
  if (!out || out.record == null) return { rmw: true, written: false, result: (out && out.result) || null, floor };

  const nextSeq = Math.max(doSeq, kvSeq, curSeq) + 1;
  const record = out.record;
  record._rmw = { seq: nextSeq, at: ctx.at };
  // KV を先に書く。KV に書けんかったら DO の床も進めん(「何も書いとらん」が本当になる)。
  try { await kv.put(key, JSON.stringify(record)); } catch (_e) { return { rmw: true, error: "kv_write_failed" }; }
  // 床は KV の後。床に書けんかっても(storage の上限など)、KV には書けとるから「書いた」と答える。床だけ欠ける。
  let floorKept = true;
  try {
    await storage.put("v:" + nextSeq, record);
    await storage.put("seq", nextSeq);
    await storage.put("last_at", now);
    const old = nextSeq - KEEP_VERSIONS;
    if (old > 0) await storage.delete("v:" + old);
  } catch (_e) { floorKept = false; }
  return { rmw: true, written: true, seq: nextSeq, record, result: out.result || null, floor, floor_kept: floorKept };
}

/* ------------------------------ worker 側から呼ぶ口 ------------------------------ */

// 関所が繋がっとらん時だけ(単体試験)。同じ op を KV に直接当てる。床も版も無い(これまでの経路)。
async function rmwLocal(env, key, op, args) {
  const fn = OPS[op];
  if (!fn) throw rmwFailed(key, "unknown_op");
  let current;
  try { current = await env.HS_HEARING_KV.get(key, "json"); }
  catch (_e) {
    if (key.startsWith("store:")) throw AP.storeReadFailed(key);
    throw rmwFailed(key, "kv_read_failed");
  }
  const out = await fn(current == null ? null : current, args || {}, { at: nowIso(), getVersion: async () => undefined });
  if (!out || out.record == null) return { rmw: false, written: false, result: (out && out.result) || null };
  await env.HS_HEARING_KV.put(key, JSON.stringify(out.record));
  return { rmw: false, written: true, record: out.record, result: out.result || null };
}

export async function rmw(env, key, op, args) {
  if (!env || !env.DISPATCH_DO) return rmwLocal(env, key, op, args);
  let j;
  try {
    const stub = env.DISPATCH_DO.get(env.DISPATCH_DO.idFromName("rmw:" + key));
    const r = await stub.fetch("https://dispatch-gate/rmw", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key, op, args }),
    });
    j = await r.json();
  } catch (e) {
    throw rmwFailed(key, "do_unreachable: " + String(e && e.message || e).slice(0, 120));
  }
  // /rmw を知らん関所(偽物、古い class)の返事では書かん。KV に直接書く逃げ道は無い。
  if (!j || j.rmw !== true) throw rmwFailed(key, "bad_reply");
  if (j.error === "kv_read_failed" && key.startsWith("store:")) throw AP.storeReadFailed(key);
  if (j.error) throw rmwFailed(key, j.error + (j.why ? ": " + j.why : ""));
  return j;
}

export function updateStore(env, sid, op, args) {
  return rmw(env, "store:" + sid, op, { ...(args || {}), store_id: sid });
}

export function updateProfile(env, sid, op, args) {
  return rmw(env, "hearing:" + sid, op, { ...(args || {}), store_id: sid });
}
