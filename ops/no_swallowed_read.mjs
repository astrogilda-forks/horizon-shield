// ops/no_swallowed_read.mjs
//
// 読めなかった物を「無かった物」として扱う型 (issue #13 の型) が workers に戻っていないかを見張る。
//
// なぜ要るか (2026-10-13)。KV や R2 の読み取りが失敗したとき、try/catch や .catch が null や {} や [] を
// 返して握りつぶし、その後ろで同じ関数が書き戻す (put / delete)、という形が多数あった。一度の一時的な失敗で
// 登録簿が {} と自分の 1 行に置き換わる、日の集計がこの 1 件だけになる、支払い済みの注文が「知らない注文」と
// 答えられる。2026-10-13 にまとめて直した (readOrder, readRegistryForWrite, readStatsRow, kvFlag,
// kiraKvJsonStrict, ReadFailure ほか)。直した後は、同じ形がまた書かれないことを見張る必要がある。これがそれ。
//
//   node ops/no_swallowed_read.mjs           workers を走査する
//   node ops/no_swallowed_read.mjs --list    走査したファイルの一覧も出す
//
// 終了コード 0 = 許可リスト外の該当なし、2 = 該当あり (場所を全部名指しする)、
//            3 = 構文解析器が使えない、または配備されるファイルが解析できない (通ったことにはしない)。
//
// 方法。正規表現ではなく、本物の構文解析器で木を作って見る。リポジトリには acorn も espree も
// @babel/parser も入っていない。Node 本体が内部に acorn を同梱しているので、それを --expose-internals で
// 借りる (ネットワーク不要、追加の依存なし)。このファイルは必要なら自分を --expose-internals 付きで
// 起動し直す。木の上での判定そのものは発見的 (heuristic) で、データの流れを完全には追わない
// (同じ関数の中だけを見る。別名は const kv = env.X と const { X } = env まで。関数をまたぐのは下の a-helper だけ)。
// 走査するのは workers/*/wrangler.jsonc|json|toml の main とそこから相対 import で辿れるファイル、
// それに workers/*/src の .js/.mjs (試験ファイルは main から辿れる物だけ)。.ts は見ない。
//
// 拾う形 (信号の強い物だけ)。「読み取り」は束縛 (env.X, c.env.X, this.env.X, wrangler の KV/R2 binding 名,
// その別名) の .get( / .getWithMetadata( か、それだけを包む関数の呼び出し。「書き込み」は束縛の .put( /
// .delete( か、それを包む関数 (writeRegistry など) の呼び出し。
//
//   a-catch     try の中で読み、catch が既定値 ({} [] Map/Set DEFAULT*, "" 0 false, null undefined) を代入するか、
//               何もせずに握りつぶす。そして同じ関数の後ろの書き込みが、その値に依る (引数に使う、その値を見る
//               条件の「無い」側の枝にある、間でその値を使う)。try の中で読んだ結果を見て抜ける形
//               (try { if (await X.get(k)) return } catch {}) は、失敗が後ろへ素通りするので、後ろの書き込みを全部数える。
//   a-dotcatch  X.get(k).catch(cb) の cb が既定値を返すか何も返さない。後ろの扱いは a-catch と同じ。
//   a-helper    失敗を「無い」と同じ答えにして返す読み取り関数 (catch { return {} } の readRegistry 型、
//               catch { return false } の isAlreadySeen 型、catch { return null } でしかも無いときも null を返す
//               getProspect 型) を呼び、同じ関数の後ろで書く。
//   b-parse     JSON.parse((await X.get(k)) || "{}") の形 ("[]" と ?? も) が try の中にあり、その catch が既定値を
//               返すか代入するか、握りつぶす (書き込みが無くても数える)。
//
// 直した形として通す物 (偽陽性を避けるため)。
//   - catch が null/undefined/falsy を入れるか何もしない場合で、後ろに「無い」ときに抜ける if がある
//     (if (!reg) return 503、if (!Array.isArray(removed)) return)、または書き込みが「有る」側の枝にだけある。
//   - catch が return null する読み取り関数で、無いときは null 以外を返す物 (readStatsRow, readRegistryForWrite)。
//   - catch が既定値でない物を入れる (prevReadFailed = true) か、throw する (ReadFailure) か、503 を返す。
//   - 何も外へ流れ出ない握りつぶし (書き込みも try の中にあり、失敗したら丸ごと飛ぶ)。
//   - 読んだ所から書き込みに届かない (間のブロックが return で終わる、let/const の有効範囲の外)。
//
// 許可リスト (ALLOW) に足すときは、なぜこの形で正しいのかを reason に一行で書くこと。reason の無い
// 項目は受け付けない。

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

// ---------------------------------------------------------------- 許可リスト
// file + fn (囲む関数の名前、入れ子は a/b) + kind (a-catch, a-dotcatch, a-helper, b-parse) で一致させる。
// 同じ関数に複数あるときは line_has (該当行に含まれる文字列) で絞る。行番号では一致させない (行は動くため)。
// 1 項目は 1 件にだけ当たる。同じ関数に新しい型が増えたら、それは許可リスト外として名指しされる。
export const ALLOW = [
  // 2026-10-13 時点の main (ff591887) を走査して分類した結果。各行の reason を読むこと。
  //
  // known: true の項目は「正しい形」ではない。本当に残っている issue #13 の型で、worker の直しは別の作業。
  // CI を赤にしないために通すが、走るたびに名指しする。直したら、その項目を消すこと (消し忘れは note で出る)。
  { file: "workers/hs-internal-mcp/src/worker.js", fn: "notifyMonitorDiff", kind: "a-catch",
    reason: "alert de-duplication only: a failed read of monitor:notified resends the current down list once, and the put stores the current alert set, not a merge with what was read" },
  { file: "workers/hs-kira-line/src/worker.js", fn: "processEvents", kind: "a-catch",
    reason: "LINE redelivery mark: a failed read processes the message (at worst one duplicate reply to a redelivery) instead of dropping a live message; the put only sets the mark" },
  { file: "workers/hs-kira-line/src/worker.js", fn: "handlePartnerEstimateMedia", kind: "a-catch",
    reason: "LINE redelivery mark: a failed read processes the image (at worst one duplicate reply to a redelivery) instead of dropping it; the put only sets the mark" },
  { file: "workers/hs-kira-line/src/worker.js", fn: "handlePartnerMessage", kind: "a-catch",
    reason: "LINE redelivery mark: a failed read processes the DM (at worst one duplicate reply to a redelivery) instead of dropping it; the put only sets the mark" },
  { file: "workers/hs-kira-line/src/worker.js", fn: "handleKiraResponse", kind: "a-catch",
    reason: "market:daily_news is an optional note in the prompt; a failed read only leaves the note out, and the saved history was read strictly (getHistory returns null on failure)" },
  { file: "workers/hs-monitor/src/worker.js", fn: "scanAndNotify", kind: "a-helper", line_has: "isAlreadySeen(",
    reason: "lead de-duplication: a failed seen-read re-scores and re-notifies one post to the owner; the put only sets the seen mark, nothing accumulated is replaced" },
  { file: "workers/hs-verify-gate/src/worker.js", fn: "notifyMeasured", kind: "a-catch",
    reason: "notify rate limit: a failed read of notify:sent lets one webhook through early; the put stores only the send time, nothing accumulated is replaced" },
];

// ---------------------------------------------------------------- 構文解析器
let acorn = null;
export function loadParser() {
  if (acorn) return acorn;
  try {
    const req = createRequire(import.meta.url);
    acorn = req("internal/deps/acorn/acorn/dist/acorn");
    return acorn;
  } catch (_e) {
    return null;
  }
}

// --expose-internals が無ければ、自分を付けて起動し直す。呼んだ側はここで終わる。
export function reexecWithParser(scriptUrl) {
  if (loadParser()) return;
  if (process.execArgv.includes("--expose-internals")) {
    console.error("no_swallowed_read: Node 内部の acorn を読めない。構文解析器が無いので、通ったことにはしない。");
    process.exit(3);
  }
  const script = fileURLToPath(scriptUrl);
  const r = spawnSync(process.execPath, ["--expose-internals", ...process.execArgv, script, ...process.argv.slice(2)], { stdio: "inherit" });
  process.exit(r.status == null ? 3 : r.status);
}

export function parse(src) {
  const a = loadParser();
  if (!a) throw new Error("parser unavailable");
  const opts = { ecmaVersion: "latest", locations: true, allowHashBang: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true, allowImportExportEverywhere: true };
  try { return a.parse(src, { ...opts, sourceType: "module" }); }
  catch (e1) {
    try { return a.parse(src, { ...opts, sourceType: "script" }); }
    catch (_e2) { throw e1; }
  }
}

// ---------------------------------------------------------------- 木の歩き方
function children(node) {
  const out = [];
  for (const k of Object.keys(node)) {
    if (k === "parent" || k === "loc" || k === "start" || k === "end" || k === "type") continue;
    const v = node[k];
    if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === "string") out.push(c); }
    else if (v && typeof v.type === "string") out.push(v);
  }
  return out;
}

// parent を全部の節に付ける。
function linkParents(root) {
  const stack = [root];
  root.parent = null;
  while (stack.length) {
    const n = stack.pop();
    for (const c of children(n)) { c.parent = n; stack.push(c); }
  }
}

function walk(node, fn) {
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    fn(n);
    const cs = children(n);
    for (let i = cs.length - 1; i >= 0; i--) stack.push(cs[i]);
  }
}

// 入れ子の関数の中には入らない歩き方。
function walkOwn(node, fn) {
  const stack = children(node).reverse();
  while (stack.length) {
    const n = stack.pop();
    fn(n);
    if (isFn(n)) continue;
    const cs = children(n);
    for (let i = cs.length - 1; i >= 0; i--) stack.push(cs[i]);
  }
}

const isFn = (n) => n && (n.type === "FunctionDeclaration" || n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression");

function enclosingFn(n) {
  let p = n.parent;
  while (p && !isFn(p)) p = p.parent;
  return p; // null なら module の最上位
}

function fnName(f) {
  if (!f) return "<top>";
  if (f.id && f.id.name) return f.id.name;
  const p = f.parent;
  if (p) {
    if (p.type === "VariableDeclarator" && p.id.type === "Identifier") return p.id.name;
    if ((p.type === "Property" || p.type === "MethodDefinition" || p.type === "PropertyDefinition") && p.key) return keyName(p.key);
    if (p.type === "AssignmentExpression") return exprName(p.left);
  }
  return "<anonymous>";
}
function keyName(k) { return k.type === "Identifier" ? k.name : k.type === "Literal" ? String(k.value) : "<computed>"; }
function exprName(e) {
  if (e.type === "Identifier") return e.name;
  if (e.type === "MemberExpression") return exprName(e.object) + "." + (e.computed ? "<computed>" : keyName(e.property));
  if (e.type === "ThisExpression") return "this";
  return "<expr>";
}
function fnPath(f) {
  const parts = [];
  for (let g = f; g; g = enclosingFn(g)) parts.unshift(fnName(g));
  return parts.length ? parts.join("/") : "<top>";
}

// ---------------------------------------------------------------- 束縛かどうか
const BINDINGISH_NAME = /^(kv|r2|bucket|ns)$|(KV|Kv|_kv|Bucket|BUCKET|_R2|R2)$/;

function isEnvRef(e) {
  // env / ENV / c.env / ctx.env / this.env
  if (!e) return false;
  if (e.type === "Identifier") return e.name === "env" || e.name === "ENV";
  if (e.type === "MemberExpression" && !e.computed && e.property.type === "Identifier" && e.property.name === "env") return true;
  return false;
}

function makeIsBinding(ctx) {
  return function isBinding(obj) {
    if (!obj) return false;
    if (obj.type === "ChainExpression") return isBinding(obj.expression);
    if (obj.type === "MemberExpression" && isEnvRef(obj.object)) return true;
    if (obj.type === "Identifier") {
      if (ctx.mapLike.has(obj.name)) return false;
      if (ctx.bindings.has(obj.name) || ctx.aliases.has(obj.name)) return true;
      if (BINDINGISH_NAME.test(obj.name)) return true;
    }
    if (obj.type === "MemberExpression" && !obj.computed && obj.property.type === "Identifier" && ctx.bindings.has(obj.property.name)) return true;
    return false;
  };
}

function calleeMember(call) {
  let c = call.callee;
  if (c && c.type === "ChainExpression") c = c.expression;
  if (c && c.type === "MemberExpression" && !c.computed && c.property.type === "Identifier") return c;
  return null;
}

function isBindingGet(call, isBinding) {
  if (!call || call.type !== "CallExpression") return false;
  const m = calleeMember(call);
  return !!(m && (m.property.name === "get" || m.property.name === "getWithMetadata") && isBinding(m.object));
}
function isBindingWrite(call, isBinding) {
  if (!call || call.type !== "CallExpression") return false;
  const m = calleeMember(call);
  return !!(m && (m.property.name === "put" || m.property.name === "delete") && isBinding(m.object));
}
function isHelperCall(call, helpers) {
  if (!call || call.type !== "CallExpression") return false;
  let c = call.callee;
  if (c.type === "Identifier") return helpers.has(c.name);
  if (c.type === "MemberExpression" && c.object.type === "ThisExpression" && !c.computed && c.property.type === "Identifier") return helpers.has(c.property.name);
  return false;
}

function containsRead(node, isBinding, helpers) {
  let found = null;
  walk(node, (n) => {
    if (found) return;
    if (n.type === "CallExpression" && (isBindingGet(n, isBinding) || isHelperCall(n, helpers))) found = n;
  });
  return found;
}

// ---------------------------------------------------------------- 既定値の分類
function unwrap(e) {
  while (e && (e.type === "AwaitExpression" || e.type === "ParenthesizedExpression" || e.type === "ChainExpression")) e = e.argument || e.expression;
  return e;
}

// 既定値の種類。
//   "empty"   = {} [] new Map() new Set() DEFAULT*/EMPTY* と、値が全部 0/""/[]/{}/null の object
//   "falsy"   = "" 0 false
//   "nullish" = null undefined void 0
//   null      = 既定値ではない
export function defaultKind(e) {
  e = unwrap(e);
  if (!e) return "nullish";
  if (e.type === "Literal") {
    if (e.value === null && !e.regex) return "nullish";
    if (e.value === "" || e.value === 0 || e.value === false) return "falsy";
    return null;
  }
  if (e.type === "Identifier") {
    if (e.name === "undefined") return "nullish";
    if (/^(DEFAULT|EMPTY)/i.test(e.name)) return "empty";
    return null;
  }
  if (e.type === "UnaryExpression" && e.operator === "void") return "nullish";
  if (e.type === "ArrayExpression") return e.elements.length === 0 ? "empty" : null;
  if (e.type === "ObjectExpression") {
    if (e.properties.length === 0) return "empty";
    // false は失敗の旗 ({ ok: false }) になり得るので、object の中では数えない。
    const allEmpty = e.properties.every((p) => {
      if (p.type !== "Property") return false;
      const v = unwrap(p.value);
      if (v.type === "Literal") return v.value === 0 || v.value === "" || (v.value === null && !v.regex);
      if (v.type === "ArrayExpression") return v.elements.length === 0;
      if (v.type === "ObjectExpression") return v.properties.length === 0;
      return false;
    });
    return allEmpty ? "empty" : null;
  }
  if (e.type === "NewExpression" && e.callee.type === "Identifier" && /^(Map|Set|WeakMap)$/.test(e.callee.name) && e.arguments.length === 0) return "empty";
  return null;
}

const RANK = { empty: 3, falsy: 2, nullish: 1 };
const stronger = (a, b) => (!a ? b : !b ? a : RANK[a] >= RANK[b] ? a : b);

const isConsoleCall = (n) => {
  const e = n && n.type === "ExpressionStatement" ? n.expression : n;
  if (!e || e.type !== "CallExpression") return false;
  const c = e.callee;
  return c.type === "MemberExpression" && c.object.type === "Identifier" && c.object.name === "console";
};

// catch 節が何を残すか。{ kind, vars, viaReturn }
//   viaReturn: catch が既定値を return する (関数がそこで終わる)
//   kind: "empty" | "falsy" | "nullish" | "swallowed" | null
// 既定値でない物を代入する catch (prevReadFailed = true, d.x = { error }) と、throw する catch、
// 既定値でない物を return する catch (503 の Response など) は、失敗を扱っているので null。
function classifyHandler(body) {
  const vars = new Set();
  let assignKind = null, retKind = null, other = false;
  walkOwn(body, (n) => {
    if (n.type === "ReturnStatement") {
      const k = n.argument ? defaultKind(n.argument) : null;
      if (k) retKind = stronger(retKind, k); else other = true;
    } else if (n.type === "AssignmentExpression" && n.operator === "=") {
      const k = defaultKind(n.right);
      if (k) { assignKind = stronger(assignKind, k); if (n.left.type === "Identifier") vars.add(n.left.name); }
      else other = true;
    } else if (n.type === "ThrowStatement") other = true;
  });
  if (retKind && !other) return { kind: retKind, vars, viaReturn: true };
  if (assignKind && !other) return { kind: assignKind, vars, viaReturn: false };
  if (!retKind && !assignKind && !other) {
    const stmts = body.type === "BlockStatement" ? body.body : [];
    if (stmts.every((s) => s.type === "EmptyStatement" || isConsoleCall(s))) return { kind: "swallowed", vars, viaReturn: false };
  }
  return { kind: null, vars, viaReturn: false };
}

// .catch(cb) の cb が返す物の種類。何も返さない cb (() => {}, console.error) は undefined を返す。
function classifyCatchCallback(cb) {
  if (!cb) return null;
  if (cb.type === "MemberExpression" && cb.object.type === "Identifier" && cb.object.name === "console") return "nullish";
  if (cb.type !== "ArrowFunctionExpression" && cb.type !== "FunctionExpression") return null;
  if (cb.body.type !== "BlockStatement") return isConsoleCall(cb.body) ? "nullish" : defaultKind(cb.body);
  const h = classifyHandler(cb.body);
  if (h.kind === "swallowed") return "nullish";
  return h.viaReturn ? h.kind : null;
}

// ---------------------------------------------------------------- 流れの近似
// 変数としての参照か (obj.name の name や { name: 1 } の key は変数ではない)。
function isVarRef(n) {
  if (n.type !== "Identifier") return false;
  const p = n.parent;
  if (!p) return true;
  if (p.type === "MemberExpression" && p.property === n && !p.computed) return false;
  if ((p.type === "Property" || p.type === "MethodDefinition" || p.type === "PropertyDefinition") && p.key === n && !p.computed && !p.shorthand) return false;
  return true;
}
function refsAny(node, vars) {
  if (!node || !vars.size) return false;
  let hit = false;
  walk(node, (n) => { if (!hit && n.type === "Identifier" && vars.has(n.name) && isVarRef(n)) hit = true; });
  return hit;
}
function exits(stmt) {
  let hit = false;
  walkOwn({ type: "Wrap", body: stmt }, (n) => { if (n.type === "ReturnStatement" || n.type === "ThrowStatement" || n.type === "ContinueStatement" || n.type === "BreakStatement") hit = true; });
  return hit;
}

// 条件 test が成り立つのは vars が「無い」(falsy) ときか、「有る」(truthy) ときか。vars を見ていなければ null。
function polarity(test, vars) {
  const t = unwrap(test);
  if (!t || !refsAny(t, vars)) return null;
  if (t.type === "UnaryExpression" && t.operator === "!") { const p = polarity(t.argument, vars); return p === "falsy" ? "truthy" : p === "truthy" ? "falsy" : null; }
  if (t.type === "BinaryExpression" && /^[!=]==?$/.test(t.operator)) {
    const lit = [t.left, t.right].map(unwrap).find((x) => (x.type === "Literal" && (x.value === null || x.value === false || x.value === 0 || x.value === "")) || (x.type === "Identifier" && x.name === "undefined"));
    if (lit) return t.operator.startsWith("=") ? "falsy" : "truthy";
    return "truthy";
  }
  if (t.type === "LogicalExpression") {
    const ps = [polarity(t.left, vars), polarity(t.right, vars)].filter(Boolean);
    return ps.includes("falsy") ? "falsy" : "truthy";
  }
  return "truthy";
}

// 書き込み w が、vars を見る条件のどちらの枝の下にあるか。"falsy" が一つでもあれば "falsy"。
function conditionPolarity(w, vars, stopAt) {
  let seenTruthy = false;
  for (let p = w.parent, c = w; p && p !== stopAt; c = p, p = p.parent) {
    let pol = null;
    if ((p.type === "IfStatement" || p.type === "ConditionalExpression") && c !== p.test) {
      pol = polarity(p.test, vars);
      if (pol && c === p.alternate) pol = pol === "falsy" ? "truthy" : "falsy";
    } else if (p.type === "LogicalExpression" && c === p.right) {
      pol = polarity(p.left, vars);
      if (pol && p.operator !== "&&") pol = pol === "falsy" ? "truthy" : "falsy";
    }
    if (pol === "falsy") return "falsy";
    if (pol === "truthy") seenTruthy = true;
  }
  return seenTruthy ? "truthy" : null;
}

// site の後ろ、limit より前に、vars が「無い」ときに抜ける if があるか (if (!reg) return 503 の形)。
function hasProtectiveGuard(scope, vars, after, limit) {
  let hit = false;
  walkOwn(scope, (n) => {
    if (hit) return;
    if (n.type === "IfStatement" && n.start >= after && n.start < limit && polarity(n.test, vars) === "falsy" && exits(n.consequent)) hit = true;
  });
  return hit;
}

function refsBetween(scope, vars, after, limit) {
  let hit = false;
  walk(scope, (n) => { if (!hit && n.type === "Identifier" && n.start > after && n.start < limit && vars.has(n.name) && isVarRef(n)) hit = true; });
  return hit;
}

// site から scope までの間に、最後が return/throw/continue で終わるブロックがあり、w がその外にあれば、
// site を通った道は w に届かない (大きな fetch の中の別の route など)。
function unreachableFrom(site, w, scope) {
  for (let p = site.parent; p && p !== scope; p = p.parent) {
    if (p.type !== "BlockStatement" && p.type !== "SwitchCase") continue;
    const body = p.type === "BlockStatement" ? p.body : p.consequent;
    const last = body[body.length - 1];
    if (last && /^(Return|Throw|Continue)Statement$/.test(last.type) && !(w.start >= p.start && w.end <= p.end)) return true;
  }
  return false;
}

// vars の宣言時の初期値の種類 (同じ関数の中)。無ければ "nullish"。
function initKind(scope, vars) {
  let k = null;
  walkOwn(scope, (n) => {
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && vars.has(n.id.name) && n.init) k = stronger(k, defaultKind(n.init));
  });
  return k || "nullish";
}

// try ブロックの中で代入され、try の外で宣言された名前 = try の外へ値が流れ出る変数。
// try の中で宣言された名前は、try の後ろからは見えないので数えない。
function assignedIn(node) {
  const assigned = new Set(), declared = new Set();
  walkOwn(node, (n) => {
    if (n.type === "AssignmentExpression" && n.left.type === "Identifier") assigned.add(n.left.name);
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier") declared.add(n.id.name);
  });
  for (const d of declared) assigned.delete(d);
  return assigned;
}

// let/const で宣言された名前 -> 宣言したブロック。var、引数、見つからない名前は入れない (どこへでも届くとみなす)。
function declBlocks(scope, vars) {
  const m = new Map();
  walkOwn({ type: "Wrap", body: scope }, (n) => {
    if (n.type !== "VariableDeclaration" || n.kind === "var") return;
    for (const d of n.declarations) {
      if (d.id.type === "Identifier" && vars.has(d.id.name) && n.parent) {
        const blk = n.parent.type === "ForStatement" || n.parent.type === "ForOfStatement" || n.parent.type === "ForInStatement" ? n.parent : n.parent;
        if (!m.has(d.id.name)) m.set(d.id.name, blk);
      }
    }
  });
  return m;
}

// vars から作られた名前を足す (const untouched = s0 && ..., const record = { already ? ... })。
function expandDerived(scope, vars, after) {
  const out = new Set(vars);
  for (let round = 0; round < 6; round++) {
    const before = out.size;
    walkOwn(scope, (n) => {
      if (n.start < after) return;
      if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init && refsAny(n.init, out)) out.add(n.id.name);
      if (n.type === "AssignmentExpression" && n.left.type === "Identifier" && refsAny(n.right, out)) out.add(n.left.name);
    });
    if (out.size === before) break;
  }
  return out;
}

// ---------------------------------------------------------------- 1 ファイルの解析
export function collectFileFacts(ast) {
  // 別名 (const kv = env.X; const { X } = env) と、Map/Set などで作った名前。
  const aliases = new Set(), mapLike = new Set();
  walk(ast, (n) => {
    if (n.type !== "VariableDeclarator" || !n.init) return;
    const init = unwrap(n.init);
    if (n.id.type === "Identifier") {
      if (init.type === "MemberExpression" && isEnvRef(init.object)) aliases.add(n.id.name);
      if (init.type === "LogicalExpression" && unwrap(init.left).type === "MemberExpression" && isEnvRef(unwrap(init.left).object)) aliases.add(n.id.name);
      if (init.type === "NewExpression" && init.callee.type === "Identifier" && /^(Map|Set|WeakMap|URLSearchParams|Headers|FormData)$/.test(init.callee.name)) mapLike.add(n.id.name);
    } else if (n.id.type === "ObjectPattern" && isEnvRef(init)) {
      for (const p of n.id.properties) if (p.type === "Property" && p.value.type === "Identifier") aliases.add(p.value.name);
    }
  });
  return { aliases, mapLike };
}

function namedFns(ast, fn) {
  walk(ast, (n) => {
    if (!isFn(n)) return;
    const name = fnName(n);
    if (name && !name.startsWith("<")) fn(n, name);
  });
}

// 束縛を .get するが .put/.delete しない、名前のある関数 = 読み取りを包む関数。
export function collectHelpers(ast, isBinding) {
  const out = new Set();
  namedFns(ast, (n, name) => {
    let get = false, write = false;
    walk(n.body, (m) => {
      if (m.type !== "CallExpression") return;
      if (isBindingGet(m, isBinding)) get = true;
      if (isBindingWrite(m, isBinding)) write = true;
    });
    if (get && !write) out.add(name);
  });
  return out;
}

// 束縛を .put / .delete する、名前のある関数 = 書き込みを包む関数 (writeRegistry, putOrder など)。
export function collectWriters(ast, isBinding) {
  const out = new Set();
  namedFns(ast, (n, name) => {
    let write = false;
    walk(n.body, (m) => { if (!write && m.type === "CallExpression" && isBindingWrite(m, isBinding)) write = true; });
    if (write) out.add(name);
  });
  return out;
}

// 失敗を「無い」と同じ答えに変えて return する読み取り関数。名前 -> 既定値の種類。
//   "empty" / "falsy": catch { return {} } (readRegistry 型)、catch { return false } (isAlreadySeen 型)
//   "nullish": catch { return null } で、しかも同じ関数が「無い」ときにも null を返す
//              (return val ? JSON.parse(val) : null、return await X.get(k)、if (!raw) return null)。
//              null を失敗だけの印にしている直した形 (readStatsRow, readRegistryForWrite) は数えない。
// 呼ぶ側には失敗と「無い」の区別が届かないので、呼ぶ側が後ろで書くと issue #13 の型になる。
function mayBeNullish(e, isBinding) {
  e = unwrap(e);
  if (!e) return true;
  if (defaultKind(e) === "nullish") return true;
  if (e.type === "CallExpression" && isBindingGet(e, isBinding)) return true;   // KV は無いとき null を返す
  if (e.type === "ConditionalExpression") return mayBeNullish(e.consequent, isBinding) || mayBeNullish(e.alternate, isBinding);
  if (e.type === "LogicalExpression") return e.operator === "&&" ? true : mayBeNullish(e.right, isBinding);
  return false;
}
export function collectLossy(ast, isBinding) {
  const out = new Map();
  const readsIn = (node) => { let r = false; walk(node, (x) => { if (!r && x.type === "CallExpression" && isBindingGet(x, isBinding)) r = true; }); return r; };
  namedFns(ast, (n, name) => {
    let kind = null;
    const nullCatches = new Set();
    walkOwn(n.body, (m) => {
      if (m.type === "TryStatement" && m.handler && readsIn(m.block)) {
        const h = classifyHandler(m.handler.body);
        if (h.viaReturn && (h.kind === "empty" || h.kind === "falsy")) kind = stronger(kind, h.kind);
        if (h.viaReturn && h.kind === "nullish") walkOwn(m.handler.body, (r) => { if (r.type === "ReturnStatement") nullCatches.add(r); });
      }
      if (m.type === "ReturnStatement" && m.argument) {
        const c = unwrap(m.argument);
        const cm = c && c.type === "CallExpression" ? calleeMember(c) : null;
        if (cm && cm.property.name === "catch" && c.arguments.length && readsIn(cm.object)) {
          const k = classifyCatchCallback(c.arguments[0]);
          if (k) kind = stronger(kind, k);   // .catch(() => null) on a get is ambiguous by itself: get answers null when absent
        }
      }
    });
    if (!kind && nullCatches.size) {
      // 他の return が「無い」ときに null になり得るか。
      let ambiguous = false;
      if (n.body.type !== "BlockStatement") ambiguous = mayBeNullish(n.body, isBinding);
      walkOwn(n.body, (r) => {
        if (ambiguous || r.type !== "ReturnStatement" || nullCatches.has(r)) return;
        if (mayBeNullish(r.argument, isBinding)) ambiguous = true;
      });
      if (ambiguous) kind = "nullish";
    }
    if (kind) out.set(name, kind);
  });
  return out;
}

const line = (n) => n.loc.start.line;
const kindWords = (k) => (k === "swallowed" ? "the value unset (swallowed)" : k === "empty" ? "an empty default" : k === "falsy" ? "a falsy default" : "a null/undefined default");

export function analyzeAst(ast, ctx) {
  const isBinding = makeIsBinding(ctx);
  const helpers = ctx.helpers || new Set();
  const lossy = ctx.lossy || new Map();
  const writers = ctx.writers || new Set();
  const hits = [];
  const seen = new Set();
  const push = (h) => { const k = h.kind + ":" + h.line; if (!seen.has(k)) { seen.add(k); hits.push(h); } };
  // 呼び出しの値を受け取る変数 (const x = await f() / x = await f())。無ければ空。
  const receivingVars = (call, scope) => {
    const vars = new Set();
    for (let p = call.parent; p && p !== scope; p = p.parent) {
      if (p.type === "VariableDeclarator" && p.id.type === "Identifier") { vars.add(p.id.name); break; }
      if (p.type === "AssignmentExpression" && p.left.type === "Identifier") { vars.add(p.left.name); break; }
      if (p.type.endsWith("Statement") || isFn(p)) break;
    }
    return vars;
  };
  const calleeName = (n) => (n.callee.type === "Identifier" ? n.callee.name : n.callee.property.name);

  // その関数の中で、pos より後ろの書き込み (束縛の put/delete と、書き込みを包む関数の呼び出し)。
  const laterWrites = (scope, pos) => {
    const ws = [];
    const self = scope && scope.parent && isFn(scope.parent) ? fnName(scope.parent) : null;
    walk(scope, (n) => {
      if (n.type !== "CallExpression" || n.start <= pos) return;
      if (isBindingWrite(n, isBinding)) ws.push(n);
      else if (isHelperCall(n, writers) && calleeName(n) !== self) ws.push(n);
    });
    return ws;
  };

  // site (try 文か .catch 呼び出し) で既定値になった vars が、後ろの書き込みに効くか。
  //   earlyExit: try の中で読んだ結果を見て抜ける (if (seen) return) 形。失敗すると重複検出や回数制限が開く。
  const firstBadWrite = (site, scope, vars0, kind, earlyExit) => {
    const vars = expandDerived(scope, vars0, site.start);
    const stopAt = scope.parent || null;
    const decl = declBlocks(scope, vars);
    for (const w of laterWrites(scope, site.end)) {
      if (unreachableFrom(site, w, scope)) continue;
      if (earlyExit) return w;
      // let/const で宣言された名前は、宣言したブロックの外の書き込みには届かない。
      if (vars.size && [...vars].every((v) => decl.has(v) && !(w.start >= decl.get(v).start && w.end <= decl.get(v).end))) continue;
      const argsRef = w.arguments.some((a) => refsAny(a, vars));
      const cond = conditionPolarity(w, vars, stopAt);
      if (kind === "empty") {
        if (argsRef || cond || refsBetween(scope, vars, site.end, w.start)) return w;
        continue;
      }
      if (cond === "falsy") return w;
      if (cond === "truthy") continue;
      if (hasProtectiveGuard(scope, vars, site.end, w.start)) continue;
      if (argsRef || refsBetween(scope, vars, site.end, w.start)) return w;
    }
    return null;
  };

  walk(ast, (n) => {
    // ---------------- (a) try { ...get... } catch { 既定値 }、後ろで書く
    if (n.type === "TryStatement" && n.handler) {
      const read = containsRead(n.block, isBinding, helpers);
      if (read) {
        const fn = enclosingFn(n);
        const scope = fn ? fn.body : ast;
        const h = classifyHandler(n.handler.body);
        // catch が return する物は、この関数の後ろの書き込みには届かない。空を返す読み取り関数は
        // collectLossy が拾い、呼ぶ側を a-helper として見る。
        if (h.kind && !h.viaReturn) {
          const out = assignedIn(n.block);
          let kind = h.kind, earlyExit = false, ok = true;
          if (kind === "swallowed") {
            if (out.size) kind = initKind(scope, out);
            else if (exits(n.block)) earlyExit = true;
            else ok = false; // 何も流れ出ない握りつぶしは、失敗したら try の仕事を飛ばすだけ
          }
          if (ok) {
            const bad = firstBadWrite(n, scope, new Set([...out, ...h.vars]), kind, earlyExit);
            if (bad) {
              push({ kind: "a-catch", line: line(read), fn: fnPath(fn), catchLine: line(n.handler), writeLine: line(bad),
                why: earlyExit
                  ? `read inside try (line ${line(read)}) decides an early exit, the catch (line ${line(n.handler)}) swallows a failure, so a failed read carries on to the write at line ${line(bad)}`
                  : `read inside try (line ${line(read)}), catch leaves ${kindWords(h.kind === "swallowed" ? (kind === "nullish" ? "swallowed" : kind) : kind)} (line ${line(n.handler)}), then a write at line ${line(bad)} that depends on it` });
            }
          }
        }
      }
    }

    if (n.type !== "CallExpression") return;

    // ---------------- (a) 失敗を「無い」と同じ答えにして返す読み取り関数を呼び、後ろで書く
    if (isHelperCall(n, lossy)) {
      const fn = enclosingFn(n);
      const callee = calleeName(n);
      if (fnName(fn) !== callee) {
        const scope = fn ? fn.body : ast;
        const kind = lossy.get(callee);
        const vars = receivingVars(n, scope);
        const bad = firstBadWrite(n, scope, vars, kind, vars.size === 0);
        if (bad) {
          push({ kind: "a-helper", line: line(n), fn: fnPath(fn), catchLine: null, writeLine: line(bad),
            why: `${callee}() answers a failed read the same way as "absent" (${kindWords(kind)}) (line ${line(n)}), then a write at line ${line(bad)} that depends on it` });
        }
      }
    }

    // ---------------- (a) X.get(k).catch(cb)、後ろで書く
    const m = calleeMember(n);
    if (m && m.property.name === "catch" && n.arguments.length >= 1) {
      const read = containsRead(m.object, isBinding, helpers);
      const kind = read ? classifyCatchCallback(n.arguments[0]) : null;
      if (kind) {
        const fn = enclosingFn(n);
        const scope = fn ? fn.body : ast;
        const vars = receivingVars(n, scope);
        // 受け取る変数が無い (if (await X.get(k).catch(() => null)) return の形) なら、後ろの書き込みは全部効く。
        const bad = firstBadWrite(n, scope, vars, kind, vars.size === 0);
        if (bad) {
          push({ kind: "a-dotcatch", line: line(read), fn: fnPath(fn), catchLine: line(n), writeLine: line(bad),
            why: `read at line ${line(read)} with .catch yielding ${kindWords(kind)}, then a write at line ${line(bad)} that depends on it` });
        }
      }
    }

    // ---------------- (b) JSON.parse((await X.get(k)) || "{}") を try に入れ、catch が既定値
    const c = n.callee;
    if (c.type === "MemberExpression" && !c.computed && c.object.type === "Identifier" && c.object.name === "JSON" && c.property.name === "parse" && n.arguments.length) {
      const arg = unwrap(n.arguments[0]);
      if (!arg || arg.type !== "LogicalExpression" || (arg.operator !== "||" && arg.operator !== "??")) return;
      const r = unwrap(arg.right);
      if (!r || r.type !== "Literal" || (r.value !== "{}" && r.value !== "[]")) return;
      const read = containsRead(arg.left, isBinding, helpers);
      if (!read) return;
      let t = null;
      for (let p = n.parent, ch = n; p && !isFn(p); ch = p, p = p.parent) {
        if (p.type === "TryStatement" && ch === p.block && p.handler) { t = p; break; }
      }
      if (!t) return;
      const fn = enclosingFn(n);
      const scope = fn ? fn.body : ast;
      const h = classifyHandler(t.handler.body);
      let kind = h.kind;
      if (!kind) return;
      const out = assignedIn(t.block);
      if (kind === "swallowed") kind = out.size ? initKind(scope, out) : null;
      let flag = false;
      if (kind === "empty" || kind === "falsy") flag = true;
      else if (kind === "nullish") flag = !h.viaReturn && !hasProtectiveGuard(scope, expandDerived(scope, new Set([...out, ...h.vars]), t.start), t.end, Infinity);
      if (flag) {
        push({ kind: "b-parse", line: line(read), fn: fnPath(fn), catchLine: line(t.handler), writeLine: null,
          why: `JSON.parse(read || "${r.value}") inside try, catch ${h.viaReturn ? "returns" : "leaves"} ${kindWords(kind)} (line ${line(t.handler)}): a failed read reads as "${r.value}"` });
      }
    }
  });
  return hits.sort((x, y) => x.line - y.line);
}

// テスト用: ソース文字列を 1 本解析する。
export function analyzeSource(src, opts = {}) {
  const ast = parse(src);
  linkParents(ast);
  const facts = collectFileFacts(ast);
  const ctx = { bindings: new Set(opts.bindings || []), aliases: facts.aliases, mapLike: facts.mapLike };
  const isB = makeIsBinding(ctx);
  ctx.helpers = collectHelpers(ast, isB);
  ctx.lossy = collectLossy(ast, isB);
  ctx.writers = collectWriters(ast, isB);
  return analyzeAst(ast, ctx);
}

// ---------------------------------------------------------------- 走査する範囲
function stripJsonc(s) {
  let out = "", i = 0, inStr = false;
  while (i < s.length) {
    const ch = s[i];
    if (inStr) { out += ch; if (ch === "\\") { out += s[i + 1] || ""; i += 2; continue; } if (ch === '"') inStr = false; i++; continue; }
    if (ch === '"') { inStr = true; out += ch; i++; continue; }
    if (ch === "/" && s[i + 1] === "/") { while (i < s.length && s[i] !== "\n") i++; continue; }
    if (ch === "/" && s[i + 1] === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i += 2; continue; }
    out += ch; i++;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function readWrangler(dir) {
  const res = { main: null, bindings: new Set() };
  for (const name of ["wrangler.jsonc", "wrangler.json"]) {
    const p = path.join(dir, name);
    if (!existsSync(p)) continue;
    try {
      const j = JSON.parse(stripJsonc(readFileSync(p, "utf8")));
      const envs = [j, ...Object.values(j.env || {})];
      for (const e of envs) {
        if (!res.main && e.main) res.main = e.main;
        for (const b of [...(e.kv_namespaces || []), ...(e.r2_buckets || [])]) if (b && b.binding) res.bindings.add(b.binding);
      }
    } catch (_e) { /* 読めない設定は main 無しとして src を走査する */ }
    return res;
  }
  const t = path.join(dir, "wrangler.toml");
  if (existsSync(t)) {
    const s = readFileSync(t, "utf8");
    const m = s.match(/^\s*main\s*=\s*"([^"]+)"/m);
    if (m) res.main = m[1];
    let section = "";
    for (const ln of s.split("\n")) {
      const h = ln.match(/^\s*\[\[?\s*([^\]]+?)\s*\]\]?/);
      if (h) { section = h[1]; continue; }
      const b = ln.match(/^\s*binding\s*=\s*"([^"]+)"/);
      if (b && /kv_namespaces|r2_buckets/.test(section)) res.bindings.add(b[1]);
    }
  }
  return res;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "_to_delete", ".wrangler", "dist"]);
const isTestFile = (rel) => /(^|\/)(test|tests|__tests__)\//.test(rel) || /[._-](test|spec)\.m?js$/.test(rel);

// git 管理下のファイルだけを見る。手元の作業場所に残った未追跡の .js(古い写し、実験)を数えると、
// CI と手元で結果が食い違う(2026-10-13: Mac で 52 本の未追跡ファイルが「新しい該当 5 件」を出した)。
// git が無い場所(展開した tar など)では、ディレクトリを歩く。
let TRACKED = null; // Map<root, Set<absolute path>> or null when not a git checkout
function trackedSet(root) {
  if (TRACKED && TRACKED.root === root) return TRACKED.set;
  let set = null;
  try {
    const r = spawnSync("git", ["-C", root, "ls-files", "-z", "--cached", "--", "workers"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (r.status === 0) set = new Set(r.stdout.split("\0").filter(Boolean).map((f) => path.join(root, f)));
  } catch { set = null; }
  TRACKED = { root, set };
  return set;
}

function listJs(dir, out = [], tracked = null) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) listJs(p, out, tracked);
    else if (/\.(js|mjs)$/.test(name) && (!tracked || tracked.has(p))) out.push(p);
  }
  return out;
}

function resolveImport(fromFile, spec) {
  if (!spec.startsWith("./") && !spec.startsWith("../")) return null;
  const base = path.resolve(path.dirname(fromFile), spec);
  for (const cand of [base, base + ".js", base + ".mjs", path.join(base, "index.js")]) {
    if (existsSync(cand) && statSync(cand).isFile() && /\.(js|mjs)$/.test(cand)) return cand;
  }
  return null;
}

function importsOf(ast) {
  const out = [];
  walk(ast, (n) => {
    if ((n.type === "ImportDeclaration" || n.type === "ExportNamedDeclaration" || n.type === "ExportAllDeclaration") && n.source && typeof n.source.value === "string") out.push(n.source.value);
    if (n.type === "ImportExpression" && n.source.type === "Literal" && typeof n.source.value === "string") out.push(n.source.value);
  });
  return out;
}

export function scanRepo(root = ROOT) {
  const workersDir = path.join(root, "workers");
  const files = [], unparsed = [];
  const hits = [];
  const tracked = trackedSet(root);
  for (const w of readdirSync(workersDir).sort()) {
    const dir = path.join(workersDir, w);
    if (!statSync(dir).isDirectory() || SKIP_DIRS.has(w)) continue;
    const cfg = readWrangler(dir);
    const set = new Map(); // file -> ast
    const queue = [];
    const parseFile = (f) => {
      if (set.has(f)) return set.get(f);
      let ast = null;
      try { ast = parse(readFileSync(f, "utf8")); linkParents(ast); } catch (e) { unparsed.push({ rel: path.relative(root, f), err: String(e.message || e).slice(0, 80) }); }
      set.set(f, ast);
      return ast;
    };
    if (cfg.main) { const m = path.join(dir, cfg.main); if (existsSync(m) && (!tracked || tracked.has(m))) queue.push(m); }
    while (queue.length) {
      const f = queue.shift();
      if (set.has(f)) continue;
      const ast = parseFile(f);
      if (!ast) continue;
      for (const spec of importsOf(ast)) { const r = resolveImport(f, spec); if (r && !set.has(r) && (!tracked || tracked.has(r))) queue.push(r); }
    }
    for (const f of listJs(path.join(dir, "src"), [], tracked)) {
      const rel = path.relative(root, f);
      if (!set.has(f) && isTestFile(rel)) continue;
      parseFile(f);
    }
    // 読み取りを包む関数は worker の中で共有する (別ファイルから import して使うため)。
    const perFile = [];
    const helpers = new Set(), lossy = new Map(), writers = new Set();
    for (const [f, ast] of set) {
      if (!ast) continue;
      const facts = collectFileFacts(ast);
      const ctx = { bindings: cfg.bindings, aliases: facts.aliases, mapLike: facts.mapLike };
      for (const h of collectHelpers(ast, makeIsBinding(ctx))) helpers.add(h);
      for (const [h, k] of collectLossy(ast, makeIsBinding(ctx))) lossy.set(h, stronger(lossy.get(h), k));
      for (const h of collectWriters(ast, makeIsBinding(ctx))) writers.add(h);
      perFile.push([f, ast, ctx]);
    }
    for (const [f, ast, ctx] of perFile) {
      ctx.helpers = helpers;
      ctx.lossy = lossy;
      ctx.writers = writers;
      files.push(path.relative(root, f));
      const srcLines = readFileSync(f, "utf8").split("\n");
      for (const h of analyzeAst(ast, ctx)) hits.push({ rel: path.relative(root, f), src: srcLines[h.line - 1] || "", ...h });
    }
  }
  return { files, unparsed, hits };
}

export function applyAllow(hits, allow = ALLOW) {
  const bad = allow.filter((a) => !a.reason || String(a.reason).trim().length < 10 || !a.file || !a.fn || !a.kind);
  const used = new Set();
  const remaining = [], allowed = [];
  for (const h of hits) {
    const i = allow.findIndex((a, j) => !used.has(j) && a.file === h.rel && a.fn === h.fn && a.kind === h.kind && (!a.line_has || (h.src || "").includes(a.line_has)) && a.reason && String(a.reason).trim().length >= 10);
    if (i >= 0) { used.add(i); allowed.push({ ...h, reason: allow[i].reason, known: !!allow[i].known }); }
    else remaining.push(h);
  }
  const stale = allow.filter((_a, i) => !used.has(i));
  return { remaining, allowed, stale, bad };
}

// ---------------------------------------------------------------- 本体
function main() {
  reexecWithParser(import.meta.url);
  const { files, unparsed, hits } = scanRepo();
  const { remaining, allowed, stale, bad } = applyAllow(hits);
  if (process.argv.includes("--list")) for (const f of files) console.log("  scanned " + f);
  console.log(`no_swallowed_read: ${files.length} files scanned, ${hits.length} hits, ${allowed.length - allowed.filter((a) => a.known).length} allowlisted as correct, ${allowed.filter((a) => a.known).length} known and not fixed, ${remaining.length} new`);
  if (bad.length) {
    console.log("=== 理由 (reason) の無い許可リスト項目 ===");
    for (const a of bad) console.log("  " + JSON.stringify(a));
  }
  const known = allowed.filter((a) => a.known);
  if (known.length) {
    console.log("=== 既知で未修正の issue #13 の型 " + known.length + " 件 (ALLOW の known: true。直したら項目を消す) ===");
    for (const h of known) console.log(`  ${h.rel}:${h.line}  [${h.kind}] ${h.fn}\n      ${h.why}`);
  }
  for (const s of stale) console.log("  note: allowlist entry no longer matches (remove it): " + s.file + " " + s.fn + " " + s.kind);
  if (unparsed.length) {
    console.log("=== 解析できなかった配備ファイル (見ていない物を通ったことにはしない) ===");
    for (const u of unparsed) console.log("  " + u.rel + "  " + u.err);
  }
  if (remaining.length) {
    console.log("=== " + remaining.length + " 件 (issue #13 の型) ===");
    for (const h of remaining) console.log(`  ${h.rel}:${h.line}  [${h.kind}] ${h.fn}\n      ${h.why}`);
    console.log("");
    console.log("直し方: 読めなかったことと、無かったことを分ける。読み取りは失敗を null や ReadFailure で返し");
    console.log("        (readStatsRow, readRegistryForWrite, readOrder を参照)、書き戻す道は失敗なら何も書かずに");
    console.log("        503 か skip にする。正しい形なのに引っかかったら、ALLOW に reason を書いて足す。");
  }
  if (remaining.length || bad.length) process.exit(2);
  if (unparsed.length) process.exit(3);
  console.log("=== 許可リスト外の該当なし ===");
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
