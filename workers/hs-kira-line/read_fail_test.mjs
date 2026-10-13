/* hs-kira-line: a read that FAILED is not a read that found nothing (issue #13, 2026-10-13). Offline, no network.

   Three outcomes for every read: ok / absent / failed. A failed read is never written back, and never told to a
   person as "none / not found". Each check below runs the real worker with KV and fetch mocked; the failure form
   is checked on a failing read, and the absent or normal form is checked to be unchanged.

   node workers/hs-kira-line/read_fail_test.mjs
*/
import crypto from "node:crypto";
import W from "./src/worker.js";

let fail = 0, checks = 0;
function check(label, cond, detail) {
  checks++;
  console.log((cond ? "  ok   " : "  NG   ") + label + (detail ? "  " + detail : ""));
  if (!cond) fail++;
}

const SECRET = "test-channel-secret";
const OWNER = "U" + "c".repeat(32);
const GID = "C" + "a".repeat(32);
const UID = "U" + "b".repeat(32);
const CONSUMER = "U" + "e".repeat(32);

// KV mock. failGet / failList are predicates on the key or prefix; a match throws like a KV outage.
function makeEnv(opts) {
  const o = opts || {};
  const kv = new Map();
  const puts = [];
  return {
    LINE_CHANNEL_SECRET: SECRET, LINE_CHANNEL_TOKEN: "tok", LINE_USER_ID: OWNER, KIRA_BRIDGE_KEY: "bk", ANTHROPIC_API_KEY: "test-not-a-key",
    _kv: kv, _puts: puts,
    SEEN_STORE: {
      get: async (k) => { if (o.failGet && o.failGet(k)) throw new Error("KV get failed (test)"); return kv.has(k) ? kv.get(k) : null; },
      put: async (k, v) => { puts.push(k); kv.set(k, v); },
      delete: async (k) => { kv.delete(k); },
      list: async (q) => {
        const p = (q && q.prefix) || "";
        if (o.failList && o.failList(p)) throw new Error("KV list failed (test)");
        return { keys: [...kv.keys()].filter((k) => k.startsWith(p)).map((name) => ({ name })) };
      },
    },
  };
}
// 2026-10-13 K1: the global book is the old list (minus tombstones) plus kira_lesson:* keys; read it the way the worker does.
async function globalLessons(env) {
  const sha32 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 32);
  const blob = JSON.parse((await env.SEEN_STORE.get("kira_lessons:global")) || "[]");
  const keys = (await env.SEEN_STORE.list({ prefix: "kira_lesson" })).keys.map((k) => k.name);
  const dels = new Set(keys.filter((k) => k.startsWith("kira_lesson_del:")).map((k) => k.slice("kira_lesson_del:".length)));
  const out = blob.filter((l) => !dels.has(sha32(l.t)));
  for (const k of keys.filter((k) => k.startsWith("kira_lesson:")).sort()) out.push(JSON.parse(await env.SEEN_STORE.get(k)));
  return out;
}
function sign(body) { return crypto.createHmac("sha256", SECRET).update(body).digest("base64"); }
async function send(env, events) {
  const body = JSON.stringify({ events });
  const waits = [];
  const res = await W.fetch(new Request("https://x/webhook", { method: "POST", headers: { "content-type": "application/json", "x-line-signature": sign(body) }, body }), env, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  return res;
}
const runCron = async (env) => { const w = []; await W.scheduled({}, env, { waitUntil: (p) => w.push(p) }); await Promise.all(w); };

let calls = [];
let llmOut = null;
let gyosha = { status: 200, body: { result: "⚠️ リスクレベル：低\n\n📋 調査結果：\n・建設業許可あり" } };
globalThis.fetch = async (url, init) => {
  const u = String(url);
  let body = null; try { body = JSON.parse((init && init.body) || "null"); } catch (_e) { body = null; }
  calls.push({ url: u, body });
  if (u.includes("/kira-bridge")) return new Response(JSON.stringify({ ok: true, reply: "ご回答ありがとうございます。掲載に反映します。" }), { status: 200 });
  if (u.includes("hs-gyosha-check")) { if (gyosha.throws) throw new Error("network down (test)"); return new Response(JSON.stringify(gyosha.body), { status: gyosha.status }); }
  if (u.includes("api.anthropic.com") && llmOut !== null) return new Response(JSON.stringify({ content: [{ type: "text", text: llmOut }] }), { status: 200 });
  return new Response("{}", { status: 200 });
};
const replies = () => calls.filter((c) => c.url.includes("/v2/bot/message/reply"));
const replyText = () => { const r = replies()[0]; return (r && r.body && r.body.messages[0].text) || ""; };
const pushes = () => calls.filter((c) => c.url.includes("/v2/bot/message/push"));
const pushTo = (to) => pushes().filter((c) => c.body && c.body.to === to);
const llms = () => calls.filter((c) => c.url.includes("api.anthropic.com"));
const bridges = () => calls.filter((c) => c.url.includes("/kira-bridge"));
const ownerMsg = (text) => ({ type: "message", replyToken: "rt_o", source: { type: "user", userId: OWNER }, message: { type: "text", id: "o" + Math.random().toString(36).slice(2), text } });
const groupMsg = (text, mention) => ({
  type: "message", replyToken: "rt_group", source: { type: "group", groupId: GID, userId: UID },
  message: Object.assign({ type: "text", id: "g" + Math.random().toString(36).slice(2), text }, mention ? { mention: { mentionees: [{ index: 0, length: 15, type: "user", isSelf: true }] } } : {}),
});
const ago = (min) => new Date(Date.now() - min * 60000).toISOString();
const NOT_FOUND = "見つかりませんでした";
const READ_FAIL = "今は読み込めませんでした";

console.log("\n1) グループへ: the group list cannot be read");
{
  const env = makeEnv({ failList: (p) => p === "groupPartner:" });
  calls = [];
  await send(env, [ownerMsg("グループへ 本日はありがとうございました。")]);
  check("failure: owner told it could not be read", replyText().includes(READ_FAIL) && replyText().includes("何も送っていません"), replyText());
  check("failure: never says not found", !replyText().includes(NOT_FOUND));
  check("failure: nothing pushed", pushes().length === 0);
  const env2 = makeEnv();
  calls = [];
  await send(env2, [ownerMsg("グループへ 本日はありがとうございました。")]);
  check("absent: unchanged not-found text", replyText() === "送り先の加盟店グループが見つかりませんでした。何も送っていません。", replyText());
}

console.log("\n2) グループ一覧: the group list cannot be read");
{
  calls = [];
  await send(makeEnv({ failList: (p) => p === "groupPartner:" }), [ownerMsg("グループ一覧")]);
  check("failure: could-not-read text", replyText().includes(READ_FAIL) && !replyText().includes("まだ見つかっていません"), replyText());
  calls = [];
  await send(makeEnv(), [ownerMsg("グループ一覧")]);
  check("absent: unchanged", replyText() === "加盟店グループはまだ見つかっていません。", replyText());
}

console.log("\n3) 1対1へ / 1対1一覧: the 1:1 list cannot be read");
{
  const failDm = { failList: (p) => p === "kira_gconv:dm:" };
  calls = [];
  await send(makeEnv(failDm), [ownerMsg("1対1へ ありがとうございます。")]);
  check("1対1へ failure: could-not-read, nothing sent", replyText().includes(READ_FAIL) && replyText().includes("何も送っていません") && !replyText().includes(NOT_FOUND), replyText());
  calls = [];
  await send(makeEnv(failDm), [ownerMsg("1対1一覧")]);
  check("1対1一覧 failure: could-not-read", replyText().includes(READ_FAIL) && replyText() !== "まだありません。", replyText());
  calls = [];
  await send(makeEnv(), [ownerMsg("1対1へ ありがとうございます。")]);
  check("1対1へ absent: unchanged", replyText().startsWith("KIRA が会話を持っている加盟店さんの 1 対 1 が見つかりませんでした"), replyText());
  calls = [];
  await send(makeEnv(), [ownerMsg("1対1一覧")]);
  check("1対1一覧 absent: unchanged", replyText() === "まだありません。", replyText());
}

console.log("\n4) 経験帳 / おぼえて / わすれて: the lesson book cannot be read");
{
  const env = makeEnv({ failGet: (k) => k === "kira_lessons:global" });
  env._kv.set("kira_lessons:global", JSON.stringify([{ t: "既存の覚え書き", by: "owner" }]));
  calls = [];
  await send(env, [ownerMsg("おぼえて 新しい覚え書き")]);
  check("おぼえて failure: book not overwritten", JSON.parse(env._kv.get("kira_lessons:global")).length === 1 && !env._puts.some((k) => k.startsWith("kira_lesson")));
  check("おぼえて failure: owner told nothing changed", replyText().includes(READ_FAIL) && replyText().includes("何も変えていません"), replyText());
  calls = [];
  await send(env, [ownerMsg("わすれて 1")]);
  check("わすれて failure: not 'no such number', nothing removed", replyText().includes(READ_FAIL) && !replyText().includes("その番号はありません") && !env._puts.some((k) => k.startsWith("kira_lesson")), replyText());
  calls = [];
  await send(env, [ownerMsg("経験帳")]);
  check("経験帳 failure: never shows an empty book", replyText().includes(READ_FAIL) && !replyText().includes("まだ無い"), replyText());
  const env2 = makeEnv();
  calls = [];
  await send(env2, [ownerMsg("おぼえて 新しい覚え書き")]);
  check("おぼえて normal: unchanged", replyText().includes("足しました") && (await globalLessons(env2)).length === 1, replyText());
  calls = [];
  await send(env2, [ownerMsg("経験帳")]);
  check("経験帳 normal: unchanged", replyText().startsWith("【経験帳 全体 1 件】"), replyText());
}

console.log("\n5) catch-up: the conversation list or the sent mark cannot be read");
{
  const reply = JSON.stringify({ action: "reply", reply: "お返事が遅くなり失礼しました。ありがとうございます。", reason: "", lessons: [] });
  const seed = (env) => {
    env._kv.set("kira_global_swept:v20", "1");
    env._kv.set("groupPartner:" + GID, "1");
    env._kv.set("kira_gconv:" + GID, JSON.stringify([{ who: "member", text: "写真送ります", at: ago(30) }]));
  };
  const logs = []; const orig = console.log; console.log = (...a) => { logs.push(a.join(" ")); };
  const env = makeEnv({ failList: (p) => p === "kira_gconv:" }); seed(env);
  calls = []; llmOut = reply;
  try { await runCron(env); } finally { console.log = orig; }
  check("list failure: logged as a failure, not silent", logs.some((l) => l.includes("[catchup] list failed")));
  check("list failure: nothing sent", pushTo(GID).length === 0);
  const env2 = makeEnv({ failGet: (k) => k.startsWith("kira_catchup:") }); seed(env2);
  calls = []; llmOut = reply;
  await runCron(env2);
  check("sent-mark failure: no late reply pushed to the store (no duplicate risk)", pushTo(GID).length === 0 && llms().length === 0);
  const env3 = makeEnv(); seed(env3);
  calls = []; llmOut = reply;
  await runCron(env3);
  check("normal: late reply pushed once (unchanged)", pushTo(GID).length === 1);
  llmOut = null;
}

console.log("\n6) drip follow-up: the partner flag cannot be read");
{
  const seed = (env) => {
    env._kv.set("kira_global_swept:v20", "1");
    env._kv.set("chat:" + CONSUMER, JSON.stringify({ registeredAt: Date.now() - 30 * 3600 * 1000, phase: "HEARING" }));
  };
  const env = makeEnv({ failGet: (k) => k === "partner:" + CONSUMER }); seed(env);
  calls = [];
  await runCron(env);
  check("failure: no consumer drip mail sent", pushTo(CONSUMER).length === 0);
  check("failure: chat record not rewritten", !env._puts.includes("chat:" + CONSUMER));
  const env2 = makeEnv(); seed(env2);
  calls = [];
  await runCron(env2);
  check("absent (a real consumer): drip sent as before", pushTo(CONSUMER).length === 1);
  const env3 = makeEnv(); seed(env3); env3._kv.set("partner:" + CONSUMER, JSON.stringify({ since: 1 }));
  calls = [];
  await runCron(env3);
  check("found (a member store): no drip, as before", pushTo(CONSUMER).length === 0);
}

console.log("\n7) group: the partner-group flag cannot be read");
{
  const env = makeEnv({ failGet: (k) => k === "groupPartner:" + GID });
  calls = []; llmOut = JSON.stringify({ action: "reply", reply: "KIRA の返事", reason: "", lessons: [] });
  await send(env, [groupMsg("@HORIZON SHIELD 写真送ります", true)]);
  check("failure: KIRA not called, no consumer or partner reply", llms().length === 0);
  check("failure: only the neutral receipt to the group", replies().length === 1 && replyText().startsWith("ご返信ありがとうございます。内容を確認して、担当の大賀から"), replyText());
  check("failure: hearing asked not to make a reply", bridges()[0] && bridges()[0].body.kira_decides === true);
  check("failure: owner told the flag could not be read", pushTo(OWNER).some((c) => c.body.messages[0].text.includes("加盟店グループかどうかを今は読み込めなかった")));
  calls = [];
  await send(env, [groupMsg("森下さん、明日よろしく", false)]);
  check("failure, not addressed: nothing to the group", replies().length === 0);
  const env2 = makeEnv();
  calls = [];
  await send(env2, [groupMsg("@HORIZON SHIELD 写真送ります", true)]);
  check("absent (not a partner group): hearing's reply as before", replyText() === "ご回答ありがとうございます。掲載に反映します。", replyText());
  check("absent: hearing makes the reply as before", bridges()[0] && bridges()[0].body.kira_decides === false);
  const env3 = makeEnv(); env3._kv.set("groupPartner:" + GID, "1");
  calls = [];
  await send(env3, [groupMsg("@HORIZON SHIELD 写真送ります", true)]);
  check("found (a partner group): KIRA replies as before", llms().length === 1 && replyText() === "KIRA の返事", replyText());
  llmOut = null;
}

console.log("\n8) conversation memory: a failed read is not written back over the history");
{
  const env = makeEnv({ failGet: (k) => k === "kira_gconv:" + GID });
  env._kv.set("groupPartner:" + GID, "1");
  env._kv.set("kira_gconv:" + GID, JSON.stringify([{ who: "member", text: "a", at: ago(5) }, { who: "kira", text: "b", at: ago(4) }]));
  const ownerInGroup = { type: "message", replyToken: "rt", source: { type: "group", groupId: GID, userId: OWNER }, message: { type: "text", id: "og1", text: "大賀です。よろしくお願いします。" } };
  calls = [];
  await send(env, [ownerInGroup]);
  check("failure: history kept (2 lines, not replaced by 1)", JSON.parse(env._kv.get("kira_gconv:" + GID)).length === 2 && !env._puts.includes("kira_gconv:" + GID));
  const env2 = makeEnv(); env2._kv.set("groupPartner:" + GID, "1");
  env2._kv.set("kira_gconv:" + GID, JSON.stringify([{ who: "member", text: "a", at: ago(5) }]));
  calls = [];
  await send(env2, [{ ...ownerInGroup, message: { ...ownerInGroup.message, id: "og2" } }]);
  check("normal: appended as before", JSON.parse(env2._kv.get("kira_gconv:" + GID)).length === 2);
}

console.log("\n9) 業者チェック: read the shape hs-gyosha-check /check actually returns");
{
  calls = []; gyosha = { status: 200, body: { result: "⚠️ リスクレベル：低\n\n📋 調査結果：\n・建設業許可あり" } };
  await send(makeEnv(), [{ type: "message", replyToken: "rt_c", source: { type: "user", userId: CONSUMER }, message: { type: "text", id: "c1", text: "業者チェック 山田工務店" } }]);
  const req = calls.find((c) => c.url.includes("hs-gyosha-check"));
  check("request uses the field /check reads (company)", req && req.body && req.body.company === "山田工務店", JSON.stringify(req && req.body));
  check("success: the report is shown", replyText().includes("リスクレベル：低") && replyText().includes("建設業許可あり"), replyText());
  check("success: no 'could not get' text", !replyText().includes("現在情報を取得できませんでした") && !replyText().includes("を調査中です"), replyText());
  for (const [label, g] of [["non-2xx", { status: 500, body: { error: "API error" } }], ["missing result", { status: 200, body: {} }], ["throw", { throws: true }]]) {
    calls = []; gyosha = g;
    await send(makeEnv(), [{ type: "message", replyToken: "rt_c", source: { type: "user", userId: CONSUMER }, message: { type: "text", id: "c" + label, text: "業者チェック 山田工務店" } }]);
    check(label + ": the existing failure text, no raw error", replyText().startsWith("🔍「山田工務店」を調査中です。") && !replyText().includes("API error"), replyText());
  }
  gyosha = { status: 200, body: { result: "ok" } };
}

console.log("\nchecks: " + checks + ", failed: " + fail);
const EXPECT = 40;
if (checks < EXPECT) { console.log("fewer checks than expected (" + EXPECT + ")"); fail++; }
console.log(fail ? "read-failure checks FAILED" : "read-failure checks all passed");
process.exit(fail ? 1 : 0);
