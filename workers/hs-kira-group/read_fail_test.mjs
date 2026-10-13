/* hs-kira-group: a failed read of the recent image or file is not "nothing was posted" (issue #13, 2026-10-13).
   Offline, no network.

   When the KV read of img:<source> or file:<source> throws, the model is told the attachment could not be read
   now (and told not to say none was posted). When the read works, behaviour is unchanged. The recent-message
   memory is not overwritten when its read fails.

   node workers/hs-kira-group/read_fail_test.mjs
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
const GID = "C" + "a".repeat(32);
const UID = "U" + "b".repeat(32);
function makeEnv(opts) {
  const o = opts || {};
  const kv = new Map();
  const puts = [];
  return {
    // the sender is the owner: a bare "キラ" in a group calls KIRA only for the owner (anyone else must @mention)
    LINE_CHANNEL_SECRET: SECRET, LINE_CHANNEL_TOKEN: "tok", ANTHROPIC_API_KEY: "test-not-a-key", OWNER_USER_ID: UID,
    _kv: kv, _puts: puts,
    HS_KIRA_GROUP_KV: {
      get: async (k) => { if (o.failGet && o.failGet(k)) throw new Error("KV get failed (test)"); return kv.has(k) ? kv.get(k) : null; },
      put: async (k, v) => { puts.push(k); kv.set(k, v); },
      delete: async (k) => { kv.delete(k); },
    },
  };
}
function sign(body) { return crypto.createHmac("sha256", SECRET).update(body).digest("base64"); }
async function send(env, events) {
  const body = JSON.stringify({ events });
  const waits = [];
  const res = await W.fetch(new Request("https://x/webhook", { method: "POST", headers: { "content-type": "application/json", "x-line-signature": sign(body) }, body }), env, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  return res;
}
let calls = [];
globalThis.fetch = async (url, init) => {
  const u = String(url);
  let body = null; try { body = JSON.parse((init && init.body) || "null"); } catch (_e) { body = null; }
  calls.push({ url: u, body });
  if (u.includes("api-data.line.me")) return new Response(new Uint8Array([255, 216, 255, 1, 2, 3]), { status: 200, headers: { "content-type": "image/jpeg" } });
  if (u.includes("api.anthropic.com")) return new Response(JSON.stringify({ content: [{ type: "text", text: "はい、見ました。" }] }), { status: 200 });
  return new Response("{}", { status: 200 });
};
const llm = () => calls.find((c) => c.url.includes("api.anthropic.com"));
const sys = () => { const l = llm(); return (l && l.body && l.body.system) || ""; };
const userContent = () => { const l = llm(); return l && l.body && l.body.messages[0].content; };
const groupText = (text) => ({ type: "message", replyToken: "rt", source: { type: "group", groupId: GID, userId: UID }, message: { type: "text", id: "m" + Math.random().toString(36).slice(2), text } });
const IMG_FAIL = "直近に貼られた画像があるかどうかを今は読み込めなかった";
const FILE_FAIL = "直近に貼られたファイルがあるかどうかを今は読み込めなかった";

console.log("\n1) the recent image record cannot be read");
{
  const env = makeEnv({ failGet: (k) => k.startsWith("img:") });
  calls = [];
  await send(env, [groupText("キラ、この画像見て")]);
  check("failure: model told the image could not be read now", sys().includes(IMG_FAIL));
  check("failure: model told not to say none was posted", sys().includes("画像が無いとは言わない"));
  check("failure: no image block invented", typeof userContent() === "string");
  check("failure: still answers (reply sent)", calls.some((c) => c.url.includes("/message/reply")));
  const env2 = makeEnv();
  env2._kv.set("img:" + GID, JSON.stringify({ id: "img123", ts: Date.now() }));
  calls = [];
  await send(env2, [groupText("キラ、この画像見て")]);
  check("normal: image fetched and shown to the model as before", Array.isArray(userContent()) && userContent()[0].type === "image");
  check("normal: no failure notice", !sys().includes(IMG_FAIL));
  calls = [];
  await send(makeEnv(), [groupText("キラ、この画像見て")]);
  check("absent: no image block and no failure notice (unchanged)", typeof userContent() === "string" && !sys().includes(IMG_FAIL));
  calls = [];
  await send(makeEnv({ failGet: (k) => k.startsWith("img:") }), [groupText("キラ、明日の段取りを教えて")]);
  check("failure, not about an attachment: no notice added", !sys().includes(IMG_FAIL));
}

console.log("\n2) the recent file record cannot be read");
{
  calls = [];
  await send(makeEnv({ failGet: (k) => k.startsWith("file:") }), [groupText("キラ、この資料読んで")]);
  check("failure: model told the file could not be read now", sys().includes(FILE_FAIL) && sys().includes("ファイルが無いとは言わない"));
  const env2 = makeEnv();
  env2._kv.set("file:" + GID, JSON.stringify({ id: "f1", name: "memo.txt", ts: Date.now() }));
  calls = [];
  const base = globalThis.fetch;
  globalThis.fetch = async (url, init) => String(url).includes("api-data.line.me") ? (calls.push({ url: String(url), body: null }), new Response("見積の覚え書き", { status: 200, headers: { "content-type": "text/plain" } })) : base(url, init);
  await send(env2, [groupText("キラ、この資料読んで")]);
  globalThis.fetch = base;
  check("normal: file text passed to the model as before", sys().includes("【添付ファイルの本文(memo.txt") && sys().includes("見積の覚え書き"));
  check("normal: no failure notice", !sys().includes(FILE_FAIL));
}

console.log("\n3) the recent-message memory is not overwritten when its read fails");
{
  const env = makeEnv({ failGet: (k) => k.startsWith("grp:") });
  env._kv.set("grp:" + GID, JSON.stringify([{ t: "a", ts: 1 }, { t: "b", ts: 2 }]));
  calls = [];
  await send(env, [groupText("今日はありがとう")]);
  check("failure: history kept (not replaced by one line)", JSON.parse(env._kv.get("grp:" + GID)).length === 2 && !env._puts.includes("grp:" + GID));
  const env2 = makeEnv();
  env2._kv.set("grp:" + GID, JSON.stringify([{ t: "a", ts: 1 }]));
  await send(env2, [groupText("今日はありがとう")]);
  check("normal: appended as before", JSON.parse(env2._kv.get("grp:" + GID)).length === 2);
}

console.log("\nchecks: " + checks + ", failed: " + fail);
const EXPECT = 13;
if (checks < EXPECT) { console.log("fewer checks than expected (" + EXPECT + ")"); fail++; }
console.log(fail ? "read-failure checks FAILED" : "read-failure checks all passed");
process.exit(fail ? 1 : 0);
