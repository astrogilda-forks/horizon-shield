/* hs-gyosha-check: a failed model call is not "0 defects" (issue #13, 2026-10-13). Offline, no network.

   /inspect: on a non-2xx or empty answer from the model, the caller gets a non-200 with an error code and the
   owner's LINE alert says the inspection was not completed. A real answer (with or without defects) is unchanged.
   /check: the response shape { result: "<text>" } that hs-kira-line relies on.

   node workers/hs-gyosha-check/inspect_test.mjs
*/
import W from "./src/worker.js";

let fail = 0, checks = 0;
function check(label, cond, detail) {
  checks++;
  console.log((cond ? "  ok   " : "  NG   ") + label + (detail ? "  " + detail : ""));
  if (!cond) fail++;
}

let calls = [];
let model = { status: 200, body: {} };
globalThis.fetch = async (url, init) => {
  const u = String(url);
  let body = null; try { body = JSON.parse((init && init.body) || "null"); } catch (_e) { body = null; }
  calls.push({ url: u, body });
  if (u.includes("api.anthropic.com")) return new Response(JSON.stringify(model.body), { status: model.status });
  return new Response("{}", { status: 200 });
};
const env = { ANTHROPIC_API_KEY: "test-not-a-key", LINE_CHANNEL_TOKEN: "tok", LINE_USER_ID: "U" + "c".repeat(32) };
async function post(path, payload) {
  const waits = [];
  const res = await W.fetch(new Request("https://x" + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }), env, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  let j = null; try { j = await res.json(); } catch (_e) { j = null; }
  return { status: res.status, json: j };
}
const alert = () => { const p = calls.find((c) => c.url.includes("/v2/bot/message/push")); return (p && p.body.messages[0].text) || ""; };
const img = { images: [{ mediaType: "image/jpeg", data: "AAAA" }], category: "外壁塗装" };
const text = (t) => ({ content: [{ type: "text", text: t }] });

console.log("\n1) /inspect: the model call fails (non-2xx)");
{
  const logs = []; const orig = console.log; console.log = (...a) => { logs.push(a.join(" ")); };
  calls = []; model = { status: 529, body: { type: "error", error: { type: "overloaded_error", message: "Overloaded" } } };
  let r; try { r = await post("/inspect", img); } finally { console.log = orig; }
  check("failure: not HTTP 200", r.status !== 200, String(r.status));
  check("failure: error code in the body", r.json && r.json.error === "inspect_upstream_failed", JSON.stringify(r.json));
  check("failure: no defects / severity handed on as a result", r.json && !("defects" in r.json) && !("severity" in r.json));
  check("failure: owner alert says not completed", alert().includes("診断できませんでした"), alert());
  check("failure: owner alert never says 検出: 0件", !alert().includes("検出: 0件"));
  check("failure: logged", logs.some((l) => l.includes("[inspect] inspect_upstream_failed")));
}

console.log("\n2) /inspect: HTTP 200 but no text from the model");
{
  calls = []; model = { status: 200, body: { content: [] } };
  const r = await post("/inspect", img);
  check("no text: not HTTP 200, error code", r.status !== 200 && r.json && r.json.error === "inspect_no_result", r.status + " " + JSON.stringify(r.json));
  check("no text: owner alert says not completed", alert().includes("診断できませんでした") && !alert().includes("検出: 0件"), alert());
}

console.log("\n3) /inspect: a real answer is unchanged");
{
  calls = []; model = { status: 200, body: text(JSON.stringify({ severity: "中", defects: [{ level: "mid", name: "塗り残し" }, { level: "low", name: "垂れ" }], report: "是正をお願いします" })) };
  let r = await post("/inspect", img);
  check("defects found: 200 with the parsed result", r.status === 200 && r.json.defects.length === 2 && r.json.severity === "中");
  check("defects found: alert counts them", alert().includes("検出: 2件") && alert().includes("深刻度: 中"), alert());
  calls = []; model = { status: 200, body: text("```json\n" + JSON.stringify({ severity: "低", defects: [], report: "" }) + "\n```") };
  r = await post("/inspect", img);
  check("no defects (a real answer): 200, empty list", r.status === 200 && Array.isArray(r.json.defects) && r.json.defects.length === 0);
  check("no defects (a real answer): alert says 検出: 0件", alert().includes("検出: 0件"), alert());
  calls = []; model = { status: 200, body: text("写真が不鮮明で判定できません") };
  r = await post("/inspect", img);
  check("unparseable answer: 200 with severity 不明 as before", r.status === 200 && r.json.severity === "不明" && r.json.report === "写真が不鮮明で判定できません");
  check("unparseable answer: alert does not claim 0 detections", !alert().includes("検出: 0件") && alert().includes("判定できず"), alert());
}

console.log("\n4) /check: response shape { result } (what hs-kira-line reads)");
{
  calls = []; model = { status: 200, body: text("⚠️ リスクレベル：低\n\n📋 調査結果：\n・建設業許可あり") };
  const r = await post("/check", { company: "山田工務店" });
  check("200 with result text", r.status === 200 && typeof r.json.result === "string" && r.json.result.includes("リスクレベル：低"), JSON.stringify(r.json));
  check("no other fields", Object.keys(r.json).join(",") === "result");
  calls = [];
  const r2 = await post("/check", { company_name: "山田工務店" });
  check("the old field name company_name is not read (400)", r2.status === 400, String(r2.status));
}

console.log("\nchecks: " + checks + ", failed: " + fail);
const EXPECT = 17;
if (checks < EXPECT) { console.log("fewer checks than expected (" + EXPECT + ")"); fail++; }
console.log(fail ? "inspect checks FAILED" : "inspect checks all passed");
process.exit(fail ? 1 : 0);
