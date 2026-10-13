/* hs-subscribe: the existence read fails (issue #13, 2026-10-13).
   Offline, no network: the real worker, with KV and fetch mocked.

   The exception of the existence read was ignored, so a re-subscribe was counted as new (count:<lang> + 1) and
   created_at was stamped as now. Now nothing is written and the form gets 503 subscriber_read_failed.
   Every "fix" check fails on d118ad9e and passes after the fix. The "guard" checks pin the success path and pass on
   both.

   node workers/hs-subscribe/read_failure_test.mjs
*/
import W from "./src/worker.js";

let fail = 0, checks = 0, guards = 0;
function check(label, cond, detail) {
  checks++;
  console.log((cond ? "  ok   " : "  NG   ") + label + (detail ? "  " + detail : ""));
  if (!cond) fail++;
}
function guard(label, cond, detail) {
  guards++;
  console.log((cond ? "  ok   " : "  NG   ") + "[guard] " + label + (detail ? "  " + detail : ""));
  if (!cond) fail++;
}

let lines = [];
globalThis.fetch = async (url, init) => {
  if (String(url).includes("api.line.me")) { lines.push(JSON.parse(init.body).messages[0].text); return new Response("{}", { status: 200 }); }
  return new Response("{}", { status: 200 });
};

function makeEnv(failGet) {
  const kv = new Map();
  const puts = [];
  return {
    _kv: kv, _puts: puts, LINE_CHANNEL_TOKEN: "tok", LINE_USER_ID: "Uowner",
    SUBSCRIBERS: {
      get: async (k) => {
        if (failGet && failGet(k)) throw new Error("KV get failed (simulated)");
        return kv.has(k) ? kv.get(k) : null;
      },
      put: async (k, v) => { puts.push(k); kv.set(k, v); },
    },
  };
}
const EMAIL = "member@example.invalid";
const KEY = "subscriber:jp:" + EMAIL;
const OLD = JSON.stringify({ email: EMAIL, name: "A", role: "", lang: "jp", created_at: "2026-06-01T00:00:00.000Z", updated_at: "2026-06-01T00:00:00.000Z" });
const post = async (env) => {
  const r = await W.fetch(new Request("https://subscribe.test.invalid/", {
    method: "POST", headers: { "content-type": "application/json", Origin: "https://shield.the-horizons-innovation.com" },
    body: JSON.stringify({ email: EMAIL, name: "A", lang: "jp" }),
  }), env);
  let body = null; try { body = await r.json(); } catch (_e) {}
  return { status: r.status, body, cors: r.headers.get("Access-Control-Allow-Origin") };
};

console.log("\n1) the existence read fails for someone already subscribed");
{
  const env = makeEnv((k) => k === KEY);
  env._kv.set(KEY, OLD);
  env._kv.set("count:jp", "7");
  lines = [];
  const r = await post(env);
  check("answers 503 subscriber_read_failed (with CORS)", r.status === 503 && r.body && r.body.ok === false && r.body.error === "subscriber_read_failed" && r.cors === "https://shield.the-horizons-innovation.com", r.status + " " + JSON.stringify(r.body));
  check("count:jp is not incremented", env._kv.get("count:jp") === "7", env._kv.get("count:jp"));
  check("the record is not rewritten (created_at kept)", !env._puts.includes(KEY) && env._kv.get(KEY) === OLD, env._puts.join(","));
  check("no LINE announces it as a new member", !lines.some((t) => t.includes("新規")), lines.map((t) => t.slice(0, 20)).join(" | "));
}

console.log("\n2) success path is unchanged");
{
  const env = makeEnv();
  env._kv.set("count:jp", "7");
  lines = [];
  const r = await post(env);
  const rec = JSON.parse(env._kv.get(KEY));
  guard("new: 200 {ok, already:false}, count 7 -> 8, created_at set, LINE says 新規", r.status === 200 && JSON.stringify(r.body) === JSON.stringify({ ok: true, already: false }) && env._kv.get("count:jp") === "8" && !!rec.created_at && lines.some((t) => t.includes("新規")));
  lines = [];
  const r2 = await post(env);
  guard("again: 200 {ok, already:true}, count stays 8, LINE says 再登録", r2.status === 200 && JSON.stringify(r2.body) === JSON.stringify({ ok: true, already: true }) && env._kv.get("count:jp") === "8" && lines.some((t) => t.includes("再登録")));
}

console.log("\nchecks: " + checks + ", guards: " + guards + ", failed: " + fail);
const EXPECT = 4, EXPECT_GUARDS = 2;
if (checks < EXPECT || guards < EXPECT_GUARDS) { console.log("fewer checks than expected (" + EXPECT + " + " + EXPECT_GUARDS + " guards)"); fail++; }
console.log(fail ? "hs-subscribe read-failure checks FAILED" : "hs-subscribe read-failure checks all passed");
process.exit(fail ? 1 : 0);
