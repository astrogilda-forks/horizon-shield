/* hs-monitor: a known prospect whose record cannot be read (issue #13, 2026-10-13).
   Offline, no network: the real worker through /scan, with KV and fetch mocked.

   getProspect returned null for both "no such prospect" and "the read failed", so a hot post from a known prospect
   saved a fresh record (contactCount 1) over the prospect's history, and the post was marked seen so it was never
   looked at again. Now the post is skipped: nothing is written, nothing is sent, the seen mark is not set, and the
   next scan reads it again. Every "fix" check fails on d118ad9e and passes after the fix. The "guard" checks pin the
   success path and pass on both.

   node workers/hs-monitor/read_failure_test.mjs
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

const FEED = "https://feed.test.invalid/rss";
const TITLE = "リフォームの見積もりが高いと感じて困っています";
const LINK = "https://blog.test.invalid/post1/entry";
const PKEY = "prospect:rss:blog.test.invalid:post1";
const RSS = `<rss><channel><item><title>${TITLE}</title><description>追加費用も請求されました</description><link>${LINK}</link></item></channel></rss>`;
const SCORE = { score: 90, pattern: "A", reason: "見積が高い", is_vendor: false, urgency: "高", reply: "" };
const KNOWN = JSON.stringify({ firstTitle: "前の投稿", firstScore: 70, firstPattern: "D", firstLink: LINK, source: "RSS", addedAt: 1, lastSeen: 1, contactCount: 3, tier: "hot" });

let calls = [];
globalThis.fetch = async (url, init) => {
  const u = String(url);
  let body = null; try { body = JSON.parse((init && init.body) || "null"); } catch (_e) { body = null; }
  calls.push({ url: u, body });
  if (u === FEED) return new Response(RSS, { status: 200 });
  if (u.includes("api.anthropic.com")) return new Response(JSON.stringify({ content: [{ type: "text", text: JSON.stringify(SCORE) }] }), { status: 200 });
  return new Response("{}", { status: 200 });
};
const lines = () => calls.filter((c) => c.url.includes("api.line.me")).map((c) => c.body.messages[0].text);

function makeEnv(failGet) {
  const kv = new Map();
  const puts = [];
  return {
    _kv: kv, _puts: puts,
    CONTROL_TOKEN: "ctl-test", ALERT_FEED_URLS: FEED, LINE_CHANNEL_TOKEN: "tok", LINE_USER_ID: "Uowner", ANTHROPIC_API_KEY: "test-not-a-key",
    SEEN_STORE: {
      get: async (k) => {
        if (failGet && failGet(k)) throw new Error("KV get failed (simulated)");
        return kv.has(k) ? kv.get(k) : null;
      },
      put: async (k, v) => { puts.push(k); kv.set(k, v); },
      delete: async (k) => { kv.delete(k); },
      list: async (q) => ({ keys: [...kv.keys()].filter((k) => k.startsWith((q && q.prefix) || "")).map((name) => ({ name })) }),
    },
  };
}
const scan = async (env) => {
  const r = await W.fetch(new Request("https://monitor.test.invalid/scan", { headers: { Authorization: "Bearer ctl-test" } }), env);
  return r.json();
};

console.log("\n1) a known prospect's record cannot be read");
{
  let failing = true;
  const env = makeEnv((k) => failing && k === PKEY);
  env._kv.set(PKEY, KNOWN);
  calls = [];
  const res = await scan(env);
  check("the prospect's history is not overwritten (no put, record intact)", !env._puts.includes(PKEY) && env._kv.get(PKEY) === KNOWN, env._puts.join(","));
  check("no LINE is sent for it as a new prospect", lines().length === 0, lines().map((t) => t.slice(0, 20)).join(" | "));
  check("the post is not marked seen, so the next scan retries it", !env._puts.some((k) => k.startsWith("seen:")), env._puts.join(","));
  check("the scan result counts it in read_failed", res.read_failed === 1, JSON.stringify(res));
  failing = false;
  calls = [];
  const res2 = await scan(env);
  const p = JSON.parse(env._kv.get(PKEY));
  check("next scan, read works: handled as the known prospect (contactCount 3 -> 4, first score kept)", p.contactCount === 4 && p.firstScore === 70 && res2.recontact === 1, JSON.stringify(p).slice(0, 120));
  check("next scan: the owner is told it is a known prospect posting again", lines().some((t) => t.includes("既存見込み客が再投稿")));
}

console.log("\n2) success path is unchanged");
{
  const env = makeEnv();
  env._kv.set(PKEY, KNOWN);
  calls = [];
  const res = await scan(env);
  const p = JSON.parse(env._kv.get(PKEY));
  guard("known prospect: contactCount + 1 and the re-contact LINE", p.contactCount === 4 && res.recontact === 1 && lines().some((t) => t.includes("既存見込み客が再投稿")));
  guard("the result has exactly the old fields (no read_failed when nothing failed)", JSON.stringify(Object.keys(res)) === JSON.stringify(["scanned", "notifiedHot", "notifiedWatch", "recontact", "skipped", "rss", "x"]), JSON.stringify(Object.keys(res)));
  const env2 = makeEnv();
  calls = [];
  const r2 = await scan(env2);
  const p2 = JSON.parse(env2._kv.get(PKEY) || "{}");
  guard("new prospect: a fresh record (contactCount 1) and the discovery LINE", p2.contactCount === 1 && p2.firstScore === 90 && r2.notifiedHot === 1 && lines().some((t) => t.includes("【90点 / パターンA】")));
  calls = [];
  const r3 = await scan(env2);
  guard("a seen post is skipped on the next scan", r3.skipped === 1 && lines().length === 0);
}

console.log("\nchecks: " + checks + ", guards: " + guards + ", failed: " + fail);
const EXPECT = 6, EXPECT_GUARDS = 4;
if (checks < EXPECT || guards < EXPECT_GUARDS) { console.log("fewer checks than expected (" + EXPECT + " + " + EXPECT_GUARDS + " guards)"); fail++; }
console.log(fail ? "hs-monitor read-failure checks FAILED" : "hs-monitor read-failure checks all passed");
process.exit(fail ? 1 : 0);
