/* ai-council: the month spend is one key per charge, the total is listed (concurrency audit AC, 2026-10-13).
   Offline, no network: the real worker with KV and fetch faked.

   Before: month_<m> was read, added to and written back by every authorized /council request. Two requests in
   flight read the same value and the second write erased the first charge, so the $30 cap could be passed.
   After: every charge is its own key spend:<month>:<ts>-<rand> (amount in the value and in the metadata), the
   month total is the old month_<m> counter (read only, a floor) plus the listed charges. If the list is truncated
   (more than 1000 charges) or fails, the request is refused with 503 budget_unknown and no AI is called.

   The fake KV has a barrier on puts of cost keys (month_<m> in the old code, spend:* in the new): the first writer
   waits until the second has also read and is about to write, so both writes are based on the same state.
   Every "fix" check fails on 4dc7e373 and passes after the fix; "guard" checks pin behaviour that must not change.

   node workers/ai-council/test/spend.test.mjs
*/
import W from "../src/worker.js";

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

const PW = "test-admin-password";
const MONTH = new Date().toISOString().slice(0, 7).replace("-", "_");
const isCostKey = (k) => k.startsWith("month_") || k.startsWith("spend:");

// barrier(n): puts of cost keys wait until n writers have arrived (or 2 s), then all go on.
function makeEnv(opts) {
  const o = opts || {};
  const kv = new Map(), meta = new Map(), puts = [];
  let arrived = 0, waiters = [];
  const release = () => { const w = waiters; waiters = []; for (const r of w) r(); };
  return {
    ADMIN_PASSWORD: PW, ANTHROPIC_API_KEY: "test-not-a-key", GEMINI_API_KEY: "test-not-a-key",
    _kv: kv, _puts: puts, _meta: meta,
    AI_COUNCIL_COST: {
      get: async (k) => (kv.has(k) ? kv.get(k) : null),
      put: async (k, v, popts) => {
        if (o.barrier && isCostKey(k)) {
          arrived++;
          if (arrived < o.barrier) await new Promise((r) => { waiters.push(r); setTimeout(release, 2000); });
          else release();
        }
        puts.push({ k, v, opts: popts || {} });
        kv.set(k, v);
        if (popts && popts.metadata) meta.set(k, popts.metadata); else meta.delete(k);
      },
      delete: async (k) => { kv.delete(k); meta.delete(k); },
      list: async (q) => {
        const p = (q && q.prefix) || "";
        if (o.failList) throw new Error("KV list failed (test)");
        let keys = [...kv.keys()].filter((k) => k.startsWith(p)).sort().map((name) => (meta.has(name) ? { name, metadata: meta.get(name) } : { name }));
        if (o.truncate) return { keys, list_complete: false, cursor: "next" };   // an endless cursor: every page says more follow
        if (o.pageSize) {   // real pagination: pageSize keys per page, cursor = index of the next key
          const start = q && q.cursor ? Number(q.cursor) : 0;
          const page = keys.slice(start, start + o.pageSize);
          const done = start + o.pageSize >= keys.length;
          return done ? { keys: page, list_complete: true } : { keys: page, list_complete: false, cursor: String(start + o.pageSize) };
        }
        return { keys, list_complete: true };
      },
    },
  };
}

// 1000 input + 1000 output tokens each: claude 0.003 + 0.015, gemini 0.000075 + 0.0003 = 0.018375 per request.
const PER_REQUEST = 0.018375;
let aiCalls = 0;
globalThis.fetch = async (url) => {
  const u = String(url);
  aiCalls++;
  if (u.includes("api.anthropic.com")) return new Response(JSON.stringify({ content: [{ type: "text", text: "結論。\n立場: 賛成" }], usage: { input_tokens: 1000, output_tokens: 1000 } }), { status: 200 });
  if (u.includes("generativelanguage.googleapis.com")) return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "数字。\n立場: 反対" }] } }], usageMetadata: { promptTokenCount: 1000, candidatesTokenCount: 1000 } }), { status: 200 });
  return new Response("{}", { status: 200 });
};
const council = (env, q) => W.fetch(new Request("https://x/council", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: q, password: PW }) }), env, {});
const cost = async (env) => { const r = await W.fetch(new Request("https://x/cost"), env, {}); return { status: r.status, body: await r.json() }; };
const spendKeys = (env) => [...env._kv.keys()].filter((k) => k.startsWith("spend:" + MONTH + ":"));
const near = (a, b) => Math.abs(Number(a) - Number(b)) < 0.00011;

console.log("\n1) two authorized requests at the same time: both charges are counted");
{
  const env = makeEnv({ barrier: 2 });
  aiCalls = 0;
  const [r1, r2] = await Promise.all([council(env, "この施策は進めるべきか"), council(env, "別の施策は進めるべきか")]);
  guard("both requests were answered 200", r1.status === 200 && r2.status === 200, r1.status + " " + r2.status);
  guard("four AI calls were made (claude + gemini, twice)", aiCalls === 4, String(aiCalls));
  const c = await cost(env);
  check("the month total is two charges, not one", c.status === 200 && near(c.body.current_cost_usd, 2 * PER_REQUEST), String(c.body.current_cost_usd) + " (want " + (2 * PER_REQUEST).toFixed(4) + ")");
  check("each charge is its own key spend:<month>:<ts>-<rand>", spendKeys(env).length === 2 && spendKeys(env).every((k) => /^spend:[0-9]{4}_[0-9]{2}:[0-9]{14}-[0-9a-z]{6,}$/.test(k)), JSON.stringify(spendKeys(env)));
  check("the amount rides in the key's metadata", spendKeys(env).length === 2 && spendKeys(env).every((k) => env._meta.has(k) && near(env._meta.get(k).usd, PER_REQUEST)));
  check("the old counter month_<m> is not written", !env._puts.some((p) => p.k === "month_" + MONTH));
  const j = await r2.json();
  guard("the response shape is unchanged (cost fields present)", typeof j.cost_this_request_usd === "string" && typeof j.cost_this_month_usd === "string" && typeof j.cost_remaining_usd === "string");
}

console.log("\n2) the old counter is a floor under the listed charges");
{
  const env = makeEnv();
  env._kv.set("month_" + MONTH, "29.9900");
  env._kv.set("spend:" + MONTH + ":00000000000001-aaaaaa", "0.020000");
  const c = await cost(env);
  check("/cost = old counter + charges", near(c.body.current_cost_usd, 30.01), String(c.body.current_cost_usd));
  aiCalls = 0;
  const r = await council(env, "この施策は進めるべきか");
  check("/council refuses with 429 at the cap (the old counter alone was under it)", r.status === 429 && aiCalls === 0, r.status + " aiCalls=" + aiCalls);
  const env2 = makeEnv();
  env2._kv.set("month_" + MONTH, "1.5000");
  aiCalls = 0;
  const r2 = await council(env2, "この施策は進めるべきか");
  const j2 = await r2.json();
  guard("under the cap the request runs and the response total includes the floor", r2.status === 200 && near(j2.cost_this_month_usd, 1.5 + PER_REQUEST), String(j2.cost_this_month_usd));
  check("the charge went to its own key; the floor is untouched", spendKeys(env2).length === 1 && env2._kv.get("month_" + MONTH) === "1.5000");
}

console.log("\n2b) a month with more than one list page");
// Pages: 2,500 charges of 1 cent spread over three list pages (1000, 1000, 500) are all summed. A one-page read would
// see $10 of $25 and let the month pass the cap. (2026-10-13 review: the first version read one page only.)
{
  const env = makeEnv({ pageSize: 1000 });
  for (let i = 0; i < 2500; i++) env.AI_COUNCIL_COST.put(`spend:${MONTH}:${String(1700000000000 + i).padStart(14, "0")}-p${i}`, "0.010000", { metadata: { usd: 0.01 } });
  await new Promise((r) => setTimeout(r, 0));
  const c = await cost(env);
  check("paged list: three pages are summed (25.00, not 10.00)", c.status === 200 && Math.abs(Number(c.body.current_cost_usd) - 25) < 0.001, c.status + " " + JSON.stringify(c.body).slice(0, 120));
}

console.log("\n3) when the month total cannot be known, nothing is spent (fail closed)");
{
  const env = makeEnv({ truncate: true });
  env._kv.set("spend:" + MONTH + ":00000000000001-aaaaaa", "0.010000");
  aiCalls = 0;
  const r = await council(env, "この施策は進めるべきか");
  const j = await r.json();
  check("truncated list: 503 budget_unknown, no AI called, no charge written", r.status === 503 && j.error === "budget_unknown" && aiCalls === 0 && spendKeys(env).length === 1, r.status + " " + JSON.stringify(j).slice(0, 80) + " aiCalls=" + aiCalls);
  const c = await cost(env);
  check("truncated list: /cost also says budget_unknown instead of a low number", c.status === 503 && c.body.error === "budget_unknown", c.status + " " + JSON.stringify(c.body).slice(0, 80));
  const env2 = makeEnv({ failList: true });
  aiCalls = 0;
  const r2 = await council(env2, "この施策は進めるべきか");
  const j2 = await r2.json();
  check("list error: 503 budget_unknown, no AI called, no charge written", r2.status === 503 && j2.error === "budget_unknown" && aiCalls === 0 && spendKeys(env2).length === 0, r2.status + " aiCalls=" + aiCalls);
}

console.log("\n4) auth and shape guards");
{
  const env = makeEnv();
  const r = await W.fetch(new Request("https://x/council", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: "この施策は進めるべきか", password: "wrong" }) }), env, {});
  guard("wrong password is 401 and spends nothing", r.status === 401 && spendKeys(env).length === 0);
  const c = await cost(env);
  guard("/cost on an empty month is 0 with the same fields", c.status === 200 && c.body.current_cost_usd === "0.0000" && c.body.monthly_limit_usd === 30 && c.body.grok_enabled === true, JSON.stringify(c.body));
}

console.log("\nchecks: " + checks + ", guards: " + guards + ", failed: " + fail);
const EXPECT = 10, EXPECT_GUARDS = 6;
if (checks < EXPECT || guards < EXPECT_GUARDS) { console.log("fewer checks than expected (" + EXPECT + " + " + EXPECT_GUARDS + " guards)"); fail++; }
console.log(fail ? "spend checks FAILED" : "spend checks all passed");
process.exit(fail ? 1 : 0);
