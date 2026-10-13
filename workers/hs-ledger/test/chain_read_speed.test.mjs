// 2026-10-13. GET /ledger/head walked entry:1..n one KV read at a time; at n = 95 production answered in about 20 s,
// past curl's 20 s limit in ops/prod_fix_check.sh. The walk now reads the entries up front, several at a time.
// This test gives every KV read a 40 ms delay and checks: the head bytes are identical to a sequential walk, a missing
// entry still breaks the chain at the same n, a failed read still fails the request, and 95 entries answer well under
// the sequential time (95 x 40 ms = 3.8 s).
import { createHash } from "node:crypto";
import { loadWorker, checker } from "./load.mjs";
const worker = await loadWorker("src/worker.js");
const chk = checker("hs-ledger chain read speed");
const B = "https://hs-ledger.example.dev";
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const N = 95, DELAY = 40;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function slowKV(map, { failKey = null } = {}) {
  let inflight = 0, peak = 0, reads = 0;
  return {
    stats: () => ({ peak, reads }),
    binding: {
      async get(k) { reads++; inflight++; peak = Math.max(peak, inflight); await sleep(DELAY); inflight--; if (k === failKey) throw new Error("kv read failed (test)"); return map.has(k) ? map.get(k) : null; },
      async put(k, v) { map.set(k, v); }, async delete(k) { map.delete(k); },
      async list() { return { keys: [], list_complete: true }; },
    },
  };
}
function store(k, { hole = 0 } = {}) {
  const m = new Map([["seq", String(k)]]);
  for (let n = 1; n <= k; n++) {
    if (n === hole) continue;
    const rc = JSON.stringify({ schema: "example", n });
    m.set("entry:" + n, JSON.stringify({ n, work: "w" + n, claim_sha256: sha(rc), record_canonical: rc, schema: "v0-plain", created_at: "2026-10-13T00:00:00.000Z", ots_status: "confirmed" }));
  }
  return m;
}
const canon = (o) => "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + JSON.stringify(o[k])).join(",") + "}";
function expectHead(m, k) {
  let prev = "0".repeat(64);
  for (let n = 1; n <= k; n++) { const e = JSON.parse(m.get("entry:" + n)); const b = { n: e.n, claim_sha256: e.claim_sha256, prev_entry_sha256: prev, schema: e.schema, created_at: e.created_at }; prev = sha(canon(b)); }
  return prev;
}
const go = (env, path) => worker.fetch(new Request(B + path), env, { waitUntil() {} });

{
  const m = store(N); const kv = slowKV(m);
  const t0 = Date.now(); const r = await go({ LEDGER: kv.binding }, "/ledger/head"); const ms = Date.now() - t0; const j = await r.json();
  chk("95 entries: 200 and the head equals the sequential recipe", r.status === 200 && j.n === N && j.head === expectHead(m, N), JSON.stringify({ status: r.status, n: j.n }));
  chk(`95 entries answer well under the sequential ${N * DELAY} ms (fails before: about ${N * DELAY} ms)`, ms < (N * DELAY) / 3, `ms=${ms}`);
  chk("reads run in parallel, bounded (peak in flight between 2 and 32)", kv.stats().peak >= 2 && kv.stats().peak <= 32, JSON.stringify(kv.stats()));
}
{
  const m = store(30, { hole: 17 }); const kv = slowKV(m);
  const r = await go({ LEDGER: kv.binding }, "/ledger/head"); const j = await r.json();
  chk("a missing entry still breaks the chain at that n (409 chain_broken, broken_at 17, last_linked 16)", r.status === 409 && j.error === "chain_broken" && j.broken_at === 17 && j.last_linked === 16, JSON.stringify(j).slice(0, 160));
}
{
  const m = store(30); const kv = slowKV(m, { failKey: "entry:9" });
  let status = 0; try { const r = await go({ LEDGER: kv.binding }, "/ledger/head"); status = r.status; } catch { status = -1; }
  chk("a failed entry read is not a hole: the request fails (5xx or throw), it does not answer 200 or chain_broken", status === -1 || status >= 500, "status=" + status);
}
{
  const m = store(N); const kv = slowKV(m);
  const r = await go({ LEDGER: kv.binding }, "/ledger/export.jsonl"); const lines = (await r.text()).trim().split("\n");
  const last = JSON.parse(lines[lines.length - 1]);
  chk("export.jsonl: 95 rows plus the bound head, head identical", lines.length === N + 1 && last.head === expectHead(m, N), "lines=" + lines.length);
}
{
  const r = await go({ LEDGER: slowKV(store(1)).binding }, "/health"); const j = await r.json();
  chk("/health says chain_read prefetch-parallel-20261013", j.chain_read === "prefetch-parallel-20261013", String(j.chain_read));
}
process.exit(chk.done() ? 1 : 0);
