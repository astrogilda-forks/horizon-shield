// 2026-10-13. The mould from issue #13 in this worker: a KV read that threw was handed on as "nothing there".
// An order read failure answered 404 "order not found" on /review, /answer and /admin/orders/<id>; a board_index read
// failure became an empty board cached for 30 s, and the publish route wrote it back as a one-card index.
// Each failure must now be reported as a failure, and each genuine absence keeps today's answer.
import assert from "node:assert/strict";
import worker from "../src/index.js";
import { boardCacheClear } from "../src/teardown.js";
import { kv, outside } from "./mocks.mjs";
import { signPath } from "../src/sign.js";

globalThis.fetch = outside([]);
const SITE = "https://horizonshield.dev";
const W = "https://w.example";
const SECRET = "link-secret-for-tests";
const store = kv();
const broken = new Set();   // keys whose get throws
const US_ORDERS = { ...store, m: store.m, meta: store.meta,
  async get(k) { if (broken.has(k)) throw new Error("KV get failed (simulated)"); return store.get(k); },
  put: (...a) => store.put(...a), delete: (...a) => store.delete(...a), list: (...a) => store.list(...a) };
const env = { US_ORDERS, SITE_URL: SITE, PUBLIC_WORKER_URL: W, LINK_SECRET: SECRET, US_ADMIN_TOKEN: "admin-token-for-tests", LINE_CHANNEL_TOKEN: "x", LINE_USER_ID: "U1" };
const ctx = { waitUntil() {} };
const get = (path, init = {}) => worker.fetch(new Request(W + path, init), env, ctx);
const admin = { authorization: "Bearer admin-token-for-tests" };

let n = 0, fail = 0;
const chk = (name, fn) => { n++; try { fn(); console.log("PASS  " + name); } catch (e) { fail++; console.log("FAIL  " + name + "  <<< " + String(e.message).slice(0, 240)); } };

// ---- orders
const ID = "US-20261013-ABCDEF";
const HEX = "0123456789abcdef";
await store.put(`order:${ID}`, JSON.stringify({ id: ID, status: "draft_ready", draft: { sha256: HEX + "ffff" } }));

broken.add(`order:${ID}`);
let r = await get(`/admin/orders/${ID}`, { headers: admin });
let body = await r.json();
chk("admin order read failure: 503 order_read_failed, not 404 order not found", () => { assert.equal(r.status, 503); assert.equal(body.error, "order_read_failed"); });
r = await get(await signPath(SECRET, `/review/${ID}/${HEX}`, 3600000));
let text = await r.text();
chk("review order read failure: 503, not 404 not found", () => { assert.equal(r.status, 503); assert.ok(!/not found/.test(text), text); });
r = await get(await signPath(SECRET, `/answer/${ID}`, 3600000));
text = await r.text();
chk("answer order read failure: 503, not 404 Not found", () => { assert.equal(r.status, 503); assert.ok(!/Not found/.test(text), text); });
broken.delete(`order:${ID}`);

await store.put(`order:${ID}`, "{not json");
r = await get(`/admin/orders/${ID}`, { headers: admin });
chk("an order that will not parse: 503, not 404", () => assert.equal(r.status, 503));
await store.delete(`order:${ID}`);

r = await get(`/admin/orders/${ID}`, { headers: admin });
body = await r.json();
chk("admin genuinely absent order: still 404 order not found", () => { assert.equal(r.status, 404); assert.deepEqual(body, { error: "order not found" }); });
r = await get(await signPath(SECRET, `/review/${ID}/${HEX}`, 3600000));
text = await r.text();
chk("review genuinely absent order: still 404 not found", () => { assert.equal(r.status, 404); assert.ok(/<p>not found<\/p>/.test(text), text); });
r = await get(await signPath(SECRET, `/answer/${ID}`, 3600000));
text = await r.text();
chk("answer genuinely absent order: still 404 Not found", () => { assert.equal(r.status, 404); assert.ok(/<p>Not found<\/p>/.test(text), text); });

// ---- board
const board = (q = "") => get("/board" + q, { headers: { origin: SITE } });
const CARD = { id: "td_aaaaaaaaaaaa", trade: "roof", total: 1000, flags: [], questions: [], kinds: [], line_count: 1 };

boardCacheClear();
r = await board();
body = await r.json();
chk("board genuinely absent index: still 200 with no cards", () => { assert.equal(r.status, 200); assert.deepEqual(body.cards, []); });

boardCacheClear();
broken.add("board_index");
r = await board();
body = await r.json();
chk("board_index read failure: 503 board_unavailable, not an empty board", () => { assert.equal(r.status, 503); assert.equal(body.error, "board_unavailable"); });
broken.delete("board_index");
await store.put("board_index", JSON.stringify([CARD.id]));
await store.put(`board:${CARD.id}`, JSON.stringify(CARD));
r = await board();
body = await r.json();
chk("after a failed read nothing was cached: the next read shows the card", () => { assert.equal(r.status, 200); assert.equal(body.cards.length, 1); });

boardCacheClear();
broken.add(`board:${CARD.id}`);
r = await board(`?id=${CARD.id}`);
body = await r.json();
chk("board card read failure: 503, not 404 not found", () => { assert.equal(r.status, 503); assert.equal(body.error, "board_unavailable"); });
broken.delete(`board:${CARD.id}`);
boardCacheClear();
r = await board("?id=td_bbbbbbbbbbbb");
chk("board genuinely absent card: still 404", () => assert.equal(r.status, 404));

// ---- publish never writes the shared index
// 2026-10-13 (concurrency audit U5). A publish writes its own board:<id> key only; the old board_index value is read
// by the board and never written. So a publish no longer depends on reading the index, and a board read with the
// index unreadable is still a 503, not a board missing its older cards.
const NEW = "td_cccccccccccc";
const pend = { id: NEW, card: { ...CARD, id: undefined }, status: "pending", submitted_at: new Date().toISOString() };
await store.put(`board_pending:${NEW}`, JSON.stringify(pend));
const publishUrl = async () => { const s = await signPath(SECRET, `/board/review/${NEW}`, 3600000); return s.replace(`/board/review/${NEW}?`, `/board/review/${NEW}/publish?`); };
broken.add("board_index");
r = await get(await publishUrl(), { method: "POST" });
chk("publish with board_index unreadable: the card is published to its own key, the index is not touched", () => {
  assert.equal(r.status, 200);
  assert.equal(store.m.get("board_index"), JSON.stringify([CARD.id]));
  assert.ok(store.m.has(`board:${NEW}`));
  assert.equal(JSON.parse(store.m.get(`board_pending:${NEW}`)).status, "published");
});
boardCacheClear();
r = await board();
chk("board with board_index unreadable after a publish: still 503, not a board without the older cards", () => assert.equal(r.status, 503));
broken.delete("board_index");
boardCacheClear();
r = await board();
body = await r.json();
chk("board with board_index readable: the new card goes in front of the old one, the index value unchanged", () => {
  assert.equal(r.status, 200);
  assert.deepEqual(body.cards.map((c) => c.id), [NEW, CARD.id]);
  assert.deepEqual(JSON.parse(store.m.get("board_index")), [CARD.id]);
});

if (fail) { console.log(`read_failure: ${fail} FAILURES of ${n}`); process.exit(1); }
console.log(`read_failure ok ${n}/${n}`);
