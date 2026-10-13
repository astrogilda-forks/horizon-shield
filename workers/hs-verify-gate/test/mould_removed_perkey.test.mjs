// mould_removed_perkey: two writers of the mould list, or of the removal stones, that overlap must both keep their line
// (2026-10-13). ops/concurrency_audit_20261013.md, findings G2 and G3. Both lists were one KV blob (mould:index,
// watch:removed) that every writer read whole, added one line to and put back whole. The KV mock here holds every
// reader of a blob at a barrier until two readers are inside, which is the interleaving KV allows (both read before
// either writes). On the code before the fix the second put replaced the first: a mould record stayed at mould:<id>
// but dropped off GET /mould, and a removal stone vanished from the public list. Now a mould record's list line rides
// on its own key (mould:<id>, metadata) and a stone is its own key (watch:removed:<sha256(endpoint)>); the old blobs
// are read (migration) and never rewritten or deleted. Offline: *.redteam.invalid never resolves, GitHub is stubbed.
// Run: node test/mould_removed_perkey.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";

const CTX = { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } };
const TOKEN = "test-token";
const O = "https://gate.horizonshield.dev";
const MOULD_BLOB = "mould:index", REMOVED_BLOB = "watch:removed", REG_BLOB = "watch:registry";

// A fake GitHub: issue N carries the mould-record label and a body the parser accepts.
const ISSUES = {};
globalThis.fetch = async (url) => {
  const u = new URL(url);
  const m = /^\/repos\/ogasurfproject-jpg\/horizon-shield\/issues\/(\d+)$/.exec(u.pathname);
  if (u.hostname === "api.github.com" && m && ISSUES[m[1]]) return new Response(JSON.stringify(ISSUES[m[1]]), { status: 200, headers: { "content-type": "application/json" } });
  return new Response("", { status: 404 });
};
const ghIssue = (n) => ({ number: n, html_url: "https://github.com/ogasurfproject-jpg/horizon-shield/issues/" + n, user: { login: "redteam" }, labels: [{ name: "mould-record" }],
  body: "### The assumption\n\nparser split on the wrong column\n\n### Where you first noticed it\n\nworker.js mouldLines\n\n### Where you searched for the same assumption\n\nsrc/\n" });

// KV with metadata, a get counter, a failing set, and a barrier on reads of the named blobs: a reader waits until
// `parties` readers are in, or `waitMs` passes (a writer that never has a second reader alongside it is only delayed).
function racingKV(barrierKeys, parties = 2, waitMs = 150) {
  const store = new Map(), meta = new Map(), failing = new Set();
  let waiting = [];
  const gets = { total: 0 };
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= parties) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, waitMs);
  });
  return {
    store, meta, gets, failing,
    get: async (k, type) => {
      gets.total++;
      if (failing.has(k)) throw new Error("KV read failed (simulated)");
      if (barrierKeys.includes(k)) await arrive();
      const v = store.has(k) ? store.get(k) : null;
      return ((type === "json" || (type && type.type === "json")) && v !== null) ? JSON.parse(v) : v;
    },
    put: async (k, v, opts) => { await Promise.resolve(); store.set(k, typeof v === "string" ? v : JSON.stringify(v)); if (opts && opts.metadata) meta.set(k, structuredClone(opts.metadata)); else meta.delete(k); },
    delete: async (k) => { store.delete(k); meta.delete(k); },
    list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || "")).sort().map((name) => (meta.has(name) ? { name, metadata: meta.get(name) } : { name })), list_complete: true }),
  };
}
const envWith = (kv) => ({ HS_VERIFY_KV: kv, SWEEP_TOKEN: TOKEN, GATE_COMMIT: "perkey-local" });
const req = (env, path, method, body, headers) => worker.fetch(new Request(O + path, { method, headers: { "content-type": "application/json", ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) }), env, CTX);
const asJson = async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) });
const safe = (p) => p.then(asJson, (e) => ({ status: 0, j: { thrown: String((e && e.message) || e) } }));
const AUTH = { "x-sweep-token": TOKEN };

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 240)); } };

const mouldBody = (id, cls) => ({ id, class: cls || "class for " + id, searched: ["src/"], found: [{ where: "worker.js", state: "fixed" }] });
const listIds = async (env) => { const r = await safe(req(env, "/mould", "GET")); return { status: r.status, count: r.j.count, ids: (r.j.records || []).map((x) => x.id), j: r.j }; };

console.log("G2 mould list");
// 1. Two operator records at the same time.
{
  const kv = racingKV([MOULD_BLOB]); const env = envWith(kv);
  const [ra, rb] = await Promise.all([safe(req(env, "/mould", "POST", mouldBody("mould-a"), AUTH)), safe(req(env, "/mould", "POST", mouldBody("mould-b"), AUTH))]);
  t("1 both records answered 201", ra.status === 201 && rb.status === 201, JSON.stringify([ra.status, rb.status]));
  const l = await listIds(env);
  t("1 GET /mould lists both (count 2)", l.count === 2 && l.ids.includes("mould-a") && l.ids.includes("mould-b"), JSON.stringify(l));
  t("1 the old blob was not written", !kv.store.has(MOULD_BLOB));
}

// 2. Two GitHub issues recorded at the same time (the workflow path).
{
  const kv = racingKV([MOULD_BLOB]); const env = envWith(kv);
  ISSUES[101] = ghIssue(101); ISSUES[102] = ghIssue(102);
  const [ra, rb] = await Promise.all([safe(req(env, "/mould/from-issue", "POST", { issue: 101 })), safe(req(env, "/mould/from-issue", "POST", { issue: 102 }))]);
  t("2 both issues answered 201", ra.status === 201 && rb.status === 201 && ra.j.id === "mould-gh-101" && rb.j.id === "mould-gh-102", JSON.stringify([ra.status, rb.status, ra.j.error, rb.j.error]));
  const l = await listIds(env);
  t("2 GET /mould lists both issues", l.count === 2 && l.ids.includes("mould-gh-101") && l.ids.includes("mould-gh-102"), JSON.stringify(l.ids));
  const line = (l.j.records || []).find((x) => x.id === "mould-gh-101");
  t("2 a list line keeps its shape (id, recorded_at, class, searched, found, repro, by, via, record_sha256)", !!line && JSON.stringify(Object.keys(line).sort()) === JSON.stringify(["by", "class", "found", "id", "record_sha256", "recorded_at", "repro", "searched", "via"]) && line.via === "github" && line.by === "redteam" && line.searched === 1 && /^[0-9a-f]{64}$/.test(line.record_sha256), JSON.stringify(line));
  const again = await safe(req(env, "/mould/from-issue", "POST", { issue: 101 }));
  t("2 recording the same issue again is 409 already_recorded", again.status === 409 && again.j.error === "already_recorded", JSON.stringify(again));
}

// 3. Migration: the old blob's lines are listed first in their order, new records are overlaid, the blob is untouched.
{
  const kv = racingKV([]); const env = envWith(kv);
  const blob = JSON.stringify([
    { id: "mould-0002", recorded_at: "2026-09-02T00:00:00.000Z", class: "second", searched: 0, found: 1, repro: 0, by: null, via: "operator", record_sha256: "b".repeat(64) },
    { id: "mould-0001", recorded_at: "2026-09-01T00:00:00.000Z", class: "first", searched: 1, found: 1, repro: 0, by: null, via: "operator", record_sha256: "a".repeat(64) },
  ]);
  kv.store.set(MOULD_BLOB, blob);
  kv.store.set("mould:mould-0001", JSON.stringify({ id: "mould-0001", class: "first", recorded_at: "2026-09-01T00:00:00.000Z" }));
  kv.store.set("mould:mould-0002", JSON.stringify({ id: "mould-0002", class: "second", recorded_at: "2026-09-02T00:00:00.000Z" }));
  // a record that exists but had dropped off the blob (the G2 race, in the past): listed from its key, without metadata
  kv.store.set("mould:mould-lost", JSON.stringify({ id: "mould-lost", class: "lost from the index", recorded_at: "2026-09-03T00:00:00.000Z", searched: ["x"], found: [], reproduce: [], submission: { via: "github", by: "someone" }, record_sha256: "c".repeat(64) }));
  let l = await listIds(env);
  t("3 blob lines and a key only record, newest first", JSON.stringify(l.ids) === JSON.stringify(["mould-lost", "mould-0002", "mould-0001"]) && l.count === 3, JSON.stringify(l.ids));
  const lost = (l.j.records || []).find((x) => x.id === "mould-lost");
  t("3 the key only record's line is derived from the record (via github, by someone, searched 1)", !!lost && lost.via === "github" && lost.by === "someone" && lost.searched === 1 && lost.record_sha256 === "c".repeat(64), JSON.stringify(lost));
  const auto = await safe(req(env, "/mould", "POST", mouldBody("", "auto id counts every record"), AUTH));
  t("3 an operator record without an id gets mould-0004 (3 records counted, blob and key)", auto.status === 201 && auto.j.id === "mould-0004", JSON.stringify([auto.status, auto.j.id]));
  l = await listIds(env);
  t("3 the new record is listed first, the blob's order is kept below it", JSON.stringify(l.ids) === JSON.stringify(["mould-0004", "mould-lost", "mould-0002", "mould-0001"]), JSON.stringify(l.ids));
  t("3 the old blob is byte for byte what it was", kv.store.get(MOULD_BLOB) === blob);
  const one = await asJson(await req(env, "/mould/mould-0004", "GET"));
  t("3 GET /mould/<id> serves the record", one.status === 200 && one.j.id === "mould-0004" && one.j.class === "auto id counts every record", JSON.stringify(one.j).slice(0, 120));
  const dup = await safe(req(env, "/mould", "POST", mouldBody("mould-0001"), AUTH));
  t("3 a blob era id is still append only (409)", dup.status === 409 && dup.j.error === "already_recorded", JSON.stringify(dup));
}

// 4. The already_recorded check reads the record key; a failed read is 503 and writes nothing, never a rewrite.
{
  const kv = racingKV([]); const env = envWith(kv);
  const first = await safe(req(env, "/mould", "POST", mouldBody("mould-x"), AUTH));
  const bytes = kv.store.get("mould:mould-x");
  kv.failing.add("mould:mould-x");
  const r = await safe(req(env, "/mould", "POST", mouldBody("mould-x", "a different class"), AUTH));
  t("4 an unreadable record key answers 503 mould_read_failed, not 201 and not 409", first.status === 201 && r.status === 503 && r.j.error === "mould_read_failed", JSON.stringify([first.status, r.status, r.j]));
  t("4 and the record is byte for byte what it was", kv.store.get("mould:mould-x") === bytes);
  kv.failing.delete("mould:mould-x");
  kv.failing.add(MOULD_BLOB);
  const l = await listIds(env);
  t("4 GET /mould with an unreadable blob answers 503 read_failed, not an empty ledger", l.status === 503 && l.j.read_failed === true && l.j.records === null, JSON.stringify([l.status, l.j.error, l.j.count]));
  kv.failing.delete(MOULD_BLOB);
}

// 5. Reading the list costs one blob get and one list while lines fit in metadata.
{
  const kv = racingKV([]); const env = envWith(kv);
  for (const id of ["mould-p", "mould-q", "mould-r"]) await req(env, "/mould", "POST", mouldBody(id), AUTH);
  const before = kv.gets.total;
  const l = await listIds(env);
  const used = kv.gets.total - before;
  t("5 three records listed", l.count === 3, JSON.stringify(l.ids));
  t("5 without a get per record (blob only)", used <= 1, "gets " + used);
}

console.log("G3 removal stones");
const A = "https://a.redteam.invalid/mcp", B = "https://b.redteam.invalid/mcp", X = "https://x.redteam.invalid/mcp";
const seedRow = (d) => ({ tier: "free", webhook: null, added_at: d, requested_by: "anonymous", owner_file_at_request: "absent" });
const removedList = async (env) => { const r = await safe(req(env, "/watchlist", "GET")); return { j: r.j, eps: (r.j.removed || []).map((s) => s.endpoint), removed: r.j.removed || [] }; };

// 6. Two removals at the same time.
{
  const kv = racingKV([REMOVED_BLOB]); const env = envWith(kv);
  kv.store.set(REG_BLOB, JSON.stringify({ [A]: seedRow("2026-10-01T00:00:00Z"), [B]: seedRow("2026-10-02T00:00:00Z") }));
  const [ra, rb] = await Promise.all([
    safe(req(env, "/watch", "DELETE", { endpoint: A, reason: "the owner asked by mail" }, AUTH)),
    safe(req(env, "/watch", "DELETE", { endpoint: B, reason: "the owner asked on GitHub" }, AUTH)),
  ]);
  t("6 both removals answered ok", ra.status === 200 && ra.j.ok === true && rb.status === 200 && rb.j.ok === true, JSON.stringify([ra, rb]).slice(0, 200));
  const rl = await removedList(env);
  t("6 /watchlist lists both stones", rl.eps.includes(A) && rl.eps.includes(B) && rl.removed.length === 2, JSON.stringify(rl.eps));
  t("6 the old blob was not written", !kv.store.has(REMOVED_BLOB));
  const reg = await asJson(await req(env, "/register", "GET"));
  t("6 /register removed_rows lists both too", Array.isArray(reg.j.removed_rows) && reg.j.removed_rows.length === 2, JSON.stringify(reg.j.removed_rows).slice(0, 200));
}

// 7. Migration: blob stones first in their order, then per-key stones; the blob is untouched; a stone keeps its shape.
{
  const kv = racingKV([]); const env = envWith(kv);
  const blob = JSON.stringify([{ endpoint: X, removed_at: "2026-09-30T00:00:00Z", reason: "an earlier removal", requested_by: "unrecorded", added_at: null, owner_file_at_request: null, history_kept: true }]);
  kv.store.set(REMOVED_BLOB, blob);
  kv.store.set(REG_BLOB, JSON.stringify({ [A]: seedRow("2026-10-01T00:00:00Z") }));
  const r = await safe(req(env, "/watch", "DELETE", { endpoint: A, reason: "removal after the migration" }, AUTH));
  t("7 the removal answered ok", r.status === 200 && r.j.ok === true, JSON.stringify(r).slice(0, 200));
  const rl = await removedList(env);
  t("7 the blob stone first, the new stone after", JSON.stringify(rl.eps) === JSON.stringify([X, A]), JSON.stringify(rl.eps));
  const s = rl.removed[1];
  t("7 the stone keeps its shape", !!s && JSON.stringify(Object.keys(s).sort()) === JSON.stringify(["added_at", "endpoint", "history_kept", "owner_file_at_request", "reason", "removed_at", "requested_by"]) && s.reason === "removal after the migration" && s.requested_by === "anonymous", JSON.stringify(s));
  t("7 the old blob is byte for byte what it was", kv.store.get(REMOVED_BLOB) === blob);
  t("7 no removed_read_failed flag", !("removed_read_failed" in rl.j));
  // re-register A and remove it again: both stones stay listed
  const re = await asJson(await req(env, "/watch", "POST", { endpoint: A }));
  const r2 = await safe(req(env, "/watch", "DELETE", { endpoint: A, reason: "removed a second time" }, AUTH));
  const rl2 = await removedList(env);
  t("7 a second removal of the same endpoint keeps the first stone (3 stones, 2 for A)", re.status === 200 && r2.status === 200 && rl2.removed.length === 3 && rl2.removed.filter((x) => x.endpoint === A).length === 2 && rl2.removed.filter((x) => x.endpoint === A).map((x) => x.reason).sort().join("|") === "removal after the migration|removed a second time", JSON.stringify(rl2.removed.map((x) => [x.endpoint, x.reason])));
  const w = await asJson(await req(env, "/watchlist", "GET"));
  t("7 and A is off the schedule", !(w.j.watched || []).some((x) => x.endpoint === A));
}

// 8. A failed read of this endpoint's own stone is a stop; a failed read of the blob no longer blocks the removal
//    (the blob is not what DELETE writes), and the public list says read_failed rather than listing nothing.
{
  const kv = racingKV([]); const env = envWith(kv);
  kv.store.set(REG_BLOB, JSON.stringify({ [A]: seedRow("2026-10-01T00:00:00Z"), [B]: seedRow("2026-10-02T00:00:00Z") }));
  const sha = async (x) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(x)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const keyA = "watch:removed:" + (await sha(A));
  kv.failing.add(keyA);
  const r = await safe(req(env, "/watch", "DELETE", { endpoint: A, reason: "with the stone key unreadable" }, AUTH));
  t("8 unreadable stone key: 503 and nothing written", r.status === 503 && !kv.store.has(keyA) && [...kv.store.keys()].every((k) => !k.startsWith("watch:reg:")), JSON.stringify([r.status, [...kv.store.keys()]]));
  kv.failing.delete(keyA);
  kv.failing.add(REMOVED_BLOB);
  const r2 = await safe(req(env, "/watch", "DELETE", { endpoint: B, reason: "with the old blob unreadable" }, AUTH));
  t("8 unreadable old blob: the removal proceeds (its stone is its own key)", r2.status === 200 && r2.j.ok === true, JSON.stringify(r2).slice(0, 200));
  const rl = await removedList(env);
  t("8 and the public list reports read_failed while the blob is unreadable (not an empty list)", rl.j.removed === null && rl.j.removed_read_failed === true, JSON.stringify([rl.j.removed, rl.j.removed_read_failed]));
  kv.failing.delete(REMOVED_BLOB);
  const rl2 = await removedList(env);
  t("8 readable again: the stone is listed", rl2.eps.includes(B) && rl2.removed.length === 1, JSON.stringify(rl2.eps));
}

// 9. Reading the stones costs one blob get and one list while stones fit in metadata.
{
  const kv = racingKV([]); const env = envWith(kv);
  kv.store.set(REG_BLOB, JSON.stringify({ [A]: seedRow("2026-10-01T00:00:00Z"), [B]: seedRow("2026-10-02T00:00:00Z"), [X]: seedRow("2026-10-03T00:00:00Z") }));
  for (const ep of [A, B, X]) await req(env, "/watch", "DELETE", { endpoint: ep, reason: "cost test removal" }, AUTH);
  const before = kv.gets.total;
  const rl = await removedList(env);
  const used = kv.gets.total - before;
  t("9 three stones listed", rl.removed.length === 3, JSON.stringify(rl.eps));
  t("9 without a get per stone (register blob + legacy list + removed blob at most)", used <= 3, "gets " + used);
}

console.log(`\n=== ${pass} / ${pass + fail} 合格 (mould list and removal stones per key, 2026-10-13) ===`);
process.exit(fail ? 1 : 0);
