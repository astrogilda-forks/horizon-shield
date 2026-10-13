import { test } from "node:test";
import assert from "node:assert/strict";
import { makeAgreementDedupeDO } from "./firestore_dedupe_do.mjs";
import { makeKv } from "./kv_firestore.mjs";
import { decideDedupe } from "../nenrin/agreement-v0/agreement_intake.mjs";
import { appendEntry } from "../src/ledger_append.mjs";

// minimal in-memory Firestore: enough for makeAgreementDedupeDO and makeKv (collection/doc get/set/delete,
// runTransaction with txn.get/txn.set + merge). It enforces Firestore's read-before-write rule so the shim is
// proven to respect it, and (2026-10-13, L1r) it models optimistic concurrency the way Firestore does: writes are
// buffered until commit, and a transaction whose read docs changed before commit is re-run. opts.barrier(path)
// names docs whose reads wait until `barrierCount` readers are inside, so two appends provably read the same
// seq before either writes.
function fakeFirestore(opts = {}) {
  const store = new Map(); // path -> { data, ver }
  const ref = (path) => ({ _path: path });
  let arrived = 0, waiters = [];
  const release = () => { const w = waiters; waiters = []; for (const r of w) r(); };
  const gate = async (path) => {
    if (!opts.barrier || !opts.barrier(path)) return;
    arrived++;
    if (arrived < (opts.barrierCount || 2)) await new Promise((r) => { waiters.push(r); setTimeout(release, 2000); });
    else release();
  };
  const snapOf = (path) => { const e = store.get(path); return { exists: e !== undefined, data: () => (e ? e.data : undefined) }; };
  const write = (path, data, merge) => {
    const prev = store.get(path);
    const base = merge && prev ? prev.data : {};
    store.set(path, { data: { ...base, ...data }, ver: (prev ? prev.ver : 0) + 1 });
  };
  const fs = {
    _store: store,
    _data: (path) => (store.get(path) || {}).data,
    collection(name) {
      return {
        doc: (id) => Object.assign(ref(name + "/" + id), {
          async get() { await gate(name + "/" + id); await new Promise((r) => setImmediate(r)); return snapOf(name + "/" + id); },
          async set(data, o) { await new Promise((r) => setImmediate(r)); write(name + "/" + id, data, o && o.merge); },
          async delete() { store.delete(name + "/" + id); },
        }),
      };
    },
    _txnRuns: 0,
    async runTransaction(fn) {
      if (opts.failTxn) throw new Error("firestore unavailable (test)");
      for (let attempt = 0; attempt < 10; attempt++) {
        fs._txnRuns++;
        let wrote = false;
        const reads = new Map(); // path -> ver seen
        const writes = [];
        const txn = {
          async get(r) {
            if (wrote) throw new Error("read after write in transaction");
            await gate(r._path);
            await new Promise((res) => setImmediate(res));
            const e = store.get(r._path);
            reads.set(r._path, e ? e.ver : 0);
            return snapOf(r._path);
          },
          set(r, data, o) { wrote = true; writes.push({ path: r._path, data, merge: !!(o && o.merge) }); },
        };
        const out = await fn(txn);
        await new Promise((res) => setImmediate(res));
        let conflict = false;
        for (const [path, ver] of reads) { const e = store.get(path); if ((e ? e.ver : 0) !== ver) { conflict = true; break; } }
        if (conflict) continue;
        for (const w of writes) write(w.path, w.data, w.merge);
        return out;
      }
      throw new Error("transaction contention: gave up");
    },
  };
  return fs;
}

const claim = (d, sha, payload) =>
  d.get(d.idFromName("agreement:" + sha)).fetch("https://agreement-dedupe/claim", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ sha, payload }),
  });
const getRec = (d, sha) =>
  d.get(d.idFromName("agreement:" + sha)).fetch("https://agreement-dedupe/get", {
    method: "POST", headers: { "content-type": "application/json" }, body: "{}",
  });

test("first claim stores and is not a duplicate (matches decideDedupe)", async () => {
  const d = makeAgreementDedupeDO(fakeFirestore(), "c");
  const p = { canonical_sha256: "aa", who: "x" };
  const r = await (await claim(d, "aa", p)).json();
  assert.deepEqual(r, decideDedupe(null, p));
  assert.equal(r.duplicate, false);
  assert.deepEqual(r.stored, p);
});

test("second claim of the same sha is a duplicate and keeps the first payload", async () => {
  const d = makeAgreementDedupeDO(fakeFirestore(), "c");
  const first = { canonical_sha256: "bb", v: 1 };
  const second = { canonical_sha256: "bb", v: 2 };
  await claim(d, "bb", first);
  const r = await (await claim(d, "bb", second)).json();
  assert.equal(r.duplicate, true);
  assert.deepEqual(r.stored, first);
});

test("get returns the stored record, or null when unknown", async () => {
  const d = makeAgreementDedupeDO(fakeFirestore(), "c");
  const p = { canonical_sha256: "cc" };
  assert.deepEqual(await (await getRec(d, "cc")).json(), { stored: null });
  await claim(d, "cc", p);
  assert.deepEqual(await (await getRec(d, "cc")).json(), { stored: p });
});

test("different shas are independent documents", async () => {
  const fs = fakeFirestore();
  const d = makeAgreementDedupeDO(fs, "c");
  const r1 = await (await claim(d, "d1", { canonical_sha256: "d1" })).json();
  const r2 = await (await claim(d, "d2", { canonical_sha256: "d2" })).json();
  assert.equal(r1.duplicate, false);
  assert.equal(r2.duplicate, false);
  assert.equal(fs._store.size, 2);
});

// ===== 2026-10-13 concurrency audit L1r: /ledger-append on the twin is one Firestore transaction =====
// env as server.mjs builds it: LEDGER is the KV adapter over collection "kv", the DO shim gets the same name.
const H1 = "a".repeat(64), H2 = "b".repeat(64), H3 = "c".repeat(64);
const SEQ_DOC = "kv/" + "k_" + Buffer.from("seq", "utf8").toString("base64url");
function twinEnv(fs) {
  return { LEDGER: makeKv(fs, "kv"), AGREEMENT_DEDUPE_DO: makeAgreementDedupeDO(fs, "c", "kv") };
}
const entryFor = (h, i) => ({ n: 0, type: "ledger_append", claim_sha256: h, i });

test("L1r: two appends in flight get n and n+1, both entries are stored, seq is 2", async () => {
  // both transactions read the seq doc before either commits (barrier on that doc for the first two readers).
  const fs = fakeFirestore({ barrier: (path) => path === SEQ_DOC, barrierCount: 2 });
  const env = twinEnv(fs);
  const [r1, r2] = await Promise.all([appendEntry(env, H1, entryFor(H1, 1)), appendEntry(env, H2, entryFor(H2, 2))]);
  const ns = [r1.n, r2.n].sort();
  assert.deepEqual(ns, [1, 2], "both appends were told the same n: " + JSON.stringify([r1.n, r2.n]));
  assert.equal(r1.dedup, false); assert.equal(r2.dedup, false);
  assert.equal(await env.LEDGER.get("seq"), "2");
  const e1 = JSON.parse(await env.LEDGER.get("entry:1")), e2 = JSON.parse(await env.LEDGER.get("entry:2"));
  assert.ok(e1 && e2, "one entry replaced the other");
  assert.deepEqual([e1.claim_sha256, e2.claim_sha256].sort(), [H1, H2]);
  assert.equal(await env.LEDGER.get("hash:" + H1), String(r1.n));
  assert.equal(await env.LEDGER.get("hash:" + H2), String(r2.n));
  // the losing transaction was re-run, not merged over the winner.
  assert.ok(fs._txnRuns >= 3, "expected a retried transaction, runs=" + fs._txnRuns);
});

test("L1r: the stored bytes are what appendEntryKv writes (n first, caller's key order), via the KV adapter's doc ids", async () => {
  const fs = fakeFirestore();
  const env = twinEnv(fs);
  await env.LEDGER.put("seq", "41"); // seeded through makeKv, read inside the transaction: doc ids agree
  const entry = { n: 0, type: "t", claim_sha256: H1, work: { a: 1 } };
  const r = await appendEntry(env, H1, entry);
  assert.deepEqual(r, { n: 42, dedup: false });
  assert.equal(entry.n, 42, "the caller's entry carries the assigned n");
  assert.equal(await env.LEDGER.get("entry:42"), JSON.stringify({ n: 42, type: "t", claim_sha256: H1, work: { a: 1 } }));
  assert.equal(await env.LEDGER.get("hash:" + H1), "42");
  assert.equal(await env.LEDGER.get("seq"), "42");
  assert.deepEqual(fs._data(SEQ_DOC), { key: "seq", value: "42", expiresAt: null });
  // the dedupe collection is untouched by appends (no DO floor is kept on the twin).
  assert.equal([...fs._store.keys()].filter((k) => k.startsWith("c/")).length, 0);
});

test("L1r: a repeated claim hash is answered as the dedup of its entry and writes nothing", async () => {
  const fs = fakeFirestore();
  const env = twinEnv(fs);
  const a = await appendEntry(env, H3, entryFor(H3, 1));
  const before = JSON.stringify([...fs._store.entries()]);
  const b = await appendEntry(env, H3, entryFor(H3, 2));
  assert.deepEqual(a, { n: 1, dedup: false });
  assert.deepEqual(b, { n: 1, dedup: true });
  assert.equal(JSON.stringify([...fs._store.entries()]), before);
});

test("L1r: when the transaction fails the append throws and nothing is written (no fallback to the racy path)", async () => {
  const fs = fakeFirestore({ failTxn: true });
  const env = twinEnv(fs);
  await assert.rejects(() => appendEntry(env, H1, entryFor(H1, 1)), /ledger_append_unserialized/);
  assert.equal(fs._store.size, 0, "the worker wrote entries without the sequencer");
});

test("L1r: the twin validates like the DO (bad h or entry is 400, never a write)", async () => {
  const fs = fakeFirestore();
  const d = makeAgreementDedupeDO(fs, "c", "kv");
  const stub = d.get(d.idFromName("ledger:seq"));
  const r1 = await stub.fetch("https://ledger-seq/ledger-append", { method: "POST", body: JSON.stringify({ h: "zz", entry: { n: 0 } }) });
  const r2 = await stub.fetch("https://ledger-seq/ledger-append", { method: "POST", body: JSON.stringify({ h: H1, entry: [] }) });
  const r3 = await stub.fetch("https://ledger-seq/ledger-append", { method: "POST", body: "not json" });
  assert.equal(r1.status, 400); assert.equal(r2.status, 400); assert.equal(r3.status, 400);
  assert.equal((await r1.json()).error, "h_and_entry_required");
  assert.equal((await r3.json()).error, "bad_json");
  assert.equal(fs._store.size, 0);
});
