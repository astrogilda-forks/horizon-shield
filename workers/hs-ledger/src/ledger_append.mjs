// ledger_append.mjs: the one place that assigns a ledger entry number (imported by src/worker.js and the nenrin pools) (2026-10-13, concurrency audit ops/concurrency_audit_20261013.md, finding L1).
//
// Why. Every append used to do, in eight copies:
//   n = Number(await LEDGER.get("seq")) + 1; put entry:n; put hash:h; put seq
// KV has no compare-and-swap and is eventually consistent. Two appends that overlap (the 00:30 UTC cron and an
// operator's POST /ledger/append or /witness/anchor, a cron delivered twice, two operator scripts) both read the same
// seq and both write entry:<seq+1>. The second put replaces the first entry, so a record that was answered 201 is gone
// from the ledger, its hash:<h> points at an entry that carries a different claim, and a witness batch's records are
// marked anchored in an entry that does not list them. The chain (jidec-chain-v1) is derived from the stored entries,
// so it does not fork; it silently loses the overwritten entry instead.
//
// The fix. The number is assigned, and the three writes made, inside the worker's existing Durable Object class
// (AgreementDedupeDO, binding AGREEMENT_DEDUPE_DO), on one instance named LEDGER_SEQ_DO_NAME, under
// blockConcurrencyWhile. A Durable Object instance runs one request at a time inside that block, and its storage is
// strongly consistent, so it also keeps the highest number it has handed out (ledger_seq) and every claim hash it has
// appended (ledger_hash:<h>). The KV seq stays the value every reader uses; the DO's copy is a floor that a stale KV
// read cannot go below. No new class, so no wrangler migration: the binding and the v1 migration already exist.
//
// When AGREEMENT_DEDUPE_DO is not bound (the unit tests' env, a local run without it), or the DO has no LEDGER (the
// GCP twin), appendEntry falls back to the old unserialized KV sequence, unchanged. Production binds it in
// wrangler.jsonc. When it is bound and the call fails, appendEntry throws and the worker never writes the entry
// itself (the pools stay pending for the next run). If the failure came after the DO had written (a lost reply), a
// retry of the same claim is answered as the dedup of that entry, from ledger_hash:<h>.

export const LEDGER_SEQ_DO_NAME = "ledger:seq";
// Served on GET /health as "sequencer", so ops/prod_fix_check.sh can tell this build is live.
export const LEDGER_SEQUENCER = "do-serialized-20261013";
export const LEDGER_APPEND_PATH = "/ledger-append";

// The old sequence, kept as the single implementation of the three writes. floor: the lowest seq the caller knows
// is already taken (the DO passes its own counter). entry keeps its key order; only entry.n is set here, so the
// stored bytes are exactly what the callers produced before this file existed.
export async function appendEntryKv(kv, h, entry, floor = 0) {
  const dup = await kv.get("hash:" + h);
  if (dup) return { n: Number(dup), dedup: true };
  const n = Math.max(Number((await kv.get("seq")) || 0), Number(floor) || 0) + 1;
  entry.n = n;
  await kv.put("entry:" + n, JSON.stringify(entry));
  await kv.put("hash:" + h, String(n));
  await kv.put("seq", String(n));
  return { n, dedup: false };
}

// Called by the DO (inside blockConcurrencyWhile). storage is the DO's strongly consistent storage.
export async function appendEntrySerialized(storage, kv, h, entry) {
  const known = await storage.get("ledger_hash:" + h);
  if (Number.isSafeInteger(known) && known > 0) return { n: known, dedup: true };
  const floor = Number(await storage.get("ledger_seq")) || 0;
  const r = await appendEntryKv(kv, h, entry, floor);
  if (!r.dedup) await storage.put("ledger_seq", r.n);
  await storage.put("ledger_hash:" + h, r.n);
  return r;
}

// The worker side. h: the entry's claim_sha256 (lowercase hex). entry: the object to store, n first (any value).
// Returns { n, dedup }. dedup:true means hash:<h> was already in the ledger at n and nothing was written.
export async function appendEntry(env, h, entry) {
  const ns = env && env.AGREEMENT_DEDUPE_DO;
  if (!ns) return appendEntryKv(env.LEDGER, h, entry);
  const stub = ns.get(ns.idFromName(LEDGER_SEQ_DO_NAME));
  const r = await stub.fetch("https://ledger-seq" + LEDGER_APPEND_PATH, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ h, entry }),
  });
  let j = null;
  try { j = await r.json(); } catch (_e) { j = null; }
  // The GCP twin (gcp/firestore_dedupe_do.mjs) builds the DO class without env, so it has no LEDGER to write and
  // answers ledger_not_bound. There, and only there, the old sequence runs as before (audit L1, residual). On
  // Cloudflare the DO always has the worker's own env.LEDGER, so this branch is not reachable in production.
  if (r.status === 503 && j && j.error === "ledger_not_bound") return appendEntryKv(env.LEDGER, h, entry);
  if (!r.ok || !j || !Number.isSafeInteger(j.n) || j.n < 1) {
    throw new Error("ledger_append_unserialized: the sequencer answered " + r.status + " " + JSON.stringify(j).slice(0, 160) + "; the worker wrote nothing itself");
  }
  entry.n = j.n;
  return { n: j.n, dedup: !!j.dedup };
}
