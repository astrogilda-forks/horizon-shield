// sweep_lease.js: one sweep at a time (2026-10-13, concurrency audit G4 and G5).
//
// The daily cron (18:00Z) and the operator's POST /sweep both run runDailySweep. Two sweeps that overlap write the
// same keys from two stale copies: hist:<sha16> and changes:recent are read whole, appended and put back (G4, one
// sweep's history entry or change line is lost), and the NENRIN window state is created if absent (G5, two sweeps
// opening a window make two salts; the commitment filed on the ledger belongs to one salt and the rows derived
// from the other, which no reader can reconcile). KV has no compare and swap, so the fix is not a cleverer write
// but a single flight: a Durable Object lease. One instance ("sweep"), one block at a time, strongly consistent
// storage. Whoever holds the lease sweeps; the other answers 409 (operator) or skips (cron) and writes nothing.
//
// Fail closed: when the binding is present and the lease call throws, the caller does not sweep (503). When the
// binding is absent (unit tests, the GCP twin, an old wrangler.jsonc) the sweep runs as before, unleased.
//
// The lease has a TTL so a sweep that dies without releasing (an isolate eviction, a thrown error past the finally)
// frees the slot by itself. A sweep is bounded by its subrequest budget and 300 ms per row, well under the TTL.

export const SWEEP_LEASE_NAME = "sweep";
export const SWEEP_LEASE_TTL_MS = 15 * 60 * 1000;   // the cron handler's own wall clock limit
const LEASE_KEY = "lease";

function doJson(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { "content-type": "application/json" } });
}

function randomToken() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export class SweepLeaseDO {
  constructor(state, env) { this.state = state; this.env = env; }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "POST") return doJson({ error: "not_found" }, 404);
    let body;
    try { body = await request.json(); } catch (_e) { return doJson({ error: "bad_json" }, 400); }
    const now = Number.isFinite(body && body.now) ? Number(body.now) : Date.now();

    if (url.pathname === "/acquire") {
      const ttl = Number.isFinite(body && body.ttl_ms) && body.ttl_ms > 0 ? Math.min(Number(body.ttl_ms), SWEEP_LEASE_TTL_MS * 4) : SWEEP_LEASE_TTL_MS;
      const holder = typeof (body && body.holder) === "string" ? body.holder.slice(0, 80) : "unknown";
      // read, decide, write, as one block. This instance takes no other request meanwhile.
      return doJson(await this.state.blockConcurrencyWhile(async () => {
        const cur = await this.state.storage.get(LEASE_KEY);
        if (cur && typeof cur.expires_at === "number" && cur.expires_at > now) {
          return { ok: false, busy: true, holder: cur.holder || null, started_at: cur.started_at || null, expires_at: new Date(cur.expires_at).toISOString() };
        }
        const lease = { token: randomToken(), holder, started_at: new Date(now).toISOString(), expires_at: now + ttl };
        await this.state.storage.put(LEASE_KEY, lease);
        return { ok: true, token: lease.token, holder, started_at: lease.started_at, expires_at: new Date(lease.expires_at).toISOString(),
          ...(cur ? { replaced_expired: { holder: cur.holder || null, started_at: cur.started_at || null } } : {}) };
      }));
    }

    if (url.pathname === "/release") {
      const token = typeof (body && body.token) === "string" ? body.token : null;
      if (!token) return doJson({ error: "token_required" }, 400);
      return doJson(await this.state.blockConcurrencyWhile(async () => {
        const cur = await this.state.storage.get(LEASE_KEY);
        if (!cur || cur.token !== token) return { ok: true, released: false, reason: cur ? "held by another token" : "no lease" };
        await this.state.storage.delete(LEASE_KEY);
        return { ok: true, released: true };
      }));
    }

    if (url.pathname === "/peek") {
      const cur = await this.state.storage.get(LEASE_KEY);
      return doJson({ lease: cur ? { holder: cur.holder || null, started_at: cur.started_at || null, expires_at: new Date(cur.expires_at).toISOString(), expired: !(cur.expires_at > now) } : null });
    }

    return doJson({ error: "not_found" }, 404);
  }
}

// Worker side glue.
// mode "unleased": no binding, the caller may run the old (unserialized) path.
// mode "acquired": run, then release(token) in a finally.
// mode "busy": another sweep holds the lease; do not sweep, write nothing.
// mode "error": the lease could not be taken or the answer was not a lease; do not sweep, write nothing (fail closed).
function stubFor(env) {
  const ns = env && env.SWEEP_LEASE_DO;
  if (!ns || typeof ns.idFromName !== "function" || typeof ns.get !== "function") return null;
  return ns.get(ns.idFromName(SWEEP_LEASE_NAME));
}

export async function acquireSweepLease(env, holder, nowMs) {
  const stub = stubFor(env);
  if (!stub) return { mode: "unleased" };
  try {
    const r = await stub.fetch("https://sweep-lease/acquire", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ holder: holder || "unknown", ttl_ms: SWEEP_LEASE_TTL_MS, now: Number.isFinite(nowMs) ? nowMs : Date.now() }) });
    const j = await r.json().catch(() => null);
    if (!j || typeof j !== "object") return { mode: "error", error: "lease answer was not JSON (http " + r.status + ")" };
    if (j.ok === true && typeof j.token === "string") return { mode: "acquired", token: j.token, holder: j.holder || holder, started_at: j.started_at || null, expires_at: j.expires_at || null };
    if (j.busy === true) return { mode: "busy", holder: j.holder || null, started_at: j.started_at || null, expires_at: j.expires_at || null };
    return { mode: "error", error: String(j.error || ("unexpected lease answer, http " + r.status)).slice(0, 200) };
  } catch (e) {
    return { mode: "error", error: String((e && e.message) || e).slice(0, 200) };
  }
}

export async function releaseSweepLease(env, token) {
  const stub = stubFor(env);
  if (!stub || !token) return false;
  try {
    const r = await stub.fetch("https://sweep-lease/release", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
    const j = await r.json().catch(() => null);
    return !!(j && j.released === true);
  } catch (_e) { return false; }   // the TTL frees it
}
