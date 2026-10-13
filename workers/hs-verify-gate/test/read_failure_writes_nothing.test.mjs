// read_failure_writes_nothing: a failed read of the register must not be written back as an empty register (2026-10-13).
// readRegistry turns a KV failure into {}. POST /watch, the quarantine route and DELETE /watch then saved {} plus their
// one change, so one transient failure during an anonymous POST /watch erased every other row and answered ok:true.
// They now read with readRegistryForWrite and answer 503 without writing. Offline; *.redteam.invalid never resolves.
// Run: node test/read_failure_writes_nothing.test.mjs   (in workers/hs-verify-gate)
import worker from "../src/worker.js";

const CTX = { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } };
globalThis.fetch = async () => new Response("", { status: 404 });   // no well-known files anywhere: fail closed

const failing = new Set();
const store = new Map();
const KV = {
  get: async (k, type) => { if (failing.has(k)) throw new Error("KV read failed (simulated)"); const v = store.has(k) ? store.get(k) : null; return (type === "json" && v !== null) ? JSON.parse(v) : v; },
  put: async (k, v) => { store.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
  delete: async (k) => { store.delete(k); },
  list: async (o) => ({ keys: [...store.keys()].filter((k) => k.startsWith((o && o.prefix) || "")).map((name) => ({ name })), list_complete: true }),
};
const TOKEN = "read-failure-test-token";
const ENV = { HS_VERIFY_KV: KV, SWEEP_TOKEN: TOKEN, GATE_COMMIT: "read-failure-local" };
const O = "https://gate.horizonshield.dev";
const req = (path, method, body, headers) => worker.fetch(new Request(O + path, { method, headers: { "content-type": "application/json", ...(headers || {}) }, body: JSON.stringify(body) }), ENV, CTX);

let pass = 0, fail = 0;
const t = (name, ok, detail = "") => { if (ok) { pass++; console.log("  ok   " + name); } else { fail++; console.log("  NG   " + name + "  " + String(detail).slice(0, 240)); } };

const A = "https://a.redteam.invalid/mcp", B = "https://b.redteam.invalid/mcp", C = "https://c.redteam.invalid/mcp";
const seed = { [A]: { tier: "free", webhook: null, added_at: "2026-10-01T00:00:00Z", requested_by: "anonymous", owner_file_at_request: "absent" },
               [B]: { tier: "free", webhook: null, added_at: "2026-10-02T00:00:00Z", requested_by: "anonymous", owner_file_at_request: "absent" } };
store.set("watch:registry", JSON.stringify(seed));
store.set("watch:removed", JSON.stringify([{ endpoint: "https://old.redteam.invalid/mcp", removed_at: "2026-09-30T00:00:00Z", reason: "an earlier removal" }]));
const regNow = () => JSON.parse(store.get("watch:registry"));

failing.add("watch:registry");
let r = await req("/watch", "POST", { endpoint: C });
let j = await r.json().catch(() => ({}));
t("POST /watch with an unreadable register answers 503, not ok:true", r.status === 503 && j.error === "registry_read_failed", r.status + " " + JSON.stringify(j));
t("and the register still holds both earlier rows (nothing written)", Object.keys(regNow()).sort().join() === [A, B].sort().join(), JSON.stringify(Object.keys(regNow())));

r = await req("/register/quarantine", "POST", { endpoint: A, proposal_sha256: "a".repeat(64), reason: "signature drift on the card" }, { "x-sweep-token": TOKEN });
j = await r.json().catch(() => ({}));
t("quarantine with an unreadable register answers 503", r.status === 503 && j.error === "registry_read_failed", r.status + " " + JSON.stringify(j));
t("and writes nothing", Object.keys(regNow()).length === 2 && !regNow()[A].quarantined);

r = await req("/watch", "DELETE", { endpoint: A, reason: "test removal with an unreadable register" }, { "x-sweep-token": TOKEN });
t("DELETE /watch with an unreadable register answers 503", r.status === 503, r.status);
t("and the row is still there", !!regNow()[A]);
failing.delete("watch:registry");

failing.add("watch:removed");
r = await req("/watch", "DELETE", { endpoint: A, reason: "test removal with an unreadable removed list" }, { "x-sweep-token": TOKEN });
t("DELETE /watch with an unreadable removed list answers 503", r.status === 503, r.status);
t("and neither the row nor the removed list changed", !!regNow()[A] && JSON.parse(store.get("watch:removed")).length === 1);
failing.delete("watch:removed");

r = await req("/watch", "POST", { endpoint: C });
t("with the register readable again, POST /watch adds the row and keeps the others", r.status === 200 && Object.keys(regNow()).length === 3, r.status + " " + JSON.stringify(Object.keys(regNow())));
r = await req("/watch", "DELETE", { endpoint: A, reason: "test removal when everything reads" }, { "x-sweep-token": TOKEN });
t("and DELETE /watch removes one row and appends one stone", r.status === 200 && !regNow()[A] && JSON.parse(store.get("watch:removed")).length === 2, r.status);

console.log(`\n=== ${pass} / ${pass + fail} 合格 (read failure writes nothing, 2026-10-13) ===`);
process.exit(fail ? 1 : 0);
