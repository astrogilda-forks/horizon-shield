/* 2026-10-13. ops/concurrency_audit_20261013.md, finding H1: two estimate files uploaded at the same time must both
   stay on the store's list. A LINE message with several photos arrives as one webhook per photo, so uploads overlap.
   The list used to be one KV value (estfiles:<store>) that each upload read, pushed onto and put back; the KV mock here
   holds every reader of it at a barrier until two are inside (both read before either writes), which KV allows, and on
   the code before the fix the second put dropped the first photo from the unread list. Now the list is built from the
   files' own keys. Offline: a copy of the real src, KV and fetch mocked, nothing leaves this machine. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRCDIR = path.join(HERE, "src");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "hsestrace-"));
for (const f of fs.readdirSync(SRCDIR)) {
  if (!f.endsWith(".js")) continue;
  let body = fs.readFileSync(path.join(SRCDIR, f), "utf8");
  body = body.replace(/from "\.\/([a-z0-9_]+)\.js"/g, 'from "./$1.mjs"');
  fs.writeFileSync(path.join(TMP, f.replace(/\.js$/, ".mjs")), body);
}
const worker = (await import(path.join(TMP, "hearing.mjs"))).default;
globalThis.fetch = async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } });

function racingKV() {
  const m = new Map(), meta = new Map();
  let waiting = [];
  const arrive = () => new Promise((resolve) => {
    waiting.push(resolve);
    if (waiting.length >= 2) { const w = waiting; waiting = []; w.forEach((r) => r()); return; }
    setTimeout(() => { const i = waiting.indexOf(resolve); if (i >= 0) { waiting.splice(i, 1); resolve(); } }, 150);
  });
  const val = (v, type) => (v == null ? null : type === "json" || (type && type.type === "json") ? JSON.parse(v) : v);
  return {
    m, meta,
    async get(k, type) { if (k.startsWith("estfiles:")) await arrive(); return val(m.has(k) ? m.get(k) : null, type); },
    async getWithMetadata(k) { return m.has(k) ? { value: m.get(k), metadata: meta.get(k) || null } : { value: null, metadata: null }; },
    async put(k, v, opts) { await Promise.resolve(); m.set(k, typeof v === "string" ? v : v); if (opts && opts.metadata) meta.set(k, opts.metadata); else meta.delete(k); },
    async delete(k) { m.delete(k); meta.delete(k); },
    async list(o) { const p = (o && o.prefix) || ""; return { keys: [...m.keys()].filter((k) => k.startsWith(p)).sort().map((name) => (meta.has(name) ? { name, metadata: meta.get(name) } : { name })), list_complete: true }; },
  };
}
const ADMIN = "test-admin";
function mkEnv() {
  const kv = racingKV();
  kv.m.set("htok:tok1", JSON.stringify({ store_id: "s1", member_no: "No.001", company: "テスト工務店" }));
  kv.m.set("store:s1", JSON.stringify({ store_id: "s1", member_no: "No.001", company: "テスト工務店" }));
  return { kv, env: { HS_HEARING_KV: kv, HEARING_ADMIN_SECRET: ADMIN } };
}
const pdf = (tag) => new TextEncoder().encode("%PDF-1.4\n% " + tag + "\n");
const upload = (env, name) => worker.fetch(new Request("https://hearing.example.dev/h/tok1/file?name=" + encodeURIComponent(name), { method: "POST", headers: { "content-type": "application/pdf" }, body: pdf(name) }), env, { waitUntil() {} });
const listFiles = async (env) => (await worker.fetch(new Request("https://hearing.example.dev/admin/estimate-files?store=s1", { headers: { "X-Admin-Key": ADMIN } }), env, { waitUntil() {} })).json();
const markRead = async (env, id) => (await worker.fetch(new Request("https://hearing.example.dev/admin/estimate-file-read", { method: "POST", headers: { "X-Admin-Key": ADMIN, "content-type": "application/json" }, body: JSON.stringify({ store: "s1", id }) }), env, { waitUntil() {} })).json();

let fail = 0, n = 0;
const ok = (c, msg, d = "") => { n++; console.log((c ? "ok   " : "FAIL ") + msg + (c ? "" : "  " + String(d).slice(0, 220))); if (!c) fail++; };

// 1. Two photos at the same time.
{
  const { env } = mkEnv();
  const [a, b] = await Promise.all([upload(env, "page1.pdf"), upload(env, "page2.pdf")]);
  ok(a.status === 200 && b.status === 200, "1 both uploads answered ok", a.status + " " + b.status);
  const l = await listFiles(env);
  ok(l.count === 2 && l.unread === 2, "1 both files are on the unread list (fails before)", JSON.stringify(l));
  ok(l.files.map((f) => f.name).sort().join() === "page1.pdf,page2.pdf", "1 by name", JSON.stringify(l.files));
  ok(JSON.stringify(Object.keys(l.files[0])) === JSON.stringify(["id", "name", "type", "size", "at", "via", "read"]), "1 each entry has the same shape as before", JSON.stringify(l.files[0]));
  const r = await markRead(env, l.files[0].id);
  ok(r.ok === true && r.marked === 1 && r.unread === 1, "1 marking one read leaves one unread", JSON.stringify(r));
  const l2 = await listFiles(env);
  ok(l2.files[0].read === true && l2.files[1].read === false && l2.unread === 1, "1 the read mark sticks", JSON.stringify(l2.files));
}

// 2. Migration: an entry and its read flag from the old index are kept; the old index is never rewritten.
{
  const { kv, env } = mkEnv();
  const oldId = "20261001000000000-abc123";
  const oldMeta = { name: "old.pdf", type: "application/pdf", size: 10, at: "2026-10-01T00:00:00.000Z", via: "form" };
  kv.m.set("estfile:s1:" + oldId, "%PDF"); kv.meta.set("estfile:s1:" + oldId, oldMeta);
  const oldIdx = JSON.stringify([{ id: oldId, ...oldMeta, read: true }]);
  kv.m.set("estfiles:s1", oldIdx);
  await upload(env, "new.pdf");
  const l = await listFiles(env);
  ok(l.count === 2 && l.files[0].id === oldId && l.files[0].read === true && l.files[1].read === false, "2 old entry first and still read, new one unread", JSON.stringify(l.files));
  ok(kv.m.get("estfiles:s1") === oldIdx, "2 the old index is byte for byte what it was");
}

console.log(fail ? `estfiles_race ${fail}/${n} FAIL` : `estfiles_race ${n}/${n} 通過`);
fs.rmSync(TMP, { recursive: true, force: true });
process.exit(fail ? 1 : 0);
