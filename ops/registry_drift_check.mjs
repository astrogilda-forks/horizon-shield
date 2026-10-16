#!/usr/bin/env node
// ops/registry_drift_check.mjs (2026-09-14): the authoritative C16 detector.
//
// C16 is "the MCP registry advertises an older version than the source of truth (main)".
// It kept recurring because server.json is republished by a manual workflow, so a bump on
// main did not reach the registry until someone remembered to run it. The version_sync gate
// test catches server.json vs worker code (P1); it cannot see the registry (P2), which is the
// real recurrence. This checks P2 for every server, and P1 as a best effort.
//
// For every server.json in the repo:
//   P2 (primary, fail-closed): main version (server.json) vs the LIVE registry latest version.
//   P1 (best effort): the worker's declared const SERVER|CONFIG version vs server.json.
// Always queries with &version=latest, so it cannot repeat the "old version reads as latest"
// false alarm that started all of this.
//
// Usage:
//   node ops/registry_drift_check.mjs             live check (needs network to the registry)
//   node ops/registry_drift_check.mjs --selftest  offline logic test with a mock registry
//
// 2026-10-16: the registry answered http 504 for 3 of 10 servers and the job failed red after 21 minutes, although
// nothing had drifted. A registry outage is not drift. Each query now has a 20 s timeout and up to 3 attempts
// (retrying 5xx, 429, timeouts and network errors only). A server the registry still cannot answer for is reported
// as [UNKNOWN] with a ::warning:: annotation and does not fail the job. The job fails only on a finding: P2 version
// mismatch, absent from the registry, not isLatest, P1 mismatch or a non-semver server.json. If every query is
// unknown the job also stays green with a warning; tomorrow's run checks again.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers";
const SEMVER = /^\d+\.\d+\.\d+$/;

function serverJsonPaths() {
  const out = [];
  if (existsSync(path.join(REPO, "server.json"))) out.push("server.json");
  const wdir = path.join(REPO, "workers");
  if (existsSync(wdir)) {
    for (const w of readdirSync(wdir)) {
      const p = path.join("workers", w, "server.json");
      if (existsSync(path.join(REPO, p))) out.push(p);
    }
  }
  return out.sort();
}

function workerVersion(subfolder) {
  if (!subfolder) return null;
  const dir = path.join(REPO, subfolder);
  if (!existsSync(dir)) return null;
  const files = [];
  const walk = (d, depth) => {
    if (depth > 2) return;
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name.startsWith(".")) continue;
      const fp = path.join(d, e.name);
      if (e.isDirectory()) walk(fp, depth + 1);
      else if (/\.(mjs|js)$/.test(e.name) && !e.name.includes(".bak")) files.push(fp);
    }
  };
  try { walk(dir, 0); } catch { return null; }
  const re = /const (?:SERVER|CONFIG)\s*=\s*\{[^}]*?version:\s*"(\d+\.\d+\.\d+)"/;
  for (const f of files.sort()) {
    try { const m = readFileSync(f, "utf8").match(re); if (m) return { version: m[1], file: path.relative(REPO, f) }; } catch {}
  }
  return null;
}

// 2026-09-26: the hint used repository.subfolder, so dev.horizonshield/horizon-shield (whose server.json has no
// repository block) read "server_dir undefined", and it pointed every name at the Actions workflow. That workflow
// logs in with GitHub OIDC, which can only publish io.github.ogasurfproject-jpg/*. A domain name needs the domain's
// own key: mcp-publisher login dns on the operator's Mac. The directory is where the server.json is.
function republishHint(name, sjPath) {
  const dir = path.dirname(sjPath);
  if (name.startsWith("io.github.")) return "republish: Actions 'MCP registry publish', server_dir " + dir;
  const ns = name.split("/")[0];
  const domain = ns.split(".").reverse().join(".");
  return "republish on the operator's Mac (Actions OIDC cannot publish " + ns + "/*): mcp-publisher login dns --domain " + domain + " with the domain key, then cd " + dir + " && mcp-publisher publish";
}

const TIMEOUT_MS = 20000;
const BACKOFF_MS = [5000, 15000];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Retries only what can be the registry's own trouble: 5xx, 429, a timeout or a network error.
// A 4xx answer (other than 429) is returned at once as a hard error. Transient errors that survive
// every attempt are marked transient, and run() reports them as unknown instead of drift.
async function fetchJson(url, fetchFn, sleepFn) {
  let last = "";
  for (let attempt = 0; attempt <= BACKOFF_MS.length; attempt++) {
    if (attempt > 0) await sleepFn(BACKOFF_MS[attempt - 1]);
    let res;
    try {
      res = await fetchFn(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (e) {
      last = e && e.name === "TimeoutError" ? "timeout " + TIMEOUT_MS / 1000 + "s" : "network " + ((e && e.message) || e);
      continue;
    }
    if (res.ok) {
      try { return await res.json(); } catch (e) { last = "bad json"; continue; }
    }
    last = "http " + res.status;
    if (res.status < 500 && res.status !== 429) { const err = new Error(last); err.transient = false; throw err; }
  }
  const err = new Error(last + " after " + (BACKOFF_MS.length + 1) + " attempts");
  err.transient = true;
  throw err;
}

async function registryLatest(name, fetchFn, sleepFn) {
  const url = REGISTRY + "?search=" + encodeURIComponent(name) + "&version=latest";
  const d = await fetchJson(url, fetchFn, sleepFn);
  const hit = (d.servers || []).find((s) => s.server && s.server.name === name);
  if (!hit) return { version: null, isLatest: null, present: false };
  const meta = (hit._meta && hit._meta["io.modelcontextprotocol.registry/official"]) || {};
  return { version: hit.server.version, isLatest: meta.isLatest === true, present: true };
}

async function run(fetchFn, sleepFn = sleep) {
  const rows = [];
  for (const sjPath of serverJsonPaths()) {
    const sj = JSON.parse(readFileSync(path.join(REPO, sjPath), "utf8"));
    const name = sj.name, mainVer = sj.version, subfolder = (sj.repository || {}).subfolder;
    const wv = workerVersion(subfolder);
    let reg, regErr = null, transient = false;
    try { reg = await registryLatest(name, fetchFn, sleepFn); }
    catch (e) { reg = { version: null, isLatest: null, present: false }; regErr = e.message; transient = e.transient === true; }
    const issues = [];
    if (!SEMVER.test(mainVer || "")) issues.push("server.json version not semver: " + JSON.stringify(mainVer));
    if (wv && wv.version !== mainVer) issues.push("P1: worker " + wv.version + " (" + wv.file + ") != server.json " + mainVer);
    let unknown = null;
    if (regErr && transient) unknown = "registry unreachable (" + regErr + "), P2 not checked this run";
    else if (regErr) issues.push("registry query failed: " + regErr);
    else if (!reg.present) issues.push("P2: not found in registry (never published?)");
    else if (reg.version !== mainVer) issues.push("P2: registry " + reg.version + " != main " + mainVer + "  -> " + republishHint(name, sjPath));
    else if (reg.isLatest !== true) issues.push("P2: registry version matches but not marked isLatest");
    rows.push({ name, mainVer, worker: wv ? wv.version : "n/a", registry: reg.present ? reg.version : (regErr ? "err" : "absent"), ok: issues.length === 0, unknown, issues });
  }
  return rows;
}

function report(rows) {
  const ci = !!process.env.GITHUB_ACTIONS;
  for (const r of rows) {
    const tag = !r.ok ? "[DRIFT]  " : r.unknown ? "[UNKNOWN]" : "[OK]     ";
    console.log(tag + " " + r.name.padEnd(50) + " main=" + String(r.mainVer).padEnd(8) + " worker=" + String(r.worker).padEnd(8) + " registry=" + String(r.registry));
    for (const i of r.issues) console.log("          - " + i);
    if (r.unknown) {
      console.log("          - " + r.unknown);
      if (ci) console.log("::warning title=MCP registry unreachable::" + r.name + ": " + r.unknown);
    }
  }
  const bad = rows.filter((r) => !r.ok).length;
  const unk = rows.filter((r) => r.ok && r.unknown).length;
  console.log("");
  console.log("=== " + (rows.length - bad - unk) + "/" + rows.length + " synced, " + bad + " drift, " + unk + " unknown (registry drift check, " + new Date().toISOString().replace(/\.\d{3}Z$/, "Z") + ") ===");
  return bad;
}

if (process.argv.includes("--selftest")) {
  const mainOf = {};
  for (const p of serverJsonPaths()) { const sj = JSON.parse(readFileSync(path.join(REPO, p), "utf8")); mainOf[sj.name] = sj.version; }
  const DRIFT = "io.github.ogasurfproject-jpg/hs-verify-gate";
  const ABSENT = "io.github.ogasurfproject-jpg/hs-hearing";
  const DOWN = "io.github.ogasurfproject-jpg/horizon-shield";   // 504 on every attempt -> unknown, not drift
  const FLAKY = "io.github.ogasurfproject-jpg/hs-partner-001-mcp"; // 504 once, then fine -> OK
  const calls = {};
  const mockFetch = async (url) => {
    const name = new URL(url).searchParams.get("search");
    calls[name] = (calls[name] || 0) + 1;
    if (name === DOWN) return { ok: false, status: 504, json: async () => ({}) };
    if (name === FLAKY && calls[name] === 1) return { ok: false, status: 504, json: async () => ({}) };
    let servers = [];
    if (name !== ABSENT) {
      const v = name === DRIFT ? "0.0.1" : (mainOf[name] || "9.9.9");
      servers = [{ server: { name, version: v }, _meta: { "io.modelcontextprotocol.registry/official": { isLatest: true } } }];
    }
    return { ok: true, json: async () => ({ servers }) };
  };
  const rows = await run(mockFetch, async () => {});
  const flagged = rows.filter((r) => !r.ok).map((r) => r.name);
  report(rows);
  console.log("");
  const gateFlagged = flagged.includes(DRIFT);
  const hearingFlagged = flagged.includes(ABSENT);
  const down = rows.find((r) => r.name === DOWN);
  const flaky = rows.find((r) => r.name === FLAKY);
  const downUnknown = !!down && down.ok && !!down.unknown && calls[DOWN] === BACKOFF_MS.length + 1;
  const flakyOk = !!flaky && flaky.ok && !flaky.unknown && calls[FLAKY] === 2;
  const othersClean = rows.filter((r) => ![DRIFT, ABSENT, DOWN, FLAKY].includes(r.name)).every((r) => r.ok && !r.unknown);
  const pass = gateFlagged && hearingFlagged && downUnknown && flakyOk && othersClean;
  console.log("selftest: forced-drift(gate)=" + gateFlagged + " forced-absent(hearing)=" + hearingFlagged + " 504-always(unknown, not drift)=" + downUnknown + " 504-once(retried, ok)=" + flakyOk + " others-clean=" + othersClean + " => " + (pass ? "PASS" : "FAIL"));
  process.exit(pass ? 0 : 1);
}

const rows = await run((u) => fetch(u));
process.exit(report(rows) ? 1 : 0);
