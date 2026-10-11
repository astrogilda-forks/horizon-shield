#!/usr/bin/env node
// tsunagi.mjs : the TSUNAGI board's referee, in JavaScript. Score any NENRIN verifier offline the way the nightly
// board's referee does, before you open a pull request. The Python package nenrin-verify ships the same referee
// (nenrin_verify/tsunagi.py); tsunagi.test.mjs holds the two to the same scores.
//
//   npx nenrin-tsunagi list
//   npx nenrin-tsunagi batch-in <corpus> <in.json>
//   npx nenrin-tsunagi score <corpus> <out.json>
//   npx nenrin-tsunagi run <corpus> -- "<your command, with {in} and {out} where the files go>"
//   npx nenrin-tsunagi row <corpus> -- "<your command, with {in} and {out}>"
//
// The contract an implementation meets, in any language:
//   input   {in}:  a JSON array [{"name": <case>, "bundle": <the fixture>}, ...]
//   output  {out}: a JSON object {<case>: {"verdict": str, "refusals": [codes], "findings": [codes]}}
//                  or {<case>: {"error": str}} for a case the implementation could not evaluate
// Codes are compared as sets (VERIFIER.md section 4). A missing case, an extra case, an error or any difference is a
// case not reproduced; nothing is rounded up. Exit 0 only when every case reproduces.
//
// The corpora (interop-v0, interop-v0.1, interop-v0.2/edge) travel in tsunagi_corpora.json, built from the repository
// by build_tsunagi_corpora.mjs; each fixture is the exact text of its file, and that text is what goes into {in}.
import { readFileSync, writeFileSync, statSync, mkdtempSync, rmSync, realpathSync, openSync, closeSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir, constants as osConstants } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
export const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_LIST = 20;

let _pack = null;
function pack() {
  if (!_pack) _pack = JSON.parse(readFileSync(join(HERE, "tsunagi_corpora.json"), "utf8")).corpora;
  return _pack;
}
export const CORPORA = ["nenrin-interop-v0", "nenrin-interop-v0.1", "nenrin-interop-v0.2-edge", "nenrin-interop-v0.2-action-presence", "nenrin-trace-intake-v0", "nenrin-trace-bind-v0", "nenrin-trace-span-v0"];

// Python's string order (by code point) and slicing (by code point), so the two referees print the same thing.
const cp = (a, b) => { const x = Array.from(a), y = Array.from(b); for (let i = 0; i < Math.min(x.length, y.length); i++) { const d = x[i].codePointAt(0) - y[i].codePointAt(0); if (d) return d; } return x.length - y.length; };
const cut = (s, n) => Array.from(s).slice(0, n).join("");
const pyStr = (v) => v === null || v === undefined ? "None" : v === true ? "True" : v === false ? "False" : typeof v === "string" ? v : typeof v === "number" ? String(v) : JSON.stringify(v);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function corpus(name) {
  const p = pack();
  if (!has(p, name)) throw new Error("unknown corpus " + JSON.stringify(name) + "; known: " + [...CORPORA].sort(cp).join(", "));
  return p[name];
}

/** {cases, batch}: the expected cases of a corpus and its batch (parsed), in the order of expected.json. */
export function loadCorpus(name) {
  const c = corpus(name);
  const batch = Object.keys(c.cases).map((k) => ({ name: k, bundle: JSON.parse(c.fixtures[k].text) }));
  return { cases: c.cases, batch };
}

/** The batch file for a corpus, with every fixture's bytes exactly as in the repository. */
export function batchText(name) {
  const c = corpus(name);
  return "[" + Object.keys(c.cases).map((k) => {
    const t = c.fixtures[k].text;
    if (createHash("sha256").update(t, "utf8").digest("hex") !== c.fixtures[k].sha256) throw new Error("fixture " + k + " does not match its sha256");
    return '{"name":' + JSON.stringify(k) + ',"bundle":' + t.trim() + "}";
  }).join(",") + "]";
}

/** The comparable form of a verdict signature, or null when the value is not one. */
export function signature(sig) {
  if (!isObj(sig) || has(sig, "error")) return null;
  const v = sig.verdict, r = sig.refusals, f = sig.findings;
  if (typeof v !== "string" || !Array.isArray(r) || !Array.isArray(f)) return null;
  if (![...r, ...f].every((x) => typeof x === "string")) return null;
  return { verdict: v, refusals: [...new Set(r)].sort(cp), findings: [...new Set(f)].sort(cp) };
}

/** One line for a signature, as on the board. */
export function short(sig) {
  if (sig === null || sig === undefined) return "no signature";
  const s = sig.verdict + " [" + sig.refusals.join(",") + "] [" + sig.findings.join(",") + "]";
  return Array.from(s).length <= 200 ? s : cut(s, 197) + "...";
}

const same = (a, b) => a.verdict === b.verdict && a.refusals.join("\u0000") === b.refusals.join("\u0000") && a.refusals.length === b.refusals.length && a.findings.join("\u0000") === b.findings.join("\u0000") && a.findings.length === b.findings.length;

/** Compare an implementation's output with the frozen expectations, case by case. */
export function score(cases, out) {
  const names = Object.keys(cases);
  if (!isObj(out)) {
    return { reproduced: 0, of: names.length, per_vector: {}, missing: [...names].sort(cp), extra: [], problem: "the output is not a JSON object keyed by case name" };
  }
  const per = {}; let ok = 0;
  for (const k of names) {
    const want = signature(cases[k].expect);
    const raw = has(out, k) ? out[k] : undefined;
    const got = signature(raw);
    const hit = got !== null && want !== null && same(got, want);
    if (hit) ok++;
    const e = { ok: hit, got: got ? short(got) : null, want: short(want) };
    if (raw === undefined || raw === null) e.problem = "missing";
    else if (got === null) e.problem = isObj(raw) && has(raw, "error") ? "error: " + cut(pyStr(raw.error), 160) : "not a verdict signature";
    per[k] = e;
  }
  const extra = Object.keys(out).filter((k) => !has(cases, k)).map((k) => cut(String(k), 120)).sort(cp);
  const res = { reproduced: ok, of: names.length, per_vector: per, missing: names.filter((k) => !has(out, k)).sort(cp), extra: extra.slice(0, MAX_LIST) };
  if (extra.length > MAX_LIST) res.extra_more = extra.length - MAX_LIST;
  return res;
}

const pyErr = (name, msg) => { const x = new Error(msg); x.name = name; return x; };
export const MAX_DEPTH = 980; // the board runs Python 3.11, whose json stops a little under 1000 levels (3.12+: about 10,000)

/** JSON as Python's json.loads reads it: NaN, Infinity and -Infinity are numbers, a key seen twice keeps its last
 * value, "__proto__" is an ordinary key, and nesting deeper than MAX_DEPTH is a RecursionError. */
export function parsePyJson(text) {
  let i = 0;
  const n = text.length;
  const ws = () => { while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++; };
  const bad = (m) => pyErr("JSONDecodeError", m + " at char " + i);
  const NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/y;
  function str() {
    i++; let out = "";
    for (;;) {
      if (i >= n) throw bad("Unterminated string");
      const c = text[i];
      if (c === '"') { i++; return out; }
      if (c === "\\") {
        const e = text[i + 1];
        const m = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (e in m) { out += m[e]; i += 2; continue; }
        if (e === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 6; continue; }
        throw bad("Invalid \\escape");
      }
      if (c.charCodeAt(0) < 0x20) throw bad("Invalid control character");
      out += c; i++;
    }
  }
  function val(depth) {
    ws();
    if (i >= n) throw bad("Expecting value");
    const c = text[i];
    if ((c === "{" || c === "[") && depth > MAX_DEPTH) throw pyErr("RecursionError", "maximum recursion depth exceeded while decoding a JSON document");
    if (c === "{") {
      i++; const o = Object.create(null); ws();
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws(); if (text[i] !== '"') throw bad("Expecting property name enclosed in double quotes");
        const k = str(); ws();
        if (text[i] !== ":") throw bad("Expecting ':' delimiter"); i++;
        o[k] = val(depth + 1); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return o; }
        throw bad("Expecting ',' delimiter");
      }
    }
    if (c === "[") {
      i++; const a = []; ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(val(depth + 1)); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return a; }
        throw bad("Expecting ',' delimiter");
      }
    }
    if (c === '"') return str();
    for (const [w, v] of [["true", true], ["false", false], ["null", null], ["NaN", NaN], ["Infinity", Infinity], ["-Infinity", -Infinity]]) {
      if (text.startsWith(w, i)) { i += w.length; return v; }
    }
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (m) { i += m[0].length; return Number(m[0]); }
    throw bad("Expecting value");
  }
  const v = val(1); ws();
  if (i !== n) throw bad("Extra data");
  return v;
}

/** An implementation's output file, refused when too large, not UTF-8 or not JSON. Errors carry Python's names. */
export function readOutput(path) {
  let st;
  try { st = statSync(path); } catch (e) { throw pyErr(e && e.code === "ENOENT" ? "FileNotFoundError" : "OSError", String(e.message)); }
  if (st.size > MAX_OUTPUT_BYTES) throw pyErr("ValueError", "output larger than " + MAX_OUTPUT_BYTES + " bytes");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(path)); } catch (e) { throw pyErr("UnicodeDecodeError", String(e.message)); }
  return parsePyJson(text);
}

/** Write the batch, run cmd (an argv list; {in} and {out} are replaced), read the output and score it. */
export function run(name, cmd, { cwd, env, timeoutSec = 900 } = {}) {
  const { cases } = loadCorpus(name);
  const t = mkdtempSync(join(tmpdir(), "tsunagi-"));
  try {
    const inp = join(t, "in.json"), outp = join(t, "out.json");
    writeFileSync(inp, batchText(name));
    const argv = cmd.map((a) => a.split("{in}").join(inp).split("{out}").join(outp));
    // stderr goes to a file (no buffer limit, as Python's capture_output); stdout is not read, by either referee.
    const errp = join(t, "stderr.txt");
    const efd = openSync(errp, "w");
    let p;
    try {
      p = spawnSync(argv[0], argv.slice(1), { cwd, env: Object.assign({}, process.env, env || {}), stdio: ["inherit", "ignore", efd], timeout: timeoutSec * 1000, killSignal: "SIGKILL" });
    } finally { closeSync(efd); }
    let code, stderr = "";
    try { const b = readFileSync(errp); stderr = b.subarray(Math.max(0, b.length - 4096)).toString("utf8"); } catch (_e) { /* no stderr */ }
    if (p.error && p.error.code === "ENOENT") { code = 127; stderr = String(p.error.message); }
    else if (p.error && p.error.code === "ETIMEDOUT") { code = 124; stderr = "timeout after " + timeoutSec + "s"; }
    else if (p.error) throw pyErr(p.error.code === "EACCES" ? "PermissionError" : "OSError", String(p.error.message));
    else code = p.status !== null ? p.status : -((osConstants.signals && osConstants.signals[p.signal]) || 1);
    let out;
    try { out = readOutput(outp); } catch (x) {
      const res = score(cases, null);
      return Object.assign(res, { exit: code, problem: "no readable output file (" + x.name + ")", stderr_tail: stderr.trim().slice(-300) });
    }
    return Object.assign(score(cases, out), { exit: code });
  } finally { rmSync(t, { recursive: true, force: true }); }
}

/** Python's shlex.split(s) (POSIX mode, no comments): splits on space, tab, CR and LF only; inside double quotes a
 * backslash escapes only " and itself; outside quotes it escapes any character; a trailing backslash or an open quote
 * is a ValueError, as in Python. */
export function shlexSplit(s) {
  const WS = " \t\r\n";
  const out = []; let cur = "", inTok = false, q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q === "'") { if (ch === "'") q = null; else cur += ch; continue; }
    if (q === '"') {
      if (ch === '"') q = null;
      else if (ch === "\\") {
        if (i + 1 >= s.length) throw pyErr("ValueError", "No closing quotation");
        const nx = s[++i];
        cur += nx === '"' || nx === "\\" ? nx : "\\" + nx;
      } else cur += ch;
      continue;
    }
    if (WS.includes(ch)) { if (inTok) { out.push(cur); cur = ""; inTok = false; } continue; }
    inTok = true;
    if (ch === "'" || ch === '"') q = ch;
    else if (ch === "\\") { if (i + 1 >= s.length) throw pyErr("ValueError", "No escaped character"); cur += s[++i]; }
    else cur += ch;
  }
  if (q) throw pyErr("ValueError", "No closing quotation");
  if (inTok) out.push(cur);
  return out;
}

function printResult(name, res) {
  for (const [k, v] of Object.entries(res.per_vector)) {
    if (v.ok) console.log("ok   " + k + "  " + v.got);
    else console.log("NG   " + k + "  want " + v.want + "  got " + pyStr(v.got) + (v.problem ? "  (" + v.problem + ")" : ""));
  }
  for (const k of res.extra || []) console.log("NG   " + k + "  not in the corpus");
  if (res.problem) console.log("problem: " + res.problem);
  console.log(name + ": " + res.reproduced + "/" + res.of + " verdict signatures reproduced (refereed by nenrin-tsunagi)");
}

const asciiJson = (o) => JSON.stringify(o, null, 2).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
const USAGE = readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 18).map((l) => l.replace(/^\/\/ ?/, "")).join("\n");

export function main(argv = process.argv.slice(2)) {
  const a = [...argv];
  if (!a.length || a[0] === "-h" || a[0] === "--help") { console.log(USAGE); return a.length ? 0 : 2; }
  const cmd = a[0];
  try {
    if (cmd === "list") {
      for (const n of [...CORPORA].sort(cp)) console.log(n.padEnd(26) + " " + String(Object.keys(corpus(n).cases).length).padStart(3) + " cases");
      return 0;
    }
    if (cmd === "batch-in" && a.length === 3) {
      writeFileSync(a[2], batchText(a[1]));
      console.log("wrote " + Object.keys(corpus(a[1]).cases).length + " cases of " + a[1] + " to " + a[2]);
      return 0;
    }
    if (cmd === "score" && a.length === 3) {
      const { cases } = loadCorpus(a[1]);
      const res = score(cases, readOutput(a[2]));
      printResult(a[1], res);
      return res.reproduced === res.of && !res.extra.length ? 0 : 1;
    }
    if ((cmd === "run" || cmd === "row") && a.length >= 4 && a[2] === "--") {
      const name = a[1];
      let user = a.slice(3);
      if (user.length === 1) user = shlexSplit(user[0]);
      if (!user.some((x) => x.includes("{in}")) || !user.some((x) => x.includes("{out}"))) { console.error("the command must contain {in} and {out}"); return 2; }
      if (cmd === "row") {
        const n = Object.keys(corpus(name).cases).length;
        console.log(asciiJson({ corpus: name, cwd: "@impl", cmd: user.map((x) => x.split("{in}").join("@in").split("{out}").join("@out")), parse: "batch_referee", total: n }));
        return 0;
      }
      const res = run(name, user);
      printResult(name, res);
      return res.reproduced === res.of && !res.extra.length && res.exit === 0 ? 0 : 1;
    }
  } catch (e) {
    // Python's referee stops with a traceback (exit 1) on these: unknown corpus, unreadable output, bad quoting.
    console.error((e && e.name ? e.name + ": " : "") + String(e && e.message || e));
    return 1;
  }
  console.error(USAGE);
  return 2;
}

let isMain = false;
try { isMain = !!process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; } catch (_e) { /* imported as a library */ }
if (isMain) process.exit(main());
