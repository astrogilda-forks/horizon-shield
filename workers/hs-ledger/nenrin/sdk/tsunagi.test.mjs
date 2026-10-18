// tsunagi.test.mjs : the JavaScript referee (tsunagi.mjs) against the corpora it carries, against this package's own
// verifier, and against the Python referee (sdk-python, nenrin_verify/tsunagi.py) on the same outputs.
//   node tsunagi.test.mjs
// The Python comparison runs when python3 and ../sdk-python/src are present (in this repository and in CI); outside
// the repository it is skipped and says so.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as T from "./tsunagi.mjs";
import { build } from "./build_tsunagi_corpora.mjs";
import { verifyProvenance, didKeyResolver } from "./nenrin_verify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DASH = new RegExp("[" + String.fromCharCode(0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xFF0D) + "]");
let fail = 0, pass = 0;
const chk = (n, c, x = "") => { console.log((c ? "PASS  " : "FAIL  ") + n + (c ? "" : "  <<< " + String(x).slice(0, 300))); c ? pass++ : fail++; };
const SIZES = { "nenrin-interop-v0": 5, "nenrin-interop-v0.1": 13, "nenrin-interop-v0.2-edge": 36, "nenrin-interop-v0.2-action-presence": 9, "nenrin-interop-v0.3-survivors": 9 };

// 1. the packed corpora are what the repository builds
const inRepo = existsSync(join(HERE, "..", "interop-v0", "expected.json"));
if (inRepo) chk("tsunagi_corpora.json is what build_tsunagi_corpora.mjs builds from the repository, byte for byte", readFileSync(join(HERE, "tsunagi_corpora.json"), "utf8") === build());
else console.log("SKIP  corpora rebuild (outside the repository)");

// 2. sizes, order, and the batch carries each fixture's bytes
for (const [n, k] of Object.entries(SIZES)) {
  const { cases, batch } = T.loadCorpus(n);
  chk(n + ": " + k + " cases, batch in expected.json order", Object.keys(cases).length === k && batch.length === k && batch.map((c) => c.name).join() === Object.keys(cases).join());
  const parsed = JSON.parse(T.batchText(n));
  chk(n + ": batch text parses to the same batch", JSON.stringify(parsed) === JSON.stringify(batch));
  if (inRepo) {
    const dir = { "nenrin-interop-v0": "interop-v0", "nenrin-interop-v0.1": "interop-v0.1", "nenrin-interop-v0.2-edge": "interop-v0.2/edge", "nenrin-interop-v0.2-action-presence": "interop-v0.2/action-presence", "nenrin-interop-v0.3-survivors": "interop-v0.3/survivors" }[n];
    const first = Object.keys(cases)[0];
    chk(n + ": the batch holds the fixture file's text", T.batchText(n).includes(readFileSync(join(HERE, "..", dir, "fixtures", first + ".json"), "utf8").trim()));
  }
}

// 3. this package's verifier reproduces every case, in process and through `run`
const own = (n) => { const o = {}; for (const c of T.loadCorpus(n).batch) { const p = verifyProvenance(Object.assign({}, c.bundle, { resolve: didKeyResolver })); o[c.name] = { verdict: p.verdict, refusals: p.refusals.map((r) => r.code), findings: p.findings.map((f) => f.code) }; } return o; };
for (const n of Object.keys(SIZES)) {
  const r = T.score(T.loadCorpus(n).cases, own(n));
  chk(n + ": nenrin_verify.mjs reproduces " + r.reproduced + "/" + r.of, r.reproduced === r.of && r.of === SIZES[n], JSON.stringify(Object.entries(r.per_vector).filter(([, v]) => !v.ok)));
}
const rr = T.run("nenrin-interop-v0.2-edge", [process.execPath, join(HERE, "tsunagi_reference_batch.mjs"), "{in}", "{out}"]);
chk("run: tsunagi_reference_batch.mjs scores 36/36, exit 0", rr.exit === 0 && rr.reproduced === 36, JSON.stringify(rr).slice(0, 300));
const rn = T.run("nenrin-interop-v0", [process.execPath, "-e", "0", "{in}", "{out}"]);
chk("run: a command that writes nothing scores 0 with the reason", rn.reproduced === 0 && /no readable output file \(FileNotFoundError\)/.test(rn.problem));
const re = T.run("nenrin-interop-v0", [process.execPath, "-e", "process.stderr.write('ImportError: no module named atlas\\n'); process.exit(1)", "{in}", "{out}"]);
chk("run: a failing command keeps its stderr tail for the report (#48)", re.reproduced === 0 && /ImportError: no module named atlas/.test(re.stderr_tail || ""), JSON.stringify(re).slice(0, 300));
{
  // aeoess/agent-governance-vocabulary#177 (2026-10-18): a full count with a non zero exit must not read as a pass on the last line
  const cli = spawnSync(process.execPath, [join(HERE, "tsunagi.mjs"), "run", "nenrin-interop-v0", "--", process.execPath, "-e", "require('child_process').execFileSync(process.execPath, [" + JSON.stringify(join(HERE, "tsunagi_reference_batch.mjs")) + ", process.argv[1], process.argv[2]]); process.exit(1)", "{in}", "{out}"], { encoding: "utf8" });
  const last = cli.stdout.trim().split("\n").pop();
  chk("run CLI: the last line says not a pass when the command exited 1", cli.status === 1 && last === "nenrin-interop-v0: 5/5 verdict signatures reproduced (refereed by nenrin-tsunagi); not a pass: the command exited 1", last);
}
const rm = T.run("nenrin-interop-v0", ["/nonexistent/verifier-binary", "{in}", "{out}"]);
chk("run: a command that does not exist exits 127", rm.exit === 127 && rm.reproduced === 0);
{
  const deep = (d) => '{"a":'.repeat(d) + "1" + "}".repeat(d);
  let e3000 = null; try { T.parsePyJson(deep(3000)); } catch (e) { e3000 = e.name; }
  chk("nesting: 980 levels read, 3000 refused as RecursionError (the board runs Python 3.11, which stops a little under 1000)", T.parsePyJson(deep(980)) !== null && e3000 === "RecursionError");
}
{
  const t0 = Date.now();
  const rt = T.run("nenrin-interop-v0", ["sh", "-c", "trap '' TERM; sleep 60", "{in}", "{out}"], { timeoutSec: 1 });
  chk("run: a verifier that ignores SIGTERM is stopped at the timeout (exit 124, " + (Date.now() - t0) + " ms)", rt.exit === 124 && Date.now() - t0 < 15000);
}

// 4. scoring rules
{
  const { cases } = T.loadCorpus("nenrin-interop-v0");
  const names = Object.keys(cases);
  const out = own("nenrin-interop-v0");
  out[names[0]].findings = [...out[names[0]].findings, ...out[names[0]].findings];
  chk("codes are compared as sets (a duplicate code counts once)", T.score(cases, out).reproduced === 5);
  delete out[names[0]]; out[names[1]] = { error: "boom" };
  out[names[2]] = Object.assign({}, out[names[2]], { verdict: out[names[2]].verdict === "accepted" ? "refused" : "accepted" });
  out["not-a-case"] = { verdict: "accepted", refusals: [], findings: [] };
  const r = T.score(cases, out);
  chk("a missing case, an error, a wrong verdict and an extra case each count against", r.reproduced === 2 && r.missing.join() === names[0] && r.extra.join() === "not-a-case" && r.per_vector[names[1]].problem === "error: boom");
  chk("a value that is not a verdict signature is not one", T.signature({ verdict: "accepted", refusals: "x", findings: [] }) === null && T.signature({ verdict: 1, refusals: [], findings: [] }) === null && T.signature(null) === null && T.signature({ verdict: "accepted", refusals: [1], findings: [] }) === null);
  chk("an output that is not an object scores 0", T.score(cases, ["not", "an", "object"]).reproduced === 0);
}
chk("shlexSplit follows shlex.split on quotes and escapes", JSON.stringify(T.shlexSplit(`python3 'my file.py' "a \\"b\\"" c\\ d {in} {out}`)) === JSON.stringify(["python3", "my file.py", 'a "b"', "c d", "{in}", "{out}"]));

// 5. the Python referee gives the same answers on the same outputs. tsunagi.py is stdlib only and finds its corpora
//    beside itself, so it runs as a plain script, the way tools/tsunagi/run_board.py loads it.
const PYMOD = join(HERE, "..", "sdk-python", "src", "nenrin_verify");
const py = spawnSync("python3", ["-c", "import json, shlex, subprocess, tempfile"], { encoding: "utf8" });
if (!existsSync(join(PYMOD, "tsunagi.py")) || py.status !== 0) {
  console.log("SKIP  Python parity (python3 or ../sdk-python/src/nenrin_verify/tsunagi.py not present)");
} else {
  const env = Object.assign({}, process.env, { PYTHONDONTWRITEBYTECODE: "1" });
  const PYT = join(PYMOD, "tsunagi.py");
  const pyc = (code, ...args) => execFileSync("python3", ["-c", "import sys; sys.path.insert(0, " + JSON.stringify(PYMOD) + ")\nimport json, tsunagi as T\n" + code, ...args], { env, encoding: "utf8" }).trim();
  const PYJSON = "json.dumps(%s, sort_keys=True, ensure_ascii=False, separators=(',', ':'))";
  const jsj = (v) => JSON.stringify(sortKeys(v), (k, x) => (typeof x === "number" && !Number.isFinite(x) ? String(x) : x));
  const t = mkdtempSync(join(tmpdir(), "tsunagi-parity-"));
  try {
    const outs = [];
    for (const n of Object.keys(SIZES)) {
      const names = Object.keys(T.loadCorpus(n).cases);
      const good = own(n);
      outs.push([n, "all right", JSON.stringify(good)]);
      const m = JSON.parse(JSON.stringify(good));
      m[names[0]] = null; m[names[1]] = { error: "e".repeat(300) + "\u00e9" }; delete m[names[2]];
      if (names[3]) m[names[3]] = { verdict: "accepted", refusals: ["z", "a", "a", "\u00e9", "\uffff", "\ud83d\ude00"], findings: ["\uffff", "\ud83d\ude00"] };
      if (names[4]) m[names[4]] = { verdict: "x".repeat(250), refusals: [], findings: [] };
      for (let i = 0; i < 23; i++) m["extra-" + String(i).padStart(2, "0") + "-\u00fc" + "y".repeat(130)] = { verdict: "accepted", refusals: [], findings: [] };
      outs.push([n, "mutated", JSON.stringify(m)]);
      outs.push([n, "a NaN timing field beside every signature", JSON.stringify(good).replace(/"findings":/g, '"ms":NaN,"findings":')]);
      outs.push([n, "a key twice, the last one counts", JSON.stringify(good).replace(/^\{/, "{" + JSON.stringify(names[0]) + ':{"error":"first"},')]);
      outs.push([n, "not an object", "[1,2,3]"]);
      outs.push([n, "string", '"nope"']);
    }
    let i = 0;
    for (const [n, label, text] of outs) {
      const f = join(t, "o" + (i++) + ".json");
      writeFileSync(f, text);
      const pyRes = pyc("c, _ = T.load_corpus(sys.argv[1])\nprint(" + PYJSON.replace("%s", "T.score(c, T.read_output(sys.argv[2]))") + ")", n, f);
      const jsRes = jsj(T.score(T.loadCorpus(n).cases, T.readOutput(f)));
      chk("Python parity, score(): " + n + ", " + label, pyRes === jsRes, "py " + pyRes.slice(0, 160) + " | js " + jsRes.slice(0, 160));
      const pyCli = spawnSync("python3", [PYT, "score", n, f], { env, encoding: "utf8" });
      const jsCli = spawnSync(process.execPath, [join(HERE, "tsunagi.mjs"), "score", n, f], { encoding: "utf8" });
      chk("Python parity, `score` CLI output and exit: " + n + ", " + label, pyCli.stdout === jsCli.stdout && pyCli.status === jsCli.status, "py exit " + pyCli.status + " js exit " + jsCli.status + "\n" + diffFirst(pyCli.stdout, jsCli.stdout));
    }
    // run(): the same command through both referees, including outputs Python cannot read and processes that do not end well
    const W = (content) => [process.execPath, "-e", "require('fs').writeFileSync(process.argv[2], " + content + ")", "{in}", "{out}"];
    const runs = [
      ["the reference batch", [process.execPath, join(HERE, "tsunagi_reference_batch.mjs"), "{in}", "{out}"], 900],
      ["writes nothing", [process.execPath, "-e", "0", "{in}", "{out}"], 900],
      ["exits 3 after writing the right answers", [process.execPath, "-e", "require('child_process').execFileSync(process.execPath, [" + JSON.stringify(join(HERE, "tsunagi_reference_batch.mjs")) + ", process.argv[1], process.argv[2]]); process.exit(3)", "{in}", "{out}"], 900],
      ["invalid UTF-8", W("Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])"), 900],
      ["a UTF-8 byte order mark", W("'\\ufeff{}'"), 900],
      ["nested 100000 deep", W("'{\"a\":'.repeat(100000) + '1' + '}'.repeat(100000)"), 900],
      ["larger than 16 MB", W("'[' + '0,'.repeat(8400000) + '0]'"), 900],
      ["killed by SIGKILL", ["sh", "-c", "kill -9 $$", "{in}", "{out}"], 900],
      ["ignores SIGTERM past the timeout", ["sh", "-c", "trap '' TERM; sleep 20", "{in}", "{out}"], 1],
      ["does not exist", [join(t, "no-such-verifier"), "{in}", "{out}"], 900],
    ];
    for (const [label, argv, to] of runs) {
      const pyRes = pyc("r = T.run(sys.argv[1], json.loads(sys.argv[2]), timeout=int(sys.argv[3]))\nprint(" + PYJSON.replace("%s", "r") + ")", "nenrin-interop-v0", JSON.stringify(argv), String(to));
      const jsRes = jsj(T.run("nenrin-interop-v0", argv, { timeoutSec: to }));
      const strip = (x) => x.replace(/"stderr_tail":"[^"]*"/, '"stderr_tail":"."');
      // nested 100000 deep: whether Python's json reads it at all depends on the build and the stack it runs on
      // (CPython on Linux raises RecursionError; Homebrew CPython 3.14 on macOS reads it). Either way no case is
      // reproduced, so that is what is compared there: the same count, zero, of the same total.
      const score0 = (x) => { const o = JSON.parse(x); return o.reproduced === 0 ? "0/" + o.of : "reproduced " + o.reproduced; };
      const same = label === "does not exist" ? strip(pyRes) === strip(jsRes)
        : label.startsWith("nested") ? score0(pyRes) === score0(jsRes) && score0(jsRes).startsWith("0/")
        : pyRes === jsRes;
      chk("Python parity, run(): " + label, same, "py " + pyRes.slice(-220) + " | js " + jsRes.slice(-220));
    }
    // shlex: the command string a person types for run and row
    for (const c of [`python3 'my file.py' "a \\"b\\"" c\\ d {in} {out}`, `a\\$b "x\\$y" "p\\\\q" 'r\\s'`, "a\u00a0b\u3000c\u000bd\fe", `x "" '' y`, `a"b c"d`, "trail\\", `open "quote`, "line\\\nbreak \"in\\\nside\""]) {
      const pyR = pyc("import shlex\ntry:\n    print(json.dumps(shlex.split(sys.argv[1]), ensure_ascii=False, separators=(',', ':')))\nexcept ValueError as e:\n    print('ValueError: ' + str(e))", c);
      let jsR; try { jsR = JSON.stringify(T.shlexSplit(c)); } catch (e) { jsR = e.name + ": " + e.message; }
      chk("Python parity, shlex.split: " + JSON.stringify(c), pyR === jsR, "py " + pyR + " | js " + jsR);
    }
    for (const n of Object.keys(SIZES)) {
      const a = spawnSync("python3", [PYT, "row", n, "--", "python3 'v\u00e9rif\u007f.py' {in} {out}"], { env, encoding: "utf8" });
      const b = spawnSync(process.execPath, [join(HERE, "tsunagi.mjs"), "row", n, "--", "python3 'v\u00e9rif\u007f.py' {in} {out}"], { encoding: "utf8" });
      chk("Python parity, `row`: " + n, a.stdout === b.stdout && a.status === 0 && b.status === 0, diffFirst(a.stdout, b.stdout));
      const pb = join(t, "py_in.json"), jb = join(t, "js_in.json");
      execFileSync("python3", [PYT, "batch-in", n, pb], { env });
      execFileSync(process.execPath, [join(HERE, "tsunagi.mjs"), "batch-in", n, jb]);
      chk("Python parity, `batch-in` carries the same batch: " + n, JSON.stringify(JSON.parse(readFileSync(pb, "utf8"))) === JSON.stringify(JSON.parse(readFileSync(jb, "utf8"))));
    }
    const la = spawnSync("python3", [PYT, "list"], { env, encoding: "utf8" });
    const lb = spawnSync(process.execPath, [join(HERE, "tsunagi.mjs"), "list"], { encoding: "utf8" });
    chk("Python parity, `list`", la.stdout === lb.stdout, diffFirst(la.stdout, lb.stdout));
    const bad = join(t, "bad.json"); writeFileSync(bad, Buffer.from([0x7b, 0xff, 0x7d]));
    for (const [label, args] of [["unknown subcommand", ["bogus"]], ["unknown corpus", ["score", "no-such-corpus", bad]], ["unreadable output", ["score", "nenrin-interop-v0", bad]], ["no {in} in the command", ["run", "nenrin-interop-v0", "--", "true {out}"]], ["an open quote", ["row", "nenrin-interop-v0", "--", "x 'y {in} {out}"]]]) {
      const a = spawnSync("python3", [PYT, ...args], { env, encoding: "utf8" });
      const b = spawnSync(process.execPath, [join(HERE, "tsunagi.mjs"), ...args], { encoding: "utf8" });
      chk("Python parity, exit code and stdout on " + label + " (" + a.status + ")", a.status === b.status && a.stdout === b.stdout, "py " + a.status + " js " + b.status);
    }
  } finally { rmSync(t, { recursive: true, force: true }); }
}

// 6. house rules on the shipped text
for (const f of ["tsunagi.mjs", "tsunagi_reference_batch.mjs", "build_tsunagi_corpora.mjs"]) chk(f + " has no dash characters", !DASH.test(readFileSync(join(HERE, f), "utf8")));

function sortKeys(v) { if (Array.isArray(v)) return v.map(sortKeys); if (v && typeof v === "object") { const o = {}; for (const k of Object.keys(v).sort()) o[k] = sortKeys(v[k]); return o; } return v; }
function diffFirst(a, b) { const x = String(a).split("\n"), y = String(b).split("\n"); for (let i = 0; i < Math.max(x.length, y.length); i++) if (x[i] !== y[i]) return "line " + (i + 1) + ":\n py " + x[i] + "\n js " + y[i]; return ""; }

console.log(fail ? `${fail} FAIL / ${pass} PASS` : `ALL PASS (${pass})`);
process.exit(fail ? 1 : 0);
