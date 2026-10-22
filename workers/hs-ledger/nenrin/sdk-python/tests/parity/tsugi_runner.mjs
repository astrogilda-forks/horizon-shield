// tsugi_runner.mjs <path to tsugi_verify.mjs> : one case per line on stdin ({"args": [...], "files": {name: text}}),
// one result per line on stdout: what the CLI would print and its exit code, or that it threw.
// The body below is tsugiArgs and tsugiMain from tsugi_verify.mjs, line for line, with two changes only: files are
// read from the case instead of the disk, and the result is returned instead of printed and exited.
// Lines are split on "\n" only (Node 24's readline also breaks at U+2028 and U+2029).
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const T = await import(pathToFileURL(process.argv[2]).href);
const { verifyChain, fetchOperatorKeys, VERIFIER_VERSION, b64Exact, ed25519KeyOk } = T;

function tsugiArgs(argv) {
  const a = {}; const pos = [];
  for (let i = 0; i < argv.length; i++) { const x = argv[i]; if (x.startsWith("--")) { const v = argv[i + 1]; if (v !== undefined && !v.startsWith("--")) { a[x.slice(2)] = v; i++; } else a[x.slice(2)] = true; } else pos.push(x); }
  return { a, pos };
}
async function tsugiMain(argv, files) {
  const readFileSync = (p) => { if (typeof p !== "string") throw new TypeError("path"); if (!(p in files)) throw new Error("ENOENT " + p); return files[p]; };
  const { a, pos } = tsugiArgs(argv);
  const file = pos[0];
  if (!file) return { usage: true, exit: 2 };
  const loaded = JSON.parse(readFileSync(file, "utf8"));
  const records = Array.isArray(loaded) ? loaded : loaded.records;
  const opts = {};
  if (a["operator-key"]) opts.operatorKeys = String(a["operator-key"]).split(",").map((s) => s.trim()).filter(Boolean);
  else if (a["fetch-operator-key"]) opts.operatorKeys = await fetchOperatorKeys(a["fetch-operator-key"]);
  else if (!Array.isArray(loaded) && typeof loaded.operator_public_key_ed25519_b64 === "string" && a["trust-embedded-key"]) opts.operatorKeys = [loaded.operator_public_key_ed25519_b64];
  for (const k of opts.operatorKeys || []) { const pk = b64Exact(k, 32); if (!pk || !ed25519KeyOk(pk)) return { usage: true, exit: 2 }; }   // 0.3.1, as tsugi_verify.mjs
  if (a.pool || a.q || a.k || a.beacon || a["require-commitment"] || a["anchor-height"] || a["require-v24"] || a["beacon-time"]) {
    opts.witnessQuorum = {};
    if (a.pool) opts.witnessQuorum.pool = JSON.parse(readFileSync(a.pool, "utf8"));
    if (a.q) opts.witnessQuorum.q = Number(a.q);
    if (a.k) opts.witnessQuorum.k = Number(a.k);
    if (a.beacon) opts.witnessQuorum.beaconHash = String(a.beacon);
    if (a["require-commitment"]) opts.witnessQuorum.requireCommitment = true;
    if (a["anchor-height"]) opts.witnessQuorum.commitmentAnchor = { height: String(a["anchor-height"]), ...(a["anchor-hash"] ? { hash: String(a["anchor-hash"]) } : {}) };
    if (a["require-v24"]) opts.witnessQuorum.requireV24 = true;
    if (a["beacon-time"]) opts.witnessQuorum.beaconTime = String(a["beacon-time"]);
  }
  const report = await verifyChain(records, opts);
  const out = { verifier: "tsugi_verify " + VERIFIER_VERSION, mode: { operator_keys: opts.operatorKeys ? opts.operatorKeys.length : 0, witness_quorum: opts.witnessQuorum || null }, ...report,
    note: opts.operatorKeys ? undefined : "lenient: no operator key given, so a chat-approved (unsigned) authorization passes; pass --operator-key or --fetch-operator-key <origin> for strict",
    does_not_establish: ["that any record is true: hashes and signatures prove who wrote what and in which order, not that the observation was correct", "that the repair was the right one: that is the proposal's own does_not_establish", "operator independence of the witness that wrote the drift records: read witness.vantage"] };
  return { stdout: JSON.stringify(out, null, 2) + "\n", exit: report.ok ? 0 : 1 };
}

for (const line of readFileSync(0, "utf8").split("\n")) {
  if (!line) continue;
  const c = JSON.parse(line);
  let r;
  try { r = await tsugiMain(c.args, c.files); r.threw = false; }
  catch (e) { r = { threw: true, error: String(e && e.message || e).slice(0, 200) }; }
  process.stdout.write(JSON.stringify(r) + "\n");
}
