#!/usr/bin/env node
// gen.mjs : reproducible NENRIN records for the VATE S3 example capture (Poke-nushi/Verifiable-Agent-Trust-Envelope
// at b3b6d4f9610e159e92d3b41b66e72fc7251758dc, reference/s3-observation-example, bundle "supported").
//
// Run:  node gen.mjs <capture-dir> [out-dir]
//   capture-dir  the "supported" capture directory (vate-capture-b3b6d4f/ next to this file is an unchanged copy)
//   out-dir      where records/ and MANIFEST.json are written (default: the directory of this file)
//
// What it does, in order, with no network and no clock:
//   1. checks every capture file against the sha256 pinned below (and against the capture's own manifest.json);
//   2. derives the NENRIN fields from the capture under the field relations agreed in
//      Poke-nushi/Verifiable-Agent-Trust-Envelope#84 and prints each check (true or false, with both values);
//   3. derives two TEST-ONLY Ed25519 keys from the public phrases below (seed = sha256(phrase));
//   4. writes three cases (match, target_mismatch, missing_receipt) as the bundle files nenrin-verify takes, and
//      MANIFEST.json with every file's sha256.
// Ed25519 signing is deterministic (RFC 8032), so a rerun is byte-identical.
//
// Label (outside the signed bytes, in MANIFEST.json and README.md only): a retrospective synthetic reconstruction;
// the signatures do not establish that a NENRIN grant existed before the original PUT, and they add no independent
// observation of it.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrict } from "../task-delegation-bind-v0/strict_json.mjs";
import { didKeyEncode, rawFromKeyObject } from "../task-delegation-bind-v0/verify_fixture.mjs";
import { grantRef, receiptId, withActionBinding, actionDigest } from "../task-execution-bind-v0/bind_exec.mjs";
import { signGrant, signReceipt } from "../task-execution-bind-v0/sign_exec.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

export const LABEL = "a retrospective synthetic reconstruction; the signatures do not establish that a NENRIN grant existed before the original PUT, and they add no independent observation of it.";
export const VATE = {
  repository: "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope",
  commit: "b3b6d4f9610e159e92d3b41b66e72fc7251758dc",
  capture_path: "reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported",
  license: "Apache-2.0 (LICENSE at the repository root of that commit; a copy is vate-capture-b3b6d4f/LICENSE; the repository has no NOTICE file at that commit)",
  license_sha256: "a7f02d0ab1cc53abde08c95ab75725d673aa5af2d3184cfa07907d34c1f7a318",
  relations_source: "Poke-nushi/Verifiable-Agent-Trust-Envelope#84 (field relations, matching case)",
};
// sha256 of every file in the pinned capture at that commit. The generator refuses a capture that differs.
export const CAPTURE_SHA256 = {
  "admission-decision.json": "78813aabcd1e6b5d436d41bc351b22112df7b89389378370884379213292f861",
  "admission-request.json": "9dced0af22ee3c8a461e73ebbf76cf564f17f6da2b89eabbdb0d81fd78400e08",
  "admission.json": "cdfab8a13e33d473166a6e37e11ac4408d4e074d522737113b5ad60f0eb8963e",
  "attempt.json": "2684017e54c7a7d54d6f290c83df226a6fc5e6b9f5270105f7393f12910c08c1",
  "effective-request.json": "2e4dce64ddc0f6b44386144ed675006e43f5e18d9214ee45de49da5d991ba98c",
  "get-body.bin": "6a639f0771bfe86b9e4dd4c0ea0b020d360308a55f34d8b0064d9f2d1d3c150c",
  "get-headers.txt": "6b1b7a99e8669e35b11d2918b55e4cb595d35ea10ed2879c7ddb5881a27d2b33",
  "get-request.json": "e20f02cf8de0bbdcaf0b02d090311fe841034a751aa2c621036f3e15813ec276",
  "get-transport.json": "f08e274f626c8139008092930e416861e827ba1cab1f9ec7937878e7370f7291",
  "manifest.json": "455e30f846585d003c3f40a83fa5d7fa24b12bebef20ff1d374517e0b642a9fa",
  "permit.json": "a1b80d6c5aa68c46381ed6a5a5e6e5f3ed96e2fa599a65bf9edb431b91689a52",
  "post.json": "d7cc150c297d5d57e8e8dc8299eaf63329b16b24d4b4617beb4db87a04578c5a",
  "put-body.bin": "6a639f0771bfe86b9e4dd4c0ea0b020d360308a55f34d8b0064d9f2d1d3c150c",
  "put-headers.txt": "fe2ed471202335df659ab466f1dfab5d420666fb450413359c3c63f344dbc554",
  "put-request.json": "b22bd05ea42b9177365e484dee35e380dc56c148c3f0208263e595c64a45aad9",
  "put-response-body.bin": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "put-transport.json": "5c9152c0333efeb2f7e1298be5f132c99793066e2043333fa7d538a7e46b634e",
  "sources.json": "74758ffcb2c255c27b7666b05b8a6488fccbe7514f65a4213e0415b1dfeda26d",
};
// The receiver policy of the same instance lives two levels up in VATE (instance/receiver-policy.json). The copy in
// vate-capture-b3b6d4f/ keeps it next to the bundle files under the same name; the generator looks in the capture
// directory first and then at ../../receiver-policy.json, so it also runs straight against a VATE checkout.
export const RECEIVER_POLICY = {
  name: "receiver-policy.json",
  vate_path: "reference/s3-observation-example/inputs/seaweedfs-4.48/instance/receiver-policy.json",
  sha256: "e828cb109fed1b02f27f188eddcbfe3763655ff25f9f65e9d8e43bdc4c2db5a4",
};
// TEST-ONLY keys. The phrases are public, so anyone can derive the private keys: these keys prove nothing about who
// signed, only that the bytes recompute. seed = sha256(UTF-8 bytes of the phrase), used as the 32-byte Ed25519 seed.
export const KEY_PHRASES = {
  caller: "NENRIN VATE S3 example caller key v0 (public, test only)",
  provider: "NENRIN VATE S3 example provider key v0 (public, test only)",
};
// the grant window: one second before the PUT started_at, one second after the PUT finished_at, six fractional digits.
export const WINDOW_MARGIN_MICROS = 1000000n;
export const OTHER_KEY = "result-other.txt";

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function keyFromPhrase(phrase) {
  const seed = createHash("sha256").update(Buffer.from(phrase, "utf8")).digest();
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const raw = rawFromKeyObject(publicKey);
  return { privateKey, publicKey, public_key_hex: raw.toString("hex"), did: didKeyEncode(raw) };
}

// The S3 example's request digest basis (VATE contract.py and docs/conformance/digest-basis.md):
// json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8").
// Reproduced here for JSON values without floats: keys sorted by code point, no whitespace, every character outside
// U+0020..U+007E escaped (Python escapes DEL and all non-ASCII as lowercase \uXXXX, surrogate pairs for astral).
function pyStr(s) {
  return JSON.stringify(s).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}
function cpCompare(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0)), y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}
export function vateFixtureJson(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("no-floats basis: number " + v + " refused"); return String(v); }
  if (typeof v === "string") return pyStr(v);
  if (Array.isArray(v)) return "[" + v.map(vateFixtureJson).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort(cpCompare).map((k) => pyStr(k) + ":" + vateFixtureJson(v[k])).join(",") + "}";
  throw new Error("not a JSON value");
}

// RFC3339 UTC with a fraction of up to six digits, to integer microseconds since the epoch, and back with six digits.
const TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/;
export function toMicros(s) {
  const m = TS.exec(s);
  if (!m) throw new Error("not an RFC3339 UTC timestamp with at most six fractional digits: " + s);
  const secs = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
  return BigInt(secs) * 1000000n + BigInt((m[7] || "").padEnd(6, "0"));
}
export function fromMicros(us) {
  const secs = us / 1000000n, frac = us % 1000000n;
  return new Date(Number(secs) * 1000).toISOString().slice(0, 19) + "." + frac.toString().padStart(6, "0") + "Z";
}

function readCapture(dir) {
  const bytes = {};
  for (const [name, want] of Object.entries(CAPTURE_SHA256)) {
    const p = join(dir, name);
    if (!existsSync(p)) throw new Error("capture file missing: " + p);
    bytes[name] = readFileSync(p);
    const got = sha256(bytes[name]);
    if (got !== want) throw new Error("capture file " + name + " has sha256 " + got + ", pinned " + want);
  }
  const rpCandidates = [join(dir, RECEIVER_POLICY.name), join(dir, "..", "..", RECEIVER_POLICY.name)];
  const rp = rpCandidates.find((p) => existsSync(p));
  if (!rp) throw new Error("receiver policy missing: looked at " + rpCandidates.join(" and "));
  bytes[RECEIVER_POLICY.name] = readFileSync(rp);
  const rpGot = sha256(bytes[RECEIVER_POLICY.name]);
  if (rpGot !== RECEIVER_POLICY.sha256) throw new Error("receiver policy " + rp + " has sha256 " + rpGot + ", pinned " + RECEIVER_POLICY.sha256);
  const json = (name) => parseStrict(bytes[name].toString("utf8"));
  return { bytes, json };
}

export function generate(captureDir) {
  const { bytes, json } = readCapture(captureDir);
  const checks = [];
  const check = (id, statement, left, right) => { const equal = left === right; checks.push({ id, statement, left, right, equal }); return equal; };

  const er = json("effective-request.json");
  const put = json("put-transport.json");
  const getReq = json("get-request.json");
  const getTr = json("get-transport.json");
  const admission = json("admission.json");
  const post = json("post.json");
  const capManifest = json("manifest.json");

  // 0. the capture's own manifest agrees with the files (every artifact it lists)
  for (const [name, a] of Object.entries(capManifest.artifacts).sort(([x], [y]) => cpCompare(x, y)))
    check("capture_manifest:" + name, "the capture's manifest.json digest for " + name + " equals sha256 of the file", a.digest.value, sha256(bytes[name]));

  // 1. identity and tool
  const task_id = er.operation_id;
  check("task_id", "task_id = effective-request.json operation_id (also attempt.json operation_id)", task_id, json("attempt.json").operation_id);
  const tool = er.action;
  check("action.tool", "action.tool = effective-request.json action, which the admission request names too", tool, admission.request.action);

  // 2. target: exact string join
  const target = er.endpoint_profile_id + "/" + er.bucket + "/" + er.key;
  check("action.target", "action.target = endpoint_profile_id + \"/\" + bucket + \"/\" + key", target, "local-seaweed-effa0477bd68/vate-linkage-b119eb3183/result.txt");
  const receiverPolicy = json(RECEIVER_POLICY.name);
  check("target_endpoint_profile_vs_receiver_policy", "effective-request.json endpoint_profile_id = receiver-policy.json endpoint_profile_id", er.endpoint_profile_id, receiverPolicy.endpoint_profile_id);
  check("target_bucket_vs_receiver_policy", "effective-request.json bucket = receiver-policy.json bucket", er.bucket, receiverPolicy.bucket);
  check("target_vs_get_request", "the GET read the same endpoint profile, bucket and key", target, getReq.endpoint_profile_id + "/" + getReq.bucket + "/" + getReq.key);

  // 3. args_sha256 under the S3 example's digest basis, against VATE's request.input_hash
  const basisBytes = Buffer.from(vateFixtureJson(er), "utf8");
  const args_sha256 = sha256(basisBytes);
  const fileBytes = bytes["effective-request.json"];
  check("args_basis_bytes", "the effective-request.json file bytes are already the basis bytes (sorted, compact, ASCII-escaped)", fileBytes.toString("utf8"), (fileBytes.equals(basisBytes) ? "" : "(bytes differ) ") + basisBytes.toString("utf8"));
  check("action.args_sha256", "action.args_sha256 = SHA-256(basis bytes of effective-request.json) = admission.json request.input_hash without \"sha-256:\"", args_sha256, admission.request.input_hash.replace(/^sha-256:/, ""));
  check("args_vs_post_effective_request_hash", "the same digest is post.json execution.effective_request_hash without \"sha-256:\"", args_sha256, post.execution.effective_request_hash.replace(/^sha-256:/, ""));

  // 4. version id across PUT and GET
  const version_id = put.returned_version_id;
  check("version_id_get_requested", "outcome.version_id = put-transport.json returned_version_id = get-request.json requested_version_id", version_id, getReq.requested_version_id);
  check("version_id_get_returned", "outcome.version_id = get-transport.json returned_version_id", version_id, getTr.returned_version_id);

  // 5. result digest over the raw GET body, and the declared PUT body digest over the raw PUT body
  const result_sha256 = sha256(bytes["get-body.bin"]);
  check("result_sha256_get_transport", "outcome.result_sha256 = SHA-256(get-body.bin) = get-transport.json body_ref digest", result_sha256, getTr.body_ref.digest.value);
  check("put_body_digest", "effective-request.json body_digest.value = SHA-256(put-body.bin)", er.body_digest.value, sha256(bytes["put-body.bin"]));
  check("put_body_length", "effective-request.json byte_length = length of put-body.bin", String(er.byte_length), String(bytes["put-body.bin"].length));

  // 6. time: executed_at verbatim, and a window holding both PUT instants
  const executed_at = put.finished_at;
  check("executed_at", "executed_at = put-transport.json finished_at, verbatim", executed_at, "2026-10-12T13:12:32.500049Z");
  check("started_at", "PUT started_at as captured", put.started_at, "2026-10-12T13:12:32.274653Z");
  check("post_times", "post.json execution started_at/finished_at equal put-transport.json", post.execution.started_at + " " + post.execution.finished_at, put.started_at + " " + put.finished_at);
  const not_before = fromMicros(toMicros(put.started_at) - WINDOW_MARGIN_MICROS);
  const not_after = fromMicros(toMicros(put.finished_at) + WINDOW_MARGIN_MICROS);
  const inUs = (t) => toMicros(not_before) <= toMicros(t) && toMicros(t) <= toMicros(not_after);
  const inMs = (t) => Date.parse(not_before) <= Date.parse(t) && Date.parse(t) <= Date.parse(not_after);
  check("window_us", "started_at and finished_at inside [not_before, not_after] at microsecond precision", String(inUs(put.started_at) && inUs(put.finished_at)), "true");
  check("window_ms", "started_at and finished_at inside [not_before, not_after] at Date.parse millisecond precision", String(inMs(put.started_at) && inMs(put.finished_at)), "true");

  // 7. distinct digests stay distinct (recorded, never equated)
  const action = { tool, target, args_sha256 };
  const outerBinding = actionDigest(action);
  const outputHash = post.result.output_hash.replace(/^sha-256:/, "");
  const distinct = [
    { id: "outer_action_binding_vs_args_sha256", statement: "NENRIN action_binding.digest.value (SHA-256 of musubi-canonical-v0(action)) is not args_sha256", left: outerBinding, right: args_sha256 },
    { id: "vate_output_hash_vs_result_sha256", statement: "VATE result.output_hash (structured-result hash) is not outcome.result_sha256 (raw GET body)", left: outputHash, right: result_sha256 },
    { id: "vate_output_hash_vs_outer_action_binding", statement: "VATE result.output_hash is not NENRIN action_binding.digest.value", left: outputHash, right: outerBinding },
  ].map((d) => Object.assign(d, { distinct: d.left !== d.right }));

  const failed = checks.filter((c) => !c.equal).concat(distinct.filter((d) => !d.distinct));

  // keys
  const caller = keyFromPhrase(KEY_PHRASES.caller), provider = keyFromPhrase(KEY_PHRASES.provider);

  // records
  const evidenceSystem = "VATE S3 example capture, Poke-nushi/Verifiable-Agent-Trust-Envelope@" + VATE.commit + ":" + VATE.capture_path + "/get-body.bin";
  const g0 = { schema: "task-execution-bind-v0/grant", task_id, action, caller_id: caller.did, provider_id: provider.did, nonce: "vate-s3-v0:" + task_id, not_before, not_after };
  g0.grant_ref = grantRef(g0);
  const grant = withActionBinding(signGrant(g0, caller.privateKey), "action");
  const mkReceipt = (executed_action) => {
    const r = { schema: "task-execution-bind-v0/receipt", task_id, grant_ref: grant.grant_ref, executed_action, outcome: { version_id, result_sha256, evidence: { kind: "document_sha256", ref: result_sha256, system: evidenceSystem } }, provider_id: provider.did, executed_at };
    r.receipt_id = receiptId(r);
    return withActionBinding(signReceipt(r, provider.privateKey), "executed_action");
  };
  const receipt = mkReceipt(action);
  const otherTarget = target.slice(0, target.length - er.key.length) + OTHER_KEY;
  const receiptOther = mkReceipt({ tool, target: otherTarget, args_sha256 });

  const cases = [
    { name: "match", statement: "grant and receipt as derived from the capture", bundle: { task_id, grant, receipt },
      prediction: { verdict: "accepted", refusals: [] } },
    { name: "target_mismatch", statement: "receipt executed_action.target ends in " + OTHER_KEY + " instead of " + er.key + "; receipt_id and the receipt's action_binding regenerated, receipt re-signed by the provider key; grant unchanged; args_sha256 unchanged (it digests the captured effective request)",
      bundle: { task_id, grant, receipt: receiptOther }, prediction: { verdict: "refused", refusals: [{ code: "execution_invalid", reason: "action_diverged" }] } },
    { name: "missing_receipt", statement: "the grant alone", bundle: { task_id, grant },
      prediction: { verdict: "refused", refusals: [{ code: "execution_incomplete_pair" }] } },
  ];

  const files = {};
  for (const c of cases) files["records/" + c.name + "/nenrin-bundle.json"] = Buffer.from(JSON.stringify(c.bundle, null, 2) + "\n", "utf8");

  const manifest = {
    schema: "nenrin-vate-s3-v0-manifest",
    label: LABEL,
    label_scope: "this label sits outside the signed bytes: it is not in any grant or receipt preimage, and no signature covers it",
    generator: { path: "gen.mjs", sha256: sha256(readFileSync(fileURLToPath(import.meta.url))), command: "node gen.mjs vate-capture-b3b6d4f" },
    vate: Object.assign({}, VATE, { capture_files_sha256: CAPTURE_SHA256, receiver_policy: RECEIVER_POLICY }),
    keys: {
      rule: "seed = SHA-256(UTF-8 bytes of the phrase), used as the 32-byte Ed25519 private seed; did = did:key of the public key (multicodec 0xed01, base58btc). TEST-ONLY: the phrases are public, so these keys establish nothing about who signed.",
      caller: { phrase: KEY_PHRASES.caller, public_key_hex: caller.public_key_hex, did: caller.did },
      provider: { phrase: KEY_PHRASES.provider, public_key_hex: provider.public_key_hex, did: provider.did },
    },
    window: {
      not_before, not_after,
      rule: "not_before = PUT started_at minus 1 second, not_after = PUT finished_at plus 1 second, computed in integer microseconds, six fractional digits",
      put_started_at: put.started_at, put_finished_at: put.finished_at, executed_at,
      precision: "nenrin-verify (npm and PyPI) compares the window in milliseconds: fractions beyond three digits are truncated (JavaScript Date.parse; the Python port's date_parse in _js.py takes the first three fraction digits). The 1 second margins are far above that, so these cases do not test sub-millisecond boundaries.",
      verifier_checks: "the verifier checks executed_at against [not_before, not_after]; it never sees started_at. The started_at containment is checked here by the generator only (window_us, window_ms).",
    },
    nonce_rule: "\"vate-s3-v0:\" + task_id (the pure verifier checks presence and window only)",
    omitted: ["preflight intent", "witness observations", "outcome.status (no agreed relation maps VATE result.outcome to it)"],
    derived: { task_id, action, action_binding_digest: outerBinding, version_id, result_sha256, executed_at, grant_ref: grant.grant_ref, receipt_id_match: receipt.receipt_id, receipt_id_target_mismatch: receiptOther.receipt_id },
    field_relations: checks,
    kept_distinct: distinct,
    cases: cases.map((c) => ({ name: c.name, statement: c.statement, prediction: c.prediction, file: "records/" + c.name + "/nenrin-bundle.json" })),
    files: Object.keys(files).sort().map((p) => ({ path: p, bytes: files[p].length, sha256: sha256(files[p]) })),
  };
  return { checks, distinct, failed, files, manifest };
}

function main() {
  const captureDir = process.argv[2];
  const outDir = process.argv[3] || HERE;
  if (!captureDir) { console.error("usage: node gen.mjs <capture-dir> [out-dir]"); process.exit(2); }
  const { checks, distinct, failed, files, manifest } = generate(captureDir);
  for (const c of checks) console.log((c.equal ? "true " : "FALSE") + "  " + c.id + "  " + c.statement + "\n       left  " + c.left.slice(0, 200) + "\n       right " + c.right.slice(0, 200));
  for (const d of distinct) console.log((d.distinct ? "distinct" : "EQUAL (unexpected)") + "  " + d.id + "  " + d.left + " vs " + d.right);
  console.log("window  not_before " + manifest.window.not_before + "  not_after " + manifest.window.not_after);
  if (failed.length) { console.error("refused: " + failed.length + " relation(s) do not hold; nothing written"); process.exit(1); }
  for (const [p, b] of Object.entries(files)) { const full = join(outDir, p); mkdirSync(dirname(full), { recursive: true }); writeFileSync(full, b); console.log("wrote " + p + "  " + sha256(b)); }
  const mb = Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8");
  writeFileSync(join(outDir, "MANIFEST.json"), mb);
  console.log("wrote MANIFEST.json  " + sha256(mb));
}

let isMain = false;
try { isMain = !!process.argv[1] && fileURLToPath(import.meta.url) === (await import("node:fs")).realpathSync(process.argv[1]); } catch (_e) { isMain = false; }
if (isMain) main();
