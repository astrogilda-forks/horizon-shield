// vate_s3_v0.test.mjs : the committed records are what gen.mjs makes from the pinned VATE capture, byte for byte, and
// the in-repo verifier (../sdk/nenrin_verify.mjs) gives the three recorded outcomes. Offline: it reads only the copy of
// the capture in vate-capture-b3b6d4f/ and never fetches it. If that directory is absent, it skips with a message.
// Run: node vate_s3_v0.test.mjs        exit 1 on any failure.
import { readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyProvenance, didKeyResolver, verifyGrantSig, verifyReceiptSig } from "../sdk/nenrin_verify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CAPTURE = join(HERE, "vate-capture-b3b6d4f");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const R = [];
const t = (name, ok, detail = "") => R.push({ name, ok: !!ok, detail: String(detail) });

if (!existsSync(CAPTURE)) {
  console.log("SKIP: " + CAPTURE + " is absent. This test runs only against the local copy of the VATE capture (it never fetches it); see README.md.");
  process.exit(0);
}

const manifestBytes = readFileSync(join(HERE, "MANIFEST.json"));
const manifest = JSON.parse(manifestBytes.toString("utf8"));

// 1. the capture copy matches the sha256s the manifest pins
for (const [name, want] of Object.entries(manifest.vate.capture_files_sha256)) {
  const p = join(CAPTURE, name);
  t("capture " + name + " sha256", existsSync(p) && sha(readFileSync(p)) === want, want);
}
{
  const rp = join(CAPTURE, manifest.vate.receiver_policy.name);
  t("capture " + manifest.vate.receiver_policy.name + " sha256", existsSync(rp) && sha(readFileSync(rp)) === manifest.vate.receiver_policy.sha256, manifest.vate.receiver_policy.sha256);
  const lic = join(CAPTURE, "LICENSE");
  t("capture LICENSE (VATE Apache-2.0) sha256", existsSync(lic) && sha(readFileSync(lic)) === manifest.vate.license_sha256, manifest.vate.license_sha256);
}

// 2. the committed files match the manifest's sha256s
for (const f of manifest.files) {
  const b = readFileSync(join(HERE, f.path));
  t("committed " + f.path + " sha256 and length", sha(b) === f.sha256 && b.length === f.bytes, f.sha256);
}
t("manifest generator sha256 is gen.mjs", sha(readFileSync(join(HERE, "gen.mjs"))) === manifest.generator.sha256);
t("every field relation holds in the manifest", manifest.field_relations.every((c) => c.equal) && manifest.field_relations.length > 0);
t("every kept-distinct pair is distinct", manifest.kept_distinct.every((d) => d.distinct));
t("label stays outside the signed bytes", manifest.files.every((f) => !readFileSync(join(HERE, f.path), "utf8").includes("retrospective")));

// 3. regenerate into a temp dir: byte-identical records and MANIFEST.json
const tmp = mkdtempSync(join(tmpdir(), "vate-s3-v0-"));
try {
  execFileSync(process.execPath, [join(HERE, "gen.mjs"), CAPTURE, tmp], { stdio: "pipe" });
  t("regenerated MANIFEST.json is byte-identical", readFileSync(join(tmp, "MANIFEST.json")).equals(manifestBytes));
  for (const f of manifest.files) t("regenerated " + f.path + " is byte-identical", readFileSync(join(tmp, f.path)).equals(readFileSync(join(HERE, f.path))));
} catch (e) {
  t("gen.mjs ran", false, e.stderr ? e.stderr.toString() : e.message);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

// 4. the in-repo verifier gives the recorded outcomes (the actual ones, recorded in runs/RUNS.md)
const EXPECT = {
  match: { verdict: "accepted", refusals: [], findings: ["evidence_bound_unchecked", "no_delegation_observations"] },
  target_mismatch: { verdict: "refused", refusals: ["execution_invalid:action_diverged"], findings: ["evidence_bound_unchecked", "no_delegation_observations"] },
  missing_receipt: { verdict: "refused", refusals: ["execution_incomplete_pair"], findings: ["no_delegation_observations"] },
};
for (const [name, want] of Object.entries(EXPECT)) {
  const bundle = JSON.parse(readFileSync(join(HERE, "records", name, "nenrin-bundle.json"), "utf8"));
  const p = verifyProvenance(Object.assign({}, bundle, { resolve: didKeyResolver }));
  const got = { verdict: p.verdict, refusals: p.refusals.map((r) => r.code + (r.reason ? ":" + r.reason : "")).sort(), findings: p.findings.map((f) => f.code).sort() };
  t(name + " verdict and codes", JSON.stringify(got) === JSON.stringify(want), JSON.stringify(got));
  t(name + " caller_sig verifies against the caller did:key", verifyGrantSig(bundle.grant, didKeyResolver(bundle.grant.caller_id)) && bundle.grant.caller_id === manifest.keys.caller.did);
  if (bundle.receipt) t(name + " provider_sig verifies against the provider did:key", verifyReceiptSig(bundle.receipt, didKeyResolver(bundle.receipt.provider_id)) && bundle.receipt.provider_id === manifest.keys.provider.did);
  // the published reports in runs/ are what the in-repo verifier prints
  for (const build of ["npm", "pypi"]) {
    const out = join(HERE, "runs", build + "-" + name + ".out");
    if (existsSync(out)) t(name + " runs/" + build + " report equals the in-repo report", readFileSync(out, "utf8") === JSON.stringify(p, null, 2) + "\n");
  }
}

const bad = R.filter((r) => !r.ok);
for (const r of R) console.log((r.ok ? "ok    " : "FAIL  ") + r.name + (r.ok ? "" : "  " + r.detail));
console.log("\n" + (R.length - bad.length) + "/" + R.length + " passed");
process.exit(bad.length ? 1 : 0);
