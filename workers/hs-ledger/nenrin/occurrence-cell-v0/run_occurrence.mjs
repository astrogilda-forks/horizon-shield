#!/usr/bin/env node
// Runs in.json through the JS verifier (verifyProvenance in nenrin_verify.mjs) and writes one verdict signature
// per case: verdict, sorted refusal codes, sorted finding codes. The cases in in.json run with no lookup, which is
// what an offline verifier does. Three more rows reuse o00 with an injected evidence lookup, the step that checks
// the provider's evidence pointer in the system it names:
//   o06_lookup_not_found, o07_lookup_found_not_matching, o08_lookup_found_and_matching
// The lookup here is a stub that returns a fixed answer. It shows what the verifier does with each answer, not that
// any real system was queried.
//
//   node run_occurrence.mjs [dir-holding-nenrin_verify.mjs] [in.json] [out.json]
//   defaults: ../sdk  in.json  results_js.json   (npm nenrin-verify@0.5.2 ships the same nenrin_verify.mjs)
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";
import { join, dirname, resolve } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const [pkg = join(here, "..", "sdk"), inp = join(here, "in.json"), outp = join(here, "results_js.json")] = process.argv.slice(2);
const { verifyProvenance, didKeyResolver } = await import(pathToFileURL(join(resolve(pkg), "nenrin_verify.mjs")).href);
const sig = (p) => ({ verdict: p.verdict, refusals: p.refusals.map((r) => r.code).sort(), findings: p.findings.map((f) => f.code).sort() });
const cases = JSON.parse(readFileSync(inp, "utf8"));
const out = {};
for (const c of cases) out[c.name] = sig(verifyProvenance(Object.assign({}, c.bundle, { resolve: didKeyResolver })));
const base = cases.find((c) => c.name === "o00_signed_grant_and_provider_receipt").bundle;
const withLookup = (name, ext) => {
  let calls = 0;
  const p = verifyProvenance(Object.assign({}, base, { resolve: didKeyResolver, lookup: () => { calls++; return ext; } }));
  out[name] = Object.assign(sig(p), { lookup_calls: calls });
};
withLookup("o06_lookup_not_found", { found: false, matches: false });
withLookup("o07_lookup_found_not_matching", { found: true, matches: false });
withLookup("o08_lookup_found_and_matching", { found: true, matches: true });
writeFileSync(outp, JSON.stringify(out, null, 2) + "\n");
for (const [k, v] of Object.entries(out)) console.log(k, JSON.stringify(v));
