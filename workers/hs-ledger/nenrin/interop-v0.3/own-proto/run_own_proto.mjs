// run_own_proto.mjs : the reference verifier (sdk/nenrin_verify.mjs) over the interop-v0.3/own-proto corpus. Each
// fixture's verdict signature must equal expected.json. The vectors add one field (the own JSON key "__proto__", or
// an ordinary key as the control) to a signed record after signing (pipavlo82, #29, 2026-10-15).
// Run: node run_own_proto.mjs
import { readFileSync } from "node:fs";
import { verifyProvenance, didKeyResolver } from "../../sdk/nenrin_verify.mjs";
const root = new URL("./", import.meta.url);
const cases = JSON.parse(readFileSync(new URL("expected.json", root), "utf8")).cases;
const sig = (p) => ({ verdict: p.verdict, refusals: [...new Set(p.refusals.map((r) => r.code))].sort(), findings: [...new Set(p.findings.map((f) => f.code))].sort() });
let fail = 0;
for (const [name, c] of Object.entries(cases)) {
  const bundle = JSON.parse(readFileSync(new URL("fixtures/" + name + ".json", root), "utf8"));
  const want = { verdict: c.expect.verdict, refusals: [...new Set(c.expect.refusals)].sort(), findings: [...new Set(c.expect.findings)].sort() };
  let got; try { got = sig(verifyProvenance(Object.assign({}, bundle, { resolve: didKeyResolver }))); } catch (e) { got = { threw: String(e && e.message || e) }; }
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) fail++;
  console.log((ok ? "PASS  " : "FAIL  ") + name + (ok ? "" : "  expected " + JSON.stringify(want) + " got " + JSON.stringify(got)));
}
const n = Object.keys(cases).length;
console.log(fail ? "\n" + fail + " FAILED" : "\nALL PASS (interop-v0.3/own-proto: the reference reproduces " + n + "/" + n + " verdict signatures)");
process.exit(fail ? 1 : 0);
