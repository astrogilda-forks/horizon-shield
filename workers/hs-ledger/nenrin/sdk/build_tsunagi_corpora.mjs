// build_tsunagi_corpora.mjs : pack the three NENRIN corpora the TSUNAGI board referees into tsunagi_corpora.json,
// so that `npx nenrin-tsunagi` scores a verifier offline with no clone.
//
//   node build_tsunagi_corpora.mjs            write tsunagi_corpora.json
//   node build_tsunagi_corpora.mjs --check    exit 1 if the committed file is not what the sources build
//
// Every fixture is carried as the exact text of its file (with its sha256), so nothing is re-serialised on the way:
// the batch file nenrin-tsunagi writes holds the fixture bytes as they are in the repository. expected.json is
// carried as its "cases" object, with the sha256 of the file it came from. Same sources, same output, byte for byte.
import { readFileSync, writeFileSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SOURCES = {
  "nenrin-interop-v0": "interop-v0",
  "nenrin-interop-v0.1": "interop-v0.1",
  "nenrin-interop-v0.2-edge": "interop-v0.2/edge",
  "nenrin-interop-v0.2-action-presence": "interop-v0.2/action-presence",
  "nenrin-trace-intake-v0": "trace-intake-v0",
  "nenrin-trace-bind-v0": "trace-bind-v0",
  "nenrin-trace-span-v0": "trace-span-v0",
};
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

export function build(root = join(HERE, "..")) {
  const corpora = {};
  for (const [name, dir] of Object.entries(SOURCES)) {
    const expText = readFileSync(join(root, dir, "expected.json"), "utf8");
    const cases = JSON.parse(expText).cases;
    const fixtures = {};
    for (const c of Object.keys(cases)) {
      const t = readFileSync(join(root, dir, "fixtures", c + ".json"), "utf8");
      JSON.parse(t); // refuse to pack a fixture that is not JSON
      fixtures[c] = { sha256: sha(t), text: t };
    }
    corpora[name] = { source: "workers/hs-ledger/nenrin/" + dir, expected_sha256: sha(expText), cases, fixtures };
  }
  return JSON.stringify({ schema: "nenrin-tsunagi-corpora-v1", generated_by: "build_tsunagi_corpora.mjs", corpora }, null, 1) + "\n";
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const out = build();
  const target = join(HERE, "tsunagi_corpora.json");
  if (process.argv.includes("--check")) {
    let have = "";
    try { have = readFileSync(target, "utf8"); } catch (_e) { /* missing counts as different */ }
    if (have !== out) { console.error("tsunagi_corpora.json is not what the corpora build; run node build_tsunagi_corpora.mjs"); process.exit(1); }
    console.log("tsunagi_corpora.json matches the corpora (" + sha(out).slice(0, 16) + ")");
  } else {
    writeFileSync(target, out);
    console.log("wrote tsunagi_corpora.json (" + out.length + " bytes, sha256 " + sha(out).slice(0, 16) + ")");
  }
}
