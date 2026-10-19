#!/usr/bin/env node
// tools/price_copies/check_bands.mjs: the price bands hs-hearing copies from souba-db must equal souba-db (2026-10-19).
//
// hs-hearing scores a contractor's quote for the Yakumo directory against KIRA_BANDS (workers/hs-hearing/src/autopilot.js),
// a hand copy of souba-db rows with no version and no hash. If souba-db moves and the copy does not, the directory is
// judged on numbers nobody can trace. This binds each band to the souba-db row it copies (by id) and fails when the
// numbers differ, when a bound row is gone, or when a band appears that is neither bound nor listed below as having
// no row. Run: node tools/price_copies/check_bands.mjs   (exit 0 = every band traced, 1 = a band drifted)
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// band key in autopilot.js -> souba-db categories[].id it copies
export const BOUND = {
  mado_inner_large: "inner_window_matsu",
  mado_inner_small: "inner_window_ume",
  mado_insulation: "dannetsu_uchimado",
  door_cover_std: "genkan_door_cover_ume",
  door_cover_mid: "genkan_door_cover",
  glass_bath: "mado_glass_work",
};
// bands with no souba-db row: used by hs-hearing, traceable to nothing in the dataset. Listed so they stay visible.
export const NO_ROW = {
  glass_special: "真空/特殊(防犯含む)ガラス交換 has no row in souba-db (checked against 2.3.0 on 2026-10-19). Add the row under the two-independent-values rule, or drop the band.",
};

export function check(bands, souba) {
  const rows = new Map((souba.categories || []).map((c) => [c.id, c]));
  const problems = [], lines = [];
  for (const [key, b] of Object.entries(bands)) {
    if (key in NO_ROW) { lines.push("NO ROW " + key + ": " + NO_ROW[key]); continue; }
    const id = BOUND[key];
    if (!id) { problems.push(key + " is in KIRA_BANDS but bound to no souba-db row and not listed as having none"); continue; }
    const r = rows.get(id);
    if (!r) { problems.push(key + " is bound to " + id + ", which souba-db no longer has"); continue; }
    const diff = ["min", "avg", "max"].filter((f) => b[f] !== r[f]);
    if (diff.length) problems.push(key + " differs from souba-db " + id + " in " + diff.map((f) => f + " (" + b[f] + " vs " + r[f] + ")").join(", "));
    else lines.push("ok     " + key + " = " + id);
  }
  for (const key of Object.keys(BOUND)) if (!(key in bands)) problems.push(key + " is bound here but no longer in KIRA_BANDS; remove it from BOUND");
  return { problems, lines };
}

async function main() {
  const { KIRA_BANDS } = await import(pathToFileURL(join(ROOT, "workers/hs-hearing/src/autopilot.js")).href);
  const souba = JSON.parse(readFileSync(join(ROOT, "data/souba-db.json"), "utf8"));
  const { problems, lines } = check(KIRA_BANDS, souba);
  for (const l of lines) console.log(l);
  for (const p of problems) console.log("FAIL   " + p);
  console.log((problems.length ? problems.length + " band(s) do not trace to souba-db " : "every band traces to souba-db ") + (souba._meta && souba._meta.version));
  return problems.length ? 1 : 0;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().then((c) => process.exit(c), (e) => { console.error(e); process.exit(1); });
