#!/usr/bin/env node
// requirements.furui in a second runtime: the same shape rule as requirements_furui_v0.py, which says what it is and
// who reads it (contract builders, settle v1.17 and render_scope_v0; never settle core v0).
//
//   node requirements_furui_v0.mjs --batch < LIST.json    prints [codes] for a JSON list of contracts
import fs, { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const CODE = "bad_requirements_furui";
const KEYS = ["rules_sha256", "scope_text"];
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const val = (o, k) => (isObj(o) && has(o, k) && o[k] !== undefined ? o[k] : null);

export function problems(contract) {
  const f = val(val(contract, "requirements"), "furui");
  if (f === null) return [];
  if (!isObj(f) || Object.keys(f).some((k) => !KEYS.includes(k))) return [CODE];
  const r = val(f, "rules_sha256"), t = val(f, "scope_text");
  if (r !== null && !(typeof r === "string" && /^[0-9a-f]{64}$/.test(r))) return [CODE];
  if (t !== null && !(typeof t === "string" && t)) return [CODE];
  return [];
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  if (process.argv[2] === "--batch") console.log(JSON.stringify(JSON.parse(fs.readFileSync(0, "utf8")).map(problems)));
  else { console.error("usage: node requirements_furui_v0.mjs --batch < LIST.json"); process.exit(1); }
}
