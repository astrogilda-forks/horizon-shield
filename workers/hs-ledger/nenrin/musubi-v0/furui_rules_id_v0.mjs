#!/usr/bin/env node
// furui-rules-id-v0 in a second runtime: the same codes and the same rules_sha256 as furui_rules_id_v0.py, which says
// what the object is and why. furui_rules_id_v0.py --selftest runs this file over its example and mutants.
//
//   node furui_rules_id_v0.mjs --id ID.json        prints rules_sha256, or the problems
//   node furui_rules_id_v0.mjs --batch < LIST.json  prints [{problems, rules_sha256}] for a JSON list of objects
import fs, { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { canonical, sha256 } from "./canonical_v0.mjs";

export const ID = "furui-rules-id-v0";
const KEYS = ["arrangement", "id", "prompts", "rule_files", "schema_sha256", "stages", "version"];
export const ARRANGEMENTS = {
  "rules-only": [["rules", null]],
  "rules-model": [["rules", null], ["model", null]],
  "rules-haiku-opus_on_flag": [["rules", null], ["model", null], ["model", "stage_2_flagged"]],
};
const HEX64 = /^[0-9a-f]{64}$/;
const NAME = /^[\x21-\x7e][\x20-\x7e]{0,127}$/;
const VERSION = /^[\x21-\x7e]{1,64}$/;
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const isStr = (x) => typeof x === "string";
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function named(xs, where, emptyOk) {
  if (!Array.isArray(xs) || (!xs.length && !emptyOk)) return [where + "_malformed"];
  for (const x of xs) {
    if (!(isObj(x) && Object.keys(x).sort().join(",") === "name,sha256" && isStr(x.name) && NAME.test(x.name) && isStr(x.sha256) && HEX64.test(x.sha256)))
      return [where + "_malformed"];
  }
  const names = xs.map((x) => x.name), uniq = [...new Set(names)].sort();
  return names.join("\u0000") === uniq.join("\u0000") && names.length === uniq.length ? [] : [where + "_not_sorted_unique"];
}

export function problems(obj) {
  if (!isObj(obj)) return ["not_an_object"];
  if (Object.keys(obj).sort().join(",") !== KEYS.join(",")) return ["keys_not_exact"];
  const p = [];
  if (obj.id !== ID) p.push("id_unknown");
  if (!(isStr(obj.version) && VERSION.test(obj.version))) p.push("version_malformed");
  p.push(...named(obj.rule_files, "rule_files", false));
  p.push(...named(obj.prompts, "prompts", true));
  const st = obj.stages;
  let shape = null;
  if (!Array.isArray(st) || !st.length) p.push("stages_malformed");
  else {
    shape = [];
    for (let i = 0; i < st.length; i++) {
      const s = st[i];
      if (!(isObj(s) && typeof s.n === "number" && Number.isInteger(s.n) && s.n === i + 1 && (s.kind === "rules" || s.kind === "model"))) {
        p.push("stages_malformed"); shape = null; break;
      }
      const allowed = new Set(["n", "kind", ...(s.kind === "model" ? ["model", "when"] : [])]);
      if (Object.keys(s).some((k) => !allowed.has(k)) || (s.kind === "model" && !(isStr(s.model) && NAME.test(s.model))) || (has(s, "when") && !isStr(s.when))) {
        p.push("stages_malformed"); shape = null; break;
      }
      shape.push([s.kind, has(s, "when") ? s.when : null]);
    }
  }
  if (!has(ARRANGEMENTS, obj.arrangement) || !isStr(obj.arrangement)) p.push("arrangement_unknown");
  else if (shape !== null && JSON.stringify(shape) !== JSON.stringify(ARRANGEMENTS[obj.arrangement])) p.push("stages_not_the_arrangement");
  const models = shape !== null && shape.some(([k]) => k === "model");
  const sch = obj.schema_sha256;
  if (!(sch === null || (isStr(sch) && HEX64.test(sch)))) p.push("schema_sha256_malformed");
  else if (shape !== null && (sch === null) === models) p.push("schema_sha256_not_the_stages");
  if (shape !== null && Array.isArray(obj.prompts) && (obj.prompts.length === 0) === models) p.push("prompts_not_the_stages");
  return p;
}

export function rulesSha256(obj) {
  const p = problems(obj);
  if (p.length) throw new Error(p.join(", "));
  return sha256(canonical(obj));
}

const one = (x) => { const p = problems(x); return { problems: p, rules_sha256: p.length ? null : rulesSha256(x) }; };

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const a = process.argv.slice(2);
  if (a[0] === "--batch") console.log(JSON.stringify(JSON.parse(fs.readFileSync(0, "utf8")).map(one)));
  else if (a[0] === "--id" && a[1]) {
    const r = one(JSON.parse(fs.readFileSync(a[1], "utf8")));
    console.log(r.problems.length ? JSON.stringify({ problems: r.problems }) : r.rules_sha256);
    process.exit(r.problems.length ? 1 : 0);
  } else { console.error("usage: node furui_rules_id_v0.mjs --id ID.json | --batch < LIST.json"); process.exit(1); }
}
