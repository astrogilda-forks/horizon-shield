#!/usr/bin/env node
// musubi-scope-v0 in a second runtime: the same scope object, digest and text as render_scope_v0.py, which says what
// the scope is and why. render_scope_v0.py --selftest runs this file over its contracts.
//
//   node render_scope_v0.mjs --contract CONTRACT.json   prints scope_sha256 and the text
//   node render_scope_v0.mjs --batch < LIST.json         prints [{scope_sha256, text}] for a JSON list of contracts
import fs, { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { canonical, sha256 } from "./canonical_v0.mjs";
import { contractSha256 } from "./clause_eval_v0.mjs";
import { problems } from "./requirements_furui_v0.mjs";

export const ID = "musubi-scope-v0";
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const val = (o, k) => (isObj(o) && has(o, k) && o[k] !== undefined ? o[k] : null);

export function scopeOf(contract) {
  const task = val(contract, "task"), grant = val(contract, "grant");
  if (!(isObj(task) && typeof task.purpose === "string" && task.purpose && isObj(grant))) throw new Error("a scope needs task.purpose and a grant object");
  if (problems(contract).length) throw new Error("requirements.furui is not in the shape requirements_furui_v0 reads");
  const f = val(val(contract, "requirements"), "furui"), st = val(f, "scope_text");
  const g = (k, empty) => (val(grant, k) !== null ? grant[k] : empty);
  return { id: ID, contract_sha256: contractSha256(contract), purpose: task.purpose,
    authorized_actions: g("authorized_actions", []), prohibited_actions: g("prohibited_actions", []),
    conditional: g("conditional", []), limits: g("limits", {}),
    data_access: g("data_access", null), privacy: g("privacy", null),
    scope_text: typeof st === "string" && st ? st : null };
}

export const scopeSha256 = (scope) => sha256(canonical(scope));
const list = (xs) => (xs.length ? xs.map(String).join(", ") : "none");

export function render(scope) {
  const out = ["Task: " + scope.purpose, "Allowed actions: " + list(scope.authorized_actions), "Forbidden actions: " + list(scope.prohibited_actions)];
  const cond = scope.conditional.map((c0) => {
    const c = isObj(c0) ? c0 : {};
    const extra = typeof c.requires === "string" ? ["requires " + c.requires] : [];
    for (const k of Object.keys(c).sort()) if (k !== "action" && k !== "requires") extra.push(k + " " + canonical(c[k]));
    return String(val(c, "action")) + (extra.length ? " (" + extra.join("; ") + ")" : "");
  });
  out.push("Actions allowed only after an approval: " + (cond.length ? cond.join(", ") : "none"));
  const lim = Object.keys(scope.limits).sort().map((a) => {
    const v = isObj(scope.limits[a]) ? scope.limits[a] : {};
    return a + " at most " + canonical(val(v, "max_amount")) + " " + String(val(v, "unit") === null ? "None" : v.unit);
  });
  out.push("Limits: " + (lim.length ? lim.join(", ") : "none"));
  if (scope.data_access !== null) out.push("Data the assistant may use: " + (Array.isArray(scope.data_access) ? list(scope.data_access) : String(scope.data_access)));
  if (scope.privacy !== null) out.push("Privacy: " + String(scope.privacy));
  if (scope.scope_text !== null) out.push("The task in the parties' words: " + scope.scope_text);
  return out.join("\n") + "\n";
}

const one = (c) => { const s = scopeOf(c); return { scope_sha256: scopeSha256(s), text: render(s) }; };

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const a = process.argv.slice(2);
  if (a[0] === "--batch") console.log(JSON.stringify(JSON.parse(fs.readFileSync(0, "utf8")).map(one)));
  else if (a[0] === "--contract" && a[1]) { const r = one(JSON.parse(fs.readFileSync(a[1], "utf8"))); process.stdout.write(r.scope_sha256 + "\n" + r.text); }
  else { console.error("usage: node render_scope_v0.mjs --contract CONTRACT.json | --batch < LIST.json"); process.exit(1); }
}
