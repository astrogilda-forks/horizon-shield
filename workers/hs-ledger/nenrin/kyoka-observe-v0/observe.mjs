// observe.mjs : ask the register once, record what it answered, and (in GitHub Actions) bind the observer's key to
// the run's OIDC identity. One query per run, on demand: this is a lookup, not a crawler.
//
//   node observe.mjs --kind minister --license-no 003000 --out out/
//   node observe.mjs --kind governor --prefecture 神奈川県 --license-no 012345 --out out/
//   node observe.mjs --verify out/ [--trust <issuer>=<jwks sha256>]   the reader alone, offline
//
// The reader names the observer's identity only for an issuer whose JWKS digest it is told to trust (--trust): the
// jwks.json in the folder is the bundle's own copy and cannot vouch for itself. To trust GitHub's keys, fetch
// https://token.actions.githubusercontent.com/.well-known/jwks yourself around the run's time and compare the sha256
// with the one the run printed; GitHub rotates these keys, so a later fetch may differ.
//
// In GitHub Actions with `permissions: id-token: write`, the run's token (issuer https://token.actions.githubusercontent.com,
// audience nenrin-kyoka-observe) is bound to the observer key with idp-bind-v0, and the issuer's JWKS is pinned by
// sha256. Outside Actions the observation is still made and signed, just not bound to an identity.
// Writes: observation.json, response.bin (the register's bytes, which carry the representative's name: the workflow
// keeps them out of the published artifact), and, when bound, binding.json and jwks.json.
import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { makeObservation, verify, requestBody, queryProblem, REGISTER_URL } from "./kyoka_observe.mjs";
import { makeBinding, newActorKey, sha256hex } from "../idp-bind-v0/idp_bind.mjs";
import { parseTrust } from "../idp-bind-v0/trusted_identity.mjs";
import { parseStrict } from "../sdk/nenrin_verify.mjs";

const args = process.argv.slice(2);
const arg = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const UA = "HORIZON SHIELD kyoka-observe-v0 (+https://horizonshield.dev; one licence lookup per run)";
const AUD = "nenrin-kyoka-observe";
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

async function observe() {
  const out = arg("--out") || "out";
  mkdirSync(out, { recursive: true });
  const query = { kind: arg("--kind"), license_no: String(arg("--license-no") || "").padStart(6, "0") };
  if (query.kind === "governor") query.prefecture = arg("--prefecture");
  const p = queryProblem(query);
  if (p) { console.error("query refused: " + p); process.exit(2); }

  // the register keeps a session: open the search page first, then post the one query
  const first = await fetch(REGISTER_URL, { headers: { "user-agent": UA } });
  const cookie = (first.headers.getSetCookie ? first.headers.getSetCookie() : []).map((c) => c.split(";")[0]).join("; ");
  await first.arrayBuffer();
  const res = await fetch(REGISTER_URL, { method: "POST", body: requestBody(query),
    headers: { "user-agent": UA, "content-type": "application/x-www-form-urlencoded", referer: REGISTER_URL, ...(cookie ? { cookie } : {}) } });
  if (!res.ok) { console.error("register answered HTTP " + res.status); process.exit(3); }
  const bytes = Buffer.from(await res.arrayBuffer());
  const observedAt = iso(new Date());
  writeFileSync(join(out, "response.bin"), bytes);

  const key = newActorKey();
  const observation = makeObservation({ observerPrivateKey: key.privateKey, observerId: key.actorId, query, responseBytes: bytes, observedAt, nonce: "run-" + (process.env.GITHUB_RUN_ID || Date.now()) });
  writeFileSync(join(out, "observation.json"), JSON.stringify(observation, null, 2) + "\n");

  // bind the observer key to this run's identity, when there is one
  const U = process.env.ACTIONS_ID_TOKEN_REQUEST_URL, T = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (U && T) {
    const tr = await fetch(U + "&audience=" + encodeURIComponent(AUD), { headers: { authorization: "bearer " + T } });
    const token = (await tr.json()).value;
    const pl = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
    const hd = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
    const jr = await fetch("https://token.actions.githubusercontent.com/.well-known/jwks");
    const doc = await jr.text();
    const binding = makeBinding({ actorPrivateKey: key.privateKey, actorId: key.actorId, token, issuer: pl.iss, subject: pl.sub,
      audience: AUD, kid: hd.kid, alg: hd.alg, boundAt: iso(new Date()), nonce: "observer-" + (process.env.GITHUB_RUN_ID || "local") });
    writeFileSync(join(out, "binding.json"), JSON.stringify(binding, null, 2) + "\n");
    writeFileSync(join(out, "jwks.json"), JSON.stringify({ sha256: sha256hex(doc), document: doc }, null, 2) + "\n");
  }
  return reader(out);
}

function reader(dir) {
  const j = (n) => parseStrict(readFileSync(join(dir, n), "utf8"));
  const trust = args.flatMap((a, i) => (a === "--trust" ? [args[i + 1]] : []));
  const input = { observation: j("observation.json"), trusted: parseTrust(trust) };
  if (existsSync(join(dir, "response.bin"))) input.response_bytes = readFileSync(join(dir, "response.bin"));
  if (existsSync(join(dir, "binding.json"))) { input.binding = j("binding.json"); input.jwks = j("jwks.json"); }
  const r = verify(input);
  const o = input.observation;
  const lines = [
    "## kyoka-observe-v0", "",
    "| | |", "| --- | --- |",
    "| query | " + (o.query.kind === "minister" ? "国土交通大臣許可" : o.query.prefecture + "知事許可") + " 第" + o.query.license_no + "号 |",
    "| observed_at | " + o.observed_at + " |",
    "| result | " + o.result.status + " (" + o.result.rows.length + " row(s)) |",
    "| response sha256 | `" + o.response.sha256 + "` (" + o.response.length + " bytes) |",
    ...(input.jwks ? ["| issuer JWKS sha256 | `" + input.jwks.sha256 + "` (compare with your own fetch before passing it to --trust) |"] : []),
    "| observation_id | `" + o.observation_id + "` |",
    "| verdict | " + r.verdict + " " + JSON.stringify(r.refusals.map((x) => x.code)) + " " + JSON.stringify(r.findings.map((x) => x.code)) + " |", "",
    ...[...new Set(o.result.rows.map((x) => x.authority + " " + x.trade_name))].map((s) => "- " + s), "",
    "Established: " + r.establishes.join("; "), "",
    "Not established: " + r.does_not_establish.join("; "),
  ];
  console.log(lines.join("\n"));
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join("\n") + "\n", { flag: "a" });
  if (r.verdict !== "accepted") process.exit(1);
}

if (arg("--verify")) reader(arg("--verify")); else await observe();
