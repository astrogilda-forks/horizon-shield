// workers/hs-reference-gateway/test/gateway_tokens_test.mjs (2026-10-20)
// 呼び手ごとのトークン: GATEWAY_TOKEN(KIRA と CI)と GATEWAY_TOKEN_YAKUMO(AIシミュレーター)のどちらでも読め、
// それ以外・空・未設定は 401。/healthz はトークン無しのまま。R2 は偽物。使い方: node workers/hs-reference-gateway/test/gateway_tokens_test.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const tmp = path.join(os.tmpdir(), "hs_gateway_tokens_" + process.pid + ".mjs");
fs.writeFileSync(tmp, fs.readFileSync(path.join(HERE, "..", "src", "gateway.js"), "utf8"));
const G = (await import(pathToFileURL(tmp).href)).default;
fs.unlinkSync(tmp);

let pass = 0, fail = 0;
const check = (n, ok, info) => { if (ok) pass++; else { fail++; console.log("  x " + n + (info !== undefined ? " " + JSON.stringify(info) : "")); } };

const souba = Buffer.from(JSON.stringify({ _meta: { version: "9.9.9" }, categories: [] }));
const bucket = {
  async get(k) { return k === "souba-db.json" ? { async arrayBuffer() { return souba; } } : null; },
  async list() { return { objects: [{ key: "souba-db.json" }] }; },
};
const env = (over = {}) => ({ MODE: "r2", REFERENCE_BUCKET: bucket, GATEWAY_TOKEN: "kira-aaaa", GATEWAY_TOKEN_YAKUMO: "yakumo-bbbb", ...over });
const call = (e, token, p = "/reference/souba-db.json") => G.fetch(new Request("https://gw.test" + p, { headers: token === undefined ? {} : { "X-Gateway-Token": token } }), e);

check("KIRA のトークンで読める", (await call(env(), "kira-aaaa")).status === 200);
const y = await call(env(), "yakumo-bbbb");
check("AIシミュレーターのトークンで読める(版と sha のヘッダ付き)", y.status === 200 && y.headers.get("X-Reference-Version") === "9.9.9" && /^[0-9a-f]{64}$/.test(y.headers.get("X-Reference-Sha256") || ""));
check("違うトークンは 401", (await call(env(), "kira-aaab")).status === 401);
check("長さだけ違うトークンも 401", (await call(env(), "yakumo-bbbbb")).status === 401);
check("トークン無しは 401", (await call(env(), undefined)).status === 401);
check("空のトークンは 401", (await call(env(), "")).status === 401);
check("GATEWAY_TOKEN_YAKUMO が未設定なら、空や undefined の値では通らない", (await call(env({ GATEWAY_TOKEN_YAKUMO: undefined }), "")).status === 401 && (await call(env({ GATEWAY_TOKEN_YAKUMO: undefined }), "undefined")).status === 401);
check("GATEWAY_TOKEN_YAKUMO が未設定でも KIRA は今までどおり", (await call(env({ GATEWAY_TOKEN_YAKUMO: undefined }), "kira-aaaa")).status === 200);
check("片方だけ回しても、もう片方は止まらない", (await call(env({ GATEWAY_TOKEN: "kira-new" }), "yakumo-bbbb")).status === 200 && (await call(env({ GATEWAY_TOKEN: "kira-new" }), "kira-aaaa")).status === 401);
check("/healthz はトークン無しで 200", (await call(env(), undefined, "/healthz")).status === 200);
check("/version もトークンが要る", (await call(env(), undefined, "/version")).status === 401);

console.log(pass + " passed, " + fail + " failed");
if (fail) process.exit(1);
console.log("all green");
