// test/witness_github.test.mjs
// 2026-10-16. A witness with no domain of its own signs with a key served from a repository it owns,
// raw.githubusercontent.com/<owner>/<repo>/<branch or tag>/<path>, and is counted as github.com/<owner>.
// Every refusal below closes a way to borrow somebody else's identity.
// Run: node test/witness_github.test.mjs   (offline; fetch is replaced for key_url lookups)

import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { loadWorker, mockKV, checker } from "./load.mjs";

const worker = await loadWorker("src/worker.js");
const chk = checker("hs-ledger witness github lane");
const ORIGIN = "https://ledger.horizonshield.dev";

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  return { privateKey, pub_b64: Buffer.from(der.subarray(der.length - 32)).toString("base64") };
}
const A = keypair();      // alice's key, served from her repository
const D = keypair();      // a domain witness, served from its own domain
const OTHER = keypair();

const RAW = "https://raw.githubusercontent.com";
const SERVED = new Map([
  [RAW + "/alice/nenrin-key/main/witness-key.json", A.pub_b64],
  [RAW + "/Alice/nenrin-key/main/witness-key.json", A.pub_b64],
  [RAW + "/alice/nenrin-key/refs/heads/main/witness-key.json", A.pub_b64],
  [RAW + "/alice/nenrin-key/v1/keys/witness-key.json", A.pub_b64],
  [RAW + "/alice/nenrin-key/0123456789abcdef0123456789abcdef01234567/witness-key.json", A.pub_b64],
  [RAW + "/alice/nenrin-key/abc1234/witness-key.json", A.pub_b64],
  [RAW + "/bob/keys/main/witness-key.json", OTHER.pub_b64],
  [RAW + "/ogasurfproject-jpg/horizon-shield/main/witness-key.json", A.pub_b64],
  ["https://gist.githubusercontent.com/alice/abc/raw/witness-key.json", A.pub_b64],
  ["https://github.com/alice/nenrin-key/raw/main/witness-key.json", A.pub_b64],
  ["https://witness.example/.well-known/nenrin-witness-key.json", D.pub_b64],
]);
globalThis.fetch = async (url) => {
  const u = String(url);
  // raw.githubusercontent.com answers with text/plain; the intake must still read the JSON body.
  if (SERVED.has(u)) return new Response(JSON.stringify({ public_key_ed25519_b64: SERVED.get(u) }), { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
  return new Response("404: Not Found", { status: 404 });
};

const canon = (o) => JSON.stringify(sortKeys(o));
function sortKeys(x) {
  if (Array.isArray(x)) return x.map(sortKeys);
  if (x && typeof x === "object") return Object.fromEntries(Object.keys(x).sort().map((k) => [k, sortKeys(x[k])]));
  return x;
}
const SHA = "a".repeat(64);
function rec(keyUrl, over = {}) {
  return {
    schema: "jidec-path-v1", purpose: "a2a-conduct-walk-v1: https://mcp.horizonshield.dev/mcp",
    walked_at: "2026-10-16T01:00:00Z", base: "https://mcp.horizonshield.dev",
    witness: { name: "Alice", vantage: "test", ...(keyUrl ? { key_url: keyUrl } : {}) },
    nodes: [{ id: "n0", kind: "fetch", request: { url: "https://mcp.horizonshield.dev/.well-known/agent-card.json", method: "GET" }, response: { status: 200, body_sha256: SHA } }],
    assertions: [{ claim: "card_bytes_stable", op: "eq", result: true, evidence_nodes: ["n0"] }],
    verdict: { ok: true, outcome: "PASS", n_pass: 1, n_total: 1 },
    mode: "full",
    establishes: ["card fetched from https://mcp.horizonshield.dev"],
    does_not_establish: ["correctness of any response", "identity of the witness beyond the key's GitHub account"],
    ...over,
  };
}

let kvMock, env;
function reset() { kvMock = mockKV([["seq", "40"]]); env = { LEDGER: kvMock.binding, LEDGER_ADMIN_TOKEN: "t".repeat(64) }; }
async function post(r, key, ip = "203.0.113.9") {
  const record_canonical = canon(r);
  const body = { record_canonical };
  if (key) {
    body.public_key_ed25519_b64 = key.pub_b64;
    body.signature_ed25519_b64 = edSign(null, Buffer.from(record_canonical, "utf8"), key.privateKey).toString("base64");
  }
  const res = await worker.fetch(new Request(ORIGIN + "/witness", {
    method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body),
  }), env);
  return { status: res.status, j: await res.json() };
}
const show = (r) => JSON.stringify(r.j);

// 1. The plain form is accepted and counted under github.com/<owner>.
reset();
let r = await post(rec(RAW + "/alice/nenrin-key/main/witness-key.json"), A);
chk("raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>: accepted as github.com/alice", r.status === 201 && r.j.signed === true && r.j.signed_domain === "github.com/alice" && r.j.counted === true, show(r));

// 2. The owner is lower-cased (GitHub account names are case-insensitive), so one account is one identity.
r = await post(rec(RAW + "/Alice/nenrin-key/main/witness-key.json", { walked_at: "2026-10-16T01:01:00Z" }), A);
chk("owner case folded: Alice counts as github.com/alice, second walk same day not counted", r.status === 201 && r.j.signed_domain === "github.com/alice" && r.j.counted === false, show(r));

// 3. refs/heads/<branch> and a tag ref with a nested path are the same account.
reset();
r = await post(rec(RAW + "/alice/nenrin-key/refs/heads/main/witness-key.json"), A);
chk("refs/heads/<branch> form accepted", r.status === 201 && r.j.signed_domain === "github.com/alice", show(r));
reset();
r = await post(rec(RAW + "/alice/nenrin-key/v1/keys/witness-key.json"), A);
chk("tag ref with a nested path accepted", r.status === 201 && r.j.signed_domain === "github.com/alice", show(r));

// 4. A commit SHA as the ref is refused: a fork's commit is served under the parent's path.
reset();
r = await post(rec(RAW + "/alice/nenrin-key/0123456789abcdef0123456789abcdef01234567/witness-key.json"), A);
chk("40-hex commit ref refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url" && /commit SHA/.test(r.j.why), show(r));
r = await post(rec(RAW + "/alice/nenrin-key/abc1234/witness-key.json"), A);
chk("7-hex short commit ref refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));

// 5. Shared GitHub hosts are not an identity.
r = await post(rec("https://gist.githubusercontent.com/alice/abc/raw/witness-key.json"), A);
chk("gist.githubusercontent.com refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));
r = await post(rec("https://github.com/alice/nenrin-key/raw/main/witness-key.json"), A);
chk("github.com/<owner>/<repo>/raw/... refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));

// 6. Malformed GitHub paths and queries.
r = await post(rec(RAW + "/alice/nenrin-key/main"), A);
chk("no file path refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));
r = await post(rec(RAW + "/alice/nenrin-key/main/witness-key.json?token=x"), A);
chk("query string refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));
r = await post(rec(RAW + "/-alice/nenrin-key/main/witness-key.json"), A);
chk("invalid owner name refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));

// 7. This project's own account cannot witness this project's agents.
r = await post(rec(RAW + "/ogasurfproject-jpg/horizon-shield/main/witness-key.json"), A);
chk("our own GitHub account refused: self_witness", r.status === 422 && r.j.reason_code === "self_witness", show(r));

// 8. A key served from somebody else's repository does not match the signing key.
r = await post(rec(RAW + "/bob/keys/main/witness-key.json"), A);
chk("signed with alice's key but key_url is bob's: key_url_mismatch", r.status === 422 && r.j.reason_code === "key_url_mismatch", show(r));

// 9. A key_url that answers 404 is unreachable, never an identity.
r = await post(rec(RAW + "/carol/keys/main/witness-key.json"), A);
chk("404 key_url: key_url_unreachable", r.status === 503 && r.j.reason_code === "key_url_unreachable", show(r));

// 10. Unsigned record with a GitHub key_url binds nothing.
r = await post(rec(RAW + "/alice/nenrin-key/main/witness-key.json"), null);
chk("unsigned record with GitHub key_url refused: bad_key_url", r.status === 422 && r.j.reason_code === "bad_key_url", show(r));

// 10b. Other path-shared hosts are refused the same way, so no shared host can ever become one identity for everyone.
for (const u of ["https://gitlab.com/alice/k/-/raw/main/witness-key.json", "https://cdn.jsdelivr.net/gh/alice/k@main/witness-key.json",
                 "https://storage.googleapis.com/somebucket/witness-key.json", "https://s3.us-east-1.amazonaws.com/b/witness-key.json",
                 "https://pastebin.com/raw/abc"]) {
  r = await post(rec(u), A);
  chk("shared host refused: " + new URL(u).hostname, r.status === 422 && r.j.reason_code === "bad_key_url", show(r));
}

// 10c. raw.githubusercontent.com itself is never an identity: every accepted GitHub record names an owner.
reset();
r = await post(rec(RAW + "/alice/nenrin-key/main/witness-key.json"), A);
chk("raw.githubusercontent.com never appears as signed_domain", r.status === 201 && r.j.signed_domain !== "raw.githubusercontent.com" && r.j.signed_domain.startsWith("github.com/"), show(r));

// 11. The domain lane is unchanged.
reset();
r = await post(rec("https://witness.example/.well-known/nenrin-witness-key.json"), D);
chk("domain lane unchanged: signed_domain witness.example", r.status === 201 && r.j.signed_domain === "witness.example", show(r));

// 12. GET /witness states the GitHub lane.
const info = await (await worker.fetch(new Request(ORIGIN + "/witness"), env)).json();
chk("GET /witness documents the GitHub lane", JSON.stringify(info).includes("raw.githubusercontent.com/<owner>/<repo>/<branch or tag>/<path>"), "");

process.exit(chk.done() ? 1 : 0);
