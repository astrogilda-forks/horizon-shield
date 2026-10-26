// The ledger's ed25519PointOk must give the same answer as the SDK's ed25519KeyOk on every key it is asked about.
import { ed25519PointOk } from "../src/ed25519_point.mjs";
import { ed25519KeyOk } from "../nenrin/task-delegation-bind-v0/ed25519_key.mjs";
import { webcrypto, verify as nodeVerify, KeyObject } from "node:crypto";
const R = []; const t = (n, ok) => R.push({ n, ok: !!ok });
const hex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const cases = [
  ["identity (order 1)", "0100000000000000000000000000000000000000000000000000000000000000", false],
  ["order 2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false],
  ["order 4", "0000000000000000000000000000000000000000000000000000000000000080", false],
  ["order 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", false],
  ["order 8 (2)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", false],
  ["non-canonical y >= p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false],
  ["base point", "5866666666666666666666666666666666666666666666666666666666666666", true],
];
for (const [n, h, want] of cases) { const k = hex(h); t(n + ": " + want, ed25519PointOk(k) === want && ed25519KeyOk(k) === want); }
for (let i = 0; i < 64; i++) {
  const kp = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]);
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", kp.publicKey));
  if (!(ed25519PointOk(raw) === true && ed25519KeyOk(raw) === true)) { t("random real key " + i, false); break; }
  const flip = raw.slice(); flip[0] ^= 1;
  if (ed25519PointOk(flip) !== ed25519KeyOk(flip)) { t("flipped key " + i + " agrees", false); break; }
}
t("64 real keys accepted and 64 one-bit variants agree with the SDK", true);
t("length other than 32 is refused", !ed25519PointOk(new Uint8Array(31)) && !ed25519PointOk(null));
// Non-canonical S (2026-10-26). THREAT_MODEL T1 listed as untested whether the WebCrypto path refuses a signature
// whose S is not reduced (S >= L, so one message and key would have more than one valid signature). RFC 8032 5.1.7
// requires S < L. S + L and S + 2L still fit in 32 bytes. The refusal comes from the runtime's OpenSSL, not from
// code here, so this pins it: if a runtime ever accepts them, this test fails.
{
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const kp = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const msg = new TextEncoder().encode("non-canonical S");
  const sig = new Uint8Array(await webcrypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, msg));
  let S = 0n; for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(sig[i]);
  const withS = (x) => { const b = sig.slice(); for (let i = 32; i < 64; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
  const pub = KeyObject.from(kp.publicKey);
  t("the reduced signature verifies (WebCrypto and node:crypto)", (await webcrypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, sig, msg)) && nodeVerify(null, msg, pub, sig));
  for (const k of [1n, 2n]) {
    const b = withS(S + k * L);
    t("S + " + k + "L is refused by WebCrypto", !(await webcrypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, b, msg)));
    t("S + " + k + "L is refused by node:crypto", !nodeVerify(null, msg, pub, b));
  }
}
for (const r of R) console.log((r.ok ? "PASS  " : "FAIL  ") + r.n);
const bad = R.filter((r) => !r.ok).length; console.log(bad ? bad + " FAILURES" : "ed25519_point: all passed"); process.exitCode = bad ? 1 : 0;
