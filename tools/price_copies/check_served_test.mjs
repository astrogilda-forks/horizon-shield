// tools/price_copies/check_served_test.mjs: the served-copy check offline (2026-10-19).
import { measure, PDF_URL, GATEWAY_URL } from "./check_served.mjs";
import { createHash } from "node:crypto";
let n = 0, bad = 0;
const ok = (c, m) => { n++; console.log((c ? "ok   " : "FAIL ") + m); if (!c) bad++; };
const FILE = Buffer.from('{"_meta":{"version":"2.3.0"},"categories":[]}');
const S = createHash("sha256").update(FILE).digest("hex");
const fake = (pdfSha, gwBytes, gwStatus = 200) => async (u) => {
  if (u === PDF_URL) return pdfSha === null ? new Response("down", { status: 503 }) : new Response(JSON.stringify({ version: "x", sha256: pdfSha }), { status: 200 });
  if (u === GATEWAY_URL) return new Response(gwStatus === 200 ? gwBytes : "unauthorized", { status: gwStatus, headers: { "x-reference-version": "x" } });
  return new Response("", { status: 404 });
};
let r = await measure(FILE, fake(S, FILE), "t");
ok(!r.red && r.rows.every((x) => x.same), "both copies the same bytes: green");
r = await measure(FILE, fake("0".repeat(64), FILE), "t");
ok(r.red && r.rows[0].same === false, "hs-pdf-gen serving other bytes: red");
r = await measure(FILE, fake(S, Buffer.from("{}")), "t");
ok(r.red && r.rows[1].same === false, "the gateway serving other bytes: red");
r = await measure(FILE, fake(S, FILE), "");
ok(!r.red && r.rows[1].not_measured, "no gateway token: the gateway is reported as not measured, not as the same");
r = await measure(FILE, fake(null, FILE), "");
ok(r.red && r.rows[0].read_failed, "hs-pdf-gen unreadable: red (the paid diagnosis cannot be traced)");
r = await measure(FILE, fake(S, FILE, 401), "wrong");
ok(r.red && r.rows[1].read_failed === "HTTP 401", "a gateway token that is set but refused: red, not a silent green");
console.log(bad ? bad + " FAIL / " + n : "ALL PASS (" + n + ")");
process.exit(bad ? 1 : 0);
