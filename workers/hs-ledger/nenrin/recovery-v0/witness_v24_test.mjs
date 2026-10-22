// RUN_ALL: suite
// v2.4 の採点 (red team R2-1 と R5-F1、2026-10-22)。witness_v24_cases.mjs の各入力を今の検証器に通し、
// 断るべき物が断られ、通るべき物が通り、古い形の印 (forms) が付くかを見る。
// 直す前の検証器 (0.3.1) では、v2.2 の形の攻めは全部通っていた (v2.4 の形の入力は、0.3.1 ではそもそも読めない)。その記録は case の old に書いてある (この file は 0.4.0 だけを採点する)。
// 緑の意味: この file の攻めが断られた。それ以上のことは言わない。ほかの攻めが無いことは言わない。
import { verifyChain } from "./recovery_verify.mjs";
import { buildV24Cases } from "./witness_v24_cases.mjs";

let pass = 0, fail = 0; const results = [];
function t(name, ok, detail) { (ok ? pass++ : fail++); results.push((ok ? "  ok   " : "  FAIL ") + name + (ok || !detail ? "" : "  <- " + detail)); }

const cases = await buildV24Cases();
t("cases: 15 inputs built", cases.length === 15, String(cases.length));
for (const c of cases) {
  const r = await verifyChain(c.records, { witnessQuorum: c.quorum });
  const codes = r.refusals.map((x) => x.code);
  const forms = r.segment && r.segment.witness ? r.segment.witness.forms : undefined;
  let ok = r.ok === c.new.ok;
  if (c.new.codes) ok = ok && c.new.codes.every((x) => codes.includes(x));
  if (c.new.forms) ok = ok && JSON.stringify(forms) === JSON.stringify(c.new.forms);
  t(c.name + (c.new.ok ? " -> passes" : " -> " + c.new.codes.join(", ")), ok, JSON.stringify({ ok: r.ok, codes, forms }));
}

console.log(results.join("\n"));
console.log("\n=== " + pass + " / " + (pass + fail) + " 合格 (witness-v24: red team R2-1 と R5-F1 の攻め、v2.2 の記録の読み) ===");
console.log("この緑は: 依頼の使い回し、k の広げ、beacon の後の池の選び直し、時刻の逆転が、この file の入力では断られた。それ以上のことは言わない。");
process.exit(fail ? 1 : 0);
