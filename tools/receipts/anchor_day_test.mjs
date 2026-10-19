// tools/receipts/anchor_day_test.mjs: the receipt anchor job offline (2026-10-19). Run: node tools/receipts/anchor_day_test.mjs
import { collect, batchBytes, sha256, STORE, yesterday } from "./anchor_day.mjs";
let n = 0, bad = 0;
const ok = (c, m) => { n++; console.log((c ? "ok   " : "FAIL ") + m); if (!c) bad++; };
const D = "2026-10-20";
const claim = (w) => ({ work: w, unit: "㎡", fair_min: 1, fair_avg: 2, fair_max: 3, source: "HORIZON SHIELD souba-db", issued_at: D + "T01:02:03.000Z" });
const c1 = claim("a"), c2 = claim("b"), c3 = { ...claim("c"), issued_at: "2026-10-19T23:59:59.000Z" };
const h1 = sha256(JSON.stringify(c1)), h2 = sha256(JSON.stringify(c2)), h3 = sha256(JSON.stringify(c3));
const tampered = "f".repeat(64);
const store = { [h1]: { claim: c1 }, [h2]: { claim: c2 }, [h3]: { claim: c3 }, [tampered]: { claim: c1 } };
const fake = (day) => async (u) => {
  if (u === STORE + "day/" + D) return new Response(JSON.stringify(day), { status: 200 });
  const h = u.slice(STORE.length);
  return store[h] ? new Response(JSON.stringify(store[h]), { status: 200 }) : new Response("{}", { status: 404 });
};
const dayOf = (list, extra) => ({ schema: "hs-fair-price-receipt-day-v1", date: D, complete: true, receipts: list, ...(extra || {}) });
let r = await collect(D, fake(dayOf([h2, h1, h1])));
ok(r.good.map((x) => x.sha).join() === [h1, h2].sort().join() && !r.refused.length, "the day's receipts recompute, duplicates collapse, sorted");
r = await collect(D, fake(dayOf([h1, tampered, h3, "0".repeat(64)])));
ok(r.good.length === 1 && r.refused.length === 3, "a claim that does not recompute, one issued on another day, and one the store does not have are refused, not anchored");
let threw = false;
try { await collect(D, fake(dayOf([h1], { complete: false }))); } catch (_e) { threw = true; }
ok(threw, "an incomplete list is an error, not a smaller day");
threw = false;
try { await collect(D, async () => new Response("down", { status: 503 })); } catch (_e) { threw = true; }
ok(threw, "a list that cannot be read is an error, never an empty day");
const b = JSON.parse(batchBytes(D, [h1, h2]));
ok(b.schema === "hs-fair-price-receipt-batch-v1" && b.count === 2 && b.records[1].sha === h2 && batchBytes(D, [h1, h2]) === batchBytes(D, [h1, h2]), "the batch lists each receipt as records[i].sha, the same bytes every time");
ok(yesterday(new Date("2026-10-21T00:30:00Z")) === "2026-10-20", "the default day is yesterday in UTC");
console.log(bad ? bad + " FAIL / " + n : "ALL PASS (" + n + ")");
process.exit(bad ? 1 : 0);
