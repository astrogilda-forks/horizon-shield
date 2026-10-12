// test/receipt_schema.test.mjs : the receipt page names a record's own schema (2026-10-13).
// Entry 88 (a nenrin-agreement-batch-v1) was shown as "schema v0 · concept-proof" with a note about estimate JSON.
// A record that names its own schema is labelled by it; a record with no schema keeps the v0 note.
//   node test/receipt_schema.test.mjs
import { loadWorker, sha256Hex, mockKV, checker } from "./load.mjs";

const worker = await loadWorker("src/worker.js");
const batch = JSON.stringify({ schema: "nenrin-agreement-batch-v1", count: 1, records: [] });
const evil = JSON.stringify({ schema: "<img src=x onerror=alert(1)>", count: 0 });
const v0 = JSON.stringify({ title: "SPEC_HASH_INDEPENDENCE_v1.md", sha256: "deadbeef" });
const ent = async (n, rec) => [`entry:${n}`, JSON.stringify({ n, work: "x", claim_sha256: await sha256Hex(rec), record_canonical: rec, schema: "v0", created_at: "2026-10-12T00:45:17Z", ots_status: "confirmed", bitcoin_block: 971024, block_time: "2026-10-12 02:08 UTC" })];
const kv = mockKV([["seq", "4"], await ent(2, v0), await ent(3, batch), await ent(4, evil)]);
const env = { LEDGER: kv.binding };
const page = async (n) => (await worker.fetch(new Request("https://ledger.example.dev/ledger/" + n), env)).text();
const chk = checker("receipt_schema");

let t = await page(3);
chk("a NENRIN batch is badged with its own schema", t.includes("record schema nenrin-agreement-batch-v1"));
chk("and not as a v0 estimate entry", !t.includes("concept-proof") && !t.includes("only the estimate JSON is hashed"));
chk("its card says what kind of record it is", t.includes("This entry is a nenrin-agreement-batch-v1 record"));
t = await page(2);
chk("a record with no schema keeps the v0 badge and note", t.includes("schema v0 · concept-proof") && t.includes("only the estimate JSON is hashed"));
t = await page(4);
chk("a schema name is HTML-escaped on the page", !t.includes("<img src=x") && t.includes("&lt;img src=x onerror=alert(1)&gt;"));
process.exit(chk.done() ? 1 : 0);
