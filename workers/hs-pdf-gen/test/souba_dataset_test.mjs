// 2026-10-19: the paid diagnosis names the souba-db bytes it read (diagnose().dataset), and GET /souba-dataset says which
// copy R2 holds. Run: node workers/hs-pdf-gen/test/souba_dataset_test.mjs   (R2 is a stub; no network)
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import w from '../src/worker.js';
let pass = 0, fail = 0;
const t = (name, ok) => { ok ? pass++ : fail++; console.log((ok ? 'ok   ' : 'NG   ') + name); };
const DB = readFileSync(new URL('../../../data/souba-db.json', import.meta.url), 'utf8');
const SHA = createHash('sha256').update(Buffer.from(DB, 'utf8')).digest('hex');
const env = (text) => ({ PDFS_BUCKET: { get: async (k) => (k === 'souba-db.json' && text !== null ? { text: async () => text } : null) } });
const get = async (e) => { const r = await w.fetch(new Request('https://hs-pdf-gen.example/souba-dataset'), e, { waitUntil() {} }); return { status: r.status, j: await r.json() }; };
let r = await get(env(DB));
t('GET /souba-dataset names the version and the sha256 of the R2 bytes', r.status === 200 && r.j.version === JSON.parse(DB)._meta.version && r.j.sha256 === SHA);
r = await get(env(null));
t('no souba-db in R2 is a 503 read failure, not an answer', r.status === 503 && r.j.read_failed === true);
console.log(fail ? `${fail} NG / ${pass} ok` : `ALL PASS (${pass})`);
process.exit(fail ? 1 : 0);
