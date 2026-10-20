// 2026-10-20: AIシミュレーター(やくも)専用の PDF トークン PDFGEN_TOKEN_YAKUMO の試験。
// 通すのは /generate-meitsumori-signed だけで、ほかの生成・監査の口は今までどおり PDFGEN_TOKEN(と X-HS-TOKEN)だけ。
// 実行: node workers/hs-pdf-gen/test/yakumo_pdf_token_test.mjs  (KV と R2 は偽物。門を通った後の失敗は 401 以外 = 門を通った印)
import w from '../src/worker.js';

let pass = 0, fail = 0;
const t = (name, ok, detail) => { ok ? pass++ : fail++; console.log((ok ? 'ok   ' : 'NG   ') + name + (ok || detail === undefined ? '' : '  <<< ' + detail)); };

const mem = new Map();
const ORDERS = { get: async (k) => (mem.has(k) ? mem.get(k) : null), put: async (k, v) => { mem.set(k, v); } };
const PDFS_BUCKET = { get: async () => null, put: async () => {} };
const TOKEN = 'test-pdfgen-token';
const YAKUMO = 'test-yakumo-pdf-token';
const mkEnv = (over = {}) => ({ ORDERS, PDFS_BUCKET, PDFGEN_TOKEN: TOKEN, PDFGEN_TOKEN_YAKUMO: YAKUMO, ENVIRONMENT: 'production', ...over });
const call = async (path, { headers = {}, env = mkEnv() } = {}) => {
  const req = new Request('https://hs-pdf-gen.example' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: '{}' });
  try { const r = await w.fetch(req, env, { waitUntil() {} }); return r.status; } catch (_e) { return 'threw'; }
};
const origError = console.error;
console.error = () => {};

const SIGNED = '/generate-meitsumori-signed';
const OTHERS = ['/generate-test', '/generate-plan-auto', '/generate-plan', '/generate-meitsumori', '/generate-kanryo', '/extract-estimate', '/generate-estimate-audit', '/generate-compare', '/generate'];

t('やくものトークンで ' + SIGNED + ' の門を通る', (await call(SIGNED, { headers: { 'X-PDF-Token': YAKUMO } })) !== 401);
t('今までのトークンでも ' + SIGNED + ' の門を通る', (await call(SIGNED, { headers: { 'X-PDF-Token': TOKEN } })) !== 401);
t('トークン無しは ' + SIGNED + ' で 401', (await call(SIGNED)) === 401);
t('違う値は ' + SIGNED + ' で 401', (await call(SIGNED, { headers: { 'X-PDF-Token': YAKUMO + 'x' } })) === 401);
t('PDFGEN_TOKEN_YAKUMO が未設定なら、やくもの値でも 401', (await call(SIGNED, { headers: { 'X-PDF-Token': YAKUMO }, env: mkEnv({ PDFGEN_TOKEN_YAKUMO: undefined }) })) === 401);
t('PDFGEN_TOKEN_YAKUMO が未設定なら、空の値でも 401', (await call(SIGNED, { headers: { 'X-PDF-Token': '' }, env: mkEnv({ PDFGEN_TOKEN_YAKUMO: undefined }) })) === 401);
for (const p of OTHERS) {
  t('やくものトークンでは ' + p + ' は 401(通すのは署名つき見積の口だけ)', (await call(p, { headers: { 'X-PDF-Token': YAKUMO } })) === 401);
}
t('今までのトークンを回しても、やくものトークンは止まらない', (await call(SIGNED, { headers: { 'X-PDF-Token': YAKUMO }, env: mkEnv({ PDFGEN_TOKEN: 'rotated' }) })) !== 401);

console.error = origError;
console.log(pass + ' passed, ' + fail + ' failed');
if (fail) process.exit(1);
console.log('all green');
