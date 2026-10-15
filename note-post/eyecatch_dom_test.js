// 見出し画像を付ける手順(uploadEyecatch)を、note のエディタを真似た小さな画面で確かめる(2026-10-02)。
// ネットワークにも note にも出ない。Chrome だけ要る(CHROME_PATH)。
//
// なぜ要るか: 第1話は「Node is either not clickable」、第2話は「見出し画像のボタンは在るが見えていない(1 個)」で、
//   どちらも見出し画像が付かないまま公開された。note のエディタは、見出し画像のボタンを題の上に
//   マウスが来たときだけ見せる作りとみられる。題の上をなぞってから探す、見えないままでも題より上の口なら押す、
//   題より下の「画像を追加」(本文に画像を入れる口)は押さない、付いたかを題の上の画像で確かめる、を見る。
//
// 走らせ方: CHROME_PATH=/usr/bin/google-chrome-stable node note-post/eyecatch_dom_test.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { uploadEyecatch } = require('./post_to_note.js');

const CHROME = process.env.CHROME_PATH || '/usr/bin/google-chrome-stable';
const PNG1 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
const pngPath = path.join(os.tmpdir(), 'eyecatch-test.png');
fs.writeFileSync(pngPath, Buffer.from(PNG1, 'base64'));

let ran = 0, bad = 0;
const ok = (c, label) => { ran++; if (!c) { bad++; console.log('  NG ', label); } };

function page(hdrCss, opts) {
  const o = opts || {};
  return `<!doctype html><meta charset="utf-8"><style>
body{margin:0;font-family:sans-serif} .hdr{min-height:120px;position:relative;padding:8px}
${hdrCss}
textarea{display:block;width:700px;height:60px;margin:8px} [contenteditable]{min-height:300px;margin:8px;border:1px solid #ccc}
.bodybar{margin:8px}
</style>
<div class="bar" style="height:56px;display:flex;justify-content:flex-end;gap:8px;align-items:center;padding:0 12px"><button>閉じる</button><button>下書き保存</button><button>公開に進む</button></div>
<div class="hdr">${o.noHeaderButton ? '' : (o.noLabel ? '<button class="eb"><svg width="20" height="20"><rect width="20" height="20"/></svg></button>' : '<button class="eb" aria-label="画像を追加">＋</button>')}</div>
<textarea placeholder="記事タイトル"></textarea>
<div class="bodybar">${o.bodyButton ? '<button class="bb" aria-label="画像を追加">本文に画像</button>' : ''}${o.hiddenMenu ? '<div style="position:absolute;left:0;top:0;width:100%;height:100%;pointer-events:none"><div style="width:0;height:0;overflow:hidden"><button class="hm" aria-label="画像を追加">画像</button></div></div>' : ''}</div>
<div contenteditable="true">本文</div>
<input type="file" id="f" accept="image/*" style="display:none">
<script>
const f = document.getElementById('f');
const direct = ${o.direct ? 'true' : 'false'};
const eb = document.querySelector('.eb');
if (eb) eb.addEventListener('click', () => {
  if (direct) { f.dataset.to = 'header'; f.click(); return; }
  const m = document.createElement('div'); m.id = 'menu';
  m.innerHTML = ${o.portalMenu
    ? "'<ul style=\"position:fixed;left:660px;top:150px;background:#fff;list-style:none;padding:4px;margin:0\"><li id=\"up\" style=\"padding:8px\"><svg width=\"16\" height=\"16\"></svg><span>画像をアップロードする</span></li><li style=\"padding:8px\"><span>記事にあう画像を選ぶ</span></li></ul>'"
    : "'<div role=\"menuitem\" id=\"up\" style=\"padding:8px;background:#fff\">画像をアップロード</div>'"};
  (${o.portalMenu ? 'document.body' : "document.querySelector('.hdr')"}).appendChild(m);
  document.getElementById('up').onclick = () => { f.dataset.to = 'header'; f.click(); };
});
const bb = document.querySelector('.bb');
if (bb) bb.addEventListener('click', () => { f.dataset.to = 'body'; f.click(); });
const hm = document.querySelector('.hm');
if (hm) hm.addEventListener('click', () => { f.dataset.to = 'body'; f.click(); });
f.addEventListener('change', () => {
  // どの口も押さずにファイル欄へ直に入れた画像は、本物の画面では本文に入るかもしれない。見出しに付いたとは数えない。
  const to = f.dataset.to || 'stray';
  if (to !== 'header') { window.__body = (window.__body || 0) + 1; const im = new Image(); im.style.cssText = 'width:600px;height:200px;display:block'; im.src = 'data:image/png;base64,${PNG1}'; document.querySelector('[contenteditable]').appendChild(im); return; }
  const mm = document.getElementById('menu'); if (mm) mm.remove();
  const d = document.createElement('div'); d.setAttribute('role', 'dialog');
  d.style.cssText = 'position:fixed;top:100px;left:100px;width:600px;height:400px;background:#eee';
  d.innerHTML = '<button id="save">保存</button>';
  document.body.appendChild(d);
  document.getElementById('save').onclick = () => {
    // M: 保存を押しても何も起きない(画面が残り、画像も付かない)。
    if (${o.saveNoop ? 'true' : 'false'}) return;
    d.remove();
    // L: 切り抜きの画面は閉じるが、別の小さな画面(role=dialog)が残る。Escape でも消えない。
    if (${o.lingerDialog ? 'true' : 'false'}) { const t = document.createElement('div'); t.setAttribute('role', 'dialog'); t.style.cssText = 'position:fixed;right:10px;bottom:10px;width:240px;height:40px;background:#ffd'; t.textContent = '画像を保存しました'; document.body.appendChild(t); }
    let im;
    if (${o.asBackground ? 'true' : 'false'}) { im = document.createElement('div'); im.style.cssText = 'width:800px;height:300px;background-image:url(data:image/png;base64,${PNG1});background-size:cover'; }
    else { im = new Image(); im.style.cssText = 'width:800px;height:300px;display:block'; im.src = 'data:image/png;base64,${PNG1}'; }
    document.querySelector('.hdr').prepend(im); window.__header = f.files[0] && f.files[0].name;
  };
});
</script>`;
}

const CASES = [
  { name: 'A 題の上に来たときだけ見える(透明)', css: '.hdr .eb{opacity:0}.hdr:hover .eb{opacity:1}', want: true },
  { name: 'B 題の上に来たときだけ現れる(display)', css: '.hdr .eb{display:none}.hdr:hover .eb{display:inline-block}', want: true },
  { name: 'C いつも見えている', css: '', want: true },
  { name: 'D 押すとすぐファイルを選ぶ画面', css: '.hdr .eb{opacity:0}.hdr:hover .eb{opacity:1}', opts: { direct: true }, want: true },
  { name: 'E ずっと透明(なぞっても出ない)', css: '.hdr .eb{opacity:0}', want: true },
  { name: 'F 題より下の本文の口しか無い', css: '', opts: { noHeaderButton: true, bodyButton: true }, want: false },
  { name: 'G 見出しの口と本文の口が両方ある', css: '.hdr .eb{opacity:0}.hdr:hover .eb{opacity:1}', opts: { bodyButton: true }, want: true },
  { name: 'H 付いた画像を背景として敷く作り', css: '.hdr .eb{opacity:0}.hdr:hover .eb{opacity:1}', opts: { asBackground: true }, want: true },
  // 本物の画面(2026-10-02 第2話の 1-editor.png)に近い形: 見出しの口は名札の無い丸いボタンでいつも見えている。
  // 名札「画像を追加」を持つのは、大きさ 0 の入れ物の中の本文用の口だけ。本文の「+」も題の下にある。
  { name: 'I 本物に近い形(名札の無い見出しの口、隠れた本文の口)', css: '', opts: { noLabel: true, hiddenMenu: true, bodyButton: true }, want: true },
  // 2026-10-03 第3話: 丸いボタンは押せたが「アップロードの項目が見つからない」。項目の言葉が完全一致しない形。
  { name: 'J メニューの言葉が「画像をアップロードする」で、外に出した浮きメニュー', css: '', opts: { noLabel: true, portalMenu: true, bodyButton: true }, want: true },
  // 2026-10-04: 三回とも「保存のあとも画面が残った」と失敗扱いにしたが、公開の頁には画像が付いていた。
  { name: 'L 保存のあとに別の画面が残るが、題の上に画像が付いた', css: '', opts: { noLabel: true, portalMenu: true, bodyButton: true, lingerDialog: true }, want: true },
  { name: 'M 保存を押しても画面が残り、画像も付かない', css: '', opts: { noLabel: true, portalMenu: true, bodyButton: true, saveNoop: true }, want: false },
];

(async () => {
  if (!fs.existsSync(CHROME)) { console.log('Chrome が無い: ' + CHROME); process.exit(2); }
  const browser = await require('puppeteer-core').launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  process.env.NOTE_DEBUG_SHOTS = '0';
  try {
    for (const c of CASES) {
      console.log(c.name);
      const p = await browser.newPage();
      await p.setViewport({ width: 1280, height: 900 });
      await p.setContent(page(c.css, c.opts), { waitUntil: 'load' });
      await p.mouse.move(1200, 880);
      const r = await uploadEyecatch(p, pngPath);
      const st = await p.evaluate(() => ({ header: window.__header || null, body: window.__body || 0 }));
      ok(!!r.ok === c.want, c.name + ': 結果 ' + JSON.stringify(r));
      if (c.want) ok(st.header === 'eyecatch-test.png', c.name + ': 見出しに付いた画像 ' + st.header);
      ok(st.body === 0, c.name + ': 本文に画像を入れていない (' + st.body + ')');
      await p.close();
    }
    console.log('K 「投稿する」が出るまで待つ');
    const { waitForButtonText } = require('./post_to_note.js');
    const pk = await browser.newPage();
    await pk.setContent('<div id=a></div><script>setTimeout(()=>{document.getElementById("a").innerHTML="<button>投稿する</button>"},1200)</script>');
    ok(await waitForButtonText(pk, '投稿する', 5000), 'K 後から出る「投稿する」を待てる');
    await pk.setContent('<button>下書き保存</button>');
    ok(!(await waitForButtonText(pk, '投稿する', 1500)), 'K 出ないときは待ちきって false');
    await pk.close();
  } finally { await browser.close(); }
  const EXPECT = CASES.reduce((n, c) => n + (c.want ? 3 : 2), 0) + 2;
  console.log('\n実行 ' + ran + ' 件 / 失敗 ' + bad + ' 件');
  if (ran !== EXPECT) { console.log('検査の数が違う(' + EXPECT + ' 件のはず)'); process.exit(2); }
  if (bad) { console.log('見出し画像の手順の検査に失敗がある'); process.exit(1); }
  console.log('見出し画像の手順の検査 すべて通過');
})().catch((e) => { console.error(e); process.exit(1); });
