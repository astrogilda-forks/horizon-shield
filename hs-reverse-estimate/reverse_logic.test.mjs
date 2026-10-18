// reverse_logic.test.mjs (2026-10-07): 逆見積もりの結果画面の決まった計算を、公開の正本 data/souba-db.json と相場ページに当てて確かめる。
// 走らせ方: node hs-reverse-estimate/reverse_logic.test.mjs   (ネットワークは使わない)
import { createRequire } from "node:module";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const L = createRequire(import.meta.url)("./reverse_logic.js");
const DB = JSON.parse(readFileSync(path.join(ROOT, "data", "souba-db.json"), "utf8"));
const page = (rel) => readFileSync(path.join(ROOT, rel), "utf8");
const INDEX = page("hs-reverse-estimate/index.html");

let pass = 0, fail = 0;
const t = (name, ok, detail) => { ok ? pass++ : fail++; console.log((ok ? "ok   " : "NG   ") + name + (ok || detail === undefined ? "" : "  <<< " + detail)); };

// ---- 1. 3 件: 竹の幅が souba-db の行と、同じ工事の相場ページの数字に一致する ----
const NOW = new Date("2026-10-07T03:00:00Z");
const CASES = [
  { name: "外壁塗装 30坪 シリコン（平塚）", text: "神奈川県平塚市です。外壁塗装をしたい。延床30坪の2階建て、築15年の木造。塗料はシリコンで。", row: "gaiheki_30tsubo", take: [70, 115], page: "souba/gaiheki/index.html", pageText: "70〜115万円", danger: "150万円" },
  { name: "給湯器 20号", text: "給湯器が壊れたので交換したい。ガス給湯器の20号です。戸建て、神奈川。", row: "kyutoki_20", take: [15, 30], page: "souba/kyutoki/index.html", pageText: "15〜30万円", danger: "45万円" },
  { name: "トイレ交換", text: "トイレ交換をしたい。1階の1台、普通の便器でいいです。", row: "toilet_replace_basic", take: [7, 22], page: "souba/toilet-tankless-souba/index.html", pageText: "7から22万円", danger: "40万円" },
];
for (const c of CASES) {
  const row = L.matchSoubaRow(DB, c.text);
  t(c.name + ": souba-db の行が一つに決まる (" + c.row + ")", !!row && row.id === c.row, row && row.id);
  const v = L.buildView({ plan: { koji: c.name, take: [999, 9999] }, row, meta: DB._meta, now: NOW });
  t(c.name + ": 竹は " + c.take.join("〜") + " 万（KIRA の数字ではなく行の数字）", v.take && v.take[0] === c.take[0] && v.take[1] === c.take[1] && v.takeSource === "souba-db", JSON.stringify(v.take));
  t(c.name + ": 行の min と max そのまま（地域の係数を掛けない）", row && v.take[0] * 10000 === row.min && v.take[1] * 10000 === row.max);
  t(c.name + ": 相場ページ " + c.page + " に同じ数字がある (" + c.pageText + ")", page(c.page).includes(c.pageText));
  t(c.name + ": 危険ラインは行の danger (" + c.danger + ")", v.dangerText === c.danger, v.dangerText);
  t(c.name + ": 「検出」もリスクスコアも出さない", v.showDetected === false && v.showRiskScore === false);
  t(c.name + ": 確かめる項目に金額が無い", v.checklist.length >= 2 && v.checklist.every((x) => !/[0-9０-９]|円|万|超過/.test(x)), v.checklist.join(" / "));
  t(c.name + ": 画面に渡す物に松・梅・最悪額・差額・削減額が無い", !Object.keys(v).some((k) => /matsu|ume|worst|diff|saving/i.test(k)));
  t(c.name + ": 出典は今の版と算出した日", v.provenance.includes("souba-db " + DB._meta.version) && v.provenance.includes("算出日: 2026-10-07") && !/2\.1\.0|2026年5月|v15/.test(v.provenance), v.provenance);
}
t("正本の版は 2.3.0", DB._meta.version === "2.3.0", DB._meta.version);

// ---- 2. 行が一つに決まらない時は null（KIRA の積み上げを目安として出す） ----
const none = (name, text) => t("行を決めない: " + name, L.matchSoubaRow(DB, text) === null, JSON.stringify(L.matchSoubaRow(DB, text)));
none("工事が二つ（外壁とキッチン）", "外壁塗装30坪とキッチン交換をしたい");
none("外壁と給湯器", "外壁塗装30坪と給湯器20号");
none("行の無い坪数（35坪）", "外壁塗装 35坪 シリコン");
none("坪数が無い", "外壁塗装をしたい");
none("シリコン以外の塗料（一式の行はシリコンだけ）", "外壁塗装 30坪 フッ素塗料で");
none("号数の無い給湯器", "給湯器を交換したい");
none("トイレ 2 台", "トイレ交換を2台");
none("関係の無い工事", "和室をフローリングにしたい");
t("外壁＋屋根 30坪はセットの行", (L.matchSoubaRow(DB, "外壁と屋根の塗装、30坪") || {}).id === "gaiheki_yane_set_30tsubo");
t("タンクレスはタンクレスの行", (L.matchSoubaRow(DB, "トイレをタンクレスに交換") || {}).id === "toilet_replace_tankless");
t("全角の数字も読む", (L.matchSoubaRow(DB, "外壁塗装 ３０坪") || {}).id === "gaiheki_30tsubo");
{
  const v = L.buildView({ plan: { koji: "キッチン交換と床張替え", take: [120, 180] }, row: null, meta: DB._meta, now: NOW });
  t("行が無い時: 竹は KIRA の積み上げで、目安と書く", v.takeSource === "kira" && v.takeText === "120万〜180万円" && /目安/.test(v.takeNote) && v.dangerText === null);
  const e = L.buildView({ plan: { koji: "x", take: [0, 0] }, row: null, meta: null, now: NOW });
  t("何も無い時: 数字を作らない", e.take === null && e.takeText === null && /版を読めませんでした/.test(e.provenance));
}

// ---- 3. 指示文を画面に出さない ----
const LEAKS = [
  "プロセス1〜5を実行します。\n\nご希望の塗料のグレードを教えてください。",
  "プロセス1: 会話履歴を読み返します\nプロセス2: 既出情報をリストアップします\n築年数はどのくらいですか？",
  "ステップ1を確認しました。地域はどちらですか？",
  "【強制指示】に従い出力します。\n===PLAN===\n工事内容：外壁塗装\n松：100万円〜150万円\n竹：70万円〜115万円\n梅：55万円〜90万円\nアドバイス：相見積もりを。\n出典：souba-db\n===END===",
  "会話履歴から既出情報を抽出しました。構造を教えてください。",
];
for (const [i, s] of LEAKS.entries()) {
  const out = L.sanitizeReply(s);
  t("指示文 " + (i + 1) + ": 出力に指示文が無い", !L.hasDirective(out) && !/プロセス|ステップ\s*[0-9]|強制指示|既出情報/.test(out), out);
  t("指示文 " + (i + 1) + ": 施主に見せる本文は残る", out.length > 0 && (/教えてください|ですか|===PLAN===/.test(out)), out);
}
t("PLAN の中身は変えない", L.sanitizeReply(LEAKS[3]).includes("竹：70万円〜115万円") && L.sanitizeReply(LEAKS[3]).includes("===END==="));
t("普通の返答は 1 文字も変えない", L.sanitizeReply("なるほど。\n築年数はどのくらいですか？") === "なるほど。\n築年数はどのくらいですか？");

// ---- 4. ?work= ----
t("?work=外壁塗装 を読む", L.workFromQuery("?work=" + encodeURIComponent("外壁塗装")) === "外壁塗装");
t("タグや引用符は落とす", L.workFromQuery("?work=" + encodeURIComponent('<img src=x onerror="a">')) === "img src=x onerror=a");
t("長すぎる値は使わない", L.workFromQuery("?work=" + encodeURIComponent("あ".repeat(25))) === "");
t("無ければ空", L.workFromQuery("") === "" && L.workFromQuery("?x=1") === "");

// ---- 5. ページそのもの（index.html）に残っていてはいけない文字 ----
const GONE = ["AI比較", "ChatGPT", "Gemini", "v2.1.0", "2026年5月", "3,350", "souba-db v15", "過剰請求リスクスコア", "検出された過剰請求パターン", "万超過", "WORST CASE", "削減できる可能性", "他のAIには", "プロセス1", "プロセス5", "プロセス"];
for (const g of GONE) t("index.html に「" + g + "」が無い", !INDEX.includes(g));
t("index.html: 「見積もりを取ったら、ここを確かめる」がある", INDEX.includes("見積もりを取ったら、ここを確かめる"));
t("index.html: 竹の箱がある（無料で見せる）", INDEX.includes('id="take-price"') && !/竹[^<]{0,40}🔒/.test(INDEX));
t("index.html: 松・梅は ¥5,500 のまま鍵つき", (INDEX.match(/🔒 ¥5,500のレポートで確認/g) || []).length === 2 && INDEX.includes('<div class="cta-price">¥5,500</div>'));
t("index.html: 検証番号で再計算できる、の説明は残る", INDEX.includes("同じ条件で再計算すれば、同じ番号になります"));
t("index.html: reverse_logic.js を読み込む", INDEX.includes('<script src="reverse_logic.js"></script>'));

// ---- 6. 指示文はページに置かない。ワーカーに送るのは会話と状況だけ ----
for (const g of ["KIRA_SYSTEM", "kiraSystem", "絶対に守るルール", "ヒアリング5項目", "【強制指示】", "[指示：", "system:", "max_tokens", "__SOUBA_VER__"]) t("index.html に「" + g + "」が無い（指示文を持たない）", !INDEX.includes(g));
{
  const hist = [{ role: "user", content: "外壁塗装をしたい", extra: 1 }, { role: "assistant", content: "築年数は？" }, { role: "user", content: "15年" }];
  const p = L.chatPayload(hist, "reverse", "外壁塗装");
  t("送る物の欄は messages・mode・work・from だけ", JSON.stringify(Object.keys(p).sort()) === '["from","messages","mode","work"]');
  t("会話はそのまま（役と中身だけ）", JSON.stringify(p.messages) === JSON.stringify(hist.map((m) => ({ role: m.role, content: m.content }))));
  t("知らない状況は STEP 02 として送る", L.chatPayload(hist, "x", "").mode === "reverse" && L.chatPayload(hist, "estimate", "").mode === "estimate");
  t("index.html: 送る所は chatPayload を 2 か所で使う", (INDEX.match(/JSON\.stringify\(HSReverse\.chatPayload\(conversationHistory, currentMode, WORK_FROM_QUERY, ENTRY_FROM\)\)/g) || []).length === 2);
  t("ボタンの文はワーカーと同じ", L.PLAN_BUTTON_TEXT === "今の情報で概算を出してください");
}

// ---- 7. 「1 回限り」の印は結果を出した後。開き直したら結果をもう一度見せる ----
{
  const row = L.matchSoubaRow(DB, CASES[0].text);
  const view = L.buildView({ plan: { koji: "外壁塗装 30坪 シリコン", take: [77, 127] }, row, meta: DB._meta, now: NOW });
  t("結果（竹の幅）が出たら印を付ける", L.shouldMarkUsed(view) === true);
  t("竹の幅が出せなかった時は印を付けない", L.shouldMarkUsed(L.buildView({ plan: { koji: "x", take: [0, 0] }, row: null, meta: null, now: NOW })) === false);
  t("結果が無い時は印を付けない", L.shouldMarkUsed(null) === false);
  const snap = L.makeSnapshot({ view, advice: "相見積もりを。", hash: "0123abcd4567ef89", now: NOW, last: { koji: view.koji } });
  const raw = JSON.stringify(snap);
  const back = L.readSnapshot(raw);
  t("控えは読み戻せて、竹は 70〜115 万のまま", back && back.view.take[0] === 70 && back.view.take[1] === 115 && back.view.takeText === "70万〜115万円" && back.hash === "0123abcd4567ef89");
  t("控えに松・梅・最悪額・削減額の欄は無い", !/matsu|ume|worst|saving/i.test(Object.keys(back.view).join(",")));
  const st = L.loadState("1", raw);
  t("結果を出した後に開き直す: 結果をもう一度見せる", st.state === "restore" && st.snapshot.view.takeText === "70万〜115万円");
  t("結果を出す前に開き直す（印も控えも無い）: 最初からやり直せる", JSON.stringify(L.loadState(null, null)) === '{"state":"fresh","clearUsed":false}');
  t("前の版が最初の 1 通で付けた印だけが残っている: 印を消してやり直せる", JSON.stringify(L.loadState("1", null)) === '{"state":"fresh","clearUsed":true}');
  t("壊れた控え: 見せずに、印を消してやり直せる", L.loadState("1", "{").state === "fresh" && L.loadState("1", "{").clearUsed === true);
  t("竹の幅の無い控えは使わない", L.readSnapshot(JSON.stringify({ ...snap, view: { ...snap.view, take: null, takeText: null } })) === null);
  t("控えの検証番号は 16 進だけ", L.makeSnapshot({ view, hash: "<script>" }).hash === "");
  t("index.html: 最初の 1 通で印を付ける行が無い", !/conversationHistory\.length === 0\)\s*\{\s*localStorage\.setItem/.test(INDEX));
  t("index.html: 印を付けるのは 1 か所で、結果を出した所", (INDEX.match(/localStorage\.setItem\(HSReverse\.USED_KEY/g) || []).length === 1 && INDEX.indexOf("localStorage.setItem(HSReverse.USED_KEY") > INDEX.indexOf("function parsePlanNow") && INDEX.indexOf("localStorage.setItem(HSReverse.USED_KEY") < INDEX.indexOf("function renderView"));
  t("index.html: 「FREE LIMIT REACHED」だけの画面が無い", !INDEX.includes("FREE LIMIT REACHED") && !/main\.main'\)\.style\.display = 'none'/.test(INDEX));
  t("index.html: 開き直した人に結果と ¥5,500 の案内を出す", INDEX.includes("function showStoredResult") && INDEX.includes("¥5,500のレポートに入ります"));
}

// ---- 8. 入口(どこから来たか)と ¥5,500 のボタン。数えるための最小の物だけを送る ----
{
  const O = "https://shield.the-horizons-innovation.com";
  const Q = "?work=" + encodeURIComponent("外壁塗装");
  t("相場ページの箱から来た: box", L.entryFrom(Q, O + "/souba/gaiheki/", O) === "box");
  t("?work= 付きで他のサイトから(AI の案内など): work", L.entryFrom(Q, "https://chatgpt.com/", O) === "work" && L.entryFrom(Q, "", O) === "work");
  t("?work= 付きでも、相場ページ以外の自サイトのページからは work", L.entryFrom(Q, O + "/yakumo/", O) === "work" && L.entryFrom(Q, O + "/hs-reverse-estimate/" + Q, O) === "work");
  t("似た名前の別サイトを箱と数えない", L.entryFrom(Q, O + ".evil.example/souba/gaiheki/", O) === "work" && L.entryFrom(Q, "https://evil.example/?x=" + O + "/souba/", O) === "work");
  t("?work= 無しでも、相場ページから来たら box（工事名の無い箱 63 本の分）", L.entryFrom("", O + "/souba/gaiheki/", O) === "box");
  t("箱のリンクの from=box: 来た元が届かなくても box", L.entryFrom("?from=box", "", O) === "box" && L.entryFrom(Q + "&from=box", "", O) === "box" && L.entryFrom("?from=box#x", "", O) === "box");
  t("from=boxy のような別の値は box にしない", L.entryFrom("?from=boxy", "", O) === "direct" && L.entryFrom("?xfrom=box", "", O) === "direct");
  t("?work= も箱の印も無く、相場ページからでもない: direct", L.entryFrom("?admin=reset", "", O) === "direct" && L.entryFrom("", "https://www.google.com/", O) === "direct" && L.entryFrom("", O + "/yakumo/", O) === "direct");
  t("使えない工事名(長すぎ)は direct", L.entryFrom("?work=" + "あ".repeat(25), "", O) === "direct");
  t("開いた時に送る物は入口の語だけ", L.landBody("box") === '{"event":"land_box"}' && L.landBody("work") === '{"event":"land_work"}' && L.landBody("direct") === '{"event":"land_direct"}' && L.landBody("https://x/") === '{"event":"land_direct"}');
  const hist = [{ role: "user", content: "外壁塗装をしたい" }];
  t("chatPayload: from は box・work・direct のどれか", L.chatPayload(hist, "reverse", "外壁塗装", "box").from === "box" && L.chatPayload(hist, "reverse", "外壁塗装", "work").from === "work" && L.chatPayload(hist, "reverse", "", undefined).from === "direct" && L.chatPayload(hist, "reverse", "", "https://x/").from === "direct");
  t("来た元の URL そのものは送らない", !JSON.stringify(L.chatPayload(hist, "reverse", "外壁塗装", L.entryFrom(Q, O + "/souba/gaiheki/?utm=abc", O))).includes("souba"));
  t("ボタンで送る物は出来事の名前だけ", L.buyClickBody() === '{"event":"buy_click"}');
  t("index.html: 入口は 1 か所で決める", (INDEX.match(/HSReverse\.entryFrom\(location\.search, document\.referrer, location\.origin\)/g) || []).length === 1);
  t("index.html: ¥5,500 のボタン 2 つは openTermsFirst を通り、そこで 1 回送る", (INDEX.match(/onclick="openTermsFirst\((\'bank\')?\)"/g) || []).length === 2 && /function openTermsFirst\(mode\) \{\n  reportBuyClick\(\);/.test(INDEX) && (INDEX.match(/reportBuyClick\(\)/g) || []).length === 2);
  t("index.html: 送り先は /rev-event だけで、cookie・localStorage・userAgent を一緒に送らない", (INDEX.match(/\/rev-event/g) || []).length === 2 && !/rev-event[^\n]*(cookie|localStorage|userAgent)/.test(INDEX));
  t("index.html: 開いた数は 1 か所で、同じタブでは 1 回だけ送る", (INDEX.match(/reportLanding\(\)/g) || []).length === 2 && /function reportLanding\(\) \{[\s\S]*?sessionStorage\.getItem\('hs_rev_land'\)[\s\S]*?HSReverse\.landBody\(ENTRY_FROM\)/.test(INDEX));
  t("index.html: 開いた数は ENTRY_FROM を決めた後に送る", INDEX.indexOf("const ENTRY_FROM") < INDEX.indexOf("\nreportLanding();"));
  {
    const dirs = readdirSync(path.join(ROOT, "souba"), { withFileTypes: true }).filter((d) => d.isDirectory() && existsSync(path.join(ROOT, "souba", d.name, "index.html")));
    const hrefs = dirs.flatMap((d) => [...page("souba/" + d.name + "/index.html").matchAll(/<div data-cta="reverse-v1"[^>]*><a href="([^"]*)"/g)].map((x) => x[1]));
    t("相場ページの箱は全部 from=box 付き(" + hrefs.length + " 本)", hrefs.length >= 100 && hrefs.every((h) => /^https:\/\/shield\.the-horizons-innovation\.com\/hs-reverse-estimate\/\?(work=[^&"]+&)?from=box$/.test(h)), hrefs.filter((h) => !/from=box$/.test(h)).slice(0, 3).join(" "));
    t("箱の工事名は今まで通り(付いていた 39 本はそのまま)", hrefs.filter((h) => h.includes("?work=")).length === 39);
  }
  const m = /function reportBuyClick\(\) \{[\s\S]*?\n\}/.exec(INDEX);
  t("index.html: 送れなくても購入の流れを止めない(try で囲む)", !!m && /try \{/.test(m[0]) && /catch \(_e\) \{\}/.test(m[0]));
}

// ---- 有料レポートの松・梅は画面の竹と同じ物差し(2026-10-08) ----
{
  const row = L.matchSoubaRow(DB, CASES[0].text);
  const v = L.buildView({ plan: { koji: "外壁塗装", take: [26, 42] }, row, meta: DB._meta, now: NOW });
  const p = L.alignPaidPlans(v, [26, 42], [34, 60], [18, 30]);
  t("松・梅: KIRA が竹 26〜42 万と出しても、松・梅は souba-db の竹 70〜115 万に合わせて同じ倍率で動く", p.basis === "scaled" && p.matsu[0] === 92.5 && p.matsu[1] === 163.2 && p.ume[0] === 49 && p.ume[1] === 81.6, JSON.stringify(p));
  t("松・梅: 梅 ≤ 竹 ≤ 松(下端どうし、上端どうし)", p.ume[0] <= v.take[0] && p.ume[1] <= v.take[1] && p.matsu[0] >= v.take[0] && p.matsu[1] >= v.take[1], JSON.stringify([p.ume, v.take, p.matsu]));
  const takeMid = Math.round((v.take[0] + v.take[1]) / 2);
  t("松・梅: PDF に渡す 3 つの額が 梅 < 竹 < 松 の順(松は上端、竹は真ん中、梅は下端)", p.ume[0] < takeMid && takeMid < p.matsu[1], [p.ume[0], takeMid, p.matsu[1]].join(" "));
  const bad = L.alignPaidPlans(v, [26, 42], [20, 30], [40, 60]);
  t("松・梅: KIRA の比が逆さ(松が竹より安い)なら竹の両端から作る", bad.basis === "ratio" && bad.matsu[0] === 115 && bad.matsu[1] === 155.3 && bad.ume[0] === 52.5 && bad.ume[1] === 70, JSON.stringify(bad));
  const none = L.alignPaidPlans(v, [0, 0], [0, 0], [0, 0]);
  t("松・梅: KIRA の数字が読めない時も竹の両端から作る(0 円のまま PDF に渡さない)", none.basis === "ratio" && none.matsu[1] > 115 && none.ume[0] > 0, JSON.stringify(none));
  const kv = L.buildView({ plan: { koji: "特殊な工事", take: [40, 60] }, row: null, meta: DB._meta, now: NOW });
  const kp = L.alignPaidPlans(kv, [40, 60], [55, 80], [30, 40]);
  t("松・梅: 竹が KIRA の積み上げ(行が無い)なら、同じ物差しなので触らない", kp.basis === "kira" && kp.matsu[0] === 55 && kp.ume[1] === 40, JSON.stringify(kp));
  t("松・梅: 画面の view には今も松・梅の欄が無い", !Object.keys(v).some((k) => /matsu|ume/i.test(k)));
  t("松・梅: index.html は lastParsedResult に揃えた松・梅を入れる", INDEX.includes("HSReverse.alignPaidPlans(view, tR, mR, uR)") && INDEX.includes("matsu: paid.matsu") && INDEX.includes("ume: paid.ume") && !INDEX.includes("plans: { matsu: mR, take: view.take || tR, ume: uR }"));
}

console.log("");
if (fail) { console.log("FAIL " + fail + " of " + (pass + fail) + " (reverse_logic)"); process.exit(1); }
console.log("PASS " + pass + "/" + pass + " (reverse_logic v4: 竹の幅が相場ページと一致、有料の松・梅も同じ物差し、指示文を持たない、印は結果の後、入口と購入ボタンは数だけ、箱は from=box 付き、開いた数も入口ごと)");
