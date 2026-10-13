// firestore_dedupe_do.mjs
// Firestore-backed twin of the Cloudflare Durable Object AGREEMENT_DEDUPE_DO.
// 台帳(hs-ledger)を Cloud Run に無改変で載せるための一部品。扉の kv_firestore.mjs /
// http_bridge.mjs と同じ考え方: worker 本体も DO クラス本体も書き換えず、周辺の
// binding だけ差し替える。
//
// Cloudflare 版は blockConcurrencyWhile が 1 インスタンス内の read-decide-write を
// 直列化して強整合を作る (agreement boundary 2.3)。GCP 版は同じ read-decide-write を
// Firestore の runTransaction 1 回に包む。1 canonical_sha256 == 1 doc == 1 transaction。
// AgreementDedupeDO クラスも decideDedupe 純関数も、Cloudflare 用のものをそのまま使う。
//
// 2026-10-13 (concurrency audit L1r). 台帳の entry 番号付け(/ledger-append、src/ledger_append.mjs)も
// ここで受ける。以前は DO クラスを env 無しで作っていたので、クラスは 503 ledger_not_bound を返し、
// 呼び出し側 appendEntry は古い直列化なしの KV 手順(seq を読んで +1、3 つ put)に落ちていた。
// 2 件が同時に走ると同じ n を取り、後の put が先の entry を上書きする(Cloudflare 側の L1 と同じ穴)。
// これからは /ledger-append を 1 つの Firestore transaction で処理する: KV コレクションの
// seq doc と hash:<h> doc を txn.get で読み、entry:n / hash:h / seq を同じ transaction で txn.set する。
// 書く中身は src/ledger_append.mjs の appendEntryKv(Cloudflare 側と同じ唯一の実装)に、transaction
// 越しの get/put を渡して作るので、保存されるバイトは Cloudflare 側と同じ。Firestore は読み取り済みの
// doc が commit 前に変わっていれば transaction をやり直すので、2 件が同じ seq を読んでも片方は
// やり直して n+1 を取る。Cloudflare の DO が持つ床(ledger_seq / ledger_hash:<h>)は、ここでは要らない:
// transaction の読みは強整合で、床が守る「古い KV の読み」が起きないから。
// transaction が失敗したら 503 ledger_append_failed を返し、呼び出し側 appendEntry は throw して何も
// 書かない(fail closed)。ledger_not_bound はもう返さない(返すと呼び出し側が古い手順に落ちる)。
import { AgreementDedupeDO } from "../nenrin/agreement-v0/agreement_intake.mjs";
import { appendEntryKv, LEDGER_APPEND_PATH } from "../src/ledger_append.mjs";

// kv_firestore.mjs の docId と同じ式(あちらは扉の twin と同一バイトの複製なので export を足さず、ここに写す)。
// 2 つが一致することは firestore_dedupe_do.test.mjs が makeKv 経由の読み書きで採点する。
const kvDocId = (key) => "k_" + Buffer.from(String(key), "utf8").toString("base64url");

// 呼び出し側(agreement_intake.mjs doStore)は:
//   env.AGREEMENT_DEDUPE_DO.get(env.AGREEMENT_DEDUPE_DO.idFromName("agreement:"+sha))
//     .fetch("https://agreement-dedupe/claim" | "/get", { method:"POST", body })
// という Cloudflare DO stub の形で叩く。同じ形をここで満たす。
// kvCollectionName: 台帳の KV(LEDGER)を満たす kv_firestore.mjs のコレクション。/ledger-append は
// その doc(seq / entry:n / hash:h)を transaction で読み書きするので、server.mjs は KV と同じ名前を渡す。
export function makeAgreementDedupeDO(firestore, collectionName = "hs_ledger_agreement_dedupe", kvCollectionName = "hs_ledger_kv") {
  const col = firestore.collection(collectionName);
  const kvCol = firestore.collection(kvCollectionName);
  const docIdFor = (name) => "d_" + Buffer.from(String(name), "utf8").toString("base64url");

  const stubResponse = (status, text) => ({
    status,
    ok: status >= 200 && status < 300,
    async json() { return JSON.parse(text); },
    async text() { return text; },
  });

  // /ledger-append: one Firestore transaction == one blockConcurrencyWhile turn of the sequencer.
  // The kv handed to appendEntryKv reads and writes the same docs kv_firestore.mjs uses
  // ({ key, value, expiresAt }, doc id kvDocId(key)), so the worker's own LEDGER.get("seq") /
  // "entry:n" / "hash:h" see exactly what was written here. appendEntryKv does its two reads
  // (hash:h, seq) before its three writes, which is the order Firestore requires.
  async function ledgerAppend(bodyStr) {
    let body;
    try { body = JSON.parse(bodyStr); } catch { return stubResponse(400, JSON.stringify({ error: "bad_json" })); }
    const h = typeof body.h === "string" && /^[0-9a-f]{64}$/.test(body.h) ? body.h : null;
    const entryIn = body.entry && typeof body.entry === "object" && !Array.isArray(body.entry) ? body.entry : null;
    if (!h || !entryIn) return stubResponse(400, JSON.stringify({ error: "h_and_entry_required" }));
    try {
      const r = await firestore.runTransaction(async (txn) => {
        // runTransaction may re-run its callback on contention: the entry is copied fresh each time,
        // so a previous attempt's n never leaks into the next.
        const entry = JSON.parse(JSON.stringify(entryIn));
        const txnKv = {
          get: async (key) => {
            const snap = await txn.get(kvCol.doc(kvDocId(key)));
            if (!snap.exists) return null;
            const d = snap.data() || {};
            if (d.expiresAt && d.expiresAt <= Date.now()) return null;
            return d.value == null ? null : String(d.value);
          },
          put: async (key, value) => {
            txn.set(kvCol.doc(kvDocId(key)), { key: String(key), value: String(value), expiresAt: null });
          },
        };
        return await appendEntryKv(txnKv, h, entry);
      });
      return stubResponse(200, JSON.stringify({ n: r.n, dedup: !!r.dedup }));
    } catch (e) {
      // fail closed: the caller (appendEntry) throws on a non-2xx that is not ledger_not_bound and writes nothing.
      return stubResponse(503, JSON.stringify({ error: "ledger_append_failed", detail: String(e && e.message || e).slice(0, 200) }));
    }
  }

  return {
    idFromName: (name) => String(name),
    get: (id) => ({
      async fetch(url, init) {
        const method = (init && init.method) || "GET";
        const headers = (init && init.headers) || {};
        const bodyStr = init && init.body != null ? String(init.body) : undefined;
        if (method === "POST" && new URL(url).pathname === LEDGER_APPEND_PATH) return await ledgerAppend(bodyStr == null ? "" : bodyStr);
        const docRef = col.doc(docIdFor(id));

        // one Firestore transaction == one blockConcurrencyWhile turn for this id.
        // runTransaction may re-run its callback on contention, so anything that
        // touches the request or the doc is built fresh inside the callback.
        return await firestore.runTransaction(async (txn) => {
          const request = new Request(url, {
            method,
            headers,
            body: method === "GET" || method === "HEAD" ? undefined : bodyStr,
          });
          const state = {
            // already inside a transaction: this block is atomic by construction.
            blockConcurrencyWhile: async (fn) => await fn(),
            storage: {
              // Firestore rule: all reads before any write. The DO reads "record"
              // once, decides, then conditionally writes. That order is preserved.
              get: async (key) => {
                const snap = await txn.get(docRef);
                if (!snap.exists) return undefined;
                const data = snap.data() || {};
                const raw = data[key + "_json"];
                return raw === undefined ? undefined : JSON.parse(raw);
              },
              put: async (key, val) => {
                txn.set(docRef, { [key + "_json"]: JSON.stringify(val) }, { merge: true });
              },
            },
          };
          const res = await new AgreementDedupeDO(state).fetch(request);
          const status = res.status;
          const text = await res.text();
          // minimal stub-response: callers only use await r.json().
          return stubResponse(status, text);
        });
      },
    }),
  };
}
