// RUN_ALL: library  証人の「支配の多様性」(control diversity) を数える。採点は witness_diversity_test.mjs
//
// 何の穴を塞ぐか (2026-09-27、外部の批判 ① ②)。
// 鍵が 3 本あっても、3 本とも同じ会社・同じサーバー・同じ支配者なら独立した証人やない。
// 籤 (witness_draw.mjs) は運営者の選り好みを消すが、池そのものが Sybil で埋まっとったら負ける。
// 要るのは鍵の多様性やなく、支配・組織・基盤の多様性の「証拠」。
//
// この file がやること:
//   1. 池の各項について、誰でも取れる公開の事実 (登録ドメイン、IP、ASN、ネームサーバー、鍵) を束ねる。
//      事実は pool builder がその時刻に見た DNS の答え。取った時刻と取り方を記録に残す。
//   2. 事実から「同じ支配の疑い」を数える。強い信号と弱い信号を分ける:
//        強い: 同じ登録ドメイン (a.example.com と b.example.com)、同じ IP、同じ鍵、同じ独自ネームサーバー、
//              同じ法人番号 (legal-entity-v1 で agent card の署名の中に宣言された registry:scheme:id、2026-09-27 追加)
//        弱い: 同じ ASN、同じホスティング基盤 (workers.dev、github.io など)、同じ DNS 事業者
//      弱い信号は大手の CDN や DNS を使うだけで重なる。弱いを強いに数えたら、正直な証人に濡れ衣を着せる。
//   3. 籤の変種 drawDiverse: 同じ乱数 (seed) で同じ順番を作り、強い信号を共有する項は 2 人目から飛ばす。
//      誰でも同じ入力 (池、事実、beacon、subject) から同じ k 人を再計算できる。
//
// 数えるだけで、点は付けん (NENRIN の芯、counts never scores)。
// 証さんこと (does_not_establish に毎回書く):
//   - 別の登録ドメイン・別の IP・別の ASN でも同じ人が支配しとる可能性。本気の Sybil は業者を変えて来る。
//     この計器は Sybil を「高く付かせる」だけで、無くしはせん。
//   - DNS の答えの真偽。答えは pool builder が見た物で、登録者の身元は分からん。
//   - 証人の観測が正しいこと。
import { canonicalUtf8 } from "../agreement-v0/agreement_canonical.mjs";
import { normalizePool, POOL_SCHEMA } from "./witness_draw.mjs";

export const DIVERSITY_SCHEMA = "nenrin-witness-diversity-v0";
export const DIVERSE_DRAW_VERSION = "0.2.0";
// 組織の多様性 (2026-09-27、外部の批判「key diversity ではなく organization diversity を」への手当)。
// 法人番号は証人自身の宣言 (legal-entity-v1、card の署名の中) で、登録簿の答えやない。同じ番号を宣言した 2 項は
// 同じ組織として 1 つの塊に入れる。宣言せん項は数えて findings に出す (無宣言は別組織の証明にならん)。
export const LEGAL_ENTITY_EXT_URI = "https://gate.horizonshield.dev/ext/legal-entity/v1";
export function legalEntityKey(le) {
  if (!le || typeof le !== "object") return null;
  const parts = ["registry", "scheme", "id"].map((k) => (typeof le[k] === "string" ? le[k].trim() : ""));
  if (parts.some((x) => !x)) return null;
  return parts[0].toUpperCase() + ":" + parts[1].toLowerCase() + ":" + parts[2];
}
const enc = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;

async function sha(s) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s);
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// 公開接尾辞 (public suffix) の小さな表。全部やないが、証人が居そうな所を押さえる。
// ホスティング基盤の接尾辞は「登録ドメイン」を 1 段深く取る (alice.workers.dev と bob.workers.dev は別人でありうる)
// が、同じ基盤の上におることは弱い信号として数える。
export const MULTI_LABEL_SUFFIXES = [
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ed.jp", "lg.jp",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.cn", "com.tw", "co.kr", "co.in",
];
export const PLATFORM_SUFFIXES = [
  "workers.dev", "pages.dev", "github.io", "vercel.app", "netlify.app", "herokuapp.com", "fly.dev", "onrender.com",
  "railway.app", "deno.dev", "web.app", "firebaseapp.com", "appspot.com", "azurewebsites.net", "cloudfront.net",
  "replit.app", "glitch.me", "ngrok.app", "ngrok-free.app", "trycloudflare.com",
  "service.tcloudbase.com",   // Tencent CloudBase: one owner per <env>.service.tcloudbase.com host (horizon-shield #56)
];

export function registrableDomain(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h || /^[0-9.:[\]]+$/.test(h)) return { registrable: h, platform: null };
  const labels = h.split(".");
  for (const p of PLATFORM_SUFFIXES) {
    if (h === p) return { registrable: h, platform: p };
    if (h.endsWith("." + p)) {
      const rest = h.slice(0, -(p.length + 1)).split(".");
      return { registrable: rest[rest.length - 1] + "." + p, platform: p };
    }
  }
  for (const s of MULTI_LABEL_SUFFIXES) {
    if (h.endsWith("." + s)) {
      const rest = h.slice(0, -(s.length + 1)).split(".");
      return { registrable: rest[rest.length - 1] + "." + s, platform: null };
    }
  }
  return { registrable: labels.slice(-2).join("."), platform: null };
}

// 大手の DNS 事業者。ネームサーバーがここなら「同じ事業者を使っとる」は弱い信号 (誰でも使う)。
// ここに無い独自のネームサーバー (例 ns1.alice-corp.com) を 2 項が共有しとったら強い信号。
export const SHARED_DNS_OPERATORS = [
  "cloudflare.com", "awsdns", "googledomains.com", "google.com", "azure-dns", "dnsv.jp", "domaincontrol.com",
  "registrar-servers.com", "nsone.net", "dnsimple.com", "digitalocean.com", "linode.com", "vercel-dns.com",
  "netlify.com", "hetzner.com", "ovh.net", "gandi.net", "name.com", "namecheaphosting.com", "sakura.ne.jp", "xserver.jp",
];
export function nsOperator(ns) {
  const n = String(ns || "").toLowerCase().replace(/\.$/, "");
  for (const op of SHARED_DNS_OPERATORS) if (n.includes(op)) return { operator: op, shared_provider: true };
  return { operator: registrableDomain(n).registrable, shared_provider: false };
}

// IP を /24 (v4) か /48 (v6) に丸める。同じ /24 は強い信号 (同じ機械か同じ小さな網)。
export function ipPrefix(ip) {
  const s = String(ip || "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) return s.split(".").slice(0, 3).join(".") + ".0/24";
  if (s.includes(":")) return s.toLowerCase().split(":").slice(0, 3).join(":") + "::/48";
  return s;
}

// 事実の形。facts[signed_domain] = { observed_at, method, ips: [..], asns: [..], ns: [..] }。
// 事実が無い項も数える (unknown として)。無いことを「別人」と数えたら甘い方に倒れる。
// 2026-09-27. 「答えが無かった」と「答えが空やった」は違う。全 resolver が A と AAAA と NS の全部に答えんかった事実
// (collect が unanswered に書く) は、事実が無いのと同じに扱う。空の答えとして数えたら、網が塞がっとる所で集めた池が
// 「強い信号が何も被っとらん = 全員別人」に見える。甘い方に倒れる穴や。実際に塞がった網で集めて見つけた。
export function factAnswered(f) {
  if (!f) return false;
  const u = Array.isArray(f.unanswered) ? f.unanswered : [];
  return !(u.includes("A") && u.includes("AAAA") && u.includes("NS"));
}
function signalsFor(entry, fact) {
  const host = entry.signed_domain.toLowerCase();
  const { registrable, platform } = registrableDomain(host);
  const strong = [["registrable_domain", registrable], ["public_key", entry.public_key_ed25519_b64]];
  const weak = [];
  if (platform) weak.push(["platform", platform]);
  const le = legalEntityKey(fact && fact.legal_entity);
  if (le) strong.push(["legal_entity", le]);
  const f = factAnswered(fact) ? fact : null;
  if (f) {
    for (const ip of [...new Set((f.ips || []).map(String))].sort()) strong.push(["ip_prefix", ipPrefix(ip)]);
    for (const a of [...new Set((f.asns || []).map(String))].sort()) weak.push(["asn", a]);
    for (const n of [...new Set((f.ns || []).map(String))].sort()) {
      const o = nsOperator(n);
      if (o.shared_provider) weak.push(["dns_provider", o.operator]);
      else strong.push(["custom_nameserver", o.operator]);
    }
  }
  return { host, registrable, platform, strong: dedupe(strong), weak: dedupe(weak), facts_present: !!f, legal_entity: le };
}
function dedupe(pairs) {
  const seen = new Set(); const out = [];
  for (const [k, v] of pairs) { const key = k + "\u0000" + v; if (!seen.has(key)) { seen.add(key); out.push([k, v]); } }
  return out;
}

function groupShared(sigs, which) {
  const m = new Map();
  for (const s of sigs) for (const [k, v] of s[which]) {
    const key = k + "\u0000" + v;
    if (!m.has(key)) m.set(key, { kind: k, value: v, members: [] });
    m.get(key).members.push(s.host);
  }
  return [...m.values()].filter((g) => g.members.length > 1)
    .map((g) => ({ ...g, members: g.members.slice().sort() }))
    .sort((a, b) => (a.kind + a.value < b.kind + b.value ? -1 : 1));
}

// 強い信号で繋がる項を 1 つの「支配の塊」(control cluster) にまとめる (推移的: A と B が IP を、B と C が
// 登録ドメインを共有すれば A B C は 1 塊)。塊の数が「独立と数えてよい上限」。
export function controlClusters(entries, facts = {}) {
  const sigs = entries.map((e) => signalsFor(e, facts[e.signed_domain.toLowerCase()] || facts[e.signed_domain]));
  const parent = new Map(sigs.map((s) => [s.host, s.host]));
  const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra < rb ? rb : ra, ra < rb ? ra : rb); };
  const owner = new Map();
  for (const s of sigs) for (const [k, v] of s.strong) {
    const key = k + "\u0000" + v;
    if (owner.has(key)) union(owner.get(key), s.host); else owner.set(key, s.host);
  }
  const clusterOf = new Map(sigs.map((s) => [s.host, find(s.host)]));
  return { sigs, clusterOf };
}

// 池に入った経路 (arrival、2026-09-30、フェデリコの指摘への手当)。
// 「こっちが選んだ証人」は多様性の報告を不正直にする。籤は誰が引かれるかから運営者を外すが、誰に声を掛けたかは
// 運営者が決めとる。それを隠さず数に出す: 各項が invited (運営者が声を掛けた)、referred (池の誰かが紹介した)、
// unsolicited (自分で来た) のどれで入ったか。書くのは運営者の申告で、invited には公開の招待の URL を ref に
// 付ける (誰でも招待の文面と日付を確かめられる)。申告の無い項は undisclosed と数え、自発とは数えん。
export const ARRIVAL_SCHEMA = "nenrin-witness-arrivals-v0";
export const ARRIVAL_KINDS = ["invited", "referred", "unsolicited"];
export function normalizeArrivals(arrivals, entries) {
  const src = arrivals && typeof arrivals === "object" ? (arrivals.arrivals && typeof arrivals.arrivals === "object" ? arrivals.arrivals : arrivals) : {};
  const out = {};
  for (const e of entries) {
    const d = e.signed_domain.toLowerCase();
    const a = src[d] || src[e.signed_domain];
    if (!a) continue;
    if (!ARRIVAL_KINDS.includes(a.via)) throw new Error("arrival for " + d + ": via must be one of " + ARRIVAL_KINDS.join(", "));
    const rec = { via: a.via };
    if (a.ref != null) {
      if (typeof a.ref !== "string" || !/^https:\/\/\S+$/.test(a.ref)) throw new Error("arrival for " + d + ": ref must be an https URL");
      rec.ref = a.ref;
    }
    if (a.via === "referred") {
      if (typeof a.referred_by !== "string" || !a.referred_by) throw new Error("arrival for " + d + ": referred needs referred_by");
      rec.referred_by = a.referred_by.toLowerCase();
    }
    out[d] = rec;
  }
  return { schema: ARRIVAL_SCHEMA, arrivals: out };
}

export async function diversityReport(pool, facts = {}, { poolSha256: givenPoolSha = null, arrivals = null } = {}) {
  const entries = normalizePool(pool);
  const { sigs, clusterOf } = controlClusters(entries, facts);
  const clusters = new Map();
  for (const s of sigs) { const c = clusterOf.get(s.host); if (!clusters.has(c)) clusters.set(c, []); clusters.get(c).push(s.host); }
  const distinct = (fn) => new Set(sigs.flatMap(fn)).size;
  const withFacts = sigs.filter((s) => s.facts_present).length;
  const withLegal = sigs.filter((s) => s.legal_entity).length;
  const pool_sha256 = givenPoolSha || await sha(canonicalUtf8({ schema: POOL_SCHEMA, entries: entries.map((e) => ({ signed_domain: e.signed_domain, key_url: e.key_url, public_key_ed25519_b64: e.public_key_ed25519_b64 })) }));
  const facts_sha256 = await sha(canonicalUtf8(normalizeFacts(facts, entries)));
  const arr = normalizeArrivals(arrivals, entries);
  const arrivals_sha256 = await sha(canonicalUtf8(arr));
  const via = { invited: 0, referred: 0, unsolicited: 0, undisclosed: 0 };
  for (const s of sigs) { const r = arr.arrivals[s.host.toLowerCase()]; via[r ? r.via : "undisclosed"] += 1; }
  const disclosed = sigs.length - via.undisclosed;
  const strong_shared = groupShared(sigs, "strong");
  const weak_shared = groupShared(sigs, "weak");
  const report = {
    schema: DIVERSITY_SCHEMA,
    pool_sha256, facts_sha256, arrivals_sha256,
    pool_size: String(sigs.length),
    entries_with_facts: String(withFacts),
    control_clusters: String(clusters.size),
    entries_declaring_legal_entity: String(withLegal),
    arrived_via: { invited: String(via.invited), referred: String(via.referred), unsolicited: String(via.unsolicited), undisclosed: String(via.undisclosed) },
    arrivals: Object.entries(arr.arrivals).map(([signed_domain, r]) => ({ signed_domain, ...r })).sort((a, b) => (a.signed_domain < b.signed_domain ? -1 : 1)),
    distinct: {
      registrable_domains: String(distinct((s) => [s.registrable])),
      public_keys: String(distinct((s) => s.strong.filter(([k]) => k === "public_key").map(([, v]) => v))),
      ip_prefixes: String(distinct((s) => s.strong.filter(([k]) => k === "ip_prefix").map(([, v]) => v))),
      asns: String(distinct((s) => s.weak.filter(([k]) => k === "asn").map(([, v]) => v))),
      legal_entities: String(distinct((s) => (s.legal_entity ? [s.legal_entity] : []))),
      dns_operators: String(distinct((s) => [...s.weak.filter(([k]) => k === "dns_provider"), ...s.strong.filter(([k]) => k === "custom_nameserver")].map(([, v]) => v))),
    },
    clusters: [...clusters.entries()].map(([id, members]) => ({ id, members: members.slice().sort() })).sort((a, b) => (a.id < b.id ? -1 : 1)),
    strong_shared, weak_shared,
    findings: [
      ...(strong_shared.length ? ["shared_control_suspected"] : []),
      ...(weak_shared.length ? ["shared_infrastructure"] : []),
      ...(withFacts < sigs.length ? ["facts_missing"] : []),
      ...(withLegal < sigs.length ? ["legal_entity_undeclared"] : []),
      ...(clusters.size < 2 ? ["single_control_cluster"] : []),
      ...(via.undisclosed ? ["arrival_undisclosed"] : []),
      ...(disclosed > 0 && via.invited === disclosed ? ["operator_outreach_only"] : []),
    ],
    establishes: [
      "the pool has " + sigs.length + " entries that fall into " + clusters.size + " control clusters, where two entries share a cluster when they share a registrable domain, a public key, an IP prefix, a custom nameserver or a declared legal entity identifier",
      "arrival is disclosed for " + disclosed + " of " + sigs.length + " entries: " + via.invited + " invited by the operator, " + via.referred + " referred by a pool member, " + via.unsolicited + " unsolicited",
      "every count is recomputable from pool_sha256, facts_sha256 and arrivals_sha256 with this file",
    ],
    does_not_establish: [
      "that entries in different clusters are controlled by different people; a determined operator can use different registrars, hosts and networks, and this instrument only makes that more expensive",
      "that the DNS answers in the facts are true or current; they are what the pool builder observed at observed_at",
      "that a declared legal entity identifier is true, registered or complete; it is the witness's own declaration under legal-entity-v1, a Sybil can omit it or declare different entities, and only the register can answer",
      "that different organizations have different economic interests; who pays each witness is not observed here",
      "that an entry recorded as unsolicited or referred was not approached privately by the operator; arrival is the operator's own disclosure, and only an invited entry carries a public link to check",
      "that any witness observes correctly",
      "any score, rank or trust level; the report counts and never scores",
    ],
  };
  return report;
}

function normalizeFacts(facts, entries) {
  const out = {};
  for (const e of entries) {
    const f = facts[e.signed_domain.toLowerCase()] || facts[e.signed_domain];
    if (!f) continue;
    out[e.signed_domain.toLowerCase()] = {
      observed_at: String(f.observed_at || ""), method: String(f.method || ""),
      ips: [...new Set((f.ips || []).map(String))].sort(),
      asns: [...new Set((f.asns || []).map(String))].sort(),
      ns: [...new Set((f.ns || []).map((n) => String(n).toLowerCase().replace(/\.$/, "")))].sort(),
      ...(Array.isArray(f.unanswered) && f.unanswered.length ? { unanswered: [...new Set(f.unanswered.map(String))].sort() } : {}),
      ...(legalEntityKey(f.legal_entity) ? { legal_entity: legalEntityKey(f.legal_entity) } : {}),
    };
  }
  return { schema: "nenrin-witness-facts-v0", facts: out };
}

// 籤の多様性つき変種。seed と並べ方は witness_draw.draw と同じ (部分 Fisher-Yates を最後まで回した順番)。
// その順番を頭から歩き、既に選んだ項と同じ支配の塊に入る項は飛ばす。塊の数より多くは引かん。
// 全部の項が別の塊なら、結果は draw() の頭 k 人と完全に同じ (試験で確かめる)。
export async function drawDiverse({ pool, facts = {}, beaconHash, subjectSha256, k, excludeHost }) {
  if (!HEX64.test(String(beaconHash || ""))) throw new Error("beaconHash must be 64 hex (a Bitcoin block hash)");
  if (!HEX64.test(String(subjectSha256 || ""))) throw new Error("subjectSha256 must be 64 hex");
  const want = Number(k);
  if (!Number.isInteger(want) || want < 0) throw new Error("k must be a non-negative integer");
  const all = normalizePool(pool);
  const pool_sha256 = await sha(canonicalUtf8({ schema: POOL_SCHEMA, entries: all.map((e) => ({ signed_domain: e.signed_domain, key_url: e.key_url, public_key_ed25519_b64: e.public_key_ed25519_b64 })) }));
  const ex = excludeHost ? String(excludeHost).toLowerCase() : null;
  const eligible = all.filter((e) => !ex || e.signed_domain.toLowerCase() !== ex);
  const n = eligible.length;
  const seed = await sha(beaconHash + "|" + pool_sha256 + "|" + subjectSha256);
  const arr = eligible.slice();
  for (let i = 0; i < n; i++) {
    const r = await sha(seed + "|" + String(i));
    const j = i + Number(BigInt("0x" + r.slice(0, 16)) % BigInt(n - i));
    const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
  const { clusterOf } = controlClusters(eligible, facts);
  const used = new Set(); const chosen = []; const skipped = [];
  for (const e of arr) {
    if (chosen.length >= want) break;
    const c = clusterOf.get(e.signed_domain.toLowerCase());
    if (used.has(c)) { skipped.push({ signed_domain: e.signed_domain, same_cluster_as: chosen.find((x) => clusterOf.get(x.signed_domain.toLowerCase()) === c).signed_domain }); continue; }
    used.add(c); chosen.push(e);
  }
  const facts_sha256 = await sha(canonicalUtf8(normalizeFacts(facts, eligible)));
  return {
    draw_version: DIVERSE_DRAW_VERSION, rule: "one_per_control_cluster",
    pool_sha256, facts_sha256, pool_size: String(all.length), eligible: String(n),
    control_clusters: String(new Set(eligible.map((e) => clusterOf.get(e.signed_domain.toLowerCase()))).size),
    k: String(chosen.length), k_requested: String(want), seed_sha256: seed,
    drawn: chosen.map((e) => e.signed_domain), skipped, entries: chosen,
  };
}
