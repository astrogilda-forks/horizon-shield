// RUN_ALL: suite
// 支配の多様性の採点: Sybil の形 (同じ登録ドメイン、同じ IP、同じ独自 NS) を強い信号で束ね、
// 大手 CDN・大手 DNS・同じ基盤は弱い信号に留め (正直な証人に濡れ衣を着せん)、
// drawDiverse が同じ塊から 2 人引かず、全員別の塊なら draw() と同じ k 人を返し、点を一切出さんこと。
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { draw } from "./witness_draw.mjs";
import { registrableDomain, nsOperator, ipPrefix, diversityReport, drawDiverse, controlClusters, normalizeArrivals } from "./witness_diversity.mjs";
import { collectFact, cymruName } from "./witness_diversity_collect.mjs";

let pass = 0, fail = 0; const results = [];
function t(name, ok, detail) { (ok ? pass++ : fail++); results.push((ok ? "  ok   " : "  FAIL ") + name + (ok || !detail ? "" : "  <- " + detail)); }

const edPubFromSeed = (label) => { const seed = createHash("sha256").update(label).digest(); const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" }); return Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url").toString("base64"); };
const key = (i) => edPubFromSeed("witness-key-" + String(i).padStart(3, "0"));
const E = (host, i) => ({ signed_domain: host, key_url: "https://" + host + "/keys/witness.json", public_key_ed25519_b64: key(i) });
const BEACON = "00000000000000000001aa2b3c4d5e6f00000000000000000001aa2b3c4d5e6f";
const SUBJECT = "c92bf886".padEnd(64, "0");

// ---- 1. 登録ドメインと基盤 ----
t("registrable: a.alice.com and b.alice.com share alice.com", registrableDomain("a.alice.com").registrable === "alice.com" && registrableDomain("b.alice.com").registrable === "alice.com");
t("registrable: x.co.jp keeps two labels of suffix (shop.example.co.jp -> example.co.jp)", registrableDomain("shop.example.co.jp").registrable === "example.co.jp");
t("platform: two Tencent CloudBase hosts are different registrable names on one platform", registrableDomain("qunling-001-d7gwxqdou24c9dad4.service.tcloudbase.com").registrable === "qunling-001-d7gwxqdou24c9dad4.service.tcloudbase.com" && registrableDomain("other-env-0001.service.tcloudbase.com").registrable === "other-env-0001.service.tcloudbase.com" && registrableDomain("other-env-0001.service.tcloudbase.com").platform === "service.tcloudbase.com");
t("platform: alice.workers.dev and bob.workers.dev are different registrable domains on one platform", registrableDomain("api.alice.workers.dev").registrable === "alice.workers.dev" && registrableDomain("bob.workers.dev").registrable === "bob.workers.dev" && registrableDomain("bob.workers.dev").platform === "workers.dev");
t("nameserver: cloudflare NS is a shared provider (weak), ns1.alice-corp.com is custom (strong)", nsOperator("jake.ns.cloudflare.com").shared_provider === true && nsOperator("ns1.alice-corp.com").shared_provider === false && nsOperator("ns1.alice-corp.com").operator === "alice-corp.com");
t("ip prefix: v4 /24", ipPrefix("203.0.113.77") === "203.0.113.0/24");

// ---- 2. Sybil の形は強い信号で 1 塊になる ----
const sybilPool = { entries: [E("w1.sybil.example", 1), E("w2.sybil.example", 2), E("w3.sybil.example", 3), E("honest-a.org", 4), E("honest-b.net", 5)] };
const facts = {
  "w1.sybil.example": { observed_at: "2026-09-27T10:00:00Z", method: "test", ips: ["198.51.100.10"], asns: ["64500"], ns: ["ns1.sybil-dns.example"] },
  "w2.sybil.example": { observed_at: "2026-09-27T10:00:00Z", method: "test", ips: ["198.51.100.11"], asns: ["64500"], ns: ["ns1.sybil-dns.example"] },
  "w3.sybil.example": { observed_at: "2026-09-27T10:00:00Z", method: "test", ips: ["198.51.100.12"], asns: ["64500"], ns: ["ns1.sybil-dns.example"] },
  "honest-a.org": { observed_at: "2026-09-27T10:00:00Z", method: "test", ips: ["104.16.1.1"], asns: ["13335"], ns: ["jake.ns.cloudflare.com"] },
  "honest-b.net": { observed_at: "2026-09-27T10:00:00Z", method: "test", ips: ["104.17.9.9"], asns: ["13335"], ns: ["courtney.ns.cloudflare.com"] },
};
const rep = await diversityReport(sybilPool, facts);
t("sybil: 5 entries, 3 control clusters (3 sybil subdomains collapse into one)", rep.pool_size === "5" && rep.control_clusters === "3", JSON.stringify(rep.clusters));
t("sybil: shared_control_suspected is raised with the registrable domain named", rep.findings.includes("shared_control_suspected") && rep.strong_shared.some((g) => g.kind === "registrable_domain" && g.value === "sybil.example" && g.members.length === 3));
t("honest on one CDN: same ASN 13335 and same DNS provider are weak only, never merge the two honest entries", rep.weak_shared.some((g) => g.kind === "asn" && g.value === "13335") && rep.clusters.filter((c) => c.members.includes("honest-a.org") || c.members.includes("honest-b.net")).length === 2);

// 別ドメインに散らしても、IP を共有したら捕まる (推移的に 1 塊)
const spread = { entries: [E("alpha-witness.com", 11), E("beta-witness.net", 12), E("gamma-witness.org", 13)] };
const spreadFacts = {
  "alpha-witness.com": { ips: ["192.0.2.5"], asns: ["64501"], ns: ["ns.cloudflare.com"] },
  "beta-witness.net": { ips: ["192.0.2.6"], asns: ["64501"], ns: ["ns.cloudflare.com"] },
  "gamma-witness.org": { ips: ["203.0.113.9"], asns: ["64502"], ns: ["ns1.gamma-own-dns.org"] },
};
const rep2 = await diversityReport(spread, spreadFacts);
t("spread sybil: three domains, but alpha and beta share an IP /24, so 2 clusters", rep2.control_clusters === "2" && rep2.strong_shared.some((g) => g.kind === "ip_prefix" && g.value === "192.0.2.0/24"));
// 独自 NS の共有で捕まる
const nsPool = { entries: [E("one.example-a.com", 21), E("two.example-b.com", 22)] };
const rep3 = await diversityReport(nsPool, { "one.example-a.com": { ips: ["192.0.2.1"], ns: ["ns1.shared-owner.io"] }, "two.example-b.com": { ips: ["198.51.100.1"], ns: ["ns2.shared-owner.io"] } });
t("custom nameserver shared across two registrable domains merges them (strong)", rep3.control_clusters === "1" && rep3.findings.includes("single_control_cluster"));

// 事実が無い項は「別人」と数えん: facts_missing を出す
const rep4 = await diversityReport(sybilPool, {});
t("missing facts are reported (facts_missing), not counted as proof of independence", rep4.findings.includes("facts_missing") && rep4.entries_with_facts === "0");

// ---- 3. 点を付けん ----
const flat = JSON.stringify(rep);
t("report carries no score, rank, trust or rating key", !/"(score|rank|rating|trust_level|trust_score|grade)"/.test(flat));
t("report says what it does not establish (different people, DNS truth, legal entity truth, economic interest, private approach, witness truth, no score)", rep.does_not_establish.length === 7 && rep.does_not_establish.some((s) => /determined operator/.test(s)) && rep.does_not_establish.some((s) => /approached privately/.test(s)));
t("report is deterministic (same inputs, same bytes)", JSON.stringify(await diversityReport(sybilPool, facts)) === flat);
t("fact order does not change facts_sha256", (await diversityReport(sybilPool, Object.fromEntries(Object.entries(facts).reverse()))).facts_sha256 === rep.facts_sha256);

// ---- 4. drawDiverse ----
for (const k of [1, 2, 3, 4, 5]) {
  const d = await drawDiverse({ pool: sybilPool, facts, beaconHash: BEACON, subjectSha256: SUBJECT, k });
  const { clusterOf } = controlClusters(sybilPool.entries, facts);
  const cl = d.drawn.map((h) => clusterOf.get(h));
  t("drawDiverse k=" + k + ": never two from one control cluster, and never more than the 3 clusters", new Set(cl).size === cl.length && d.drawn.length === Math.min(k, 3), JSON.stringify(d.drawn));
}
const dA = await drawDiverse({ pool: sybilPool, facts, beaconHash: BEACON, subjectSha256: SUBJECT, k: 3 });
const dB = await drawDiverse({ pool: sybilPool, facts, beaconHash: BEACON, subjectSha256: SUBJECT, k: 3 });
t("drawDiverse is recomputable (same inputs, same drawn list and seed)", JSON.stringify(dA.drawn) === JSON.stringify(dB.drawn) && dA.seed_sha256 === dB.seed_sha256);
t("drawDiverse records every skipped entry and which drawn entry it shares a cluster with", dA.skipped.every((s) => dA.drawn.includes(s.same_cluster_as)));
const dOther = await drawDiverse({ pool: sybilPool, facts, beaconHash: BEACON.replace(/.$/, "0"), subjectSha256: SUBJECT, k: 3 });
t("a different beacon gives a different seed", dOther.seed_sha256 !== dA.seed_sha256);

// 全員が別の塊なら、draw() の頭 k 人とまったく同じ (互換: 既存の籤を壊さん)
const honestPool = { entries: [E("a.one.org", 31), E("b.two.net", 32), E("c.three.com", 33), E("d.four.io", 34), E("e.five.jp", 35), E("f.six.dev", 36)] };
const honestFacts = Object.fromEntries(honestPool.entries.map((e, i) => [e.signed_domain, { ips: ["10.0." + i + ".1"], asns: ["13335"], ns: ["x.ns.cloudflare.com"] }]));
for (const k of [1, 3, 6]) {
  const a = await draw({ pool: honestPool, beaconHash: BEACON, subjectSha256: SUBJECT, k });
  const b = await drawDiverse({ pool: honestPool, facts: honestFacts, beaconHash: BEACON, subjectSha256: SUBJECT, k });
  t("all clusters distinct, k=" + k + ": drawDiverse equals draw() exactly (same seed, same pool_sha256, same drawn)", a.seed_sha256 === b.seed_sha256 && a.pool_sha256 === b.pool_sha256 && JSON.stringify(a.drawn) === JSON.stringify(b.drawn), JSON.stringify([a.drawn, b.drawn]));
}
const exOwn = await drawDiverse({ pool: { entries: [...honestPool.entries, E("gate.horizonshield.dev", 99)] }, facts: honestFacts, beaconHash: BEACON, subjectSha256: SUBJECT, k: 7, excludeHost: "gate.horizonshield.dev" });
t("the operator's own host is excluded before the draw (self_witness)", !exOwn.drawn.includes("gate.horizonshield.dev") && exOwn.eligible === "6");
let threw = false; try { await drawDiverse({ pool: honestPool, beaconHash: "zz", subjectSha256: SUBJECT, k: 1 }); } catch { threw = true; }
t("a malformed beacon is refused", threw);

// ---- 5. 集める側 (偽 fetch) ----
t("cymru name for v4 reverses octets", cymruName("104.16.1.2") === "2.1.16.104.origin.asn.cymru.com");
t("cymru name for v6 reverses nibbles", cymruName("2606:4700::1").endsWith(".origin6.asn.cymru.com") && cymruName("2606:4700::1").startsWith("1.0.0.0."));
const fake = (disagree) => async (url) => {
  const u = new URL(url); const name = u.searchParams.get("name"); const type = u.searchParams.get("type");
  const google = u.host === "dns.google";
  let Answer = [];
  if (type === "A") Answer = [{ type: 1, data: disagree && google ? "198.51.100.99" : "198.51.100.7" }];
  if (type === "AAAA") Answer = [];
  if (type === "NS") Answer = [{ type: 2, data: "ns1.example-dns.com." }];
  if (type === "TXT" && name.endsWith("origin.asn.cymru.com")) Answer = [{ type: 16, data: "\"64500 | 198.51.100.0/24 | US | arin | 2010-01-01\"" }];
  return { ok: true, json: async () => ({ Answer }) };
};
const f1 = await collectFact("w.example.com", { fetchImpl: fake(false), now: () => "2026-09-27T10:00:00Z" });
t("collect: IPs, ASN from cymru TXT, NS of the registrable domain, time and method recorded", JSON.stringify(f1.ips) === '["198.51.100.7"]' && JSON.stringify(f1.asns) === '["64500"]' && f1.ns[0] === "ns1.example-dns.com" && f1.observed_at === "2026-09-27T10:00:00Z" && /cymru/.test(f1.method) && !f1.resolver_disagreements);
const f2 = await collectFact("w.example.com", { fetchImpl: fake(true), now: () => "2026-09-27T10:00:00Z" });
t("collect: when the two resolvers disagree, both answers are kept and the union is used (not the favorable one)", f2.ips.length === 2 && f2.resolver_disagreements && f2.resolver_disagreements[0].type === "A");

// ---- 6. 答えが無いのは事実が無いのと同じ (2026-09-27、塞がった網で集めて見つけた穴) ----
const dead = async () => { throw new Error("network blocked"); };
const f3 = await collectFact("w.example.com", { fetchImpl: dead, now: () => "2026-09-27T10:00:00Z" });
t("collect: when no resolver answers, the types are recorded as unanswered (not as an empty answer)", JSON.stringify(f3.unanswered) === '["A","AAAA","NS"]' && f3.ips.length === 0);
t("collect: an empty but real answer is not unanswered", !f1.unanswered || !f1.unanswered.includes("AAAA"));
const twoPool = { entries: [E("a.example.org", 1), E("b.example.net", 2)] };
const repDead = await diversityReport(twoPool, { "a.example.org": f3, "b.example.net": f3 });
t("report: facts that are entirely unanswered count as missing (facts_missing, entries_with_facts 0)", repDead.findings.includes("facts_missing") && repDead.entries_with_facts === "0", JSON.stringify(repDead.findings) + " " + repDead.entries_with_facts);
const partial = { ...f1, unanswered: ["AAAA"] };
const repPartial = await diversityReport(twoPool, { "a.example.org": partial, "b.example.net": partial });
t("report: a partially answered fact still counts, and its shared IP still clusters", repPartial.entries_with_facts === "2" && repPartial.control_clusters === "1", repPartial.entries_with_facts + " " + repPartial.control_clusters);
const repA = await diversityReport(twoPool, { "a.example.org": f3, "b.example.net": f3 });
const repB = await diversityReport(twoPool, { "a.example.org": { ...f3, unanswered: undefined }, "b.example.net": { ...f3, unanswered: undefined } });
t("report: unanswered is inside facts_sha256 (a reader can tell 'blocked' from 'empty')", repA.facts_sha256 !== repB.facts_sha256);

// ---- 7. 組織の多様性: legal-entity-v1 の宣言 (2026-09-27) ----
const LE_A = { registry: "JP", scheme: "houjin-bango", id: "7021001075279" };
const fA = (ip, le) => ({ observed_at: "2026-09-27T10:00:00Z", method: "test", ips: [ip], asns: ["64500"], ns: ["kate.ns.cloudflare.com"], ...(le ? { legal_entity: le } : {}) });
const orgPool = { entries: [E("w1.alpha.org", 11), E("w2.beta.net", 12), E("w3.gamma.io", 13)] };
const repOrg = await diversityReport(orgPool, { "w1.alpha.org": fA("198.51.100.1", LE_A), "w2.beta.net": fA("203.0.113.9", { ...LE_A, registry: "jp", scheme: "HOUJIN-BANGO" }), "w3.gamma.io": fA("192.0.2.77", { registry: "GLEIF", scheme: "lei", id: "5493001KJTIIGC8Y1R12" }) });
t("legal entity: different domains, IPs and hosts but the same declared entity form one control cluster", repOrg.control_clusters === "2" && repOrg.strong_shared.some((g) => g.kind === "legal_entity" && g.members.length === 2), repOrg.control_clusters + " " + JSON.stringify(repOrg.strong_shared));
t("legal entity: registry and scheme compare case-insensitively, the id exactly", repOrg.distinct.legal_entities === "2");
t("legal entity: all declared, so no legal_entity_undeclared finding", !repOrg.findings.includes("legal_entity_undeclared") && repOrg.entries_declaring_legal_entity === "3");
const repNoLe = await diversityReport(orgPool, { "w1.alpha.org": fA("198.51.100.1", LE_A), "w2.beta.net": fA("203.0.113.9"), "w3.gamma.io": fA("192.0.2.77") });
t("legal entity: undeclared entries are counted and named as a finding, never as proof of a different organization", repNoLe.findings.includes("legal_entity_undeclared") && repNoLe.entries_declaring_legal_entity === "1" && repNoLe.control_clusters === "3");
t("legal entity: does_not_establish says the declaration is not the register's answer and economic interest is not observed", repOrg.does_not_establish.some((x) => /only the register can answer/.test(x)) && repOrg.does_not_establish.some((x) => /economic interests/.test(x)));
const repLeDead = await diversityReport({ entries: [E("x.one.org", 21), E("y.two.org", 22)] }, { "x.one.org": { ...f3, legal_entity: LE_A }, "y.two.org": { ...f3, legal_entity: LE_A } });
t("legal entity: a shared declaration still clusters when DNS went unanswered (the declaration is not a DNS fact)", repLeDead.control_clusters === "1" && repLeDead.findings.includes("facts_missing"));
const drawOrg = await drawDiverse({ pool: orgPool, facts: { "w1.alpha.org": fA("198.51.100.1", LE_A), "w2.beta.net": fA("203.0.113.9", LE_A), "w3.gamma.io": fA("192.0.2.77") }, beaconHash: BEACON, subjectSha256: SUBJECT, k: 3 });
t("drawDiverse never draws two witnesses that declared the same legal entity", drawOrg.drawn.filter((h) => h === "w1.alpha.org" || h === "w2.beta.net").length === 1, JSON.stringify(drawOrg.drawn));
const cardFetch = (card, status = 200) => async (url) => {
  if (url.includes("agent-card.json")) return { ok: status === 200, status, json: async () => card };
  return { ok: true, json: async () => ({ Answer: [] }) };
};
const fLe = await collectFact("w.example.com", { fetchImpl: cardFetch({ capabilities: { extensions: [{ uri: "https://gate.horizonshield.dev/ext/legal-entity/v1", params: { ...LE_A, name: "X" } }] } }) });
t("collect: reads the legal-entity-v1 declaration from the agent card and records where it came from", fLe.legal_entity && fLe.legal_entity.id === LE_A.id && /agent-card\.json$/.test(fLe.legal_entity_source));
const fNoLe = await collectFact("w.example.com", { fetchImpl: cardFetch({ capabilities: { extensions: [] } }) });
t("collect: a card without the declaration is recorded as not_declared", fNoLe.legal_entity === null && fNoLe.legal_entity_source === "not_declared");
const f404 = await collectFact("w.example.com", { fetchImpl: cardFetch({}, 404) });
t("collect: a card that does not answer is recorded with its status, not as an absent declaration", f404.legal_entity === null && f404.legal_entity_source === "card_http_404");

// ---- 池に入った経路 (arrival): 運営者の声掛けを数に出す ----
{
  const none = await diversityReport(sybilPool, facts);
  t("arrival: with no disclosure every entry is undisclosed, never counted as unsolicited", none.arrived_via.undisclosed === "5" && none.arrived_via.unsolicited === "0" && none.findings.includes("arrival_undisclosed"));
  const arrivals = { arrivals: {
    "w1.sybil.example": { via: "invited", ref: "https://github.com/example/repo/issues/1" },
    "honest-a.org": { via: "unsolicited" },
    "honest-b.net": { via: "referred", referred_by: "Honest-A.org" },
  } };
  const r = await diversityReport(sybilPool, facts, { arrivals });
  t("arrival: counts each kind and leaves the rest undisclosed", r.arrived_via.invited === "1" && r.arrived_via.unsolicited === "1" && r.arrived_via.referred === "1" && r.arrived_via.undisclosed === "2");
  t("arrival: the invitation link and the referrer are carried, referrer lowercased", r.arrivals.find((a) => a.signed_domain === "w1.sybil.example").ref === "https://github.com/example/repo/issues/1" && r.arrivals.find((a) => a.signed_domain === "honest-b.net").referred_by === "honest-a.org");
  t("arrival: disclosure never changes the control clusters or pool_sha256", r.control_clusters === rep.control_clusters && r.pool_sha256 === rep.pool_sha256 && r.facts_sha256 === rep.facts_sha256);
  t("arrival: arrivals_sha256 changes when a disclosure changes", r.arrivals_sha256 !== none.arrivals_sha256 && (await diversityReport(sybilPool, facts, { arrivals: { arrivals: { ...arrivals.arrivals, "honest-a.org": { via: "invited" } } } })).arrivals_sha256 !== r.arrivals_sha256);
  t("arrival: a free-text note is not hashed (only via, ref, referred_by)", (await diversityReport(sybilPool, facts, { arrivals: { arrivals: { ...arrivals.arrivals, "honest-a.org": { via: "unsolicited", note: "found us on a search" } } } })).arrivals_sha256 === r.arrivals_sha256);
  t("arrival: a domain that is not in the pool is ignored (an invited candidate who never joined is not listed)", (await diversityReport(sybilPool, facts, { arrivals: { arrivals: { ...arrivals.arrivals, "never-joined.example": { via: "invited" } } } })).arrivals_sha256 === r.arrivals_sha256);
  const allInvited = await diversityReport({ entries: [E("a.one.org", 31), E("b.two.org", 32)] }, {}, { arrivals: { "a.one.org": { via: "invited" }, "b.two.org": { via: "invited" } } });
  t("arrival: when every disclosed entry was invited, operator_outreach_only is raised", allInvited.findings.includes("operator_outreach_only") && !allInvited.findings.includes("arrival_undisclosed"));
  t("arrival: one unsolicited entry clears operator_outreach_only", !r.findings.includes("operator_outreach_only"));
  const bad = (a) => { try { normalizeArrivals(a, sybilPool.entries); return null; } catch (e) { return e.message; } };
  t("arrival: an unknown kind is refused", /via must be one of/.test(bad({ "honest-a.org": { via: "volunteered" } })));
  t("arrival: referred without referred_by is refused", /referred needs referred_by/.test(bad({ "honest-a.org": { via: "referred" } })));
  t("arrival: a non-https ref is refused", /ref must be an https URL/.test(bad({ "honest-a.org": { via: "invited", ref: "http://x.example/1" } })));
  t("arrival: the report still carries no score", !/"(score|rank|rating|trust_level|trust_score|grade)"/.test(JSON.stringify(r)));
}

console.log(results.join("\n"));
console.log("\nwitness_diversity: " + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
