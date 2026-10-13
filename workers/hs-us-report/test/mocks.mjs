// In-memory stand-ins for KV, R2, the hs-jccdb-obs service binding and outside HTTP calls.
// 2026-10-13 (concurrency audit U3). kv({ lagList: true }) makes list() answer from a snapshot of the keys and their
// metadata taken by freezeList(), the way real KV list metadata can lag a put by up to 60 s. get() is never lagged.
// thawList() goes back to listing the live store. Without the option nothing changes.
export function kv({ lagList = false } = {}) {
  const m = new Map();
  let snap = null;
  return {
    m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    meta: new Map(),
    async put(k, v, opts = {}) { m.set(k, String(v)); if (opts.metadata) this.meta.set(k, opts.metadata); else this.meta.delete(k); },
    async delete(k) { m.delete(k); this.meta.delete(k); },
    freezeList() { snap = [...m.keys()].map((name) => ({ name, metadata: this.meta.get(name) })); },
    thawList() { snap = null; },
    async list({ prefix = "", limit = 1000 } = {}) {
      const keys = lagList && snap ? snap : [...m.keys()].map((name) => ({ name, metadata: this.meta.get(name) }));
      return { keys: keys.filter((k) => k.name.startsWith(prefix)).slice(0, limit), list_complete: true };
    },
  };
}
export function r2() {
  const m = new Map();
  return {
    m,
    async put(key, data, opts = {}) { const bytes = data instanceof Uint8Array ? data : new TextEncoder().encode(String(data)); m.set(key, { bytes, httpMetadata: opts.httpMetadata || {}, customMetadata: opts.customMetadata || {}, uploaded: new Date(opts._uploaded || Date.now()) }); },
    async get(key) { const o = m.get(key); if (!o) return null; return { httpMetadata: o.httpMetadata, customMetadata: o.customMetadata, body: new Blob([o.bytes]).stream(), arrayBuffer: async () => o.bytes.buffer.slice(o.bytes.byteOffset, o.bytes.byteOffset + o.bytes.byteLength) }; },
    async delete(key) { m.delete(key); },
    async list({ prefix = "" } = {}) { return { objects: [...m.entries()].filter(([k]) => k.startsWith(prefix)).map(([key, o]) => ({ key, uploaded: o.uploaded, customMetadata: o.customMetadata })), truncated: false }; },
  };
}
const wageRow = (soc, name, level, code, basis, price, period = "2025-05") => ({ item_name: name, spec: `SOC ${soc}; O_GROUP detailed`, unit: basis.startsWith("wage_hourly") ? "USD/hour" : "USD/year", geo_level: level, geo_code: code, geo_name: level === "metro" ? "Austin-Round Rock-San Marcos, TX" : "Texas", price, price_basis: basis, has_value: true, period, source_id: level === "metro" ? "bls-oews-m2025-metro" : "bls-oews-m2025-state", evidence_url: "https://www.bls.gov/oes/special-requests/oesm25ma.zip" });
export const WAGE_ROWS_METRO = [
  // helpers first, as the text search ranks them, to prove the SOC filter
  wageRow("47-3016", "Helpers--Roofers", "metro", "12420", "wage_hourly_mean", 18.1),
  wageRow("47-3016", "Helpers--Roofers", "metro", "12420", "wage_hourly_p90", 22.9),
  wageRow("47-2181", "Roofers", "metro", "12420", "wage_hourly_mean", 22.0, "2024-05"),
  wageRow("47-2181", "Roofers", "metro", "12420", "wage_hourly_p90", 30.0, "2024-05"),
  wageRow("47-2181", "Roofers", "metro", "12420", "wage_hourly_mean", 24.08),
  wageRow("47-2181", "Roofers", "metro", "12420", "wage_hourly_p90", 33.24),
  wageRow("47-2181", "Roofers", "metro", "12420", "wage_hourly_p10", 17.37),
  wageRow("47-2181", "Roofers", "metro", "12420", "wage_annual_mean", 50080),
];
export const CHAIN = { data_version: { built_at: "2026-09-26T12:28:45Z", ym: "202607" }, rows: [{ hs10: "6807900010", unit: "KG", period: "2026-01..2026-07 (YTD)", landed: { unit_landed_usd: 0.46665497 }, wholesale: { gross_margin: 0.283493 }, contractor: { range: { markup: [0.15, 0.25] } } }] };
export function jccdbService(calls = []) {
  return {
    async fetch(req) {
      const u = new URL(req.url);
      calls.push(u.pathname + u.search);
      if (u.hostname !== "jccdb-obs.internal") return new Response(JSON.stringify({ error: "us_private" }), { status: 403 });
      if (u.pathname === "/us" && u.searchParams.get("layer") === "wage") {
        const geo = u.searchParams.get("geo");
        const rows = geo === "cbsa:12420" ? WAGE_ROWS_METRO : [];
        const off = Number(u.searchParams.get("offset") || 0);
        const lim = Number(u.searchParams.get("limit") || 100);
        const page = rows.slice(off, off + lim);
        return new Response(JSON.stringify({ rows: page, next_offset: off + lim < rows.length ? off + lim : null }));
      }
      if (u.pathname === "/us/chain") return new Response(JSON.stringify(CHAIN));
      return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
    },
  };
}
export function outside(log, { ipn = "VERIFIED" } = {}) {
  return async (url, init = {}) => {
    const u = String(url);
    log.push({ url: u, body: init.body });
    if (u.startsWith("https://ipnpb.paypal.com")) return new Response(ipn);
    if (u.startsWith("https://api.resend.com")) return new Response(JSON.stringify({ id: "email_1" }));
    if (u.startsWith("https://api.line.me")) return new Response("{}");
    return new Response("unexpected " + u, { status: 599 });
  };
}
export const EXTRACTED = {
  schema_version: "us-extract-0.1",
  doc: { contractor: "Example Roofing LLC", quote_no: "Q-1042", quote_date: "2026-09-20", total: 19872, trade: "roof replacement" },
  lines: [
    { item: "Tear-off and disposal, 1 layer", amount: 3360, kind: "disposal" },
    { item: "Architectural shingles, 26 squares", amount: 4420, qty: 26, unit: "SQ", kind: "material", material: { type: "asphalt_shingles", squares: 26, weight_lb_per_square: 240 } },
    { item: "Underlayment, flashing, vents", amount: 1850, kind: "other" },
    { item: "Labor, 3 roofers x 3 days", amount: 6480, kind: "labor", labor: { workers: 3, days: 3, hours: null } },
    { item: "Permit", amount: 450, kind: "permit" },
    { item: "Overhead and profit 20%", amount: 3312, kind: "overhead" },
  ],
};
