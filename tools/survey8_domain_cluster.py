# -*- coding: utf-8 -*-
"""
survey8 domain clusters: count the registrable domains (eTLD+1) behind the run2 transport rows and print a
domain-cluster bootstrap of the survey8 estimate. No network: reads run2, the survey8 rows and a Public Suffix List file.

Why (2026-10-11, modelcontextprotocol/registry discussion #1547, zzzz0902zzzz-rgb): rows on one dead host are not
independent, so a band that treats rows as independent can be too narrow. Reduce each 'not_reached, DNS' row to its
registrable domain and count; if the top 10 domains cover a double-digit share of 635, resample domains, not rows,
1,000 reps, (5785 + sum of flips) / 10963 each, and report the 2.5 to 97.5 percentile band.

Definitions are imported from survey8_transport_recheck.py (transport_class, population, estimate), so the classes,
the left-out rows and the point estimate are the published ones. A row's flip is the survey8 estimator's: within class
c, flips_c = population_c * (flipped rows / rechecked rows), robots_unreachable counted as rechecked and not flipped,
robots_disallowed / instrument_down / probe_error left out. The bootstrap recomputes that ratio on resampled clusters.

Registrable domain: the Public Suffix List bundled with the publicsuffixlist package (no fetch at run time). The full
list (ICANN and private sections, as browsers use it: each *.trycloudflare.com tunnel is its own domain) is the main
reading; ICANN-only (all tunnels under trycloudflare.com) is printed next to it. A templated host such as {host} has no
suffix; its literal host is its cluster.

Templated hosts (2026-10-12, zzzz0902zzzz-rgb): 59 of the 635 DNS rows have a host that is only a template variable
such as {host} or {api_host}; by default each literal host is one cluster (34 clusters). --templates normalized replaces
every {...} span with one placeholder first, so they collapse to the normalized hosts ({} and {}{}), and --templates one
puts every templated host in a single cluster. Each band line prints n_clusters (all classes) and the DNS class's count.

  pip install publicsuffixlist==1.1.0.20261010      # the only dependency outside the standard library
  python3 tools/survey8_domain_cluster.py verify-directory/survey/data/survey1_walk_2026-08-23_run2.jsonl \
      verify-directory/survey/data/survey8_transport_recheck_2026-10-10.jsonl

With that package version the output is fixed: PSL sha256 ba7d836c..., 194 domains in the 635 DNS rows (top 10: 418,
65.8%), domain-cluster band 53.32% to 54.25%, rows treated as independent 53.49% to 54.08%, published Wilson sum 53.30%
to 54.63%.
"""
import argparse, collections, hashlib, io, math, os, random, re, sys
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))

SEED = "survey8-domain-cluster-2026-10-11"
REPS = 1000
LEFT_OUT = ("robots_disallowed", "instrument_down", "probe_error")   # as in survey8_transport_recheck.estimate()


def load_survey8(tools_dir):
    sys.path.insert(0, tools_dir)
    import survey8_transport_recheck as S8
    return S8


def psl_open(path, only_icann):
    from publicsuffixlist import PublicSuffixList
    with io.open(path, encoding="utf-8") as fh:
        return PublicSuffixList(source=fh, only_icann=only_icann)


def psl_info(path):
    b = open(path, "rb").read()
    head = {}
    for line in b.decode("utf-8").splitlines()[:60]:
        for k in ("VERSION", "COMMIT"):
            if line.startswith("// %s:" % k):
                head[k] = line.split(":", 1)[1].strip()
    return hashlib.sha256(b).hexdigest(), head


TEMPLATES = "literal"   # literal (each templated host its own cluster) | normalized ({...} -> {}) | one
TEMPLATE_SPAN = re.compile(r"\{[^}]*\}")


def domain_of(endpoint, psl):
    host = (urlsplit(endpoint).hostname or "").rstrip(".")
    d = psl.privatesuffix(host) if (host and psl is not None) else None
    if d:
        return d
    lit = host or endpoint
    if TEMPLATES == "normalized":
        lit = TEMPLATE_SPAN.sub("{}", lit)
    elif TEMPLATES == "one" and "{" in lit:
        lit = "{templated}"
    return "literal:" + lit


def percentile(sorted_vals, q):
    """Linear interpolation between closest ranks (numpy's default)."""
    k = (len(sorted_vals) - 1) * q
    f = math.floor(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, mid - half), min(1.0, mid + half))


def class_clusters(recheck_rows, classes, psl, by_row=()):
    """{class: [(rows, flipped), ...]} one entry per domain (or per row for classes in by_row)."""
    out = {}
    for c in classes:
        rs = [r for r in recheck_rows if r.get("run2_class") == c and r.get("outcome") not in LEFT_OUT]
        if c in by_row:
            out[c] = [(1, 1 if r.get("speaks_mcp") else 0) for r in rs]
            continue
        g = collections.OrderedDict()
        for r in sorted(rs, key=lambda r: r["endpoint"]):
            d = domain_of(r["endpoint"], psl)
            n, f = g.get(d, (0, 0))
            g[d] = (n + 1, f + (1 if r.get("speaks_mcp") else 0))
        out[c] = list(g.values())
    return out


def flips_of(clusters, sizes):
    return sum(sizes[c] * (sum(f for _, f in cl) / sum(n for n, _ in cl)) for c, cl in clusters.items() if cl)


def bootstrap(clusters, sizes, speaks, measured, seed, reps):
    """Stratified cluster bootstrap: in each class draw as many clusters as it has, with replacement."""
    rng = random.Random(hashlib.sha256(seed.encode("utf-8")).digest())
    order = sorted(clusters)
    rates = []
    for _ in range(reps):
        total = 0.0
        for c in order:
            cl = clusters[c]
            if not cl:
                continue
            n = f = 0
            for _ in range(len(cl)):
                a, b = cl[rng.randrange(len(cl))]
                n += a
                f += b
            total += sizes[c] * f / n
        rates.append((speaks + total) / measured)
    rates.sort()
    return percentile(rates, 0.025), percentile(rates, 0.975), rates


def population_bootstrap(run2_rows, recheck_rows, S8, psl, seed, reps):
    """The other reading, printed only to show it: give every one of the 1,106 transport rows a flip value (its 0/1 if
    rechecked, its class fraction if not), cluster the 1,106 by domain, resample domains, sum. It matches the point
    estimate but most of its rows carry a constant, so it does not measure the sampling error of the 300."""
    est = S8.estimate(run2_rows, recheck_rows)
    frac = {c: v["fraction"] or 0.0 for c, v in est["per_class"].items()}
    seen = {r["endpoint"]: (1.0 if r.get("speaks_mcp") else 0.0) for r in recheck_rows if r.get("outcome") not in LEFT_OUT}
    rechecked_left_out = {r["endpoint"] for r in recheck_rows if r.get("outcome") in LEFT_OUT}
    g = collections.OrderedDict()
    for r in sorted(run2_rows, key=lambda r: r["endpoint"]):
        c = S8.transport_class(r)
        if not c:
            continue
        e = r["endpoint"]
        v = seen.get(e, frac[c]) if e not in rechecked_left_out else frac[c]
        d = domain_of(e, psl)
        g.setdefault(d, []).append(v)
    cl = [sum(v) for v in g.values()]
    point = sum(cl)
    rng = random.Random(hashlib.sha256((seed + "|population").encode("utf-8")).digest())
    rates = sorted((est["speaks_run2"] + sum(cl[rng.randrange(len(cl))] for _ in range(len(cl)))) / est["measured"] for _ in range(reps))
    return point, len(cl), percentile(rates, 0.025), percentile(rates, 0.975)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run2")
    ap.add_argument("recheck")
    ap.add_argument("--psl", default=None, help="Public Suffix List file (default: the one bundled with publicsuffixlist)")
    ap.add_argument("--tools", default=HERE, help="directory holding survey8_transport_recheck.py")
    ap.add_argument("--seed", default=SEED)
    ap.add_argument("--reps", type=int, default=REPS)
    ap.add_argument("--templates", choices=("literal", "normalized", "one"), default="literal",
                    help="how a host that is only a template variable is clustered (default: each literal host)")
    a = ap.parse_args()
    global TEMPLATES
    TEMPLATES = a.templates
    print("templated hosts: %s" % TEMPLATES)

    S8 = load_survey8(a.tools)
    if a.psl is None:
        import publicsuffixlist
        a.psl = os.path.join(os.path.dirname(publicsuffixlist.__file__), "public_suffix_list.dat")
    psl_sha, psl_head = psl_info(a.psl)
    run2 = S8.load_rows(a.run2)
    rech = S8.load_rows(a.recheck)
    print("run2     %s sha256 %s" % (os.path.basename(a.run2), hashlib.sha256(open(a.run2, "rb").read()).hexdigest()))
    print("survey8  %s sha256 %s" % (os.path.basename(a.recheck), hashlib.sha256(open(a.recheck, "rb").read()).hexdigest()))
    print("PSL      %s sha256 %s (VERSION %s, COMMIT %s)" % (os.path.basename(a.psl), psl_sha, psl_head.get("VERSION"), psl_head.get("COMMIT", "")[:12]))

    pop = S8.population(run2)
    sizes = {c: len(v) for c, v in pop.items()}
    est = S8.estimate(run2, rech)
    speaks, measured = est["speaks_run2"], est["measured"]
    print("published estimate: (%d + %.1f) / %d = %.2f%%" % (speaks, est["estimated_flips"], measured, 100 * est["rate_measured"]))

    for label, icann in (("full PSL (ICANN + private)", False), ("ICANN section only", True)):
        psl = psl_open(a.psl, icann)
        print("\n== %s ==" % label)
        dns = collections.Counter(domain_of(e, psl) for e in pop["dns"])
        top = dns.most_common(10)
        cov = sum(n for _, n in top)
        lit = sum(n for d, n in dns.items() if d.startswith("literal:"))
        print("dns rows %d, distinct domains %d (%d rows on templated hosts, %d such clusters)" % (len(pop["dns"]), len(dns), lit, sum(1 for d in dns if d.startswith("literal:"))))
        for d, n in top:
            print("  %5d  %5.1f%%  %s" % (n, 100 * n / len(pop["dns"]), d))
        print("top 10 cover %d / %d = %.1f%%; top 1 %.1f%%" % (cov, len(pop["dns"]), 100 * cov / len(pop["dns"]), 100 * top[0][1] / len(pop["dns"])))

        allc = collections.Counter(domain_of(e, psl) for c in S8.CLASSES for e in pop[c])
        print("all 1,106 transport rows: %d distinct domains, top 10 cover %d" % (len(allc), sum(n for _, n in allc.most_common(10))))

        cl = class_clusters(rech, S8.CLASSES, psl)
        for c in S8.CLASSES:
            flipped_domains = sum(1 for n, f in cl[c] if f)
            print("  survey8 %-20s rows %3d  domains %3d  flipped rows %2d on %d domains" % (c, sum(n for n, _ in cl[c]), len(cl[c]), sum(f for _, f in cl[c]), flipped_domains))
        assert abs(flips_of(cl, sizes) - est["estimated_flips"]) < 1e-9, "cluster table does not reproduce the published flips"

        lo, hi, rates = bootstrap(cl, sizes, speaks, measured, a.seed, a.reps)
        print("domain-cluster bootstrap, all classes by domain, %d reps, seed %r: %.2f%% to %.2f%%  (flips %.0f to %.0f)  n_clusters %d (dns %d)"
              % (a.reps, a.seed, 100 * lo, 100 * hi, lo * measured - speaks, hi * measured - speaks, sum(len(v) for v in cl.values()), len(cl["dns"])))
        cl_dns = class_clusters(rech, S8.CLASSES, psl, by_row=tuple(c for c in S8.CLASSES if c != "dns"))
        lo2, hi2, _ = bootstrap(cl_dns, sizes, speaks, measured, a.seed, a.reps)
        print("  only dns by domain, other classes by row:                         %.2f%% to %.2f%%  n_clusters %d (dns %d)" % (100 * lo2, 100 * hi2, sum(len(v) for v in cl_dns.values()), len(cl_dns["dns"])))
        point, ncl, lo4, hi4 = population_bootstrap(run2, rech, S8, psl, a.seed, a.reps)
        print("  other reading, 1,106 rows imputed and resampled by domain (%d): point %.1f flips, %.2f%% to %.2f%% (not used)" % (ncl, point, 100 * lo4, 100 * hi4))

    rows_cl = class_clusters(rech, S8.CLASSES, None, by_row=S8.CLASSES)
    lo3, hi3, _ = bootstrap(rows_cl, sizes, speaks, measured, a.seed, a.reps)
    print("\nrow bootstrap (rows independent, same seed and reps):                %.2f%% to %.2f%%" % (100 * lo3, 100 * hi3))

    wl = wh = 0.0
    for c, v in est["per_class"].items():
        l, h = wilson(v["flipped"], v["rechecked"])
        wl += v["population"] * l
        wh += v["population"] * h
    print("published: sum of per-class 95%% Wilson bounds: %.0f to %.0f flips, %.2f%% to %.2f%%" % (wl, wh, 100 * (speaks + wl) / measured, 100 * (speaks + wh) / measured))


if __name__ == "__main__":
    main()
