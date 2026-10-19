#!/usr/bin/env python3
"""Count, once a week, how far NENRIN has moved from "people check HORIZON SHIELD" to "people use it without us".

Five numbers, each from a source a stranger can read, none typed by hand:

  independent_implementations  implementations by other authors that reproduced our bytes or verdicts.
                               Source: tools/adoption/registry.json (hand-kept rows, each with a public link);
                               this script checks every link still answers and counts rows and distinct authors.
                               Only rows of kind "implementation" count; "reproduction" (a rerun of our code) and
                               "integration" (our vectors or records in someone else's tests) are reported apart.
  independent_witnesses        domains outside this project that signed a walk and filed it to the ledger.
                               Source: every nenrin-witness-batch-v1 entry on https://ledger.horizonshield.dev,
                               field signed_domain. Unsigned walks are listed by name and not counted. The TSUGI
                               re-verification pool (recovery-v0/pool_report.json) is reported beside it.
  external_contracts           MUSUBI contracts signed by both sides with a party that is not this project, and
                               separately those with no party from this project at all.
                               Source: the signed contracts committed under workers/hs-ledger/nenrin/musubi-v0,
                               except settle-core-v0/ (test vectors signed by synthetic keys, and copies of a
                               contract its parties publish, which is counted from registry.json instead). In the
                               repository, a party named with a reserved test name (RFC 2606, RFC 6761) is not counted.
  external_evidence_producers  distinct outside identities that signed anything the evidence layer keeps: a
                               ledger witness walk, a contract, an agreement record. The union of the above.
  outside_trace_pins           distinct TRACE signing keys (RFC 7638 thumbprints) not listed as ours whose records
                               were pinned with trace-pin-v0. Source: every nenrin-trace-pin-batch-v0 entry on the
                               ledger plus the pending pool (GET /evidence/trace/pending). The TRACE registry asked
                               for this count before it would consider holding a copy of the ledger.
  third_party_ci_reproductions public repositories, not owned by this project, created from
                               conduct-witness-template whose weekly reproduce workflow succeeded in the last 30
                               days. Source: the GitHub REST API (search, repository, workflow runs).

A source that cannot be read is reported as not measured, with the reason, and its number is null. It is never
counted as zero: an outage of ours is not a finding about anyone.

    python3 tools/adoption/count_adoption.py            # print the count
    python3 tools/adoption/count_adoption.py --write    # also write ops/adoption/ and the README block
    python3 tools/adoption/count_adoption.py --check    # exit 1 if the README block differs from latest.json

GITHUB_TOKEN, when set, is sent to api.github.com only (higher rate limit). Standard library only.
"""
import argparse, datetime, glob, hashlib, io, json, os, shutil, subprocess, sys, tempfile, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REG = os.path.join(ROOT, "tools", "adoption", "registry.json")
OUT_DIR = os.path.join(ROOT, "ops", "adoption")
README = os.path.join(ROOT, "README.md")
LEDGER = os.environ.get("HS_LEDGER", "https://ledger.horizonshield.dev")
POOL = os.path.join(ROOT, "workers", "hs-ledger", "nenrin", "recovery-v0", "pool_report.json")
DIVERSITY = os.path.join(ROOT, "workers", "hs-ledger", "nenrin", "recovery-v0", "witness_diversity_report.json")
MUSUBI = os.path.join(ROOT, "workers", "hs-ledger", "nenrin", "musubi-v0")
AGREEMENT = os.path.join(ROOT, "workers", "hs-ledger", "nenrin", "agreement-v0")
# Directories under musubi-v0 that hold test material, not contracts anyone made: settle-core-v0/vectors are signed by
# synthetic keys, and settle-core-v0/inputs/peer31 is a copy of a contract its parties publish (counted from
# registry.json). Found 2026-10-19: the 2026-10-17 vectors made the offline test count 46 contracts with no party from us.
NOT_CONTRACT_RECORDS = ("settle-core-v0",)
RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
RESERVED_NAMES = ("example.com", "example.net", "example.org", "localhost", "test", "example", "invalid")
TEMPLATE = "ogasurfproject-jpg/conduct-witness-template"
OWNER = "ogasurfproject-jpg"
UA = "HORIZON-SHIELD-adoption-count/1.0 (+https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/tools/adoption)"
START, END = "<!-- adoption-count:start -->", "<!-- adoption-count:end -->"


def tracked(pattern_dir, recursive):
    """Files git tracks under a directory: a draft left in a working tree is not evidence anyone signed."""
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files", "--", os.path.relpath(pattern_dir, ROOT)],
                             capture_output=True, text=True, check=True).stdout.split()
        files = [os.path.join(ROOT, f) for f in out if f.endswith(".json")]
        return sorted(f for f in files if recursive or os.path.dirname(f) == pattern_dir)
    except Exception:
        pat = os.path.join(pattern_dir, "**", "*.json") if recursive else os.path.join(pattern_dir, "*.json")
        return sorted(glob.glob(pat, recursive=recursive))


def get(url, accept="application/json", timeout=20):
    headers = {"user-agent": UA, "accept": accept}
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def get_json(url):
    status, body = get(url)
    return json.loads(body.decode("utf-8"))


# 2026-10-16. Hosts where many unrelated people publish files under different paths are nobody's identity. The ledger
# intake refuses them (and maps raw.githubusercontent.com to github.com/<owner>); this count refuses them again, so a
# record filed before that rule, or by a broken intake, can never make everyone one witness.
SHARED_HOSTS = {
    "raw.githubusercontent.com", "github.com", "gist.github.com", "gist.githubusercontent.com", "objects.githubusercontent.com",
    "codeload.github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com", "huggingface.co", "cdn.jsdelivr.net",
    "unpkg.com", "raw.githack.com", "storage.googleapis.com", "s3.amazonaws.com", "drive.google.com", "docs.google.com",
    "dl.dropboxusercontent.com", "pastebin.com", "web.archive.org",
}


def shared_host(identity):
    s = (identity or "").lower()
    return s in SHARED_HOSTS or (s.startswith("s3.") and s.endswith(".amazonaws.com"))


def reserved_name(identity):
    """A reserved test name (RFC 2606, RFC 6761) names nobody, so it is never a party."""
    s = (identity or "").lower().rstrip(".")
    return s in RESERVED_NAMES or s.endswith(RESERVED_SUFFIXES) or any(s.endswith("." + n) for n in RESERVED_NAMES[:3])


def ours(identity, our):
    s = (identity or "").lower()
    return any(s == o or s.endswith("." + o) for o in our)


KINDS = ("implementation", "reproduction", "integration")


def implementations(reg):
    items, alive = [], 0
    for row in reg["implementations"]:
        try:
            status, _ = get(row["evidence"], accept="text/html,application/json")
            ok = 200 <= status < 400
        except urllib.error.HTTPError as e:
            ok, status = False, e.code
        except Exception as e:
            ok, status = None, type(e).__name__
        alive += ok is True
        # The row's free-text "what" stays in registry.json and is not copied here: a dated snapshot is kept forever,
        # so wording that has to change later (a name withheld until a fix ships, say) must live in one place only.
        items.append({**{k: v for k, v in row.items() if k != "what"}, "link_status": status, "link_ok": ok})
    # Only rows of kind "implementation" (code of the author's own that reproduced our bytes or verdicts) are counted
    # here. A rerun of our own code ("reproduction") and our vectors or records taken into someone else's tests or
    # mapping ("integration") are real and listed, but reported apart (asked for in VATE #84 on 2026-10-14: a
    # reproduction must not feed the implementation count). A row without a kind is an implementation.
    for r in items:
        r["kind"] = r.get("kind") or "implementation"
        if r["kind"] not in KINDS:
            raise ValueError("registry row %r has unknown kind %r" % (r.get("evidence"), r["kind"]))
    impl = [r for r in items if r["kind"] == "implementation"]
    by_subject = {}
    for r in impl:
        by_subject[r["subject"]] = by_subject.get(r["subject"], 0) + 1
    # Authors are counted by a stable id (a GitHub account, or a domain for an author with no account), never by the
    # free-text "who": the same person written two ways was counted twice until 2026-10-09 (8 reported, 7 real).
    aid = lambda r: str(r.get("author") or r["who"]).strip().lower()
    authors = {aid(r) for r in impl}
    other = {}
    for k in KINDS[1:]:
        rows_k = [r for r in items if r["kind"] == k]
        other[k] = {"count": len(rows_k), "distinct_authors": len({aid(r) for r in rows_k})}
    return {"count": len(impl), "distinct_authors": len(authors), "authors": sorted(authors), "links_answering": alive,
            "by_subject": dict(sorted(by_subject.items())), "other_kinds": other, "open_calls": reg.get("open_calls", {}),
            "items": items}


def ledger_witnesses(our, our_names=()):
    head = get_json(LEDGER + "/ledger/head")
    n = int(head["n"])
    signed, unsigned, batches, unreadable, trace, refused = {}, {}, 0, [], [], []
    for i in range(1, n + 1):
        try:
            e = get_json("%s/ledger/%d" % (LEDGER, i))
        except Exception as ex:
            unreadable.append(i)
            continue
        rc = e.get("record_canonical")
        if isinstance(rc, str) and "nenrin-trace-pin-batch-v0" in rc:
            try:
                tb = json.loads(rc)
            except Exception:
                tb = {}
            if tb.get("schema") == "nenrin-trace-pin-batch-v0":
                for r in tb.get("records") or []:
                    if r.get("key_thumbprint"):
                        trace.append({"key_thumbprint": r["key_thumbprint"], "subject": r.get("subject"), "sha": r.get("sha"), "entry": i})
            continue
        if not isinstance(rc, str) or "nenrin-witness-batch-v1" not in rc:
            continue
        try:
            b = json.loads(rc)
        except Exception:
            continue
        if b.get("schema") != "nenrin-witness-batch-v1":
            continue
        batches += 1
        for r in b.get("records") or []:
            d = r.get("signed_domain")
            if d:
                if shared_host(d):
                    refused.append({"entry": i, "signed_domain": d.lower()})
                elif not ours(d, our):
                    signed.setdefault(d.lower(), []).append(i)
            elif r.get("witness_name") and not ours(r["witness_name"], our) and not any(x in r["witness_name"].lower() for x in our_names):
                unsigned.setdefault(r["witness_name"], []).append(i)
    return {"ledger_n": n, "ledger_head": head.get("head"), "witness_batches": batches, "unreadable_entries": unreadable, "refused_shared_host": refused,
            "signed_domains": {k: sorted(set(v)) for k, v in sorted(signed.items())},
            "unsigned_names": {k: sorted(set(v)) for k, v in sorted(unsigned.items())}, "trace_pins_anchored": trace}


def trace_pins(anchored, our_thumbprints):
    """Outside TRACE producers who pinned a record: anchored batches plus the pending pool, by key thumbprint."""
    rows = list(anchored or [])
    pend = get_json(LEDGER + "/evidence/trace/pending")
    for r in pend.get("pending") or []:
        if r.get("key_thumbprint"):
            rows.append({"key_thumbprint": r["key_thumbprint"], "subject": r.get("subject"), "sha": r.get("sha"), "entry": None})
    keys = {}
    for r in rows:
        if r["key_thumbprint"] in our_thumbprints:
            continue
        k = keys.setdefault(r["key_thumbprint"], {"key_thumbprint": r["key_thumbprint"], "records": 0, "anchored": 0, "subjects": set()})
        k["records"] += 1
        k["anchored"] += r["entry"] is not None
        if r.get("subject"):
            k["subjects"].add(r["subject"].split("/run/")[0])
    out = [{**v, "subjects": sorted(v["subjects"])} for v in keys.values()]
    return {"count": len(out), "keys": sorted(out, key=lambda x: x["key_thumbprint"]), "pending_pool": pend.get("count")}


def published_contracts(reg, our):
    """Contracts the parties keep in their own repositories, listed in registry.json under published_contracts as
    {"contract_url", "contract_sha256"?, "settlement_url"?, "note"?}. A row counts only when the bytes at the URL are a
    contract both sides signed and contract_v0.verify_contract accepts the signatures; a pinned contract_sha256 must
    match. Rows that cannot be fetched or checked are listed with the reason and not counted."""
    out, problems = [], []
    rows = reg.get("published_contracts") or []
    if not rows:
        return out, problems
    try:
        sys.path.insert(0, MUSUBI)
        import contract_v0 as v0
    except Exception as e:
        return out, [{"contract_url": r.get("contract_url"), "why": "contract_v0 not importable: %s" % e} for r in rows]
    for r in rows:
        url = r.get("contract_url")
        try:
            status, body = get(url)
            d = json.loads(body.decode("utf-8"))
        except Exception as e:
            problems.append({"contract_url": url, "why": "not readable: %s" % e}); continue
        try:
            v = v0.verify_contract(d)
        except SystemExit as e:
            problems.append({"contract_url": url, "why": "signatures not checked here: %s" % e}); continue
        csha = v.get("contract_sha256")
        if r.get("contract_sha256") and r["contract_sha256"] != csha:
            problems.append({"contract_url": url, "why": "the bytes hash to %s, the registry pins %s" % (csha, r["contract_sha256"])}); continue
        if v.get("verdict") != "accepted":
            problems.append({"contract_url": url, "why": "verify_contract: %s" % v.get("verdict")}); continue
        domains = [str(x.get("domain") or "").lower() for x in d.get("parties") or [] if isinstance(x, dict)]
        out.append({"contract_id": d.get("contract_id"), "file": url, "contract_sha256": csha, "parties": domains,
                    "outside_parties": [x for x in domains if x and not ours(x, our)], "published_by_the_parties": True,
                    "settlement_url": r.get("settlement_url"), "settlement": recompute_settlement(r, body, csha)})
    return out, problems


SETTLE_SCRIPTS = {"a2a-settlement-v1.10": "settle_v1_10.py"}


def recompute_settlement(row, contract_bytes, csha):
    """A settlement the parties publish counts as settled only when this count recomputes it: the settle verifier of
    the version the settlement names, run here on the contract bytes counted above and the event and header view the
    parties publish (registry row: settle_inputs {event_url, view_url}), must print the same bytes as settlement_url.
    Anything short of that is reported with the reason and not counted as settled."""
    url = row.get("settlement_url")
    if not url:
        return None
    res = {"settlement_url": url, "recomputed_identical": False}
    try:
        st, sb = get(url)
        sd = json.loads(sb.decode("utf-8"))
    except Exception as e:
        return {**res, "why": "settlement not readable: %s" % e}
    res.update({"schema": sd.get("schema"), "status": sd.get("status"), "verdict": sd.get("verdict"),
                "final_at_height": (sd.get("finality_horizon") or {}).get("height"),
                "settlement_sha256": hashlib.sha256(sb).hexdigest()})
    if sd.get("contract_sha256") != csha:
        return {**res, "why": "the settlement names contract %s, the contract counted is %s" % (sd.get("contract_sha256"), csha)}
    script = SETTLE_SCRIPTS.get(sd.get("schema"))
    inp = row.get("settle_inputs") or {}
    if not script or not inp.get("event_url") or not inp.get("view_url"):
        return {**res, "why": "no settle_inputs in the registry row, or a settlement schema this count does not recompute"}
    tdir = tempfile.mkdtemp()
    try:
        paths = {}
        for k, u in (("c", None), ("e", inp["event_url"]), ("v", inp["view_url"])):
            b = contract_bytes if u is None else get(u)[1]
            paths[k] = os.path.join(tdir, k + ".json"); open(paths[k], "wb").write(b)
        outp = os.path.join(tdir, "s.json")
        rr = subprocess.run([sys.executable, os.path.join(MUSUBI, script), "--settle", paths["c"], "--event", paths["e"],
                             "--view", paths["v"], "--out", outp], capture_output=True, timeout=300)
        if not os.path.exists(outp):
            return {**res, "why": "%s wrote nothing (exit %d)" % (script, rr.returncode)}
        same = open(outp, "rb").read() == sb
        res.update({"recomputed_identical": same, "recomputed_with": "workers/hs-ledger/nenrin/musubi-v0/" + script})
        if not same:
            res["why"] = "recomputed bytes differ from the published settlement"
        return res
    except Exception as e:
        return {**res, "why": "recompute failed: %s" % e}
    finally:
        shutil.rmtree(tdir, ignore_errors=True)


def contracts(our, published=(), published_problems=()):
    out, repo_refused, repo_skipped = [], [], 0
    skip = tuple(os.path.join(MUSUBI, d) + os.sep for d in NOT_CONTRACT_RECORDS)
    for p in tracked(MUSUBI, True):
        if p.startswith(skip):
            repo_skipped += 1
            continue
        try:
            d = json.load(io.open(p, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(d, dict) or not isinstance(d.get("parties"), list) or "contract_id" not in d:
            continue
        sigs = d.get("signatures") if isinstance(d.get("signatures"), (list, dict)) else None
        if not sigs or len(sigs) < 2:
            continue   # only contracts both sides signed
        # Two signature fields are not two signatures: every contract in the repository goes through the same
        # verify_contract as the ones the parties publish (red team 2026-10-09: a file with two forged fields counted).
        try:
            sys.path.insert(0, MUSUBI)
            import contract_v0 as _v0
            if _v0.verify_contract(d).get("verdict") != "accepted":
                repo_refused.append({"file": os.path.relpath(p, ROOT), "why": "verify_contract did not accept it"})
                continue
        except SystemExit as e:
            repo_refused.append({"file": os.path.relpath(p, ROOT), "why": "signatures not checked here: %s" % e}); continue
        except Exception as e:
            repo_refused.append({"file": os.path.relpath(p, ROOT), "why": "contract_v0 not importable: %s" % e}); continue
        domains = [str(x.get("domain") or "").lower() for x in d["parties"] if isinstance(x, dict)]
        if any(reserved_name(x) for x in domains):
            repo_refused.append({"file": os.path.relpath(p, ROOT), "why": "a party has a reserved test name"}); continue
        cid = d["contract_id"]
        if any(o["contract_id"] == cid for o in out):
            continue
        out.append({"contract_id": cid, "file": os.path.relpath(p, ROOT), "parties": domains,
                    "outside_parties": [x for x in domains if x and not ours(x, our)]})
    for c in published:
        if not any(o["contract_id"] == c["contract_id"] for o in out):
            out.append(c)
    with_outside = [c for c in out if c["outside_parties"]]
    without_us = [c for c in out if c["parties"] and not any(ours(x, our) for x in c["parties"])]
    settled = [c for c in with_outside if (c.get("settlement") or {}).get("recomputed_identical") and c["settlement"].get("status") == "final"]
    return {"signed_by_both": len(out), "with_an_outside_party": len(with_outside), "with_no_party_from_us": len(without_us),
            "settled_final_recomputed": len(settled),
            "items": out, "published_not_counted": list(published_problems), "repo_not_counted": repo_refused,
            "repo_test_material_skipped": {"dirs": ["workers/hs-ledger/nenrin/musubi-v0/" + d for d in NOT_CONTRACT_RECORDS], "json_files": repo_skipped}}


def agreements(our):
    out = []
    for p in tracked(AGREEMENT, False):
        try:
            d = json.load(io.open(p, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(d, dict) or not str(d.get("schema", "")).startswith("a2a-agreement-v1"):
            continue
        sigs = d.get("signatures") or []
        if len(sigs) < 2:
            continue
        parties = [str((x or {}).get("domain") or "").lower() for x in d.get("parties") or []]
        out.append({"file": os.path.relpath(p, ROOT), "parties": parties,
                    "outside_parties": [x for x in parties if x and not ours(x, our)]})
    return out


def ci_reproductions():
    since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    cands = get_json("https://api.github.com/search/repositories?q=conduct-witness+in:name&per_page=100")
    repos = []
    for r in cands.get("items", []):
        full = r["full_name"]
        if full.split("/")[0].lower() == OWNER:
            continue
        meta = get_json("https://api.github.com/repos/" + full)
        tpl = (meta.get("template_repository") or {}).get("full_name")
        if tpl != TEMPLATE:
            continue
        runs = get_json("https://api.github.com/repos/%s/actions/workflows/reproduce.yml/runs?status=success&created=%%3E%%3D%s&per_page=1" % (full, since))
        last = (runs.get("workflow_runs") or [{}])[0].get("created_at")
        repos.append({"repo": full, "created_from_template": True, "reproduce_success_last_30_days": bool(last), "last_success": last})
    return {"count": sum(r["reproduce_success_last_30_days"] for r in repos), "from_template": len(repos), "repos": repos,
            "method": "GitHub search for repositories named like conduct-witness, kept when template_repository is " + TEMPLATE
                      + " and reproduce.yml has a successful run in the last 30 days"}


def measure():
    reg = json.load(io.open(REG, encoding="utf-8"))
    our = [o.lower() for o in reg["our_identities"]]
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    m, not_measured = {}, []

    m["independent_implementations"] = implementations(reg)

    try:
        w = ledger_witnesses(our, [x.lower() for x in reg.get("our_names", [])])
    except Exception as e:
        w = None
        not_measured.append({"metric": "independent_witnesses", "reason": "ledger not readable: %s" % e})
    pool = json.load(io.open(POOL, encoding="utf-8")) if os.path.exists(POOL) else {}
    diversity = json.load(io.open(DIVERSITY, encoding="utf-8")) if os.path.exists(DIVERSITY) else {}
    m["independent_witnesses"] = {
        "count": None if w is None else len(w["signed_domains"]),
        "ledger": w,
        "reverification_pool": {"admitted": pool.get("admitted", []), "file": os.path.relpath(POOL, ROOT),
                                "generated_at": pool.get("generated_at"), "quorum_of_independent_controls_needed": 2,
                                "control_clusters": diversity.get("control_clusters"), "diversity_file": os.path.relpath(DIVERSITY, ROOT)},
    }

    try:
        if w is None:
            raise RuntimeError("the ledger was not readable")
        m["outside_trace_pins"] = trace_pins(w.get("trace_pins_anchored"), set(reg.get("our_trace_key_thumbprints", [])))
    except Exception as e:
        m["outside_trace_pins"] = {"count": None}
        not_measured.append({"metric": "outside_trace_pins", "reason": "not readable: %s" % e})

    pub, pub_problems = published_contracts(reg, our)
    c = contracts(our, pub, pub_problems)
    m["external_contracts"] = {"count": c["with_an_outside_party"], **c}

    ag = agreements(our)
    producers = {}
    for d, entries in ((w or {}).get("signed_domains") or {}).items():
        producers.setdefault(d, set()).add("ledger witness walk")
    for it in c["items"]:
        for d in it["outside_parties"]:
            producers.setdefault(d, set()).add("MUSUBI contract")
    for it in ag:
        for d in it["outside_parties"]:
            producers.setdefault(d, set()).add("agreement record")
    m["external_evidence_producers"] = {
        "count": len(producers) if w is not None else None,
        "identities": [{"id": k, "via": sorted(v)} for k, v in sorted(producers.items())],
        "agreements_signed_by_both": ag,
    }
    if w is None:
        not_measured.append({"metric": "external_evidence_producers", "reason": "depends on the ledger, which was not readable"})

    try:
        m["third_party_ci_reproductions"] = ci_reproductions()
    except Exception as e:
        m["third_party_ci_reproductions"] = {"count": None}
        not_measured.append({"metric": "third_party_ci_reproductions", "reason": "GitHub API not readable: %s" % e})

    return {"schema": "hs-adoption-count-v1", "measured_at": now, "metrics": m, "not_measured": not_measured,
            "how_to_recompute": "python3 tools/adoption/count_adoption.py",
            "does_not_establish": ["a count is not a score or an endorsement",
                                   "an implementation that reproduced bytes did not thereby adopt or approve anything",
                                   "absent from these sources is not absent from the world"]}


def fmt(v):
    return "not measured" if v is None else str(v)


def readme_block(d):
    m = d["metrics"]
    imp, wit, con, pro, ci = (m["independent_implementations"], m["independent_witnesses"], m["external_contracts"],
                              m["external_evidence_producers"], m["third_party_ci_reproductions"])
    wl = wit.get("ledger") or {}
    doms = ", ".join("`%s`" % k for k in (wl.get("signed_domains") or {})) or "none"
    pool = wit["reverification_pool"]
    lines = [
        START,
        "Counted every week by [`tools/adoption/count_adoption.py`](tools/adoption/count_adoption.py), last on %s. "
        "Every number comes from a source you can read; one that could not be read says so instead of counting zero. "
        "The whole count: [`ops/adoption/latest.json`](ops/adoption/latest.json)." % d["measured_at"][:10],
        "",
        "| What | Count | From |",
        "|---|---|---|",
        "| Independent implementations that reproduced our bytes or verdicts | %s rows by %s authors (%s) | [`tools/adoption/registry.json`](tools/adoption/registry.json), each row with its public link |"
        % (imp["count"], imp["distinct_authors"], ", ".join("%s %d" % kv for kv in imp["by_subject"].items())),
        ("| Reproductions of our code and integrations of our vectors or records, counted apart from the row above | %s | [`tools/adoption/registry.json`](tools/adoption/registry.json), rows with kind `reproduction` or `integration` |"
         % ", ".join("%s %d row%s by %d author%s" % (k, v["count"], "" if v["count"] == 1 else "s", v["distinct_authors"], "" if v["distinct_authors"] == 1 else "s")
                     for k, v in imp["other_kinds"].items())) if imp.get("other_kinds") else None,
        "| Outside domains that signed a walk and filed it to the ledger | %s | every `nenrin-witness-batch-v1` entry on the ledger |"
        % (fmt(wit["count"]) if wit["count"] is None else "%d (%s)" % (wit["count"], doms)),
        ("| Re-verification pool | %d member(s) in %s control cluster(s), %d clusters needed for a quorum | `%s`, clusters from `%s` |" % (len(pool["admitted"]), pool["control_clusters"], pool["quorum_of_independent_controls_needed"], pool["file"], pool.get("diversity_file", ""))
         if pool.get("control_clusters") is not None else
         "| Re-verification pool | %d member(s), %d independent control clusters needed for a quorum | `%s` |" % (len(pool["admitted"]), pool["quorum_of_independent_controls_needed"], pool["file"])),
        "| MUSUBI contracts signed with an outside party | %d (with no party from this project: %d) | the signed contracts in `workers/hs-ledger/nenrin/musubi-v0/`, and contracts the parties publish themselves, listed in `registry.json` and signature-checked |" % (con["with_an_outside_party"], con["with_no_party_from_us"]),
        "| ...of which settled final, the parties' settlement recomputed here byte for byte | %d | the settle verifier of the version each settlement names, run on the parties' own contract, event and header view |" % con.get("settled_final_recomputed", 0),
        "| Outside identities that signed evidence (walk, contract or agreement) | %s | the three rows above and the agreement records |" % fmt(pro["count"]),
        "| Outside TRACE signing keys whose records were pinned with trace-pin-v0 | %s | every `nenrin-trace-pin-batch-v0` entry on the ledger and the pending pool |" % fmt((m.get("outside_trace_pins") or {}).get("count")),
        "| Public repositories created from conduct-witness-template whose reproduce run succeeded in the last 30 days | %s | GitHub API |" % fmt(ci.get("count")),
        "",
        "Open: %s" % "; ".join(imp["open_calls"].values()) if imp.get("open_calls") else "",
        END,
    ]
    return "\n".join(l for l in lines if l is not None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.check:
        d = json.load(io.open(os.path.join(OUT_DIR, "latest.json"), encoding="utf-8"))
        s = io.open(README, encoding="utf-8").read()
        have = s[s.index(START):s.index(END) + len(END)] if START in s and END in s else ""
        if have != readme_block(d):
            print("README adoption block differs from ops/adoption/latest.json; run --write")
            return 1
        print("README adoption block matches ops/adoption/latest.json")
        return 0
    d = measure()
    text = json.dumps(d, ensure_ascii=False, indent=2) + "\n"
    print(readme_block(d))
    if d["not_measured"]:
        print("\nnot measured: " + "; ".join("%s (%s)" % (x["metric"], x["reason"]) for x in d["not_measured"]))
    if a.write:
        os.makedirs(OUT_DIR, exist_ok=True)
        io.open(os.path.join(OUT_DIR, "adoption_%s.json" % d["measured_at"][:10]), "w", encoding="utf-8").write(text)
        io.open(os.path.join(OUT_DIR, "latest.json"), "w", encoding="utf-8").write(text)
        s = io.open(README, encoding="utf-8").read()
        block = readme_block(d)
        if START in s and END in s:
            s = s[:s.index(START)] + block + s[s.index(END) + len(END):]
        else:
            anchor = "\nOne external witness is a start, not a network."
            if anchor not in s:
                raise SystemExit("README anchor not found; place the markers by hand")
            s = s.replace(anchor, "\n" + block + "\n" + anchor, 1)
        io.open(README, "w", encoding="utf-8").write(s)
        print("\nwrote ops/adoption/latest.json and the README block")
    return 0


if __name__ == "__main__":
    sys.exit(main())
