#!/bin/sh
# make_seed_nenrin_spec_correction_20261013.sh: JIDEC の seed を組む。entry 19(NENRIN v1 仕様書)の 1 文
# 「one MCP server appeared in 93,983 search results and was invoked zero times」を狭める訂正記録。
# entry 19 は編集しない。この記録を積んで entry 19 を引用する。両方が読める。
# 何も送らない。seed の JSON を書くだけ。append は append_witness.sh (token は隠し入力)。
# 事実はその場で照合する: entry 19 の claim sha は手元の claim_19.txt から再計算、出典の文は verify-directory から読む。
set -eu
cd "${HS_REPO:-$HOME/horizon-shield}/workers/hs-ledger"
OUT="seed_entry_nenrin_spec_correction_20261013.json"

OUT="$OUT" python3 - <<'PY'
import hashlib, io, os, json, sys
out = os.environ["OUT"]
def sha(b): return hashlib.sha256(b).hexdigest()
c19 = io.open("../../claim_19.txt", "rb").read()
s19 = sha(c19)
if s19 != "9ccba2e325fd2a555fcdb2dec519b8c6bf7a669064674846aea98ecfff824e3d":
    print("claim_19.txt does not hash to entry 19's claim; stop"); sys.exit(1)
phrase = b"one MCP server appeared in 93,983 search results and was invoked zero times"
if phrase not in c19:
    print("the sentence is not in claim_19.txt as expected; stop"); sys.exit(1)
vd = io.open("../../verify-directory/index.html", "rb").read()
src = b"Our own listing on another MCP directory produced 93,983 impressions, 24 clicks, 421 profile views and zero tool calls"
if src not in vd or b"in the thirty days to 2026-08-14" not in vd:
    print("the source paragraph is not in verify-directory/index.html as expected; stop"); sys.exit(1)
lines = []
lines.append("schema: nenrin-spec-v1-correction")
lines.append("date: 2026-10-13")
lines.append("corrects: JIDEC entry 19, claim sha256 %s, NENRIN v1 specification, Bitcoin block 962507" % s19)
lines.append("method: the corrected entry is not edited; this record is appended and cites it, and both stay readable")
lines.append("phrase: \"In one measured thirty-day window, one MCP server appeared in 93,983 search results and was invoked zero times.\" (Section 1 of entry 19)")
lines.append("corrected_1: 93,983 is the impression count shown by the dashboard of one MCP directory on which the operator's own server is listed, for the thirty days to 2026-08-14 (93,983 impressions, 24 clicks, 421 profile views); it is not a count of search results across search engines or AI assistants")
lines.append("corrected_2: zero is the number of tool calls made through that one directory listing in the same window; it is not the server's total. The server's own usage counter recorded calls in that window; it stores no IP addresses and cannot separate the operator's automated checks from outside calls, so how many calls came from outside is not known")
lines.append("source: the Traffic paragraph of verify-directory/index.html in github.com/ogasurfproject-jpg/horizon-shield, which states the dashboard figures with their date")
lines.append("also_corrected: README.md of the same repository, which had called the 93,983 AI search results; corrected in the commit that adds this seed")
lines.append("not_yet_corrected: papers/nenrin-reproducibility/manuscript_v0.1.md repeats the sentence; it has two authors and is corrected only when both approve")
lines.append("what_stays: the argument of Section 1 (an agent choosing between servers can read only what each vendor wrote about itself) and every other section of entry 19; this record changes no hash")
lines.append("limits: this record narrows one sentence of entry 19; claim_19.txt and NENRIN_SPEC_v1.md are the anchored bytes and stay unchanged")
rec = "\n".join(lines) + "\n"
seed = {"claim_sha256": sha(rec.encode("utf-8")), "record_canonical": rec,
        "work": "NENRIN v1 specification: correction narrowing the 93,983 / zero sentence of entry 19, 2026-10-13"}
io.open(out, "w", encoding="utf-8").write(json.dumps(seed, ensure_ascii=False))
print(rec)
print("claim_sha256:", seed["claim_sha256"])
print("wrote", out, len(json.dumps(seed, ensure_ascii=False).encode("utf-8")), "bytes")
bad = [ch for ch in rec if ord(ch) in (0x2014, 0x2013, 0x2015, 0x2500, 0x2501, 0xFF0D)]
print("forbidden dashes in record:", len(bad))
PY
