# 公開の 5 つのデータを、攻め (attack) と普通 (benign) に分け、sha256(dataset|text) の偶奇で BUILD と MEASURE に分ける。
# 数と sha だけを出す。本文は出さない。
import csv, glob, hashlib, json, os, sys, collections
import pyarrow.parquet as pq
csv.field_size_limit(10**9)
RAW = "/private/tmp/claude-501/pubdata/raw"; OUT = "/private/tmp/claude-501/pubdata/split"
os.makedirs(OUT, exist_ok=True)
def pqrows(pat, col):
    for f in sorted(glob.glob(os.path.join(RAW, pat))):
        t = pq.read_table(f)
        yield from ((f, r) for r in t.to_pylist())
def gen():
    for f, r in pqrows("deepset__prompt-injections/data/*.parquet", "text"):
        yield "deepset/prompt-injections", r["text"], {1: "attack", 0: "benign"}[r["label"]]
    for f, r in pqrows("Lakera__gandalf_ignore_instructions/data/*.parquet", "text"):
        yield "Lakera/gandalf_ignore_instructions", r["text"], "attack"
    for f, r in pqrows("Lakera__mosscap_prompt_injection/data/*.parquet", "prompt"):
        yield "Lakera/mosscap_prompt_injection", r["prompt"], "attack"
    for r in csv.DictReader(open(os.path.join(RAW, "reshabhs__SPML_Chatbot_Prompt_Injection/spml_prompt_injection.csv"), newline="", encoding="utf-8")):
        yield "reshabhs/SPML_Chatbot_Prompt_Injection", r["User Prompt"], {"1": "attack", "0": "benign"}[r["Prompt injection"]]
    for r in csv.DictReader(open(os.path.join(RAW, "jackhhao__jailbreak-classification/default/jailbreak_dataset_full.csv"), newline="", encoding="utf-8")):
        yield "jackhhao/jailbreak-classification", r["prompt"], {"jailbreak": "attack", "benign": "benign"}[r["type"]]
items = collections.OrderedDict(); stats = collections.Counter()
for ds, text, lab in gen():
    stats[(ds, "rows")] += 1
    if text is None or not str(text).strip(): stats[(ds, "empty")] += 1; continue
    key = hashlib.sha256((ds + "|" + text).encode("utf-8")).hexdigest()
    if key in items:
        if items[key]["label"] != lab: items[key]["conflict"] = True
        stats[(ds, "dup")] += 1; continue
    items[key] = {"ds": ds, "key": key, "label": lab, "text": text}
fh = {}
summary = collections.OrderedDict()
for it in items.values():
    ds = it["ds"]
    if it.pop("conflict", False): stats[(ds, "label_conflict_dropped")] += 1; continue
    half = "build" if int(it["key"][:2], 16) % 2 == 0 else "measure"
    name = ds.replace("/", "__") + "." + half + ".jsonl"
    if name not in fh: fh[name] = open(os.path.join(OUT, name), "w", encoding="utf-8")
    fh[name].write(json.dumps(it, ensure_ascii=False, sort_keys=True) + "\n")
    stats[(ds, half, it["label"])] += 1
for f in fh.values(): f.close()
res = {"stats": {"|".join(k): v for k, v in sorted(stats.items())}, "files": {}}
for n in sorted(os.listdir(OUT)):
    res["files"][n] = hashlib.sha256(open(os.path.join(OUT, n), "rb").read()).hexdigest()
print(json.dumps(res, indent=1))
