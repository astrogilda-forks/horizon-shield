# フルイ blind-02 のくじ。本文は画面にも log にも出さない(出すのは件数、sha、root だけ)。
# usage:
#   python3 -I draw_blind02.py salt <out_salt.hex>       32 バイトの塩を書く。出すのは sha256(塩) だけ
#   python3 -I draw_blind02.py commit <salt.hex>         sha256(塩) を出す
#   python3 -I draw_blind02.py check <split_dir>          母集団の 4 つの file の sha を固定と照らす(中は出さない)
#   python3 -I draw_blind02.py draw <salt.hex> <block_hash> <split_dir> <vol_dir> <rest_dir> <summary.json>
#   python3 -I draw_blind02.py verify <salt.hex> <block_hash> <full_measure_dir> <manifest.json> <blind02.jsonl>
import hashlib, json, os, secrets, sys

SCHEMA = "furui-blind02-draw-v0"
# 母集団: 0.2.7 の試しの MEASURE の半分(SPLIT.md の表の sha)。mosscap は使わない(TOshi、10/24)。
FILES = {
    "deepset/prompt-injections": ("deepset__prompt-injections.measure.jsonl", "16aea9bc6964913ce4a87b3f2f1949abd2861f36484ff3de2f6f0ab7cbc4114a"),
    "Lakera/gandalf_ignore_instructions": ("Lakera__gandalf_ignore_instructions.measure.jsonl", "c2db4e2f8fe963516bcf8f50812b2adc02f95b27ae37ae24bc20567dbe71a9ab"),
    "reshabhs/SPML_Chatbot_Prompt_Injection": ("reshabhs__SPML_Chatbot_Prompt_Injection.measure.jsonl", "fd53b56a0ce0a11196e16625b281e2005e7dd95e44591866d69676bdade458a2"),
    "jackhhao/jailbreak-classification": ("jackhhao__jailbreak-classification.measure.jsonl", "10d3f1b062f32231c62f72669ae0c45098b1f76a56d4317ad83517d1b934c680"),
}
# 層と引く数(計 2,030、TOshi、10/24)
STRATA = [
    ("deepset/prompt-injections", "attack", 40),
    ("deepset/prompt-injections", "benign", 60),
    ("Lakera/gandalf_ignore_instructions", "attack", 140),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", "attack", 1000),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", "benign", 500),
    ("jackhhao/jailbreak-classification", "attack", 100),
    ("jackhhao/jailbreak-classification", "benign", 190),
]
HEX64 = set("0123456789abcdef")

def die(m): sys.exit("止めた: " + m)
def h(b): return hashlib.sha256(b).hexdigest()
def hex64(s, what):
    if len(s) != 64 or not set(s) <= HEX64: die(what + " が 64 字の小文字の hex でない")
    return s
def read_salt(p):
    s = open(p, encoding="ascii").read()
    if s.endswith("\n"): s = s[:-1]
    return hex64(s, "塩")
def salt_commit(salt): return h(bytes.fromhex(salt))
def seed_of(salt, bh): return h(("furui-blind-02|" + salt + "|" + bh).encode("ascii"))
def order_key(seed, key): return h((seed + "|" + key).encode("ascii"))

def load(split_dir, files):
    """各データの行(元のバイトのまま)を読み、sha を照らす。返すのは {ds: [(key, label, line_bytes)]}"""
    out = {}
    for ds, (name, want) in files.items():
        raw = open(os.path.join(split_dir, name), "rb").read()
        if h(raw) != want: die(name + " の sha が固定と違う")
        rows, seen = [], set()
        for line in raw.split(b"\n"):
            if not line: continue
            r = json.loads(line)
            if r.get("ds") != ds: die(name + " に別のデータの行がある")
            k = hex64(r.get("key", ""), name + " の key")
            if k in seen: die(name + " に同じ key が 2 つある")
            seen.add(k); rows.append((k, r.get("label"), line))
        out[ds] = rows
    return out

def select(data, seed, strata):
    """層ごとに order_key の小さい順に決めた数を取る。返すのは {"ds|label": [key...]}(key の昇順)"""
    sel = {}
    for ds, lab, k in strata:
        cand = [key for key, l, _ in data[ds] if l == lab]
        if len(cand) < k: die("%s の %s は %d 件で、%d 件を引けない" % (ds, lab, len(cand), k))
        sel[ds + "|" + lab] = sorted(sorted(cand, key=lambda x: order_key(seed, x))[:k])
    return sel

def root_of(lines): return h("\n".join(h(l) for l in lines).encode("ascii"))

def draw(salt, bh, split_dir, vol, rest_dir, summary_p, files=FILES, strata=STRATA):
    seed = seed_of(salt, bh)
    data = load(split_dir, files)
    sel = select(data, seed, strata)
    drawn = set(k for v in sel.values() for k in v)
    if len(drawn) != sum(k for _, _, k in strata): die("引いた key の数が合わない")
    picked = sorted(((k, line) for rows in data.values() for k, _, line in rows if k in drawn), key=lambda x: x[0])
    lines = [line for _, line in picked]
    os.makedirs(os.path.join(vol, "measure_full"), exist_ok=True)
    with open(os.path.join(vol, "blind02.jsonl"), "wb") as fh:
        for l in lines: fh.write(l + b"\n")
    for ds, (name, _) in files.items():
        with open(os.path.join(split_dir, name), "rb") as a, open(os.path.join(vol, "measure_full", name), "wb") as b: b.write(a.read())
    man = {"schema": SCHEMA, "block_hash": bh, "salt_sha256": salt_commit(salt), "seed": seed,
           "files": {ds: {"name": n, "sha256": s} for ds, (n, s) in files.items()},
           "strata": {k: {"n": len(v), "keys": v} for k, v in sel.items()}, "root": root_of(lines)}
    with open(os.path.join(vol, "manifest.json"), "w", encoding="utf-8") as fh: json.dump(man, fh, sort_keys=True, indent=1); fh.write("\n")
    os.makedirs(rest_dir, exist_ok=True)
    rest = {}
    for ds, (name, _) in files.items():
        keep = [line for k, _, line in data[ds] if k not in drawn]
        p = os.path.join(rest_dir, name)
        with open(p, "wb") as fh:
            for l in keep: fh.write(l + b"\n")
        rest[name] = {"rows": len(keep), "sha256": h(open(p, "rb").read())}
        if len(keep) + sum(1 for k, _, _ in data[ds] if k in drawn) != len(data[ds]): die(name + " の残りと引いた物の和が元と合わない")
    summ = {"schema": SCHEMA + "-summary", "block_hash": bh, "salt_sha256": salt_commit(salt), "root": man["root"],
            "manifest_sha256": h(open(os.path.join(vol, "manifest.json"), "rb").read()),
            "blind02_sha256": h(open(os.path.join(vol, "blind02.jsonl"), "rb").read()), "n": len(lines),
            "strata_n": {k: len(v) for k, v in sel.items()}, "measure_full": {n: s for n, s in files.values()}, "measure_rest": rest}
    with open(summary_p, "w", encoding="utf-8") as fh: json.dump(summ, fh, sort_keys=True, indent=1); fh.write("\n")
    for k, v in sorted(summ["strata_n"].items()): print("層 %s %d 件" % (k, v))
    print("計 %d 件、root %s" % (len(lines), man["root"]))
    return summ

def verify(salt, bh, full_dir, man_p, b02_p, files=FILES, strata=STRATA):
    man = json.load(open(man_p, encoding="utf-8"))
    if man["salt_sha256"] != salt_commit(salt) or man["block_hash"] != bh: die("塩かブロックの hash が manifest と違う")
    seed = seed_of(salt, bh)
    if man["seed"] != seed: die("seed が合わない")
    sel = select(load(full_dir, files), seed, strata)
    if {k: v["keys"] for k, v in man["strata"].items()} != sel: die("計算し直した選び方が manifest と違う")
    lines = [l for l in open(b02_p, "rb").read().split(b"\n") if l]
    if sorted(json.loads(l)["key"] for l in lines) != sorted(k for v in sel.values() for k in v): die("blind02.jsonl の key が選び方と違う")
    if root_of(lines) != man["root"]: die("root が合わない")
    print("選び方と root を計算し直して一致(%d 件、root %s)" % (len(lines), man["root"]))

def main(a):
    if len(a) == 2 and a[0] == "salt":
        if os.path.exists(a[1]): die(a[1] + " が既にある(塩を作り直さない)")
        s = secrets.token_bytes(32).hex()
        fd = os.open(a[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh: fh.write(s + "\n")
        print(salt_commit(read_salt(a[1])))
    elif len(a) == 2 and a[0] == "commit": print(salt_commit(read_salt(a[1])))
    elif len(a) == 2 and a[0] == "check":
        for ds, (name, want) in sorted(FILES.items()):
            if h(open(os.path.join(a[1], name), "rb").read()) != want: die(name + " の sha が固定と違う(もう引いた後か、作り直しで変わった)")
        print("母集団の %d つの file は固定と同じ" % len(FILES))
    elif len(a) == 7 and a[0] == "draw":
        if os.path.exists(os.path.join(a[4], "manifest.json")): die("ディスクイメージの中に manifest.json が既にある(引き直さない)")
        draw(read_salt(a[1]), hex64(a[2], "ブロックの hash"), a[3], a[4], a[5], a[6])
    elif len(a) == 6 and a[0] == "verify": verify(read_salt(a[1]), hex64(a[2], "ブロックの hash"), a[3], a[4], a[5])
    else: die("使い方は先頭の注を見る")

if __name__ == "__main__": main(sys.argv[1:])
