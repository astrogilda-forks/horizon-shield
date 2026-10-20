"""The JavaScript the TSUGI port leans on, against Node itself: `new URL(s).host`, toLowerCase, Buffer.from on any
JSON value, and string conversion of any JSON value. Skipped without Node.

For URLs and lowercasing the port raises NotReproduced instead of guessing on the inputs it does not cover; the
test checks those raises happen only where the port says they will (file URLs, IPv6, hosts that need UTS #46, code
points this Python does not assign), and that every other input gives Node's answer."""
import json
import random
import shutil
import subprocess
import unicodedata

import pytest

from nenrin_verify import _js
from nenrin_verify._url import URLFailure, url_host

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="needs node")

NODE = r"""
const inp = JSON.parse(require("fs").readFileSync(0, "utf8"));
const res = (f) => { try { return { v: f() }; } catch (e) { return { e: String(e && e.message || e) }; } };
const out = {
  url: inp.url.map((s) => res(() => new URL(s).host)),
  lower: inp.lower.map((s) => s.toLowerCase()),
  buf: inp.buf.map((v) => res(() => Buffer.from(v, "base64").toString("hex"))),
  str: inp.str.map((v) => res(() => "" + v)),
  node: process.versions.node,
};
process.stdout.write(JSON.stringify(out));
"""

SCHEMES = ["https", "HTTPS", "http", "ws", "wss", "ftp", "foo", "a+b.c-d", "1x", "", "h ttps", "file", "mailto"]
SEPS = ["://", ":", ":/", ":///", ":\\\\", "://\\", ":/\\/", ": //", ":\t//"]
USERS = ["", "u@", "u:p@", "@", "a@b@", "u:p%40@", "%@"]
HOSTS = ["example.com", "EXAMPLE.Com", "a..b", ".", "..", "a.", "127.0.0.1", "0x7f.1", "0x7F.0.0.01", "1.2.3.4.5",
         "256.1", "1.256", "4294967295", "4294967296", "08", "0x", "example.0x", "example.123", "example.123.",
         "ex%41mple.com", "%zz", "%", "%2e", "ex ample", "a_b", "a*b", "a{b}", "a`b", "a~b", "a!b", "a$b", "a&b",
         "a'b", "a(b)", "a+b", "a,b", "a;b", "a=b", 'a"b', "a<b", "a^b", "a|b", "a\x7fb", "a\x01b", "ex\tam\nple",
         "café.example", "xn--caf-dma.example", "XN--abc", "[::1]", "", "0", "0.0.0.0", "999999999999", "1e2",
         "0x100000000", "01.02.03.04", "0xffffffff", "gate.horizonshield.dev", "witness-a.example", "a%2Fb",
         "é", "a%C3%A9", "a%FF", "%41", "ex\\ample"]
PORTS = ["", ":", ":0", ":443", ":0443", ":80", ":21", ":65535", ":65536", ":x", ":8a", "::80", ":99999999999999999999"]
TAILS = ["", "/", "/p?q#f", "?q", "#f", "\\x", "/@x", "?@x"]
EDGES = [" ", "\x00", "\x1f", "\t", "\n"]


def _urls(rnd):
    out = ["https://example.com", "https:example.com", "https:/x", "https:", "foo://", "foo:///x", "foo:x", "x",
           "", " https://a ", "\x00https://a\x1f", "https://\ud800.example", "foo://\ud800", "foo://a\\b",
           "https://a:b@", "https://@x", "foo://:80", "foo://a:80", "HTTP://A:80/", "wss://h:443", "ftp://h:21",
           "https://gate.horizonshield.dev/keys/witness.json", "https://witness-a.example/.well-known/hs-witness-key.json"]
    for _ in range(6000):
        s = rnd.choice(SCHEMES) + rnd.choice(SEPS) + rnd.choice(USERS) + rnd.choice(HOSTS) + rnd.choice(PORTS) + rnd.choice(TAILS)
        if rnd.random() < 0.1:
            s = rnd.choice(EDGES) + s + rnd.choice(EDGES)
        out.append(s)
    return out


def _lowers(rnd):
    pal = ("AZaz09 ΣσςΑΒ.'·İIıẞßǅǄͅΙKΩ"
           "ႠᲐᎠꭰ\U00010400\U00010c80\U0001e900̀ᲉꟋ\U00016e40\U0001e030"
           "𐀀ⅠⒶＡևﬀ")
    out = ["ΑΣ", "ΑΣ ", "ΑΣΑ", "Σ", "Α.Σ", "ᾼΣ",
           "İ", "İ", "ABC", "gate.HORIZONSHIELD.dev"]
    for _ in range(4000):
        out.append("".join(rnd.choice(pal) for _ in range(rnd.randint(1, 8))))
    return out


def _bufs(rnd):
    leaf = ["QUJD", "", "AAAA", "a-_b", "==", "x", True, False, None, "12", "300", "-1", "1e3", " 12 ", "0x1f", "a"]
    def val(d):
        r = rnd.random()
        if d > 2 or r < 0.4:
            return rnd.choice(leaf)
        if r < 0.65:
            return [val(d + 1) for _ in range(rnd.randint(0, 4))]
        keys = ["valueOf", "length", "type", "data", "constructor", "toString", "name", "x", "__proto__"]
        o = {}
        for k in rnd.sample(keys, rnd.randint(0, 3)):
            o[k] = "Buffer" if k == "type" and rnd.random() < 0.6 else val(d + 1)
        return o
    out = [{}, {"type": "Buffer", "data": ["1", "2"]}, {"length": None}, {"valueOf": ""}, {"valueOf": "QUJD"},
           {"constructor": "x"}, {"constructor": {"name": "Foo"}}, {"constructor": None}, {"constructor": True},
           {"constructor": "<Object>"}, {"constructor": ""}, {"constructor": {"name": ""}}, {"constructor": {"name": 5}},
           {"constructor": {"name": {}}}, {"constructor": {}}, {"constructor": []},
           [{"toString": "x"}], ["1", ["2", "3"]], True]
    out += [val(0) for _ in range(3000)]
    return [v for v in out if v is not False and v is not None]


def _expected_unreproduced_url(s, err):
    low = s.lower()
    return ("file" in low or "[" in s or "xn--" in low or any(ord(c) > 0x7F for c in s) or "%" in s)


def test_tsugi_semantics_against_node():
    rnd = random.Random(20261001)
    payload = {"url": _urls(rnd), "lower": _lowers(rnd), "buf": _bufs(rnd), "str": _bufs(rnd)}
    text = json.dumps(payload, ensure_ascii=True)
    p = subprocess.run(["node", "-e", NODE], input=text, capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    js = json.loads(p.stdout)
    back = json.loads(text)

    bad, unrep = [], 0
    for s, j in zip(back["url"], js["url"]):
        try:
            got = {"v": url_host(s)}
        except URLFailure:
            got = {"e": "Invalid URL"}
        except _js.NotReproduced as e:
            unrep += 1
            if not _expected_unreproduced_url(s, e):
                bad.append(("url unreproduced", s, str(e)))
            continue
        want = {"e": "Invalid URL"} if "e" in j else j
        if got != want:
            bad.append(("url", s, got, j))
    print("\nurl: %d inputs, %d not reproduced by design" % (len(back["url"]), unrep))

    lunrep = 0
    for s, j in zip(back["lower"], js["lower"]):
        try:
            got = _js.lower(s)
        except _js.NotReproduced:
            lunrep += 1
            if not any(unicodedata.category(c) == "Cn" for c in s):
                bad.append(("lower unreproduced", s))
            continue
        if got != j:
            bad.append(("lower", s, got, j))
    print("lower: %d inputs, %d hold a code point this Python does not assign" % (len(back["lower"]), lunrep))

    legacy = not _js.node_has_new_specific_type(js["node"])
    print("buf: Node %s, %s determineSpecificType" % (js["node"], "the pre-24.22.0" if legacy else "the 24.22.0"))
    for v, j in zip(back["buf"], js["buf"]):
        try:
            got = {"v": _js.buffer_from(v, legacy=legacy).hex()}
        except _js.JSTypeError as e:
            got = {"e": str(e)}
        if got != j:
            bad.append(("buf", v, got, j))
    for v, j in zip(back["str"], js["str"]):
        try:
            got = {"v": _js.to_string(v)}
        except _js.JSTypeError as e:
            got = {"e": str(e)}
        if got != j:
            bad.append(("str", v, got, j))
    for b in bad[:30]:
        print("  ", b)
    assert not bad
