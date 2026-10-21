"""nenrin-track: whether a door's signed admissions, in a nenrin mirror you hold, form one history.

The repository's track-v0/track.py, installed byte for byte (VENDORED.json pins it), with its vectors:

    nenrin-track --dir ./nenrin-mirror --pin <base64 Ed25519 key>@<key_url>    exit 0 no finding, 1 a finding, 2 input error
    nenrin-track --dir ./nenrin-mirror --pin ... --json                       the report as canonical JSON
    nenrin-track --selftest                                                   every vector's report, byte for byte

Make the mirror with workers/hs-ledger/nenrin/mirror-v0/mirror.py (or its GitHub Action). Pin keys you obtained yourself;
nothing is fetched. The Go port, nenrin-track-go, prints the same report.
"""
import importlib.util
import json
import os
import sys

TRACK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_repo", "track-v0")


def load():
    spec = importlib.util.spec_from_file_location("nenrin_track_v0", os.path.join(TRACK_DIR, "track.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def selftest():
    T = load()
    root = os.path.join(TRACK_DIR, "vectors")
    names = sorted(x for x in os.listdir(root) if os.path.isdir(os.path.join(root, x)))
    bad = 0
    for n in names:
        d = os.path.join(root, n)
        pins = T.parse_pins(["%s@%s" % (v, k) for k, v in sorted(json.load(open(os.path.join(d, "pins.json"))).items())])
        got = T.canonical(T.track(d, pins))
        want = open(os.path.join(d, "expected.json"), encoding="utf-8").read().rstrip("\n")
        ok = got == want
        bad += not ok
        print("%s %s" % ("ok  " if ok else "FAIL", n))
    print("=== %d / %d (nenrin-track-v0) ===" % (len(names) - bad, len(names)))
    return 1 if bad else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--selftest"]:
        return selftest()
    return load().main(argv)


if __name__ == "__main__":
    sys.exit(main())
