package nenrinverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every vector in ../../track-v0/vectors: the report Go writes is the report track.py wrote, byte for byte.
func TestTrackVectors(t *testing.T) {
	root := filepath.Join("..", "..", "track-v0", "vectors")
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		d := filepath.Join(root, e.Name())
		pv, err := ParseJSON(mustRead(t, filepath.Join(d, "pins.json")))
		if err != nil {
			t.Fatal(err)
		}
		pins := map[string][]byte{}
		po := pv.(*Object)
		for _, k := range po.Keys() {
			dom, raw, err := TrackPin(Get(po, k).(string) + "@" + k)
			if err != nil {
				t.Fatal(err)
			}
			pins[dom] = raw
		}
		rep, err := Track(d, pins, TrackLateBlocks)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		got, err := Canonical(rep.Value)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.TrimRight(string(mustRead(t, filepath.Join(d, "expected.json"))), "\n")
		if got != want {
			t.Errorf("%s:\n got  %s\n want %s", e.Name(), got, want)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("only %d vectors", n)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
