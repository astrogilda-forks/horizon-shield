package nenrinverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The frozen provenance corpora: every verdict signature must be reproduced.
func TestFrozenCorpora(t *testing.T) {
	for _, dir := range []string{"interop-v0", "interop-v0.1", "interop-v0.2/edge", "interop-v0.2/action-presence", "interop-v0.3/survivors"} {
		root := filepath.Join("..", "..", dir)
		b, err := os.ReadFile(filepath.Join(root, "expected.json"))
		if err != nil {
			t.Fatal(err)
		}
		var exp struct {
			Cases map[string]struct {
				Expect Signature `json:"expect"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(b, &exp); err != nil {
			t.Fatal(err)
		}
		for name, c := range exp.Cases {
			raw, err := os.ReadFile(filepath.Join(root, "fixtures", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			v, err := ParseJSON(raw)
			if err != nil {
				t.Fatalf("%s/%s: %v", dir, name, err)
			}
			rep, err := VerifyBundle(v)
			if err != nil {
				t.Fatalf("%s/%s: %v", dir, name, err)
			}
			want := c.Expect
			if want.Refusals == nil {
				want.Refusals = []string{}
			}
			if want.Findings == nil {
				want.Findings = []string{}
			}
			if got := rep.Signature(); !reflect.DeepEqual(got, want) {
				t.Errorf("%s/%s:\n want %+v\n got  %+v", dir, name, want, got)
			}
		}
	}
}

// Canonical form against the shared vectors (musubi-v0/canonical_vectors.json) where they carry input and output.
func TestCanonicalStrings(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":[true,null,-0,1.0]}`: `{"a":[true,null,0,1],"b":1}`,
		`"\ud800x\u0001\u2028é"`:         "\"\\ud800x\\u0001\u2028é\"",
		`"\ud83d\ude00"`:                 "\"\U0001F600\"",
		`{"a":1,"a":2}`:                  `{"a":2}`,
	}
	for in, want := range cases {
		v, err := ParseJSON([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Canonical(v)
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", in, got, err, want)
		}
	}
	for _, in := range []string{`1.5`, `9007199254740992`, `{"\u0001":1}`} {
		v, _ := ParseJSON([]byte(in))
		if _, err := Canonical(v); err == nil {
			t.Errorf("%s: expected a canonical refusal", in)
		}
	}
}

// The shared canonical vectors every implementation of musubi-canonical-v0 reproduces byte for byte.
func TestSharedCanonicalVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "musubi-v0", "canonical_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	vs := Get(doc.(*Object), "vectors").(*Array).Items
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	for _, it := range vs {
		o := it.(*Object)
		c, err := Canonical(Get(o, "value"))
		if err != nil {
			t.Fatalf("%v: %v", Get(o, "name"), err)
		}
		if sha256hex(c) != Get(o, "sha256") || float64(len(c)) != Get(o, "bytes") {
			t.Errorf("%v: sha256 %s, %d bytes", Get(o, "name"), sha256hex(c), len(c))
		}
	}
}
