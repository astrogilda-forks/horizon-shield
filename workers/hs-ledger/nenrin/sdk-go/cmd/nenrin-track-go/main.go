// nenrin-track-go follows a relying party's signed admissions in a nenrin mirror (mirror-v0) and says whether its
// history is one: forks, broken links, admissions anchored long after the height they name, gaps. Keys are pinned by
// you, never fetched. The Go port of track-v0/track.py; the report is the same canonical JSON, byte for byte.
//
//	nenrin-track-go --dir ./nenrin-mirror --pin <base64 Ed25519 key>@<key_url> [--pin ...] [--late-blocks 576] [--json]
//
// Exit 0 when no fork, broken link or late anchor is found (incomplete included), 1 when one is, 2 on an input error.
package main

import (
	"flag"
	"fmt"
	"os"

	nv "github.com/ogasurfproject-jpg/horizon-shield/workers/hs-ledger/nenrin/sdk-go/nenrinverify"
)

type pinList []string

func (p *pinList) String() string     { return fmt.Sprint(*p) }
func (p *pinList) Set(s string) error { *p = append(*p, s); return nil }

func main() {
	var pins pinList
	dir := flag.String("dir", "", "the mirror directory")
	late := flag.Int64("late-blocks", nv.TrackLateBlocks, "an admission anchored more blocks than this after its chain view is late")
	asJSON := flag.Bool("json", false, "print the report as canonical JSON")
	flag.Var(&pins, "pin", "<base64 of a 32 byte Ed25519 public key>@<key_url the admissions name>, repeatable")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: nenrin-track-go --dir <mirror> --pin <key>@<key_url> [--json]")
		os.Exit(2)
	}
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		fmt.Fprintln(os.Stderr, "no such directory:", *dir)
		os.Exit(2)
	}
	pm := map[string][]byte{}
	for _, p := range pins {
		d, k, err := nv.TrackPin(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		pm[d] = k
	}
	rep, err := nv.Track(*dir, pm, *late)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	c, _ := nv.Canonical(rep.Value)
	if *asJSON {
		fmt.Println(c)
	} else {
		fmt.Println("verdict:", rep.Verdict)
		fmt.Println("report_sha256", nv.Get(rep.Value, "report_sha256"))
	}
	if rep.Verdict == "findings" {
		os.Exit(1)
	}
}
