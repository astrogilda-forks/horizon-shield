package nenrinverify

// nenrin-track-v0 in Go: follow a relying party's signed admissions in a nenrin mirror and say whether its history is
// one. The reference is ../../track-v0/track.py; the report is the same canonical JSON, byte for byte, held by the
// vectors in ../../track-v0/vectors (TestTrackVectors).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	TrackSchema      = "nenrin-track-v0"
	TrackLateBlocks  = 576
	trackGenesis     = "0000000000000000000000000000000000000000000000000000000000000000"
	admissionContext = "a2a-admission-v0\n"
)

var (
	trackAdmissionID = regexp.MustCompile(`\A([^\x00-\x20:][^\x00-\x20]*):seq=([1-9][0-9]{0,14}):prev=([0-9a-f]{64})\z`)
	trackDigits      = regexp.MustCompile(`\A[0-9]{1,15}\z`)
	trackHex64       = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
)

type trackUnreadable struct{}

func (trackUnreadable) Error() string { return "unreadable" }

// trackParse reads bytes as track.py's parse does: UTF-8, JSON.parse semantics (a repeated key: the last wins), every
// number an integer within 2^53, printable ASCII keys, no lone surrogate.
func trackParse(b []byte) (Value, error) {
	if !utf8.Valid(b) {
		return nil, trackUnreadable{}
	}
	v, err := ParseJSON(b)
	if err != nil {
		return nil, trackUnreadable{}
	}
	if !trackOK(v) {
		return nil, trackUnreadable{}
	}
	return v, nil
}

func trackOK(v Value) bool {
	switch x := v.(type) {
	case nil, bool:
		return true
	case float64:
		return !math.IsInf(x, 0) && !math.IsNaN(x) && x == math.Trunc(x) && math.Abs(x) <= maxSafe
	case string:
		for i := 0; i+1 < len(x); i++ {
			if x[i] == 0xED && x[i+1] >= 0xA0 && x[i+1] <= 0xBF { // a lone surrogate, kept as WTF-8
				return false
			}
		}
		return true
	case *Array:
		for _, it := range x.Items {
			if !trackOK(it) {
				return false
			}
		}
		return true
	case *Object:
		for _, k := range x.keys {
			for i := 0; i < len(k); i++ {
				if k[i] < 0x20 || k[i] > 0x7e {
					return false
				}
			}
			if !trackOK(x.vals[k]) {
				return false
			}
		}
		return true
	}
	return false
}

func trackSha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func trackB64(v Value) []byte {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil
	}
	return raw
}

func asInt(v Value) (int64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

type trackAnchor struct {
	n  int64
	bb int64
	ok bool // bb is known
}

func trackAnchors(dir string) map[string]trackAnchor {
	out := map[string]trackAnchor{}
	ld := filepath.Join(dir, "ledger")
	ents, err := os.ReadDir(ld)
	if err != nil {
		return out
	}
	var ns []int64
	for _, e := range ents {
		name := e.Name()
		if strings.HasSuffix(name, ".json") && trackDigits.MatchString(strings.TrimSuffix(name, ".json")) {
			n, _ := strconv.ParseInt(strings.TrimSuffix(name, ".json"), 10, 64)
			ns = append(ns, n)
		}
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	for _, n := range ns {
		raw, err := os.ReadFile(filepath.Join(ld, strconv.FormatInt(n, 10)+".json"))
		if err != nil {
			continue
		}
		ev, err := trackParse(raw)
		if err != nil {
			continue
		}
		e, ok := ev.(*Object)
		if !ok {
			continue
		}
		rc, ok := Get(e, "record_canonical").(string)
		if !ok {
			continue
		}
		bv, err := trackParse([]byte(rc))
		if err != nil {
			continue
		}
		batch, ok := bv.(*Object)
		if !ok || Get(batch, "schema") != "nenrin-agreement-batch-v1" {
			continue
		}
		a := trackAnchor{n: n}
		if f, ok := Get(e, "bitcoin_block").(float64); ok {
			a.bb, a.ok = int64(f), true
		}
		recs, ok := Get(batch, "records").(*Array)
		if !ok {
			continue
		}
		for _, it := range recs.Items {
			o, ok := it.(*Object)
			if !ok || Get(o, "record_schema") != "a2a-admission-v0" {
				continue
			}
			sha, ok := Get(o, "canonical_sha256").(string)
			if !ok || !trackHex64.MatchString(sha) {
				continue
			}
			if _, seen := out[sha]; !seen {
				out[sha] = a
			}
		}
	}
	return out
}

type trackItem struct {
	asha, prev, sha string
	h               int64
}

// TrackReport is the report: Canonical(rep.Value) is what track.py --json prints.
type TrackReport struct {
	Value   *Object
	Verdict string
}

func obj(kv ...interface{}) *Object {
	o := newObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.set(kv[i].(string), kv[i+1])
	}
	return o
}

func num(i int64) Value { return float64(i) }

func strs(xs []string) *Array {
	a := &Array{}
	for _, x := range xs {
		a.Items = append(a.Items, x)
	}
	return a
}

// Track reads the mirror at dir under pins (domain -> 32 byte Ed25519 key) and returns the report.
func Track(dir string, pins map[string][]byte, lateBlocks int64) (*TrackReport, error) {
	anch := trackAnchors(dir)
	var shas []string
	for s := range anch {
		shas = append(shas, s)
	}
	sort.Strings(shas)
	held := map[string][]byte{}
	var heldShas, missing []string
	for _, s := range shas {
		b, err := os.ReadFile(filepath.Join(dir, "objects", s))
		if err != nil {
			missing = append(missing, s)
			continue
		}
		held[s] = b
		heldShas = append(heldShas, s)
	}
	problems := &Array{}
	unpinned := map[string]int64{}
	type looseItem struct {
		sha string
		h   int64
	}
	loose := map[string][]looseItem{}
	type chainKey struct{ ku, name string }
	chains := map[chainKey]map[int64][]trackItem{}
	for _, sha := range heldShas {
		b := held[sha]
		why, ku, msg, rec := trackRead(sha, b, pins)
		if why == "unpinned" {
			unpinned[ku]++
			continue
		}
		if why != "" {
			problems.Items = append(problems.Items, obj("sha256", sha, "what", why))
			continue
		}
		id, _ := Get(rec, "admission_id").(string)
		m := trackAdmissionID.FindStringSubmatch(id)
		var h int64 = -1
		if cv, ok := Get(rec, "chain_view").(*Object); ok {
			if x, ok := asInt(Get(cv, "height")); ok {
				h = x
			}
		}
		if h < 0 {
			problems.Items = append(problems.Items, obj("sha256", sha, "what", "bad_chain_view"))
			continue
		}
		if m == nil { // signed, but the admission_id names no seq and prev: judged for lateness only
			loose[ku] = append(loose[ku], looseItem{sha, h})
			continue
		}
		seq, _ := strconv.ParseInt(m[2], 10, 64)
		k := chainKey{ku, m[1]}
		if chains[k] == nil {
			chains[k] = map[int64][]trackItem{}
		}
		chains[k][seq] = append(chains[k][seq], trackItem{trackSha(msg), m[3], sha, h})
	}
	var doms []chainKey
	for d := range chains {
		doms = append(doms, d)
	}
	sort.Slice(doms, func(i, j int) bool {
		if doms[i].ku != doms[j].ku {
			return doms[i].ku < doms[j].ku
		}
		return doms[i].name < doms[j].name
	})
	domArr := &Array{}
	finding, incomplete := false, len(missing) > 0 || len(problems.Items) > 0
	for _, dom := range doms {
		c := chains[dom]
		var seqs []int64
		for s := range c {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		forks, broken, late, gaps := &Array{}, &Array{}, &Array{}, &Array{}
		distinct := func(items []trackItem) int {
			m := map[string]bool{}
			for _, x := range items {
				m[x.asha] = true
			}
			return len(m)
		}
		total := int64(0)
		for _, s := range seqs {
			items := append([]trackItem(nil), c[s]...)
			sort.Slice(items, func(i, j int) bool {
				a, b := items[i], items[j]
				if a.asha != b.asha {
					return a.asha < b.asha
				}
				if a.prev != b.prev {
					return a.prev < b.prev
				}
				if a.sha != b.sha {
					return a.sha < b.sha
				}
				return a.h < b.h
			})
			c[s] = items
			total += int64(len(items))
			if distinct(items) > 1 {
				var ss []string
				for _, x := range items {
					ss = append(ss, x.sha)
				}
				sort.Strings(ss)
				forks.Items = append(forks.Items, obj("seq", num(s), "admissions", strs(ss)))
			}
		}
		for _, s := range seqs {
			for _, x := range c[s] {
				if s == 1 {
					if x.prev != trackGenesis {
						broken.Items = append(broken.Items, obj("seq", num(s), "sha256", x.sha, "why", "seq 1 names a previous admission"))
					}
				} else if prevItems, ok := c[s-1]; ok && distinct(prevItems) == 1 && x.prev != prevItems[0].asha {
					broken.Items = append(broken.Items, obj("seq", num(s), "sha256", x.sha, "why", fmt.Sprintf("prev is not the admission held at seq %d", s-1)))
				}
				a := anch[x.sha]
				if a.ok && a.bb-x.h > lateBlocks {
					late.Items = append(late.Items, obj("seq", num(s), "sha256", x.sha, "height", num(x.h), "bitcoin_block", num(a.bb), "ledger_entry", num(a.n)))
				}
			}
		}
		prev := int64(0)
		for _, s := range seqs {
			if s-prev > 1 {
				gaps.Items = append(gaps.Items, &Array{Items: []Value{num(prev + 1), num(s - 1)}})
			}
			prev = s
		}
		top := seqs[len(seqs)-1]
		var head Value
		if distinct(c[top]) == 1 {
			head = c[top][0].asha
		}
		notYet := int64(0)
		for _, s := range seqs {
			for _, x := range c[s] {
				if !anch[x.sha].ok {
					notYet++
				}
			}
		}
		if len(forks.Items) > 0 || len(broken.Items) > 0 || len(late.Items) > 0 {
			finding = true
		}
		if len(gaps.Items) > 0 {
			incomplete = true
		}
		domArr.Items = append(domArr.Items, obj("key_url", dom.ku, "name", dom.name, "admissions", num(total), "first_seq", num(seqs[0]), "last_seq", num(top),
			"head", head, "forks", forks, "broken_links", broken, "anchored_late", late, "gaps", gaps, "not_yet_on_bitcoin", num(notYet)))
	}
	var lks []string
	for k := range loose {
		lks = append(lks, k)
	}
	sort.Strings(lks)
	unchained := &Array{}
	for _, ku := range lks {
		items := loose[ku]
		sort.Slice(items, func(i, j int) bool {
			if items[i].sha != items[j].sha {
				return items[i].sha < items[j].sha
			}
			return items[i].h < items[j].h
		})
		late := &Array{}
		notYet := int64(0)
		for _, x := range items {
			a := anch[x.sha]
			if a.ok && a.bb-x.h > lateBlocks {
				late.Items = append(late.Items, obj("sha256", x.sha, "height", num(x.h), "bitcoin_block", num(a.bb), "ledger_entry", num(a.n)))
			}
			if !a.ok {
				notYet++
			}
		}
		if len(late.Items) > 0 {
			finding = true
		}
		unchained.Items = append(unchained.Items, obj("key_url", ku, "admissions", num(int64(len(items))), "anchored_late", late, "not_yet_on_bitcoin", num(notYet)))
	}
	verdict := "one_history"
	if finding {
		verdict = "findings"
	} else if incomplete {
		verdict = "incomplete"
	}
	var pinned, ud []string
	for d := range pins {
		pinned = append(pinned, d)
	}
	sort.Strings(pinned)
	for d := range unpinned {
		ud = append(ud, d)
	}
	sort.Strings(ud)
	upArr := &Array{}
	for _, d := range ud {
		upArr.Items = append(upArr.Items, obj("key_url", d, "admissions", num(unpinned[d])))
	}
	if missing == nil {
		missing = []string{}
	}
	rep := obj("schema", TrackSchema, "late_blocks", num(lateBlocks), "pinned", strs(pinned), "verdict", verdict,
		"chains", domArr, "unchained", unchained, "problems", problems, "unpinned", upArr, "named_not_held", strs(missing),
		"does_not_establish", strs([]string{"that any decision was right; admission_verify_v0 and the settlement recompute that",
			"that this copy holds every admission the signer made; a gap is named, an unpublished admission is not seen",
			"that a ledger entry's bitcoin_block is true; verify its .ots against Bitcoin headers"}))
	c, err := Canonical(rep)
	if err != nil {
		return nil, err
	}
	rep.set("report_sha256", trackSha([]byte(c)))
	return &TrackReport{Value: rep, Verdict: verdict}, nil
}

func trackRead(sha string, b []byte, pins map[string][]byte) (why, ku string, msg []byte, rec *Object) {
	var dom string
	if trackSha(b) != sha {
		return "bytes_mismatch", "", nil, nil
	}
	v, err := trackParse(b)
	if err != nil {
		return "not_canonical", "", nil, nil
	}
	r, ok := v.(*Object)
	if !ok {
		return "not_canonical", "", nil, nil
	}
	c, err := Canonical(r)
	if err != nil || !bytes.Equal([]byte(c), b) {
		return "not_canonical", "", nil, nil
	}
	if Get(r, "schema") != "a2a-admission-v0" {
		return "not_an_admission", "", nil, nil
	}
	rp, _ := Get(r, "relying_party").(*Object)
	if rp != nil {
		dom, _ = Get(rp, "domain").(string)
		ku, _ = Get(rp, "key_url").(string)
	}
	if dom == "" || ku == "" {
		return "unsigned", "", nil, r
	}
	body := newObject()
	for _, k := range r.keys {
		if k != "signatures" {
			body.set(k, r.vals[k])
		}
	}
	bc, err := Canonical(body)
	if err != nil {
		return "not_canonical", "", nil, nil
	}
	msg = append([]byte(admissionContext), []byte(bc)...)
	pub, pinned := pins[ku]
	if !pinned {
		return "unpinned", ku, msg, r
	}
	sigs, _ := Get(r, "signatures").(*Array)
	any := false
	if sigs != nil {
		for _, it := range sigs.Items {
			s, ok := it.(*Object)
			if !ok || Get(s, "domain") != dom || Get(s, "alg") != "ed25519" {
				continue
			}
			any = true
			raw := trackB64(Get(s, "sig"))
			if len(raw) == 64 && ed25519.Verify(ed25519.PublicKey(pub), msg, raw) {
				return "", ku, msg, r
			}
		}
	}
	if !any {
		return "unsigned", ku, msg, r
	}
	return "bad_signature", ku, msg, r
}

// TrackPin reads "<base64 of a 32 byte Ed25519 key>@<key_url>" and returns (key_url, key).
func TrackPin(s string) (string, []byte, error) {
	i := strings.Index(s, "@")
	if i < 0 || i == len(s)-1 {
		return "", nil, fmt.Errorf("--pin wants <base64 key>@<key_url>: %q", s)
	}
	raw := trackB64(s[:i])
	if len(raw) != 32 {
		return "", nil, fmt.Errorf("--pin wants a 32 byte Ed25519 key in base64: %q", s)
	}
	return s[i+1:], raw, nil
}
