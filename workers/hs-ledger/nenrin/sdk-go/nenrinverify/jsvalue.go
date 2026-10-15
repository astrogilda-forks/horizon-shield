// Package nenrinverify is a Go port of the NENRIN provenance verifier (npm and PyPI nenrin-verify,
// verifier_version 0.1.7). The JavaScript file sdk/nenrin_verify.mjs is the reference; this port is held to it by
// the frozen corpora (interop-v0, interop-v0.1, interop-v0.2/edge) and by conformance-v0/differential.py, which
// runs JavaScript, Python and this port on the same bundles and prints every verdict signature that differs.
//
// This file holds the JavaScript semantics the verifier depends on, so the port can be read against the original
// line by line: JSON.parse into JavaScript values (every number a double, strings that may hold lone surrogates,
// duplicate keys last-wins), property reads that throw on null and undefined, strict equality, SameValueZero,
// truthiness, Object.assign's __proto__ rule, Number::toString, and the numeric sort as V8 runs it.
package nenrinverify

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Value is a JavaScript value as a JSON document can produce it:
//
//	Undefined (a property that is not there), nil (null), bool, float64, string, *Array, *Object
//
// Strings are UTF-8 except that a lone surrogate from a \uD800..\uDFFF escape is kept as its 3-byte generalized
// UTF-8 form (WTF-8), so canonical() can write it back as \udxxx exactly as JSON.stringify does.
type Value interface{}

type undefinedType struct{}

func (undefinedType) String() string { return "undefined" }

// Undefined is JavaScript undefined.
var Undefined Value = undefinedType{}

// Array is a JavaScript array. Identity matters (=== compares objects by reference), so arrays are pointers.
type Array struct{ Items []Value }

// Object is a JavaScript object with own keys in insertion order. Proto is set only on objects made by
// Object.assign from a source carrying an own "__proto__" key whose value is an object.
type Object struct {
	keys  []string
	vals  map[string]Value
	Proto *Object
}

func newObject() *Object { return &Object{vals: map[string]Value{}} }

func (o *Object) set(k string, v Value) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *Object) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *Object) own(k string) (Value, bool) { v, ok := o.vals[k]; return v, ok }

var indexKey = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func isIndexKey(k string) bool {
	if !indexKey.MatchString(k) {
		return false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < 4294967295
}

// Keys is Object.keys: array-index keys ascending, then the rest in insertion order.
func (o *Object) Keys() []string {
	var idx, rest []string
	for _, k := range o.keys {
		if isIndexKey(k) {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(idx, func(i, j int) bool {
		a, _ := strconv.ParseUint(idx[i], 10, 64)
		b, _ := strconv.ParseUint(idx[j], 10, 64)
		return a < b
	})
	return append(idx, rest...)
}

// ---- errors that stand for a JavaScript throw ----

// JSTypeError is where the JavaScript original throws a TypeError (a property read on null or undefined).
type JSTypeError struct{ Msg string }

func (e *JSTypeError) Error() string { return "TypeError: " + e.Msg }

// CanonicalError is checkCanonicalInput's refusal (strict_json.mjs).
type CanonicalError struct{ Code, At string }

func (e *CanonicalError) Error() string { return e.Code + " at " + e.At }

// ErrNotReproduced marks an input where this port does not reproduce the JavaScript and stops instead of guessing.
var ErrNotReproduced = errors.New("not reproduced")

type throw struct{ err error }

func raise(err error) { panic(throw{err}) }

// catch converts a throw back into an error; any other panic is re-raised.
func catch(errp *error) {
	if r := recover(); r != nil {
		if t, ok := r.(throw); ok {
			*errp = t.err
			return
		}
		panic(r)
	}
}

// ---- JSON.parse ----

// ParseJSON is JSON.parse(text) over the bytes as Node's readFileSync(path, "utf8") decodes them (an invalid
// UTF-8 sequence becomes U+FFFD per maximal subpart). Every number is a double, duplicate keys keep the first
// position and the last value, and a \u escape of a lone surrogate is kept.
func ParseJSON(b []byte) (v Value, err error) {
	p := &parser{s: decodeUTF8Lossy(b)}
	defer func() {
		if r := recover(); r != nil {
			if pe, ok := r.(parseError); ok {
				err = errors.New(string(pe))
				return
			}
			panic(r)
		}
	}()
	p.ws()
	v = p.value()
	p.ws()
	if p.i != len(p.s) {
		p.fail("unexpected trailing data")
	}
	return v, nil
}

type parseError string

type parser struct {
	s string
	i int
}

func (p *parser) fail(msg string) {
	panic(parseError(fmt.Sprintf("bad JSON at byte %d: %s", p.i, msg)))
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value() Value {
	if p.i >= len(p.s) {
		p.fail("unexpected end")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		return p.str()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	p.fail("unexpected character")
	return nil
}

func (p *parser) number() Value {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		p.fail("bad number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			p.fail("bad number")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			p.fail("bad number")
		}
	}
	f, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		p.fail("bad number")
	}
	return f
}

func hexVal(s string) (int, bool) {
	if len(s) != 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 16, 32)
	return int(n), err == nil
}

func (p *parser) str() string {
	p.i++
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			p.fail("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String()
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				p.fail("bad escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				if p.i+4 > len(p.s) {
					p.fail("bad escape")
				}
				u, ok := hexVal(p.s[p.i : p.i+4])
				if !ok {
					p.fail("bad escape")
				}
				p.i += 4
				if u >= 0xD800 && u <= 0xDBFF && p.i+6 <= len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
					if lo, ok := hexVal(p.s[p.i+2 : p.i+6]); ok && lo >= 0xDC00 && lo <= 0xDFFF {
						p.i += 6
						b.WriteRune(rune(0x10000 + (u-0xD800)<<10 + (lo - 0xDC00)))
						continue
					}
				}
				writeCodeUnit(&b, u)
			default:
				p.fail("bad escape")
			}
		case c < 0x20:
			p.fail("control character in string")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

// writeCodeUnit writes one UTF-16 code unit; a surrogate is written in its 3-byte generalized UTF-8 form.
func writeCodeUnit(b *strings.Builder, u int) {
	if u >= 0xD800 && u <= 0xDFFF {
		b.WriteByte(byte(0xE0 | u>>12))
		b.WriteByte(byte(0x80 | (u>>6)&0x3F))
		b.WriteByte(byte(0x80 | u&0x3F))
		return
	}
	b.WriteRune(rune(u))
}

func (p *parser) array() Value {
	p.i++
	a := &Array{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return a
	}
	for {
		p.ws()
		a.Items = append(a.Items, p.value())
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a
		}
		p.fail("expected , or ]")
	}
}

func (p *parser) object() Value {
	p.i++
	o := newObject()
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return o
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			p.fail("expected key")
		}
		k := p.str()
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			p.fail("expected :")
		}
		p.i++
		p.ws()
		o.set(k, p.value())
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o
		}
		p.fail("expected , or }")
	}
}

// decodeUTF8Lossy decodes as the WHATWG UTF-8 decoder does: each maximal subpart of an ill-formed sequence
// becomes one U+FFFD. A leading byte order mark is kept (Node's "utf8" decoding keeps it; JSON.parse then
// refuses it as an unexpected character).
func decodeUTF8Lossy(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		need, lo, hi := 0, byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			need = 1
		case c == 0xE0:
			need, lo = 2, 0xA0
		case c >= 0xE1 && c <= 0xEC, c == 0xEE, c == 0xEF:
			need = 2
		case c == 0xED:
			need, hi = 2, 0x9F
		case c == 0xF0:
			need, lo = 3, 0x90
		case c >= 0xF1 && c <= 0xF3:
			need = 3
		case c == 0xF4:
			need, hi = 3, 0x8F
		default:
			out.WriteRune(utf8.RuneError)
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) || b[j] < lo || b[j] > hi {
				ok = false
				break
			}
			lo, hi = 0x80, 0xBF
			j++
		}
		if ok {
			out.Write(b[i:j])
		} else {
			out.WriteRune(utf8.RuneError)
		}
		i = j
	}
	return out.String()
}

// ---- property access, equality, truthiness ----

func typeName(v Value) string {
	if v == nil {
		return "null"
	}
	return "undefined"
}

// prop is o.k in JavaScript: throws on null and undefined, undefined when absent.
func prop(o Value, k string) Value {
	switch x := o.(type) {
	case nil, undefinedType:
		raise(&JSTypeError{fmt.Sprintf("Cannot read properties of %s (reading '%s')", typeName(o), k)})
	case *Object:
		if v, ok := x.own(k); ok {
			return v
		}
		if x.Proto != nil {
			if v, ok := x.Proto.own(k); ok {
				return v
			}
		}
		return Undefined
	case *Array:
		if k == "length" {
			return float64(len(x.Items))
		}
		if isIndexKey(k) {
			n, _ := strconv.Atoi(k)
			if n < len(x.Items) {
				return x.Items[n]
			}
		}
		return Undefined
	case string:
		if k == "length" {
			return float64(utf16Len(x))
		}
	}
	return Undefined
}

// andProp is o && o.k
func andProp(o Value, k string) Value {
	if truthy(o) {
		return prop(o, k)
	}
	return o
}

func truthy(v Value) bool {
	switch x := v.(type) {
	case nil, undefinedType:
		return false
	case bool:
		return x
	case float64:
		return x != 0 && !math.IsNaN(x)
	case string:
		return len(x) > 0
	}
	return true
}

func or(a, b Value) Value {
	if truthy(a) {
		return a
	}
	return b
}

// nullish is v == null
func nullish(v Value) bool { return v == nil || v == Undefined }

func isObj(v Value) bool { _, ok := v.(*Object); return ok }

func isStr(v Value) bool { _, ok := v.(string); return ok }

// seq is a === b
func seq(a, b Value) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case undefinedType:
		return b == Undefined
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case *Array:
		y, ok := b.(*Array)
		return ok && x == y
	case *Object:
		y, ok := b.(*Object)
		return ok && x == y
	}
	return false
}

func sameValueZero(a, b Value) bool {
	if x, ok := a.(float64); ok && math.IsNaN(x) {
		y, ok := b.(float64)
		return ok && math.IsNaN(y)
	}
	return seq(a, b)
}

// uniq is [...new Set(xs)].
func uniq(xs []Value) []Value {
	var out []Value
	for _, x := range xs {
		found := false
		for _, y := range out {
			if sameValueZero(x, y) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, x)
		}
	}
	return out
}

// jsMap is new Map() with SameValueZero keys in insertion order.
type jsMap struct {
	keys []Value
	vals [][]*Object
}

func (m *jsMap) idx(k Value) int {
	for i, x := range m.keys {
		if sameValueZero(x, k) {
			return i
		}
	}
	return -1
}

func (m *jsMap) push(k Value, o *Object) {
	if i := m.idx(k); i >= 0 {
		m.vals[i] = append(m.vals[i], o)
		return
	}
	m.keys = append(m.keys, k)
	m.vals = append(m.vals, []*Object{o})
}

func (m *jsMap) get(k Value) []*Object {
	if i := m.idx(k); i >= 0 {
		return m.vals[i]
	}
	return nil
}

// assign is Object.assign({}, ...sources): a source's own "__proto__" key is not copied; when its value is an
// object it becomes the target's prototype.
func assign(sources ...Value) *Object {
	out := newObject()
	for _, src := range sources {
		switch s := src.(type) {
		case *Object:
			for _, k := range s.Keys() {
				v := s.vals[k]
				if k == "__proto__" {
					if po, ok := v.(*Object); ok {
						out.Proto = po
					} else if v == nil {
						out.Proto = nil
					}
					continue
				}
				out.set(k, v)
			}
		case *Array:
			for i, v := range s.Items {
				out.set(strconv.Itoa(i), v)
			}
		case string:
			for i, u := range utf16Units(s) {
				var b strings.Builder
				writeCodeUnit(&b, u)
				out.set(strconv.Itoa(i), b.String())
			}
		}
	}
	return out
}

// ---- strings ----

// decodeWTF8 yields the code points of s, a lone surrogate as itself.
func decodeWTF8(s string) []rune {
	var out []rune
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
			out = append(out, rune(0xD000|int(s[i+1]&0x3F)<<6|int(s[i+2]&0x3F)))
			i += 3
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		out = append(out, r)
		i += w
	}
	return out
}

func utf16Units(s string) []int {
	var out []int
	for _, r := range decodeWTF8(s) {
		if r > 0xFFFF {
			r -= 0x10000
			out = append(out, 0xD800+int(r>>10), 0xDC00+int(r&0x3FF))
		} else {
			out = append(out, int(r))
		}
	}
	return out
}

func utf16Len(s string) int { return len(utf16Units(s)) }

// quote is JSON.stringify(string): '"', '\\', U+0000..U+001F and lone surrogates escaped, everything else raw.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range decodeWTF8(s) {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || (r >= 0xD800 && r <= 0xDFFF) {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---- numbers ----

const maxSafe = 9007199254740991

// numStr is Number::toString(10).
func numStr(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "Infinity"
	}
	if math.IsInf(v, -1) {
		return "-Infinity"
	}
	if v == 0 {
		return "0"
	}
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	e := strconv.FormatFloat(v, 'e', -1, 64) // d.ddddde±XX, shortest round-trip digits
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	k, n := len(digits), x+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	es := strconv.Itoa(n - 1)
	if n-1 >= 0 {
		es = "+" + es
	}
	if k == 1 {
		return sign + digits + "e" + es
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + es
}

// primStr is String(v) for the values a JSON document holds.
func primStr(v Value) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case undefinedType:
		return "undefined"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return numStr(x)
	case string:
		return x
	case *Array:
		parts := make([]string, len(x.Items))
		for i, it := range x.Items {
			if !nullish(it) {
				parts[i] = primStr(it)
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

const jsWhitespace = " \t\n\v\f\r\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

var (
	decNum = regexp.MustCompile(`^[+-]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|Infinity)$`)
	hexNum = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)
	octNum = regexp.MustCompile(`^0[oO][0-7]+$`)
	binNum = regexp.MustCompile(`^0[bB][01]+$`)
)

// radixNum is the double nearest to the integer written in digits (round half to even, Infinity past the
// largest double), as V8 reads 0x, 0o and 0b literals.
func radixNum(digits string, base int) float64 {
	n, ok := new(big.Int).SetString(digits, base)
	if !ok {
		return math.NaN()
	}
	f, _ := new(big.Float).SetInt(n).Float64()
	return f
}

// toNumber is ToNumber for the values a JSON document can hold.
func toNumber(v Value) float64 {
	switch x := v.(type) {
	case undefinedType:
		return math.NaN()
	case nil:
		return 0
	case bool:
		if x {
			return 1
		}
		return 0
	case float64:
		return x
	case string:
		t := strings.Trim(x, jsWhitespace)
		switch {
		case t == "":
			return 0
		case hexNum.MatchString(t):
			return radixNum(t[2:], 16)
		case octNum.MatchString(t):
			return radixNum(t[2:], 8)
		case binNum.MatchString(t):
			return radixNum(t[2:], 2)
		case decNum.MatchString(t):
			f, err := strconv.ParseFloat(strings.Replace(t, "Infinity", "Inf", 1), 64)
			if err != nil && !errors.Is(err, strconv.ErrRange) {
				return math.NaN()
			}
			return f
		}
		return math.NaN()
	case *Array:
		return toNumber(primStr(x))
	}
	return math.NaN()
}

// subCompare is SortCompare over (a, b) => a - b: ToNumber on both, a NaN result read as +0.
func subCompare(a, b Value) float64 {
	v := toNumber(a) - toNumber(b)
	if math.IsNaN(v) {
		return 0
	}
	return v
}

// sortNumeric is keys.slice().sort((a, b) => a - b) as V8 runs it: undefined moved to the end without calling
// the comparator, and for fewer than 64 elements one run from CountAndMakeRun finished by BinaryInsertionSort.
func sortNumeric(keys []Value) []Value {
	var a, tail []Value
	for _, k := range keys {
		if k == Undefined {
			tail = append(tail, k)
		} else {
			a = append(a, k)
		}
	}
	n := len(a)
	if n < 2 {
		return append(a, tail...)
	}
	allNum := true
	for _, k := range a {
		if f, ok := k.(float64); !ok || math.IsNaN(f) {
			allNum = false
			break
		}
	}
	if allNum {
		sort.SliceStable(a, func(i, j int) bool { return a[i].(float64) < a[j].(float64) })
		return append(a, tail...)
	}
	if n >= 64 {
		raise(fmt.Errorf("%w: 64 or more hop.seq keys that are not all numbers; V8 would merge runs here", ErrNotReproduced))
	}
	run := 2
	desc := subCompare(a[1], a[0]) < 0
	prev := a[1]
	for i := 2; i < n; i++ {
		order := subCompare(a[i], prev)
		if desc {
			if order >= 0 {
				break
			}
		} else if order < 0 {
			break
		}
		prev = a[i]
		run++
	}
	if desc {
		for i, j := 0, run-1; i < j; i, j = i+1, j-1 {
			a[i], a[j] = a[j], a[i]
		}
	}
	for start := run; start < n; start++ {
		left, right, pivot := 0, start, a[start]
		for left < right {
			mid := left + (right-left)>>1
			if subCompare(pivot, a[mid]) < 0 {
				right = mid
			} else {
				left = mid + 1
			}
		}
		copy(a[left+1:start+1], a[left:start])
		a[left] = pivot
	}
	return append(a, tail...)
}

// ---- canonical form (musubi-canonical-v0, strict_json.mjs checkCanonicalInput + bind.mjs canon) ----

func keyOK(k string) bool {
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

func checkCanonicalInput(v Value, path string) {
	switch x := v.(type) {
	case nil, bool, string:
		return
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) || x != math.Trunc(x) {
			raise(&CanonicalError{"non_integer_number", path})
		}
		if x > maxSafe || x < -maxSafe {
			raise(&CanonicalError{"unsafe_number", path})
		}
	case *Array:
		for i, it := range x.Items {
			checkCanonicalInput(it, path+"["+strconv.Itoa(i)+"]")
		}
	case *Object:
		for _, k := range x.Keys() {
			if !keyOK(k) {
				raise(&CanonicalError{"key_not_printable_ascii", path + "." + k})
			}
			checkCanonicalInput(x.vals[k], path+"."+k)
		}
	default:
		raise(&CanonicalError{"bad_json", path})
	}
}

func canon(b *strings.Builder, v Value) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case float64:
		b.WriteString(numStr(x))
	case string:
		b.WriteString(quote(x))
	case *Array:
		b.WriteByte('[')
		for i, it := range x.Items {
			if i > 0 {
				b.WriteByte(',')
			}
			canon(b, it)
		}
		b.WriteByte(']')
	case *Object:
		keys := append([]string(nil), x.keys...)
		sort.Strings(keys) // printable ASCII only, so byte order is code point order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quote(k))
			b.WriteByte(':')
			canon(b, x.vals[k])
		}
		b.WriteByte('}')
	}
}

// canonical is bind.mjs canonical(): checkCanonicalInput (throws CanonicalError), then the canonical bytes.
func canonical(v Value) string {
	checkCanonicalInput(v, "$")
	var b strings.Builder
	canon(&b, v)
	return b.String()
}

// Canonical returns canonical(v) or the CanonicalError.
func Canonical(v Value) (s string, err error) {
	defer catch(&err)
	return canonical(v), nil
}

// Get returns o's own value for k, or Undefined.
func Get(o *Object, k string) Value {
	if v, ok := o.own(k); ok {
		return v
	}
	return Undefined
}
