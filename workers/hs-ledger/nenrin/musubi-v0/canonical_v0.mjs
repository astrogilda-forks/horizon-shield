#!/usr/bin/env node
// musubi-canonical-v0: the canonical bytes every MUSUBI digest is computed over, written in a second runtime.
//
// The rule (the same one contract_v0.canonical / agreement_verify.canonical produce in Python):
//   1. UTF-8. Non-ASCII characters are written as themselves, never as \u escapes.
//   2. Object keys sorted by Unicode code point at every level. Keys must be printable ASCII (0x20..0x7E),
//      which verify_contract enforces, so code point order and byte order and UTF-16 order all agree.
//   3. Separators "," and ":" with no whitespace anywhere outside strings.
//   4. Strings: only '"', '\\' and U+0000..U+001F are escaped; \b \f \n \r \t take the short form, the other
//      control characters \u00xx with lowercase hex. U+007F and everything above U+001F are written raw.
//   5. Numbers: integers only, within plus or minus (2^53 - 1), written in decimal with no sign on zero, no
//      exponent, no fraction. A float, NaN or Infinity has no canonical form and verify_contract refuses it.
//   6. true, false, null as literals. Empty object "{}" and empty array "[]".
//   7. A lone surrogate (a UTF-16 code unit U+D800..U+DFFF outside a pair) is written as \udxxx with lowercase hex,
//      the same as provenance-v0/VERIFIER.md section 2 and JSON.stringify. It is the one code unit above U+001F that
//      is escaped: UTF-8 cannot carry it raw. Before 2026-10-15 this file wrote U+FFFD for it, so "\ud800", "\ud801"
//      and "\ufffd" hashed alike, while the Python canonicalizer raised UnicodeEncodeError (pipavlo82, Issue #29).
//      Vectors "lone surrogates" in canonical_vectors.json pin the bytes in both runtimes.
//
// canonical_vectors.json holds fixed inputs with the sha256 of their canonical bytes. contract_v0.py's selftest
// recomputes them in Python and, when node is present, runs this file over the same vectors and asserts the
// bytes are identical. Two runtimes, one set of bytes, checked on every run: that is what "canonical" means here.
//
//   node canonical_v0.mjs --vectors canonical_vectors.json     # prints  <sha256>  <name> per vector
//   echo '{"b":1,"a":[true,null]}' | node canonical_v0.mjs        # prints the canonical bytes
import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

const SAFE = 9007199254740991;

function keyOk(k) {
  for (let i = 0; i < k.length; i++) {
    const c = k.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

function str(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c >= 0xd800 && c <= 0xdfff) out += "\\u" + c.toString(16);   // rule 7: a lone surrogate (for..of yields a pair as one code point)
    else if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function canonical(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > SAFE) throw new Error("no canonical form for " + String(v));
    return v === 0 ? "0" : String(v);
  }
  if (typeof v === "bigint") {
    if (v > BigInt(SAFE) || v < -BigInt(SAFE)) throw new Error("no canonical form for " + v.toString());
    return v.toString();
  }
  if (typeof v === "string") return str(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v);
    for (const k of keys) if (!keyOk(k)) throw new Error("key is not printable ASCII: " + JSON.stringify(k));
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));          // ASCII keys: code point order is string order
    return "{" + keys.map((k) => str(k) + ":" + canonical(v[k])).join(",") + "}";
  }
  throw new Error("no canonical form for " + typeof v);
}

export function sha256(s) {
  return createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
}

// Main-module check by URL, not by string: on Windows process.argv[1] is C:\\...\\canonical_v0.mjs and
// "file://" + that never equals import.meta.url, so the CLI printed nothing (pipavlo82, Issue #29, 2026-10-05).
// realpath as well, because Node resolves import.meta.url through symlinks and argv[1] does not.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const a = process.argv.slice(2);
  if (a[0] === "--vectors") {
    const raw = JSON.parse(readFileSync(a[1], "utf8"));
    const vectors = Array.isArray(raw) ? raw : raw.vectors;   // canonical_vectors.json is {rule, note, vectors}
    for (const vec of vectors) {
      let line;
      try { line = sha256(canonical(vec.value)) + "  " + vec.name; }
      catch (e) { line = "REFUSED  " + vec.name + "  " + e.message; }
      process.stdout.write(line + "\n");
    }
  } else {
    const text = readFileSync(0, "utf8");
    process.stdout.write(canonical(JSON.parse(text)));
  }
}
