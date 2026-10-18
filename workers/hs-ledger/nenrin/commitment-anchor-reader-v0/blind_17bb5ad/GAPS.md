# GAPS: blind reading of the OBS-06 commitment_anchor README (reader17)

Inputs read: fence/README.md, fence/vectors.blind.json, fence/38.ots. Nothing else.
Each note is either a point where the README is ambiguous or silent and the reading reader17 chose, or an observation about the text. A note marked (no effect) changes no result on these 14 vectors.

1. Where the event lives. The README says the digest is recomputed "from the record's fields" and names `[0,pubkey,created_at,kind,tags,content]`, but never says where those fields sit. The vectors carry them under `record.subject`. Reading: use `record.subject` when it is an object, else the record itself. The name `subject` comes from the vectors, not the README.

2. Which digest is compared. The README says a self-stated digest (Nostr `id`, a `hash` field) is not a recompute. Reading: the recomputed NIP-01 id is compared with `commitment_anchor.digest`, and `subject.id` is ignored. Observation: in all 14 vectors `subject.id` equals `commitment_anchor.digest`, including `control-anchor-does-not-cover-record`, so a reader that trusted `subject.id` would get that vector wrong. That vector is the one that makes the "self-stated is not a recompute" sentence load-bearing.

3. NIP-01 escaping as stated. Implemented exactly as the README states: only `\n \" \\ \r \t \b \f` are escaped, every other character (other C0 controls, non-ASCII) is written as itself; no whitespace; UTF-8. The README's list is the whole rule reader17 follows; it does not consult NIP-01 itself (outside the fence). (no effect)

4. Escaping coverage of the vectors. Every vector's `content` is pure ASCII with no control characters; the only escapes exercised are `\"` and `\\` (three literal backslashes, from the six-character texts backslash-u-21d2, backslash-u-00b7 and backslash-u-2014 that the content holds literally, i.e. JSON escapes left undecoded inside the content string). A stock `json.dumps(..., separators=(',',':'), ensure_ascii=True)` gives the same 13 matches and the same 1 mismatch. So the vectors do not distinguish the README's escaping from ordinary JSON escaping: non-ASCII, `\u00XX` for other controls, and `/` are untested. (no effect)

5. "content is hashed exactly as it stands". Read as: the decoded JSON string value of `content` is serialized as a string, not parsed. The literal six-character text backslash-u-21d2 inside content is therefore hashed with its backslash escaped, as two backslashes then u21d2, i.e. `\\u21d2`. Decoding the inner JSON and re-serializing would change the bytes (key order is already sorted, but the `\uXXXX` text would become the characters). (no effect: followed as stated)

6. Number format in the serialization. The README says a rule that leaves number format open establishes nothing, and NIP-01 fields `created_at` and `kind` are integers. Reading: integers are written in plain decimal; a non-integer, boolean or null in those fields, or a non-string tag element, is treated as "does not recompute" (ANCHOR_DOES_NOT_COVER_RECORD). No vector exercises this. (no effect)

7. Unknown or missing `digest_rule`, missing `digest`, missing `commitment_anchor`. The README names `nip01-event-id` and gives JCS (RFC 8785) then SHA-256 as an example, but only spells out the bytes for `nip01-event-id`. Reading: only `nip01-event-id` is implemented; any other rule, a missing digest, or a record with no `commitment_anchor` at all yields ANCHOR_DOES_NOT_COVER_RECORD with precedence_established=false. The README does not say what result a record with no anchor gets (it is RECOMMENDED, REQUIRED only when precedence is asserted); one could argue such a record should go to steps 2 to 4 with "inputs missing". No vector exercises this. (no effect)

8. Digest comparison case. Reading: the stated digest is lowercased and compared with the lowercase hex recompute. The README does not say hex, or which case. (no effect)

9. precedence_established when the digest fails. The README says such a record "has no anchor for this rule" and that "each result also carries precedence_established". Reading: false. The text does not state it for result 1 explicitly.

10. `rule=` in the output. The README says a verifier SHOULD report which rule a verdict used. Reading: print the declared `anchor_time_rule`; when absent or null, print `header_time_plus_tolerance` (the stated default). For ANCHOR_DOES_NOT_COVER_RECORD the rule is still printed though it was not used to reach the verdict. For an unrecognised rule string, the string is printed as given and precedence is not established. Every vector here declares its rule explicitly, so the "absent means header_time_plus_tolerance" default is never exercised.

11. Null treated as absent. README says "absent" for `anchor_time_rule`, `anchor_time_tolerance_s`, `asserts_precedence`. Reading: a JSON null is treated as absent for `anchor_time_rule`; for numeric inputs null is "inputs missing". (no effect)

12. `asserts_precedence` values. Reading: only JSON `true` counts as asserting. A string "true", 1, etc. count as not asserting. The README says only "`true` if the record claims it". (no effect)

13. `does_not_assert` shape. Reading: the limitation is declared only if `does_not_assert` is a JSON array containing the exact string `precedence_before_outcome`. A missing field, a non-array, or a different spelling is "not declared". (no effect)

14. Inputs for `later_median`. The README says ceiling = `anchor_ceiling_time`, "with `anchor_ceiling_source` naming them". Reading: only `anchor_ceiling_time` is required; `anchor_ceiling_source` is informational and not checked. `anchor_time` and the tolerance are not used under this rule. `control-later-median-ceiling-missing` has neither field and gets UNSUPPORTED under either reading. (no effect on these vectors)

15. Inputs for `height`. Reading: `anchor_height` inside `commitment_anchor`, `outcome_height` on the record next to it, both integers; precedence iff anchor_height < outcome_height. `outcome_time` is present in the height vectors but is not compared, as the README says. Observation: in `height-outcome-in-later-block`, `outcome_height` appears after `note` in the JSON, unlike the other record-level fields; order does not matter to a JSON reader.

16. Inputs for `header_time_plus_tolerance`. Reading: needs numeric `anchor_time`, `anchor_time_tolerance_s` and `outcome_time`; any one missing means "establishes nothing" (not zero tolerance, per the README). Comparison is strict: anchor_time + tolerance < outcome_time. `control-backdated-header-moves-the-ceiling` sits 1 s inside this (1782651081 + 7200 = 1782658281 < 1782658282), so a `<=` reading would not change it but an off-by-one in the other direction would.

17. Strictness generally. All three rules are read as strict (`<`), from "strictly earlier" and "strictly below". `control-height-same-block` (equal heights) depends on it.

18. Precedence established but not asserted, or established and also listed in does_not_assert. The README's results do not flag either. Reading: both are CONFORMING with precedence_established=true. No vector has this combination. (no effect)

19. Step 2 wording. "the record asserts precedence and the rule does not establish it (this covers a record that also fails to declare the limitation)". Read as: step 2 fires regardless of `does_not_assert`. A record that asserts precedence and also lists `precedence_before_outcome` in `does_not_assert` (self-contradictory) gets step 2 if not established, CONFORMING if established. The README does not address the contradiction. (no effect)

20. Units. `outcome_time` is stated as Unix seconds; `anchor_time` and `anchor_ceiling_time` are not given units in the README. Reading: Unix seconds for all, as the vectors' values imply. (no effect)

21. Proof not verified. The README says `check.py` does not verify the proof and that the mechanism's own verifier should be run. reader17 does not parse or verify `38.ots`, does not check `mechanism`, `proof_ref` or the Schnorr `sig` (not possible in stdlib, and not required by the text). The result is about the rule only.

22. Observation on 38.ots (read for context, not used by the reader). It is an OpenTimestamps proof (magic header, version 1, file hash op sha256) whose file digest is a42205d7e39c684f0aa43f80fe7ea1aa8e180df93ff46e82b5bff95b70c663e9, the same as `commitment_anchor.digest` and the recomputed NIP-01 id of the untampered vectors. It contains one Bitcoin block-header attestation at height 955810 (matching `anchor_time_source` and `anchor_height`) and four pending calendar attestations (alice and bob btc.calendar.opentimestamps.org, finney.calendar.eternitywall.com, btc.calendar.catallaxy.com). The block header time itself is not in the proof, so `anchor_time` 1782654639 could not be checked within the fence.

23. File naming. The README describes `vectors.json` and `check.py` ("14/14 agree"); the fence holds `vectors.blind.json` (no expected values) and no checker. Vector count 14 matches.

24. Vector counts vs `kind` labels. README: "the requested pair, four negative controls, five vectors for the other two ceiling rules, and three backdated-header vectors" = 2 + 4 + 5 + 3 = 14. By content: pair = vectors 1 and 2; four negative controls = vectors 3 to 6; five later_median/height = vectors 7 to 11; three backdated = vectors 12 to 14. But the `kind` labels are pair x3 (1, 2, 14), negative_control x9 (3 to 11), control x2 (12, 13). The README says `kind` is a label only, so reader17 ignores it; the labels just do not match the README's grouping.

25. Names vs results. Several vector names read like expected verdicts but are labels. `later-median-outcome-inside-old-tolerance` is labelled negative_control yet comes out CONFORMING/true under the stated rule (ceiling 1782657732 < outcome 1782658239); the README warns that some negative_control vectors are expected CONFORMING. `control-backdated-header-moves-the-ceiling` comes out CONFORMING/true, which is the point the README makes (the miner's header choice decides the verdict under header_time_plus_tolerance), not a claim that the record is sound.

26. Arithmetic in the README checks out against the vectors: 1782654639 + 3093 = 1782657732 (the later-median ceiling); 1782654639 minus 1782651081 = 3558 s (the stated ceiling move); 1782651080 + 1 = 1782651081 (median time past plus one). The README says `check.py` takes `anchor_ceiling_time` and heights as given; reader17 does the same, since fetching headers is outside the fence and off-network.

27. Section placement. In the README the "Results" and the "Rule" paragraphs both appear inside the OBS-06 draft-text section, while the line "Each control is load-bearing" is in the Vectors section and refers to `check.py`, which reader17 has not seen. reader17 implements all four controls named there (tolerance, digest recompute, undeclared-limitation check, unsupported-claim check).

28. `observation_vantage` is mentioned ("assessed separately") but is not a field in any vector and has no result. reader17 does not assess it. (no effect)

29. Bugs fixed after the run: none. reader17.py was run once as written; no change was made after seeing RAW.txt. (GAPS.md itself was corrected once: the file writer had turned the literal backslash-u texts in notes 4 and 5 into the characters they stand for, which changed their meaning; they are now spelled out in words.)
