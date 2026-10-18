# GAPS: blind reading of commitment_anchor (OBS-06)

Read from README.md, vectors.blind.json and 38.ots only. Each item: what the text left open, the reading reader.py uses, and whether the other reading flips a verdict on these 11 vectors.

## A. Gaps in the text

1. **Result names.** The README names no result values (the table was removed). Reader's own names: `conformant`, `unsupported_claim` (asserts precedence the rule does not establish; README "MUST NOT assert precedence"), `undeclared_limitation` (not established and `precedence_before_outcome` absent from `does_not_assert`; README "MUST list"). Both are printed joined by `+` when both apply. Notes use the README's own words where it has them: "no anchor" for a digest mismatch, "inputs missing" for "a rule whose inputs are missing establishes nothing". Flip: naming only, no verdict change.

2. **Two violations in one record.** A record that asserts precedence without basis and has an empty `does_not_assert` breaks both MUSTs. The text does not say whether one verdict or two. Reader reports both. Six vectors carry both: control-claims-precedence-after-outcome, control-outcome-inside-tolerance, control-anchor-does-not-cover-record, control-later-median-ceiling-after-outcome, control-later-median-ceiling-missing, control-height-same-block. control-late-anchor-silent is the only single `undeclared_limitation`. A reader that stops at the first violation would print only `unsupported_claim`. Flip: label only; pass/fail is the same (fail).

3. **"Otherwise" scope for the `does_not_assert` MUST.** Read as: whenever precedence is not established (including no anchor, missing inputs, unknown rule), the record MUST list `precedence_before_outcome`. The alternative (the listing is only required when the record does not assert) would make the six double violations single `unsupported_claim`. Flip: label only.

4. **Digest mismatch means "no anchor for this rule".** Read as: precedence is not established, and the rule's "Otherwise" branch then applies. The text does not say whether a record with no valid anchor must still list `precedence_before_outcome`. Reader says yes. On control-anchor-does-not-cover-record (asserts true) the verdict is a failure under either reading. Flip: label only. A reader that compared `digest` to the record's stated `subject.id` instead of recomputing would PASS this control (both are a42205d7...), which is exactly the "digest recompute" control the README says is load-bearing.

5. **What the recomputed digest is compared to.** Reader compares the NIP-01 recompute to `commitment_anchor.digest` and ignores `subject.id`. In control-anchor-does-not-cover-record the subject's content says `"verdict":"approve"` (the others say `approve_with_concerns`) but `subject.id`, `sig` and `digest` are left at the original values; recompute gives f037e4d43c62c3a06334a584c5dfe5e1cc07f9a286e2e0d4dd05bd51a0c4c64b. Flip: no, provided some recompute happens (see 4).

6. **NIP-01 serialization details.** The README says "digest = its NIP-01 event id" and does not spell out the serialization. Reader uses the instruction given to it: sha256 of UTF-8 `[0,pubkey,created_at,kind,tags,content]`, no whitespace, non-ASCII unescaped, Python's standard escaping for `"` and `\`. Content holds U+21D2, U+00B7 and U+2014 (as JSON `\u` escapes in the vector file, decoded before hashing) and no control characters, so the escaping corner cases of NIP-01 do not arise; reader refuses (does not guess) if an unusual control character appears. Flip: an implementation that kept `ensure_ascii` on would fail the digest on every vector, flipping anchor-before-outcome, later-median-outcome-inside-old-tolerance and height-outcome-in-later-block to failures.

7. **Strictly earlier, and the equality case.** Text says "strictly earlier" and "strictly below". Reader uses `ceiling < outcome_time` and `anchor_height < outcome_height`. Equality only occurs in control-height-same-block (955810 vs 955810). Flip: yes for that vector if `<=` were used (it would become `conformant`).

8. **Tolerance absent under `header_time_plus_tolerance`.** Not said whether a missing `anchor_time_tolerance_s` is "inputs missing" or tolerance 0. Reader: inputs missing, establishes nothing. All header-rule vectors carry 7200. Flip: no.

9. **Is `header_time_plus_tolerance` acceptable for a Bitcoin anchor at all?** The text calls it "only a convention" for Bitcoin, says nothing caps lag, and RECOMMENDS `later_median`, but does not forbid it. Reader accepts it as declared. Flip: yes. If a reader refused header time plus tolerance for `opentimestamps-bitcoin`, anchor-before-outcome would become `unsupported_claim+undeclared_limitation`, the four header-rule controls would stay failures, and anchor-after-outcome-declared would stay conformant.

10. **Size of the tolerance.** The text does not say what tolerance is sufficient for Bitcoin; the vectors use 7200 s (the README's "about two hours" is a statement about running ahead, i.e. a floor, not a lag bound). Reader takes the declared value. Flip: no on these vectors unless a reader imposed its own larger tolerance; with any tolerance of 443147 s or more anchor-before-outcome flips, and with any tolerance strictly below 3600 s control-outcome-inside-tolerance (outcome 1782658239, anchor 1782654639, gap 3600) flips to established.

11. **`later_median` inputs.** Reader treats a missing `anchor_ceiling_time` as inputs missing. The text says the record names the blocks in `anchor_ceiling_source`; whether a missing source is also "inputs missing" is unstated. Reader only notes it. Every later_median vector that has a ceiling also has a source. Flip: no. Reader does not check `anchor_ceiling_time >= anchor_time` (true here: 1782657732 > 1782654639) and does not fetch headers, as the README says check.py does not either.

12. **Where `outcome_height` lives.** The text names `anchor_height` and `outcome_height` but gives no location. In the vectors `anchor_height` is inside `commitment_anchor` and `outcome_height` is at record level, next to `outcome_time`. Reader reads `outcome_height` from the record, falling back to the anchor. Flip: yes, if a reader looked only inside `commitment_anchor`, both height vectors would have missing inputs; height-outcome-in-later-block would flip to failure.

13. **`height` rule and the outcome time.** Text: "No time and no tolerance." Reader ignores `outcome_time` under `height`. In height-outcome-in-later-block, `outcome_time` 1782654361 is EARLIER than `anchor_time` 1782654639 (header times are not ordered by height, as the README says). Flip: yes, a reader that also required a time check would fail that vector.

14. **`outcome_time` and `asserts_precedence` are not defined by the text.** The draft names `does_not_assert` and "the outcome" but never names a field for the outcome's time or for the record's precedence assertion. Reader takes `outcome_time` (Unix seconds) and `asserts_precedence` (only literal `true` counts) from the vectors. Flip: no, given these names; an absent `asserts_precedence` is read as not asserting.

15. **Precedence established and limitation also listed.** Not covered by the text (it only constrains the "Otherwise" case). Reader: conformant, with a note. Not in the vectors. Flip: no.

16. **Unknown `anchor_time_rule` or `digest_rule`.** Reader: establishes nothing. Not in the vectors. Flip: no.

17. **The anchor time itself.** The text says compare the mechanism's attested time to `anchor_time` with the mechanism's own verifier. Reader takes `anchor_time` as given and does not verify the proof. As an informational check only (not in reader.py): 38.ots begins with the OpenTimestamps magic, file hash op sha256 and the 32 bytes a42205d7...c663e9, matching `digest`, and contains one Bitcoin attestation at height 955810 (plus 4 pending calendar attestations). That agrees with `anchor_time_source` and `anchor_height`. The block time was not checked (no network).

## B. Things in the inputs the text does not mention

- `kind` labels: the README says "the requested pair, four negative controls, and five vectors for the other two ceiling rules" (2 + 4 + 5 = 11). The file labels 2 as `pair` and 9 as `negative_control`, including later-median-outcome-inside-old-tolerance and height-outcome-in-later-block, which reader finds conformant (precedence established). Reader ignores `kind`.
- `subject.sig` (Schnorr signature) is present but the text never asks for it to be verified; reader does not. In control-anchor-does-not-cover-record the signature is the original one, so it should not verify against the altered content (not checked: no Schnorr in the stdlib).
- `anchor_time_source` (block 955810 and its hash), `mechanism`, `proof_ref` are carried but not used by the rule.
- `subject.id` duplicates `digest`; not used (see A5).
- The time vectors' `outcome_time` values are synthetic per the README; the README's "median of 955811-955821 = 1782657732 = T + 3093" matches 1782654639 + 3093 = 1782657732. The README's second number (median of the 11 before 955810 = 1782651080) is not used by any vector.
- The 38.ots file carries pending calendar attestations besides the Bitcoin one; the text does not address them.
