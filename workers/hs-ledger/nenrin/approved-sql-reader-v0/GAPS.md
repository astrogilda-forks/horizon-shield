# GAPS: places where INPUT-CONTRACT.md did not decide for me

Source used: only `fence/INPUT-CONTRACT.md` and `fence/fixtures/*.json`.
Each entry: the contract text (or "silent"), what `reader.py` does, and whether another reasonable reading changes any fixture's `result` or exit code.

## Result names

Named verbatim in the contract: `recorded_commit_matches`, `no_match_in_declared_complete_scope`.

Spelled by me from contract prose (the contract has the idea but no token):

- `insufficient_evidence` (from "produces insufficient evidence")
- `ambiguous` (from "More than one matching record is ambiguous")

Invented by me (the contract has neither the idea as a result nor a token):

- `approval_not_granted`
- `call_differs_from_approval`
- `application_disagrees_with_audit`
- `recorded_outcome_not_successful_commit`
- `invalid_input` (printed on exit 2)

Invented `later_state` output values: `not_supplied`, `unchanged`, `changed`.

### G1. Token for "insufficient evidence"
Contract: "An empty incomplete or differently scoped collection produces insufficient evidence."
Chosen: `insufficient_evidence`. Another spelling changes the `result` string of approved-audit-incomplete and application-record-missing (see G7), never an exit code.

### G2. Token for "ambiguous"
Contract: "More than one matching record is ambiguous."
Chosen: `ambiguous`. Another spelling (for example with a suffix) changes the `result` string of ambiguous-execution only; exit stays 1.

### G3. `approval.granted: false`
Contract: "`approval.granted` | An actual JSON boolean. It is not an authenticated approval." Silent on what `false` does to the result. The definition of `recorded_commit_matches` ("those supplied records agree and their supplied outcome says successful and committed") does not mention `granted`.
Chosen: `approval_not_granted`, checked first after validation, exit 1.
Other reading: because the definition of `recorded_commit_matches` lists only record agreement and outcome, a reader could ignore `granted`. Then approval-not-granted (otherwise identical to matching-commit) would return `recorded_commit_matches` and **exit 0 instead of 1**. This is the most consequential gap.

### G4. Audit record disagrees with approval
Contract: "A matching record must agree with approval on SQL bytes, typed parameters, every target field, and the principal." Silent on the result name.
Chosen: one name `call_differs_from_approval` plus a `differing_fields` list. Other reading: one name per field (sql, parameters, instance, schema, principal). Changes the `result` strings of the five different-* fixtures, not their exit 1.

### G5. Application disagrees with audit
Contract: "The application record must also agree with the audit on the request and outcome." Silent on the result name.
Chosen: `application_disagrees_with_audit` with `differing_fields` and both outcomes echoed. Affects outcome-disagreement's `result` string only; exit 1 under any reading.

### G6. Agreeing records whose outcome is not succeeded + committed
Contract: "The reader preserves the two claims separately. It does not infer a commit from a successful statement." Silent on the result name.
Chosen: one name `recorded_outcome_not_successful_commit`, with `recorded_outcome.statement` and `recorded_outcome.transaction` reported separately. Other reading: separate names for failed / rolled back / unknown. Changes the `result` strings of statement-failed, rolled-back, commit-unknown; exit stays 1.

### G7. `application: null`
Contract: "`application` | The supplied application call and outcome, or `null` for an absent record." Silent on the result when the audit matches and the application is absent.
Chosen: `insufficient_evidence` with `reason: application_record_absent`, exit 1.
Other readings: (a) a dedicated invented name (string change only); (b) "those supplied records agree" could be read as "whatever records were supplied agree", so an absent application does not block the match. Reading (b) turns application-record-missing into `recorded_commit_matches` and **exit 0 instead of 1**.

### G8. Order of checks
Contract: silent on precedence.
Chosen order: validation, `granted`, audit join (ambiguous / no match / insufficient), approval vs audit fields, application presence, application vs audit, outcome.
Other reading: checking application presence before the audit join would turn approved-no-match-declared-scope (whose application is null) into `insufficient_evidence` instead of `no_match_in_declared_complete_scope`; exit stays 1. The fixture name suggests my order. Approval mismatch before application disagreement: no fixture has both.

### G9. Meaning of "agree with the audit on the request"
Contract: "The application record must also agree with the audit on the request and outcome."
Chosen: "request" = the whole call (request_id, SQL bytes, parameters, target, principal), mirroring the table's description of `approval.call` as "The request identifier, exact SQL bytes, ...". Other reading: only `request_id`. In every fixture the application call equals the audit call, so no change.

### G10. Parsing "An empty incomplete or differently scoped collection"
Chosen: completeness and scope only matter when no record joins. Zero joined records and (not complete or scope differs) gives `insufficient_evidence`, whether or not the collection holds records for other requests. An incomplete collection with exactly one joined record is evaluated normally.
Other reading: any incomplete collection yields `insufficient_evidence`, even with a match. No fixture combines `complete: false` with a record, so no change.

### G11. What "differently scoped" means
Contract: "`audit.scope` | The declared request, target, and a nonempty window label." and "No matching event in a declared complete, matching scope".
Chosen: scope matches when `scope.request_id` equals the approval request_id and all three `scope.target` fields equal the approval target. `window_label` has nothing to be compared against, so it is only required nonempty and echoed. A scope mismatch does not block evaluation of a joined record.
Other reading: scope mismatch always gives `insufficient_evidence`. No fixture has a differing scope, so no change.

### G12. Ambiguity details
Contract: "More than one matching record is ambiguous."
Chosen: more than one record with the approval's request_id is `ambiguous` regardless of completeness, scope, or whether the records are identical apart from `event_id`, and before any field comparison. No reasonable alternative changes ambiguous-execution's exit.

### G13. Comparison of typed parameters
Contract: "ordered typed parameters", "an opaque `database_type`", "`value_b64: null` means SQL NULL. An empty base64 string means empty bytes. The two remain distinct."
Chosen: compare the ordered list of (position, database_type as exact case-sensitive string, decoded bytes or NULL). NULL never equals empty bytes. No fixture differs only in type or NULL-vs-empty, so no change.

### G14. Order of parameter positions
Contract: "Each parameter has consecutive `position` values starting at 1".
Chosen: the array element at index i must have position i+1 (order and consecutiveness both enforced). Other reading: positions form the set 1..n in any array order, sorted before comparing. All fixtures are in order; no change.

### G15. What the reader prints for `later_state`
Contract: "`later_state` | A target, resource label, bytes supplied as the at-commit state, and later bytes. Use `null` when absent." and "A later byte difference leaves an earlier matching commit result intact." Silent on the output form.
Chosen: output `later_state` is `not_supplied` (input null), `unchanged` (bytes equal) or `changed` (bytes differ), plus `later_state_detail` with `resource`, `target_matches_approval`, `bytes_differ`. It never alters `result`. Other output forms (echoing the input object, null, a boolean) change the `later_state` value in results.json for every fixture but never `result` or exit.

### G16. `later_state` internals
Contract: silent on whether `later_state.target` must equal the approval target, whether the bytes may be null, and whether `at_commit` must match a parameter value.
Chosen: target difference is reported (`target_matches_approval`), not rejected; `at_commit_b64` and `later_b64` must be canonical base64 strings (null rejected as invalid); `resource` must be a nonempty string; `at_commit` is not compared with approval parameters. Only matching-commit-later-change has a later_state and it passes under every reading.

### G17. `later_change_attribution`
Contract: "`later_change_attribution` always remains `not_assessed`."
Chosen: always emitted as `not_assessed`, including when `later_state` is null and for non-matching results (not on exit 2). No effect on results.json fields.

### G18. Output on invalid input
Contract: "the CLI returns ... 2 for invalid input." Silent on stdout.
Chosen: print `{"result": "invalid_input", "later_state": null, "error": ...}`. Usage errors (wrong argument count) and unreadable files also exit 2. No fixture is invalid.

### G19. Nonempty strings
Contract requires nonempty only for the window label ("a nonempty window label").
Chosen: also nonempty `request_id` (both in calls and scope), `event_id`, `executing_principal`, `database_type`, `later_state.resource`. Target strings (`instance`, `database`, `schema`) may be empty ("exact ... strings"). Other reading: only window_label nonempty. All fixtures pass either way.

### G20. Empty SQL and empty parameter lists
Contract: silent.
Chosen: empty SQL bytes (`""`) and `parameters: []` are accepted. No fixture uses them.

### G21. "Canonical base64" and UTF-8
Contract: "SQL uses canonical base64 of exact UTF-8 bytes. Spaces and Unicode forms stay distinct."
Chosen: canonical = RFC 4648 standard alphabet, `=` padding required, no whitespace or line breaks, zero padding bits (re-encoding must reproduce the string). The same rule is applied to `value_b64`, `at_commit_b64`, `later_b64` (contract says "canonical" only for SQL). SQL bytes must decode as strict UTF-8; no Unicode normalization; comparison is on bytes. Parameter values may be any bytes. All fixtures pass.

### G22. JSON-level strictness
Contract: "Every object must contain exactly its declared keys." Silent on duplicate keys, NaN/Infinity, BOM, number types.
Chosen: duplicate object keys, `NaN`/`Infinity`, a UTF-8 BOM and non-UTF-8 files are invalid; `position` must be a JSON integer (not `1.0`, not `true`); booleans must be JSON `true`/`false` (not 0/1 or strings). All fixtures pass.

### G23. `executing_principal` and the mapping rule
Contract: "Do not fill that field from an application user identifier without an established native mapping." and "Unknown fields remain unknown."
Chosen: the reader cannot check where the value came from, so it only requires a nonempty string; `null` (an "unknown" principal) is rejected as invalid rather than treated as unknown. Other reading: allow null and make the result non-matching. No fixture has a null principal.

### G24. Records whose request_id differs from the scope's request_id
Contract: silent.
Chosen: allowed; they simply do not join. No fixture has one.

### G25. Native section
Contract: "Native work needs one versioned Settle approval ... Connecting a native format is a separate adapter task".
Chosen: not implemented; `origin` must equal `author-created-fixture` and `profile` must equal `oel-approved-sql-illustration/v1` exactly. No fixture effect.

## Summary

25 gaps. Readings that would change an exit code on the given fixtures: G3 (approval-not-granted 1 to 0) and G7 (application-record-missing 1 to 0). All other gaps change at most result or later_state strings.
