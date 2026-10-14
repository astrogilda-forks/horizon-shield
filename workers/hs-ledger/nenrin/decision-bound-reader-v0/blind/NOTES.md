# What a BOUND verdict means

Does establish: decision_preimage hashes (my own RFC 8785 + SHA-256) to the stated decision_id, and the stated output hash equals SHA-256(JCS({content_sha256, decision_id, "decision-bound-output-v1"})). So the stated output hash depends on the full decision content and could not be computed without it.
Does not establish: that the content bytes hash to content_sha256 (bytes not in the record).
Does not establish: that the decision_preimage is authentic or complete (it comes from the same file, not a separate channel).
Does not establish: any wall-clock order, elapsed time, or that decision and output were not both fabricated together later.
Does not establish: single use of decision_id.
Does not establish: that the bound hash was produced at write time; the record says it is an after-the-fact "overlay".
Cross-field source checks (content hash, policy_id, timestamp) agree but are informational, not part of the verdict.
