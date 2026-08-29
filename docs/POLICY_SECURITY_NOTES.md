# Policy evaluator security notes

The policy evaluator consumes only finalized SciRust-Verify dossiers whose `bundle.json` integrity verification succeeds.

The policy file is configuration, not evidence. Its exact input bytes are SHA-256 digested into the result so an external caller can bind a policy decision to the policy document it supplied.

A policy cannot invent evidence: every rule must match at least one recorded claim evaluation. Rules accept explicit original verdicts only. No implicit conversion exists between `SKIPPED`, `UNSUPPORTED`, `NOT_VERIFIED`, `FAILED`, and `VERIFIED`.

A permissive policy may explicitly accept states such as `skipped`; that is an acceptance decision made by the caller, not a change to the recorded SciRust-Verify verdict.
