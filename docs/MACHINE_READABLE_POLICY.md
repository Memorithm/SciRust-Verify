# Machine-readable policy evaluation

SciRust-Verify can evaluate an already-finalized evidence dossier against a caller-supplied JSON acceptance policy.

This is **policy evaluation over recorded evidence**, not a new verification method and not a formal proof system. The original `VERIFIED`, `FAILED`, `NOT_VERIFIED`, `SKIPPED`, and `UNSUPPORTED` verdicts are preserved exactly.

## Command

```bash
scirust-verify-policy RUN_ID --policy policy.json --project . --json
```

Before consuming any claim evaluation, the command verifies the complete dossier integrity seal and requires the run to be finalized. A corrupted, incomplete, or missing dossier is never policy-accepted.

## Policy schema v1

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "tests",
      "claim": "tests_pass@cargo",
      "match_mode": "exact",
      "allowed_verdicts": ["verified"],
      "min_matches": 1,
      "max_matches": 1
    },
    {
      "id": "numeric-suite",
      "claim": "numerically_close",
      "match_mode": "contains",
      "allowed_verdicts": ["verified"],
      "min_matches": 2
    }
  ]
}
```

Unknown fields are rejected. Empty policies, duplicate rule ids, empty selectors, empty accepted-verdict sets, zero `min_matches`, and contradictory match bounds are rejected.

`match_mode` defaults to `exact`. `allowed_verdicts` defaults to `["verified"]`. `min_matches` defaults to `1`.

For every rule, all matching evaluations must have an explicitly allowed verdict and the match count must remain inside the declared bounds. Missing evidence therefore fails closed rather than being silently ignored.

## Output and exit status

The JSON result binds the decision to:

- the exact run id;
- the SHA-256 digest of the policy bytes;
- the number of files verified by the dossier seal;
- every matched claim id and its original verdict;
- per-rule reasons for non-satisfaction;
- an explicit trust-boundary statement.

Exit status is `0` only when every rule is satisfied, `1` when valid sealed evidence does not satisfy the policy, `2` for an invalid policy document, and `3` for local filesystem/infrastructure errors.

## Trust boundary

A satisfied policy means only:

> The integrity-verified recorded claim evaluations in this dossier satisfy these caller-supplied acceptance rules.

It does **not** mean:

- empirical evidence became a formal proof;
- a single-host result became cross-platform evidence;
- a remote host or CI worker became trusted;
- a dossier signature established signer identity or authorization;
- a `SKIPPED`, `NOT_VERIFIED`, or `UNSUPPORTED` verdict was upgraded to `VERIFIED`.

Signer trust, remote-host trust, artifact identity, and cross-platform scope remain separate trust decisions handled by their existing SciRust-Verify mechanisms.
