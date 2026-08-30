# Machine-readable policy evaluation

SciRust-Verify can evaluate an already-finalized evidence dossier against a caller-supplied JSON acceptance policy.

This is **policy evaluation over recorded evidence**, not a new verification method and not a formal proof system. The original `VERIFIED`, `FAILED`, `NOT_VERIFIED`, `SKIPPED`, and `UNSUPPORTED` verdicts are preserved exactly.

## Command

```bash
scirust-verify-policy RUN_ID --policy policy.json --project . --json
```

Before consuming any policy input from a run, the command verifies the complete dossier integrity seal and requires the run to be finalized. A corrupted, incomplete, or missing dossier is never policy-accepted.

## Policy schema v1

Schema v1 is frozen and remains claim-only:

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
    }
  ]
}
```

A v1 document containing `execution_boundary` is rejected rather than silently changing the meaning of the published schema.

## Policy schema v2

Schema v2 keeps the same claim rules and can additionally require the exact execution-boundary declaration sealed in `environment.json`:

```json
{
  "schema_version": 2,
  "rules": [
    {
      "id": "tests",
      "claim": "tests_pass@cargo",
      "allowed_verdicts": ["verified"]
    }
  ],
  "execution_boundary": {
    "mechanism": "bubblewrap",
    "profile": "bubblewrap-v1",
    "assertion_scope": "producer_declared_not_attested"
  }
}
```

A v2 policy may contain claim rules, an `execution_boundary` requirement, or both. A completely empty v2 policy is rejected.

All three execution-boundary fields are exact-match requirements and are mandatory when the object is present. In particular, the caller must explicitly name `assertion_scope`. For the current bubblewrap launcher that scope is `producer_declared_not_attested`; matching it means the sealed dossier contains that producer declaration. It does **not** turn the declaration into kernel-backed or remote attestation.

## Claim-rule semantics

Unknown fields are rejected. Duplicate rule ids, empty selectors, empty accepted-verdict sets, zero `min_matches`, and contradictory match bounds are rejected.

`match_mode` defaults to `exact`. `allowed_verdicts` defaults to `["verified"]`. `min_matches` defaults to `1`.

For every rule, all matching evaluations must have an explicitly allowed verdict and the match count must remain inside the declared bounds. Missing evidence therefore fails closed rather than being silently ignored.

## Output and exit status

The JSON result binds the decision to:

- the exact run id;
- the policy schema version;
- the SHA-256 digest of the exact policy bytes;
- the number of files verified by the dossier seal;
- every matched claim id and its original verdict;
- the required and recorded execution-boundary objects when schema v2 uses them;
- per-rule and boundary reasons for non-satisfaction;
- an explicit trust-boundary statement.

Exit status is `0` only when every requested rule and provenance requirement is satisfied, `1` when valid sealed evidence does not satisfy the policy, `2` for an invalid policy document, and `3` for local filesystem/infrastructure errors.

## Trust boundary

A satisfied policy means only that the integrity-verified recorded claim evaluations and explicitly requested sealed provenance fields satisfy the caller-supplied acceptance rules.

It does **not** mean:

- empirical evidence became a formal proof;
- a single-host result became cross-platform evidence;
- a remote host or CI worker became trusted;
- a producer-declared execution boundary became independently attested;
- a dossier signature established signer identity or authorization;
- a `SKIPPED`, `NOT_VERIFIED`, or `UNSUPPORTED` verdict was upgraded to `VERIFIED`.

Signer trust, remote-host trust, artifact identity, actual isolation enforcement, and cross-platform scope remain separate trust decisions handled by their existing SciRust-Verify mechanisms.
