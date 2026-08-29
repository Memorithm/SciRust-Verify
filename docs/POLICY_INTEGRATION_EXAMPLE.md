# Policy integration example

A CI or Hub consumer can first collect/import a finalized dossier, then evaluate an explicit policy without re-running the project:

```bash
cargo run -p scirust-verify-cli --bin scirust-verify-policy -- \
  RUN_ID \
  --project /path/to/project \
  --policy examples/policy.v1.json \
  --json
```

The policy evaluator verifies the dossier seal before reading `evaluations.json`. Its exit code can gate deployment or promotion, while the JSON output remains suitable for machine consumption.

This command does not modify the dossier, does not create new scientific verdicts, and does not infer trust in the machine that produced the evidence.
