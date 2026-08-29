## Machine-readable policy evaluation

- add `scirust-verify-policy` for integrity-gated evaluation of finalized dossiers against JSON policy v1;
- bind each result to the exact policy bytes by SHA-256;
- preserve original claim verdicts without relabelling gaps or failures;
- fail closed on missing claims, invalid bounds, malformed evaluations, and dossier-integrity failures;
- add adversarial unit coverage and CI/Hub integration examples.
