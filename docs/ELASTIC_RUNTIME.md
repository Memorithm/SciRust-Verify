# ElasticXxx runtime evidence integration

SciRust-Verify publishes a narrow source-preserving adapter and process contract for the ElasticXxx runtime evidence produced by `elastic.hub.run@1.0.0`.

## Source contract

Qualified source:

- repository: `Memorithm/ElasticXxx`
- process contract: `elastic.hub.run@1.0.0`
- evidence schema: `elastic-runtime-evidence-v1`
- media type: `application/vnd.elastic.runtime-evidence.v1+json`
- source PR: `#54`
- source final exact head: `571d0deb8921df54502fbb35909dd8830cbf4fb4`
- source merge: `9e51879b96e54c812b6a265fe5901e960bbe6250`
- source CI: `#211` success on the repository's trusted ARM64 runner

## Verify process

```text
scirust-verify-elastic \
  --evidence <elastic-runtime-evidence.json> \
  --output <new-dossier.tar>
```

Process contract: `scirust-verify.elastic-runtime-dossier@1.0.0`.

The output is an integrity-sealed `application/vnd.scirust-verify.dossier.v1+tar` artifact suitable for SciRust Hub content-addressed ingestion.

## Independent checks

The adapter independently checks the bounded file and JSON shape, exact evidence schema, `command=run`, `source=operator-config`, `config_version=1`, bounded controller/cycle/event structure, unique resource identities, and consistency between the source `committed`/`rolled_back` flags and matching `CommitExecuted`/`RollbackExecuted` events.

The only SciRust-Verify `VERIFIED` claim produced by this process is structural evidence-contract conformance.

## Ownership boundary

ElasticXxx owns observation, forecasting, planning, validation, actuation, post-actuation verification and COMMIT/ROLLBACK semantics. A runtime COMMIT or ROLLBACK is retained as an observation inside the Verify dossier. It is not itself a SciRust-Verify verdict.

SciRust-Verify owns the dossier, integrity seal, source-preserving normalization, scoped structural claim, limitations and resulting Verify verdict for that structural claim.

SciRust Hub may invoke both the Elastic runtime and this Verify process as separate versioned components and retain their outputs as immutable artifacts. Hub must not recompute either Elastic policy or Verify verdict semantics.

## Non-claims

A successful dossier does not establish resource-policy optimality, model quality, performance superiority, cross-host comparability, hardware portability, sandboxing, distributed correctness, or ML maturity 5/5. Those require separate executed evidence and explicit claims.
