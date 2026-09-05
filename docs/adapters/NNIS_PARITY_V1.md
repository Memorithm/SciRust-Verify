# NNIS NNML1 parity evidence adapter v1

SciRust-Verify consumes two immutable inputs for this boundary:

- `parity_evidence` — `application/vnd.nnis.nnml1.parity-evidence.v1+json`;
- `validation` — `application/vnd.nnis.nnml1.parity-validation.v1+json`, produced by `nnis.nnml1.parity-validation@1.0.0`.

The qualified NNIS source is PR #114, exact head `c74b6b04c45e320c86cdd973b31f49f43c720681`, merge `0ae4b0d4659c8de9b8a8322ed6ab7f8e110b53f2`.

## Verification scope

`scirust-verify-nnis-parity` independently:

1. hashes the exact original parity-evidence bytes;
2. requires the NNIS validation result to reference the same SHA-256 and evidence kind;
3. validates the NNIS validation contract, media type, schema, scope and exact execution Git commit linkage;
4. preserves checkpoint-spec names, NNIS parity levels, reference runtimes and execution backends as source observations;
5. rejects validation results that authorize promotion or assert serving/general-model-family claims;
6. includes the exact validation result inside the sealed dossier as a content-addressed attachment.

The dossier contract is:

```text
scirust-verify.nnis-parity-dossier@1.0.0
```

and the output media type is:

```text
application/vnd.scirust-verify.dossier.v1+tar
```

## Ownership boundary

NNIS remains authoritative for exact checkpoint identities, tokenizer identity, greedy-trajectory requirements, strict logit tolerances, same-head composition and runtime/model-family promotion policy. SciRust-Verify does not copy or reimplement those rules in this adapter.

A `VERIFIED` result from this process means only that the supplied bytes are correctly bound to a structurally qualified NNIS validation envelope and that the explicit non-claims were preserved. It is not a new CUDA/model execution, general model-family admission, cross-host portability result, serving-performance result, or promotion authorization.

Authenticating that the validation result was actually produced by the qualified NNIS process requires trusted orchestration/execution provenance, for example the separate versioned SciRust Hub component that invokes the pinned NNIS process.
