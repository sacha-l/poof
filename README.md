
## Architecture

```
Solidity Contract
      ↓ (EVM ↔ PolkaVM bridge / precompile call)
PolkaVM Rust Verifier Contract
      ↓ (RISC-V VM host functions)
ark-crypto-primitives Groth16 Verifier
      ↑
Poseidon + EC gadgets in no_std
```

## Overview

Circuit crate exposes a no_std verifier entrypoint.

PolkaVM contract embeds that verifier and parses calldata.

Solidity facade calls into PolkaVM as a “precompile.”

----

Poseidon‐preimage circuit (PoseidonHashCircuit in src/lib.rs):

Allocates a private secret and a public expected_hash.

Loads a PoseidonConfig<Fr> as a constant.

Runs CRHGadget::evaluate(...) and enforces equality.

We’ve already hand-tested it via a small R1CS “satisfied/unsatisfied” suite.

Byte-level verifier (verify_proof_bytes in src/verifier.rs):

No-std entry point that deserializes a PreparedVerifyingKey, Proof, and a blob of public-input bytes.

Calls Groth16::<Bn254>::verify_proof(...) and returns bool.

We’ve unit-tested it rejects empty/malformed inputs and (via integration tests) accepts a genuine proof and rejects a proof with the wrong public input.