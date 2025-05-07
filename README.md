
<p align="center">
  <img src="assets/poof-banner.png" alt="Poof." width="60%">
</p>

_Poof_ provides a framework to easily build and deploy applications that require zero-knowledge proofs.

As an initial "poof-of-concept", users are able to use a CLI to generate and verify Groth16 proofs for a simple multiplication circuit. Once their verifying key is generated, they can run a script to deploy their verifier contract on-chain along with a Solidity business logic contract designed to call into the verifier and to make it easy to build a user facing interfact. 

Poof is the first step forward towards making it easy for anyone to build and deploy ZK applications that run directly on the PVM.

## How it works

A prover generates a proof and submits calldata to the verifier contract which uses the [arkworks](https://arkworks.rs/) ecosystem of libraries to verify Groth16 zkSNARK proofs over the BN254 curve. The contract returns "true" if the the proof is valid. 

The example circuit being used is a simple multiplication circuit a * b = c whereby the value c is publicly known and the prover proves they know values a and b without revealing them.

There are two types of users:

- Users deploying the verifier system. To do this, run the provided script `deploy_verifier.sh`.
- Users who want to generate a proof to submit to a known verifier. To do this, run `generate_proof_offline.sh`.

### Proving system 

- A user (prover) who knows a and b such that a * b = c calls `cargo run -- prove --a 3 --b 4 --c 12`
- Generates a Groth16 proof using the proving key (128 bytes), serializes the proof (128-bytes) and public input c (32 bytes) and writes a 164-byte ABI-compatible calldata
- The user sends a call to a deployed contract: `cast call $VERIFIER_CONTRACT --data 0x$(xxd -p calldata.bin | tr -d '\n')`
- The verifier contract deserializes the proof and input and reconstructs the verifying key from the embedded bytes and returns a 32-byte bool (true = valid, false = invalid)

### Verifier contract 

- `prover/src/circuit.rs` defines a constraint system (e.g., a * b = c) using ark-r1cs.
- `ark-groth16::generate_random_parameters_with_reduction()` is used to generate:
   - A `ProvingKey` (which contains toxic waste values in obfuscated form).
   - A `VerifyingKey` (which is public and goes on-chain).
- The verifying key is embedded into a Rust contract targeting the Polkadot Virtual Machine (PVM).
- The Rust contract deserializes the proof and verifying key and performs the verification.

A Solidity wrapper contract designed to call into the Rust contract provides the entry point for application interfaces to submit proofs and make it easy to extend any user facing business logic.

## Assumptions

- You as a developer runs the trusted setup, implying a trust assumption. That being said, with ark-groth16 `generate_random_parameters_with_reduction` you'd have to modify the function in order to expose the toxic waste.
- Users generate their own proofs offchain.
- Contract contains the correct verifying key (VK) and wasn't tampered with.
- Prover and verifier must agree on the exact circuit logic, its for the application-specifc business logic to define how incentives can be best aligned.
- Verification key is a fixed size

##  Challenges
- Needing to use an allocator in the Rust contract
- Even a dummy allocator (like one returning null_mut()) will not work, because the PVM trap system interprets any such call as undefined memory behavior, and your contract gets ContractTrapped.
- All deserialization, proof verification, and cryptographic work must not allocate at runtime

## CLI

The library comes with a CLI tool to easily pass in inputs for generating proofs and verification locally.

Run proof:

```sh
cargo run -p zkcli prove --a 3 --b 4 --c 12
```

Verify proof:

```sh
cargo run -p zkcli -- \
  verify \
  --proof  ../proofs/proof.bin \
  --input  ../proofs/public_input.bin \
  --vk     ../keys/verifying_key.bin
```

Run script for deploying the verifier contract:

```sh
./deploy_verifier.sh
```

Run script for submitting the proof:

```sh
./verify_proof.sh
```

## Application circuits to explore

### Games

**"You can come camping"**. Verifier contract is deployed by the "leader" who crafts a circuit according to their constraint. A Solidity contract handles the game logic such as duration of rounds, minimum number of proofs to be "allowed to come camping", rewards etc. Leader can deploy the verifier along with a clue (e.g. constraint is that it must be a three letter word and the clue is "one, two, ?"). Circuit implementation can get fancy by constaining a circuit to a list of words from a specific category.
This could even be a game where the business logic (on the Solidity side) allows the "leader" to deposit an amount of funds that provers can win if they submit the correct proofs. And provers also deposit a small amount to play which get put in the pot of funds where some disbursement mechanism ensures fair distribution of funds.

**"Word to mouth inviations"**. Verifier contract is deployed designed to verify whether a prover has a specific code. Business logic handles sending invites out. Codes are only given offline, word to mouth to invitees. The app sends an invitation NFT for participants who submit correct proofs.


**"Deniable messaging"**.


## Future direction

## Add different zk proving schemes to the `prover` library

These could include:
- Plonk (Bellman-CE, zk Plonk, Plonky2)
- Marlin 


### Make it easy to add new circuits

To add new circuits you'd define them in `proof/src/circuits.rs`:

```rust
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_bn254::Fr;

pub trait CircuitDefinition {
    fn name(&self) -> &'static str;
    fn setup_instance(&self) -> Box<dyn ConstraintSynthesizer<Fr>>;
    fn proving_instance(&self) -> Box<dyn ConstraintSynthesizer<Fr>>;
    fn public_inputs(&self) -> Vec<Fr>;
}
```

And then use the CLI to call specific circuits passing in parameters directly:

```bash
zk-cli prove --multiplication --a 3 --b 4 --c 12
```

### Turn into self hosted client software

Make it a self-hosted P2P based app. This would open up possibilities to run applications that don't require public verifiers. Also, it could add improvements to:
- Key management issues
- Extending nodes so they can store proofs
- Create products for network nodes, building community around deploying verifier contracts and hosting infrastructure to power the application UX
- Add functionality to launch p2p relayers

Here's an example of extending the Poof framework to a libp2p node:

```ascii
             +----------------------+
             |   Client App &      |
             |   libp2p Node       |
             |  • PubSub Subscribe |
             |  • Local Store      |
             +----------------------+
                       │
         (1) Publish   │  zk‐boxed message
          epk,C,Π      ▼
             +----------------------+
             |  Relay libp2p Node   |
             |  • PubSub Gossip     |
             |  • Simple Store      |
             +----------------------+
                       │
    (2) Gossip & cache │
                       ▼
             +----------------------+
             | Client App &        |
             | libp2p Node         |
             | • Receive & Store   |
             | • Notify UI         |
             +----------------------+
                       │
        (3) User taps  │
        “Open Box”     ▼
             +----------------------+
             | Offchain Prover     |
             | • Generate Π        |
             | • Export VK / CRS   |
             +----------------------+
                       │
           (4) Verify & decrypt  
                       ▼
             +----------------------+
             |  Verifier Contract   |
             |  (on‐chain)          |
             +----------------------+
```


