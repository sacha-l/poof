
_Poof_ started as an experiment to explore what's possible on the upcoming Polkadot Hub powered by the PVM (Polkadot Virtual Machine).

It provides the framework for anyone to deploy a deniable messaging app powered by zero-knowledge “invisible stamps.” 
Using inivisible stamps, anyone can send a message in the open and "poof" &mdash; only the intended recipient can decrypt it and verify its sender.
But the receiver can also make an exact same copy of that encrypted message meaning that no-one can actually prove who sent the message.


## Architecture

```ascii

[User Device / CLI]
   |
   | 1. Inputs:
   |   - message: "The eagle lands at dawn"
   |   - recipient: @agent47
   |
   ▼
╭────────────────────────────╮
│        Prover CLI Tool     │  ◄── `zkcli prove --message "..." --recipient ...`
│  (ephemeral encryption +   │
│   zkSNARK generation)      │
╰────────────┬───────────────╯
             │
             │ Output: `spirit box`
             │   {
             │     proof,
             │     ephemeral_pubkey,
             │     ciphertext (AES-GCM),
             │     recipient_id,
             │     optional commitment hash
             │   }
             │
             ▼
  ╭──────────────────────────────────╮
  │     Spirit Box Delivery Layer    │  ◄── P2P, Matrix, Whisper, IPFS, contract mailbox
  ╰──────────────────────────────────╯
             │
             ▼
  ╭──────────────────────────────────╮
  │        Recipient Client App      │  ◄── recipient opens spirit box
  │ - Uses their secret key          │
  │ - Decrypts message via ECDH + AES│
  │ - Simulates SNARK verifier       │
  │   to privately verify sender     │
  ╰──────────────────────────────────╯
             │
             ▼
╭────────────────────────────────────────────────╮
│  [Optional] Public Verifiability (on-chain)    │
│   - Recipient hashes message + proof           │
│   - Submits proof to contract (PVM)            │
│   - Verifier returns true/false                │
╰────────────────────────────────────────────────╯
```

## UX Overview

For Poof, the zk-seance deniable messaging app, I envision a UX around using a simple mailbox. 

- **Magic Box & Keys**: Sender generates a one-time (ephemeral) keypair and encrypts the message under a shared secret (Diffie–Hellman with the receiver’s long-term public key). Receiver holds a long-term private key that both derives the shared secret and verifies proofs.
- **Invisible Stamp (ZK Proof)**: Sender attaches a zero-knowledge proof (“the stamp”) attesting that the ciphertext was correctly formed under their ephemeral key and the receiver’s public key. This is a designated-verifier proof: only the receiver can check it, and only they can simulate identical proofs themselves
- **Mailbox Notification**: When the sender pushes (epk, C, Π) to the relay/server for the receiver, the server marks “unread” for that mailbox. A WebSocket event flips the on-screen mailbox lamp from “off” to “glowing,” letting the receiver know there’s something waiting.
- **Opening & Reading**: Receiver clicks the mailbox, uses their private key to verify the proof, and—if valid—decrypts the message. All this happens without leaking sender identity or message contents to anyone else.

## Future plans

### Turn into self hosted app

Make it a self-hosted P2P based app so that users can send messages on the network, store messages locally, have better key management and use verifier periodically. 

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
             |  (optional on‐chain) |
             +----------------------+
```

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

### CLI

- Make it easy to deploy contracts
- To verify proofs: `zkcli verify --proof ./proof.bin --vk ./verifying_key.bin` 
- To export verificaiton key: `zkcli export-vk --circuit mul`
- To generate calldata: `zkcli calldata --proof ./proof.bin --input ./input.bin`

