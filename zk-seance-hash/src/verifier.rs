#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use ark_bn254::Bn254;
use ark_ff::Field;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;

/// Deserialize a prepared verifying key, proof, and public inputs,
/// then run the Groth16 verifier. Returns true if the proof is valid.
pub fn verify_proof_bytes(
    pvk_bytes: &[u8],
    proof_bytes: &[u8],
    inputs_bytes: &[u8],
) -> bool {
    // 1) Deserialize the PreparedVerifyingKey
    let pvk = match PreparedVerifyingKey::<Bn254>::deserialize_uncompressed(pvk_bytes) {
        Ok(pvk) => pvk,
        Err(_) => return false,
    };
    // 2) Deserialize the Proof
    let proof = match Proof::<Bn254>::deserialize_uncompressed(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // 3) Deserialize public inputs (Fr) from inputs_bytes
    let mut inputs = Vec::new();
    let mut buf = inputs_bytes;
    while !buf.is_empty() {
        match <ark_bn254::Fr as CanonicalDeserialize>::deserialize_uncompressed(&mut buf) {
            Ok(f) => inputs.push(f),
            Err(_) => return false,
        }
    }
    // 4) Run the verifier
    Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::verify_proof_bytes;

    /// Should return false for completely empty byte slices
    #[test]
    fn test_empty_payload() {
        assert!(!verify_proof_bytes(&[], &[], &[]));
    }

    /// Should return false for arbitrary invalid data
    #[test]
    fn test_invalid_payload() {
        let pvk = [0u8; 16];
        let proof = [0xFFu8; 32];
        let inputs = [0xAAu8; 8];
        assert!(!verify_proof_bytes(&pvk, &proof, &inputs));
    }
}
