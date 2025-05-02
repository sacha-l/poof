// Minimal main.rs for CLI or test harness entrypoint.
// Core logic is moved to lib.rs for reuse across CLI, tests, and smart contract targets.

use prover::{generate_proof, verify_proof, export_verifying_key_to_rs};
use ark_bn254::Bn254;

fn main() {
    println!("Run `cargo test -p prover` to test, or use the library via CLI integration.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use prover::load_verifying_key_from_file;

    #[test]
    fn test_valid_proof_verifies() {
        let (proof, c, pk) = generate_proof(3, 4).expect("proof generation failed");

        let is_valid = verify_proof(&proof, c, &pk.vk).expect("verification failed");
        assert!(is_valid, "Expected valid proof to verify successfully");
    }

    #[test]
    fn test_invalid_public_input_fails() {
        let (proof, _c, pk) = generate_proof(3, 4).expect("proof generation failed");
        let invalid_c = Fr::from(999u64);

        let is_valid = verify_proof(&proof, invalid_c, &pk.vk).expect("verification failed");
        assert!(!is_valid, "Expected invalid proof to fail verification");
    }

    #[test]
    fn test_export_verifying_key_to_rs() {
        let (_proof, _c, pk) = generate_proof(3, 4).expect("proof generation failed");
        export_verifying_key_to_rs(&pk.vk).expect("export failed");
        assert!(std::path::Path::new("../keys/verifying_key_bytes.rs").exists());
    }
}
