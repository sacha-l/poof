// Entry point for generating and testing zkSNARK proofs for a * b = c.
// Contains unit tests for valid and invalid verification cases.
// Also includes a function to export the verifying key as a byte array for on-chain verifier use.

mod circuit;
mod utils;
mod verify;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;
use std::fs::{self, File};
use std::io::Write;
use circuit::MulCircuit;
use utils::{save_verifying_key, save_proof, save_public_input};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Run `cargo test -p prover` to execute zkSNARK tests.");
    Ok(())
}

/// Exports the verifying key as a Rust byte array source file for embedding in on-chain contracts.
pub fn export_verifying_key_to_rs() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("../keys").unwrap();
    let mut rng = thread_rng();

    let circuit = MulCircuit { a: None, b: None, c: None };
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)?;

    let mut vk_bytes = Vec::new();
    pk.vk.serialize_uncompressed(&mut vk_bytes)?;

    let mut out = File::create("../keys/verifying_key_bytes.rs")?;
    writeln!(out, "// Auto-generated verifying key byte array\npub const VERIFYING_KEY_BYTES: &[u8] = &[")?;
    for chunk in vk_bytes.chunks(16) {
        write!(out, "    ")?;
        for byte in chunk {
            write!(out, "0x{:02x}, ", byte)?;
        }
        writeln!(out)?;
    }
    writeln!(out, "];\n")?;

    println!("Verifying key exported to verifying_key_bytes.rs ({} bytes)", vk_bytes.len());
    Ok(())
}

// Steps for generating proofs in each test:
// 1. Define example witness values (a = 3, b = 4, c = 12)
// 2. Construct the circuit and generates a verifying key using reduction setup
// 3. Generate a Groth16 proof for the witness values
// 4. Serializes the verifying key, proof, and public input to disk
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof_verifies() {
        fs::create_dir_all("../keys").unwrap();
        fs::create_dir_all("../proofs").unwrap();

        let mut rng = thread_rng();

        let a = Fr::from(3u64);
        let b = Fr::from(4u64);
        let c = a * b;

        let circuit = MulCircuit { a: None, b: None, c: None };
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();

        save_verifying_key(&pk.vk).unwrap();

        let circuit_instance = MulCircuit {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        };

        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit_instance, &pk, &mut rng).unwrap();
        save_proof(&proof).unwrap();
        save_public_input(&c).unwrap();

        let pvk = prepare_verifying_key(&pk.vk);
        let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[c]).unwrap();
        assert!(is_valid, "Expected valid proof to verify successfully");
    }

    #[test]
    fn test_invalid_public_input_fails() {
        fs::create_dir_all("../keys").unwrap();
        fs::create_dir_all("../proofs").unwrap();

        let mut rng = thread_rng();

        let a = Fr::from(3u64);
        let b = Fr::from(4u64);
        let c = a * b;
        let invalid_c = Fr::from(999u64);

        let circuit = MulCircuit { a: None, b: None, c: None };
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();

        let circuit_instance = MulCircuit {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        };

        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit_instance, &pk, &mut rng).unwrap();

        let pvk = prepare_verifying_key(&pk.vk);
        let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[invalid_c]).unwrap();
        assert!(!is_valid, "Expected invalid proof to fail verification");
    }

    #[test]
    fn test_export_verifying_key_to_rs() {
        export_verifying_key_to_rs().unwrap();
        assert!(std::path::Path::new("../keys/verifying_key_bytes.rs").exists());
    }
}
