// Entry point for generating a zkSNARK proof for a * b = c.
// 1. Defines example witness values (a = 3, b = 4, c = 12)
// 2. Constructs the circuit and generates a verifying key using reduction setup
// 3. Generates a Groth16 proof for the witness values
// 4. Serializes the verifying key, proof, and public input to disk

mod circuit;
mod utils;
mod verify;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use rand::thread_rng;
use std::fs;
use circuit::MulCircuit;
use utils::{save_verifying_key, save_proof, save_public_input};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure output directories exist
    fs::create_dir_all("../keys")?;
    fs::create_dir_all("../proofs")?;

    let mut rng = thread_rng();

    // Sample inputs
    let a = Fr::from(3u64);
    let b = Fr::from(4u64);
    let c = a * b;

    // Generate verifying key (only) from reduction setup
    let circuit = MulCircuit { a: None, b: None, c: None };
    let vk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)?;

    save_verifying_key(&vk.vk)?;

    // Create a proof with real inputs
    let circuit_instance = MulCircuit {
        a: Some(a),
        b: Some(b),
        c: Some(c),
    };

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit_instance, &vk, &mut rng)?;
    save_proof(&proof)?;
    save_public_input(&c)?;

    println!("Proof generated and saved.");

    // Optional: Immediately verify proof after creation (off-chain)
    verify::verify_proof_from_files()?;

    Ok(())
}

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
}
