// Minimal main.rs for CLI or test harness entrypoint.
// Core logic is moved to lib.rs for reuse across CLI, tests, and smart contract targets.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use rand::thread_rng;
use prover::circuit::MulCircuit;
use prover::utils::save_calldata;
use prover::utils::export_verifying_key_to_rs;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating zkSNARK proof and calldata...");

    // Inputs for circuit: proving that a * b = c
    let a = Fr::from(3u64);
    let b = Fr::from(4u64);
    let c = Fr::from(12u64);

    // Use one instance for setup, one for proving
    let setup_circuit = MulCircuit { a: Some(a), b: Some(b), c: Some(c) };
    let prove_circuit = MulCircuit { a: Some(a), b: Some(b), c: Some(c) };

    let mut rng = thread_rng();

    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(setup_circuit, &mut rng)?;
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(prove_circuit, &params, &mut rng)?;

    save_calldata(&proof, &c, "../calldata.bin")?;
    export_verifying_key_to_rs(&params.vk)?;

    println!("✅ Calldata written to ../calldata.bin");
    Ok(())
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
