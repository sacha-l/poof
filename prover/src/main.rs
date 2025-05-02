mod circuit;
mod utils;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use rand::thread_rng;
use circuit::MulCircuit;
use utils::{save_verifying_key, save_proof, save_public_input};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}
