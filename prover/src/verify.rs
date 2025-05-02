// Loads the verifying key, proof, and public input from disk.
// Verifies the proof using Groth16 and prints whether the result is valid.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;
use std::fs::File;
use std::io::BufReader;

pub fn verify_proof_from_files() -> Result<(), Box<dyn std::error::Error>> {
    let vk_file = File::open("../keys/verifying_key.bin")?;
    let proof_file = File::open("../proofs/proof.bin")?;
    let input_file = File::open("../proofs/public_input.bin")?;

    let vk: VerifyingKey<Bn254> = CanonicalDeserialize::deserialize_uncompressed(BufReader::new(vk_file))?;
    let proof: Proof<Bn254> = CanonicalDeserialize::deserialize_uncompressed(BufReader::new(proof_file))?;
    let public_input: Fr = CanonicalDeserialize::deserialize_uncompressed(BufReader::new(input_file))?;

    let pvk = prepare_verifying_key(&vk);
    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_input])?;

    println!("Proof is valid: {}", is_valid);
    Ok(())
}
