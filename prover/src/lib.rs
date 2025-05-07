// Core zkSNARK logic for proof generation, verification, and key export.
// Designed for use across CLI, tests, and embedded smart contract targets.

// Includes:
// - `generate_proof`: produces a Groth16 proof and public output for a * b = c
// - `verify_proof`: checks validity of a proof against a verifying key
// - `export_verifying_key_to_rs`: outputs verifying key as a Rust byte array for embedding
// - `load_verifying_key_from_file`: loads a verifying key from a binary file

pub mod circuit;
pub mod utils;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use std::fs::{self, File};
use std::io::{BufReader, Write};

use crate::circuit::MulCircuit;

/// Generate a Groth16 proof for a * b = c
pub fn generate_proof(a: u64, b: u64) -> Result<(Proof<Bn254>, Fr, ProvingKey<Bn254>), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let a_fr = Fr::from(a);
    let b_fr = Fr::from(b);
    let c = a_fr * b_fr;

    let circuit = MulCircuit { a: None, b: None, c: None };
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)?;

    let instance = MulCircuit {
        a: Some(a_fr),
        b: Some(b_fr),
        c: Some(c),
    };

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(instance, &pk, &mut rng)?;
    Ok((proof, c, pk))
}

/// Verify a Groth16 proof against public input c
pub fn verify_proof(proof: &Proof<Bn254>, c: Fr, vk: &VerifyingKey<Bn254>) -> Result<bool, Box<dyn std::error::Error>> {
    let pvk = prepare_verifying_key(vk);
    let result = Groth16::<Bn254>::verify_proof(&pvk, proof, &[c])?;
    Ok(result)
}

/// Export verifying key to a byte array source file for on-chain embedding
pub fn export_verifying_key_to_rs(vk: &VerifyingKey<Bn254>) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("../keys")?;

    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes)?;

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

    Ok(())
}

/// Load a verifying key from a binary file
pub fn load_verifying_key_from_file(path: &str) -> Result<VerifyingKey<Bn254>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(reader)?;
    Ok(vk)
}
