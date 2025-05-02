use ark_bn254::{Fr};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use std::fs::File;
use std::io::Write;

pub fn save_proving_key(pk: &ProvingKey<ark_bn254::Bn254>) -> std::io::Result<()> {
    let mut file = File::create("../keys/proving_key.bin")?;
    pk.serialize_uncompressed(&mut file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;;
    Ok(())
}

pub fn save_verifying_key(vk: &VerifyingKey<ark_bn254::Bn254>) -> std::io::Result<()> {
    let mut file = File::create("../keys/verifying_key.bin")?;
    vk.serialize_uncompressed(&mut file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

pub fn save_proof(proof: &Proof<ark_bn254::Bn254>) -> std::io::Result<()> {
    let mut file = File::create("../proofs/proof.bin")?;
    proof.serialize_uncompressed(&mut file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

pub fn save_public_input(c: &Fr) -> std::io::Result<()> {
    let mut file = File::create("../proofs/public_input.bin")?;
    c.serialize_uncompressed(&mut file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}