// Utility functions for serializing zkSNARK components to disk.
// Includes helpers to save:
// - Verifying key to ../keys/verifying_key.bin
// - zkSNARK proof to ../proofs/proof.bin
// - Public input to ../proofs/public_input.bin

use ark_bn254::{Fr};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_ff::PrimeField;
use std::fs::File;
use std::io::Write;
use ark_serialize::CanonicalSerialize;
use ark_ff::BigInteger;


pub fn save_proving_key(pk: &ProvingKey<ark_bn254::Bn254>) -> std::io::Result<()> {
    let mut file = File::create("../keys/proving_key.bin")?;
    pk.serialize_uncompressed(&mut file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

pub fn save_verifying_key(vk: &VerifyingKey<ark_bn254::Bn254>) -> std::io::Result<()> {
    let out_path = "../keys/verifying_key.bin";

    let mut buf = Vec::new();
    vk.serialize_uncompressed(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    println!("📦 Saved verifying key ({} bytes) to: {}", buf.len(), out_path);

    let mut file = File::create(out_path)?;
    file.write_all(&buf)?;
    Ok(())
}


pub fn save_proof(proof: &Proof<ark_bn254::Bn254>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let out_path = "../proofs/proof.bin";
    println!("🔍 Compressed proof size: {} bytes", buf.len());
    println!("📦 Saved proof to: {}", out_path);

    let mut file = File::create(out_path)?;
    file.write_all(&buf)?;
    Ok(())
}

pub fn save_public_input(c: &Fr) -> std::io::Result<()> {
    let out_path = "../proofs/public_input.bin";

    let mut buf = Vec::new();
    c.serialize_uncompressed(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    println!("📦 Saved public input ({} bytes) to: {}", buf.len(), out_path);

    let mut file = File::create(out_path)?;
    file.write_all(&buf)?;
    Ok(())
}


fn wrap_serialize_error<E: std::fmt::Display>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err))
}

pub fn save_calldata<F: PrimeField>(
    proof: &Proof<ark_bn254::Bn254>,
    public_input: &F,
    path: &str,
) -> std::io::Result<()> {
    let mut buf = Vec::new();

    // 4-byte dummy selector
    buf.extend_from_slice(&[0u8; 4]);

    // Compress and serialize Groth16 proof
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).map_err(wrap_serialize_error)?;
    assert_eq!(proof_bytes.len(), 128);
    buf.extend_from_slice(&proof_bytes);

    // Serialize public input
    let bytes = public_input.into_bigint().to_bytes_be();
    assert_eq!(bytes.len(), 32);
    buf.extend_from_slice(&bytes);

    // Final length check: 4 (selector) + 128 (proof) + 32 (input) = 164
    assert_eq!(buf.len(), 164);

    let mut file = File::create(path)?;
    file.write_all(&buf)?;

    println!("📦 Saved calldata ({} bytes) to: {}", buf.len(), path);

    Ok(())
}


pub fn export_verifying_key_to_rs(
    vk: &VerifyingKey<ark_bn254::Bn254>
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    std::fs::create_dir_all("../keys")?;
    std::fs::write(
        "../keys/verifying_key_bytes.rs",
        format!("pub const VERIFYING_KEY_BYTES: &[u8] = &{:?};", buf),
    )?;
    Ok(())
}
