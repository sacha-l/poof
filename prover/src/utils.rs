// Utility functions for serializing zkSNARK components to disk.
// Includes helpers to save:
// - Verifying key to ../keys/verifying_key.bin
// - zkSNARK proof to ../proofs/proof.bin
// - Public input to ../proofs/public_input.bin
// - calldata to ../calldata.bin

use ark_bn254::{Fr};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_ff::PrimeField;
use std::fs::File;
use std::io::Write;
use ark_serialize::CanonicalSerialize;
use ark_ff::BigInteger;
use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_bn254::Bn254;
use sha3::{Digest, Keccak256};
use std::fs;


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
    proof: &Proof<Bn254>,
    public_input: &F,
    path: &str,
) -> std::io::Result<()> {
    // Generate function selector for verifyProofFromCalldata(bytes)
    let function_sig = "verifyProofFromCalldata(bytes)";
    let mut hasher = Keccak256::new();
    hasher.update(function_sig.as_bytes());
    let hash = hasher.finalize();
    let function_selector = &hash[0..4];
    
    println!("Function selector: 0x{}", hex::encode(function_selector));
    
    // Prepare the inner data that will be ABI-encoded as bytes
    let mut inner_data = Vec::new();
    
    // Add proof components (uint[2], uint[2][2], uint[2], uint)
    // uint[2] a
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.a.x));
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.a.y));
    
    // uint[2][2] b - FIXED: Correct coordinate order for Ethereum
    // Ethereum expects G2 coordinates as [x.c1, x.c0, y.c1, y.c0]
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.x.c1)); // x1 first
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.x.c0)); // x0 second  
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.y.c1)); // y1 first
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.y.c0)); // y0 second
    
    // uint[2] c
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.c.x));
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.c.y));
    
    // uint input0
    let input_bytes = public_input.into_bigint().to_bytes_be();
    inner_data.extend_from_slice(&pad_to_32_bytes(&input_bytes));
    
    println!("Inner data length: {}", inner_data.len());
    println!("Expected length: 288 bytes (9 * 32)");
    
    // Verify we have the right amount of data
    if inner_data.len() != 288 {
        println!("⚠️ Warning: Inner data length is {}, expected 288", inner_data.len());
    }
    
    // Now ABI encode as bytes parameter
    let mut calldata = Vec::new();
    
    // Function selector (4 bytes)
    calldata.extend_from_slice(function_selector);
    
    // ABI encode the bytes parameter
    // Offset to data (32 bytes) - points to where the bytes data starts
    calldata.extend_from_slice(&u256_to_bytes(0x20)); // offset = 32 bytes
    
    // Length of bytes data (32 bytes)
    calldata.extend_from_slice(&u256_to_bytes(inner_data.len() as u64));
    
    // The actual bytes data
    calldata.extend_from_slice(&inner_data);
    
    // Pad to 32-byte boundary if needed
    let padding_needed = (32 - (inner_data.len() % 32)) % 32;
    for _ in 0..padding_needed {
        calldata.push(0);
    }
    
    std::fs::write(path, &calldata)?;
    
    println!("📦 Saved ABI-encoded calldata ({} bytes) to: {}", calldata.len(), path);
    
    // Print hex string for testing
    let hex_string = format!("0x{}", hex::encode(&calldata));
    println!("\n🔗 Complete calldata for testing:");
    println!("{}", hex_string);
    
    // Print debugging info
    println!("\n🔍 Proof components (for debugging):");
    println!("A.x: 0x{}", hex::encode(field_element_to_32_bytes(&proof.a.x)));
    println!("A.y: 0x{}", hex::encode(field_element_to_32_bytes(&proof.a.y)));
    println!("B.x.c1: 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.x.c1)));
    println!("B.x.c0: 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.x.c0)));
    println!("B.y.c1: 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.y.c1)));
    println!("B.y.c0: 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.y.c0)));
    println!("C.x: 0x{}", hex::encode(field_element_to_32_bytes(&proof.c.x)));
    println!("C.y: 0x{}", hex::encode(field_element_to_32_bytes(&proof.c.y)));
    println!("Input: 0x{}", hex::encode(pad_to_32_bytes(&input_bytes)));
    
    Ok(())
}

fn field_element_to_32_bytes<F: PrimeField>(field: &F) -> [u8; 32] {
    let bytes = field.into_bigint().to_bytes_be();
    pad_to_32_bytes(&bytes)
}

fn pad_to_32_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    if bytes.len() >= 32 {
        padded.copy_from_slice(&bytes[bytes.len()-32..]);
    } else {
        let start = 32 - bytes.len();
        padded[start..].copy_from_slice(bytes);
    }
    padded
}

fn u256_to_bytes(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

// Alternative: Create calldata that calls the function directly
pub fn create_transaction_calldata<F: PrimeField>(
    proof: &Proof<Bn254>,
    public_input: &F,
    path: &str,
) -> std::io::Result<()> {
    // This creates the complete ABI encoded transaction calldata
    save_calldata(proof, public_input, path)
}


fn field_to_decimal_string<F: PrimeField>(field: &F) -> String {
    field.into_bigint().to_string()
}

pub fn print_verifying_key_info(vk: &VerifyingKey<Bn254>) {
    println!("\n🔍 Verifying Key Information:");
    println!("Alpha: ({}, {})", 
        field_to_hex_string(&vk.alpha_g1.x), 
        field_to_hex_string(&vk.alpha_g1.y));
    
    println!("Beta: ([{}, {}], [{}, {}])", 
        field_to_hex_string(&vk.beta_g2.x.c0),
        field_to_hex_string(&vk.beta_g2.x.c1),
        field_to_hex_string(&vk.beta_g2.y.c0),
        field_to_hex_string(&vk.beta_g2.y.c1));
    
    println!("Gamma ABC points: {}", vk.gamma_abc_g1.len());
    for (i, point) in vk.gamma_abc_g1.iter().enumerate() {
        println!("  [{}]: ({}, {})", 
            i, 
            field_to_hex_string(&point.x), 
            field_to_hex_string(&point.y));
    }
}

fn field_to_hex_string<F: PrimeField>(field: &F) -> String {
    let bytes = field.into_bigint().to_bytes_be();
    let mut hex_string = "0x".to_string();
    for byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}


pub fn generate_complete_verifier_contract(vk: &VerifyingKey<Bn254>) -> std::io::Result<()> {
    let contract_template = format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Groth16Verifier {{
    using Pairing for *;

    struct VerifyingKey {{ 
        Pairing.G1Point alpha; 
        Pairing.G2Point beta; 
        Pairing.G2Point gamma; 
        Pairing.G2Point delta; 
        Pairing.G1Point[2] gamma_abc; 
    }}

    struct Proof {{ 
        Pairing.G1Point a; 
        Pairing.G2Point b; 
        Pairing.G1Point c; 
    }}

    VerifyingKey private verifyingKey;

    constructor() {{
        // Generated verifying key from trusted setup
        verifyingKey.alpha = Pairing.G1Point({}, {});
        verifyingKey.beta = Pairing.G2Point([{}, {}], [{}, {}]);
        verifyingKey.gamma = Pairing.G2Point([{}, {}], [{}, {}]);
        verifyingKey.delta = Pairing.G2Point([{}, {}], [{}, {}]);
        verifyingKey.gamma_abc[0] = Pairing.G1Point({}, {});
        verifyingKey.gamma_abc[1] = Pairing.G1Point({}, {});
    }}

    function verifyProofFromCalldata(bytes calldata proofData) external view returns (bool) {{
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint input0) = abi.decode(
            proofData,
            (uint[2], uint[2][2], uint[2], uint)
        );
        uint[] memory inps = new uint[](1);
        inps[0] = input0;
        Proof memory proof = Proof({{
            a: Pairing.G1Point(a[0], a[1]),
            b: Pairing.G2Point([b[0][0],b[0][1]], [b[1][0],b[1][1]]),
            c: Pairing.G1Point(c[0], c[1])
        }});
        return verify(inps, proof);
    }}

    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {{
        Pairing.G1Point memory vk_x = Pairing.addition(
            verifyingKey.gamma_abc[0],
            Pairing.scalar_mul(verifyingKey.gamma_abc[1], input[0])
        );
        return Pairing.pairing(
            Pairing.negate(proof.a), proof.b,
            verifyingKey.alpha, verifyingKey.beta,
            vk_x, verifyingKey.gamma,
            proof.c, verifyingKey.delta
        );
    }}
}}

library Pairing {{
    struct G1Point {{ uint X; uint Y; }}
    struct G2Point {{ uint[2] X; uint[2] Y; }}

    function negate(G1Point memory p) internal pure returns (G1Point memory) {{
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - p.Y);
    }}

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint256[4] memory inps = [p1.X, p1.Y, p2.X, p2.Y];
        bool ok;
        assembly {{ ok := staticcall(sub(gas(),2000), 6, inps, 0x80, r, 0x60) }}
        require(ok, "add failed");
    }}

    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {{
        uint256[3] memory inps = [p.X, p.Y, s];
        bool ok;
        assembly {{ ok := staticcall(sub(gas(),2000), 7, inps, 0x60, r, 0x60) }}
        require(ok, "mul failed");
    }}

    function pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {{
        uint256[] memory inps = new uint256[](24);
        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        for (uint i = 0; i < 4; i++) {{
            inps[i*6 + 0] = p1[i].X;
            inps[i*6 + 1] = p1[i].Y;
            inps[i*6 + 2] = p2[i].X[0];
            inps[i*6 + 3] = p2[i].X[1];
            inps[i*6 + 4] = p2[i].Y[0];
            inps[i*6 + 5] = p2[i].Y[1];
        }}
        uint256[1] memory out;
        bool ok;
        assembly {{ ok := staticcall(sub(gas(),2000), 8, add(inps,0x20), mul(24,0x20), out, 0x20) }}
        require(ok, "pairing failed");
        return out[0] != 0;
    }}
}}"#,
        // Alpha (G1)
        field_to_uint_string(&vk.alpha_g1.x),
        field_to_uint_string(&vk.alpha_g1.y),
        // Beta (G2) - FIXED: Correct coordinate order for Ethereum
        field_to_uint_string(&vk.beta_g2.x.c1), // x1 first
        field_to_uint_string(&vk.beta_g2.x.c0), // x0 second
        field_to_uint_string(&vk.beta_g2.y.c1), // y1 first
        field_to_uint_string(&vk.beta_g2.y.c0), // y0 second
        // Gamma (G2) - FIXED: Correct coordinate order for Ethereum
        field_to_uint_string(&vk.gamma_g2.x.c1), // x1 first
        field_to_uint_string(&vk.gamma_g2.x.c0), // x0 second
        field_to_uint_string(&vk.gamma_g2.y.c1), // y1 first
        field_to_uint_string(&vk.gamma_g2.y.c0), // y0 second
        // Delta (G2) - FIXED: Correct coordinate order for Ethereum
        field_to_uint_string(&vk.delta_g2.x.c1), // x1 first
        field_to_uint_string(&vk.delta_g2.x.c0), // x0 second
        field_to_uint_string(&vk.delta_g2.y.c1), // y1 first
        field_to_uint_string(&vk.delta_g2.y.c0), // y0 second
        // Gamma ABC[0] (G1)
        field_to_uint_string(&vk.gamma_abc_g1[0].x),
        field_to_uint_string(&vk.gamma_abc_g1[0].y),
        // Gamma ABC[1] (G1)  
        field_to_uint_string(&vk.gamma_abc_g1[1].x),
        field_to_uint_string(&vk.gamma_abc_g1[1].y),
    );

    // Ensure contracts directory exists
    fs::create_dir_all("./contracts")?;
    
    // Write the complete contract
    fs::write("./contracts/Groth16Verifier.sol", contract_template)?;
    
    println!("✅ Generated complete verifier contract: ./contracts/Groth16Verifier.sol");
    Ok(())
}

fn field_to_uint_string<F: PrimeField>(field: &F) -> String {
    field.into_bigint().to_string()
}

// Update your main.rs to call this instead
pub fn export_verifying_key_to_rs(vk: &VerifyingKey<Bn254>) -> std::io::Result<()> {
    generate_complete_verifier_contract(vk)?;
    // print_verifying_key_info(vk);
    Ok(())
}