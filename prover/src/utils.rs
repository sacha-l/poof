/*!
# ZK-SNARK Utilities for Groth16 Proof System

This module provides utilities for serializing and handling zkSNARK components
for deployment to Ethereum. It specifically handles the Groth16 proving system
on the BN254 elliptic curve.

## Key Components:
- Proof serialization and calldata generation
- Verifying key handling and Solidity contract generation  
- Ethereum-compatible coordinate system conversions
- ABI encoding for smart contract interaction

## Critical Implementation Notes:

### Coordinate System Compatibility
Ethereum's alt_bn128 precompile expects G2 coordinates in a specific order that
differs from arkworks' internal representation:

- **Arkworks**: G2(x, y) where x = c0 + c1*i, y = c0 + c1*i stored as [c0, c1, c0, c1]
- **Ethereum**: Expects [c1, c0, c1, c0] (imaginary part first, then real part)

This affects both proof generation and verifying key embedding in contracts.

### ABI Encoding Structure
The generated calldata follows Ethereum's ABI specification:
```ignore
[4-byte function selector][32-byte offset][32-byte length][data][padding]
```

Where data contains the proof components in order:
1. G1 point A (64 bytes: x, y)
2. G2 point B (128 bytes: x.c1, x.c0, y.c1, y.c0) 
3. G1 point C (64 bytes: x, y)
4. Public input (32 bytes)
*/

use ark_bn254::{Fr, Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_ff::{PrimeField, BigInteger};
use ark_serialize::CanonicalSerialize;
use sha3::{Digest, Keccak256};
use std::fs::{File, create_dir_all};
use std::io::Write;

/// Saves the proving key to binary format for reuse.
/// 
/// # Arguments
/// * `pk` - The Groth16 proving key to serialize
/// 
/// # File Output
/// Creates `../keys/proving_key.bin` containing the uncompressed proving key.
pub fn save_proving_key(pk: &ProvingKey<Bn254>) -> std::io::Result<()> {
    let mut file = File::create("../keys/proving_key.bin")?;
    pk.serialize_uncompressed(&mut file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("📦 Saved proving key to: ../keys/proving_key.bin");
    Ok(())
}

/// Saves the verifying key to binary format.
/// 
/// The verifying key contains the public parameters needed for proof verification:
/// - alpha_g1, beta_g2, gamma_g2, delta_g2: trusted setup parameters
/// - gamma_abc_g1: array of G1 points for public input handling
/// 
/// # Arguments
/// * `vk` - The Groth16 verifying key to serialize
/// 
/// # File Output  
/// Creates `../keys/verifying_key.bin` containing the uncompressed verifying key.
pub fn save_verifying_key(vk: &VerifyingKey<Bn254>) -> std::io::Result<()> {
    let out_path = "../keys/verifying_key.bin";

    let mut buf: Vec<u8> = Vec::new();
    vk.serialize_uncompressed(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    println!("📦 Saved verifying key ({} bytes) to: {}", buf.len(), out_path);

    let mut file = File::create(out_path)?;
    file.write_all(&buf)?;
    Ok(())
}

/// Saves a Groth16 proof in compressed binary format.
/// 
/// A Groth16 proof consists of three elliptic curve points:
/// - A: G1 point (compressed: 32 bytes)  
/// - B: G2 point (compressed: 64 bytes)
/// - C: G1 point (compressed: 32 bytes)
/// Total: 128 bytes when compressed
/// 
/// # Arguments
/// * `proof` - The Groth16 proof to serialize
/// 
/// # File Output
/// Creates `../proofs/proof.bin` containing the compressed proof
pub fn save_proof(proof: &Proof<Bn254>) -> std::io::Result<()> {
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

/// Saves the public input (witness) for the circuit.
/// 
/// In our multiplication circuit (a * b = c), the public input is the result 'c'.
/// This value must be provided during verification to ensure the proof
/// corresponds to the claimed public statement.
/// 
/// # Arguments
/// * `c` - The public input field element (typically the circuit output)
/// 
/// # File Output
/// Creates `../proofs/public_input.bin` containing the serialized field element
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

//================================================================================================
// ETHEREUM CALLDATA GENERATION
//================================================================================================

/// Generates Ethereum-compatible calldata for proof verification
/// 
/// This function creates properly ABI-encoded calldata that can be used to call
/// the `verifyProofFromCalldata(bytes)` function on the deployed Solidity verifier.
/// 
/// # Critical Implementation Details:
/// 
/// ## G2 Coordinate Ordering Fix
/// Ethereum's alt_bn128 precompile expects G2 field elements in [c1, c0] order
/// (imaginary part first), while arkworks stores them as [c0, c1] (real part first).
/// This function applies the necessary coordinate transformation.
/// 
/// ## ABI Encoding Structure
/// The calldata follows Ethereum's ABI specification for dynamic bytes:
/// ```ignore
/// [4 bytes]  Function selector (keccak256("verifyProofFromCalldata(bytes)")[0:4])
/// [32 bytes] Offset to data (0x20 = 32 bytes)
/// [32 bytes] Length of data (288 bytes)
/// [288 bytes] Proof data: [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y, input]
/// [padding]  Zero padding to 32-byte boundary
/// ```
/// 
/// # Arguments
/// * `proof` - The Groth16 proof containing points A, B, C
/// * `public_input` - The public input to the circuit
/// * `path` - File path to write the calldata binary
/// 
/// # File Output
/// Creates a binary file containing complete transaction calldata ready for Ethereum.
/// 
/// # Example Usage
/// ```ignore
/// save_calldata(&proof, &Fr::from(12u64), "../calldata.bin")?;
/// ```
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
    
    // Add proof components in the order expected by Solidity:
    // (uint[2] a, uint[2][2] b, uint[2] c, uint input0)
    
    // uint[2] a - G1 point A coordinates (64 bytes)
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.a.x));
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.a.y));
    
    // uint[2][2] b - G2 point B coordinates (128 bytes)
    // ETHEREUM ORDER: [c1, c0, c1, c0] (imaginary first, then real)
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.x.c1)); // x imaginary
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.x.c0)); // x real
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.y.c1)); // y imaginary
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.y.c0)); // y real
    
    // uint[2] c - G1 point C coordinates (64 bytes)
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.c.x));
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.c.y));
    
    // uint input0 - Public input (32 bytes)
    let input_bytes = public_input.into_bigint().to_bytes_be();
    inner_data.extend_from_slice(&pad_to_32_bytes(&input_bytes));
    
    println!("Inner data length: {}", inner_data.len());
    println!("Expected length: 288 bytes (9 * 32)");
    
    // Verify we have the correct amount of data
    if inner_data.len() != 288 {
        println!("⚠️ Warning: Inner data length is {}, expected 288", inner_data.len());
    }
    
    // Build complete ABI-encoded calldata
    let mut calldata = Vec::new();
    
    // Function selector (4 bytes)
    calldata.extend_from_slice(function_selector);
    
    // ABI encoding for dynamic bytes parameter:
    // - Offset to data location (32 bytes)
    calldata.extend_from_slice(&u256_to_bytes(0x20)); // Data starts at byte 32
    
    // - Length of the bytes data (32 bytes)  
    calldata.extend_from_slice(&u256_to_bytes(inner_data.len() as u64));
    
    // - The actual data
    calldata.extend_from_slice(&inner_data);
    
    // - Padding to 32-byte boundary (ABI requirement)
    let padding_needed = (32 - (inner_data.len() % 32)) % 32;
    for _ in 0..padding_needed {
        calldata.push(0);
    }
    
    // Write calldata to file
    std::fs::write(path, &calldata)?;
    
    println!("📦 Saved ABI-encoded calldata ({} bytes) to: {}", calldata.len(), path);
    
    // Output calldata for easy copying/testing
    let hex_string = format!("0x{}", hex::encode(&calldata));
    println!("\n🔗 Complete calldata for testing:");
    println!("{}", hex_string);
    
    // Debug output for coordinate order confirmation
    println!("\n🔍 Proof components (ETHEREUM coordinate order - c1,c0,c1,c0):");
    println!("A.x: 0x{}", hex::encode(field_element_to_32_bytes(&proof.a.x)));
    println!("A.y: 0x{}", hex::encode(field_element_to_32_bytes(&proof.a.y)));
    println!("B.x.c1 (imag): 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.x.c1)));
    println!("B.x.c0 (real): 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.x.c0)));
    println!("B.y.c1 (imag): 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.y.c1)));
    println!("B.y.c0 (real): 0x{}", hex::encode(field_element_to_32_bytes(&proof.b.y.c0)));
    println!("C.x: 0x{}", hex::encode(field_element_to_32_bytes(&proof.c.x)));
    println!("C.y: 0x{}", hex::encode(field_element_to_32_bytes(&proof.c.y)));
    println!("Public input: 0x{}", hex::encode(pad_to_32_bytes(&input_bytes)));
    
    Ok(())
}

/// Generate alternative calldata with reversed G2 coordinate order for testing.
pub fn save_calldata_alternative<F: PrimeField>(
    proof: &Proof<Bn254>,
    public_input: &F,
    path: &str,
) -> std::io::Result<()> {
    let function_sig = "verifyProofFromCalldata(bytes)";
    let mut hasher = Keccak256::new();
    hasher.update(function_sig.as_bytes());
    let hash = hasher.finalize();
    let function_selector = &hash[0..4];
    
    let mut inner_data = Vec::new();
    
    // A point (same as before)
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.a.x));
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.a.y));
    
    // B point - ARKWORKS ORDER: [c0, c1, c0, c1] (real first)
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.x.c0)); // x real first
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.x.c1)); // x imaginary second
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.y.c0)); // y real first
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.b.y.c1)); // y imaginary second
    
    // C point (same as before)
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.c.x));
    inner_data.extend_from_slice(&field_element_to_32_bytes(&proof.c.y));
    
    // Public input (same as before)
    let input_bytes = public_input.into_bigint().to_bytes_be();
    inner_data.extend_from_slice(&pad_to_32_bytes(&input_bytes));
    
    // Build calldata
    let mut calldata = Vec::new();
    calldata.extend_from_slice(function_selector);
    calldata.extend_from_slice(&u256_to_bytes(0x20));
    calldata.extend_from_slice(&u256_to_bytes(inner_data.len() as u64));
    calldata.extend_from_slice(&inner_data);
    
    let padding_needed = (32 - (inner_data.len() % 32)) % 32;
    for _ in 0..padding_needed {
        calldata.push(0);
    }
    
    std::fs::write(path, &calldata)?;
    
    println!("📦 Alternative calldata (c0,c1,c0,c1 order): 0x{}", hex::encode(&calldata));
    
    Ok(())
}

/// Alternative calldata generation for direct transaction creation
/// 
/// This is a convenience wrapper around `save_calldata` that can be used
/// when you need to create transaction calldata programmatically.
pub fn create_transaction_calldata<F: PrimeField>(
    proof: &Proof<Bn254>,
    public_input: &F,
    path: &str,
) -> std::io::Result<()> {
    save_calldata(proof, public_input, path)
}

//================================================================================================
// SOLIDITY CONTRACT GENERATION
//================================================================================================

/// Generates a complete Solidity verifier contract with embedded verifying key
/// 
/// This function creates a ready-to-deploy Solidity contract that includes:
/// - The complete Groth16 verification logic
/// - Pairing library for elliptic curve operations  
/// - Embedded verifying key from the trusted setup
/// - ABI-compatible proof verification function
/// 
/// # Critical Implementation Notes:
/// 
/// ## Coordinate System Transformation
/// The verifying key G2 points must be transformed from arkworks format to
/// Ethereum format. This affects beta, gamma, and delta parameters.
/// 
/// ## Contract Structure
/// The generated contract includes:
/// - `VerifyingKey` struct with trusted setup parameters
/// - `verifyProofFromCalldata(bytes)` function for external calls
/// - Internal `verify()` function implementing Groth16 algorithm
/// - `Pairing` library with elliptic curve precompile wrappers
/// 
/// # Arguments
/// * `vk` - The verifying key from the trusted setup
/// 
/// # File Output
/// Creates `./contracts/Groth16Verifier.sol` with embedded verifying key
/// 
/// # Security Considerations
/// The embedded verifying key represents the "trusted setup" for this specific
/// circuit. It must match the proving key used to generate proofs, and should
/// be generated through a secure ceremony for production use.
pub fn generate_complete_verifier_contract(vk: &VerifyingKey<Bn254>) -> std::io::Result<()> {
    let contract_template = format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Groth16Verifier
 * @dev Verifies Groth16 zero-knowledge proofs on Ethereum
 * 
 * This contract embeds the verifying key from a trusted setup and provides
 * a function to verify proofs generated with the corresponding proving key.
 * 
 * Circuit: Multiplication proof (a * b = c)
 * Curve: BN254 (alt_bn128)
 * 
 * SECURITY NOTE: The embedded verifying key must come from a trusted setup.
 * In production, this should be generated through a secure ceremony.
 */
contract Groth16Verifier {{
    using Pairing for *;

    /// @dev Verifying key structure containing trusted setup parameters
    struct VerifyingKey {{ 
        Pairing.G1Point alpha;        // α in G1
        Pairing.G2Point beta;         // β in G2  
        Pairing.G2Point gamma;        // γ in G2
        Pairing.G2Point delta;        // δ in G2
        Pairing.G1Point[2] gamma_abc; // [γ^0, γ^1, ...] for public inputs
    }}

    /// @dev Groth16 proof structure
    struct Proof {{ 
        Pairing.G1Point a;  // A in G1
        Pairing.G2Point b;  // B in G2  
        Pairing.G1Point c;  // C in G1
    }}

    VerifyingKey private verifyingKey;

    /**
     * @dev Constructor embeds the verifying key from trusted setup
     * 
     * COORDINATE ORDER: Ethereum order [imaginary, real] to match calldata generation
     */
    constructor() {{
        // Generated verifying key from trusted setup
        verifyingKey.alpha = Pairing.G1Point({}, {});
        verifyingKey.beta = Pairing.G2Point([{}, {}], [{}, {}]);
        verifyingKey.gamma = Pairing.G2Point([{}, {}], [{}, {}]);
        verifyingKey.delta = Pairing.G2Point([{}, {}], [{}, {}]);
        verifyingKey.gamma_abc[0] = Pairing.G1Point({}, {});
        verifyingKey.gamma_abc[1] = Pairing.G1Point({}, {});
    }}

    /**
     * @dev Verifies a Groth16 proof from ABI-encoded calldata
     * 
     * @param proofData ABI-encoded proof: (uint[2] a, uint[2][2] b, uint[2] c, uint input0)
     * @return bool True if the proof is valid, false otherwise
     * 
     * CALLDATA FORMAT:
     * - a: [A.x, A.y] (64 bytes)
     * - b: [[B.x.imag, B.x.real], [B.y.imag, B.y.real]] (128 bytes)  
     * - c: [C.x, C.y] (64 bytes)
     * - input0: public input (32 bytes)
     */
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

    /**
     * @dev Internal Groth16 verification algorithm
     * 
     * Implements the Groth16 verification equation:
     * e(A, B) = e(α, β) * e(vk_x, γ) * e(C, δ)
     * 
     * Where vk_x = γ_abc[0] + Σ(input[i] * γ_abc[i+1])
     * 
     * @param input Array of public inputs  
     * @param proof The proof to verify
     * @return bool True if verification passes
     */
    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {{
        // Compute the linear combination of public inputs
        Pairing.G1Point memory vk_x = Pairing.addition(
            verifyingKey.gamma_abc[0],
            Pairing.scalar_mul(verifyingKey.gamma_abc[1], input[0])
        );
        
        // Perform the pairing check: e(-A, B) * e(α, β) * e(vk_x, γ) * e(C, δ) = 1
        return Pairing.pairing(
            Pairing.negate(proof.a), proof.b,    // e(-A, B)
            verifyingKey.alpha, verifyingKey.beta, // e(α, β)  
            vk_x, verifyingKey.gamma,              // e(vk_x, γ)
            proof.c, verifyingKey.delta            // e(C, δ)
        );
    }}
}}

/**
 * @title Pairing
 * @dev Library for elliptic curve pairing operations on BN254
 * 
 * This library wraps Ethereum's precompiled contracts for:
 * - ecAdd (0x06): Elliptic curve point addition
 * - ecMul (0x07): Elliptic curve scalar multiplication  
 * - ecPairing (0x08): Bilinear pairing check
 * 
 * CURVE DETAILS:
 * - G1: Points on E(Fp) where E: y² = x³ + 3
 * - G2: Points on E'(Fp2) where E': y² = x³ + 3/(9+u)
 * - Field prime: 21888242871839275222246405745257275088696311157297823662689037894645226208583
 */
library Pairing {{
    /// @dev G1 point in affine coordinates
    struct G1Point {{ uint X; uint Y; }}
    
    /// @dev G2 point in affine coordinates over Fp2
    /// X and Y are arrays [imaginary_part, real_part] to match Ethereum format
    struct G2Point {{ uint[2] X; uint[2] Y; }}

    /**
     * @dev Negates a G1 point: (x, y) -> (x, -y mod p)
     * @param p The point to negate
     * @return The negated point
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {{
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - p.Y);
    }}

    /**
     * @dev Adds two G1 points using the ecAdd precompile (0x06)
     * @param p1 First point
     * @param p2 Second point  
     * @return r The sum p1 + p2
     */
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint256[4] memory inps = [p1.X, p1.Y, p2.X, p2.Y];
        bool ok;
        assembly {{ ok := staticcall(sub(gas(),2000), 6, inps, 0x80, r, 0x60) }}
        require(ok, "ecAdd failed");
    }}

    /**
     * @dev Multiplies a G1 point by a scalar using ecMul precompile (0x07)
     * @param p The point to multiply
     * @param s The scalar multiplier
     * @return r The product s * p
     */
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {{
        uint256[3] memory inps = [p.X, p.Y, s];
        bool ok;
        assembly {{ ok := staticcall(sub(gas(),2000), 7, inps, 0x60, r, 0x60) }}
        require(ok, "ecMul failed");
    }}

    /**
     * @dev Performs bilinear pairing check using ecPairing precompile (0x08)
     * 
     * Checks if e(a1, a2) * e(b1, b2) * e(c1, c2) * e(d1, d2) = 1
     * 
     * @param a1,a2,b1,b2,c1,c2,d1,d2 The points for pairing
     * @return True if the pairing equation holds
     */
    function pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {{
        uint256[] memory inps = new uint256[](24);
        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        
        // Pack points into input array for precompile
        for (uint i = 0; i < 4; i++) {{
            inps[i*6 + 0] = p1[i].X;      // G1.x
            inps[i*6 + 1] = p1[i].Y;      // G1.y  
            inps[i*6 + 2] = p2[i].X[0];   // G2.x.imaginary
            inps[i*6 + 3] = p2[i].X[1];   // G2.x.real
            inps[i*6 + 4] = p2[i].Y[0];   // G2.y.imaginary  
            inps[i*6 + 5] = p2[i].Y[1];   // G2.y.real
        }}
        
        uint256[1] memory out;
        bool ok;
        assembly {{ ok := staticcall(sub(gas(),2000), 8, add(inps,0x20), mul(24,0x20), out, 0x20) }}
        require(ok, "pairing failed");
        return out[0] != 0;
    }}
}}"#,
        // Alpha (G1) - straightforward coordinates
        field_to_uint_string(&vk.alpha_g1.x),
        field_to_uint_string(&vk.alpha_g1.y),
        
        // Beta (G2) - ETHEREUM ORDER: [imaginary, real] to match calldata
        field_to_uint_string(&vk.beta_g2.x.c1), // x imaginary part first
        field_to_uint_string(&vk.beta_g2.x.c0), // x real part second
        field_to_uint_string(&vk.beta_g2.y.c1), // y imaginary part first
        field_to_uint_string(&vk.beta_g2.y.c0), // y real part second
        
        // Gamma (G2) - same coordinate order
        field_to_uint_string(&vk.gamma_g2.x.c1),
        field_to_uint_string(&vk.gamma_g2.x.c0),
        field_to_uint_string(&vk.gamma_g2.y.c1),
        field_to_uint_string(&vk.gamma_g2.y.c0),
        
        // Delta (G2) - same coordinate order  
        field_to_uint_string(&vk.delta_g2.x.c1),
        field_to_uint_string(&vk.delta_g2.x.c0),
        field_to_uint_string(&vk.delta_g2.y.c1),
        field_to_uint_string(&vk.delta_g2.y.c0),
        
        // Gamma ABC points (G1) - straightforward coordinates
        field_to_uint_string(&vk.gamma_abc_g1[0].x),
        field_to_uint_string(&vk.gamma_abc_g1[0].y),
        field_to_uint_string(&vk.gamma_abc_g1[1].x),
        field_to_uint_string(&vk.gamma_abc_g1[1].y),
    );

    // Ensure output directory exists
    create_dir_all("./contracts")?;
    
    // Write the complete contract to file
    std::fs::write("./contracts/Groth16Verifier.sol", contract_template)?;
    
    println!("✅ Generated complete verifier contract: ./contracts/Groth16Verifier.sol");
    println!("📋 Contract includes embedded verifying key and can be deployed directly");
    Ok(())
}

//================================================================================================
// DEBUG FUNCTIONS FOR COORDINATE TESTING
//================================================================================================

/// Generate both coordinate orders for comprehensive testing
pub fn debug_coordinate_systems<F: PrimeField>(
    proof: &Proof<Bn254>,
    public_input: &F,
) -> std::io::Result<()> {
    println!("\n🔬 DEBUGGING COORDINATE SYSTEMS");
    println!("Generating calldata with both coordinate orderings...\n");

    // Generate main calldata (c1, c0, c1, c0 order) - Ethereum order
    save_calldata(proof, public_input, "../calldata.bin")?;
    
    // Generate alternative calldata (c0, c1, c0, c1 order) - Arkworks order
    save_calldata_alternative(proof, public_input, "../calldata_alt.bin")?;
    
    println!("\n📋 Test both calldata files with your contract:");
    println!("   - ../calldata.bin (ethereum order: c1,c0,c1,c0)");
    println!("   - ../calldata_alt.bin (arkworks order: c0,c1,c0,c1)");
    println!("🎯 The main calldata should work with the updated contract!");
    
    Ok(())
}

//================================================================================================
// UTILITY FUNCTIONS
//================================================================================================

/// Converts a field element to a 32-byte big-endian representation
/// 
/// This ensures compatibility with Ethereum's 256-bit word size and
/// big-endian byte ordering used in the EVM.
fn field_element_to_32_bytes<F: PrimeField>(field: &F) -> [u8; 32] {
    let bytes = field.into_bigint().to_bytes_be();
    pad_to_32_bytes(&bytes)
}

/// Pads a byte array to exactly 32 bytes with leading zeros
/// 
/// This is required for Ethereum compatibility where all values
/// must be represented as 32-byte words.
fn pad_to_32_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    if bytes.len() >= 32 {
        // If input is longer than 32 bytes, take the last 32 bytes
        padded.copy_from_slice(&bytes[bytes.len()-32..]);
    } else {
        // If input is shorter, pad with leading zeros
        let start = 32 - bytes.len();
        padded[start..].copy_from_slice(bytes);
    }
    padded
}

/// Converts a u64 value to a 32-byte big-endian representation
/// 
/// Used for ABI encoding of offsets and lengths in calldata generation.
fn u256_to_bytes(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

/// Converts a field element to its decimal string representation
/// 
/// This is used for embedding field element values directly in the
/// generated Solidity contract as uint256 literals.
fn field_to_uint_string<F: PrimeField>(field: &F) -> String {
    field.into_bigint().to_string()
}

/// Converts a field element to hexadecimal string representation  
/// 
/// Useful for debugging and logging field element values in a
/// human-readable format.
fn field_to_hex_string<F: PrimeField>(field: &F) -> String {
    let bytes = field.into_bigint().to_bytes_be();
    let mut hex_string = "0x".to_string();
    for byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}

/// Converts a field element to decimal string (alias for compatibility)
fn field_to_decimal_string<F: PrimeField>(field: &F) -> String {
    field.into_bigint().to_string()
}

//================================================================================================
// DEBUG AND INFORMATION FUNCTIONS
//================================================================================================

/// Prints detailed information about a verifying key for debugging
/// 
/// This function outputs all the verifying key components in both
/// hexadecimal format for easy inspection and verification.
/// 
/// # Arguments
/// * `vk` - The verifying key to inspect
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

//================================================================================================
// PUBLIC API FUNCTIONS
//================================================================================================

/// Main entry point for verifying key processing with coordinate debugging
/// 
/// This function is called from main.rs to generate the complete
/// Solidity verifier contract and debug coordinate systems.
/// 
/// # Arguments
/// * `vk` - The verifying key from the trusted setup
pub fn export_verifying_key_to_rs(vk: &VerifyingKey<Bn254>) -> std::io::Result<()> {
    generate_complete_verifier_contract(vk)?;
    // Uncomment for debugging: print_verifying_key_info(vk);
    Ok(())
}

/// Add coordinate debugging to existing proof generation
pub fn add_coordinate_debug_to_main<F: PrimeField>(
    proof: &Proof<Bn254>, 
    public_input: &F
) -> std::io::Result<()> {
    
    // Generate both coordinate orders for testing
    debug_coordinate_systems(proof, public_input)?;
    
    println!("\n🎯 TESTING STRATEGY:");
    println!("1. Deploy your contract");
    println!("2. Test ../calldata.bin - should work with updated contract");
    println!("3. Test ../calldata_alt.bin - for comparison");
    println!("4. The main calldata uses Ethereum coordinate order");
    
    Ok(())
}

/// Helper function for error conversion from serialization errors
fn wrap_serialize_error<E: std::fmt::Display>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err))
}