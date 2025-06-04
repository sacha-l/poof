// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Groth16Verifier
 * @dev Verifies Groth16 zero-knowledge proofs on EVM
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
contract Groth16Verifier {
    using Pairing for *;

    /// @dev Verifying key structure containing trusted setup parameters
    struct VerifyingKey { 
        Pairing.G1Point alpha;        // α in G1
        Pairing.G2Point beta;         // β in G2  
        Pairing.G2Point gamma;        // γ in G2
        Pairing.G2Point delta;        // δ in G2
        Pairing.G1Point[2] gamma_abc; // [γ^0, γ^1, ...] for public inputs
    }

    /// @dev Groth16 proof structure
    struct Proof { 
        Pairing.G1Point a;  // A in G1
        Pairing.G2Point b;  // B in G2  
        Pairing.G1Point c;  // C in G1
    }

    VerifyingKey private verifyingKey;

    /**
     * @dev Constructor embeds the verifying key from trusted setup
     * 
     * COORDINATE ORDER: Ethereum order [imaginary, real] to match calldata generation
     */
    constructor() {
        // Generated verifying key from trusted setup
        verifyingKey.alpha = Pairing.G1Point(7009395089429839938452934743220296235721484443172514024368575284431067112402, 14850036547409752752212360348836641961905195278686271422565578979286723260784);
        verifyingKey.beta = Pairing.G2Point([14667421318642829591660392620878750925786962552905645131943082377577770677536, 19673818692199312763004958820303227392631081556541582776860545314150521976509], [16016671921510436574077320484622073548760846124801003332375123843506748193925, 3675564794190193188074633636681461947231965630188341849681733824541550281184]);
        verifyingKey.gamma = Pairing.G2Point([1728939921869630854105357129454455219371436929468308043001940477706751234734, 5137874442861409554612368481454000891395698906511250774668163890199157440312], [17886874522274347510529738956738542948061714284336416010528714033191070428746, 16874120103129185698010967691018415230001762660983112720085685443856488590965]);
        verifyingKey.delta = Pairing.G2Point([6464835490169460263031859949289448091445994779705039339986761900913839091712, 19492450256803387307832116122006502292680276043516954229768802005069559581837], [6120293845606265552303505288739874325916404691639717668904617410295217419984, 3913778313733353406073584733548851658520227075078378476839245339076329231927]);
        verifyingKey.gamma_abc[0] = Pairing.G1Point(4306103283246688929674380002968500270177121860050179451565484082967980268368, 17717082559038767598175619697947859374437905662176636082382737126208257023569);
        verifyingKey.gamma_abc[1] = Pairing.G1Point(20493451946027499984940435579722998695661640962643462627748390718138459035761, 12622802893977582457246511195137452274612826600614025701581737847067115133761);
    }

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
    function verifyProofFromCalldata(bytes calldata proofData) external view returns (bool) {
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint input0) = abi.decode(
            proofData,
            (uint[2], uint[2][2], uint[2], uint)
        );
        uint[] memory inps = new uint[](1);
        inps[0] = input0;
        Proof memory proof = Proof({
            a: Pairing.G1Point(a[0], a[1]),
            b: Pairing.G2Point([b[0][0],b[0][1]], [b[1][0],b[1][1]]),
            c: Pairing.G1Point(c[0], c[1])
        });
        return verify(inps, proof);
    }

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
    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {
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
    }
}

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
library Pairing {
    /// @dev G1 point in affine coordinates
    struct G1Point { uint X; uint Y; }
    
    /// @dev G2 point in affine coordinates over Fp2
    /// X and Y are arrays [imaginary_part, real_part] to match Ethereum format
    struct G2Point { uint[2] X; uint[2] Y; }

    /**
     * @dev Negates a G1 point: (x, y) -> (x, -y mod p)
     * @param p The point to negate
     * @return The negated point
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - p.Y);
    }

    /**
     * @dev Adds two G1 points using the ecAdd precompile (0x06)
     * @param p1 First point
     * @param p2 Second point  
     * @return r The sum p1 + p2
     */
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory inps = [p1.X, p1.Y, p2.X, p2.Y];
        bool ok;
        assembly { ok := staticcall(sub(gas(),2000), 6, inps, 0x80, r, 0x60) }
        require(ok, "ecAdd failed");
    }

    /**
     * @dev Multiplies a G1 point by a scalar using ecMul precompile (0x07)
     * @param p The point to multiply
     * @param s The scalar multiplier
     * @return r The product s * p
     */
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint256[3] memory inps = [p.X, p.Y, s];
        bool ok;
        assembly { ok := staticcall(sub(gas(),2000), 7, inps, 0x60, r, 0x60) }
        require(ok, "ecMul failed");
    }

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
    ) internal view returns (bool) {
        uint256[] memory inps = new uint256[](24);
        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        
        // Pack points into input array for precompile
        for (uint i = 0; i < 4; i++) {
            inps[i*6 + 0] = p1[i].X;      // G1.x
            inps[i*6 + 1] = p1[i].Y;      // G1.y  
            inps[i*6 + 2] = p2[i].X[0];   // G2.x.imaginary
            inps[i*6 + 3] = p2[i].X[1];   // G2.x.real
            inps[i*6 + 4] = p2[i].Y[0];   // G2.y.imaginary  
            inps[i*6 + 5] = p2[i].Y[1];   // G2.y.real
        }
        
        uint256[1] memory out;
        bool ok;
        assembly { ok := staticcall(sub(gas(),2000), 8, add(inps,0x20), mul(24,0x20), out, 0x20) }
        require(ok, "pairing failed");
        return out[0] != 0;
    }
}