// SPDX-License-Identifier: MIT
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
        verifyingKey.alpha = Pairing.G1Point(10516338638651516726425273877383650924057234336822543544272948431681998108797, 11220667300625982681358339538880697797303008148636066990267668368627759227911);
        verifyingKey.beta = Pairing.G2Point([1056170381208974342191449251803312014218196803864485496365751710708511755785, 10287370305022206763415971942719754728020348439101647030591175626872706298856], [7510868556811828252230237618252212222977164295550980422163117399981992008233, 17004456732212364740362243282369989012566130685681619279317444445891476704435]);
        verifyingKey.gamma = Pairing.G2Point([12082762494375202179526141760177101507253046753954732829820519583285814143741, 1734639204981861197901779145353253198549475268872180087632326380315007927841], [393247484891205946266856496254813905018132600622418619616358422417037268457, 6118108260946821685266354293369963473887128532210562974169276910401883485880]);
        verifyingKey.delta = Pairing.G2Point([19085605314216758477751040959546305278116496170988947513432755243335824104883, 4740815706805799422697664095381433786556843389724909522232318159285160715241], [20674242684658000176205813966348683203704315445713595299878677990163860414977, 19653072510481438102092350875777707992257859664424413881689778256250323480483]);
        verifyingKey.gamma_abc[0] = Pairing.G1Point(11041328869287156005550586270764949729037149748530635683645389580857098123487, 4407150576664794719903365123793579671831761703598960550318179725289132153300);
        verifyingKey.gamma_abc[1] = Pairing.G1Point(11104268873708486516594649966409670224624340363646955604214204031691850772231, 5829207112982922130093855994010607483382362010127136945807109654809970845523);
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