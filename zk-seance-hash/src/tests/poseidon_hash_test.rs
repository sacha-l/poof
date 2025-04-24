use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::test_rng;

use zk_seance_hash::{PoseidonHashCircuit};
use ark_crypto_primitives::crh::poseidon::CRH as PoseidonCRH;
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

#[test]
fn test_poseidon_preimage_circuit() {
    // Initialize RNG
    let mut rng = test_rng();

    // Poseidon parameters for BN254
    let full_rounds: usize    = 8;
    let partial_rounds: usize = 57;
    let alpha: u64            = 5;
    let rate: usize           = 2;
    let capacity: usize       = 1;
    let field_bits: u64       = Fr::MODULUS_BIT_SIZE as u64;

    // Generate PoseidonConfig
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        field_bits,
        rate,
        full_rounds,
        partial_rounds,
        capacity,
    );
    let params = PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        ark,
        rate,
        capacity,
    );

    // Sample a random secret and compute its Poseidon hash
    let secret = Fr::rand(&mut rng);
    let hash = PoseidonCRH::<Fr>::evaluate(&params, [secret]).unwrap();

    // Construct the circuit
    let circuit = PoseidonHashCircuit {
        secret: Some(secret),
        expected_hash: Some(hash),
        params: params.clone(),
    };

    // Trusted setup
    let snark_params = generate_random_parameters::<Bn254, _, _>(circuit.clone(), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&snark_params.vk);

    // Create a proof
    let proof = create_random_proof(circuit.clone(), &snark_params, &mut rng).unwrap();

    // Verify the proof
    let result = verify_proof(&pvk, &proof, &[hash]).unwrap();
    assert!(result, "Poseidon preimage proof verification failed");
}
