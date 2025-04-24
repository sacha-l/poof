use rand::thread_rng;
use ark_ff::PrimeField;
use ark_crypto_primitives::crh::CRHScheme;              
use ark_crypto_primitives::snark::SNARK;                
use ark_groth16::Groth16;                               
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::poseidon::CRH as PoseidonCRH;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use zk_seance_hash::PoseidonHashCircuit;

fn main() {
    let mut rng = thread_rng();

    // Poseidon parameters for BN254:
    let full_rounds    = 8usize;
    let partial_rounds = 57usize;
    let alpha: u64     = 5;
    let rate: usize    = 2; // t = rate + capacity = 3
    let capacity = 1;
    let field_bits: u64= Fr::MODULUS_BIT_SIZE as u64;

    // Pull baked-in ARK & MDS:
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        field_bits,
        rate as usize,
        full_rounds as u64,
        partial_rounds as u64,
        capacity as u64,
    );

    // Build PoseidonConfig:
    let params: PoseidonConfig<Fr> = PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        ark,
        rate,
        capacity,
    );

    // Off-chain: pick secret + hash
    let secret = Fr::from(1337u64);
    let hash   = PoseidonCRH::<Fr>::evaluate(&params, [secret]).unwrap();

    // Build circuit
    let circuit = PoseidonHashCircuit {
        secret: Some(secret),
        expected_hash: Some(hash),
        params: params.clone(),
    };

    // Groth16: setup, prove, verify
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let proof    = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
    let ok       = Groth16::<Bn254>::verify(&vk, &[hash], &proof).unwrap();

    println!("Proof verified: {}", ok);
}
