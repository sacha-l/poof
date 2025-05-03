use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use prover::circuit::MulCircuit;
use prover::utils::{save_calldata, export_verifying_key_to_rs};
use prover::utils::{save_proof, save_public_input, save_verifying_key};

use clap::{Parser, Subcommand};
use rand::thread_rng;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;


/// zkcli: zkSNARK proof and calldata tool
#[derive(Parser)]
#[command(name = "zkcli")]
#[command(about = "Generate zkSNARK proof and calldata")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate proof and calldata for a * b = c
    Prove {
        #[arg(long)]
        a: u64,
        #[arg(long)]
        b: u64,
        #[arg(long)]
        c: u64,

        #[arg(long, default_value = "../calldata.bin")]
        out: String,
    },

    /// Verify proof + public input using verifying key
    Verify {
        #[arg(long)]
        proof: String,

        #[arg(long)]
        input: String,

        #[arg(long)]
        vk: String,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Prove { a, b, c, out } => {
            let a = Fr::from(*a);
            let b = Fr::from(*b);
            let c = Fr::from(*c);
        
            let setup_circuit = MulCircuit { a: Some(a), b: Some(b), c: Some(c) };
            let prove_circuit = MulCircuit { a: Some(a), b: Some(b), c: Some(c) };
        
            let mut rng = thread_rng();
            let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(setup_circuit, &mut rng)?;
            let proof = Groth16::<Bn254>::create_random_proof_with_reduction(prove_circuit, &params, &mut rng)?;
        
            std::fs::create_dir_all("../proofs")?;
            std::fs::create_dir_all("../keys")?;
        
            save_calldata(&proof, &c, out)?;
            save_proof(&proof)?;
            save_public_input(&c)?;
            save_verifying_key(&params.vk)?;
            export_verifying_key_to_rs(&params.vk)?;
        
            println!("✅ Wrote calldata, proof, public input, and verifying key.");
        },        

        Commands::Verify { proof, input, vk } => {
            use ark_groth16::{Proof, VerifyingKey, Groth16, prepare_verifying_key};
            use ark_serialize::CanonicalDeserialize;
            use std::fs::File;
            use std::io::BufReader;
        
            // Load proof
            let mut file = BufReader::new(File::open(proof)?);
            let proof = Proof::<Bn254>::deserialize_compressed(&mut file)
                .map_err(|e| format!("Failed to deserialize proof: {e}"))?;
        
            // Load public input
            let mut file = BufReader::new(File::open(input)?);
            let public_input = Fr::deserialize_uncompressed(&mut file)
                .map_err(|e| format!("Failed to deserialize input: {e}"))?;
        
            // Load verifying key
            let mut file = BufReader::new(File::open(vk)?);
            let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut file)
                .map_err(|e| format!("Failed to deserialize verifying key: {e}"))?;
        
            // Verify
            let pvk = prepare_verifying_key(&vk);
            let result = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
                &pvk, &proof, &[public_input]
            ).map_err(|e| format!("Verification error: {e}"))?;

            println!("✅ Verification result: {}", result);
        }
        
    }

    Ok(())
}
