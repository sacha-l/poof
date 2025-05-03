use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use prover::circuit::MulCircuit;
use prover::utils::{save_calldata, export_verifying_key_to_rs};

use clap::{Parser, Subcommand};
use rand::thread_rng;

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

            save_calldata(&proof, &c, out)?;
            export_verifying_key_to_rs(&params.vk)?;

            println!("✅ Calldata saved to {}", out);
        }
    }

    Ok(())
}
