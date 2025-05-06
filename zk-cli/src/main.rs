use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use prover::circuit::MulCircuit;
use prover::utils::{save_calldata, export_verifying_key_to_rs};
use prover::utils::{save_proof, save_public_input, save_verifying_key};

use clap::{Parser, Subcommand};
use rand::thread_rng;
use ark_groth16::{Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::path::Path;
use anyhow::{Result, Context};  


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
            let a_fr = Fr::from(*a);
            let b_fr = Fr::from(*b);
            let c_fr = a_fr * b_fr; // enforces property to handle user error
        
            if *a * *b != *c {
                println!("⚠️ Warning: you entered inputs that won't match the expected outputs!");
            }

            let setup_circuit = MulCircuit { a: None, b: None, c: None };
            let prove_circuit = MulCircuit { a: Some(a_fr), b: Some(b_fr), c: Some(c_fr) };
        
            let mut rng = thread_rng();
            let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(setup_circuit, &mut rng)?;
            let proof = Groth16::<Bn254>::create_random_proof_with_reduction(prove_circuit, &params, &mut rng)?;
        
            let calldata_path = PathBuf::from(out);                
            let proof_path      = Path::new("../proofs/proof.bin");
            let input_path      = Path::new("../proofs/public_input.bin");
            let vk_bin_path     = Path::new("../keys/verifying_key.bin");
            let vk_rs_path      = Path::new("../keys/verifying_key_bytes.rs");

            std::fs::create_dir_all("../proofs")?;
            std::fs::create_dir_all("../keys")?;
        
            save_calldata(&proof, &c_fr, out)?;
            save_proof(&proof)?;
            save_public_input(&c_fr)?;
            save_verifying_key(&params.vk)?;
            export_verifying_key_to_rs(&params.vk)?;
        
            println!("✅ Wrote calldata, proof, public input, and verifying key.");
            println!(
                "\n📂  Artefacts written:\n\
                 • calldata .......... {}\n\
                 • compressed proof .. {}\n\
                 • public input ...... {}\n\
                 • verifying key ..... {}\n\
                 • vk byte array ..... {}\n",
                calldata_path.display(),
                proof_path.display(),
                input_path.display(),
                vk_bin_path.display(),
                vk_rs_path.display(),
            );
        },        

        Commands::Verify { proof, input, vk } => {        
            // Load proof
            let proof_path = PathBuf::from(proof);
            let input_path = PathBuf::from(input);
            let vk_path    = PathBuf::from(vk);
            
            println!("Proof: {:?}", proof);

            let proof: Proof<Bn254> = {
                let mut reader = BufReader::new(
                    File::open(&proof_path)
                        .with_context(|| format!("opening proof file {}", proof_path.display()))?
                );
                Proof::<Bn254>::deserialize_compressed(&mut reader)
                    .context("deserialising Groth16 proof")?
            };
        
            let public_input: Fr = {
                let mut reader = BufReader::new(
                    File::open(&input_path)
                        .with_context(|| format!("opening input file {}", input_path.display()))?
                );
                Fr::deserialize_uncompressed(&mut reader)
                    .context("deserialising public input")?
            };
        
            let vk: VerifyingKey<Bn254> = {
                let mut reader = BufReader::new(
                    File::open(&vk_path)
                        .with_context(|| format!("opening verifying-key file {}", vk_path.display()))?
                );
                VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)
                    .context("deserialising verifying key")?
            };

            // verify 
            let pvk   = prepare_verifying_key(&vk);
            let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_input])
                .context("running pairing check")?;
        
            println!("✅ Verification result: {valid}");
        }
        
    }

    Ok(())
}
