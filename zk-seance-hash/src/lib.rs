/// “I know a secret value x such that H(x) = h, where H is a ZK-friendly hash function.”
/// 
/// This simply implements a zk-SNARK circuit for the Poseidon hash function proving 
/// knowledge of `x` such that PoseidonCRH(params, &[x]) == expected_hash.
/// The circuit is designed to be used with the Groth16 SNARK scheme.

pub mod verifier;
pub use verifier::verify_proof_bytes;

use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, eq::EqGadget};

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHParametersVar, CRHGadget};
use ark_crypto_primitives::crh::CRHSchemeGadget;

#[derive(Clone)]
pub struct PoseidonHashCircuit {
    pub secret: Option<Fr>,
    pub expected_hash: Option<Fr>,
    pub params: PoseidonConfig<Fr>,
}

impl ConstraintSynthesizer<Fr> for PoseidonHashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let hash_var = FpVar::new_input(cs.clone(), || {
            self.expected_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let params_var = CRHParametersVar::new_constant(cs.clone(), &self.params)?;
        let out_var = CRHGadget::<Fr>::evaluate(&params_var, &[secret_var.clone()])?;
        out_var.enforce_equal(&hash_var)?;
        Ok(())
    }
}
