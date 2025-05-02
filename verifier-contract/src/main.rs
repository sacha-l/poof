/*!
    zkSNARK Verifier Contract for PVM

    This contract is a minimal verifier implementation targeting the Polkadot Virtual Machine (PVM).
    It performs zero-knowledge proof verification using the Groth16 proving system over the BN254 curve.

    ## Highlights:
    - Compiles to `no_std` and targets the `riscv64emac-unknown-none-polkavm` architecture.
    - Verifier logic implemented in Rust using the `arkworks` Groth16 backend.
    - Takes ABI-compatible calldata (selector + proof + input), verifies it, and returns a boolean result.
    - Uses a custom dummy allocator to support builds in environments without heap support.

    ## Expected Calldata Format:
    - 4 bytes: function selector (ignored for now)
    - 256 bytes: Groth16 proof (A: G1 = 64, B: G2 = 128, C: G1 = 64)
    - 32 bytes: Public input (Fr element from BN254)

    Total: 292 bytes

    ## Deployment and Use:
    - Embed the verifying key at compile time using `verifying_key_bytes.rs`.
    - Use an off-chain prover to generate the calldata.
    - Deploy the contract using `deploy()`.
    - Call the contract with `call()` and calldata to perform verification.
*/

#![no_std]
#![no_main]

use ark_ec::models::bn::Bn;
use ark_bn254::{Config as Bn254Config};

use ark_groth16::{Groth16, prepare_verifying_key, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use uapi::{HostFn, HostFnImpl as api, ReturnFlags};
use core::alloc::Layout;

type Bn254 = Bn<Bn254Config>;

#[global_allocator]
static ALLOCATOR: DummyAllocator = DummyAllocator;

pub struct DummyAllocator;

unsafe impl core::alloc::GlobalAlloc for DummyAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp");
        core::hint::unreachable_unchecked();
    }
}

// Embed verifying key at compile time
include!("../../keys/verifying_key_bytes.rs");

#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {}

#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    // Allocate enough for selector (4 bytes) + compressed proof (256 bytes) + input (32 bytes)
    let mut calldata = [0u8; 4 + 256 + 32];

    api::call_data_copy(&mut calldata, 0);

    let proof_bytes = &calldata[4..260];
    let input_bytes = &calldata[260..];

    let vk: VerifyingKey<Bn254> = match CanonicalDeserialize::deserialize_compressed(VERIFYING_KEY_BYTES) {
        Ok(vk) => vk,
        Err(_) => {
            return_false();
            return;
        }
    };

    let proof: Proof<Bn254> = match CanonicalDeserialize::deserialize_compressed(proof_bytes) {
        Ok(p) => p,
        Err(_) => {
            return_false();
            return;
        }
    };

    let public_input = match CanonicalDeserialize::deserialize_compressed(input_bytes) {
        Ok(i) => i,
        Err(_) => {
            return_false();
            return;
        }
    };

    let pvk = prepare_verifying_key(&vk);
    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public_input]).unwrap_or(false);

    return_bool(is_valid);
}

fn return_bool(b: bool) {
    let mut output = [0u8; 32];
    output[31] = if b { 1 } else { 0 };
    api::return_value(ReturnFlags::empty(), &output);
}

fn return_false() {
    return_bool(false);
}
