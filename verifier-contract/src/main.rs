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
#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

use core::{
    alloc::{GlobalAlloc, Layout},
    panic::PanicInfo,
    ptr::null_mut,
};

use uapi::{HostFn, HostFnImpl as api, ReturnFlags};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;

// ---------------------------------------------------------------------
// 1.  Static bump allocator (512 KiB)
// ---------------------------------------------------------------------
const HEAP_SIZE: usize = 512 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
static mut OFFSET: usize = 0;

struct Bump;

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size  = layout.size();

        // Align current offset
        let mis = OFFSET % align;
        if mis != 0 {
            OFFSET += align - mis;
        }
        if OFFSET + size > HEAP_SIZE {
            return null_mut();          // triggers trap → ContractTrapped
        }
        let ptr = HEAP.as_mut_ptr().add(OFFSET);
        OFFSET += size;
        ptr
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) { /* no-op */ }
}

#[global_allocator]
static ALLOC: Bump = Bump;

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    unsafe { core::arch::asm!("unimp"); core::hint::unreachable_unchecked() }
}

// ---------------------------------------------------------------------
// 2.  Panic → PolkaVM trap
// ---------------------------------------------------------------------
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { core::arch::asm!("unimp"); core::hint::unreachable_unchecked() }
}

// ---------------------------------------------------------------------
// 3.  Embed verifying-key bytes (generated off-chain)
// ---------------------------------------------------------------------
include!("../../keys/verifying_key_bytes.rs");

// ---------------------------------------------------------------------
// 4.  PolkaVM entry points
// ---------------------------------------------------------------------
#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn deploy() {}

#[no_mangle]
#[polkavm_derive::polkavm_export]
pub extern "C" fn call() {
    // ┌──────────┬──────────────────────────┬───────────────────────┐
    // │ 0..3 sel │ 4..131 compressed Proof │ 132..163 public input │
    // └──────────┴──────────────────────────┴───────────────────────┘
    let mut calldata = [0u8; 164];
    api::call_data_copy(&mut calldata, 0);

    let proof_bytes  = &calldata[4..132];
    let input_bytes  = &calldata[132..164];

    // ----------  Deserialize verifying-key (once per call) ----------
    let mut vk_src = VERIFYING_KEY_BYTES;
    // ----------  Deserialize verifying-key (once per call) ----------
    let vk: VerifyingKey<Bn254> = match VerifyingKey::deserialize_uncompressed(&mut vk_src) {
        Ok(vk) => vk,
        Err(_) => {
            return_bool(false);
            return;
        }
    };
    
    // ----------  Deserialize proof & public input  ----------
    let proof: Proof<Bn254> = match Proof::deserialize_compressed(&mut &*proof_bytes) {
        Ok(p) => p,
        Err(_) => {
            return_bool(false);
            return;
        }
    };
    
    let public: Fr = match Fr::deserialize_compressed(&mut &*input_bytes) {
        Ok(f) => f,
        Err(_) => {
            return_bool(false);
            return;
        }
    };
    
    // ----------  Verify  ----------
    let pvk   = prepare_verifying_key(&vk);
    let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public])
        .unwrap_or(false);

    return_bool(valid);
}

// ---------------------------------------------------------------------
// 5.  Helper: return Solidity-style bool (32-byte word)
// ---------------------------------------------------------------------
fn return_bool(b: bool) {
    let mut out = [0u8; 32];
    out[31] = b as u8;
    api::return_value(ReturnFlags::empty(), &out);
}
