#!/usr/bin/env bash
set -euo pipefail

echo "🔧 Building Rust contract..."
(cd verifier-contract && make)

echo "🔐 Generating zkSNARK proof and calldata..."
cargo run --bin zkcli prove --a 3 --b 4 --c 12 --out calldata.bin

echo "📦 Deploying Rust contract to PVM..."
RUST_ADDRESS=$(cast send --account dev-account --create "$(xxd -p -c 99999 verifier-contract/contract.polkavm)" --json | jq -r .contractAddress)
echo "✅ Rust contract deployed at: $RUST_ADDRESS"

echo "🧾 Compiling Solidity wrapper..."
npx @parity/revive@latest --bin verifier-contract/CallVerifier.sol

echo "📦 Deploying Solidity wrapper..."
SOL_WRAPPER=verifier-contract_CallVerifier_sol_VerifyFromSolidity.polkavm
SOL_ADDRESS=$(cast send --account dev-account --create "$(xxd -p -c 99999 $SOL_WRAPPER)" --json | jq -r .contractAddress)
echo "✅ Solidity wrapper deployed at: $SOL_ADDRESS"

echo "📨 Calling Solidity wrapper to test zkSNARK verification..."
CALldata_HEX=$(xxd -p calldata.bin | tr -d '\n')
cast call $SOL_ADDRESS "verify(bytes,address)(bool)" 0x$CALldata_HEX $RUST_ADDRESS