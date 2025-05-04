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
npx @parity/revive@latest --bin contracts/CallVerifier.sol

echo "📦 Deploying Solidity wrapper..."
SOL_WRAPPER=contracts/CallVerifier_sol_CallVerifier.polkavm
SOL_ADDRESS=$(cast send --account dev-account --create "$(xxd -p -c 99999 $SOL_WRAPPER)" --json | jq -r .contractAddress)
echo "✅ Solidity wrapper deployed at: $SOL_ADDRESS"

echo "🧪 Calling Solidity wrapper to invoke zkSNARK verifier..."
cast call $SOL_ADDRESS "verify(address) returns (bool)" $RUST_ADDRESS
