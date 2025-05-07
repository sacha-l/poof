#!/usr/bin/env bash
set -euo pipefail

# ───────────────────────── CONFIG ──────────────────────────
export ETH_RPC_URL="${ETH_RPC_URL:-https://westend-asset-hub-eth-rpc.polkadot.io}"

ACCOUNT_ALIAS="dev-account"
PROVER_BIN="zkcli"
RUST_DIR="verifier-contract"
RUST_BIN="$RUST_DIR/contract.polkavm"
WRAPPER_SOL="$RUST_DIR/CallVerifier.sol"
WRAPPER_BIN="verifier-contract_CallVerifier_sol_VerifyFromSolidity.polkavm"
CALDATA_FILE="calldata.bin"
# ────────────────────────────────────────────────────────────

echo "🔧 Building Rust verifier …"
(cd "$RUST_DIR" && make)

echo "🔐 Generating proof & calldata …"
cargo run --release --bin "$PROVER_BIN" -- prove \
      --a 3 --b 4 --c 12 --out "$CALDATA_FILE"

echo "♻️  Estimating deploy gas …"
DEPLOY_GAS=$(cast estimate \
              --account "$ACCOUNT_ALIAS" \
              --create "$(xxd -p -c 99999 "$RUST_BIN")")
echo "   deploy gas: $DEPLOY_GAS"

echo "📦 Deploying verifier contract …"
RUST_ADDRESS=$(cast send \
                 --account "$ACCOUNT_ALIAS" \
                 --create "$(xxd -p -c 99999 "$RUST_BIN")" \
                 --json | jq -r .contractAddress)
echo "✅ Rust contract at: $RUST_ADDRESS"

CALDATA_HEX=$(xxd -p "$CALDATA_FILE" | tr -d '\n')

echo "♻️  Estimating proof-call gas …"
CALL_GAS=$(cast estimate \
             "$RUST_ADDRESS" 0x"$CALDATA_HEX" \
             --account "$ACCOUNT_ALIAS")
echo "   proof call gas: $CALL_GAS"

echo "🚀 Calling verifier directly …"
RESULT_DIRECT=$(cast call "$RUST_ADDRESS" 0x"$CALDATA_HEX")
echo "   verifier returned: $RESULT_DIRECT"

# optional: fetch heap usage event
TX_HASH=$(cast send \
            --account "$ACCOUNT_ALIAS" \
            --to "$RUST_ADDRESS" \
            0x"$CALDATA_HEX" \
            --json | jq -r .transactionHash)
EVENT_HEAP=$(cast receipt "$TX_HASH" --json \
              | jq -r '.logs[]? | select(.topics[0]=="0xdeadbeef") | .data')
[[ -n "$EVENT_HEAP" ]] && echo "   heap used (bytes): $((0x${EVENT_HEAP:2}))"

echo "🧾 Compiling Solidity wrapper …"
npx --yes @parity/revive@latest --bin "$WRAPPER_SOL"

echo "📦 Deploying wrapper …"
SOL_ADDRESS=$(cast send \
                --account "$ACCOUNT_ALIAS" \
                --create "$(xxd -p -c 99999 "$WRAPPER_BIN")" \
                --json | jq -r .contractAddress)
echo "✅ Wrapper at: $SOL_ADDRESS"

echo "📨 Calling wrapper → verifier …"
RESULT_WRAP=$(cast call "$SOL_ADDRESS" \
               "verify(bytes,address)(bool)" 0x"$CALDATA_HEX" "$RUST_ADDRESS")
echo "   wrapper returned: $RESULT_WRAP"
