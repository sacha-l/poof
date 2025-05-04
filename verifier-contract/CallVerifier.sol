// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// Wrapper to call the Rust contract's exported `call()` with encoded calldata
contract VerifyFromSolidity {
    /// Calls the deployed Rust contract and passes ABI-compatible calldata
    function verify(bytes calldata proofAndInput, address rustContract) external view returns (bool result) {
        (bool success, bytes memory returnData) = rustContract.staticcall(proofAndInput);
        require(success, "Rust contract call failed");

        // Expect a single bool (last byte is 0 or 1)
        require(returnData.length == 32, "Invalid return data");
        result = returnData[31] != 0;
    }
}
