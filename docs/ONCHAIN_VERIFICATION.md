# On-Chain Verification of Opcode Hash Execution Traces

This document explains how to verify on-chain that an opcode hash represents a correct execution trace from a valid Ethereum state.

## Overview

The verification process has three layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                    On-Chain Verification                        │
├─────────────────────────────────────────────────────────────────┤
│  1. SP1 Proof Verification                                      │
│     └─ Proves: Execution was correct, opcode hash is valid      │
│                                                                 │
│  2. Block Hash Verification (Helios / EIP-4788)                 │
│     └─ Proves: The anchor block hash is a real Ethereum block   │
│                                                                 │
│  3. Public Values Extraction                                    │
│     └─ Extract: opcodeHash, contractAddress, calldata, output   │
└─────────────────────────────────────────────────────────────────┘
```

## What the Proof Commits To

The `ContractPublicValuesWithTrace` struct contains all public values:

```solidity
struct ContractPublicValuesWithTrace {
    uint256 id;              // Anchor ID
    bytes32 anchorHash;      // Block hash the execution is anchored to
    AnchorType anchorType;   // How the anchor is verified (BlockHash, EIP4788, Beacon)
    bytes32 chainConfigHash; // Hash of chain configuration
    address callerAddress;   // Who called the contract
    address contractAddress; // Contract that was executed
    bytes contractCalldata;  // The calldata sent to the contract
    bytes contractOutput;    // The return data from the contract
    bytes32 opcodeHash;      // keccak256 of state-modifying opcodes
}
```

The `opcodeHash` is computed as:
```
opcodeHash = keccak256(concat(SSTORE, CALL, LOG0, LOG1, LOG2, LOG3, LOG4 opcodes in execution order))
```

## Step 1: Deploy SP1 Verifier Contract

SP1 provides a PLONK verifier that can be deployed on-chain:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

contract OpcodeHashVerifier {
    /// @notice The SP1 verifier contract (deployed by Succinct)
    ISP1Verifier public immutable verifier;

    /// @notice The verification key for the opcode tracing program
    bytes32 public immutable programVKey;

    constructor(address _verifier, bytes32 _programVKey) {
        verifier = ISP1Verifier(_verifier);
        programVKey = _programVKey;
    }

    /// @notice Verifies a proof and extracts the opcode hash
    /// @param proof The SP1 PLONK proof
    /// @param publicValues The ABI-encoded ContractPublicValuesWithTrace
    /// @return opcodeHash The verified opcode hash
    function verifyAndExtractOpcodeHash(
        bytes calldata proof,
        bytes calldata publicValues
    ) external view returns (bytes32 opcodeHash) {
        // Verify the SP1 proof
        verifier.verifyProof(programVKey, publicValues, proof);

        // Decode public values to extract opcode hash
        (
            uint256 id,
            bytes32 anchorHash,
            uint8 anchorType,
            bytes32 chainConfigHash,
            address callerAddress,
            address contractAddress,
            bytes memory contractCalldata,
            bytes memory contractOutput,
            bytes32 _opcodeHash
        ) = abi.decode(publicValues, (
            uint256, bytes32, uint8, bytes32, address, address, bytes, bytes, bytes32
        ));

        return _opcodeHash;
    }
}
```

## Step 2: Verify Block Hash with Helios or EIP-4788

The proof anchors execution to a specific block hash. You need to verify this block hash is real.

### Option A: EIP-4788 Beacon Block Root (Recommended for Recent Blocks)

EIP-4788 stores beacon block roots in a ring buffer accessible at `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`:

```solidity
contract BlockHashVerifier {
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice Verify a beacon block root is valid
    /// @param timestamp The timestamp of the block
    /// @param expectedRoot The expected beacon block root
    function verifyBeaconRoot(uint256 timestamp, bytes32 expectedRoot) public view returns (bool) {
        (bool success, bytes memory data) = BEACON_ROOTS.staticcall(abi.encode(timestamp));
        require(success, "Beacon root lookup failed");
        bytes32 storedRoot = abi.decode(data, (bytes32));
        return storedRoot == expectedRoot;
    }
}
```

### Option B: Helios Light Client (For Any Historical Block)

Helios is an Ethereum light client that verifies block headers using sync committees. To use Helios on-chain:

1. **Deploy Helios Light Client Contract**

```solidity
// Simplified Helios interface
interface IHeliosLightClient {
    /// @notice Get a verified block hash for a given block number
    function getBlockHash(uint256 blockNumber) external view returns (bytes32);

    /// @notice Check if a block hash is verified
    function isBlockHashValid(bytes32 blockHash) external view returns (bool);
}
```

2. **Integrate with Opcode Verifier**

```solidity
contract OpcodeHashVerifierWithHelios {
    ISP1Verifier public immutable sp1Verifier;
    IHeliosLightClient public immutable helios;
    bytes32 public immutable programVKey;

    constructor(
        address _sp1Verifier,
        address _helios,
        bytes32 _programVKey
    ) {
        sp1Verifier = ISP1Verifier(_sp1Verifier);
        helios = IHeliosLightClient(_helios);
        programVKey = _programVKey;
    }

    /// @notice Full verification: SP1 proof + Helios block validation
    function verifyExecution(
        bytes calldata proof,
        bytes calldata publicValues
    ) external view returns (
        bytes32 opcodeHash,
        address contractAddress,
        bytes memory output
    ) {
        // 1. Verify the SP1 proof
        sp1Verifier.verifyProof(programVKey, publicValues, proof);

        // 2. Decode public values
        (
            uint256 id,
            bytes32 anchorHash,
            uint8 anchorType,
            bytes32 chainConfigHash,
            address callerAddress,
            address _contractAddress,
            bytes memory contractCalldata,
            bytes memory contractOutput,
            bytes32 _opcodeHash
        ) = abi.decode(publicValues, (
            uint256, bytes32, uint8, bytes32, address, address, bytes, bytes, bytes32
        ));

        // 3. Verify the block hash is real using Helios
        require(helios.isBlockHashValid(anchorHash), "Invalid block hash");

        return (_opcodeHash, _contractAddress, contractOutput);
    }
}
```

## Step 3: Complete Verification Flow

Here's the complete flow from proof generation to on-chain verification:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           OFF-CHAIN (Host)                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│  1. Fetch Ethereum state at block N via RPC                                  │
│  2. Execute contract call in SP1 zkVM with opcode tracing                    │
│  3. Compute opcodeHash = keccak256(state_modifying_opcodes)                  │
│  4. Generate PLONK proof                                                     │
│  5. Output: proof, publicValues (includes anchorHash, opcodeHash)            │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                           ON-CHAIN (Verifier)                                │
├──────────────────────────────────────────────────────────────────────────────┤
│  1. Receive proof + publicValues                                             │
│  2. SP1Verifier.verifyProof(vkey, publicValues, proof)                       │
│     └─ Cryptographically proves execution was correct                        │
│  3. Helios.isBlockHashValid(anchorHash)                                      │
│     └─ Proves the execution was against real Ethereum state                  │
│  4. Extract and use opcodeHash                                               │
│     └─ Guaranteed to be the correct hash of executed opcodes                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Understanding What opcodeHash Proves

The `opcodeHash` provides a cryptographic commitment to the state-modifying operations:

| Opcode | Hex  | Meaning |
|--------|------|---------|
| SSTORE | 0x55 | Storage write |
| CALL   | 0xF1 | External call (may transfer value) |
| LOG0   | 0xA0 | Event with 0 topics |
| LOG1   | 0xA1 | Event with 1 topic |
| LOG2   | 0xA2 | Event with 2 topics |
| LOG3   | 0xA3 | Event with 3 topics |
| LOG4   | 0xA4 | Event with 4 topics |

### Example Opcode Hashes

| Function Type | Opcodes Executed | opcodeHash |
|---------------|------------------|------------|
| View function (slot0) | None | `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` (keccak256 of empty) |
| ERC20 approve | SSTORE, LOG3 | `0x774811dd939f21c1902869a58a93d489d1d413f6111291b79e9e2d11f42b1572` |
| ERC20 transfer | SSTORE, SSTORE, LOG3 | Different hash depending on exact execution path |

## Practical Integration Example

Here's a complete example using the generated proof fixture:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

contract WETHApproveVerifier {
    ISP1Verifier public verifier;
    bytes32 public vkey;

    // Expected opcode hash for WETH approve (SSTORE + LOG3)
    bytes32 constant EXPECTED_APPROVE_OPCODE_HASH =
        0x774811dd939f21c1902869a58a93d489d1d413f6111291b79e9e2d11f42b1572;

    constructor(address _verifier, bytes32 _vkey) {
        verifier = ISP1Verifier(_verifier);
        vkey = _vkey;
    }

    /// @notice Verify a WETH approve execution and check opcode hash
    function verifyApprove(
        bytes calldata proof,
        bytes calldata publicValues
    ) external view returns (bool isValidApprove) {
        // Verify the proof
        verifier.verifyProof(vkey, publicValues, proof);

        // Extract opcode hash (last bytes32 in the struct)
        bytes32 opcodeHash;
        assembly {
            // opcodeHash is at a known offset in publicValues
            // This is simplified - real implementation needs proper ABI decoding
            opcodeHash := calldataload(add(publicValues.offset, 256))
        }

        // Verify this matches expected approve behavior
        return opcodeHash == EXPECTED_APPROVE_OPCODE_HASH;
    }
}
```

## Using with Helios: Full Setup

### 1. Deploy Helios Light Client

Helios can be run as an on-chain light client. See: https://github.com/a]1mersern/helios

```bash
# Clone and build Helios
git clone https://github.com/a16z/helios
cd helios

# Generate Solidity contracts
cargo run --bin helios-contracts
```

### 2. Sync Helios to Target Block

```rust
use helios::client::Client;
use helios::config::networks::Network;

#[tokio::main]
async fn main() {
    let mut client = Client::new(
        "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
        Network::Mainnet,
    ).await.unwrap();

    // Sync to the block used in the proof
    client.sync_to_block(20600000).await.unwrap();

    // Get the verified block hash
    let block = client.get_block_by_number(20600000).await.unwrap();
    println!("Verified block hash: {:?}", block.hash);
}
```

### 3. Submit Helios Proof On-Chain

```solidity
interface IHelios {
    function submitUpdate(bytes calldata update) external;
    function getBlockHash(uint256 slot) external view returns (bytes32);
}

contract FullVerifier {
    IHelios public helios;
    ISP1Verifier public sp1Verifier;
    bytes32 public programVKey;

    function verifyWithHelios(
        bytes calldata heliosUpdate,
        bytes calldata sp1Proof,
        bytes calldata publicValues,
        uint256 blockSlot
    ) external returns (bytes32 opcodeHash) {
        // 1. Update Helios light client
        helios.submitUpdate(heliosUpdate);

        // 2. Get verified block hash from Helios
        bytes32 verifiedBlockHash = helios.getBlockHash(blockSlot);

        // 3. Verify SP1 proof
        sp1Verifier.verifyProof(programVKey, publicValues, sp1Proof);

        // 4. Decode and verify anchor matches Helios
        (, bytes32 anchorHash,,,,,,,bytes32 _opcodeHash) =
            abi.decode(publicValues, (uint256, bytes32, uint8, bytes32, address, address, bytes, bytes, bytes32));

        require(anchorHash == verifiedBlockHash, "Block hash mismatch");

        return _opcodeHash;
    }
}
```

## Security Considerations

1. **Trust in SP1 Verifier**: The SP1 verifier contract must be the official deployment from Succinct Labs
2. **Verification Key Integrity**: The `vkey` must match the exact program that was compiled
3. **Block Hash Verification**: Without Helios/EIP-4788, an attacker could submit proofs against fake state
4. **Opcode Hash Interpretation**: The hash only proves WHICH opcodes ran, not their arguments

## Gas Costs (Approximate)

| Operation | Gas Cost |
|-----------|----------|
| SP1 PLONK Verification | ~300,000 gas |
| Helios Light Client Update | ~200,000 gas |
| EIP-4788 Beacon Root Lookup | ~2,600 gas |
| Public Values Decoding | ~5,000 gas |

## Summary

To verify an opcode hash on-chain:

1. **Deploy**: SP1 Verifier + Helios Light Client (or use EIP-4788)
2. **Submit**: The PLONK proof and public values
3. **Verify**: SP1 proof validity + block hash authenticity via Helios
4. **Extract**: The trusted `opcodeHash` from public values

The opcode hash is then cryptographically guaranteed to represent the exact sequence of state-modifying opcodes that would execute for that contract call on real Ethereum state.
