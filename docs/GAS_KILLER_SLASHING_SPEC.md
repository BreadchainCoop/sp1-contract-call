# Technical Spec: Gas Killer On-Chain Slashing

## 1. Background

### Problem Statement

The Gas Killer aggregate network signs storage updates for contract state transitions, but there is currently no mechanism to penalize operators who sign incorrect storage updates. Without slashing, malicious or faulty operators can sign fraudulent state transitions without consequence, undermining the security guarantees of the system.

### Context / History

- **Gas Killer SDK**: Implements `verifyAndUpdate()` for applying signed storage updates
- **EigenLayer Integration**: Uses BLS signature verification with 66% quorum threshold
- **SP1 Contract Call**: Provides zkVM execution proofs for EVM contract calls
- **Opcode Hash Feature**: Commits to state-modifying opcodes (SSTORE, CALL, LOG0-LOG4) in proofs
- **Current Gap**: The signed message lacks sufficient data for reproducible execution verification

**Relevant Links:**
- [GasKillerSDK.sol](https://github.com/BreadchainCoop/gas-killer-solidity-sdk/blob/main/src/GasKillerSDK.sol)
- [SP1 Contract Call](https://github.com/succinctlabs/sp1-contract-call)
- [Helios Light Client](https://github.com/a16z/helios)

### Stakeholders

| Stakeholder | Role |
|-------------|------|
| Aggregate Network Operators | Sign storage updates, subject to slashing |
| Gas Killer SDK Users | Rely on correct state transitions |
| Challengers | Submit fraud proofs to slash malicious operators |
| EigenLayer | Provides restaking and slashing infrastructure |
| Helios/EIP-4788 | Block hash verification for state anchoring |

---

## 2. Motivation

### Goals & Success Stories

**Goal 1: Enable Fraud Detection**
> As a challenger, I can prove that the aggregate network signed incorrect storage updates by generating an SP1 proof of the correct execution and comparing results.

**Goal 2: Cryptoeconomic Security**
> As a Gas Killer user, I can trust that operators have economic stake at risk, ensuring they are incentivized to sign correct updates.

**Goal 3: Deterministic Verification**
> As a slashing contract, I can verify that given the same inputs (block, caller, calldata), the signed storage updates do not match the proven execution.

**Goal 4: Minimal Protocol Changes**
> As a developer, I can integrate slashing by modifying only the signed message format, without changing the core execution flow.

---

## 3. Scope and Approaches

### Non-Goals

| Technical Functionality | Reasoning for being off scope | Tradeoffs |
|------------------------|------------------------------|-----------|
| Real-time slashing | Requires complex dispute game | Delayed slashing is acceptable for economic security |
| Slashing for liveness failures | Out of scope for this spec | Focus on correctness, not availability |
| Cross-chain slashing | Adds complexity | Single-chain slashing first |
| Automatic challenger rewards | Incentive design is separate | Manual reward distribution initially |

### Value Proposition

| Technical Functionality | Value | Tradeoffs |
|------------------------|-------|-----------|
| SP1 Proof Verification | Cryptographic guarantee of correct execution | ~300k gas per verification |
| Helios Block Verification | Proves execution against real Ethereum state | ~200k gas, requires light client sync |
| EIP-4788 Alternative | Cheaper block verification for recent blocks | Only works for last ~27 hours |
| Derived Opcode Hash | Execution fingerprint from storage updates | Implicit in storage structure |

### Alternative Approaches

| Approach | Pros | Cons |
|----------|------|------|
| **SP1 zkVM Proofs (Chosen)** | Cryptographic soundness, supports any EVM execution | Higher gas cost, proof generation time |
| **Optimistic Fraud Proofs** | Lower gas in happy path | Longer dispute windows, complex bisection |
| **TEE Attestation** | Fast verification | Trust in hardware, not cryptographic |
| **Re-execution by Committee** | Simple implementation | Requires trusted committee, not trustless |

### Relevant Metrics

- Slashing proof verification gas cost: ~500k gas (SP1 + Helios)
- Proof generation time: ~5 minutes (CPU), ~30 seconds (SP1 Network)
- Challenge window: Configurable (suggested: 7 days)
- Minimum slash amount: Configurable per operator stake

---

## 4. Step-by-Step Flow

### 4.1 Main ("Happy") Path: No Fraud

**Pre-condition:** Aggregate network has signed a valid storage update commitment

1. **Operator** signs storage update commitment:
   ```
   commitment = sha256(transitionIndex, contract, anchorHash, caller, calldata, storageUpdates)
   ```

2. **User** calls `verifyAndUpdate()` with BLS signature

3. **Contract** validates:
   - Block number is not stale (≤300 blocks)
   - Transition index is sequential
   - BLS signature has ≥66% quorum

4. **Contract** applies storage updates via `StateChangeHandlerLib`

**Post-condition:** State updated, no fraud detected, operators retain stake

---

### 4.2 Slashing Path: Fraud Detected

**Pre-condition:** Challenger believes signed storage updates are incorrect

1. **Challenger** retrieves the signed commitment from on-chain events

2. **Challenger** generates SP1 proof:
   - Fetches Ethereum state at `anchorHash` block
   - Executes `calldata` against `contract` from `caller`
   - Captures actual storage updates from execution
   - Generates PLONK proof with `ContractPublicValuesWithTrace`

3. **Challenger** calls `slash()` with:
   - Original signed commitment + BLS signature
   - SP1 proof + public values

4. **Slashing Contract** validates:
   - BLS signature is valid for the commitment
   - SP1 proof is valid
   - Anchor hash matches (via Helios or EIP-4788)
   - Inputs match (caller, contract, calldata)
   - Storage updates differ → **FRAUD CONFIRMED**

5. **Slashing Contract** executes penalty:
   - Emits `OperatorSlashed` event
   - Triggers EigenLayer slashing for signing operators

**Post-condition:** Malicious operators slashed, challenger optionally rewarded

---

### 4.3 Alternate / Error Paths

| # | Condition | System Action | Suggested Handling |
|---|-----------|---------------|-------------------|
| A1 | SP1 proof invalid | Revert with `InvalidProof` | Challenger must regenerate proof |
| A2 | Anchor hash not verified by Helios | Revert with `UnverifiedBlock` | Wait for Helios sync or use EIP-4788 |
| A3 | Inputs don't match commitment | Revert with `InputMismatch` | Challenger submitted wrong data |
| A4 | Storage updates match | Revert with `NoFraudDetected` | No slashing, commitment was correct |
| A5 | Challenge window expired | Revert with `ChallengeExpired` | Too late to challenge this transition |
| A6 | Operator already slashed | Revert with `AlreadySlashed` | Prevent double slashing |

---

## 5. UML Diagrams

### 5.1 Class Diagram

```mermaid
classDiagram
    class GasKillerSlasher {
        +ISP1Verifier sp1Verifier
        +IHeliosLightClient helios
        +bytes32 programVKey
        +uint256 challengeWindow
        +slash(commitment, sp1Proof, publicValues)
        +isSlashed(bytes32 commitmentHash) bool
    }

    class SignedCommitment {
        +uint256 transitionIndex
        +address contractAddress
        +bytes32 anchorHash
        +address callerAddress
        +bytes contractCalldata
        +bytes storageUpdates
        +bytes blsSignature
    }

    class ContractPublicValuesWithTrace {
        +uint256 id
        +bytes32 anchorHash
        +uint8 anchorType
        +bytes32 chainConfigHash
        +address callerAddress
        +address contractAddress
        +bytes contractCalldata
        +bytes contractOutput
        +bytes32 opcodeHash
    }

    class ISP1Verifier {
        +verifyProof(vkey, publicValues, proof)
    }

    class IHeliosLightClient {
        +isBlockHashValid(blockHash) bool
        +getBlockHash(blockNumber) bytes32
    }

    GasKillerSlasher --> ISP1Verifier : verifies proofs
    GasKillerSlasher --> IHeliosLightClient : verifies blocks
    GasKillerSlasher --> SignedCommitment : validates
    GasKillerSlasher --> ContractPublicValuesWithTrace : extracts
```

### 5.2 Sequence Diagram: Slashing Flow

```mermaid
sequenceDiagram
    participant Challenger
    participant SlashingContract
    participant SP1Verifier
    participant Helios
    participant EigenLayer

    Note over Challenger: Detects fraudulent commitment

    Challenger->>Challenger: Generate SP1 proof locally
    Challenger->>SlashingContract: slash(commitment, proof, publicValues)

    SlashingContract->>SlashingContract: Verify BLS signature
    SlashingContract->>SP1Verifier: verifyProof(vkey, publicValues, proof)
    SP1Verifier-->>SlashingContract: Valid ✓

    SlashingContract->>Helios: isBlockHashValid(anchorHash)
    Helios-->>SlashingContract: Valid ✓

    SlashingContract->>SlashingContract: Compare storageUpdates
    Note over SlashingContract: signed ≠ proven → FRAUD

    SlashingContract->>EigenLayer: initiateSlashing(operators)
    SlashingContract-->>Challenger: SlashingExecuted event
```

### 5.3 State Diagram: Commitment Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Signed: Operators sign commitment
    Signed --> Applied: verifyAndUpdate() succeeds
    Signed --> Challenged: Challenger submits proof
    Applied --> Challenged: Within challenge window
    Challenged --> Slashed: Fraud confirmed
    Challenged --> Finalized: No fraud detected
    Applied --> Finalized: Challenge window expires
    Slashed --> [*]: Operators penalized
    Finalized --> [*]: Commitment is final
```

---

## 6. Technical Specification

### 6.1 Modified Signed Message Format

**Current (Insufficient):**
```solidity
sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates))
```

**Required (Slashable):**
```solidity
sha256(abi.encode(
    transitionIndex,      // uint256: Sequential counter
    contractAddress,      // address: Target contract
    anchorHash,           // bytes32: Block hash for state anchoring
    callerAddress,        // address: msg.sender for the call
    contractCalldata,     // bytes: Full calldata with arguments
    storageUpdates        // bytes: Claimed storage changes
))
```

### 6.2 Storage Updates Format

Storage updates are encoded as parallel arrays:
```solidity
struct StorageUpdate {
    bytes32 slot;   // Storage slot
    bytes32 value;  // New value
}

// Encoded as: abi.encode(StorageUpdate[])
```

**Deriving Opcode Hash from Storage Updates:**
Since each SSTORE corresponds to a storage update, the opcode sequence can be reconstructed:
```
opcodeHash = keccak256(concat(0x55 for each storage update, LOG opcodes from events))
```

### 6.3 Slashing Contract Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

interface IGasKillerSlasher {
    struct SignedCommitment {
        uint256 transitionIndex;
        address contractAddress;
        bytes32 anchorHash;
        address callerAddress;
        bytes contractCalldata;
        bytes storageUpdates;
        bytes blsSignature;
        address[] signers;  // Operators who signed
    }

    event SlashingExecuted(
        bytes32 indexed commitmentHash,
        address indexed challenger,
        address[] slashedOperators,
        uint256 slashAmount
    );

    event ChallengeSubmitted(
        bytes32 indexed commitmentHash,
        address indexed challenger
    );

    /// @notice Submit a slashing proof
    /// @param commitment The original signed commitment
    /// @param sp1Proof The SP1 PLONK proof
    /// @param sp1PublicValues The SP1 public values (ContractPublicValuesWithTrace)
    function slash(
        SignedCommitment calldata commitment,
        bytes calldata sp1Proof,
        bytes calldata sp1PublicValues
    ) external;

    /// @notice Check if a commitment has been slashed
    function isSlashed(bytes32 commitmentHash) external view returns (bool);

    /// @notice Get the challenge window duration
    function challengeWindow() external view returns (uint256);
}
```

### 6.4 SP1 Public Values Decoding

```solidity
function decodePublicValues(bytes calldata publicValues)
    internal
    pure
    returns (
        bytes32 anchorHash,
        address callerAddress,
        address contractAddress,
        bytes memory contractCalldata,
        bytes memory contractOutput,
        bytes32 opcodeHash
    )
{
    // Skip first 32 bytes (offset for dynamic struct)
    // Then decode the ContractPublicValuesWithTrace struct
    (
        uint256 id,
        bytes32 _anchorHash,
        uint8 anchorType,
        bytes32 chainConfigHash,
        address _callerAddress,
        address _contractAddress,
        bytes memory _contractCalldata,
        bytes memory _contractOutput,
        bytes32 _opcodeHash
    ) = abi.decode(publicValues, (
        uint256, bytes32, uint8, bytes32, address, address, bytes, bytes, bytes32
    ));

    return (_anchorHash, _callerAddress, _contractAddress, _contractCalldata, _contractOutput, _opcodeHash);
}
```

### 6.5 Fraud Detection Logic

```solidity
function detectFraud(
    SignedCommitment calldata commitment,
    bytes calldata sp1PublicValues
) internal view returns (bool isFraud, string memory reason) {
    (
        bytes32 provenAnchor,
        address provenCaller,
        address provenContract,
        bytes memory provenCalldata,
        bytes memory provenOutput,
        bytes32 provenOpcodeHash
    ) = decodePublicValues(sp1PublicValues);

    // Verify inputs match
    if (provenAnchor != commitment.anchorHash) {
        return (false, "Anchor mismatch - invalid challenge");
    }
    if (provenCaller != commitment.callerAddress) {
        return (false, "Caller mismatch - invalid challenge");
    }
    if (provenContract != commitment.contractAddress) {
        return (false, "Contract mismatch - invalid challenge");
    }
    if (keccak256(provenCalldata) != keccak256(commitment.contractCalldata)) {
        return (false, "Calldata mismatch - invalid challenge");
    }

    // Extract storage updates from proven output
    bytes memory provenStorageUpdates = extractStorageUpdates(provenOutput);

    // Compare storage updates
    if (keccak256(provenStorageUpdates) != keccak256(commitment.storageUpdates)) {
        return (true, "Storage updates differ - FRAUD DETECTED");
    }

    return (false, "No fraud detected");
}
```

---

## 7. Edge Cases and Concessions

### Edge Cases

| Case | Description | Handling |
|------|-------------|----------|
| **Reorg Risk** | Block containing commitment is reorged | Use sufficient block confirmations before challenge |
| **Gas Limit** | Proof verification exceeds block gas limit | SP1 PLONK proofs ~300k gas, well within limits |
| **Helios Sync Delay** | Helios not synced to anchor block | Allow EIP-4788 fallback for recent blocks |
| **Multiple Challengers** | Race condition on slashing | First valid slash wins, others refunded |
| **Partial Quorum Slash** | Only some signers were malicious | Slash all signers equally (simplest model) |

### Design Concessions

1. **All-or-Nothing Slashing**: All operators who signed a fraudulent commitment are slashed equally, even if some were following honest leader.

2. **No Graduated Penalties**: First offense and repeat offenses have same penalty. Future iterations may add graduated penalties.

3. **Challenge Window Fixed**: A single global challenge window applies to all commitments. Per-commitment windows add complexity.

4. **EigenLayer Dependency**: Slashing execution depends on EigenLayer infrastructure. Alternative slashing mechanisms not supported.

---

## 8. Open Questions

| # | Question | Impact | Status |
|---|----------|--------|--------|
| 1 | What is the appropriate challenge window duration? | Security vs. finality tradeoff | **Suggested: 7 days** |
| 2 | Should challengers receive rewards from slashed stake? | Incentive alignment | **TBD - separate spec** |
| 3 | How to handle the case where a contract self-destructs? | Edge case in verification | **Low priority** |
| 4 | Should we support batched slashing for multiple frauds? | Gas efficiency | **Future optimization** |
| 5 | What minimum stake is required for operators to be slashable? | Economic security threshold | **Defer to EigenLayer params** |
| 6 | How do we handle upgrades to the SP1 program (new vkey)? | Version management | **Registry contract needed** |

---

## 9. Glossary / References

### Glossary

| Term | Definition |
|------|------------|
| **Aggregate Network** | Set of operators who collectively sign storage updates |
| **Anchor Hash** | Block hash that anchors EVM execution to a specific Ethereum state |
| **BLS Signature** | Boneh-Lynn-Shacham signature scheme used for aggregate signatures |
| **Challenger** | Entity that submits fraud proofs to slash malicious operators |
| **Commitment** | Cryptographic hash binding operators to specific storage updates |
| **EIP-4788** | Ethereum improvement storing beacon block roots on-chain |
| **Helios** | Ethereum light client for trustless block hash verification |
| **Opcode Hash** | `keccak256` of state-modifying opcodes executed during a call |
| **Quorum** | Minimum stake threshold (66%) required for valid signatures |
| **Slashing** | Penalty mechanism that confiscates operator stake for misbehavior |
| **SP1** | Succinct's zkVM for generating PLONK proofs of program execution |
| **Storage Updates** | Array of `(slot, value)` pairs representing state changes |
| **Transition Index** | Sequential counter preventing replay of signed commitments |

### References

- [EigenLayer Slashing Documentation](https://docs.eigenlayer.xyz/eigenlayer/security/slashing)
- [SP1 Contract Call Repository](https://github.com/succinctlabs/sp1-contract-call)
- [Helios Light Client](https://github.com/a16z/helios)
- [EIP-4788: Beacon Block Root in the EVM](https://eips.ethereum.org/EIPS/eip-4788)
- [Gas Killer SDK](https://github.com/BreadchainCoop/gas-killer-solidity-sdk)
- [BLS Signature Checker (EigenLayer)](https://github.com/Layr-Labs/eigenlayer-middleware)

---

## 10. Implementation Checklist

- [ ] Modify `GasKillerSDK.verifyAndUpdate()` to sign extended commitment
- [ ] Deploy `GasKillerSlasher` contract
- [ ] Integrate SP1 Verifier contract
- [ ] Deploy/integrate Helios light client (or use EIP-4788)
- [ ] Implement challenger tooling (proof generation scripts)
- [ ] Add slashing hooks to EigenLayer AVS registration
- [ ] Write comprehensive test suite for slashing paths
- [ ] Security audit of slashing contract
- [ ] Deploy to testnet and validate end-to-end flow
- [ ] Mainnet deployment with operator onboarding
