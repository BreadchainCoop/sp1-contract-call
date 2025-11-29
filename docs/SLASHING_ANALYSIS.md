# Slashing Analysis: GasKillerSDK verifyAndUpdate()

## Current Signed Message

The aggregate network signs:
```solidity
sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates))
```

| Field | Type | Description |
|-------|------|-------------|
| `transitionIndex` | `uint256` | Sequential state transition counter |
| `address(this)` | `address` | Target contract being updated |
| `targetFunction` | `bytes4` | Function selector (4 bytes only) |
| `storageUpdates` | `bytes` | Encoded storage changes `(slot, value)` pairs |

## Problem: Missing Values for Slashable Proofs

To create a valid slashing proof, you need to **reproduce the exact execution** and prove the signed `storageUpdates` were incorrect. The current signature is missing critical values:

### 1. Full Calldata (CRITICAL)

**Current:** Only `targetFunction` (4-byte selector) is signed

**Problem:** Cannot reproduce the call without function arguments

```solidity
// Example: ERC20 transfer
// Selector: 0xa9059cbb
// But you also need (address to, uint256 amount)!

function transfer(address to, uint256 amount) external returns (bool);
```

Without the full calldata, you cannot:
- Know what parameters were passed
- Reproduce the execution
- Prove the storage updates were wrong

**Fix:** Sign `contractCalldata` instead of just `targetFunction`

### 2. Block Hash / Block Number (CRITICAL)

**Current:** Not signed

**Problem:** Cannot anchor execution to a specific Ethereum state

Without a block reference:
- Attacker could claim "this was valid at block X"
- No way to prove which state the execution was against
- SP1 proof needs an anchor to verify against

**Fix:** Sign `anchorHash` (block hash) or `blockNumber`

### 3. Caller Address (CRITICAL)

**Current:** Not signed

**Problem:** `msg.sender` affects execution

```solidity
// Access control depends on caller
require(msg.sender == owner, "Not owner");

// Balances depend on caller
balances[msg.sender] -= amount;
```

Without the caller:
- Cannot reproduce execution (different msg.sender = different results)
- Cannot prove the aggregate network was wrong

**Fix:** Sign `callerAddress`

### 4. msg.value (MEDIUM)

**Current:** Not signed

**Problem:** Affects payable functions

```solidity
// WETH deposit() uses msg.value
function deposit() public payable {
    balanceOf[msg.sender] += msg.value;
}
```

**Fix:** Sign `msgValue` for payable function support

### 5. Opcode Hash (RECOMMENDED)

**Current:** Not signed

**Problem:** No execution path commitment

The `opcodeHash` provides:
- Proof of which opcodes executed
- Detection of execution path divergence
- Commitment to the exact execution trace

While not strictly required, it strengthens the slashing proof by providing a unique fingerprint of the execution.

## Proposed Signed Message for Slashable Proofs

```solidity
sha256(abi.encode(
    transitionIndex,      // Existing: replay protection
    address(this),        // Existing: target contract
    anchorHash,           // NEW: block hash for state anchoring
    callerAddress,        // NEW: who made the call
    contractCalldata,     // CHANGED: full calldata, not just selector
    storageUpdates,       // Existing: the claimed storage changes
    opcodeHash            // NEW: execution trace commitment
))
```

## Comparison: Current vs Required

| Value | Currently Signed | Required for Slashing |
|-------|-----------------|----------------------|
| `transitionIndex` | ✅ Yes | ✅ Replay protection |
| `contractAddress` | ✅ Yes | ✅ Target identification |
| `targetFunction` | ✅ Yes (4 bytes) | ❌ Need full calldata |
| `contractCalldata` | ❌ No | ✅ **CRITICAL** |
| `anchorHash` | ❌ No | ✅ **CRITICAL** |
| `callerAddress` | ❌ No | ✅ **CRITICAL** |
| `msgValue` | ❌ No | ⚠️ For payable functions |
| `storageUpdates` | ✅ Yes | ✅ What's being verified |
| `opcodeHash` | ❌ No | ⚠️ Recommended |

## Slashing Flow with Required Values

```
┌─────────────────────────────────────────────────────────────────┐
│                     Slashing Proof Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Aggregate Network Signs:                                    │
│     hash = sha256(transitionIndex, contract, anchor, caller,    │
│                   calldata, storageUpdates, opcodeHash)         │
│                                                                 │
│  2. Challenger Claims Fraud:                                    │
│     "The signed storageUpdates are incorrect!"                  │
│                                                                 │
│  3. Challenger Generates SP1 Proof:                             │
│     - Uses same anchor (block hash)                             │
│     - Uses same calldata                                        │
│     - Uses same caller                                          │
│     - Executes in zkVM with opcode tracing                      │
│     - Gets actual storageUpdates and opcodeHash                 │
│                                                                 │
│  4. On-Chain Verification:                                      │
│     a) Verify SP1 proof is valid                                │
│     b) Verify anchor hash via Helios/EIP-4788                   │
│     c) Compare signed vs proven storageUpdates                  │
│     d) If different → SLASH                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Slashing Contract Pseudocode

```solidity
contract GasKillerSlasher {
    ISP1Verifier public sp1Verifier;
    bytes32 public programVKey;

    struct SignedCommitment {
        uint256 transitionIndex;
        address contractAddress;
        bytes32 anchorHash;
        address callerAddress;
        bytes contractCalldata;
        bytes storageUpdates;
        bytes32 opcodeHash;
        bytes signature;  // BLS signature from aggregate network
    }

    function slash(
        SignedCommitment calldata commitment,
        bytes calldata sp1Proof,
        bytes calldata sp1PublicValues
    ) external {
        // 1. Verify the aggregate network actually signed this
        bytes32 signedHash = sha256(abi.encode(
            commitment.transitionIndex,
            commitment.contractAddress,
            commitment.anchorHash,
            commitment.callerAddress,
            commitment.contractCalldata,
            commitment.storageUpdates,
            commitment.opcodeHash
        ));
        require(verifyBLSSignature(signedHash, commitment.signature), "Invalid signature");

        // 2. Verify the SP1 proof
        sp1Verifier.verifyProof(programVKey, sp1PublicValues, sp1Proof);

        // 3. Decode SP1 public values (the correct execution)
        (
            ,
            bytes32 provenAnchorHash,
            ,
            ,
            address provenCaller,
            address provenContract,
            bytes memory provenCalldata,
            bytes memory provenOutput,
            bytes32 provenOpcodeHash
        ) = abi.decode(sp1PublicValues, (...));

        // 4. Verify inputs match
        require(provenAnchorHash == commitment.anchorHash, "Anchor mismatch");
        require(provenContract == commitment.contractAddress, "Contract mismatch");
        require(provenCaller == commitment.callerAddress, "Caller mismatch");
        require(keccak256(provenCalldata) == keccak256(commitment.contractCalldata), "Calldata mismatch");

        // 5. Check for fraud: either storage or opcode hash differs
        bytes32 provenStorageHash = keccak256(extractStorageUpdates(provenOutput));
        bytes32 signedStorageHash = keccak256(commitment.storageUpdates);

        bool storageFraud = provenStorageHash != signedStorageHash;
        bool opcodeFraud = provenOpcodeHash != commitment.opcodeHash;

        require(storageFraud || opcodeFraud, "No fraud detected");

        // 6. SLASH - penalize the aggregate network
        _executeSlashing(commitment.signature);
    }
}
```

## Summary

**The current `verifyAndUpdate()` function is NOT slashable** because it's missing:

1. ❌ **Full calldata** - Only function selector signed
2. ❌ **Block anchor** - No state reference
3. ❌ **Caller address** - Cannot reproduce execution

**To enable slashing, the aggregate network must sign:**

```solidity
// Minimum required for slashing
sha256(abi.encode(
    transitionIndex,
    address(this),
    anchorHash,        // Block hash
    callerAddress,     // msg.sender
    contractCalldata,  // Full calldata with arguments
    storageUpdates     // The claimed results
))

// Recommended (adds execution trace verification)
sha256(abi.encode(
    transitionIndex,
    address(this),
    anchorHash,
    callerAddress,
    contractCalldata,
    storageUpdates,
    opcodeHash         // Execution fingerprint
))
```

This allows a challenger to:
1. Reproduce the exact execution using SP1 + the signed inputs
2. Compare the proven results with the signed results
3. Slash if they differ
