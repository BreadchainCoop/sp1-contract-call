//! # Opcode Tracer
//!
//! A simple library for tracing EVM opcode execution on Ethereum mainnet.
//!
//! ## Example
//!
//! ```rust,ignore
//! use opcode_tracer::{trace_call, TraceConfig};
//! use alloy_primitives::address;
//!
//! #[tokio::main]
//! async fn main() -> eyre::Result<()> {
//!     let config = TraceConfig {
//!         rpc_url: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY".to_string(),
//!         contract: address!("1d42064Fc4Beb5F8aAF85F4617AE8b3b5B8Bd801"),
//!         calldata: vec![0x3850c7bd], // slot0() selector
//!         block_number: Some(20600000),
//!         caller: None,
//!     };
//!
//!     let trace = trace_call(config).await?;
//!     println!("Executed {} opcodes", trace.opcodes.len());
//!     Ok(())
//! }
//! ```

use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types::BlockNumberOrTag;
use eyre::Result;
use reth_primitives::EthPrimitives;
use serde::{Deserialize, Serialize};
use sp1_cc_client_executor::{io::Primitives, ContractInput};
use sp1_cc_host_executor::EvmSketch;
use url::Url;

/// Re-export useful types
pub use alloy_primitives;
pub use revm::bytecode::opcode::OpCode as RevmOpCode;
pub use sp1_cc_host_executor::{CallTraceArena, CallTraceNode, CallTraceStep};

/// Configuration for tracing a contract call.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// The RPC URL to use for fetching state.
    pub rpc_url: String,
    /// The contract address to call.
    pub contract: Address,
    /// The calldata to send (function selector + encoded args).
    pub calldata: Vec<u8>,
    /// The block number to execute at. If None, uses latest.
    pub block_number: Option<u64>,
    /// The caller address. If None, uses zero address.
    pub caller: Option<Address>,
}

/// A single opcode execution step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeExecution {
    /// Program counter.
    pub pc: usize,
    /// The opcode value (0x00-0xFF).
    pub opcode: u8,
    /// The opcode name (e.g., "PUSH1", "SLOAD").
    pub name: String,
    /// Gas remaining before this step.
    pub gas_remaining: u64,
    /// Gas cost of this step.
    pub gas_cost: u64,
    /// Stack snapshot at this step (top of stack is index 0).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack: Vec<U256>,
    /// Memory snapshot at this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<u8>,
    /// Storage change if this is an SSTORE (slot, old_value, new_value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_change: Option<StorageChange>,
}

/// A storage slot change from SSTORE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChange {
    /// The storage slot key.
    pub slot: U256,
    /// The value before the change.
    pub old_value: U256,
    /// The value after the change.
    pub new_value: U256,
}

/// The result of tracing a contract call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    /// The sequence of opcodes executed.
    pub opcodes: Vec<OpcodeExecution>,
    /// Number of call frames (1 = no internal calls).
    pub call_frames: usize,
    /// Total gas used.
    pub total_gas_used: u64,
    /// The contract output bytes.
    pub output: Vec<u8>,
}

impl TraceResult {
    /// Get just the opcode values as a vector.
    pub fn opcode_values(&self) -> Vec<u8> {
        self.opcodes.iter().map(|o| o.opcode).collect()
    }

    /// Get just the opcode names as a vector.
    pub fn opcode_names(&self) -> Vec<&str> {
        self.opcodes.iter().map(|o| o.name.as_str()).collect()
    }

    /// Get opcode frequency counts.
    pub fn opcode_frequency(&self) -> std::collections::HashMap<String, usize> {
        let mut counts = std::collections::HashMap::new();
        for op in &self.opcodes {
            *counts.entry(op.name.clone()).or_insert(0) += 1;
        }
        counts
    }
}

/// Trace a contract call and return the opcode execution sequence.
///
/// This is the main entry point for the library.
pub async fn trace_call(config: TraceConfig) -> Result<TraceResult> {
    let rpc_url: Url = config.rpc_url.parse()?;
    let caller = config.caller.unwrap_or_default();

    let block = match config.block_number {
        Some(n) => BlockNumberOrTag::Number(n),
        None => BlockNumberOrTag::Latest,
    };

    // Build the sketch
    let sketch = EvmSketch::builder()
        .at_block(block)
        .el_rpc_url(rpc_url)
        .build()
        .await?;

    // Create the contract input
    let input = ContractInput {
        contract_address: config.contract,
        caller_address: caller,
        calldata: sp1_cc_client_executor::ContractCalldata::Call(Bytes::from(config.calldata)),
    };

    // Execute with tracing using the raw call method
    let cache_db = revm::database::CacheDB::new(&sketch.rpc_db);
    let chain_spec = EthPrimitives::build_spec(&sketch.genesis)?;

    let (output, trace) = EthPrimitives::transact_with_trace(
        &input,
        cache_db,
        sketch.anchor.header(),
        alloy_primitives::U256::ZERO,
        chain_spec,
    )
    .map_err(|e: String| eyre::eyre!(e))?;

    // Extract output bytes
    let output_bytes = match output.result {
        revm::context::result::ExecutionResult::Success { output, .. } => output.data().to_vec(),
        revm::context::result::ExecutionResult::Revert { output, .. } => {
            eyre::bail!("Execution reverted: {output}")
        }
        revm::context::result::ExecutionResult::Halt { reason, .. } => {
            eyre::bail!("Execution halted: {reason:?}")
        }
    };

    // Convert trace to our format
    let nodes = trace.nodes();
    let call_frames = nodes.len();

    let mut opcodes = Vec::new();
    let mut total_gas_used = 0u64;

    for node in nodes {
        for step in &node.trace.steps {
            let name = step.op.as_str().to_string();

            // Extract stack (reversed so index 0 is top of stack)
            let stack = step
                .stack
                .as_ref()
                .map(|s| s.iter().rev().copied().collect())
                .unwrap_or_default();

            // Extract memory
            let memory = step
                .memory
                .as_ref()
                .map(|m| m.as_bytes().to_vec())
                .unwrap_or_default();

            // Extract storage change for SSTORE
            let storage_change = step.storage_change.as_ref().map(|sc| StorageChange {
                slot: sc.key,
                old_value: sc.had_value.unwrap_or_default(),
                new_value: sc.value,
            });

            opcodes.push(OpcodeExecution {
                pc: step.pc,
                opcode: step.op.get(),
                name,
                gas_remaining: step.gas_remaining,
                gas_cost: step.gas_cost,
                stack,
                memory,
                storage_change,
            });
            total_gas_used += step.gas_cost;
        }
    }

    Ok(TraceResult {
        opcodes,
        call_frames,
        total_gas_used,
        output: output_bytes,
    })
}

/// Convenience function to trace a function call using a selector and args.
pub async fn trace_function(
    rpc_url: &str,
    contract: Address,
    selector: [u8; 4],
    args: &[u8],
    block_number: Option<u64>,
) -> Result<TraceResult> {
    let mut calldata = selector.to_vec();
    calldata.extend_from_slice(args);

    trace_call(TraceConfig {
        rpc_url: rpc_url.to_string(),
        contract,
        calldata,
        block_number,
        caller: None,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_execution_serialization() {
        let op = OpcodeExecution {
            pc: 0,
            opcode: 0x60, // PUSH1
            name: "PUSH1".to_string(),
            gas_remaining: 1000000,
            gas_cost: 3,
            stack: vec![U256::from(42)],
            memory: vec![],
            storage_change: None,
        };

        let json = serde_json::to_string(&op).unwrap();
        let parsed: OpcodeExecution = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.opcode, 0x60);
        assert_eq!(parsed.name, "PUSH1");
        assert_eq!(parsed.stack.len(), 1);
    }

    #[test]
    fn test_storage_change_serialization() {
        let op = OpcodeExecution {
            pc: 100,
            opcode: 0x55, // SSTORE
            name: "SSTORE".to_string(),
            gas_remaining: 500000,
            gas_cost: 20000,
            stack: vec![U256::from(1), U256::from(42)], // slot, value
            memory: vec![],
            storage_change: Some(StorageChange {
                slot: U256::from(1),
                old_value: U256::ZERO,
                new_value: U256::from(42),
            }),
        };

        let json = serde_json::to_string(&op).unwrap();
        let parsed: OpcodeExecution = serde_json::from_str(&json).unwrap();

        assert!(parsed.storage_change.is_some());
        let sc = parsed.storage_change.unwrap();
        assert_eq!(sc.slot, U256::from(1));
        assert_eq!(sc.new_value, U256::from(42));
    }
}
