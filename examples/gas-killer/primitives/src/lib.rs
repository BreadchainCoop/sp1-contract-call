//! Shared types and trace processing for the Gas Killer challenger program.
//!
//! The challenger program re-executes a contract call that the Gas Killer aggregate
//! network signed storage updates for, and commits the *correct* storage updates to the
//! proof's public values. On-chain, `GasKillerSlasher` compares the committed updates
//! with the signed ones and slashes the operators if they differ.
//!
//! For the comparison to be sound, the storage-update bytes committed here must be
//! byte-for-byte identical to what an honest operator would sign for the same call.
//! Operators derive them with `gas-analyzer`:
//!
//! ```text
//! debug_traceCall(tx, block, {enableMemory: true, disableStorage: true})
//!     -> gas_analyzer_core::trace::compute_state_updates(DefaultFrame)
//!     -> gas_analyzer_core::encoding::encode_state_updates_to_abi
//! ```
//!
//! This crate reproduces that exact pipeline from an in-zkVM execution trace: the
//! recorded [`CallTraceArena`] is converted to a Geth-style `DefaultFrame` with the same
//! tracer options production uses, and then fed through the *same* `gas-analyzer-core`
//! functions (pinned to the revision the Gas Killer service uses).

use alloy_primitives::Bytes;
use alloy_rpc_types::trace::geth::GethDefaultTracingOptions;
use alloy_sol_types::sol;
use sp1_cc_client_executor::{CallTraceArena, GethTraceBuilder, TracingInspectorConfig};

pub use gas_analyzer_core::{trace::compute_state_updates, StateUpdate};

sol! {
    /// Public values committed by the Gas Killer challenger program.
    ///
    /// This mirrors [`sp1_cc_client_executor::ContractPublicValuesWithTrace`] with one
    /// additional field: `storageUpdates`, the canonical Gas Killer encoding
    /// (`abi.encode(StateUpdateType[], bytes[])`) of the state updates produced by the
    /// traced execution. `anchorType` is the `AnchorType` enum encoded as `uint8`.
    #[derive(Debug)]
    struct GasKillerPublicValues {
        uint256 id;
        bytes32 anchorHash;
        uint8 anchorType;
        bytes32 chainConfigHash;
        address callerAddress;
        address contractAddress;
        bytes contractCalldata;
        bytes contractOutput;
        bytes storageUpdates;
        bytes32 opcodeHash;
    }
}

/// The tracer options production uses for `debug_traceCall`
/// (see `gas_analyzer_rpc::get_trace_from_call`).
pub fn production_tracing_options() -> GethDefaultTracingOptions {
    GethDefaultTracingOptions {
        enable_memory: Some(true),
        disable_storage: Some(true),
        ..Default::default()
    }
}

/// The [`TracingInspectorConfig`] whose recorded trace can reproduce a production
/// `DefaultFrame`: geth defaults plus memory snapshots (needed for CALL/LOG/CREATE
/// argument extraction).
pub fn challenger_inspector_config() -> TracingInspectorConfig {
    TracingInspectorConfig::default_geth().set_memory_snapshots(true)
}

/// Converts a recorded [`CallTraceArena`] into the Geth-style `DefaultFrame` that
/// production tracing would have produced for the same execution.
pub fn arena_to_default_frame(
    arena: &CallTraceArena,
    gas_used: u64,
    output: Bytes,
) -> alloy_rpc_types::trace::geth::DefaultFrame {
    GethTraceBuilder::new_borrowed(arena.nodes()).geth_traces(
        gas_used,
        output,
        production_tracing_options(),
    )
}

/// Extracts the Gas Killer state updates from a recorded execution trace and encodes
/// them exactly as an honest operator signs them.
///
/// Returns the encoded `storageUpdates` bytes and the set of skipped (unsupported)
/// opcodes, if any (SELFDESTRUCT, TSTORE). A non-empty skip set means the call is not
/// representable as Gas Killer state updates and an honest operator would not have
/// signed it either.
pub fn encoded_state_updates_from_arena(
    arena: &CallTraceArena,
    gas_used: u64,
    output: Bytes,
) -> eyre::Result<(Bytes, Vec<String>)> {
    let frame = arena_to_default_frame(arena, gas_used, output);
    let (state_updates, skipped_opcodes, _call_gas_total) =
        compute_state_updates(frame).map_err(|e| eyre::eyre!("{e:?}"))?;
    let encoded = gas_analyzer_core::encoding::encode_state_updates_to_abi(&state_updates);

    let mut skipped: Vec<String> = skipped_opcodes.into_iter().collect();
    skipped.sort();

    Ok((encoded, skipped))
}
