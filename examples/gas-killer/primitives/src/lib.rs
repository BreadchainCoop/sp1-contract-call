//! Shared types and trace processing for the Gas Killer challenger program.
//!
//! The challenger program re-executes a contract call that the Gas Killer aggregate
//! network signed storage updates for, and commits the *correct* storage updates to the
//! proof's public values. On-chain, `GasKillerSlasher` compares the committed updates
//! with the signed ones and slashes the operators if they differ.
//!
//! For the comparison to be sound, the storage-update bytes committed here must be
//! byte-for-byte identical to what an honest operator would sign for the same call.
//! Which bytes those are depends on the fleet's `STATE_ENCODING`, and the deployed
//! fleet runs `prestate-net`:
//!
//! ```text
//! debug_traceCall(prestateTracer{diffMode}) + debug_traceCall(callTracer{withLog})
//!     -> classify_prestate_eligibility
//!        Eligible -> build_state_updates_from_prestate
//!        Fallback -> compute_state_updates_canonical(DefaultFrame)
//!     -> encode_state_updates_to_abi
//! ```
//!
//! This crate reproduces that from a single in-zkVM execution. The recorded journal
//! becomes the `diffMode` diff and the [`CallTraceArena`] becomes the `callTracer`
//! frame, then the *same* `gas-analyzer-core` functions decide and encode, pinned to
//! the revision the Gas Killer service uses.
//!
//! The net form is not a cheaper route to the Legacy bytes: it carries one store per
//! *changed* slot, so repeated writes collapse and a slot written back to its original
//! value produces none. Reproducing the wrong encoding would make every honest operator
//! look fraudulent, so the encoding is part of what has to match, not an implementation
//! detail. `STATE_ENCODING` is not yet bound into the commitment
//! (gas-killer/solidity-sdk#83), so this is hardcoded to the deployed value.

use alloy_primitives::{Address, Bytes};
use alloy_rpc_types::trace::geth::GethDefaultTracingOptions;
use alloy_sol_types::sol;
use sp1_cc_client_executor::{
    prestate::{call_frame_from_arena, storage_diff_from_state, ExecutionState},
    CallTraceArena, GethTraceBuilder, TracingInspectorConfig,
};

use gas_analyzer_core::{
    build_state_updates_from_prestate, classify_prestate_eligibility,
    compute_state_updates_canonical, encoding::encode_state_updates_to_abi, PrestateEligibility,
};

pub use gas_analyzer_core::StateUpdate;

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

/// Extracts the Gas Killer state updates from a recorded execution and encodes them
/// exactly as an honest operator on a `prestate-net` fleet signs them.
///
/// `consumer` is the contract whose storage the payload is allowed to write, i.e. the
/// call's target. Eligibility is decided against it, and it is the only account whose
/// slots become stores.
///
/// Returns the encoded `storageUpdates` bytes and the set of skipped (unsupported)
/// opcodes, if any (SELFDESTRUCT, TSTORE). A non-empty skip set means the call is not
/// representable as Gas Killer state updates and an honest operator would not have
/// signed it either. The net form reports none by construction: neither tracer sees
/// opcodes, and eligibility already rules out the frames that would skip one.
pub fn encoded_state_updates_from_execution(
    consumer: Address,
    state: &ExecutionState,
    arena: &CallTraceArena,
    gas_used: u64,
    output: Bytes,
) -> eyre::Result<(Bytes, Vec<String>)> {
    let diff = storage_diff_from_state(state);
    let frame = call_frame_from_arena(arena, gas_used);

    let (state_updates, skipped_opcodes) = match classify_prestate_eligibility(&frame, &diff, consumer)
    {
        PrestateEligibility::Eligible => {
            (build_state_updates_from_prestate(consumer, &diff, &frame), Vec::new())
        }
        // No net form for this call, so the struct-log encoder produces the program.
        // `Canonical` rather than `Legacy`: it is what `prestate-net` pairs with, and
        // both of its representations stay revert-aware.
        PrestateEligibility::Fallback(_) => {
            let trace = arena_to_default_frame(arena, gas_used, output);
            let (updates, skipped, _call_gas_total) =
                compute_state_updates_canonical(trace, consumer).map_err(|e| eyre::eyre!("{e:?}"))?;
            let mut skipped: Vec<String> =
                skipped.into_iter().map(|op| format!("{op:?}")).collect();
            skipped.sort();
            (updates, skipped)
        }
    };

    Ok((encode_state_updates_to_abi(&state_updates), skipped_opcodes))
}
