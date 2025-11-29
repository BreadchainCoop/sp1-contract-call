//! Opcode tracing inspector for EVM execution.
//!
//! This module re-exports the tracing inspector from `revm-inspectors` and provides
//! convenient type aliases for capturing opcode execution traces.

// Re-export the tracing types from revm-inspectors
pub use revm_inspectors::tracing::{
    types::{CallTrace, CallTraceNode, CallTraceStep, StorageChangeReason},
    CallTraceArena, TracingInspector, TracingInspectorConfig,
};
