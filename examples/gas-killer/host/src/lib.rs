//! Gas Killer challenger: re-execute a signed call, detect fraud, and prove it for slashing.
//!
//! The [`challenge`] module is the reusable core shared by the `gas-killer-challenger` one-shot
//! CLI and the `gas-killer-watcher` daemon.

pub mod challenge;
