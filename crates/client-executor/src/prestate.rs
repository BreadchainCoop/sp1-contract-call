//! `prestateTracer` and `callTracer` outputs derived from an in-process execution.
//!
//! A caller that re-executes a call locally holds revm's journal and a
//! [`CallTraceArena`]; a caller that asks a node for the same call holds the two
//! Geth tracer outputs. Consumers written against the tracer types can serve both
//! once the local execution is projected onto those types, which is what this
//! module does.
//!
//! The projection is deliberately narrow: see [`storage_diff_from_state`] for what
//! it does and does not populate.

use std::collections::BTreeMap;

use alloy_primitives::B256;
use alloy_rpc_types::trace::geth::{AccountState, CallConfig, CallFrame, DiffMode};
use revm::state::EvmState;

/// Re-exported so a caller can name the journal type these adapters consume without
/// taking a direct `revm` dependency at a version that has to match this crate's.
pub use revm::state::EvmState as ExecutionState;
use revm_inspectors::tracing::GethTraceBuilder;

use crate::inspector::CallTraceArena;

/// Build a `prestateTracer` `diffMode` diff from an execution's final journal.
///
/// **Storage only.** `balance`, `nonce` and `code` are left `None` on every entry,
/// because revm's [`EvmState`] carries an account's *present* info and not its
/// pre-execution info, so those fields cannot be filled from this input at all. The
/// result is therefore a storage projection of a `diffMode` diff and not a
/// substitute for one.
///
/// An account appears in both `pre` and `post`, or in neither. Only slots whose
/// value changed are included, matching `diffMode`, so an account touched without
/// a net storage change is omitted entirely.
///
/// Two limitations worth knowing before relying on this for a consensus decision:
///
/// * A self-destructed account's storage is reported as going to zero, but only for
///   the slots the execution actually loaded. Slots never touched are absent from
///   the journal, so a diff built from it cannot report them. Reading the full
///   pre-state would require the database, which this function does not take.
/// * Log ordering inside [`call_frame_from_arena`] is this builder's, and Geth
///   populates `position` where other clients populate `index`. A consumer that
///   compares against a node's `callTracer` output byte-for-byte has to confirm the
///   two agree on ordering rather than assume it.
pub fn storage_diff_from_state(state: &EvmState) -> DiffMode {
    let mut diff = DiffMode::default();

    for (address, account) in state {
        let mut pre: BTreeMap<B256, B256> = BTreeMap::new();
        let mut post: BTreeMap<B256, B256> = BTreeMap::new();

        if account.is_selfdestructed() {
            for (key, slot) in account.storage.iter() {
                pre.insert(B256::from(*key), B256::from(slot.original_value));
                post.insert(B256::from(*key), B256::ZERO);
            }
        } else {
            for (key, slot) in account.changed_storage_slots() {
                pre.insert(B256::from(*key), B256::from(slot.original_value));
                post.insert(B256::from(*key), B256::from(slot.present_value));
            }
        }

        // `diffMode` omits an account with no net change; keeping the two maps in
        // step means a consumer that unions their key sets sees each account once.
        if pre == post {
            continue;
        }

        diff.pre
            .insert(*address, AccountState { storage: pre, ..Default::default() });
        diff.post
            .insert(*address, AccountState { storage: post, ..Default::default() });
    }

    diff
}

/// Build a `callTracer` root frame from an execution's trace arena.
///
/// Logs are included and sub-calls are kept: a consumer walking the frame tree to
/// classify a call, or reading events out of it, needs both.
pub fn call_frame_from_arena(arena: &CallTraceArena, gas_used: u64) -> CallFrame {
    GethTraceBuilder::new_borrowed(arena.nodes()).geth_call_traces(
        CallConfig { only_top_call: Some(false), with_log: Some(true) },
        gas_used,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Address, U256};
    use revm::state::{Account, AccountStatus, EvmStorageSlot};

    const A: Address = address!("0x00000000000000000000000000000000000000aa");
    const B: Address = address!("0x00000000000000000000000000000000000000bb");

    fn slot(original: u64, present: u64) -> EvmStorageSlot {
        EvmStorageSlot::new_changed(U256::from(original), U256::from(present), 0)
    }

    fn account(status: AccountStatus, slots: &[(u64, EvmStorageSlot)]) -> Account {
        let mut account = Account { status, ..Default::default() };
        for (key, s) in slots {
            account.storage.insert(U256::from(*key), s.clone());
        }
        account
    }

    fn key(k: u64) -> B256 {
        B256::from(U256::from(k))
    }

    fn value(v: u64) -> B256 {
        B256::from(U256::from(v))
    }

    #[test]
    fn a_changed_slot_appears_in_both_halves() {
        let mut state = EvmState::default();
        state.insert(A, account(AccountStatus::Touched, &[(1, slot(7, 9))]));

        let diff = storage_diff_from_state(&state);

        assert_eq!(diff.pre[&A].storage, BTreeMap::from([(key(1), value(7))]));
        assert_eq!(diff.post[&A].storage, BTreeMap::from([(key(1), value(9))]));
    }

    #[test]
    fn an_unchanged_slot_is_omitted_entirely() {
        let mut state = EvmState::default();
        state.insert(A, account(AccountStatus::Touched, &[(1, slot(7, 7))]));

        let diff = storage_diff_from_state(&state);

        assert!(diff.pre.is_empty(), "unchanged account must not appear");
        assert!(diff.post.is_empty(), "unchanged account must not appear");
    }

    /// A slot zeroed is a change, and the consumer distinguishes "absent" from
    /// "present and zero" only by the key being there.
    #[test]
    fn zeroing_a_slot_is_a_change() {
        let mut state = EvmState::default();
        state.insert(A, account(AccountStatus::Touched, &[(1, slot(7, 0))]));

        let diff = storage_diff_from_state(&state);

        assert_eq!(diff.pre[&A].storage, BTreeMap::from([(key(1), value(7))]));
        assert_eq!(diff.post[&A].storage, BTreeMap::from([(key(1), B256::ZERO)]));
    }

    #[test]
    fn accounts_are_reported_independently() {
        let mut state = EvmState::default();
        state.insert(A, account(AccountStatus::Touched, &[(1, slot(0, 5))]));
        state.insert(B, account(AccountStatus::Touched, &[(2, slot(3, 3))]));

        let diff = storage_diff_from_state(&state);

        assert!(diff.pre.contains_key(&A));
        assert!(!diff.pre.contains_key(&B), "B had no net change");
    }

    #[test]
    fn a_selfdestructed_accounts_loaded_slots_go_to_zero() {
        let mut state = EvmState::default();
        state.insert(
            A,
            account(
                AccountStatus::Touched | AccountStatus::SelfDestructed,
                &[(1, slot(7, 7)), (2, slot(4, 4))],
            ),
        );

        let diff = storage_diff_from_state(&state);

        // Unchanged under normal rules, but the wipe changes both.
        assert_eq!(
            diff.pre[&A].storage,
            BTreeMap::from([(key(1), value(7)), (key(2), value(4))])
        );
        assert_eq!(
            diff.post[&A].storage,
            BTreeMap::from([(key(1), B256::ZERO), (key(2), B256::ZERO)])
        );
    }

    /// The projection never claims to know balances, nonces or code. A consumer
    /// reading them would silently read `None` rather than a wrong value.
    #[test]
    fn account_info_is_never_populated() {
        let mut state = EvmState::default();
        state.insert(A, account(AccountStatus::Touched, &[(1, slot(0, 1))]));

        let diff = storage_diff_from_state(&state);

        for side in [&diff.pre[&A], &diff.post[&A]] {
            assert!(side.balance.is_none());
            assert!(side.nonce.is_none());
            assert!(side.code.is_none());
        }
    }

    #[test]
    fn an_empty_execution_yields_an_empty_diff() {
        let diff = storage_diff_from_state(&EvmState::default());
        assert!(diff.pre.is_empty());
        assert!(diff.post.is_empty());
    }

    #[test]
    fn an_empty_arena_yields_a_default_frame() {
        let frame = call_frame_from_arena(&CallTraceArena::default(), 0);
        assert!(frame.calls.is_empty());
    }
}
