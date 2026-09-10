//! Gas Killer challenger guest program.
//!
//! Re-executes a contract call against a witnessed Ethereum state (anchored to a block
//! hash) and commits [`GasKillerPublicValues`], including the canonical Gas Killer
//! `storageUpdates` encoding of the execution's state changes. The on-chain
//! `GasKillerSlasher` compares these proven storage updates with the ones the aggregate
//! network signed; a mismatch proves fraud.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolValue;
use gas_killer_primitives::{
    challenger_inspector_config, encoded_state_updates_from_arena, GasKillerPublicValues,
};
use sp1_cc_client_executor::{
    compute_opcode_hash, io::EvmSketchInput, ClientExecutor, ContractCalldata, ContractInput,
    EnvOverrides,
};

pub fn main() {
    // Read the state sketch: the witnessed Ethereum state the call executes against.
    let state_sketch_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let state_sketch = bincode::deserialize::<EvmSketchInput>(&state_sketch_bytes).unwrap();

    // Read the call to re-execute: the exact (contract, caller, calldata) triple that the
    // aggregate network signed storage updates for.
    let contract_address = sp1_zkvm::io::read::<Address>();
    let caller_address = sp1_zkvm::io::read::<Address>();
    let calldata = Bytes::from(sp1_zkvm::io::read::<Vec<u8>>());

    // Initialize the client executor. This validates all witnessed storage against the
    // anchor header's state root.
    let executor = ClientExecutor::eth(&state_sketch).unwrap();

    let call = ContractInput {
        contract_address,
        caller_address,
        calldata: ContractCalldata::Call(calldata.clone()),
    };

    // Execute with a trace that can reproduce a production `debug_traceCall` frame.
    let traced = executor
        .execute_traced(&call, EnvOverrides::default(), challenger_inspector_config())
        .unwrap();

    // Derive the canonical Gas Killer storage updates from the trace. This is the same
    // pipeline (same code) an honest operator runs when signing.
    let (storage_updates, skipped) =
        encoded_state_updates_from_arena(&traced.arena, traced.gas_used, traced.output.clone())
            .unwrap();
    assert!(skipped.is_empty(), "execution used unsupported opcodes: {skipped:?}");

    let opcode_hash = compute_opcode_hash(&traced.arena);

    let public_values = GasKillerPublicValues {
        id: executor.anchor.id,
        anchorHash: executor.anchor.hash,
        anchorType: executor.anchor.ty as u8,
        chainConfigHash: executor.chain_config_hash,
        callerAddress: caller_address,
        contractAddress: contract_address,
        contractCalldata: calldata,
        contractOutput: traced.output,
        storageUpdates: storage_updates,
        opcodeHash: opcode_hash,
    };

    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
