//! Byte-parity test between the challenger guest pipeline and the production
//! gas-analyzer pipeline.
//!
//! An honest Gas Killer operator derives the signed `storageUpdates` bytes with:
//! `debug_traceCall` (enableMemory, disableStorage) -> `compute_state_updates` ->
//! `encode_state_updates_to_abi`. Slashing is only sound if the challenger guest
//! produces byte-identical output for the same call — otherwise honest operators
//! could be slashed. This test runs both pipelines for the same call and asserts
//! byte equality:
//!
//! - production: anvil forked at the anchor block serves `debug_traceCall`, the
//!   trace is processed with the same `gas-analyzer-core` functions the service uses
//! - challenger: `EvmSketch` witnesses the state, and the guest pipeline
//!   (`execute_traced` + `encoded_state_updates_from_arena`) derives the updates
//!
//! Requires network access and the `anvil` binary:
//! ```text
//! cargo test -p gas-killer --test parity -- --ignored
//! ```
//! Override the upstream RPC with `SEPOLIA_RPC_URL`.

use alloy_node_bindings::Anvil;
use alloy_primitives::{address, bytes, Address, Bytes, TxKind};
use alloy_provider::{network::AnyNetwork, Provider, RootProvider};
use alloy_rpc_types::{
    trace::geth::{DefaultFrame, GethDebugTracingCallOptions, GethDefaultTracingOptions},
    BlockNumberOrTag, TransactionInput, TransactionRequest,
};
use gas_killer_primitives::{challenger_inspector_config, encoded_state_updates_from_arena};
use sp1_cc_client_executor::{
    ClientExecutor, ContractCalldata, ContractInput, EnvOverrides, Genesis,
};
use sp1_cc_host_executor::EvmSketch;
use url::Url;

/// Sepolia WETH9.
const CONTRACT: Address = address!("fFf9976782d46CC05630D1f6eBAb18b2324d6B14");
const CALLER: Address = address!("1111111111111111111111111111111111111111");
/// A block on Sepolia recent enough for public RPCs to serve `eth_getProof`.
const ANCHOR_BLOCK: u64 = 11198179;

fn sepolia_rpc_url() -> String {
    std::env::var("SEPOLIA_RPC_URL")
        .unwrap_or_else(|_| "https://ethereum-sepolia-rpc.publicnode.com".to_string())
}

/// `approve(0x2222...22, 1000)` — one SSTORE and one LOG3.
fn approve_calldata() -> Bytes {
    bytes!(
        "095ea7b3000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000003e8"
    )
}

/// The production pipeline: `debug_traceCall` against an anvil fork of the anchor
/// block, processed with gas-analyzer-core (same options as
/// `gas_analyzer_rpc::get_trace_from_call`).
async fn production_storage_updates(calldata: Bytes) -> Bytes {
    let anvil = Anvil::new()
        .fork(sepolia_rpc_url())
        .fork_block_number(ANCHOR_BLOCK)
        .try_spawn()
        .expect("failed to spawn anvil; is foundry installed?");
    let provider = RootProvider::<AnyNetwork>::new_http(anvil.endpoint_url());

    let tx = TransactionRequest {
        from: Some(CALLER),
        to: Some(TxKind::Call(CONTRACT)),
        input: TransactionInput::new(calldata),
        ..Default::default()
    };

    let options = GethDebugTracingCallOptions {
        tracing_options: alloy_rpc_types::trace::geth::GethDebugTracingOptions {
            config: GethDefaultTracingOptions {
                enable_memory: Some(true),
                disable_storage: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let frame: DefaultFrame = provider
        .raw_request(
            "debug_traceCall".into(),
            (tx, BlockNumberOrTag::Latest, options),
        )
        .await
        .expect("debug_traceCall failed");

    let (state_updates, skipped, _call_gas) =
        gas_analyzer_core::compute_state_updates(frame).expect("compute_state_updates failed");
    assert!(skipped.is_empty(), "production pipeline skipped opcodes: {skipped:?}");

    gas_analyzer_core::encode_state_updates_to_abi(&state_updates)
}

/// The challenger pipeline, exactly as the guest program runs it.
async fn challenger_storage_updates(calldata: Bytes) -> Bytes {
    let sketch = EvmSketch::builder()
        .at_block(BlockNumberOrTag::Number(ANCHOR_BLOCK))
        .with_genesis(Genesis::Sepolia)
        .el_rpc_url(Url::parse(&sepolia_rpc_url()).unwrap())
        .build()
        .await
        .expect("failed to build sketch");

    let call = ContractInput {
        contract_address: CONTRACT,
        caller_address: CALLER,
        calldata: ContractCalldata::Call(calldata),
    };

    sketch.call_raw(&call).await.expect("host execution failed");
    let input = sketch.finalize().await.expect("finalize failed");

    let executor = ClientExecutor::eth(&input).expect("client executor failed");
    let traced = executor
        .execute_traced(&call, EnvOverrides::default(), challenger_inspector_config())
        .expect("traced execution failed");
    let (storage_updates, skipped) =
        encoded_state_updates_from_arena(&traced.arena, traced.gas_used, traced.output.clone())
            .expect("state update extraction failed");
    assert!(skipped.is_empty(), "challenger pipeline skipped opcodes: {skipped:?}");

    storage_updates
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires network access and the anvil binary"]
async fn challenger_storage_updates_match_production() {
    let calldata = approve_calldata();

    let production = production_storage_updates(calldata.clone()).await;
    let challenger = challenger_storage_updates(calldata).await;

    assert_eq!(
        production, challenger,
        "challenger storage updates diverge from the production gas-analyzer encoding"
    );
    assert!(!production.is_empty());
}
