//! Byte-parity test between the challenger guest pipeline and the production
//! gas-analyzer pipeline.
//!
//! An honest Gas Killer operator on the deployed fleet runs `STATE_ENCODING=prestate-net`,
//! deriving the signed `storageUpdates` bytes from two cheap tracers rather than a
//! struct-log trace: `prestateTracer` in `diffMode` plus `callTracer` with logs, fed
//! through `classify_prestate_eligibility` and then either
//! `build_state_updates_from_prestate` or, for calls with no net form,
//! `compute_state_updates_canonical`. Slashing is only sound if the challenger guest
//! produces byte-identical output for the same call, or honest operators get slashed.
//! This test runs both pipelines for the same call and asserts byte equality:
//!
//! - production: anvil forked at the anchor block serves both tracers, and the outputs
//!   are processed with the same `gas-analyzer-core` functions the service uses
//! - challenger: `EvmSketch` witnesses the state, and the guest pipeline
//!   (`execute_traced` + `encoded_state_updates_from_execution`) derives the updates
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
    trace::geth::{
        CallConfig, CallFrame, DefaultFrame, DiffMode, GethDebugTracingCallOptions,
        GethDebugTracingOptions, GethDefaultTracingOptions, PreStateConfig,
    },
    BlockNumberOrTag, TransactionInput, TransactionRequest,
};
use gas_killer_primitives::{challenger_inspector_config, encoded_state_updates_from_execution};
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

/// The production pipeline for a `prestate-net` fleet: `prestateTracer` in `diffMode`
/// plus `callTracer` with logs, against an anvil fork of the anchor block, processed
/// with gas-analyzer-core exactly as `extract_state_updates_hybrid` does.
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

    let diff: DiffMode = provider
        .raw_request(
            "debug_traceCall".into(),
            (
                tx.clone(),
                BlockNumberOrTag::Latest,
                GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions::prestate_tracer(PreStateConfig {
                        diff_mode: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("prestateTracer debug_traceCall failed");

    let frame: CallFrame = provider
        .raw_request(
            "debug_traceCall".into(),
            (
                tx.clone(),
                BlockNumberOrTag::Latest,
                GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions::call_tracer(CallConfig {
                        with_log: Some(true),
                        only_top_call: Some(false),
                    }),
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("callTracer debug_traceCall failed");

    let state_updates = match gas_analyzer_core::classify_prestate_eligibility(
        &frame, &diff, CONTRACT,
    ) {
        gas_analyzer_core::PrestateEligibility::Eligible => {
            gas_analyzer_core::build_state_updates_from_prestate(CONTRACT, &diff, &frame)
        }
        // No net form, so production falls back to the struct-log encoder. Fetching the
        // struct-log trace only on this path mirrors the analyzer: the net form never
        // pays for it.
        gas_analyzer_core::PrestateEligibility::Fallback(_) => {
            let struct_log: DefaultFrame = provider
                .raw_request(
                    "debug_traceCall".into(),
                    (
                        tx,
                        BlockNumberOrTag::Latest,
                        GethDebugTracingCallOptions {
                            tracing_options: GethDebugTracingOptions {
                                config: GethDefaultTracingOptions {
                                    enable_memory: Some(true),
                                    disable_storage: Some(true),
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                    ),
                )
                .await
                .expect("struct-log debug_traceCall failed");
            let (updates, skipped, _call_gas) =
                gas_analyzer_core::compute_state_updates_canonical(struct_log, CONTRACT)
                    .expect("compute_state_updates_canonical failed");
            assert!(skipped.is_empty(), "production pipeline skipped opcodes: {skipped:?}");
            updates
        }
    };

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
    let (storage_updates, skipped) = encoded_state_updates_from_execution(
        call.contract_address,
        &traced.state,
        &traced.arena,
        traced.gas_used,
        traced.output.clone(),
    )
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
