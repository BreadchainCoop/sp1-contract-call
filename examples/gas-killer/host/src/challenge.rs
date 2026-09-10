//! Reusable Gas Killer challenge core: re-execute a signed call, detect fraud, and prove it.
//!
//! Shared by the one-shot `gas-killer-challenger` CLI and the `gas-killer-watcher` daemon.
//! `recompute` is the cheap fraud check (native re-execution, seconds); `prove` is the
//! expensive SP1 proof (minutes) run only once fraud is confirmed.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{network::AnyNetwork, Provider, RootProvider};
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::SolValue;
use gas_killer_primitives::{
    challenger_inspector_config, encoded_state_updates_from_arena, GasKillerPublicValues,
};
use sp1_cc_client_executor::{
    io::EvmSketchInput, ClientExecutor, ContractCalldata, ContractInput, EnvOverrides, Genesis,
};
use sp1_cc_host_executor::EvmSketch;
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};
use url::Url;

/// The challenger guest program ELF.
pub const ELF: &[u8] = include_elf!("gas-killer-client");

/// Which proof to generate. Only Groth16/Plonk are on-chain verifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    Core,
    Groth16,
    Plonk,
}

/// An anvil-style dev chain config: every fork active from genesis, post-merge from block 0.
pub fn dev_chain_config(chain_id: u64) -> alloy_genesis::ChainConfig {
    alloy_genesis::ChainConfig {
        chain_id,
        homestead_block: Some(0),
        dao_fork_block: Some(0),
        dao_fork_support: true,
        eip150_block: Some(0),
        eip155_block: Some(0),
        eip158_block: Some(0),
        byzantium_block: Some(0),
        constantinople_block: Some(0),
        petersburg_block: Some(0),
        istanbul_block: Some(0),
        muir_glacier_block: Some(0),
        berlin_block: Some(0),
        london_block: Some(0),
        arrow_glacier_block: Some(0),
        gray_glacier_block: Some(0),
        merge_netsplit_block: Some(0),
        shanghai_time: Some(0),
        cancun_time: Some(0),
        prague_time: Some(0),
        terminal_total_difficulty: Some(U256::ZERO),
        terminal_total_difficulty_passed: true,
        ..Default::default()
    }
}

/// Resolve the guest's chain genesis from the RPC's chain id.
pub async fn resolve_genesis(eth_rpc_url: &Url, dev_genesis: bool) -> eyre::Result<(Genesis, u64)> {
    let provider = RootProvider::<AnyNetwork>::new_http(eth_rpc_url.clone());
    let chain_id = provider.get_chain_id().await?;
    let genesis = if dev_genesis {
        Genesis::Custom(dev_chain_config(chain_id))
    } else {
        match chain_id {
            1 => Genesis::Mainnet,
            11155111 => Genesis::Sepolia,
            id => eyre::bail!("unsupported chain id {id}; add its Genesis mapping or pass dev-genesis"),
        }
    };
    Ok((genesis, chain_id))
}

/// The correct execution of a signed call: the storage updates an honest operator would sign,
/// plus the witness needed to prove it.
pub struct CorrectExecution {
    /// Canonical Gas Killer `storageUpdates` for the call (what an honest operator signs).
    pub storage_updates: Bytes,
    /// Hash of the anchor block (`block`).
    pub anchor_hash: B256,
    /// The anchor block number.
    pub block: u64,
    /// The witnessed state + headers for the guest.
    pub input: EvmSketchInput,
    /// The re-executed call.
    pub call: ContractInput,
}

/// Re-execute `calldata` from `caller` against `contract` at `block`, returning the *correct*
/// storage updates and the witness. Native, no proof — this is the cheap fraud check.
pub async fn recompute(
    eth_rpc_url: &Url,
    genesis: Genesis,
    block: u64,
    contract: Address,
    caller: Address,
    calldata: Bytes,
) -> eyre::Result<CorrectExecution> {
    let sketch = EvmSketch::builder()
        .at_block(BlockNumberOrTag::Number(block))
        .with_genesis(genesis)
        .el_rpc_url(eth_rpc_url.clone())
        .build()
        .await?;
    let anchor_hash = sketch.anchor.resolve().hash;

    let call = ContractInput {
        contract_address: contract,
        caller_address: caller,
        calldata: ContractCalldata::Call(calldata),
    };

    // Execute on the host so the rpc_db records every accessed account/slot, then fetch proofs.
    sketch.call_raw(&call).await?;
    let input = sketch.finalize().await?;

    // Derive the canonical storage updates via the exact guest pipeline (native).
    let executor = ClientExecutor::eth(&input)?;
    let traced =
        executor.execute_traced(&call, EnvOverrides::default(), challenger_inspector_config())?;
    let (storage_updates, skipped) =
        encoded_state_updates_from_arena(&traced.arena, traced.gas_used, traced.output.clone())?;
    if !skipped.is_empty() {
        eyre::bail!("execution used unsupported opcodes: {skipped:?}");
    }

    Ok(CorrectExecution { storage_updates, anchor_hash, block, input, call })
}

/// A generated challenge proof: the public values + proof bytes to submit to `GasKillerSlasher`.
pub struct ProvenChallenge {
    /// ABI-encoded `GasKillerPublicValues` (the SP1 public values).
    pub public_values: Vec<u8>,
    /// The proof bytes (Groth16/PLONK on-chain encoding; empty for Core).
    pub proof: Vec<u8>,
    /// The program verification key as a bytes32 hex string.
    pub vkey_bytes32: String,
    /// The chain config hash the proof commits (chain id + active hardfork).
    pub chain_config_hash: B256,
}

/// Generate an SP1 proof of the correct execution. Expensive — run only once fraud is confirmed.
pub fn prove(exec: &CorrectExecution, mode: ProofMode) -> eyre::Result<ProvenChallenge> {
    let input_bytes = bincode::serialize(&exec.input)?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    stdin.write(&exec.call.contract_address);
    stdin.write(&exec.call.caller_address);
    let calldata = match &exec.call.calldata {
        ContractCalldata::Call(c) => c.to_vec(),
        ContractCalldata::Create(c) => c.to_vec(),
    };
    stdin.write(&calldata);

    let client = ProverClient::from_env();

    // Sanity: execute the guest to get the committed public values and confirm the anchor.
    let (execute_values, _report) = client.execute(ELF, &stdin).run().unwrap();
    let public_vals = GasKillerPublicValues::abi_decode(execute_values.as_slice())?;
    if public_vals.anchorHash != exec.anchor_hash {
        eyre::bail!("guest anchor hash mismatch");
    }

    let (pk, vk) = client.setup(ELF);
    let proof = match mode {
        ProofMode::Core => client.prove(&pk, &stdin).run().unwrap(),
        ProofMode::Groth16 => client.prove(&pk, &stdin).groth16().run().unwrap(),
        ProofMode::Plonk => client.prove(&pk, &stdin).plonk().run().unwrap(),
    };
    client.verify(&proof, &vk).expect("proof verification failed");

    let proof_bytes = match mode {
        ProofMode::Core => Vec::new(),
        _ => proof.bytes(),
    };

    Ok(ProvenChallenge {
        public_values: proof.public_values.to_vec(),
        proof: proof_bytes,
        vkey_bytes32: vk.bytes32(),
        chain_config_hash: public_vals.chainConfigHash,
    })
}
