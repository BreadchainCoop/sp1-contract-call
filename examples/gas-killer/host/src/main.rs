//! Gas Killer challenger host (one-shot).
//!
//! Given the (contract, caller, calldata, block) tuple that the Gas Killer aggregate network
//! signed storage updates for, this re-executes the call, prints the *correct* storage updates,
//! and (with `--prove`) generates an on-chain-verifiable SP1 proof, writing a fixture JSON for
//! the `GasKillerSlasher` Foundry tests.
//!
//! ```text
//! cargo run --release --bin gas-killer-challenger -- \
//!     --eth-rpc-url https://ethereum-sepolia-rpc.publicnode.com \
//!     --block 12345678 --contract 0x... --caller 0x... --calldata 0xa9059cbb... \
//!     --prove groth16 --fixture-out fixture.json
//! ```
//!
//! For an automated challenger that watches contracts and slashes fraud on-chain, see the
//! `gas-killer-watcher` binary.

use std::path::PathBuf;

use alloy::hex;
use alloy_primitives::{Address, Bytes};
use clap::{Parser, ValueEnum};
use gas_killer::challenge::{self, ProofMode};
use serde::{Deserialize, Serialize};
use sp1_sdk::utils;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProveMode {
    /// Execute only, no proof.
    None,
    /// Core (STARK) proof — fast sanity check, not on-chain verifiable.
    Core,
    /// Groth16 proof — on-chain verifiable via SP1VerifierGroth16.
    Groth16,
    /// PLONK proof — on-chain verifiable via SP1VerifierPlonk.
    Plonk,
}

/// A fixture for verifying the challenger proof inside Solidity tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GasKillerProofFixture {
    chain_id: u64,
    block_number: u64,
    anchor_hash: String,
    chain_config_hash: String,
    caller_address: String,
    contract_address: String,
    contract_calldata: String,
    storage_updates: String,
    vkey: String,
    public_values: String,
    proof: String,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum RPC endpoint (must support eth_getProof at the target block).
    #[clap(long, env = "ETH_RPC_URL")]
    eth_rpc_url: Url,

    /// The block the execution is anchored to (state AFTER this block; anchorHash = its hash).
    #[clap(long)]
    block: u64,

    /// The target contract address.
    #[clap(long)]
    contract: Address,

    /// The caller address (msg.sender) of the original call.
    #[clap(long)]
    caller: Address,

    /// The full calldata, hex encoded (with or without 0x prefix).
    #[clap(long)]
    calldata: String,

    /// Proof mode.
    #[clap(long, value_enum, default_value = "none")]
    prove: ProveMode,

    /// Use a dev chain config (all forks active from genesis) for local anvil chains.
    #[clap(long)]
    dev_genesis: bool,

    /// Where to write the proof fixture JSON.
    #[clap(long, default_value = "gas-killer-fixture.json")]
    fixture_out: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();
    utils::setup_logger();

    let args = Args::parse();
    let calldata = Bytes::from(
        hex::decode(args.calldata.trim_start_matches("0x"))
            .map_err(|e| eyre::eyre!("invalid --calldata hex: {e}"))?,
    );

    let (genesis, chain_id) = challenge::resolve_genesis(&args.eth_rpc_url, args.dev_genesis).await?;

    // Re-execute the call and derive the correct storage updates.
    let exec = challenge::recompute(
        &args.eth_rpc_url,
        genesis,
        args.block,
        args.contract,
        args.caller,
        calldata.clone(),
    )
    .await?;
    println!("anchor block {} hash {}", exec.block, exec.anchor_hash);
    println!(
        "storage updates ({} bytes): 0x{}",
        exec.storage_updates.len(),
        hex::encode(&exec.storage_updates)
    );

    let mode = match args.prove {
        ProveMode::None => {
            println!("--prove not set; done.");
            return Ok(());
        }
        ProveMode::Core => ProofMode::Core,
        ProveMode::Groth16 => ProofMode::Groth16,
        ProveMode::Plonk => ProofMode::Plonk,
    };

    let proven = challenge::prove(&exec, mode)?;
    println!("generated {:?} proof; verified", args.prove);

    let fixture = GasKillerProofFixture {
        chain_id,
        block_number: exec.block,
        anchor_hash: format!("{}", exec.anchor_hash),
        chain_config_hash: format!("{}", proven.chain_config_hash),
        caller_address: format!("{}", args.caller),
        contract_address: format!("{}", args.contract),
        contract_calldata: format!("0x{}", hex::encode(&calldata)),
        storage_updates: format!("0x{}", hex::encode(&exec.storage_updates)),
        vkey: proven.vkey_bytes32,
        public_values: format!("0x{}", hex::encode(&proven.public_values)),
        proof: if proven.proof.is_empty() {
            String::new()
        } else {
            format!("0x{}", hex::encode(&proven.proof))
        },
    };

    if let Some(parent) = args.fixture_out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&args.fixture_out, serde_json::to_string_pretty(&fixture)?)?;
    println!("saved fixture to {}", args.fixture_out.display());

    Ok(())
}
