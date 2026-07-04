//! Gas Killer challenger watcher.
//!
//! Watches a configured list of Gas Killer contracts, and for every `verifyAndUpdate` submitted
//! to them:
//!   1. decodes the signed commitment (transition, anchor, caller, calldata, storage updates,
//!      operators, signatures) from the transaction,
//!   2. re-executes the call against the anchor block to derive the *correct* storage updates
//!      (cheap, native),
//!   3. if the signed storage updates differ from the correct ones — fraud — generates an SP1
//!      proof of the correct execution, and
//!   4. submits `GasKillerSlasher.slash(...)` on-chain to slash the signing operators.
//!
//! ```text
//! cargo run --release --bin gas-killer-watcher -- --config watcher.toml
//! ```
//! See `watcher.example.toml` for the config format. The challenger key may be given in the
//! config or via the `CHALLENGER_KEY` env var.

// The sol!-generated verifyAndUpdate RPC binding takes all 9 params + a provider (10 args).
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use alloy::consensus::Transaction as _;
use alloy::network::EthereumWallet;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256};
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_macro::sol;
use alloy_sol_types::{SolCall, SolValue};
use clap::Parser;
use gas_killer::challenge::{self, ProofMode};
use serde::Deserialize;
use tracing::{error, info, warn};
use url::Url;

sol! {
    #[sol(rpc)]
    interface IGasKillerSDK {
        function verifyAndUpdate(
            bytes32 msgHash,
            uint32 referenceBlockNumber,
            bytes storageUpdates,
            uint256 transitionIndex,
            bytes32 anchorHash,
            address callerAddress,
            bytes contractCalldata,
            address[] operators,
            bytes[] signatures
        ) external;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    interface IGasKillerSlasher {
        struct SignedCommitment {
            uint256 transitionIndex;
            address contractAddress;
            bytes32 anchorHash;
            address callerAddress;
            bytes contractCalldata;
            bytes storageUpdates;
        }

        function slash(
            SignedCommitment commitment,
            uint32 referenceBlockNumber,
            address[] operators,
            bytes[] signatures,
            bytes sp1Proof,
            bytes sp1PublicValues
        ) external;

        function isSlashed(bytes32 commitmentHash) external view returns (bool);
    }
}

#[derive(Debug, Deserialize)]
struct Config {
    /// Challenger private key (0x-hex). Falls back to the `CHALLENGER_KEY` env var.
    challenger_key: Option<String>,
    /// Seconds between polls of each target chain's head.
    #[serde(default = "default_poll_interval")]
    poll_interval_secs: u64,
    /// Confirmations to wait before scanning a block (reorg safety).
    #[serde(default)]
    confirmations: u64,
    /// Proof mode: "groth16" (default), "plonk", or "core" (core is not on-chain verifiable).
    #[serde(default = "default_prove_mode")]
    prove_mode: String,
    /// Use a dev chain config (all forks from genesis) for local anvil chains.
    #[serde(default)]
    dev_genesis: bool,
    /// Detect and log fraud but do not generate proofs or submit slashes.
    #[serde(default)]
    dry_run: bool,
    targets: Vec<Target>,
}

fn default_poll_interval() -> u64 {
    12
}
fn default_prove_mode() -> String {
    "groth16".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct Target {
    name: String,
    rpc_url: Url,
    contract: Address,
    slasher: Address,
    /// First block to scan; omit to start from the chain head.
    start_block: Option<u64>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the watcher config TOML.
    #[clap(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    let config: Config = toml::from_str(&std::fs::read_to_string(&args.config)?)
        .map_err(|e| eyre::eyre!("failed to parse config {}: {e}", args.config.display()))?;

    let key = config
        .challenger_key
        .clone()
        .or_else(|| std::env::var("CHALLENGER_KEY").ok())
        .ok_or_else(|| eyre::eyre!("no challenger key (set config.challenger_key or CHALLENGER_KEY)"))?;
    let signer: PrivateKeySigner = key.trim().parse().map_err(|e| eyre::eyre!("bad key: {e}"))?;
    let challenger = signer.address();
    let wallet = EthereumWallet::from(signer);

    let mode = match config.prove_mode.as_str() {
        "groth16" => ProofMode::Groth16,
        "plonk" => ProofMode::Plonk,
        "core" => ProofMode::Core,
        other => eyre::bail!("unknown prove_mode {other:?}"),
    };

    info!(
        challenger = %challenger,
        targets = config.targets.len(),
        prove_mode = %config.prove_mode,
        dry_run = config.dry_run,
        "starting Gas Killer challenger watcher"
    );

    // Per-target last-scanned block. `None` until initialized from the chain head / start_block.
    let mut cursors: HashMap<String, u64> = HashMap::new();

    loop {
        for target in &config.targets {
            if let Err(e) = scan_target(&config, target, &wallet, mode, &mut cursors).await {
                warn!(target = %target.name, error = %e, "scan failed; will retry next poll");
            }
        }
        tokio::time::sleep(Duration::from_secs(config.poll_interval_secs)).await;
    }
}

/// Scan a single target chain from its cursor to `head - confirmations`, challenging any fraud.
async fn scan_target(
    config: &Config,
    target: &Target,
    wallet: &EthereumWallet,
    mode: ProofMode,
    cursors: &mut HashMap<String, u64>,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new().wallet(wallet.clone()).connect_http(target.rpc_url.clone());

    let head = provider.get_block_number().await?;
    let latest = head.saturating_sub(config.confirmations);

    // Initialize the cursor to (start_block - 1) or the current head so we only look forward.
    let from = match cursors.get(&target.name) {
        Some(c) => *c + 1,
        None => {
            let start = target.start_block.unwrap_or(latest.saturating_add(1));
            cursors.insert(target.name.clone(), start.saturating_sub(1));
            start
        }
    };
    if from > latest {
        return Ok(());
    }

    for block_number in from..=latest {
        let Some(block) = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
            .await?
        else {
            continue;
        };
        let Some(txs) = block.transactions.as_transactions() else {
            continue;
        };
        for tx in txs {
            if tx.to() != Some(target.contract) {
                continue;
            }
            let input = tx.input();
            if input.len() < 4 || input[..4] != IGasKillerSDK::verifyAndUpdateCall::SELECTOR {
                continue;
            }
            let decoded = match IGasKillerSDK::verifyAndUpdateCall::abi_decode(input) {
                Ok(d) => d,
                Err(e) => {
                    warn!(target = %target.name, block = block_number, error = %e, "failed to decode verifyAndUpdate");
                    continue;
                }
            };
            if let Err(e) = process_submission(config, target, &provider, mode, decoded).await {
                error!(target = %target.name, block = block_number, error = %e, "challenge attempt failed");
            }
        }
        cursors.insert(target.name.clone(), block_number);
    }
    Ok(())
}

/// Handle one observed `verifyAndUpdate`: check for fraud and, if found, prove and slash.
async fn process_submission<P: Provider + Clone>(
    config: &Config,
    target: &Target,
    provider: &P,
    mode: ProofMode,
    sub: IGasKillerSDK::verifyAndUpdateCall,
) -> eyre::Result<()> {
    let commitment = IGasKillerSlasher::SignedCommitment {
        transitionIndex: sub.transitionIndex,
        contractAddress: target.contract,
        anchorHash: sub.anchorHash,
        callerAddress: sub.callerAddress,
        contractCalldata: sub.contractCalldata.clone(),
        storageUpdates: sub.storageUpdates.clone(),
    };

    // The commitment hash is exactly the message hash the operators signed and `verifyAndUpdate`
    // verified — recompute it and confirm it matches the submitted msgHash.
    let commitment_hash = commitment_hash(&commitment);
    if commitment_hash != sub.msgHash {
        warn!(target = %target.name, "submission msgHash does not match recomputed commitment; skipping");
        return Ok(());
    }

    let slasher = IGasKillerSlasher::new(target.slasher, provider);
    if slasher.isSlashed(commitment_hash).call().await.unwrap_or(false) {
        info!(target = %target.name, hash = %commitment_hash, "already slashed; skipping");
        return Ok(());
    }

    // Resolve the anchor block number from its hash so we can witness the state.
    let Some(anchor_block) = provider.get_block_by_hash(sub.anchorHash).await? else {
        warn!(target = %target.name, anchor = %sub.anchorHash, "anchor block not found on RPC (pruned?); skipping");
        return Ok(());
    };
    let anchor_number = anchor_block.header.number;

    // Re-execute the call to derive the correct storage updates (cheap; no proof).
    let (genesis, _chain_id) = challenge::resolve_genesis(&target.rpc_url, config.dev_genesis).await?;
    let exec = match challenge::recompute(
        &target.rpc_url,
        genesis,
        anchor_number,
        target.contract,
        sub.callerAddress,
        sub.contractCalldata.clone(),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            warn!(target = %target.name, error = %e, "could not re-execute (state unavailable?); skipping");
            return Ok(());
        }
    };

    if keccak256(&exec.storage_updates) == keccak256(&sub.storageUpdates) {
        info!(
            target = %target.name,
            transition = %sub.transitionIndex,
            "submission is honest (storage updates match); no action"
        );
        return Ok(());
    }

    warn!(
        target = %target.name,
        hash = %commitment_hash,
        transition = %sub.transitionIndex,
        anchor_block = anchor_number,
        signed_len = sub.storageUpdates.len(),
        correct_len = exec.storage_updates.len(),
        "FRAUD DETECTED: signed storage updates differ from correct execution"
    );

    if config.dry_run {
        info!(target = %target.name, "dry-run: would prove and slash");
        return Ok(());
    }

    // Prove the correct execution (expensive — minutes).
    info!(target = %target.name, "generating {:?} proof...", mode);
    let exec_for_prove = exec;
    let proven = tokio::task::spawn_blocking(move || challenge::prove(&exec_for_prove, mode))
        .await
        .map_err(|e| eyre::eyre!("prove task panicked: {e}"))??;
    info!(target = %target.name, "proof generated; submitting slash");

    let slasher = IGasKillerSlasher::new(target.slasher, provider);
    let pending = slasher
        .slash(
            commitment,
            sub.referenceBlockNumber,
            sub.operators.clone(),
            sub.signatures.clone(),
            Bytes::from(proven.proof),
            Bytes::from(proven.public_values),
        )
        .send()
        .await?;
    let tx_hash = *pending.tx_hash();
    info!(target = %target.name, tx = %tx_hash, "slash submitted; awaiting receipt");
    let receipt = pending.get_receipt().await?;
    if receipt.status() {
        info!(target = %target.name, tx = %tx_hash, "operators slashed ✓");
    } else {
        error!(target = %target.name, tx = %tx_hash, "slash transaction reverted");
    }
    Ok(())
}

/// `sha256(abi.encode(transitionIndex, contractAddress, anchorHash, callerAddress,
/// contractCalldata, storageUpdates))` — the message operators sign and `verifyAndUpdate` verifies.
fn commitment_hash(c: &IGasKillerSlasher::SignedCommitment) -> B256 {
    use sha2::{Digest, Sha256};
    let encoded = (
        c.transitionIndex,
        c.contractAddress,
        c.anchorHash,
        c.callerAddress,
        c.contractCalldata.clone(),
        c.storageUpdates.clone(),
    )
        .abi_encode_params();
    let digest = Sha256::digest(&encoded);
    FixedBytes::<32>::from_slice(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes, U256};

    /// `commitment_hash` must equal the on-chain `sha256(abi.encode(...))` the SDK computes.
    /// The golden value is from `cast abi-encode ... | sha256`, independent of this code.
    #[test]
    fn commitment_hash_matches_solidity_golden() {
        let c = IGasKillerSlasher::SignedCommitment {
            transitionIndex: U256::from(3u64),
            contractAddress: address!("000000000000000000000000000000000000dEaD"),
            anchorHash: FixedBytes::<32>::from([0x11u8; 32]),
            callerAddress: address!("00000000000000000000000000000000000000CA"),
            contractCalldata: bytes!("a9059cbb"),
            storageUpdates: bytes!("deadbeef"),
        };
        let got = commitment_hash(&c);
        let golden: B256 =
            "0xdec59faa3ed0173f2f471e9f269448697cb67c8d716d7be5799e0aa23a9f9fe8".parse().unwrap();
        assert_eq!(got, golden);
    }

    /// The verifyAndUpdate selector must decode calldata round-trip.
    #[test]
    fn verify_and_update_selector_roundtrip() {
        let call = IGasKillerSDK::verifyAndUpdateCall {
            msgHash: FixedBytes::<32>::from([0x22u8; 32]),
            referenceBlockNumber: 7,
            storageUpdates: bytes!("0102"),
            transitionIndex: U256::from(1u64),
            anchorHash: FixedBytes::<32>::from([0x33u8; 32]),
            callerAddress: address!("00000000000000000000000000000000000000CA"),
            contractCalldata: bytes!("a9059cbb"),
            operators: vec![address!("0000000000000000000000000000000000000001")],
            signatures: vec![bytes!("aa")],
        };
        let encoded = call.abi_encode();
        assert_eq!(encoded[..4], IGasKillerSDK::verifyAndUpdateCall::SELECTOR);
        let decoded = IGasKillerSDK::verifyAndUpdateCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.transitionIndex, U256::from(1u64));
        assert_eq!(decoded.referenceBlockNumber, 7);
        assert_eq!(decoded.operators.len(), 1);
    }
}
