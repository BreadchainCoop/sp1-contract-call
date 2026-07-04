//! Gas Killer challenger host.
//!
//! Given the (contract, caller, calldata, block) tuple that the Gas Killer aggregate
//! network signed storage updates for, this binary:
//!
//! 1. fetches the required Ethereum state at the anchor block via RPC,
//! 2. re-executes the call natively and derives the canonical Gas Killer
//!    `storageUpdates` bytes (same pipeline as the operators),
//! 3. runs the challenger guest program in SP1 to (optionally) prove the execution, and
//! 4. writes a proof fixture JSON consumable by the `GasKillerSlasher` Foundry tests.
//!
//! Example (execute only):
//! ```text
//! cargo run --release --bin gas-killer-challenger -- \
//!     --eth-rpc-url https://ethereum-sepolia-rpc.publicnode.com \
//!     --block 12345678 \
//!     --contract 0x... --caller 0x... --calldata 0xa9059cbb...
//! ```
//!
//! Add `--prove groth16 --fixture-out fixture.json` to generate an on-chain-verifiable
//! proof (requires substantial resources; use `SP1_PROVER=cpu`).

use std::path::PathBuf;

use alloy::hex;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{network::AnyNetwork, Provider, RootProvider};
use alloy_rpc_types::BlockNumberOrTag;
use alloy_sol_types::SolValue;
use clap::{Parser, ValueEnum};
use gas_killer_primitives::{
    challenger_inspector_config, encoded_state_updates_from_arena, GasKillerPublicValues,
};
use serde::{Deserialize, Serialize};
use sp1_cc_client_executor::{ClientExecutor, ContractCalldata, ContractInput, Genesis};
use sp1_cc_host_executor::EvmSketch;
use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1Stdin};
use url::Url;

/// The challenger guest program ELF.
const ELF: &[u8] = include_elf!("gas-killer-client");

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProveMode {
    /// Execute only, no proof.
    None,
    /// Generate a core (STARK) proof — fast sanity check, not on-chain verifiable.
    Core,
    /// Generate a Groth16 proof — on-chain verifiable via SP1VerifierGroth16.
    Groth16,
    /// Generate a PLONK proof — on-chain verifiable via SP1VerifierPlonk.
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
    contract_output: String,
    storage_updates: String,
    opcode_hash: String,
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

    /// The block the execution is anchored to. The call executes against the state
    /// AFTER this block (its state root), and `anchorHash` is this block's hash.
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

    /// Where to write the proof fixture JSON.
    #[clap(long, default_value = "gas-killer-fixture.json")]
    fixture_out: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv::dotenv().ok();
    utils::setup_logger();

    let args = Args::parse();
    let calldata =
        Bytes::from(hex::decode(args.calldata.trim_start_matches("0x")).map_err(|e| {
            eyre::eyre!("invalid --calldata hex: {e}")
        })?);

    // Detect the chain so the guest validates headers against the right chain spec.
    let provider = RootProvider::<AnyNetwork>::new_http(args.eth_rpc_url.clone());
    let chain_id = provider.get_chain_id().await?;
    let genesis = match chain_id {
        1 => Genesis::Mainnet,
        11155111 => Genesis::Sepolia,
        31337 => Genesis::Mainnet, // Anvil forking mainnet; adjust if forking another chain.
        id => eyre::bail!("unsupported chain id {id}; add its Genesis mapping"),
    };

    // Prepare the host executor at the anchor block.
    let sketch = EvmSketch::builder()
        .at_block(BlockNumberOrTag::Number(args.block))
        .with_genesis(genesis)
        .el_rpc_url(args.eth_rpc_url.clone())
        .build()
        .await?;

    let anchor = sketch.anchor.resolve();
    println!("anchor block {} hash {}", args.block, anchor.hash);

    let call = ContractInput {
        contract_address: args.contract,
        caller_address: args.caller,
        calldata: ContractCalldata::Call(calldata.clone()),
    };

    // Execute the call on the host so the rpc_db records every accessed account/slot.
    let output = sketch.call_raw(&call).await?;
    println!("call output: 0x{}", hex::encode(&output));

    // Finalize: fetch merkle proofs for all touched state.
    let input = sketch.finalize().await?;

    // Native pre-check: run the exact guest pipeline natively and print the storage
    // updates the proof will commit. This catches unsupported-opcode failures early.
    {
        let executor = ClientExecutor::eth(&input)?;
        let traced = executor.execute_traced(&call, challenger_inspector_config())?;
        let (storage_updates, skipped) = encoded_state_updates_from_arena(
            &traced.arena,
            traced.gas_used,
            traced.output.clone(),
        )?;
        if !skipped.is_empty() {
            eyre::bail!("execution used unsupported opcodes: {skipped:?}");
        }
        println!("storage updates ({} bytes): 0x{}", storage_updates.len(), {
            hex::encode(&storage_updates)
        });
    }

    // Feed the sketch + call into the guest.
    let input_bytes = bincode::serialize(&input)?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_bytes);
    stdin.write(&args.contract);
    stdin.write(&args.caller);
    stdin.write(&calldata.to_vec());

    let client = ProverClient::from_env();

    // Execute the guest without proving to get the committed public values + cycles.
    let (execute_values, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let public_vals = GasKillerPublicValues::abi_decode(execute_values.as_slice())?;
    assert_eq!(public_vals.anchorHash, anchor.hash, "anchor hash mismatch");
    assert_eq!(public_vals.id, U256::from(args.block), "anchor id mismatch");

    if args.prove == ProveMode::None {
        println!("--prove not set; done.");
        return Ok(());
    }

    // Generate the proof.
    let (pk, vk) = client.setup(ELF);
    let proof = match args.prove {
        ProveMode::Core => client.prove(&pk, &stdin).run().unwrap(),
        ProveMode::Groth16 => client.prove(&pk, &stdin).groth16().run().unwrap(),
        ProveMode::Plonk => client.prove(&pk, &stdin).plonk().run().unwrap(),
        ProveMode::None => unreachable!(),
    };
    println!("generated {:?} proof", args.prove);

    client.verify(&proof, &vk).expect("proof verification failed");
    println!("proof verified");

    let proof_bytes = match args.prove {
        // Core proofs have no compact on-chain encoding.
        ProveMode::Core => String::new(),
        _ => format!("0x{}", hex::encode(proof.bytes())),
    };

    let fixture = GasKillerProofFixture {
        chain_id,
        block_number: args.block,
        anchor_hash: format!("{}", public_vals.anchorHash),
        chain_config_hash: format!("{}", public_vals.chainConfigHash),
        caller_address: format!("{}", public_vals.callerAddress),
        contract_address: format!("{}", public_vals.contractAddress),
        contract_calldata: format!("0x{}", hex::encode(&public_vals.contractCalldata)),
        contract_output: format!("0x{}", hex::encode(&public_vals.contractOutput)),
        storage_updates: format!("0x{}", hex::encode(&public_vals.storageUpdates)),
        opcode_hash: format!("{}", public_vals.opcodeHash),
        vkey: vk.bytes32(),
        public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
        proof: proof_bytes,
    };

    std::fs::write(&args.fixture_out, serde_json::to_string_pretty(&fixture)?)?;
    println!("saved fixture to {}", args.fixture_out.display());

    Ok(())
}
