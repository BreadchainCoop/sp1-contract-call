//! Simple CLI to trace a contract call.
//!
//! Usage:
//!   cargo run -p opcode-tracer --bin trace -- \
//!     --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
//!     --contract 0x1d42064Fc4Beb5F8aAF85F4617AE8b3b5B8Bd801 \
//!     --selector 0x3850c7bd \
//!     --block 20600000

use alloy_primitives::Address;
use eyre::{bail, Result, WrapErr};
use opcode_tracer::{trace_call, TraceConfig};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let rpc_url = get_arg(&args, "--rpc-url")
        .or_else(|| env::var("ETH_RPC_URL").ok())
        .ok_or_else(|| eyre::eyre!("--rpc-url or ETH_RPC_URL environment variable required"))?;

    let contract_str = get_arg(&args, "--contract")
        .ok_or_else(|| eyre::eyre!("--contract required"))?;
    let contract: Address = contract_str
        .parse()
        .wrap_err_with(|| format!("invalid contract address: {contract_str}"))?;

    let selector_str = get_arg(&args, "--selector")
        .ok_or_else(|| eyre::eyre!("--selector required (4-byte function selector, e.g., 0x3850c7bd)"))?;
    let selector = hex::decode(selector_str.trim_start_matches("0x"))
        .wrap_err_with(|| format!("invalid selector hex: {selector_str}"))?;

    if selector.len() != 4 {
        bail!("selector must be exactly 4 bytes, got {} bytes", selector.len());
    }

    let block_number = match get_arg(&args, "--block") {
        Some(s) => Some(s.parse::<u64>().wrap_err_with(|| format!("invalid block number: {s}"))?),
        None => None,
    };

    let config = TraceConfig {
        rpc_url,
        contract,
        calldata: selector,
        block_number,
        caller: None,
    };

    println!("Tracing contract call...");
    println!("  Contract: {}", config.contract);
    println!("  Block: {:?}", config.block_number);

    let result = trace_call(config).await?;

    println!("\n=== Trace Result ===");
    println!("Total opcodes: {}", result.opcodes.len());
    println!("Call frames: {}", result.call_frames);
    println!("Total gas used: {}", result.total_gas_used);

    println!("\nFirst 30 opcodes:");
    for (i, op) in result.opcodes.iter().take(30).enumerate() {
        println!(
            "  {:4}: PC={:5} | {:12} | gas={:8} | cost={:4}",
            i, op.pc, op.name, op.gas_remaining, op.gas_cost
        );
    }

    if result.opcodes.len() > 30 {
        println!("  ... ({} more)", result.opcodes.len() - 30);
    }

    println!("\nOpcode frequency (top 10):");
    let mut freq: Vec<_> = result.opcode_frequency().into_iter().collect();
    freq.sort_by(|a, b| b.1.cmp(&a.1));
    for (name, count) in freq.iter().take(10) {
        println!("  {:12}: {:5}", name, count);
    }

    // Print the raw opcode array
    println!("\nRaw opcode values (hex):");
    let hex_opcodes: Vec<String> = result.opcode_values().iter().map(|b| format!("{:02x}", b)).collect();
    println!("  [{}]", hex_opcodes.join(", "));

    Ok(())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}
