//! Simple CLI to trace a contract call.
//!
//! Usage:
//!   cargo run -p opcode-tracer --bin trace -- \
//!     --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
//!     --contract 0x1d42064Fc4Beb5F8aAF85F4617AE8b3b5B8Bd801 \
//!     --selector 0x3850c7bd \
//!     --block 20600000

use alloy_primitives::Address;
use eyre::Result;
use opcode_tracer::{trace_call, TraceConfig};
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let rpc_url = get_arg(&args, "--rpc-url")
        .or_else(|| env::var("ETH_RPC_URL").ok())
        .expect("--rpc-url or ETH_RPC_URL required");

    let contract: Address = get_arg(&args, "--contract")
        .expect("--contract required")
        .parse()
        .expect("invalid contract address");

    let selector = get_arg(&args, "--selector").expect("--selector required");
    let selector = hex::decode(selector.trim_start_matches("0x")).expect("invalid selector hex");

    let block_number = get_arg(&args, "--block").map(|s| s.parse::<u64>().expect("invalid block"));

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
