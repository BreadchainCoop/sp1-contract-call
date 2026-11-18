# SP1 Contract Calls

Generates zero-knowledge proofs of Ethereum smart contract execution.

[Documentation](https://succinctlabs.github.io/sp1-contract-call/)

## Overview

This library (`sp1-contract-call`, or `sp1-cc` for short), provides developers with a simple interface to efficiently generate a ZKP of Ethereum smart contract execution offchain, that can be verified cheaply onchain for ~280k gas. This enables developers to verifiably run very expensive Solidity smart contract calls and be able to use this information in their onchain applications. Developers simply specify their Solidity function interface in Rust using the [`alloy_sol_macro`](https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/) library and can write an SP1 program to generate these proofs. Let's check out an example below:

## Formatting

`rustfmt.toml` uses nightly-only options, so format with the pinned nightly that CI checks against:

```sh
rustup toolchain install nightly-2026-11-18 --profile minimal --component rustfmt
cargo +nightly-2026-11-18 fmt --all
```

Plain `cargo fmt` uses the stable toolchain from `rust-toolchain`, which ignores those options and produces different output. The repository's VS Code settings already point rust-analyzer's format-on-save at the pinned nightly; set the equivalent in other editors.

## Acknowledgments

* [Unstable.Money](https://www.unstable.money/): Developed the smart contract featured in the `multiplexer` example.
* [SP1](https://github.com/succinctlabs/sp1): A fast, feature-complete zkVM for developers that can prove the execution of arbitrary Rust (or any LLVM-compiled) program.

