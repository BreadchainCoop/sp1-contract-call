//! EVM sketch input structures and implementations.
//!
//! This module provides the [`EvmSketchInput`] struct, which contains all the necessary
//! information for executing Ethereum Virtual Machine (EVM) contracts in SP1. Instead of
//! passing the entire blockchain state, it includes only the required state roots, merkle
//! proofs, and specific storage slots that were accessed or modified during execution.
//!
//! The main purpose is to optimize contract execution by providing a minimal witness
//! that contains just the data needed to prove correct execution.

use std::{fmt::Debug, iter::once, sync::Arc};

use alloy_consensus::ReceiptEnvelope;
use alloy_evm::{Database, Evm, IntoTxEnv};
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_consensus::{ConsensusError, HeaderValidator};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_evm::{ConfigureEvm, EthEvm, EvmEnv};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives::{EthPrimitives, Header, NodePrimitives, SealedHeader};
use revm::{
    context::{
        result::{HaltReason, ResultAndState},
        TxEnv,
    },
    inspector::NoOpInspector,
    state::Bytecode,
    Context, MainBuilder, MainContext,
};

use crate::inspector::{CallTraceArena, TracingInspector, TracingInspectorConfig};
use revm_primitives::{B256, U256};
use rsp_client_executor::{error::ClientError, io::WitnessInput};
use rsp_mpt::EthereumState;
use rsp_primitives::genesis::Genesis;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{Anchor, ContractInput, EnvOverrides};

/// Information about how the contract executions accessed state, which is needed to execute the
/// contract in SP1.
///
/// Instead of passing in the entire state, only the state roots and merkle proofs
/// for the storage slots that were modified and accessed are passed in.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmSketchInput {
    /// The current block anchor.
    pub anchor: Anchor,
    /// The genesis block specification.
    pub genesis: Genesis,
    /// The previous block headers starting from the most recent. These are used for calls to the
    /// blockhash opcode.
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    pub ancestor_headers: Vec<Header>,
    /// Current block's Ethereum state.
    pub state: EthereumState,
    /// Account bytecodes.
    pub bytecodes: Vec<Bytecode>,
    /// Receipts.
    #[serde_as(as = "Option<Vec<alloy_consensus::serde_bincode_compat::ReceiptEnvelope>>")]
    pub receipts: Option<Vec<ReceiptEnvelope>>,
}

impl WitnessInput for EvmSketchInput {
    #[inline(always)]
    fn state(&self) -> &EthereumState {
        &self.state
    }

    #[inline(always)]
    fn state_anchor(&self) -> B256 {
        self.anchor.header().state_root
    }

    #[inline(always)]
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode> {
        self.bytecodes.iter()
    }

    #[inline(always)]
    fn sealed_headers(&self) -> impl Iterator<Item = SealedHeader> {
        once(SealedHeader::seal_slow(self.anchor.header().clone()))
            .chain(self.ancestor_headers.iter().map(|h| SealedHeader::seal_slow(h.clone())))
    }
}

pub trait Primitives: NodePrimitives {
    type ChainSpec: EthChainSpec + Debug;
    type HaltReason: Debug;

    fn build_spec(genesis: &Genesis) -> Result<Arc<Self::ChainSpec>, ClientError>;

    fn validate_header(
        header: &SealedHeader,
        chain_spec: Arc<Self::ChainSpec>,
    ) -> Result<(), ConsensusError>;

    /// Execute a contract call.
    ///
    /// `overrides` adjusts the simulated environment (gas limits) and MUST be
    /// bit-identical between the host that built the sketch and the guest that
    /// proves the execution — see [`EnvOverrides`]. Pass
    /// `EnvOverrides::default()` for the historical header-derived behaviour.
    fn transact<DB>(
        input: &ContractInput,
        db: DB,
        header: &Header,
        difficulty: U256,
        chain_spec: Arc<Self::ChainSpec>,
        overrides: EnvOverrides,
    ) -> Result<ResultAndState<Self::HaltReason>, String>
    where
        DB: Database;

    /// Execute a contract call with opcode tracing enabled.
    /// Returns both the execution result and the execution trace.
    fn transact_with_trace<DB>(
        input: &ContractInput,
        db: DB,
        header: &Header,
        difficulty: U256,
        chain_spec: Arc<Self::ChainSpec>,
        overrides: EnvOverrides,
    ) -> Result<(ResultAndState<Self::HaltReason>, CallTraceArena), String>
    where
        DB: Database;

    fn active_fork_name(chain_spec: &Self::ChainSpec, header: &Header) -> String;
}

impl Primitives for EthPrimitives {
    type ChainSpec = ChainSpec;
    type HaltReason = HaltReason;

    fn build_spec(genesis: &Genesis) -> Result<Arc<Self::ChainSpec>, ClientError> {
        Ok(Arc::new(ChainSpec::try_from(genesis).unwrap()))
    }

    fn validate_header(
        header: &SealedHeader,
        chain_spec: Arc<Self::ChainSpec>,
    ) -> Result<(), ConsensusError> {
        let validator = EthBeaconConsensus::new(chain_spec);
        validator.validate_header(header)
    }

    fn transact<DB: Database>(
        input: &ContractInput,
        db: DB,
        header: &Header,
        difficulty: U256,
        chain_spec: Arc<Self::ChainSpec>,
        overrides: EnvOverrides,
    ) -> Result<ResultAndState<Self::HaltReason>, String> {
        let EvmEnv { mut cfg_env, mut block_env, .. } =
            EthEvmConfig::new(chain_spec).evm_env(header).unwrap();

        // Set the base fee to 0 to enable 0 gas price transactions.
        block_env.basefee = 0;
        block_env.difficulty = difficulty;
        cfg_env.disable_nonce_check = true;
        cfg_env.disable_balance_check = true;
        cfg_env.disable_fee_charge = true;

        let tx_gas_limit = overrides.tx_gas_limit.unwrap_or(header.gas_limit);
        if let Some(block_gas_limit) = overrides.block_gas_limit {
            block_env.gas_limit = block_gas_limit;
        }
        if overrides.tx_gas_limit.is_some() {
            // revm applies the EIP-7825 cap (2^24) from Osaka on; an overridden
            // tx gas limit must not be silently clamped by it, or the same
            // execution would diverge across the hardfork boundary.
            cfg_env.tx_gas_limit_cap = Some(tx_gas_limit);
        }

        // The gas limit must be set on the TxEnv actually passed to
        // `transact` — `Evm::transact` replaces the context's tx env with the
        // converted input, so a `modify_tx_chained` assignment never survives.
        // (`TxEnv::default()` carries revm's 2^24 builder default, which would
        // silently cap every execution otherwise.)
        let mut tx_env: TxEnv = input.into_tx_env();
        tx_env.gas_limit = tx_gas_limit;

        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(cfg_env)
            .with_block(block_env)
            .build_mainnet_with_inspector(NoOpInspector {});

        let mut evm = EthEvm::new(evm, false);

        evm.transact(tx_env).map_err(|err| err.to_string())
    }

    fn transact_with_trace<DB: Database>(
        input: &ContractInput,
        db: DB,
        header: &Header,
        difficulty: U256,
        chain_spec: Arc<Self::ChainSpec>,
        overrides: EnvOverrides,
    ) -> Result<(ResultAndState<Self::HaltReason>, CallTraceArena), String> {
        let EvmEnv { mut cfg_env, mut block_env, .. } =
            EthEvmConfig::new(chain_spec).evm_env(header).unwrap();

        // Set the base fee to 0 to enable 0 gas price transactions.
        block_env.basefee = 0;
        block_env.difficulty = difficulty;
        cfg_env.disable_nonce_check = true;
        cfg_env.disable_balance_check = true;
        cfg_env.disable_fee_charge = true;

        let tx_gas_limit = overrides.tx_gas_limit.unwrap_or(header.gas_limit);
        if let Some(block_gas_limit) = overrides.block_gas_limit {
            block_env.gas_limit = block_gas_limit;
        }
        if overrides.tx_gas_limit.is_some() {
            // See `transact`: an overridden tx gas limit must escape the
            // EIP-7825 cap revm applies from Osaka on.
            cfg_env.tx_gas_limit_cap = Some(tx_gas_limit);
        }

        let inspector = TracingInspector::new(TracingInspectorConfig::default_geth());

        // See `transact`: the gas limit must ride on the TxEnv passed to
        // `Evm::transact`, not on the context.
        let mut tx_env: TxEnv = input.into_tx_env();
        tx_env.gas_limit = tx_gas_limit;

        let evm = Context::mainnet()
            .with_db(db)
            .with_cfg(cfg_env)
            .with_block(block_env)
            .build_mainnet_with_inspector(inspector);

        let mut evm = EthEvm::new(evm, true); // true enables inspector

        let result = evm.transact(tx_env).map_err(|err| err.to_string())?;

        // Extract the trace from the inspector
        let trace = evm.into_inner().inspector.into_traces();

        Ok((result, trace))
    }

    fn active_fork_name(chain_spec: &Self::ChainSpec, header: &Header) -> String {
        let spec = reth_evm_ethereum::revm_spec(chain_spec, header);

        spec.to_string()
    }
}

#[cfg(feature = "optimism")]
impl Primitives for reth_optimism_primitives::OpPrimitives {
    type ChainSpec = reth_optimism_chainspec::OpChainSpec;
    type HaltReason = op_revm::OpHaltReason;

    fn build_spec(genesis: &Genesis) -> Result<Arc<Self::ChainSpec>, ClientError> {
        Ok(Arc::new(reth_optimism_chainspec::OpChainSpec::try_from(genesis).unwrap()))
    }

    fn validate_header(
        header: &SealedHeader,
        chain_spec: Arc<Self::ChainSpec>,
    ) -> Result<(), ConsensusError> {
        let validator = reth_optimism_consensus::OpBeaconConsensus::new(chain_spec);
        validator.validate_header(header)
    }

    fn transact<DB: Database>(
        input: &ContractInput,
        db: DB,
        header: &Header,
        difficulty: U256,
        chain_spec: Arc<Self::ChainSpec>,
        overrides: EnvOverrides,
    ) -> Result<ResultAndState<Self::HaltReason>, String> {
        use op_revm::{DefaultOp, OpBuilder};

        let EvmEnv { mut cfg_env, mut block_env, .. } =
            reth_optimism_evm::OpEvmConfig::optimism(chain_spec).evm_env(header).unwrap();

        // Set the base fee to 0 to enable 0 gas price transactions.
        block_env.basefee = 0;
        block_env.difficulty = difficulty;
        cfg_env.disable_nonce_check = true;
        cfg_env.disable_balance_check = true;
        cfg_env.disable_fee_charge = true;

        let tx_gas_limit = overrides.tx_gas_limit.unwrap_or(header.gas_limit);
        if let Some(block_gas_limit) = overrides.block_gas_limit {
            block_env.gas_limit = block_gas_limit;
        }
        if overrides.tx_gas_limit.is_some() {
            cfg_env.tx_gas_limit_cap = Some(tx_gas_limit);
        }

        // See the Ethereum `transact`: the gas limit must ride on the tx env
        // passed to `Evm::transact`, not on the context.
        let mut tx_env: op_revm::OpTransaction<TxEnv> = input.into_tx_env();
        tx_env.base.gas_limit = tx_gas_limit;

        let evm = op_revm::OpContext::op()
            .with_db(db)
            .with_cfg(cfg_env)
            .with_block(block_env)
            .build_op_with_inspector(NoOpInspector {});

        let mut evm = alloy_op_evm::OpEvm::new(evm, false);

        evm.transact(tx_env).map_err(|err| err.to_string())
    }

    fn transact_with_trace<DB: Database>(
        input: &ContractInput,
        db: DB,
        header: &Header,
        difficulty: U256,
        chain_spec: Arc<Self::ChainSpec>,
        overrides: EnvOverrides,
    ) -> Result<(ResultAndState<Self::HaltReason>, CallTraceArena), String> {
        // For Optimism, we currently don't support tracing due to API limitations.
        // Just run the regular transact and return an empty trace.
        let result = Self::transact(input, db, header, difficulty, chain_spec, overrides)?;
        Ok((result, CallTraceArena::default()))
    }

    fn active_fork_name(chain_spec: &Self::ChainSpec, header: &Header) -> String {
        let spec = reth_optimism_evm::revm_spec(chain_spec, header);
        let spec: &'static str = spec.into();

        spec.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContractCalldata;
    use alloy_primitives::{address, hex, keccak256, Bytes, U256 as PrimU256};
    use revm::{
        context::result::{ExecutionResult, HaltReason},
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
    };

    /// ~40M-gas busy loop (1,000,000 iterations × ~40 gas), then return 42.
    /// The compute deliberately exceeds the 30M header gas limit used below.
    fn gigagas_burner_runtime() -> Bytes {
        // PUSH3 1_000_000; JUMPDEST(4); DUP1; ISZERO; PUSH1 0x11; JUMPI;
        // PUSH1 1; SWAP1; SUB; PUSH1 4; JUMP; JUMPDEST(0x11); POP;
        // PUSH1 42; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN.
        hex!("620f42405b8015601157600190036004565b50602a60005260206000f3").into()
    }

    /// A Cancun-era mainnet header with a 30M gas limit.
    fn test_header() -> Header {
        Header {
            number: 20_000_000,
            timestamp: 1_717_000_000, // post-Cancun mainnet timestamp
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            excess_blob_gas: Some(0),
            blob_gas_used: Some(0),
            ..Default::default()
        }
    }

    fn burner_call_result(
        overrides: crate::EnvOverrides,
    ) -> revm::context::result::ResultAndState<HaltReason> {
        let burner = address!("0x0000000000000000000000000000000000002001");
        let mut db = CacheDB::new(EmptyDB::default());
        let code = revm::state::Bytecode::new_raw(gigagas_burner_runtime());
        db.insert_account_info(
            burner,
            AccountInfo {
                balance: PrimU256::ZERO,
                nonce: 0,
                code_hash: keccak256(code.original_byte_slice()),
                code: Some(code),
            },
        );

        let input = ContractInput {
            contract_address: burner,
            caller_address: address!("0x0000000000000000000000000000000000000c11"),
            calldata: ContractCalldata::Call(Bytes::new()),
        };
        let chain_spec = EthPrimitives::build_spec(&Genesis::Mainnet).unwrap();

        EthPrimitives::transact(&input, db, &test_header(), U256::ZERO, chain_spec, overrides)
            .expect("transact must not error at the EVM-construction level")
    }

    /// Without overrides the guest executes at the header's gas limit — the
    /// 40M-gas burner MUST halt out-of-gas. This is the historical behaviour
    /// and the exact hazard for unbounded Gas Killer executions: an honest
    /// heavy execution re-run in the guest would diverge and falsely slash.
    #[test]
    fn burner_halts_out_of_gas_at_header_limit() {
        let output = burner_call_result(crate::EnvOverrides::default());
        match output.result {
            ExecutionResult::Halt { reason: HaltReason::OutOfGas(_), gas_used } => {
                // The full header limit must be available — not revm's 2^24
                // TxEnv builder default, which the old `modify_tx_chained`
                // (dead code: `Evm::transact` replaces the context tx env)
                // silently left in place.
                assert_eq!(
                    gas_used, 30_000_000,
                    "execution must OOG at the header gas limit, not at another cap"
                );
            }
            other => panic!("expected OutOfGas halt at the 30M header limit, got {other:?}"),
        }
    }

    /// With both limits lifted to 2^40 the same call succeeds and burns more
    /// gas than any real block admits — proving the override reaches revm's
    /// block env, tx env, and the EIP-7825 cap alike.
    #[test]
    fn burner_succeeds_beyond_header_limit_with_overrides() {
        let output = burner_call_result(crate::EnvOverrides::gas_limits(1 << 40));
        match output.result {
            ExecutionResult::Success { gas_used, output, .. } => {
                assert!(
                    gas_used > 30_000_000,
                    "burner must consume more than the header gas limit, used {gas_used}"
                );
                assert_eq!(
                    output.data().as_ref(),
                    PrimU256::from(42).to_be_bytes::<32>(),
                    "burner must return 42"
                );
            }
            other => panic!("expected success under unbounded overrides, got {other:?}"),
        }
    }

    /// The chainConfigHash must bind the overrides: legacy hash for
    /// no-overrides (bit-compatible with existing proofs), a distinct
    /// [`ChainConfigWithEnvOverrides`] hash otherwise, both round-tripping
    /// through their verifiers.
    #[test]
    fn chain_config_hash_binds_overrides() {
        use crate::{verifiy_chain_config_eth, verify_chain_config_eth_with_overrides};
        use revm_primitives::hardfork::SpecId;

        let chain_id = 1u64;
        let header_gas_limit = 30_000_000u64;
        let legacy = {
            let config = crate::ChainConfig {
                chainId: PrimU256::from(chain_id),
                activeForkName: SpecId::CANCUN.to_string(),
            };
            keccak256(alloy_sol_types::SolValue::abi_encode_packed(&config))
        };
        let overridden = {
            let config = crate::ChainConfigWithEnvOverrides {
                chainId: PrimU256::from(chain_id),
                activeForkName: SpecId::CANCUN.to_string(),
                blockGasLimitOverride: 1 << 40,
                txGasLimitOverride: 1 << 40,
            };
            keccak256(alloy_sol_types::SolValue::abi_encode_packed(&config))
        };
        assert_ne!(legacy, overridden, "overrides must change the chain config hash");

        verifiy_chain_config_eth(legacy, chain_id, SpecId::CANCUN).unwrap();
        verify_chain_config_eth_with_overrides(
            overridden,
            chain_id,
            SpecId::CANCUN,
            crate::EnvOverrides::gas_limits(1 << 40),
            header_gas_limit,
        )
        .unwrap();
        // Cross-checks must fail: a proof under lifted limits cannot satisfy a
        // verifier expecting header-derived limits, and vice versa.
        assert!(verifiy_chain_config_eth(overridden, chain_id, SpecId::CANCUN).is_err());
        assert!(verify_chain_config_eth_with_overrides(
            legacy,
            chain_id,
            SpecId::CANCUN,
            crate::EnvOverrides::gas_limits(1 << 40),
            header_gas_limit,
        )
        .is_err());
        // No-override verification degenerates to the legacy path.
        verify_chain_config_eth_with_overrides(
            legacy,
            chain_id,
            SpecId::CANCUN,
            crate::EnvOverrides::default(),
            header_gas_limit,
        )
        .unwrap();
    }
}
