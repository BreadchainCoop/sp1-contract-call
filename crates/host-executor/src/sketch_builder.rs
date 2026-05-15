use std::marker::PhantomData;

use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::B256;
use alloy_provider::{network::AnyNetwork, Provider, RootProvider};
use alloy_rpc_client::RpcClient;
use reth_primitives::EthPrimitives;
use rsp_primitives::genesis::Genesis;
use rsp_rpc_db::BasicRpcDb;
use sp1_cc_client_executor::io::Primitives;
use url::Url;

use crate::{
    anchor_builder::{
        AnchorBuilder, BeaconAnchorBuilder, ChainedBeaconAnchorBuilder, HeaderAnchorBuilder,
    },
    ConsensusBeaconAnchor, Eip4788BeaconAnchor, EvmSketch, HostError,
};

/// A builder for [`EvmSketch`].
#[derive(Debug)]
pub struct EvmSketchBuilder<P, PT, A> {
    block: BlockId,
    genesis: Genesis,
    provider: P,
    anchor_builder: A,
    /// When `true` (default), fetch block N-1 to seed `BasicRpcDb` with the parent
    /// state root. Set to `false` via [`without_state_root_seed`] when the caller
    /// never invokes [`EvmSketch::finalize`] and wants to save one RPC round-trip.
    ///
    /// [`without_state_root_seed`]: EvmSketchBuilder::without_state_root_seed
    seed_state_root: bool,
    phantom: PhantomData<PT>,
}

impl<P, PT, A> EvmSketchBuilder<P, PT, A> {
    /// Sets the block on which the contract will be called.
    pub fn at_block<B: Into<BlockId>>(mut self, block: B) -> Self {
        self.block = block.into();
        self
    }

    /// Sets the chain on which the contract will be called.
    pub fn with_genesis(mut self, genesis: Genesis) -> Self {
        self.genesis = genesis;
        self
    }

    /// Skip the N-1 block fetch used to seed [`BasicRpcDb`] with the parent state root.
    ///
    /// Safe when the caller never invokes [`EvmSketch::finalize`], which is the only
    /// path that reads `BasicRpcDb::state_root`. Saves one `eth_getBlockByNumber`
    /// round-trip (~30–50 ms per build).
    pub fn without_state_root_seed(mut self) -> Self {
        self.seed_state_root = false;
        self
    }
}

impl<PT> EvmSketchBuilder<(), PT, ()> {
    /// Sets the Ethereum HTTP RPC endpoint that will be used.
    pub fn el_rpc_url(
        self,
        rpc_url: Url,
    ) -> EvmSketchBuilder<RootProvider<AnyNetwork>, PT, HeaderAnchorBuilder<RootProvider<AnyNetwork>>>
    {
        let provider = RootProvider::new_http(rpc_url);
        EvmSketchBuilder {
            block: self.block,
            genesis: self.genesis,
            provider: provider.clone(),
            anchor_builder: HeaderAnchorBuilder::new(provider),
            seed_state_root: self.seed_state_root,
            phantom: PhantomData,
        }
    }

    pub fn el_rpc_client(
        self,
        rpc_client: RpcClient,
    ) -> EvmSketchBuilder<RootProvider<AnyNetwork>, PT, HeaderAnchorBuilder<RootProvider<AnyNetwork>>>
    {
        let provider = RootProvider::new(rpc_client);
        EvmSketchBuilder {
            block: self.block,
            genesis: self.genesis,
            provider: provider.clone(),
            anchor_builder: HeaderAnchorBuilder::new(provider),
            seed_state_root: self.seed_state_root,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "optimism")]
impl<P, A> EvmSketchBuilder<P, EthPrimitives, A> {
    /// Configures the [`EvmSketch`] for OP Stack.
    ///
    /// Note: the sketch must be configured with a OP stack genesis with [`with_genesis()`]. On the
    /// client, the executor must be created with [`ClientExecutor::optimism()`].
    ///
    /// [`with_genesis()`]: EvmSketchBuilder::with_genesis
    /// [`ClientExecutor::optimism()`]: sp1_cc_client_executor::ClientExecutor::optimism
    pub fn optimism(self) -> EvmSketchBuilder<P, reth_optimism_primitives::OpPrimitives, A> {
        EvmSketchBuilder {
            block: self.block,
            genesis: self.genesis,
            provider: self.provider,
            anchor_builder: self.anchor_builder,
            seed_state_root: self.seed_state_root,
            phantom: PhantomData,
        }
    }

    /// Configures the [`EvmSketch`] for OP Mainnet..
    pub fn optimism_mainnet(
        self,
    ) -> EvmSketchBuilder<P, reth_optimism_primitives::OpPrimitives, A> {
        EvmSketchBuilder {
            block: self.block,
            genesis: Genesis::OpMainnet,
            provider: self.provider,
            anchor_builder: self.anchor_builder,
            seed_state_root: self.seed_state_root,
            phantom: PhantomData,
        }
    }
}

impl<P, PT> EvmSketchBuilder<P, PT, HeaderAnchorBuilder<P>>
where
    P: Provider<AnyNetwork>,
{
    /// Sets the Beacon HTTP RPC endpoint that will be used.
    pub fn cl_rpc_url(
        self,
        rpc_url: Url,
    ) -> EvmSketchBuilder<P, PT, BeaconAnchorBuilder<P, Eip4788BeaconAnchor>> {
        EvmSketchBuilder {
            block: self.block,
            genesis: self.genesis,
            provider: self.provider,
            anchor_builder: BeaconAnchorBuilder::new(self.anchor_builder, rpc_url),
            seed_state_root: self.seed_state_root,
            phantom: self.phantom,
        }
    }
}

impl<P, PT> EvmSketchBuilder<P, PT, BeaconAnchorBuilder<P, Eip4788BeaconAnchor>>
where
    P: Provider<AnyNetwork>,
{
    /// Sets the Beacon HTTP RPC endpoint that will be used.
    pub fn at_reference_block<B: Into<BlockId>>(
        self,
        block_id: B,
    ) -> EvmSketchBuilder<P, PT, ChainedBeaconAnchorBuilder<P>> {
        EvmSketchBuilder {
            block: self.block,
            genesis: self.genesis,
            provider: self.provider,
            anchor_builder: ChainedBeaconAnchorBuilder::new(self.anchor_builder, block_id.into()),
            seed_state_root: self.seed_state_root,
            phantom: self.phantom,
        }
    }

    /// Configures the builder to generate an [`Anchor`] containing the slot number associated to
    /// the beacon block root.
    ///
    /// This is useful for verification methods that have direct access to the state of the beacon
    /// chain, such as systems using beacon light clients.
    ///
    /// [`Anchor`]: sp1_cc_client_executor::Anchor
    pub fn consensus(
        self,
    ) -> EvmSketchBuilder<P, PT, BeaconAnchorBuilder<P, ConsensusBeaconAnchor>> {
        EvmSketchBuilder {
            block: self.block,
            genesis: self.genesis,
            provider: self.provider,
            anchor_builder: self.anchor_builder.into_consensus(),
            seed_state_root: self.seed_state_root,
            phantom: self.phantom,
        }
    }
}

impl<P, PT, A> EvmSketchBuilder<P, PT, A>
where
    P: Provider<AnyNetwork> + Clone,
    PT: Primitives,
    A: AnchorBuilder,
{
    /// Builds an [`EvmSketch`].
    pub async fn build(self) -> Result<EvmSketch<P, PT>, HostError> {
        let anchor;
        let state_root;

        if self.seed_state_root {
            if let BlockId::Number(BlockNumberOrTag::Number(n)) = self.block {
                // Block number is known upfront — fetch anchor and N-1 block concurrently.
                let prev_block_id = BlockId::number(n - 1);
                let (a, prev_block) = tokio::try_join!(
                    self.anchor_builder.build(self.block),
                    async { self.provider.get_block(prev_block_id).await.map_err(Into::into) }
                )?;
                anchor = a;
                state_root = prev_block
                    .ok_or_else(|| HostError::BlockNotFoundError(prev_block_id))?
                    .header
                    .state_root;
            } else {
                anchor = self.anchor_builder.build(self.block).await?;
                let block_number = anchor.header().number;
                let prev_block_id = BlockId::number(block_number - 1);
                let prev_block = self
                    .provider
                    .get_block(prev_block_id)
                    .await?
                    .ok_or_else(|| HostError::BlockNotFoundError(prev_block_id))?;
                state_root = prev_block.header.state_root;
            }
        } else {
            anchor = self.anchor_builder.build(self.block).await?;
            state_root = B256::ZERO;
        };

        let block_number = anchor.header().number;

        let sketch = EvmSketch {
            genesis: self.genesis,
            anchor,
            rpc_db: BasicRpcDb::new(self.provider.clone(), block_number, state_root),
            receipts: None,
            provider: self.provider,
            phantom: PhantomData,
        };

        Ok(sketch)
    }
}

impl Default for EvmSketchBuilder<(), EthPrimitives, ()> {
    fn default() -> Self {
        Self {
            block: BlockId::default(),
            genesis: Genesis::Mainnet,
            provider: (),
            anchor_builder: (),
            seed_state_root: true,
            phantom: PhantomData,
        }
    }
}
