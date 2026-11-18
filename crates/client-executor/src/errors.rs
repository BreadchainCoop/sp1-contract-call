use thiserror::Error;

/// Error types for the client library.
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("ABI error: {0}")]
    ABI(#[from] alloy_sol_types::Error),

    #[error("RSP error: {0}")]
    RSP(#[from] rsp_client_executor::error::ClientError),

    #[error("The logs weren't prefetched")]
    LogsNotPrefetched,

    #[error("The provided chain config is invalid")]
    InvalidChainConfig,
}

/// Why [`Primitives::transact`] produced no execution result.
///
/// A revert or halt is not a `TransactError`: those are execution results.
/// This covers the cases where revm refused to run the call at all, split by
/// cause so a caller can tell an input the prover chose (an invalid
/// transaction) from a failure of the environment (a database error).
///
/// [`Primitives::transact`]: crate::io::Primitives::transact
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TransactError {
    /// The transaction is invalid under the execution environment, e.g. its
    /// gas limit is below the intrinsic cost. This depends only on the call
    /// and the environment, so the same inputs fail the same way everywhere.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// The block header is invalid for execution.
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// The database failed to serve state.
    #[error("database error: {0}")]
    Database(String),

    /// Any other EVM error.
    #[error("EVM error: {0}")]
    Custom(String),
}

impl<DBError, TxError> From<revm::context::result::EVMError<DBError, TxError>> for TransactError
where
    DBError: std::fmt::Display,
    TxError: std::fmt::Display,
{
    fn from(err: revm::context::result::EVMError<DBError, TxError>) -> Self {
        use revm::context::result::EVMError;

        match err {
            EVMError::Transaction(e) => Self::InvalidTransaction(e.to_string()),
            EVMError::Header(e) => Self::InvalidHeader(e.to_string()),
            EVMError::Database(e) => Self::Database(e.to_string()),
            EVMError::Custom(e) => Self::Custom(e),
        }
    }
}
