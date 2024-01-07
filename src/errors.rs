use borsh::{BorshDeserialize, BorshSerialize};

/// The [Result] type that hold [MessagingError] as the `Err()` type
pub type MessagingResult<T> = Result<T, MessagingError>;

/// All errors encountered in this crate
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, BorshDeserialize, BorshSerialize,
)]
pub enum MessagingError {
    /// The hash is not supported
    UnsupportedX3dhHash,
    /// The curve is not supported
    UnsupportedX3dhCurve,
    /// Invalid byte length for the slice provided as serialized [X3dhParameters]
    InvalidX3dhInfoByteLength,
}
