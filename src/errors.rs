/// A result with [X3dhError] as the `Err` parameter
pub type X3dhResult<T> = Result<T, X3dhError>;

/// A representation of all errors from this crate
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum X3dhError {
    /// The bytes provided for the OneTimePrekey are more or less than those required
    InvalidBytesForOTPBytes(usize),
    /// The bytes provided are not able to be converted to `[u8; 8]`
    InvalidBytesForu64Conversion,
    /// Invalid Length for converting to a [Tai64N](crates.io/tai64) value
    Tai64NLengthInvalid,
    /// Invalid Length for the nanoseconds when converting to a [Tai64N](crates.io/tai64) value
    Tai64NNanosInvalid,
}

impl From<tai64::Error> for X3dhError {
    fn from(value: tai64::Error) -> Self {
        match value {
            tai64::Error::LengthInvalid => X3dhError::Tai64NLengthInvalid,
            tai64::Error::NanosInvalid => X3dhError::Tai64NNanosInvalid,
        }
    }
}
