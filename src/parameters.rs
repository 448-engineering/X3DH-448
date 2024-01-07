use borsh::{BorshDeserialize, BorshSerialize};
use bytes::{BufMut, Bytes, BytesMut};

use crate::{MessagingError, MessagingResult};

/// The parameters of an X3DH protocol run.
/// THe parameters are:
///
/// 1. curve - which can be X25519 or X448
/// 2. hash - this is a 256 or 512 bit hash function
/// 3. info - an ASCII string identifying the application
/// #### Example
/// ```rust
/// use x3dh_448::{X3dhParameters, X3dhCurve, X3dhHash};
///
/// const PROTOCOL_IDENTIFIER: &str = "448_MESSAGING";
///
/// // Create the parameters for a protocol run
/// let x25519_blake3 = X3dhParameters::new(PROTOCOL_IDENTIFIER);
/// let packed = x25519_blake3.pack();
/// assert!(packed.len() >= 3);
/// assert_eq!(x25519_blake3.curve(), X3dhCurve::X25519);
/// assert_eq!(x25519_blake3.hash(), X3dhHash::Blake3);
///
/// let unpacked = X3dhParameters::unpack(&packed);
/// assert!(unpacked.is_ok());
/// assert_eq!(unpacked.unwrap(), x25519_blake3);
/// assert_eq!(x25519_blake3.curve(), X3dhCurve::X25519);
/// assert_eq!(x25519_blake3.hash(), X3dhHash::Blake3);
///
/// dbg!(&x25519_blake3);
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
pub struct X3dhParameters {
    curve: X3dhCurve,
    hash: X3dhHash,
    info: Bytes,
}

impl X3dhParameters {
    /// Instantiate the struct with defaults for curve and hash.
    /// The default for cure is `X25519` and the default for hash is `Blake3`.
    /// The function argument `info` is the `info` parameter of the X3DH protocol
    pub fn new(info: &str) -> Self {
        Self {
            curve: X3dhCurve::default(),
            hash: X3dhHash::default(),
            info: Bytes::copy_from_slice(info.as_bytes()),
        }
    }

    /// Change the [curve](X3dhCurve) parameter
    pub fn with_curve(mut self, curve: X3dhCurve) -> Self {
        self.curve = curve;

        self
    }

    /// Change the [hash](X3dhHash) parameter
    pub fn with_hash(mut self, hash: X3dhHash) -> Self {
        self.hash = hash;

        self
    }

    /// Get the [curve](X3dhCurve) used in the X3DH protocol
    pub fn curve(&self) -> X3dhCurve {
        self.curve
    }

    /// Get the [hash](X3dhHash) used in the X3DH protocol
    pub fn hash(&self) -> X3dhHash {
        self.hash
    }

    /// Get the info used in the X3DH protocol
    pub fn info(&self) -> &Bytes {
        &self.info
    }

    /// Pack into serialized bytes
    pub fn pack(&self) -> BytesMut {
        let mut outcome = BytesMut::new();

        outcome.put(&self.curve.to_bytes()[..]);
        outcome.put(&self.hash.to_bytes()[..]);
        outcome.extend_from_slice(&self.info);

        outcome
    }

    /// Unpack from bytes
    pub fn unpack(bytes: &[u8]) -> MessagingResult<Self> {
        if bytes.len() < 3 {
            return Err(MessagingError::InvalidX3dhInfoByteLength);
        }
        let curve = X3dhCurve::from_bytes(&bytes[0])?;
        let hash = X3dhHash::from_bytes(&bytes[1])?;
        let info = Bytes::copy_from_slice(&bytes[2..]);

        Ok(Self { curve, hash, info })
    }
}

/// The curves for the X3DH protocol
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, BorshSerialize, BorshDeserialize,
)]
pub enum X3dhCurve {
    /// The X25519 elliptic curve Diffie-Hellman key exchange
    #[default]
    X25519,
    /// The X448 elliptic curve Diffie-Hellman key exchange
    X448,
}

impl X3dhCurve {
    /// Convert to [Self]
    pub fn from_bytes(value: &u8) -> MessagingResult<Self> {
        let outcome = match value {
            0u8 => Self::X25519,
            1u8 => Self::X448,
            _ => return Err(MessagingError::UnsupportedX3dhCurve),
        };

        Ok(outcome)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 1] {
        match self {
            X3dhCurve::X25519 => [0u8],
            X3dhCurve::X448 => [1u8],
        }
    }
}

/// The hashing algorithm used by the X3DH protocol
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default, BorshSerialize, BorshDeserialize,
)]
pub enum X3dhHash {
    /// Sha256 algorithm
    Sha256,
    /// Sha512 algorithm
    Sha512,
    /// Blake3 algorithm
    #[default]
    Blake3,
    /// Ascon algorithm
    Ascon,
}

impl X3dhHash {
    /// Convert to [Self]
    pub fn from_bytes(value: &u8) -> MessagingResult<Self> {
        let outcome = match value {
            0u8 => Self::Blake3,
            1u8 => Self::Ascon,
            2u8 => Self::Sha256,
            3u8 => Self::Sha512,
            _ => return Err(MessagingError::UnsupportedX3dhHash),
        };

        Ok(outcome)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 1] {
        match self {
            X3dhHash::Blake3 => [0u8],
            X3dhHash::Ascon => [1u8],
            X3dhHash::Sha256 => [2u8],
            X3dhHash::Sha512 => [3u8],
        }
    }
}

#[cfg(test)]
mod parameter_correctness_checks {
    use crate::{MessagingError, X3dhCurve, X3dhHash, X3dhParameters};
    use bytes::Bytes;

    const PROTOCOL_IDENTIFIER: &str = "448_MESSAGING";

    #[test]
    fn packing_and_unpacking_defaults() {
        const PROTOCOL_IDENTIFIER: &str = "448_MESSAGING";

        // Create the parameters for a protocol run
        let x25519_blake3 = X3dhParameters::new(PROTOCOL_IDENTIFIER);
        let packed = x25519_blake3.pack();
        assert!(packed.len() >= 3);
        assert_eq!(x25519_blake3.curve(), X3dhCurve::X25519);
        assert_eq!(x25519_blake3.hash(), X3dhHash::Blake3);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), x25519_blake3);
        assert_eq!(x25519_blake3.curve(), X3dhCurve::X25519);
        assert_eq!(x25519_blake3.hash(), X3dhHash::Blake3);

        {
            // Create `MessagingError::UnsupportedX3dhCurve`
            let mut packed_changed = packed.clone();
            packed_changed[0] = 3;
            let packed = Bytes::copy_from_slice(&packed_changed);
            let unpacked = X3dhParameters::unpack(&packed);

            assert_eq!(unpacked.err(), Some(MessagingError::UnsupportedX3dhCurve));
        }

        {
            // Create `MessagingError::UnsupportedX3dhHash`
            let mut packed_changed = packed.clone();
            packed_changed[1] = 4;
            let packed = Bytes::copy_from_slice(&packed_changed);
            let unpacked = X3dhParameters::unpack(&packed);

            assert_eq!(unpacked.err(), Some(MessagingError::UnsupportedX3dhHash));
        }

        {
            // Create `MessagingError::InvalidX3dhInfoByteLength`
            let packed = Bytes::copy_from_slice(&packed[..2]);
            let unpacked = X3dhParameters::unpack(&packed);

            assert_eq!(
                unpacked.err(),
                Some(MessagingError::InvalidX3dhInfoByteLength)
            );
        }
    }

    #[test]
    fn curve_25519_info_checks() {
        let protocol = X3dhParameters::new(PROTOCOL_IDENTIFIER)
            .with_curve(X3dhCurve::X25519)
            .with_hash(X3dhHash::Ascon);
        let packed = protocol.pack();
        assert!(packed.len() >= 3);
        assert_eq!(protocol.curve(), X3dhCurve::X25519);
        assert_eq!(protocol.hash(), X3dhHash::Ascon);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), protocol);
        assert_eq!(protocol.curve(), X3dhCurve::X25519);
        assert_eq!(protocol.hash(), X3dhHash::Ascon);

        let protocol = X3dhParameters::new(PROTOCOL_IDENTIFIER)
            .with_curve(X3dhCurve::X25519)
            .with_hash(X3dhHash::Sha256);
        let packed = protocol.pack();
        assert!(packed.len() >= 3);
        assert_eq!(protocol.curve(), X3dhCurve::X25519);
        assert_eq!(protocol.hash(), X3dhHash::Sha256);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), protocol);
        assert_eq!(protocol.curve(), X3dhCurve::X25519);
        assert_eq!(protocol.hash(), X3dhHash::Sha256);

        let protocol = X3dhParameters::new(PROTOCOL_IDENTIFIER)
            .with_curve(X3dhCurve::X25519)
            .with_hash(X3dhHash::Sha512);
        let packed = protocol.pack();
        assert!(packed.len() >= 3);
        assert_eq!(protocol.curve(), X3dhCurve::X25519);
        assert_eq!(protocol.hash(), X3dhHash::Sha512);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), protocol);
        assert_eq!(protocol.curve(), X3dhCurve::X25519);
        assert_eq!(protocol.hash(), X3dhHash::Sha512);
    }

    #[test]
    fn curve_448_info_checks() {
        let protocol = X3dhParameters::new(PROTOCOL_IDENTIFIER)
            .with_curve(X3dhCurve::X448)
            .with_hash(X3dhHash::Ascon);
        let packed = protocol.pack();
        assert!(packed.len() >= 3);
        assert_eq!(protocol.curve(), X3dhCurve::X448);
        assert_eq!(protocol.hash(), X3dhHash::Ascon);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), protocol);
        assert_eq!(protocol.curve(), X3dhCurve::X448);
        assert_eq!(protocol.hash(), X3dhHash::Ascon);

        let protocol = X3dhParameters::new(PROTOCOL_IDENTIFIER)
            .with_curve(X3dhCurve::X448)
            .with_hash(X3dhHash::Sha256);
        let packed = protocol.pack();
        assert!(packed.len() >= 3);
        assert_eq!(protocol.curve(), X3dhCurve::X448);
        assert_eq!(protocol.hash(), X3dhHash::Sha256);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), protocol);
        assert_eq!(protocol.curve(), X3dhCurve::X448);
        assert_eq!(protocol.hash(), X3dhHash::Sha256);

        let protocol = X3dhParameters::new(PROTOCOL_IDENTIFIER)
            .with_curve(X3dhCurve::X448)
            .with_hash(X3dhHash::Sha512);
        let packed = protocol.pack();
        assert!(packed.len() >= 3);
        assert_eq!(protocol.curve(), X3dhCurve::X448);
        assert_eq!(protocol.hash(), X3dhHash::Sha512);

        let unpacked = X3dhParameters::unpack(&packed);
        assert!(unpacked.is_ok());
        assert_eq!(unpacked.unwrap(), protocol);
        assert_eq!(protocol.curve(), X3dhCurve::X448);
        assert_eq!(protocol.hash(), X3dhHash::Sha512);
    }
}
