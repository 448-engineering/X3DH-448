use core::time::Duration;

/// The DH protocol used for the X3DH protocol in this case `X25519`
pub const CURVE_NAME: &str = "X25519";
/// The hash used in the cryptographically procotol in this case Blake3
pub const HASH_NAME: &str = "BLAKE3";
/// The ASCII string identifying the application
pub const INFO: &str = "X25519_BLAKE3_KEY_AGREEMENT_PROTOCOL";

/// The hash of a long term public key used as the key in a key/value store
pub type StaticSecretHash = blake3::Hash;

/// The hash of an ephemeral public key
pub type EphemeralPublicKeyHash = blake3::Hash;

/// The hash of an static public key
pub type StaticPublicKeyHash = blake3::Hash;

/// A Duration of one hour
pub const DURATION_ONE_HOUR: Duration = Duration::from_secs(60 * 60);

/// An empty array representing 32 byte array `[u8; 32]` initialized with 0 bytes
pub const BYTEARRAY_32_EMPTY: [u8; 32] = [0u8; 32];

/// An empty array representing the OneTime PreKey initialized with 0 bytes
pub const OTP_BYTEARRAY_EMPTY: [u8; 76] = [0u8; 76];

/// An empty array representing the Signed PreKey initialized with 0 bytes
pub const SPK_BYTEARRAY_EMPTY: [u8; 140] = [0u8; 140];
