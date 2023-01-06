use crate::{
    X3dhError, X3dhResult, BYTEARRAY_32_EMPTY, DURATION_ONE_HOUR, OTP_BYTEARRAY_EMPTY,
    SPK_BYTEARRAY_EMPTY,
};
use arrayvec::ArrayVec;
use core::{fmt, time::Duration};
use ed25519_dalek::{ed25519::signature::Signature, Signature as Ed25519Signature};
use rand_core::OsRng;
use tai64::Tai64N;
use x25519_dalek::{
    EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey,
    StaticSecret as X25519StaticSecret,
};

/// A local storage of all the KeyPairs
pub struct KeyStore {
    identity_key_secret: X25519StaticSecret,
    identity_key_public: X25519PublicKey,
    ephemeral_key_secret: Option<X25519EphemeralSecret>,
    ephemeral_key_public: Option<X25519PublicKey>,
    signed_prekey: SignedPrekey,
    previous_signed_prekey: Option<SignedPrekey>,
    /// A Client can Hold a Maximum of 10 PreKeys
    onetime_prekeys: ArrayVec<OneTimePrekey, 10>,
    /// When this keystore was initialized.
    /// To check when the `previous_signed_prekey` was discaded just check the timestamp of the current `signed_prekey`
    timestamp: Tai64N,
    /// Renew Schedule in seconds
    renew_at: Duration,
    /// A function called to sign some bytes
    signer_func: fn(bytes: &[u8]) -> Ed25519Signature,
}

impl KeyStore {
    /// Initialize a new [KeyStore]
    pub fn new(signer_func: fn(bytes: &[u8]) -> Ed25519Signature) -> Self {
        let (identity_key_secret, identity_key_public) = KeyStore::new_static_keypair();

        KeyStore {
            identity_key_secret,
            identity_key_public,
            ephemeral_key_secret: Option::None,
            ephemeral_key_public: Option::None,
            signed_prekey: SignedPrekey::new(signer_func),
            previous_signed_prekey: Option::None,
            onetime_prekeys: OneTimePrekey::generate(),
            timestamp: Tai64N::now(),
            renew_at: Duration::from_secs(86400),
            signer_func,
        }
    }

    /// Initialize the long term static keys, onetime prekeys, and signed prekeys from a slice of bytes.
    /// This slice of bytes can be previously stored initialized protocol keys read from a file or from memory.
    /// NOTE: If the long-term static key is not found all other bytes are discarded and a new [KeyStore] is initialized using `KeyStore::new()`
    pub fn init(
        bytes: [u8; 1124],
        signer_func: fn(bytes: &[u8]) -> Ed25519Signature,
    ) -> X3dhResult<Self> {
        KeyStore::keystore_unpacker(bytes, signer_func)
    }

    /// Generate new ephemeral keypair on each protocol run
    pub fn new_ephemeral_keypair(&mut self) -> &mut Self {
        let secret = X25519EphemeralSecret::new(OsRng);
        let public = X25519PublicKey::from(&secret);

        self.ephemeral_key_secret.replace(secret);
        self.ephemeral_key_public.replace(public);

        self
    }

    /// Clear ephemeral keypair. This is especially useful for assertion tests
    pub fn clear_ephemeral_keypair(&mut self) -> &mut Self {
        self.ephemeral_key_secret = Option::None;
        self.ephemeral_key_public = Option::None;

        self
    }

    /// Helper function to allow reuse of a static keypair
    pub fn new_static_keypair() -> (X25519StaticSecret, X25519PublicKey) {
        let secret = X25519StaticSecret::new(OsRng);
        let public = X25519PublicKey::from(&secret);

        (secret, public)
    }

    /// Get the ephemeral public key
    pub fn ephemeral_key_public(&self) -> Option<X25519PublicKey> {
        self.ephemeral_key_public
    }

    /// Get the identity public key
    pub fn identity_key_public(&self) -> X25519PublicKey {
        self.identity_key_public
    }

    /// Get the signed prekey
    pub fn signed_prekey(&self) -> &SignedPrekey {
        &self.signed_prekey
    }

    /// Get the previously signed prekey
    pub fn previous_signed_prekey(&self) -> Option<&SignedPrekey> {
        self.previous_signed_prekey.as_ref()
    }

    /// Get the onetime prekeys
    pub fn onetime_prekeys(&self) -> &ArrayVec<OneTimePrekey, 10> {
        &self.onetime_prekeys
    }

    /// Remove a [OneTimePreKey]
    pub fn remove_otp(&mut self, used_otp: X25519PublicKey) -> Option<OneTimePrekey> {
        let outcome = self
            .onetime_prekeys
            .iter()
            .enumerate()
            .find(|(_index, otp)| otp.onetime_prekey_public == used_otp);

        match outcome {
            Some((index, _otp)) => Some(self.onetime_prekeys.remove(index)),
            None => None,
        }
    }

    /// Get the timestamp when the [KeyStore] was initialized
    pub fn timestamp(&self) -> &Tai64N {
        &self.timestamp
    }

    /// Get the renewal rate for the [SignedPreKey]
    pub fn renew_at(&self) -> Duration {
        self.renew_at
    }

    /// Generate a prekey bundle to upload to a server
    pub fn prekeys(&self) -> PrekeyBundle {
        let onetime_prekeys = self
            .onetime_prekeys
            .iter()
            .map(|prekey| prekey.onetime_prekey_public)
            .collect::<ArrayVec<X25519PublicKey, 10>>();

        PrekeyBundle {
            identity_key_public: self.identity_key_public,
            signed_prekey_public: self.signed_prekey.public,
            signed_prekey_signature: self.signed_prekey.signature,
            signed_prekey_timestamp: self.signed_prekey.timestamp,
            onetime_prekeys: onetime_prekeys,
        }
    }

    /// Add the rate in seconds at which the `signed_prekey` will be renewed
    pub fn add_renewal_rate(&mut self, seconds: u64) -> &mut Self {
        self.renew_at = Duration::from_secs(seconds);

        self
    }

    /// Generate a new signed prekey
    pub fn new_signed_prekey(&mut self) -> &mut Self {
        let secret = X25519StaticSecret::new(OsRng);
        let public = X25519PublicKey::from(&secret);
        let timestamp = Tai64N::now();
        let signature = (self.signer_func)(public.as_bytes());

        let previous_signed_prekey = self.signed_prekey.clone();
        self.previous_signed_prekey = Some(previous_signed_prekey);

        self.signed_prekey = SignedPrekey {
            secret,
            public,
            signature,
            timestamp,
        };

        self
    }

    /// Check if the `signed_prekey` is up for renewal based on the value of `renew_at`
    pub fn renew_signed_prekey(&mut self) -> &mut Self {
        if Tai64N::now() >= (self.signed_prekey.timestamp + self.renew_at) {
            self.new_signed_prekey();
        }

        self
    }

    /// Discard `previous_signed_prekey`
    pub fn discard_previous_signed_prekey(&mut self) -> &mut Self {
        if let Some(previous_exists) = self.previous_signed_prekey.as_ref() {
            if Tai64N::now() >= (previous_exists.timestamp + self.renew_at + DURATION_ONE_HOUR) {
                self.previous_signed_prekey = Option::None;
            }
        }

        self
    }

    /// Packs `Self` into a byte representation
    pub fn keystore_packer(&self) -> [u8; 1124] {
        let mut bytes = [0; 1124];
        let identity_secret_bytes = self.identity_key_secret.to_bytes();
        let identity_public_bytes: [u8; 32] = self.identity_key_public.to_bytes();
        let signed_prekey_bytes: [u8; 140] = self.signed_prekey.to_bytes();
        let previous_signed_prekey_bytes: [u8; 140] =
            if let Some(spk_exists) = self.previous_signed_prekey.as_ref() {
                spk_exists.to_bytes()
            } else {
                SPK_BYTEARRAY_EMPTY
            };

        let onetime_prekeys_bytes: [[u8; 76]; 10] = OneTimePrekey::packer(&self.onetime_prekeys);
        let timestamp_bytes: [u8; 12] = self.timestamp.to_bytes();
        let renew_at_bytes = self.renew_at.as_secs().to_le_bytes();

        bytes[0..32].copy_from_slice(&identity_secret_bytes);
        bytes[32..64].copy_from_slice(&identity_public_bytes);
        bytes[64..204].copy_from_slice(&signed_prekey_bytes);
        bytes[204..344].copy_from_slice(&previous_signed_prekey_bytes);

        bytes[344..420].copy_from_slice(&onetime_prekeys_bytes[0]);
        bytes[420..496].copy_from_slice(&onetime_prekeys_bytes[1]);
        bytes[496..572].copy_from_slice(&onetime_prekeys_bytes[2]);
        bytes[572..648].copy_from_slice(&onetime_prekeys_bytes[3]);
        bytes[648..724].copy_from_slice(&onetime_prekeys_bytes[4]);
        bytes[724..800].copy_from_slice(&onetime_prekeys_bytes[5]);
        bytes[800..876].copy_from_slice(&onetime_prekeys_bytes[6]);
        bytes[876..952].copy_from_slice(&onetime_prekeys_bytes[7]);
        bytes[952..1028].copy_from_slice(&onetime_prekeys_bytes[8]);
        bytes[1028..1104].copy_from_slice(&onetime_prekeys_bytes[9]);

        bytes[1104..1116].copy_from_slice(&timestamp_bytes);
        bytes[1116..1124].copy_from_slice(&renew_at_bytes);

        bytes
    }

    /// Unpacks a slice of bytes to build the keystore
    pub fn keystore_unpacker(
        bytes: [u8; 1124],
        signer_func: fn(bytes: &[u8]) -> Ed25519Signature,
    ) -> X3dhResult<Self> {
        let identity_key_secret = {
            let is: [u8; 32] = bytes[0..32].try_into().unwrap();

            if is == BYTEARRAY_32_EMPTY {
                return Ok(KeyStore::new(signer_func));
            }
            let is: X25519StaticSecret = is.into();

            is
        };
        let identity_key_public = {
            let ik: [u8; 32] = bytes[32..64].try_into().unwrap();
            let ik: X25519PublicKey = ik.into();

            ik
        };
        let ephemeral_key_secret = Option::None;
        let ephemeral_key_public = Option::None;
        let signed_prekey = {
            let previous_spk: [u8; 140] = bytes[64..204].try_into().unwrap();

            SignedPrekey::from_bytes(previous_spk)
        };
        let previous_signed_prekey = {
            let previous_spk: [u8; 140] = bytes[204..344].try_into().unwrap();

            if previous_spk == SPK_BYTEARRAY_EMPTY {
                Option::None
            } else {
                Some(SignedPrekey::from_bytes(previous_spk))
            }
        };
        let onetime_prekeys = OneTimePrekey::unpacker(&bytes[344..1104])?;
        let timestamp = Tai64N::from_slice(&bytes[1104..1116])?;
        let renew_at = {
            let secs_bytes: [u8; 8] = match bytes[1116..1124].try_into() {
                Ok(value) => value,
                Err(_) => return Err(X3dhError::InvalidBytesForu64Conversion),
            };

            let secs = u64::from_le_bytes(secs_bytes);

            Duration::from_secs(secs)
        };

        Ok(KeyStore {
            identity_key_secret,
            identity_key_public,
            ephemeral_key_secret,
            ephemeral_key_public,
            signed_prekey,
            previous_signed_prekey,
            onetime_prekeys,
            timestamp,
            renew_at,
            signer_func,
        })
    }
}

/// Contains a Signed Prekey
#[derive(Clone)]
pub struct SignedPrekey {
    secret: X25519StaticSecret,
    public: X25519PublicKey,
    signature: Ed25519Signature,
    timestamp: Tai64N,
}

impl SignedPrekey {
    /// Generate a new signed prekey
    pub fn new(signer_func: fn(bytes: &[u8]) -> Ed25519Signature) -> Self {
        let secret = X25519StaticSecret::new(OsRng);
        let public = X25519PublicKey::from(&secret);
        let timestamp = Tai64N::now();
        let signature = (signer_func)(public.as_bytes());

        SignedPrekey {
            secret,
            public,
            signature,
            timestamp,
        }
    }
}

impl ToByteArray<140> for SignedPrekey {
    fn to_bytes(&self) -> [u8; 140] {
        let mut bytes = [0; 140];
        let secret_bytes: [u8; 32] = self.secret.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal
        let public_bytes: [u8; 32] = self.public.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal
        let signature_bytes: [u8; 64] = self.signature.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal
        let timestamp_bytes: [u8; 12] = self.timestamp.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal

        bytes[0..=31].copy_from_slice(&secret_bytes);
        bytes[32..=63].copy_from_slice(&public_bytes);
        bytes[64..=127].copy_from_slice(&signature_bytes);
        bytes[128..=139].copy_from_slice(&timestamp_bytes);

        bytes
    }

    fn from_bytes(bytes: [u8; 140]) -> Self {
        let mut secret = [0; 32];
        let mut public = [0; 32];
        let mut signature = [0; 64];
        let mut timestamp = [0; 12];

        secret.copy_from_slice(&bytes[0..32]);
        public.copy_from_slice(&bytes[32..64]);
        signature.copy_from_slice(&bytes[64..128]);
        timestamp.copy_from_slice(&bytes[128..]);

        let secret: [u8; 32] = secret.try_into().unwrap();
        let secret: X25519StaticSecret = secret.into();
        let public: [u8; 32] = public.try_into().unwrap();
        let public: X25519PublicKey = public.into();
        let signature: [u8; 64] = signature.try_into().unwrap();
        let signature: Ed25519Signature = signature.into();
        let timestamp: [u8; 12] = timestamp.try_into().unwrap();
        let timestamp: Tai64N = Tai64N::from_slice(&timestamp).unwrap();

        SignedPrekey {
            secret,
            public,
            signature,
            timestamp,
        }
    }
}

trait ToByteArray<const T: usize> {
    fn to_bytes(&self) -> [u8; T];

    fn from_bytes(bytes: [u8; T]) -> Self;
}

/// Holds information about a one-time prekey
pub struct OneTimePrekey {
    onetime_prekey_secret: X25519StaticSecret,
    onetime_prekey_public: X25519PublicKey,
    timestamp: Tai64N,
}

impl OneTimePrekey {
    /// Generate a new [OneTimePreKey]
    pub fn new() -> OneTimePrekey {
        let (onetime_prekey_secret, onetime_prekey_public) = KeyStore::new_static_keypair();

        OneTimePrekey {
            onetime_prekey_secret,
            onetime_prekey_public,
            timestamp: Tai64N::now(),
        }
    }

    /// Generate 10 [OneTimePreKeys]
    pub fn generate() -> ArrayVec<Self, 10> {
        (0..10)
            .map(|_| OneTimePrekey::new())
            .collect::<ArrayVec<OneTimePrekey, 10>>()
    }

    fn packer(onetime_prekeys: &ArrayVec<OneTimePrekey, 10>) -> [[u8; 76]; 10] {
        let mut outcome = [[0u8; 76]; 10];

        let mut index = 0usize;

        onetime_prekeys.iter().for_each(|byte_array| {
            let byte_array = byte_array.to_bytes();
            if byte_array != OTP_BYTEARRAY_EMPTY {
                outcome[index] = byte_array;

                index += 1;
            }
        });

        outcome
    }

    fn unpacker(bytes: &[u8]) -> X3dhResult<ArrayVec<OneTimePrekey, 10>> {
        let bytes_len = bytes.len();

        if bytes_len != 760 {
            return Err(X3dhError::InvalidBytesForOTPBytes(bytes_len));
        }

        let mut outcome = ArrayVec::<OneTimePrekey, 10>::new();

        fn to_bytearray76(source: &[u8]) -> X3dhResult<[u8; 76]> {
            match source.try_into() {
                Ok(value) => Ok(value),
                Err(_) => Err(X3dhError::InvalidBytesForOTPBytes(source.len())),
            }
        }

        let mut current = 76usize;
        let mut previous = 0usize;

        for _ in 0..10 {
            let otp_bytes = to_bytearray76(&bytes[previous..current])?;

            if otp_bytes != OTP_BYTEARRAY_EMPTY {
                let otp = OneTimePrekey::from_bytes(otp_bytes);

                outcome.push(otp);
            }

            previous = current;

            current += 76;
        }

        Ok(outcome)
    }
}

impl ToByteArray<76> for OneTimePrekey {
    fn to_bytes(&self) -> [u8; 76] {
        let mut bytes = [0; 76];
        let secret_bytes: [u8; 32] = self.onetime_prekey_secret.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal
        let public_bytes: [u8; 32] = self.onetime_prekey_public.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal
        let timestamp_bytes: [u8; 12] = self.timestamp.to_bytes().try_into().unwrap(); // Cannot fail as their sizes are equal

        bytes[0..=31].copy_from_slice(&secret_bytes);
        bytes[32..=63].copy_from_slice(&public_bytes);
        bytes[64..=75].copy_from_slice(&timestamp_bytes);

        bytes
    }

    fn from_bytes(bytes: [u8; 76]) -> Self {
        let mut secret = [0; 32];
        let mut public = [0; 32];
        let mut timestamp = [0; 12];

        secret.copy_from_slice(&bytes[0..=31]);
        public.copy_from_slice(&bytes[32..=63]);
        timestamp.copy_from_slice(&bytes[64..=75]);

        let secret: [u8; 32] = secret.try_into().unwrap();
        let onetime_prekey_secret: X25519StaticSecret = secret.into();
        let public: [u8; 32] = public.try_into().unwrap();
        let onetime_prekey_public: X25519PublicKey = public.into();
        let timestamp: [u8; 12] = timestamp.try_into().unwrap();
        let timestamp: Tai64N = Tai64N::from_slice(&timestamp).unwrap();

        OneTimePrekey {
            onetime_prekey_secret,
            onetime_prekey_public,
            timestamp,
        }
    }
}

/// A PreKey Bundle for a party in X3DH
#[derive(Debug)]
pub struct PrekeyBundle {
    identity_key_public: X25519PublicKey,
    signed_prekey_public: X25519PublicKey,
    signed_prekey_signature: Ed25519Signature,
    signed_prekey_timestamp: Tai64N,
    onetime_prekeys: ArrayVec<X25519PublicKey, 10>,
}

impl PrekeyBundle {
    /// Get the long term public key
    pub fn identity_key_public(&self) -> X25519PublicKey {
        self.identity_key_public
    }

    /// Get the signed prekey
    pub fn signed_prekey_public(&self) -> X25519PublicKey {
        self.signed_prekey_public
    }

    /// Get the signed prekey signature signed as Ed25519 signature
    pub fn signed_prekey_signature(&self) -> Ed25519Signature {
        self.signed_prekey_signature
    }

    /// Get the timestamp when the signature of the signed prekey was generated
    pub fn signed_prekey_timestamp(&self) -> Tai64N {
        self.signed_prekey_timestamp
    }

    /// Get the collection of one time prekeys
    pub fn onetime_prekeys(&self) -> &ArrayVec<X25519PublicKey, 10> {
        &self.onetime_prekeys
    }
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore")
            .field("identity_key_secret", &"[REDACTED]")
            .field(
                "identity_key_public",
                &blake3::hash(self.identity_key_public.as_bytes()),
            )
            .field("ephemeral_key_secret", &"[REDACTED]")
            .field("ephemeral_key_public", &{
                if let Some(epk) = &self.ephemeral_key_public {
                    blake3::hash(&epk.to_bytes())
                } else {
                    blake3::hash(&BYTEARRAY_32_EMPTY)
                }
            })
            .field("signed_prekey", &self.signed_prekey)
            .field("previous_signed_prekey", &self.previous_signed_prekey)
            .field("onetime_prekeys", &self.onetime_prekeys)
            .field("timestamp", &self.timestamp)
            .field("renew_at", &self.renew_at)
            .field("signer_func", &"signer_func")
            .finish()
    }
}

impl fmt::Debug for OneTimePrekey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimePrekey")
            .field("onetime_prekey_secret", &"[REDACTED]")
            .field(
                "onetime_prekey_public",
                &blake3::hash(self.onetime_prekey_public.as_bytes()),
            )
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl fmt::Debug for SignedPrekey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPrekey")
            .field("secret", &"[REDACTED]")
            .field("public", &blake3::hash(self.public.as_bytes()))
            .field("signature", &blake3::hash(self.signature.as_bytes()))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl PartialEq for OneTimePrekey {
    fn eq(&self, other: &Self) -> bool {
        let otpk = blake3::hash(self.onetime_prekey_public.as_bytes())
            == blake3::hash(other.onetime_prekey_public.as_bytes());
        let timestamp =
            blake3::hash(&self.timestamp.to_bytes()) == blake3::hash(&other.timestamp.to_bytes());

        if otpk && timestamp {
            true
        } else {
            false
        }
    }
}

impl PartialEq for SignedPrekey {
    fn eq(&self, other: &Self) -> bool {
        let public = blake3::hash(self.public.as_bytes()) == blake3::hash(other.public.as_bytes());
        let signature =
            blake3::hash(self.signature.as_bytes()) == blake3::hash(self.signature.as_bytes());
        let timestamp =
            blake3::hash(&self.timestamp.to_bytes()) == blake3::hash(&self.timestamp.to_bytes());

        if public && signature && timestamp {
            true
        } else {
            false
        }
    }
}

impl PartialEq for KeyStore {
    fn eq(&self, other: &Self) -> bool {
        let ik = blake3::hash(self.identity_key_public.as_bytes())
            == blake3::hash(other.identity_key_public.as_bytes());

        /* FIXME The packed version contains [Option::None] but the one yet to be packed can contain [Option::Some(_)]

        let self_epk = {
            if let Some(ephemeral_public) = self.ephemeral_key_public {
                blake3::hash(ephemeral_public.as_bytes())
            } else {
                blake3::hash(&crate::BYTEARRAY_32_EMPTY)
            }
        };
        let other_epk = {
            if let Some(ephemeral_public) = other.ephemeral_key_public {
                blake3::hash(ephemeral_public.as_bytes())
            } else {
                blake3::hash(&crate::BYTEARRAY_32_EMPTY)
            }
        };
        assert_eq!(self_epk, other_epk);
        let epk = self_epk == other_epk;
        */

        let spk = self.signed_prekey == other.signed_prekey;

        let otps = {
            let mut outcome = [false; 10];

            for (index, otp) in self.onetime_prekeys.iter().enumerate() {
                if otp == &other.onetime_prekeys[index] {
                    outcome[index] = true;
                }
            }

            match outcome.iter().find(|is_false| *is_false == &false) {
                Some(_) => false,
                None => true,
            }
        };

        let timestamp =
            blake3::hash(&self.timestamp.to_bytes()) == blake3::hash(&self.timestamp.to_bytes());

        let renew_at = blake3::hash(&self.renew_at.as_secs().to_le_bytes())
            == blake3::hash(&other.renew_at.as_secs().to_le_bytes());

        if ik && spk && otps && timestamp && renew_at {
            true
        } else {
            false
        }
    }
}
