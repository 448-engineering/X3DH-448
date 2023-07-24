use arrayvec::ArrayVec;
use core::fmt;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519PublicKey};
use std::borrow::Borrow;
use tai64::Tai64N;
use x25519_dalek::{
    EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret,
};

pub type X25519StaticPublic = X25519PublicKey;

#[derive(PartialEq, Eq)]
pub struct X25519PublicKeyData {
    pub(crate) public_key: X25519StaticPublic,
    pub(crate) timestamp: Tai64N,
}

impl fmt::Debug for X25519PublicKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519PublicKeyData")
            .field("public_key", &blake3::hash(self.public_key.as_bytes()))
            .field(
                "timestamp",
                &humantime::format_rfc3339_nanos(self.timestamp.to_system_time()),
            )
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct Ed25519PublicKeyData {
    pub(crate) public_key: Ed25519PublicKey,
    pub(crate) timestamp: Tai64N,
    pub(crate) signature: Ed25519Signature,
}

impl fmt::Debug for Ed25519PublicKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PublicKeyData")
            .field("public_key", &blake3::hash(self.public_key.as_bytes()))
            .field(
                "timestamp",
                &humantime::format_rfc3339_nanos(self.timestamp.to_system_time()),
            )
            .field("signature", &blake3::hash(&self.signature.to_bytes()))
            .finish()
    }
}

struct X25519EphemeralKeyData {
    ek_secret: X25519EphemeralSecret,
    ek_public: X25519PublicKey,
}

impl X25519EphemeralKeyData {
    fn generate() -> Self {
        let ek_secret = X25519EphemeralSecret::random();
        let ek_public: X25519PublicKey = ek_secret.borrow().into();

        X25519EphemeralKeyData {
            ek_secret,
            ek_public,
        }
    }

    fn dh(self, their_public_key: X25519PublicKey) -> SharedSecret {
        self.ek_secret.diffie_hellman(&their_public_key)
    }
}

pub struct X3dhState {
    dsk_data: Option<Ed25519PublicKeyData>,
    ik_data: Option<X25519PublicKeyData>,
    ek_data: X25519EphemeralKeyData,
    opks: ArrayVec<X25519PublicKeyData, 50>,
}

impl fmt::Debug for X3dhState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "X3dhState {{\n  dsk_data: {:?},\n  ik_data: {:?},\n  ek_data: {:?},\n  opks: {:?}\n}}",
            &self.dsk_data, &self.ik_data, &"REDACTED[EPHEMERAL_X25519_PUBLIC_KEY]", &self.opks
        )
    }
}

impl X3dhState {
    pub fn new() -> Self {
        X3dhState {
            dsk_data: Option::default(),
            ik_data: Option::default(),
            ek_data: X25519EphemeralKeyData::generate(),
            opks: ArrayVec::new(),
        }
    }

    pub fn load_dsk(
        &mut self,
        public_key: Ed25519PublicKey,
        timestamp: Tai64N,
        signature: Ed25519Signature,
    ) -> &mut Self {
        self.dsk_data = Some(Ed25519PublicKeyData {
            public_key,
            timestamp,
            signature,
        });

        self
    }

    pub fn load_ik(&mut self, public_key: X25519StaticPublic, timestamp: Tai64N) -> &mut Self {
        self.ik_data = Some(X25519PublicKeyData {
            public_key,
            timestamp,
        });

        self
    }

    pub fn rotate_ek(&mut self) -> &mut Self {
        self.ek_data = X25519EphemeralKeyData::generate();

        self
    }

    pub fn ephemeral_public_key(&self) -> X25519PublicKey {
        self.ek_data.ek_public
    }

    // HANDLE MULTIPLE SHARED SECRETS

    //pub fn prekey_bundle(&self) -> PreKeyBundle {} // Include Signature and timestamps
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreKeyBundle {
    dks: Ed25519PublicKey,
    //ik: X,
}
