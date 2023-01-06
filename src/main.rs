#![forbid(unsafe_code)]
#![deny(missing_docs)]

//!
//!
//!
//!
//! The encoding function `Encode(PK)` is provided by the `x25519_dalek::PublicKey::as_bytes()` function

fn main() {}

mod constants;
pub use constants::*;

mod state;
pub use state::*;

mod utils;
pub use utils::*;

mod errors;
pub use errors::*;

#[cfg(test)]
mod test {
    #[test]
    fn sanity_check_eq() {
        fn ed25519_signer(bytes: &[u8]) -> ed25519_dalek::Signature {
            use ed25519_dalek::Keypair;
            use ed25519_dalek::{Signature, Signer};
            use rand::rngs::OsRng;

            let mut csprng = OsRng {};
            let keypair: Keypair = Keypair::generate(&mut csprng);

            let signature: Signature = keypair.sign(bytes);

            signature
        }

        let mut keystore = crate::KeyStore::new(ed25519_signer);

        keystore.new_ephemeral_keypair();

        let packed_keystore = keystore.keystore_packer();

        let unpacked_keystore = crate::KeyStore::keystore_unpacker(packed_keystore, ed25519_signer);

        // Assert that the active yet to be packed keystore is not equal to the unpacked keystore since
        // packing the keystore clear the current ephemeral keypairs.
        assert_ne!(
            keystore.ephemeral_key_public(),
            unpacked_keystore.as_ref().unwrap().ephemeral_key_public()
        );

        // Clear the ephemeral keypairs to simulate a [KeyStore] loaded from a file or in-memory
        keystore.clear_ephemeral_keypair();

        //dbg!(&keystore);
        assert_eq!(keystore, unpacked_keystore.unwrap());
    }
}
