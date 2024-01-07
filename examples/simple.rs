use bytes::Bytes;
use x3dh_448::{MessagingError, X3dhCurve, X3dhHash, X3dhParameters};

fn main() {
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

    dbg!(&x25519_blake3);

    {
        // Create `MessagingError::UnsupportedX3dhCurve`
        let mut packed_changed = packed.clone();
        packed_changed[0] = 3;
        let packed = Bytes::copy_from_slice(&packed_changed);
        let unpacked = X3dhParameters::unpack(&packed);
        dbg!(&unpacked);

        assert_eq!(unpacked.err(), Some(MessagingError::UnsupportedX3dhCurve));
    }

    {
        // Create `MessagingError::UnsupportedX3dhHash`
        let mut packed_changed = packed.clone();
        packed_changed[1] = 4;
        let packed = Bytes::copy_from_slice(&packed_changed);
        let unpacked = X3dhParameters::unpack(&packed);
        dbg!(&unpacked);

        assert_eq!(unpacked.err(), Some(MessagingError::UnsupportedX3dhHash));
    }

    {
        // Create `MessagingError::InvalidX3dhInfoByteLength`
        let packed = Bytes::copy_from_slice(&packed[..2]);
        let unpacked = X3dhParameters::unpack(&packed);
        dbg!(&unpacked);

        assert_eq!(
            unpacked.err(),
            Some(MessagingError::InvalidX3dhInfoByteLength)
        );
    }
}
