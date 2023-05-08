### X3DH-448
A fast, minimal dependency, key agreement library based on Extended Triple Diffie-Hellman protocol. It is built in Rust, is fast to compile and uses well established cryptographic libraries (Blake3, ed25519-dalek and x25519-dalek) to offer a secure and reliable key-agreement protocol.


#### NOTATION AND PROTOCOL INFORMATION (adapted from the official X3DH Key Agreement Protocol docs)
1. The `curve` used is `X25519`
2. The `hash` used is `BLAKE3`
3. The default ASCII string identifying the application `info` is `X25519_BLAKE3_KEY_AGREEMENT_PROTOCOL` and is specified in this library in the namespace constant `x3dh_xor::INFO`.
4. The encoding function `Encode(PK)` to encode the Diffie-Hellman public keys as a byte sequence is provided by the library `x25519-dalek` on the `x25519_dalek::PublicKey` methods `x25519_dalek::PublicKey::to_bytes()` and `x25519_dalek::PublicKey::as_bytes()`.
5. The concatenation of byte sequences `X` and `Y` is `X || Y`. 
6. `DH(PK1, PK2)` represents a byte sequence which is the shared secret
output from an Elliptic Curve Diffie-Hellman function involving the key
pairs represented by public keys `PK1` and `PK2`. The Elliptic Curve Diffie-
Hellman function is `X25519`.
7. `Sig(PK, M)` represents a byte sequence that is an `Ed25519` signature
on the byte sequence `M` and verifies with public key `PK`, and which was
created by signing `M` with `PK`’s corresponding `private key`. The signing
and verification functions for `Ed25519` are provided by the Rust crate `ed25519_dalek`.
8. `KDF(KM)` represents 32 bytes of output from a HKDF algorithm in this case the crate `blake3` using the function `blake3::derive_key()`
with inputs:
– HKDF input key material = `F || KM`, where `KM` is an input byte
sequence containing secret key material, and F is a byte sequence
containing `32 0xFF` bytes since curve is X25519. `F` is used for cryptographic domain separation with `Ed25519`.
– `HKDF salt` = A zero-filled byte sequence with length equal to the hash output length.
– `HKDF info` = The info parameter from the `info` parameter outlined at number `3`


More changes to improve the security of secrets in memory will be made in the future. Currently this is a great proof-of-concept in creating more information security libraries in Rust
