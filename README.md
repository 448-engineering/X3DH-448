### X3DH-448
A fast, minimal dependency, key agreement library based on Extended Triple Diffie-Hellman protocol. It is built in Rust, is fast to compile and uses well established cryptographic libraries (Blake3, ed25519-dalek and x25519-dalek) to offer a secure and reliable key-agreement protocol.

This algorithm is derived from the specification from the Signal encrypted chat protocol - [https://signal.org/docs/specifications/x3dh/](https://signal.org/docs/specifications/x3dh/)


#### NOTATION AND PROTOCOL INFORMATION (adapted from the official X3DH Key Agreement Protocol docs)
1. The `curve` used is `X25519`
2. The `hash` used is `BLAKE3`
3. The `info` is the default ASCII string identifying the application is specified in this library in the namespace constant `X3DH_X25519_BLAKE3_ED25519_KEY_AGREEMENT`.
4. The `Encode(PK)` encoding function for a X25519 public key is to convert the `PK` to a 32 bytes. In this library `x25519-dalek` rust crate is used for DH Key agreement and therefore the encoding function `EncodePK` is in the crate namespace `ed25519_dalek::PublicKey::to_bytes()` .
5. `X||Y` is a concatenation of byte sequences `X` and `Y`
6. `DH(PK1, PK2)` is a byte sequence which is the shared secret output from an Elliptic Curve Diffie-Hellman function involving the key pairs represented by the X25519 public keys PK1 and PK2.
7. `Sig(PK, M)` represents a byte sequence that is an `Ed25519` signature on the byte sequence `M` and public key `PK` is used to verify the signature of byte sequence `M`
8. `KDF(KM)` represents 32 bytes of output from blake3 `HKDF` algorithm where:
   -  `HKDF input key material = F||M` where `KM` is an input byte sequence containing secret key material and `F` is a byte sequence containing `[256u8; 32]` bytes since X25519 is used. `F` is used for cryptographic domain separation with `Ed25519`.
   - `HKDF salt` = A `[0u8; 32]` byte sequence with length equal to the hash output length.
   - `HKDF info` = The info parameter specified above as `X3DH_X25519_BLAKE3_ED25519_KEY_AGREEMENT`

####  Elliptic Curve Public Keys:
|      Name       | Definition                     |
| :-------------: | :----------------------------- |
| IK<sub>A</sub>  | Alice's Long-term Identity Key |
| IK<sub>B</sub>  | Bobs's Long-term Identity Key  |
| EK<sub>A</sub>  | Alice's Ephemeral Key          |
| EK<sub>B</sub>  | Bob's Ephemeral Key            |
| SPK<sub>A</sub> | Alice's Signed PreKey          |
| SPK<sub>B</sub> | Bob's Signed PreKey            |
| OPK<sub>A</sub> | Alice's One-time PreKey        |
| SPK<sub>B</sub> | Bob's One-time PreKey          |


- The signed prekeys are changed periodically
- Each One-Time prekey is used for each single X3DH run.
- The name `prekeys` means that these type of keys are published to a trusted server prior to any party beginning the protocol.
- Each party publishes an Ed25519 signed pre-key `SPK` and a set of X25519 one-time prekeys `OPKs`
- During each protocol run, each party generates a new X25519 ephemeral key pair with public key `EK` 
- Each successful X3DH run results in a shared `32-byte` secret key `SK` between parties. This key can be used with a  `post-X3DH` secure protocol.