//! Cryptographic primitives, written from scratch against their RFCs and
//! validated by the official test vectors in each module's tests.
//!
//! Deliberately *not* from scratch: secp256k1 elliptic-curve arithmetic,
//! which comes from libsecp256k1 (the same library Bitcoin Core and LDK
//! use). Hand-rolling EC field math is how funds get lost; hashes and
//! stream ciphers with public test vectors are a different risk class.

pub mod aead;
pub mod chacha20;
pub mod hkdf;
pub mod hmac;
pub mod poly1305;
pub mod ripemd160;
pub mod sha256;

/// SHA-256 convenience.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256::Sha256::digest(data)
}

/// Bitcoin's HASH160 = RIPEMD160(SHA256(x)) — used in P2WPKH and the HTLC
/// script revocation/payment-hash branches.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160::Ripemd160::digest(&sha256(data))
}

/// Constant-time equality for MACs and secrets.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}
