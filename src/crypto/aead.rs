//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) — the cipher of the BOLT 8
//! transport ("ChaChaPoly-1305" in Noise terms).

use super::chacha20::ChaCha20;
use super::poly1305::Poly1305;

pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptError;

impl core::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("AEAD tag verification failed")
    }
}

impl std::error::Error for DecryptError {}

fn mac(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    // Poly1305 key = first 32 bytes of the ChaCha20 block at counter 0.
    let mut poly_key = [0u8; 32];
    ChaCha20::new(key, nonce, 0).xor(&mut poly_key);

    let mut p = Poly1305::new(&poly_key);
    p.update(aad);
    p.update(&[0u8; 16][..(16 - aad.len() % 16) % 16]);
    p.update(ciphertext);
    p.update(&[0u8; 16][..(16 - ciphertext.len() % 16) % 16]);
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ciphertext.len() as u64).to_le_bytes());
    p.finalize()
}

/// Encrypt `plaintext` in place-ish: returns ciphertext || 16-byte tag.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    ChaCha20::new(key, nonce, 1).xor(&mut out);
    let tag = mac(key, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// Decrypt ciphertext||tag, verifying the tag in constant time first.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(DecryptError);
    }
    let (ct, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_LEN);
    let expect = mac(key, nonce, aad, ct);
    if !super::ct_eq(&expect, tag) {
        return Err(DecryptError);
    }
    let mut out = ct.to_vec();
    ChaCha20::new(key, nonce, 1).xor(&mut out);
    Ok(out)
}

/// BOLT 8 nonce layout: 4 zero bytes then the 64-bit counter little-endian.
pub fn nonce_from_counter(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // RFC 8439 §2.8.2.
    #[test]
    fn rfc8439_aead() {
        let key = hex::decode_array::<32>(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap();
        let nonce = hex::decode_array::<12>("070000004041424344454647").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

        let out = encrypt(&key, &nonce, &aad, plaintext);
        let (ct, tag) = out.split_at(out.len() - TAG_LEN);
        assert_eq!(
            hex::encode(ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex::encode(tag), "1ae10b594f09e26a7e902ecbd0600691");

        let back = decrypt(&key, &nonce, &aad, &out).unwrap();
        assert_eq!(back, plaintext);

        // Flip one bit anywhere → must fail.
        let mut bad = out.clone();
        bad[5] ^= 1;
        assert!(decrypt(&key, &nonce, &aad, &bad).is_err());
        let mut bad_tag = out.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 1;
        assert!(decrypt(&key, &nonce, &aad, &bad_tag).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        // BOLT 8 act messages encrypt an empty payload with nonempty AAD.
        let key = [7u8; 32];
        let nonce = nonce_from_counter(0);
        let aad = [1u8; 32];
        let out = encrypt(&key, &nonce, &aad, &[]);
        assert_eq!(out.len(), TAG_LEN);
        assert_eq!(decrypt(&key, &nonce, &aad, &out).unwrap(), Vec::<u8>::new());
    }
}
