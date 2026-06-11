//! HKDF-SHA256 (RFC 5869). BOLT 8 uses it with a zero-length info string
//! to derive handshake and transport keys.

use super::hmac::{hmac_sha256, HmacSha256};

pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * 32, "HKDF output too long");
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    let mut written = 0;
    while written < out.len() {
        let mut h = HmacSha256::new(prk);
        h.update(&t);
        h.update(info);
        h.update(&[counter]);
        let block = h.finalize();
        let take = (out.len() - written).min(32);
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        t = block.to_vec();
        counter = counter.checked_add(1).expect("output length bounded above");
    }
}

/// The BOLT 8 shape: extract with `salt`, expand 64 bytes with empty info,
/// return as two 32-byte keys.
pub fn hkdf_two_keys(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = extract(salt, ikm);
    let mut okm = [0u8; 64];
    expand(&prk, &[], &mut okm);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // RFC 5869 test case 1.
    #[test]
    fn rfc5869_case1() {
        let ikm = vec![0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = extract(&salt, &ikm);
        assert_eq!(
            hex::encode(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = vec![0u8; 42];
        expand(&prk, &info, &mut okm);
        assert_eq!(
            hex::encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // RFC 5869 test case 3 (zero-length salt and info — the BOLT 8 shape).
    #[test]
    fn rfc5869_case3() {
        let ikm = vec![0x0b; 22];
        let prk = extract(&[], &ikm);
        let mut okm = vec![0u8; 42];
        expand(&prk, &[], &mut okm);
        assert_eq!(
            hex::encode(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }
}
