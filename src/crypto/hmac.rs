//! HMAC-SHA256 (RFC 2104), the MAC for Sphinx onions and the PRF inside
//! HKDF.

use super::sha256::Sha256;

pub struct HmacSha256 {
    inner: Sha256,
    opad: [u8; 64],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> HmacSha256 {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        HmacSha256 { inner, opad }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner_digest = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_digest);
        outer.finalize()
    }
}

/// One-shot HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // RFC 4231 test cases 1, 2, 3, 6 (6 exercises key > block size).
    #[test]
    fn rfc4231() {
        let cases = [
            (
                hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
        ];
        for (key, data, want) in cases {
            assert_eq!(hex::encode(&hmac_sha256(&key, &data)), want);
        }
    }
}
