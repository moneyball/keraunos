//! ChaCha20 stream cipher (RFC 8439), with the 96-bit nonce / 32-bit
//! counter layout. Used inside the BOLT 8 AEAD and as the raw keystream
//! generator for BOLT 4 Sphinx (rho/pi/ammag streams, zero nonce).

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[derive(Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> ChaCha20 {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&SIGMA);
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        }
        state[12] = counter;
        for i in 0..3 {
            state[13 + i] =
                u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        }
        ChaCha20 { state }
    }

    fn block(&self, counter: u32) -> [u8; 64] {
        let mut x = self.state;
        x[12] = counter;
        let input = x;
        for _ in 0..10 {
            // Column rounds.
            quarter(&mut x, 0, 4, 8, 12);
            quarter(&mut x, 1, 5, 9, 13);
            quarter(&mut x, 2, 6, 10, 14);
            quarter(&mut x, 3, 7, 11, 15);
            // Diagonal rounds.
            quarter(&mut x, 0, 5, 10, 15);
            quarter(&mut x, 1, 6, 11, 12);
            quarter(&mut x, 2, 7, 8, 13);
            quarter(&mut x, 3, 4, 9, 14);
        }
        let mut out = [0u8; 64];
        for i in 0..16 {
            let word = x[i].wrapping_add(input[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// XOR the keystream (starting at this cipher's initial counter) into
    /// `data`. Encrypt and decrypt are the same operation.
    pub fn xor(&self, data: &mut [u8]) {
        let mut counter = self.state[12];
        for chunk in data.chunks_mut(64) {
            let ks = self.block(counter);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
            counter = counter.wrapping_add(1);
        }
    }

    /// Produce `len` bytes of raw keystream (Sphinx uses this directly).
    pub fn keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        ChaCha20::new(key, nonce, counter).xor(&mut out);
        out
    }
}

#[inline(always)]
fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // RFC 8439 §2.3.2: block function test vector.
    #[test]
    fn rfc8439_block() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = hex::decode_array::<12>("000000090000004a00000000").unwrap();
        let cipher = ChaCha20::new(&key, &nonce, 1);
        let block = cipher.block(1);
        assert_eq!(
            hex::encode(&block),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    // RFC 8439 §2.4.2: encryption test vector ("Ladies and Gentlemen...").
    #[test]
    fn rfc8439_encrypt() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = hex::decode_array::<12>("000000000000004a00000000").unwrap();
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it."
            .to_vec();
        ChaCha20::new(&key, &nonce, 1).xor(&mut data);
        assert_eq!(
            hex::encode(&data),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }
}
