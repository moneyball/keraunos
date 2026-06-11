//! RIPEMD-160, needed for Bitcoin's HASH160 (P2WPKH programs and the
//! `RIPEMD160(payment_hash)` / `RIPEMD160(SHA256(revocationpubkey))`
//! branches of BOLT 3 HTLC scripts).

#[rustfmt::skip]
const R_LEFT: [usize; 80] = [
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
];
#[rustfmt::skip]
const R_RIGHT: [usize; 80] = [
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
];
#[rustfmt::skip]
const S_LEFT: [u32; 80] = [
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
];
#[rustfmt::skip]
const S_RIGHT: [u32; 80] = [
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
];
const K_LEFT: [u32; 5] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xa953_fd4e];
const K_RIGHT: [u32; 5] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x7a6d_76e9, 0x0000_0000];

fn f(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        4 => x ^ (y | !z),
        _ => unreachable!(),
    }
}

pub struct Ripemd160 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self::new()
    }
}

impl Ripemd160 {
    pub fn new() -> Ripemd160 {
        Ripemd160 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Ripemd160::new();
        h.update(data);
        h.finalize()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return; // input exhausted without completing the block
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(64);
        for block in &mut chunks {
            self.compress(block.try_into().expect("exact chunk"));
        }
        let rem = chunks.remainder();
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        // RIPEMD-160 length is little-endian (MD4 lineage), unlike SHA-2.
        self.buf[56..64].copy_from_slice(&bit_len.to_le_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        }

        let [mut al, mut bl, mut cl, mut dl, mut el] = self.state;
        let [mut ar, mut br, mut cr, mut dr, mut er] = self.state;

        for j in 0..80 {
            let round = j / 16;
            let t = al
                .wrapping_add(f(round, bl, cl, dl))
                .wrapping_add(x[R_LEFT[j]])
                .wrapping_add(K_LEFT[round])
                .rotate_left(S_LEFT[j])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f(4 - round, br, cr, dr))
                .wrapping_add(x[R_RIGHT[j]])
                .wrapping_add(K_RIGHT[round])
                .rotate_left(S_RIGHT[j])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;
        }

        let t = self.state[1].wrapping_add(cl).wrapping_add(dr);
        self.state[1] = self.state[2].wrapping_add(dl).wrapping_add(er);
        self.state[2] = self.state[3].wrapping_add(el).wrapping_add(ar);
        self.state[3] = self.state[4].wrapping_add(al).wrapping_add(br);
        self.state[4] = self.state[0].wrapping_add(bl).wrapping_add(cr);
        self.state[0] = t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // Vectors from the RIPEMD-160 paper (Dobbertin, Bosselaers, Preneel).
    #[test]
    fn paper_vectors() {
        let cases: [(&[u8], &str); 5] = [
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "6f3fa39b6b503c384f919a49a7aa5c2c08bdfb45",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex::encode(&Ripemd160::digest(input)), want);
        }
    }

    #[test]
    fn hash160_known_value() {
        // HASH160 of the generator-point pubkey (well-known value):
        // pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        assert_eq!(
            hex::encode(&crate::crypto::hash160(&pk)),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }
}
