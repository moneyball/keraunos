//! Poly1305 one-time authenticator (RFC 8439), 32-bit limb implementation
//! in the style of poly1305-donna.

pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Poly1305 {
        let le = |i: usize| u32::from_le_bytes(key[i..i + 4].try_into().expect("4 bytes"));
        // r is clamped and split into five 26-bit limbs.
        let r = [
            le(0) & 0x03ff_ffff,
            (le(3) >> 2) & 0x03ff_ff03,
            (le(6) >> 4) & 0x03ff_c0ff,
            (le(9) >> 6) & 0x03f0_3fff,
            (le(12) >> 8) & 0x000f_ffff,
        ];
        let pad = [le(16), le(20), le(24), le(28)];
        Poly1305 { r, h: [0; 5], pad, buf: [0; 16], buf_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 16 {
                return; // input exhausted without completing the block
            }
            let block = self.buf;
            self.block(&block, 1 << 24);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for block in &mut chunks {
            self.block(block.try_into().expect("exact chunk"), 1 << 24);
        }
        let rem = chunks.remainder();
        self.buf[..rem.len()].copy_from_slice(rem);
        self.buf_len = rem.len();
    }

    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let le = |i: usize| u32::from_le_bytes(m[i..i + 4].try_into().expect("4 bytes"));
        let [r0, r1, r2, r3, r4] = self.r;
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

        // h += m
        let h0 = self.h[0] + (le(0) & 0x03ff_ffff);
        let h1 = self.h[1] + ((le(3) >> 2) & 0x03ff_ffff);
        let h2 = self.h[2] + ((le(6) >> 4) & 0x03ff_ffff);
        let h3 = self.h[3] + ((le(9) >> 6) & 0x03ff_ffff);
        let h4 = self.h[4] + ((le(12) >> 8) | hibit);

        // h *= r (mod 2^130 - 5)
        let m = |a: u32, b: u32| a as u64 * b as u64;
        let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
        let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
        let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
        let mut d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
        let mut d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

        // Partial carry propagation.
        let mut c;
        c = d0 >> 26;
        let mut h0 = (d0 & 0x03ff_ffff) as u32;
        d1 += c;
        c = d1 >> 26;
        let h1 = (d1 & 0x03ff_ffff) as u32;
        d2 += c;
        c = d2 >> 26;
        let h2 = (d2 & 0x03ff_ffff) as u32;
        d3 += c;
        c = d3 >> 26;
        let h3 = (d3 & 0x03ff_ffff) as u32;
        d4 += c;
        c = d4 >> 26;
        let h4 = (d4 & 0x03ff_ffff) as u32;
        h0 += (c as u32) * 5;
        let c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        let h1 = h1 + c;

        self.h = [h0, h1, h2, h3, h4];
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            // Final partial block: append 0x01, zero-fill, no high bit.
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 1;
            self.block(&block.clone(), 0);
        }

        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;

        // Full carry.
        let mut c;
        c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute h + -p and constant-time select if h >= p.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let take_g = (g4 >> 31).wrapping_sub(1); // all-ones if h >= p
        let keep_h = !take_g;
        h0 = (h0 & keep_h) | (g0 & take_g);
        h1 = (h1 & keep_h) | (g1 & take_g);
        h2 = (h2 & keep_h) | (g2 & take_g);
        h3 = (h3 & keep_h) | (g3 & take_g);
        h4 = (h4 & keep_h) | (g4 & take_g);

        // Repack 5x26-bit limbs into 4x32-bit words (mod 2^128).
        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);

        // tag = (h + pad) mod 2^128
        let mut f: u64;
        f = w0 as u64 + self.pad[0] as u64;
        let t0 = f as u32;
        f = w1 as u64 + self.pad[1] as u64 + (f >> 32);
        let t1 = f as u32;
        f = w2 as u64 + self.pad[2] as u64 + (f >> 32);
        let t2 = f as u32;
        f = w3 as u64 + self.pad[3] as u64 + (f >> 32);
        let t3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&t0.to_le_bytes());
        tag[4..8].copy_from_slice(&t1.to_le_bytes());
        tag[8..12].copy_from_slice(&t2.to_le_bytes());
        tag[12..16].copy_from_slice(&t3.to_le_bytes());
        tag
    }

    pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let mut p = Poly1305::new(key);
        p.update(data);
        p.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // RFC 8439 §2.5.2.
    #[test]
    fn rfc8439_mac() {
        let key = hex::decode_array::<32>(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        )
        .unwrap();
        let tag = Poly1305::mac(&key, b"Cryptographic Forum Research Group");
        assert_eq!(hex::encode(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    // RFC 8439 Appendix A.3 vector #2 (wraparound-stress r value).
    #[test]
    fn rfc8439_a3_2() {
        let mut key = [0u8; 32];
        key[16..].copy_from_slice(
            &hex::decode("36e5f6b5c5e06070f0efca96227a863e").unwrap(),
        );
        let text = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
        let tag = Poly1305::mac(&key, &text[..]);
        assert_eq!(hex::encode(&tag), "36e5f6b5c5e06070f0efca96227a863e");
    }

    #[test]
    fn incremental_matches_oneshot() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
        let data: Vec<u8> = (0..201u32).map(|i| (i % 256) as u8).collect();
        for chunk in [1usize, 5, 15, 16, 17, 33] {
            let mut p = Poly1305::new(&key);
            for part in data.chunks(chunk) {
                p.update(part);
            }
            assert_eq!(p.finalize(), Poly1305::mac(&key, &data), "chunk={chunk}");
        }
    }
}
