//! Original bech32 (BIP-173 charset/checksum, constant 1) — BOLT 11 uses
//! it without the 90-character length cap.

pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32Error {
    BadChar(char),
    BadChecksum,
    NoSeparator,
    MixedCase,
    PaddingError,
}

impl core::fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Bech32Error::BadChar(c) => write!(f, "invalid bech32 character {c:?}"),
            Bech32Error::BadChecksum => write!(f, "bech32 checksum mismatch"),
            Bech32Error::NoSeparator => write!(f, "missing bech32 separator '1'"),
            Bech32Error::MixedCase => write!(f, "mixed-case bech32 string"),
            Bech32Error::PaddingError => write!(f, "invalid bit-group padding"),
        }
    }
}

impl std::error::Error for Bech32Error {}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        out.push(c >> 5);
    }
    out.push(0);
    for c in hrp.bytes() {
        out.push(c & 31);
    }
    out
}

/// Encode 5-bit values with checksum.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let plm = polymod(&values) ^ 1;

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &d in data {
        out.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((plm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

/// Decode to `(hrp, 5-bit values)` (checksum stripped and verified).
pub fn decode(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let s = s.to_ascii_lowercase();
    let sep = s.rfind('1').ok_or(Bech32Error::NoSeparator)?;
    if sep == 0 || sep + 7 > s.len() {
        return Err(Bech32Error::NoSeparator);
    }
    let hrp = &s[..sep];
    let mut data = Vec::with_capacity(s.len() - sep - 1);
    for c in s[sep + 1..].chars() {
        let v = CHARSET.iter().position(|&x| x as char == c).ok_or(Bech32Error::BadChar(c))?;
        data.push(v as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    if polymod(&values) != 1 {
        return Err(Bech32Error::BadChecksum);
    }
    data.truncate(data.len() - 6);
    Ok((hrp.to_string(), data))
}

/// General power-of-two base conversion (BIP-173 reference semantics).
pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, Bech32Error> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    for &value in data {
        if (value as u32) >> from != 0 {
            return Err(Bech32Error::PaddingError);
        }
        acc = (acc << from) | value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Bech32Error::PaddingError);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-173 valid test vectors.
    #[test]
    fn bip173_valid() {
        let eighty_two_q = "q".repeat(82);
        let long_hrp_one = format!("11{eighty_two_q}c8247j");
        for s in [
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            long_hrp_one.as_str(),
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        ] {
            let (hrp, data) = decode(s).unwrap_or_else(|e| panic!("{s}: {e:?}"));
            assert_eq!(encode(&hrp, &data), s.to_ascii_lowercase());
        }
    }

    #[test]
    fn bip173_invalid() {
        for s in [
            "x1b4n0q5v",                                                    // invalid data char
            "li1dgmt3",                                                     // too-short checksum
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e2w", // bad checksum
            "1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",      // empty hrp
            "splIt1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", // mixed case
        ] {
            assert!(decode(s).is_err(), "{s}");
        }
    }

    #[test]
    fn bit_conversion() {
        // 8->5->8 roundtrip with padding.
        let data = [0xffu8, 0x00, 0xab, 0x42];
        let five = convert_bits(&data, 8, 5, true).unwrap();
        let back = convert_bits(&five, 5, 8, false).unwrap();
        assert_eq!(back, data);
        // Non-zero padding must fail strict conversion.
        let mut bad = five;
        let last = bad.len() - 1;
        bad[last] |= 0x07;
        assert!(convert_bits(&bad, 5, 8, false).is_err());
    }
}
