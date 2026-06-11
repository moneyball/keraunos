//! Hex encoding/decoding. Used pervasively in tests (BOLT vectors are hex)
//! and in `Debug`/`Display` impls for protocol types.

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string (upper- or lowercase, no prefix) into bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        out.push(val(pair[0])? << 4 | val(pair[1])?);
    }
    Ok(out)
}

/// Decode hex into a fixed-size array, erroring on length mismatch.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let v = decode(s)?;
    v.try_into().map_err(|_| HexError::BadLength)
}

fn val(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::BadChar(c as char)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    BadLength,
    BadChar(char),
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HexError::OddLength => write!(f, "hex string has odd length"),
            HexError::BadLength => write!(f, "hex string has wrong length for target"),
            HexError::BadChar(c) => write!(f, "invalid hex character {c:?}"),
        }
    }
}

impl std::error::Error for HexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = [0u8, 1, 0xab, 0xcd, 0xff];
        assert_eq!(encode(&bytes), "0001abcdff");
        assert_eq!(decode("0001abcdff").unwrap(), bytes);
        assert_eq!(decode("0001ABCDFF").unwrap(), bytes);
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("zz"), Err(HexError::BadChar('z')));
        let arr: [u8; 2] = decode_array("beef").unwrap();
        assert_eq!(arr, [0xbe, 0xef]);
        assert!(decode_array::<3>("beef").is_err());
    }
}
