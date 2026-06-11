//! Bitcoin consensus encoding: little-endian integers and CompactSize.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    NonMinimal,
    Oversized,
    BadFormat(&'static str),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DecodeError::UnexpectedEnd => write!(f, "unexpected end of data"),
            DecodeError::NonMinimal => write!(f, "non-minimal CompactSize"),
            DecodeError::Oversized => write!(f, "size exceeds sanity limit"),
            DecodeError::BadFormat(s) => write!(f, "bad format: {s}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A simple consuming reader over a byte slice.
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.data.len() < n {
            return Err(DecodeError::UnexpectedEnd);
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16_le(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32_le(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64_le(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// CompactSize ("varint"), enforcing minimal encoding.
    pub fn compact_size(&mut self) -> Result<u64, DecodeError> {
        let first = self.u8()?;
        Ok(match first {
            0..=0xfc => first as u64,
            0xfd => {
                let v = self.u16_le()? as u64;
                if v < 0xfd {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
            0xfe => {
                let v = self.u32_le()? as u64;
                if v <= u16::MAX as u64 {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
            0xff => {
                let v = self.u64_le()?;
                if v <= u32::MAX as u64 {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
        })
    }

    /// A CompactSize-prefixed byte vector, with a sanity cap.
    pub fn sized_bytes(&mut self, cap: usize) -> Result<Vec<u8>, DecodeError> {
        let len = self.compact_size()?;
        if len > cap as u64 {
            return Err(DecodeError::Oversized);
        }
        Ok(self.take(len as usize)?.to_vec())
    }
}

pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub fn write_sized_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_roundtrip() {
        for n in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, n);
            let mut r = Reader::new(&buf);
            assert_eq!(r.compact_size().unwrap(), n);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn compact_size_rejects_non_minimal() {
        // 0xfc encoded with the 0xfd prefix.
        let mut r = Reader::new(&[0xfd, 0xfc, 0x00]);
        assert_eq!(r.compact_size(), Err(DecodeError::NonMinimal));
    }
}
