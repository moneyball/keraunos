//! BigSize: Bitcoin's CompactSize with big-endian multi-byte values
//! (BOLT 1). Minimal encoding is mandatory on decode.

use super::ser::{WireError, WireReader, WireWriter};

pub fn write(w: &mut WireWriter, value: u64) {
    match value {
        0..=0xfc => w.u8(value as u8),
        0xfd..=0xffff => {
            w.u8(0xfd);
            w.u16(value as u16);
        }
        0x1_0000..=0xffff_ffff => {
            w.u8(0xfe);
            w.u32(value as u32);
        }
        _ => {
            w.u8(0xff);
            w.u64(value);
        }
    }
}

pub fn read(r: &mut WireReader) -> Result<u64, WireError> {
    let first = r.u8()?;
    Ok(match first {
        0..=0xfc => first as u64,
        0xfd => {
            let v = r.u16()? as u64;
            if v < 0xfd {
                return Err(WireError::NonMinimalBigSize);
            }
            v
        }
        0xfe => {
            let v = r.u32()? as u64;
            if v <= 0xffff {
                return Err(WireError::NonMinimalBigSize);
            }
            v
        }
        0xff => {
            let v = r.u64()?;
            if v <= 0xffff_ffff {
                return Err(WireError::NonMinimalBigSize);
            }
            v
        }
    })
}

/// Encoded length without writing.
pub fn len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    // BOLT 1 Appendix A decoding vectors.
    #[test]
    fn bolt1_vectors() {
        let good: [(u64, &str); 8] = [
            (0, "00"),
            (252, "fc"),
            (253, "fd00fd"),
            (65535, "fdffff"),
            (65536, "fe00010000"),
            (4294967295, "feffffffff"),
            (4294967296, "ff0000000100000000"),
            (18446744073709551615, "ffffffffffffffffff"),
        ];
        for (value, bytes) in good {
            let raw = hex::decode(bytes).unwrap();
            let mut r = WireReader::new(&raw);
            assert_eq!(read(&mut r).unwrap(), value, "decode {bytes}");
            assert!(r.is_empty());

            let mut w = WireWriter::new();
            write(&mut w, value);
            assert_eq!(hex::encode(&w.finish()), bytes, "encode {value}");
            assert_eq!(len(value), raw.len());
        }

        let non_canonical = ["fd00fc", "fe0000ffff", "ff00000000ffffffff"];
        for bytes in non_canonical {
            let raw = hex::decode(bytes).unwrap();
            assert_eq!(
                read(&mut WireReader::new(&raw)),
                Err(WireError::NonMinimalBigSize),
                "{bytes}"
            );
        }

        let truncated = ["fd00", "feffff", "ffffffffff", "fd", "fe", "ff", ""];
        for bytes in truncated {
            let raw = hex::decode(bytes).unwrap();
            assert_eq!(
                read(&mut WireReader::new(&raw)),
                Err(WireError::UnexpectedEnd),
                "{bytes}"
            );
        }
    }
}
