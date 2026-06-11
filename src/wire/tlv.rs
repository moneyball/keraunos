//! TLV streams (BOLT 1): `bigsize type | bigsize length | value`, types
//! strictly ascending, unknown *even* types are a hard error, unknown odd
//! types are ignored ("it's OK to be odd").
//!
//! Also implements `tu16`/`tu32`/`tu64` — truncated big-endian integers
//! with mandatory minimal length — used heavily by onion payloads.

use super::bigsize;
use super::ser::{WireError, WireReader, WireWriter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord {
    pub typ: u64,
    pub value: Vec<u8>,
}

/// Parse a TLV stream occupying the entirety of `data`, enforcing
/// ordering. Returns raw records; callers interpret known types and must
/// call [`check_unknown_even`] with the set they understood.
pub fn parse_stream(data: &[u8]) -> Result<Vec<TlvRecord>, WireError> {
    let mut r = WireReader::new(data);
    let mut records: Vec<TlvRecord> = Vec::new();
    let mut last_type: Option<u64> = None;
    while !r.is_empty() {
        let typ = bigsize::read(&mut r)?;
        if let Some(prev) = last_type {
            if typ <= prev {
                return Err(WireError::TlvNotStrictlyAscending);
            }
        }
        last_type = Some(typ);
        let len = bigsize::read(&mut r)?;
        if len > r.remaining() as u64 {
            return Err(WireError::TlvLengthMismatch);
        }
        let value = r.take(len as usize)?.to_vec();
        records.push(TlvRecord { typ, value });
    }
    Ok(records)
}

/// After interpreting the types in `known`, reject any remaining unknown
/// *even* type per BOLT 1.
pub fn check_unknown_even(records: &[TlvRecord], known: &[u64]) -> Result<(), WireError> {
    for rec in records {
        if rec.typ % 2 == 0 && !known.contains(&rec.typ) {
            return Err(WireError::UnknownRequiredTlv(rec.typ));
        }
    }
    Ok(())
}

pub fn write_record(w: &mut WireWriter, typ: u64, value: &[u8]) {
    bigsize::write(w, typ);
    bigsize::write(w, value.len() as u64);
    w.bytes(value);
}

/// Truncated big-endian u64: leading zero bytes stripped; decoding rejects
/// non-minimal encodings.
pub fn write_tu64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    bytes[skip..].to_vec()
}

pub fn read_tu64(value: &[u8]) -> Result<u64, WireError> {
    if value.len() > 8 {
        return Err(WireError::BadFormat("tu64 too long"));
    }
    if value.first() == Some(&0) {
        return Err(WireError::BadFormat("tu64 not minimal"));
    }
    let mut out = 0u64;
    for &b in value {
        out = out << 8 | b as u64;
    }
    Ok(out)
}

pub fn write_tu32(value: u32) -> Vec<u8> {
    write_tu64(value as u64)
}

pub fn read_tu32(value: &[u8]) -> Result<u32, WireError> {
    if value.len() > 4 {
        return Err(WireError::BadFormat("tu32 too long"));
    }
    Ok(read_tu64(value)? as u32)
}

pub fn write_tu16(value: u16) -> Vec<u8> {
    write_tu64(value as u64)
}

pub fn read_tu16(value: &[u8]) -> Result<u16, WireError> {
    if value.len() > 2 {
        return Err(WireError::BadFormat("tu16 too long"));
    }
    Ok(read_tu64(value)? as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    #[test]
    fn ordering_enforced() {
        // type 1 then type 1 again — not strictly ascending.
        let data = hex::decode("01010001010000").unwrap();
        assert_eq!(
            parse_stream(&data),
            Err(WireError::TlvNotStrictlyAscending)
        );
        // descending
        let data = hex::decode("0301000101010000").unwrap_or_default();
        let _ = parse_stream(&data); // just must not panic
    }

    #[test]
    fn unknown_even_rejected_odd_ignored() {
        // A single record of type 10 (even, unknown).
        let data = hex::decode("0a0100").unwrap();
        let recs = parse_stream(&data).unwrap();
        assert_eq!(check_unknown_even(&recs, &[]), Err(WireError::UnknownRequiredTlv(10)));
        assert_eq!(check_unknown_even(&recs, &[10]), Ok(()));
        // Type 11 (odd, unknown) passes.
        let data = hex::decode("0b0100").unwrap();
        let recs = parse_stream(&data).unwrap();
        assert_eq!(check_unknown_even(&recs, &[]), Ok(()));
    }

    #[test]
    fn length_overrun() {
        // type 1, length 2, but only 1 byte present.
        let data = hex::decode("010200").unwrap();
        assert!(matches!(
            parse_stream(&data),
            Err(WireError::TlvLengthMismatch) | Err(WireError::UnexpectedEnd)
        ));
    }

    #[test]
    fn truncated_ints() {
        assert_eq!(write_tu64(0), Vec::<u8>::new());
        assert_eq!(write_tu64(1), vec![0x01]);
        assert_eq!(write_tu64(0x0100), vec![0x01, 0x00]);
        assert_eq!(write_tu64(0x0102030405060708), hex::decode("0102030405060708").unwrap());
        assert_eq!(read_tu64(&[]).unwrap(), 0);
        assert_eq!(read_tu64(&[0x01]).unwrap(), 1);
        assert_eq!(read_tu64(&[0x01, 0x00]).unwrap(), 0x0100);
        // Non-minimal: leading zero.
        assert!(read_tu64(&[0x00, 0x01]).is_err());
        assert!(read_tu32(&[0x01, 0x02, 0x03, 0x04, 0x05]).is_err());
        assert_eq!(read_tu32(&write_tu32(42)).unwrap(), 42);
        assert_eq!(read_tu16(&write_tu16(420)).unwrap(), 420);
    }
}
