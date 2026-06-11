//! Big-endian wire primitives shared by all BOLT messages.

use secp256k1::ecdsa::Signature;
use secp256k1::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    UnexpectedEnd,
    NonMinimalBigSize,
    BadPubkey,
    BadSignature,
    /// TLV stream contained an unknown even type (BOLT 1: "it's OK to be odd").
    UnknownRequiredTlv(u64),
    TlvNotStrictlyAscending,
    TlvLengthMismatch,
    UnknownMessageType(u16),
    TrailingBytes,
    BadFormat(&'static str),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            WireError::UnexpectedEnd => write!(f, "unexpected end of message"),
            WireError::NonMinimalBigSize => write!(f, "BigSize not minimally encoded"),
            WireError::BadPubkey => write!(f, "invalid secp256k1 public key"),
            WireError::BadSignature => write!(f, "invalid signature encoding"),
            WireError::UnknownRequiredTlv(t) => write!(f, "unknown even TLV type {t}"),
            WireError::TlvNotStrictlyAscending => write!(f, "TLV types not strictly ascending"),
            WireError::TlvLengthMismatch => write!(f, "TLV value length mismatch"),
            WireError::UnknownMessageType(t) => write!(f, "unknown message type {t}"),
            WireError::TrailingBytes => write!(f, "trailing bytes after message"),
            WireError::BadFormat(s) => write!(f, "bad format: {s}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Growable big-endian writer.
#[derive(Default)]
pub struct WireWriter(pub Vec<u8>);

impl WireWriter {
    pub fn new() -> WireWriter {
        WireWriter(Vec::with_capacity(256))
    }

    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    /// u16 length-prefixed bytes (the BOLT `len`/`data` idiom).
    pub fn bytes_u16(&mut self, b: &[u8]) {
        debug_assert!(b.len() <= u16::MAX as usize);
        self.u16(b.len() as u16);
        self.bytes(b);
    }
    pub fn pubkey(&mut self, pk: &PublicKey) {
        self.bytes(&pk.serialize());
    }
    /// 64-byte compact signature (LN wire never uses DER).
    pub fn signature(&mut self, sig: &Signature) {
        self.bytes(&sig.serialize_compact());
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Consuming big-endian reader.
pub struct WireReader<'a> {
    data: &'a [u8],
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> WireReader<'a> {
        WireReader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.data.len() < n {
            return Err(WireError::UnexpectedEnd);
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    /// All remaining bytes.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = self.data;
        self.data = &[];
        out
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn bytes_u16(&mut self) -> Result<Vec<u8>, WireError> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    pub fn pubkey(&mut self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(self.take(33)?).map_err(|_| WireError::BadPubkey)
    }
    pub fn signature(&mut self) -> Result<Signature, WireError> {
        Signature::from_compact(self.take(64)?).map_err(|_| WireError::BadSignature)
    }

    pub fn finish(&self) -> Result<(), WireError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}
