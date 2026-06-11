//! Transactions: types, consensus (de)serialization, txid/wtxid, weight.

use super::encode::{write_compact_size, write_sized_bytes, DecodeError, Reader};
use super::script::Script;
use super::sha256d;
use crate::util::hex;
use core::fmt;

/// A transaction id in *internal* byte order (the raw double-SHA256).
/// `Display` shows the conventional reversed ("RPC") hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Txid(pub [u8; 32]);

impl Txid {
    pub fn from_internal(bytes: [u8; 32]) -> Txid {
        Txid(bytes)
    }

    /// Parse the human/RPC (reversed) hex form, as used in the BOLT vectors.
    pub fn from_display_hex(s: &str) -> Result<Txid, hex::HexError> {
        let mut b: [u8; 32] = hex::decode_array(s)?;
        b.reverse();
        Ok(Txid(b))
    }

    pub fn to_display_hex(&self) -> String {
        let mut b = self.0;
        b.reverse();
        hex::encode(&b)
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Txid({})", self.to_display_hex())
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.to_display_hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: Txid, vout: u32) -> OutPoint {
        OutPoint { txid, vout }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.txid.0);
        out.extend_from_slice(&self.vout.to_le_bytes());
    }

    pub fn read(r: &mut Reader) -> Result<OutPoint, DecodeError> {
        Ok(OutPoint { txid: Txid(r.array()?), vout: r.u32_le()? })
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

pub type Witness = Vec<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Witness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Satoshis.
    pub value: u64,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        write_sized_bytes(out, self.script_pubkey.as_bytes());
    }

    pub fn read(r: &mut Reader) -> Result<TxOut, DecodeError> {
        Ok(TxOut {
            value: r.u64_le()?,
            script_pubkey: Script::new(r.sized_bytes(10_000)?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
}

impl Transaction {
    pub fn has_witness(&self) -> bool {
        self.input.iter().any(|i| !i.witness.is_empty())
    }

    /// Serialize without witness data (the txid preimage).
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.version.to_le_bytes());
        self.write_inputs_outputs(&mut out);
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Full serialization: BIP-144 segwit format when any witness present.
    pub fn serialize(&self) -> Vec<u8> {
        if !self.has_witness() {
            return self.serialize_legacy();
        }
        let mut out = Vec::with_capacity(384);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(0x00); // marker
        out.push(0x01); // flag
        self.write_inputs_outputs(&mut out);
        for input in &self.input {
            write_compact_size(&mut out, input.witness.len() as u64);
            for item in &input.witness {
                write_sized_bytes(&mut out, item);
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    fn write_inputs_outputs(&self, out: &mut Vec<u8>) {
        write_compact_size(out, self.input.len() as u64);
        for input in &self.input {
            input.previous_output.write(out);
            write_sized_bytes(out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(out, self.output.len() as u64);
        for output in &self.output {
            output.write(out);
        }
    }

    pub fn txid(&self) -> Txid {
        Txid(sha256d(&self.serialize_legacy()))
    }

    pub fn wtxid(&self) -> Txid {
        Txid(sha256d(&self.serialize()))
    }

    /// BIP-141 weight: 3×base + total.
    pub fn weight(&self) -> u64 {
        let base = self.serialize_legacy().len() as u64;
        let total = self.serialize().len() as u64;
        base * 3 + total
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Transaction, DecodeError> {
        let mut r = Reader::new(bytes);
        let tx = Self::read(&mut r)?;
        if !r.is_empty() {
            return Err(DecodeError::BadFormat("trailing bytes after transaction"));
        }
        Ok(tx)
    }

    pub fn read(r: &mut Reader) -> Result<Transaction, DecodeError> {
        let version = r.u32_le()? as i32;
        let mut input_count = r.compact_size()?;
        let mut segwit = false;
        if input_count == 0 {
            // BIP-144: marker 0x00 then flag 0x01.
            if r.u8()? != 0x01 {
                return Err(DecodeError::BadFormat("bad segwit flag"));
            }
            segwit = true;
            input_count = r.compact_size()?;
        }
        if input_count > 100_000 {
            return Err(DecodeError::Oversized);
        }
        let mut input = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            input.push(TxIn {
                previous_output: OutPoint::read(r)?,
                script_sig: r.sized_bytes(10_000)?,
                sequence: r.u32_le()?,
                witness: Vec::new(),
            });
        }
        let output_count = r.compact_size()?;
        if output_count > 100_000 {
            return Err(DecodeError::Oversized);
        }
        let mut output = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            output.push(TxOut::read(r)?);
        }
        if segwit {
            for txin in input.iter_mut() {
                let items = r.compact_size()?;
                if items > 1000 {
                    return Err(DecodeError::Oversized);
                }
                for _ in 0..items {
                    txin.witness.push(r.sized_bytes(4_000_000)?);
                }
            }
        }
        let lock_time = r.u32_le()?;
        Ok(Transaction { version, lock_time, input, output })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The first-ever Bitcoin transaction (block 170, Satoshi → Hal Finney).
    const BLOCK170_TX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423ed\
ce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5f\
b8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a\
3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f5\
54a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a01\
6b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c0\
3f999b8643f656b412a3ac00000000";

    #[test]
    fn parse_and_reserialize_block170() {
        let bytes = hex::decode(BLOCK170_TX).unwrap();
        let tx = Transaction::deserialize(&bytes).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, 10_0000_0000);
        assert_eq!(tx.serialize(), bytes);
        assert_eq!(
            tx.txid().to_display_hex(),
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
        );
    }

    #[test]
    fn segwit_roundtrip_and_weight() {
        // Hand-built single-input single-output segwit tx.
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid([0x11; 32]), 1),
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: vec![vec![0x30; 71], vec![0x02; 33]],
            }],
            output: vec![TxOut {
                value: 50_000,
                script_pubkey: Script::new_p2wpkh(&[0xab; 20]),
            }],
        };
        let bytes = tx.serialize();
        let back = Transaction::deserialize(&bytes).unwrap();
        assert_eq!(back, tx);
        // txid must ignore witness data.
        let mut stripped = tx.clone();
        stripped.input[0].witness.clear();
        assert_eq!(tx.txid(), stripped.txid());
        assert_ne!(tx.wtxid(), tx.txid());
        // weight = 3*base + total
        assert_eq!(
            tx.weight(),
            3 * tx.serialize_legacy().len() as u64 + bytes.len() as u64
        );
    }
}
