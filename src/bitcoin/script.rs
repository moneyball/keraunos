//! Bitcoin script: a thin byte-vector newtype, a builder that mirrors
//! Bitcoin Core's `CScript <<` semantics (minimal pushes, CScriptNum
//! integer encoding), and the segwit v0 output templates Lightning uses.

use crate::crypto::{hash160, sha256};

pub mod opcodes {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_1: u8 = 0x51;
    pub const OP_2: u8 = 0x52;
    pub const OP_16: u8 = 0x60;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_RETURN: u8 = 0x6a;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_SWAP: u8 = 0x7c;
    pub const OP_SIZE: u8 = 0x82;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_ADD: u8 = 0x93;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Script(pub Vec<u8>);

impl Script {
    pub fn new(bytes: Vec<u8>) -> Script {
        Script(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `OP_0 <32-byte SHA256(witness_script)>`
    pub fn new_p2wsh(witness_script: &Script) -> Script {
        let mut v = Vec::with_capacity(34);
        v.push(opcodes::OP_0);
        v.push(32);
        v.extend_from_slice(&sha256(&witness_script.0));
        Script(v)
    }

    /// `OP_0 <20-byte HASH160(pubkey)>`
    pub fn new_p2wpkh_from_pubkey(compressed_pubkey: &[u8; 33]) -> Script {
        let mut v = Vec::with_capacity(22);
        v.push(opcodes::OP_0);
        v.push(20);
        v.extend_from_slice(&hash160(compressed_pubkey));
        Script(v)
    }

    pub fn new_p2wpkh(pubkey_hash: &[u8; 20]) -> Script {
        let mut v = Vec::with_capacity(22);
        v.push(opcodes::OP_0);
        v.push(20);
        v.extend_from_slice(pubkey_hash);
        Script(v)
    }

    pub fn is_p2wsh(&self) -> bool {
        self.0.len() == 34 && self.0[0] == opcodes::OP_0 && self.0[1] == 32
    }

    pub fn is_p2wpkh(&self) -> bool {
        self.0.len() == 22 && self.0[0] == opcodes::OP_0 && self.0[1] == 20
    }

    /// Any v0+ segwit program (BOLT 2 `shutdown` scripts allow these).
    pub fn is_witness_program(&self) -> bool {
        if self.0.len() < 4 || self.0.len() > 42 {
            return false;
        }
        let version_ok = self.0[0] == opcodes::OP_0
            || (self.0[0] >= opcodes::OP_1 && self.0[0] <= opcodes::OP_16);
        let push_len = self.0[1] as usize;
        version_ok && (2..=40).contains(&push_len) && self.0.len() == push_len + 2
    }

    /// The `scriptCode` used by BIP-143 when spending this output.
    /// For P2WPKH it is the canonical P2PKH script; for P2WSH the caller
    /// must supply the witness script instead.
    pub fn p2wpkh_script_code(&self) -> Option<Script> {
        if !self.is_p2wpkh() {
            return None;
        }
        let mut v = Vec::with_capacity(25);
        v.extend_from_slice(&[opcodes::OP_DUP, opcodes::OP_HASH160, 20]);
        v.extend_from_slice(&self.0[2..22]);
        v.extend_from_slice(&[opcodes::OP_EQUALVERIFY, opcodes::OP_CHECKSIG]);
        Some(Script(v))
    }
}

impl core::fmt::Debug for Script {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Script({})", crate::util::hex::encode(&self.0))
    }
}

#[derive(Default)]
pub struct ScriptBuilder(Vec<u8>);

impl ScriptBuilder {
    pub fn new() -> ScriptBuilder {
        ScriptBuilder(Vec::new())
    }

    pub fn push_opcode(mut self, op: u8) -> ScriptBuilder {
        self.0.push(op);
        self
    }

    /// Minimal data push (direct length, PUSHDATA1/2/4 as needed).
    pub fn push_slice(mut self, data: &[u8]) -> ScriptBuilder {
        match data.len() {
            0 => self.0.push(opcodes::OP_0),
            1..=0x4b => {
                self.0.push(data.len() as u8);
                self.0.extend_from_slice(data);
            }
            0x4c..=0xff => {
                self.0.push(opcodes::OP_PUSHDATA1);
                self.0.push(data.len() as u8);
                self.0.extend_from_slice(data);
            }
            0x100..=0xffff => {
                self.0.push(opcodes::OP_PUSHDATA2);
                self.0.extend_from_slice(&(data.len() as u16).to_le_bytes());
                self.0.extend_from_slice(data);
            }
            _ => {
                self.0.push(opcodes::OP_PUSHDATA4);
                self.0.extend_from_slice(&(data.len() as u32).to_le_bytes());
                self.0.extend_from_slice(data);
            }
        }
        self
    }

    /// Integer push with Bitcoin Core semantics: 0 → OP_0, 1..=16 → OP_n,
    /// -1 → OP_1NEGATE, otherwise minimal CScriptNum bytes.
    pub fn push_int(self, n: i64) -> ScriptBuilder {
        match n {
            0 => self.push_opcode(opcodes::OP_0),
            -1 => self.push_opcode(opcodes::OP_1NEGATE),
            1..=16 => self.push_opcode(opcodes::OP_1 + (n as u8) - 1),
            _ => {
                let bytes = scriptnum_encode(n);
                self.push_slice(&bytes)
            }
        }
    }

    pub fn into_script(self) -> Script {
        Script(self.0)
    }
}

/// Minimal CScriptNum encoding: little-endian magnitude, sign bit in the
/// high bit of the final byte.
pub fn scriptnum_encode(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let negative = n < 0;
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().expect("nonzero") & 0x80 != 0 {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = out.len() - 1;
        out[last] |= 0x80;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    #[test]
    fn scriptnum() {
        assert_eq!(scriptnum_encode(0), Vec::<u8>::new());
        assert_eq!(scriptnum_encode(1), vec![0x01]);
        assert_eq!(scriptnum_encode(127), vec![0x7f]);
        assert_eq!(scriptnum_encode(128), vec![0x80, 0x00]);
        assert_eq!(scriptnum_encode(144), vec![0x90, 0x00]); // common to_self_delay
        assert_eq!(scriptnum_encode(255), vec![0xff, 0x00]);
        assert_eq!(scriptnum_encode(256), vec![0x00, 0x01]);
        assert_eq!(scriptnum_encode(500), vec![0xf4, 0x01]);
        assert_eq!(scriptnum_encode(-1000), vec![0xe8, 0x83]);
        assert_eq!(scriptnum_encode(505149), vec![0x3d, 0xb5, 0x07]);
    }

    #[test]
    fn p2wpkh_from_pubkey() {
        // Generator pubkey → the canonical "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7k" program.
        let pk = hex::decode_array::<33>(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let spk = Script::new_p2wpkh_from_pubkey(&pk);
        assert_eq!(
            hex::encode(spk.as_bytes()),
            "0014751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert!(spk.is_p2wpkh());
        assert_eq!(
            hex::encode(spk.p2wpkh_script_code().unwrap().as_bytes()),
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
        );
    }

    #[test]
    fn multisig_2of2_shape() {
        let a = [2u8; 33];
        let b = [3u8; 33];
        let script = ScriptBuilder::new()
            .push_int(2)
            .push_slice(&a)
            .push_slice(&b)
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(script.len(), 1 + 34 + 34 + 1 + 1);
        assert_eq!(script.as_bytes()[0], opcodes::OP_2);
        assert_eq!(*script.as_bytes().last().unwrap(), opcodes::OP_CHECKMULTISIG);
    }
}
