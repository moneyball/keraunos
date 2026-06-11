//! BIP-143 segwit v0 signature hashes. Every Lightning signature —
//! funding spends, commitment transactions, HTLC transactions, closing
//! transactions, justice sweeps — is a BIP-143 sighash over P2WSH or
//! P2WPKH inputs.

use super::encode::write_sized_bytes;
use super::script::Script;
use super::sha256d;
use super::tx::Transaction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SighashType {
    All,
    None,
    Single,
    AllPlusAnyoneCanPay,
    NonePlusAnyoneCanPay,
    SinglePlusAnyoneCanPay,
}

impl SighashType {
    pub fn as_u32(self) -> u32 {
        match self {
            SighashType::All => 0x01,
            SighashType::None => 0x02,
            SighashType::Single => 0x03,
            SighashType::AllPlusAnyoneCanPay => 0x81,
            SighashType::NonePlusAnyoneCanPay => 0x82,
            SighashType::SinglePlusAnyoneCanPay => 0x83,
        }
    }

    fn anyone_can_pay(self) -> bool {
        self.as_u32() & 0x80 != 0
    }

    fn base(self) -> u32 {
        self.as_u32() & 0x1f
    }
}

/// Caches the three midstate hashes that BIP-143 shares across inputs.
pub struct SighashCache<'a> {
    tx: &'a Transaction,
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
}

impl<'a> SighashCache<'a> {
    pub fn new(tx: &'a Transaction) -> SighashCache<'a> {
        let mut prevouts = Vec::with_capacity(36 * tx.input.len());
        let mut sequences = Vec::with_capacity(4 * tx.input.len());
        for input in &tx.input {
            input.previous_output.write(&mut prevouts);
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        let mut outputs = Vec::with_capacity(43 * tx.output.len());
        for output in &tx.output {
            output.write(&mut outputs);
        }
        SighashCache {
            tx,
            hash_prevouts: sha256d(&prevouts),
            hash_sequence: sha256d(&sequences),
            hash_outputs: sha256d(&outputs),
        }
    }

    /// The BIP-143 digest for `input_index`, spending an output of `value`
    /// satoshis whose scriptCode is `script_code` (the witness script for
    /// P2WSH; the canonical P2PKH script for P2WPKH).
    pub fn segwit_v0_sighash(
        &self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: SighashType,
    ) -> [u8; 32] {
        let zeros = [0u8; 32];
        let input = &self.tx.input[input_index];

        let hash_prevouts = if sighash_type.anyone_can_pay() { &zeros } else { &self.hash_prevouts };
        let hash_sequence = if sighash_type.anyone_can_pay() || sighash_type.base() != 0x01 {
            &zeros
        } else {
            &self.hash_sequence
        };
        let hash_outputs = match sighash_type.base() {
            0x01 => self.hash_outputs,
            0x03 if input_index < self.tx.output.len() => {
                let mut single = Vec::with_capacity(43);
                self.tx.output[input_index].write(&mut single);
                sha256d(&single)
            }
            _ => zeros,
        };

        let mut preimage = Vec::with_capacity(200 + script_code.len());
        preimage.extend_from_slice(&self.tx.version.to_le_bytes());
        preimage.extend_from_slice(hash_prevouts);
        preimage.extend_from_slice(hash_sequence);
        input.previous_output.write(&mut preimage);
        write_sized_bytes(&mut preimage, script_code.as_bytes());
        preimage.extend_from_slice(&value.to_le_bytes());
        preimage.extend_from_slice(&input.sequence.to_le_bytes());
        preimage.extend_from_slice(&hash_outputs);
        preimage.extend_from_slice(&self.tx.lock_time.to_le_bytes());
        preimage.extend_from_slice(&sighash_type.as_u32().to_le_bytes());

        sha256d(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::tx::Transaction;
    use crate::util::hex;

    // BIP-143 "Native P2WPKH" example: the spec gives the full unsigned tx,
    // the scriptCode, the amount, and the expected sighash for input 1.
    #[test]
    fn bip143_native_p2wpkh() {
        let unsigned = hex::decode(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
             0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000\
             00000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988\
             ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
        )
        .unwrap();
        let tx = Transaction::deserialize(&unsigned).unwrap();
        let script_code = Script::new(
            hex::decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac").unwrap(),
        );
        let cache = SighashCache::new(&tx);
        assert_eq!(
            hex::encode(&cache.hash_prevouts),
            "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"
        );
        assert_eq!(
            hex::encode(&cache.hash_sequence),
            "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"
        );
        assert_eq!(
            hex::encode(&cache.hash_outputs),
            "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"
        );
        let sighash = cache.segwit_v0_sighash(1, &script_code, 6_0000_0000, SighashType::All);
        assert_eq!(
            hex::encode(&sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    // BIP-143 "Native P2WSH" example exercises SINGLE and scriptCode
    // truncation; we test the SIGHASH_SINGLE digest of input 1.
    #[test]
    fn bip143_native_p2wsh_single() {
        let unsigned = hex::decode(
            "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000\
             0000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f800000\
             00000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788\
             ac00000000",
        )
        .unwrap();
        let tx = Transaction::deserialize(&unsigned).unwrap();
        // scriptCode is the witnessScript for value 49 BTC at input 1
        // (already truncated to the single CHECKSIG by the spec example —
        // we use the full witnessScript variant labeled scriptCode in the
        // BIP for hashing "without OP_CODESEPARATOR" case 0).
        let script_code = Script::new(
            hex::decode(
                "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9\
                 626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac",
            )
            .unwrap(),
        );
        let cache = SighashCache::new(&tx);
        let sighash =
            cache.segwit_v0_sighash(1, &script_code, 49_0000_0000, SighashType::Single);
        assert_eq!(
            hex::encode(&sighash),
            "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
        );
    }
}
