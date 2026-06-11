//! BOLT 3 transaction construction: commitment transactions, second-stage
//! HTLC transactions, and the cooperative closing transaction.
//!
//! Tested byte-for-byte against the Appendix C vectors, including the
//! HTLC-trimming, fee, output-ordering and CLTV-tiebreak rules.

use crate::bitcoin::script::opcodes::*;
use crate::bitcoin::{OutPoint, Script, ScriptBuilder, Transaction, TxIn, TxOut, Txid, Witness};
use crate::crypto::ripemd160::Ripemd160;
use crate::crypto::sha256::Sha256;
use crate::keys::TxCreationKeys;
use crate::types::{FeeRatePerKw, Msat, PaymentHash, PaymentPreimage};
use secp256k1::ecdsa::Signature;
use secp256k1::PublicKey;

pub const COMMITMENT_TX_BASE_WEIGHT: u64 = 724;
pub const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;
pub const HTLC_TIMEOUT_TX_WEIGHT: u64 = 663;
pub const HTLC_SUCCESS_TX_WEIGHT: u64 = 703;
/// Approximate weight of the (funding-spend) closing transaction with two
/// P2WPKH outputs — used for fee proposals.
pub const CLOSING_TX_WEIGHT_BOUND: u64 = 714;

/// An HTLC as it appears in a specific commitment transaction.
/// `offered` is from the broadcaster's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtlcOutputInCommitment {
    pub offered: bool,
    pub amount_msat: Msat,
    pub cltv_expiry: u32,
    pub payment_hash: PaymentHash,
}

pub fn htlc_timeout_fee(feerate: FeeRatePerKw) -> u64 {
    feerate.fee_for_weight(HTLC_TIMEOUT_TX_WEIGHT)
}

pub fn htlc_success_fee(feerate: FeeRatePerKw) -> u64 {
    feerate.fee_for_weight(HTLC_SUCCESS_TX_WEIGHT)
}

/// Is this HTLC output created at all, or trimmed to fees?
pub fn htlc_is_trimmed(
    htlc: &HtlcOutputInCommitment,
    feerate: FeeRatePerKw,
    broadcaster_dust_limit_sat: u64,
) -> bool {
    let second_stage_fee =
        if htlc.offered { htlc_timeout_fee(feerate) } else { htlc_success_fee(feerate) };
    htlc.amount_msat.to_sat_floor() < broadcaster_dust_limit_sat + second_stage_fee
}

pub mod scripts {
    use super::*;

    /// `2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG`, keys sorted.
    pub fn funding_redeemscript(a: &PublicKey, b: &PublicKey) -> Script {
        let (first, second) = if a.serialize() <= b.serialize() { (a, b) } else { (b, a) };
        ScriptBuilder::new()
            .push_int(2)
            .push_slice(&first.serialize())
            .push_slice(&second.serialize())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    /// The revocable, CSV-delayed output script used by `to_local` and by
    /// both second-stage HTLC transaction outputs.
    pub fn revocable_delayed(
        revocation_key: &PublicKey,
        to_self_delay: u16,
        delayed_payment_key: &PublicKey,
    ) -> Script {
        ScriptBuilder::new()
            .push_opcode(OP_IF)
            .push_slice(&revocation_key.serialize())
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CHECKSEQUENCEVERIFY)
            .push_opcode(OP_DROP)
            .push_slice(&delayed_payment_key.serialize())
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// `to_remote`: P2WPKH to the countersignatory's payment basepoint
    /// (static remotekey — the modern, mandatory derivation).
    pub fn to_remote(countersignatory_payment_basepoint: &PublicKey) -> Script {
        Script::new_p2wpkh_from_pubkey(&countersignatory_payment_basepoint.serialize())
    }

    fn revocation_pubkey_hash160(revocation_key: &PublicKey) -> [u8; 20] {
        Ripemd160::digest(&Sha256::digest(&revocation_key.serialize()))
    }

    fn payment_hash_ripemd(payment_hash: &PaymentHash) -> [u8; 20] {
        Ripemd160::digest(&payment_hash.0)
    }

    /// Offered (from the broadcaster) HTLC witness script, non-anchor.
    pub fn offered_htlc(keys: &TxCreationKeys, payment_hash: &PaymentHash) -> Script {
        ScriptBuilder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocation_pubkey_hash160(&keys.revocation_key))
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_slice(&keys.countersignatory_htlc_key.serialize())
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_NOTIF)
            .push_opcode(OP_DROP)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_slice(&keys.broadcaster_htlc_key.serialize())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_HASH160)
            .push_slice(&payment_hash_ripemd(payment_hash))
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
    }

    /// Received (by the broadcaster) HTLC witness script, non-anchor.
    pub fn received_htlc(
        keys: &TxCreationKeys,
        payment_hash: &PaymentHash,
        cltv_expiry: u32,
    ) -> Script {
        ScriptBuilder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocation_pubkey_hash160(&keys.revocation_key))
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_slice(&keys.countersignatory_htlc_key.serialize())
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_HASH160)
            .push_slice(&payment_hash_ripemd(payment_hash))
            .push_opcode(OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_slice(&keys.broadcaster_htlc_key.serialize())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_DROP)
            .push_int(cltv_expiry as i64)
            .push_opcode(OP_CHECKLOCKTIMEVERIFY)
            .push_opcode(OP_DROP)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
    }

    pub fn htlc_witness_script(keys: &TxCreationKeys, htlc: &HtlcOutputInCommitment) -> Script {
        if htlc.offered {
            offered_htlc(keys, &htlc.payment_hash)
        } else {
            received_htlc(keys, &htlc.payment_hash, htlc.cltv_expiry)
        }
    }
}

/// Lower 48 bits of `SHA256(opener_payment_basepoint || accepter_payment_basepoint)`.
pub fn commit_number_obscure_factor(
    opener_payment_basepoint: &PublicKey,
    accepter_payment_basepoint: &PublicKey,
) -> u64 {
    let mut h = Sha256::new();
    h.update(&opener_payment_basepoint.serialize());
    h.update(&accepter_payment_basepoint.serialize());
    let d = h.finalize();
    u64::from_be_bytes([0, 0, d[26], d[27], d[28], d[29], d[30], d[31]])
}

pub struct CommitmentTxParams<'a> {
    pub funding_outpoint: OutPoint,
    pub commitment_number: u64,
    pub obscure_factor: u64,
    /// True when the broadcaster opened the channel (and therefore pays fees).
    pub broadcaster_pays_fee: bool,
    pub feerate: FeeRatePerKw,
    pub broadcaster_dust_limit_sat: u64,
    pub to_self_delay: u16,
    pub keys: &'a TxCreationKeys,
    pub countersignatory_payment_basepoint: PublicKey,
    pub to_broadcaster_msat: Msat,
    pub to_countersignatory_msat: Msat,
    pub htlcs: &'a [HtlcOutputInCommitment],
}

#[derive(Debug, Clone)]
pub struct BuiltCommitmentTx {
    pub tx: Transaction,
    pub txid: Txid,
    /// Base fee actually deducted from the funder output (excluding value
    /// recovered from trimmed outputs).
    pub fee_sat: u64,
    /// Parallel to the input `htlcs` slice: the output index each landed
    /// at, or `None` if trimmed.
    pub htlc_output_indices: Vec<Option<u32>>,
    /// `(input_htlc_index, witness_script)` for each untrimmed HTLC, in
    /// commitment-output order — exactly the order `htlc_signatures` must
    /// take in `commitment_signed`.
    pub htlcs_in_output_order: Vec<(usize, Script)>,
    pub to_broadcaster_index: Option<u32>,
    pub to_countersignatory_index: Option<u32>,
}

pub fn build_commitment_tx(p: &CommitmentTxParams) -> BuiltCommitmentTx {
    let obscured = p.commitment_number ^ p.obscure_factor;
    debug_assert!(p.commitment_number < (1 << 48));

    // Sortable staging: (TxOut, cltv_tiebreak, origin)
    enum Origin {
        Broadcaster,
        Countersignatory,
        Htlc(usize, Script),
    }
    let mut staged: Vec<(TxOut, u32, Origin)> = Vec::new();

    let num_untrimmed = p
        .htlcs
        .iter()
        .filter(|h| !htlc_is_trimmed(h, p.feerate, p.broadcaster_dust_limit_sat))
        .count() as u64;
    let base_fee = p
        .feerate
        .fee_for_weight(COMMITMENT_TX_BASE_WEIGHT + COMMITMENT_TX_WEIGHT_PER_HTLC * num_untrimmed);

    let mut to_broadcaster_sat = p.to_broadcaster_msat.to_sat_floor();
    let mut to_countersignatory_sat = p.to_countersignatory_msat.to_sat_floor();
    if p.broadcaster_pays_fee {
        to_broadcaster_sat = to_broadcaster_sat.saturating_sub(base_fee);
    } else {
        to_countersignatory_sat = to_countersignatory_sat.saturating_sub(base_fee);
    }

    if to_broadcaster_sat >= p.broadcaster_dust_limit_sat {
        let script = scripts::revocable_delayed(
            &p.keys.revocation_key,
            p.to_self_delay,
            &p.keys.broadcaster_delayed_payment_key,
        );
        staged.push((
            TxOut { value: to_broadcaster_sat, script_pubkey: Script::new_p2wsh(&script) },
            0,
            Origin::Broadcaster,
        ));
    }
    if to_countersignatory_sat >= p.broadcaster_dust_limit_sat {
        staged.push((
            TxOut {
                value: to_countersignatory_sat,
                script_pubkey: scripts::to_remote(&p.countersignatory_payment_basepoint),
            },
            0,
            Origin::Countersignatory,
        ));
    }
    for (i, htlc) in p.htlcs.iter().enumerate() {
        if htlc_is_trimmed(htlc, p.feerate, p.broadcaster_dust_limit_sat) {
            continue;
        }
        let script = scripts::htlc_witness_script(p.keys, htlc);
        staged.push((
            TxOut {
                value: htlc.amount_msat.to_sat_floor(),
                script_pubkey: Script::new_p2wsh(&script),
            },
            htlc.cltv_expiry,
            Origin::Htlc(i, script),
        ));
    }

    // BOLT 3 output ordering: value, then scriptpubkey (memcmp; shorter
    // first on common prefix — Rust slice ordering), then cltv_expiry.
    staged.sort_by(|a, b| {
        a.0.value
            .cmp(&b.0.value)
            .then_with(|| a.0.script_pubkey.0.cmp(&b.0.script_pubkey.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut htlc_output_indices = vec![None; p.htlcs.len()];
    let mut htlcs_in_output_order = Vec::new();
    let mut to_broadcaster_index = None;
    let mut to_countersignatory_index = None;
    let mut outputs = Vec::with_capacity(staged.len());
    for (vout, (txout, _, origin)) in staged.into_iter().enumerate() {
        match origin {
            Origin::Broadcaster => to_broadcaster_index = Some(vout as u32),
            Origin::Countersignatory => to_countersignatory_index = Some(vout as u32),
            Origin::Htlc(i, script) => {
                htlc_output_indices[i] = Some(vout as u32);
                htlcs_in_output_order.push((i, script));
            }
        }
        outputs.push(txout);
    }

    let tx = Transaction {
        version: 2,
        lock_time: 0x2000_0000 | (obscured & 0xff_ffff) as u32,
        input: vec![TxIn {
            previous_output: p.funding_outpoint,
            script_sig: vec![],
            sequence: 0x8000_0000 | ((obscured >> 24) & 0xff_ffff) as u32,
            witness: vec![],
        }],
        output: outputs,
    };
    let txid = tx.txid();

    BuiltCommitmentTx {
        tx,
        txid,
        fee_sat: base_fee,
        htlc_output_indices,
        htlcs_in_output_order,
        to_broadcaster_index,
        to_countersignatory_index,
    }
}

/// Build the (unsigned) second-stage HTLC transaction for an HTLC output
/// of a commitment transaction broadcast by the holder of `keys`.
pub fn build_htlc_tx(
    commitment_txid: &Txid,
    htlc_output_index: u32,
    htlc: &HtlcOutputInCommitment,
    keys: &TxCreationKeys,
    to_self_delay: u16,
    feerate: FeeRatePerKw,
) -> Transaction {
    let fee = if htlc.offered { htlc_timeout_fee(feerate) } else { htlc_success_fee(feerate) };
    let output_script = scripts::revocable_delayed(
        &keys.revocation_key,
        to_self_delay,
        &keys.broadcaster_delayed_payment_key,
    );
    Transaction {
        version: 2,
        lock_time: if htlc.offered { htlc.cltv_expiry } else { 0 },
        input: vec![TxIn {
            previous_output: OutPoint::new(*commitment_txid, htlc_output_index),
            script_sig: vec![],
            sequence: 0,
            witness: vec![],
        }],
        output: vec![TxOut {
            value: htlc.amount_msat.to_sat_floor().saturating_sub(fee),
            script_pubkey: Script::new_p2wsh(&output_script),
        }],
    }
}

fn sig_with_sighash_all(sig: &Signature) -> Vec<u8> {
    let mut v = sig.serialize_der().to_vec();
    v.push(0x01); // SIGHASH_ALL
    v
}

/// Witness for spending the funding output: `0 <sig1> <sig2> <redeemscript>`
/// with signatures ordered by funding-pubkey sort order.
pub fn funding_spend_witness(
    holder_funding_pubkey: &PublicKey,
    counterparty_funding_pubkey: &PublicKey,
    holder_sig: &Signature,
    counterparty_sig: &Signature,
) -> Witness {
    let redeem = scripts::funding_redeemscript(holder_funding_pubkey, counterparty_funding_pubkey);
    let (first, second) =
        if holder_funding_pubkey.serialize() <= counterparty_funding_pubkey.serialize() {
            (holder_sig, counterparty_sig)
        } else {
            (counterparty_sig, holder_sig)
        };
    vec![
        vec![],
        sig_with_sighash_all(first),
        sig_with_sighash_all(second),
        redeem.0,
    ]
}

/// Witness for a second-stage HTLC tx input:
/// `0 <remotehtlcsig> <localhtlcsig> <payment_preimage|<>> <witness_script>`
pub fn htlc_tx_witness(
    countersignatory_sig: &Signature,
    holder_sig: &Signature,
    preimage: Option<&PaymentPreimage>,
    witness_script: &Script,
) -> Witness {
    vec![
        vec![],
        sig_with_sighash_all(countersignatory_sig),
        sig_with_sighash_all(holder_sig),
        preimage.map(|p| p.0.to_vec()).unwrap_or_default(),
        witness_script.0.clone(),
    ]
}

/// The legacy (BOLT 2 `closing_signed`) cooperative-close transaction.
/// Amounts must already have the fee deducted from the funder side; outputs
/// below `dust_limit_sat` are dropped.
pub fn build_closing_tx(
    funding_outpoint: OutPoint,
    to_holder_sat: u64,
    to_counterparty_sat: u64,
    holder_script: &Script,
    counterparty_script: &Script,
    dust_limit_sat: u64,
) -> Transaction {
    let mut outputs: Vec<TxOut> = Vec::new();
    if to_holder_sat >= dust_limit_sat {
        outputs.push(TxOut { value: to_holder_sat, script_pubkey: holder_script.clone() });
    }
    if to_counterparty_sat >= dust_limit_sat {
        outputs
            .push(TxOut { value: to_counterparty_sat, script_pubkey: counterparty_script.clone() });
    }
    outputs.sort_by(|a, b| {
        a.value.cmp(&b.value).then_with(|| a.script_pubkey.0.cmp(&b.script_pubkey.0))
    });
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        output: outputs,
    }
}

#[cfg(test)]
mod tests;
