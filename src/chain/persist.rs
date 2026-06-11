//! Monitor persistence.
//!
//! The [`ChannelMonitor`] is the state that MUST survive a crash: revocation
//! secrets, the latest signed commitments, and learned preimages. Lose it
//! and a malicious peer can broadcast an old commitment unpunished; keep it
//! and even a node that lost everything else can claim its funds.
//!
//! Encoding: one version byte, then fixed-order fields using the same
//! primitives as the wire/consensus layers. Forward compatibility comes
//! from the version byte — old software refuses newer blobs rather than
//! misreading them (this is money; guessing is worse than stopping).

use super::monitor::{ChannelMonitor, CounterpartyCommitmentData};
use crate::bitcoin::encode::{DecodeError, Reader};
use crate::bitcoin::{OutPoint, Script, Transaction, Txid};
use crate::channel::HolderCommitment;
use crate::commitment::{BuiltCommitmentTx, HtlcOutputInCommitment};
use crate::keys::{ChannelPublicKeys, TxCreationKeys};
use crate::shachain::SecretStore;
use crate::types::*;
use secp256k1::ecdsa::Signature;
use secp256k1::PublicKey;
use std::collections::HashMap;

const VERSION: u8 = 1;

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn pubkey(&mut self, pk: &PublicKey) {
        self.bytes(&pk.serialize());
    }
    fn sig(&mut self, s: &Signature) {
        self.bytes(&s.serialize_compact());
    }
    fn opt<T>(&mut self, v: &Option<T>, f: impl FnOnce(&mut Self, &T)) {
        match v {
            None => self.u8(0),
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
        }
    }
    fn var_bytes(&mut self, b: &[u8]) {
        self.u16(b.len() as u16);
        self.bytes(b);
    }
}

struct R<'a>(Reader<'a>);

impl<'a> R<'a> {
    fn u8(&mut self) -> Result<u8, DecodeError> {
        self.0.u8()
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.0.array()?))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.0.array()?))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.0.array()?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.0.array()
    }
    fn pubkey(&mut self) -> Result<PublicKey, DecodeError> {
        PublicKey::from_slice(&self.array::<33>()?)
            .map_err(|_| DecodeError::BadFormat("invalid public key"))
    }
    fn sig(&mut self) -> Result<Signature, DecodeError> {
        Signature::from_compact(&self.array::<64>()?)
            .map_err(|_| DecodeError::BadFormat("invalid signature"))
    }
    fn opt<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            _ => Err(DecodeError::BadFormat("invalid option tag")),
        }
    }
    fn var_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u16()? as usize;
        Ok(self.0.take(len)?.to_vec())
    }
}

fn write_pubkeys(w: &mut W, pk: &ChannelPublicKeys) {
    w.pubkey(&pk.funding_pubkey);
    w.pubkey(&pk.revocation_basepoint);
    w.pubkey(&pk.payment_basepoint);
    w.pubkey(&pk.delayed_payment_basepoint);
    w.pubkey(&pk.htlc_basepoint);
}

fn read_pubkeys(r: &mut R) -> Result<ChannelPublicKeys, DecodeError> {
    Ok(ChannelPublicKeys {
        funding_pubkey: r.pubkey()?,
        revocation_basepoint: r.pubkey()?,
        payment_basepoint: r.pubkey()?,
        delayed_payment_basepoint: r.pubkey()?,
        htlc_basepoint: r.pubkey()?,
    })
}

fn write_htlc(w: &mut W, h: &HtlcOutputInCommitment) {
    w.u8(h.offered as u8);
    w.u64(h.amount_msat.0);
    w.u32(h.cltv_expiry);
    w.bytes(&h.payment_hash.0);
}

fn read_htlc(r: &mut R) -> Result<HtlcOutputInCommitment, DecodeError> {
    Ok(HtlcOutputInCommitment {
        offered: r.u8()? == 1,
        amount_msat: Msat(r.u64()?),
        cltv_expiry: r.u32()?,
        payment_hash: PaymentHash(r.array()?),
    })
}

impl ChannelMonitor {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(1024));
        w.u8(VERSION);
        w.bytes(&self.funding_outpoint.txid.0);
        w.u32(self.funding_outpoint.vout);
        w.u64(self.capacity_sat);
        w.u64(self.obscure_factor);
        write_pubkeys(&mut w, &self.holder_pubkeys);
        write_pubkeys(&mut w, &self.counterparty_pubkeys);
        w.u16(self.holder_selected_delay);
        w.u16(self.counterparty_selected_delay);

        let secrets = self.counterparty_secrets.entries();
        w.u16(secrets.len() as u16);
        for (index, secret) in secrets {
            w.u64(index);
            w.bytes(&secret);
        }

        w.opt(&self.counterparty_current, |w, cp| {
            w.u64(cp.number);
            w.bytes(&cp.txid.0);
            w.pubkey(&cp.per_commitment_point);
            w.u16(cp.htlcs.len() as u16);
            for (htlc, vout) in &cp.htlcs {
                write_htlc(w, htlc);
                w.opt(vout, |w, v| w.u32(*v));
            }
        });

        w.opt(&self.holder_commitment, |w, hc| {
            w.u64(hc.number);
            let tx_bytes = hc.built.tx.serialize();
            w.u16(tx_bytes.len() as u16);
            w.bytes(&tx_bytes);
            w.u64(hc.built.fee_sat);
            w.u16(hc.built.htlc_output_indices.len() as u16);
            for idx in &hc.built.htlc_output_indices {
                w.opt(idx, |w, v| w.u32(*v));
            }
            w.u16(hc.built.htlcs_in_output_order.len() as u16);
            for (htlc_idx, script) in &hc.built.htlcs_in_output_order {
                w.u16(*htlc_idx as u16);
                w.var_bytes(&script.0);
            }
            w.opt(&hc.built.to_broadcaster_index, |w, v| w.u32(*v));
            w.opt(&hc.built.to_countersignatory_index, |w, v| w.u32(*v));
            w.sig(&hc.counterparty_sig);
            w.u16(hc.counterparty_htlc_sigs.len() as u16);
            for s in &hc.counterparty_htlc_sigs {
                w.sig(s);
            }
            w.u16(hc.htlcs.len() as u16);
            for h in &hc.htlcs {
                write_htlc(w, h);
            }
            w.pubkey(&hc.keys.per_commitment_point);
            w.pubkey(&hc.keys.revocation_key);
            w.pubkey(&hc.keys.broadcaster_htlc_key);
            w.pubkey(&hc.keys.countersignatory_htlc_key);
            w.pubkey(&hc.keys.broadcaster_delayed_payment_key);
            w.u32(hc.feerate.0);
        });

        w.u32(self.holder_commitment_feerate.0);
        w.u16(self.preimages.len() as u16);
        for preimage in self.preimages.values() {
            w.bytes(&preimage.0);
        }
        w.0
    }

    pub fn deserialize(data: &[u8]) -> Result<ChannelMonitor, DecodeError> {
        let mut r = R(Reader::new(data));
        let version = r.u8()?;
        if version != VERSION {
            return Err(DecodeError::BadFormat("unknown monitor version"));
        }
        let funding_outpoint = OutPoint::new(Txid(r.array()?), r.u32()?);
        let capacity_sat = r.u64()?;
        let obscure_factor = r.u64()?;
        let holder_pubkeys = read_pubkeys(&mut r)?;
        let counterparty_pubkeys = read_pubkeys(&mut r)?;
        let holder_selected_delay = r.u16()?;
        let counterparty_selected_delay = r.u16()?;

        let n = r.u16()?;
        let mut entries = Vec::with_capacity(n as usize);
        for _ in 0..n {
            entries.push((r.u64()?, r.array()?));
        }
        let counterparty_secrets = SecretStore::from_entries(&entries);

        let counterparty_current = r.opt(|r| {
            let number = r.u64()?;
            let txid = Txid(r.array()?);
            let per_commitment_point = r.pubkey()?;
            let n = r.u16()?;
            let mut htlcs = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let h = read_htlc(r)?;
                let vout = r.opt(|r| r.u32())?;
                htlcs.push((h, vout));
            }
            Ok(CounterpartyCommitmentData { number, txid, per_commitment_point, htlcs })
        })?;

        let holder_commitment = r.opt(|r| {
            let number = r.u64()?;
            let tx_len = r.u16()? as usize;
            let tx = Transaction::deserialize(r.0.take(tx_len)?)
                .map_err(|_| DecodeError::BadFormat("invalid holder commitment tx"))?;
            let txid = tx.txid();
            let fee_sat = r.u64()?;
            let n = r.u16()?;
            let mut htlc_output_indices = Vec::with_capacity(n as usize);
            for _ in 0..n {
                htlc_output_indices.push(r.opt(|r| r.u32())?);
            }
            let n = r.u16()?;
            let mut htlcs_in_output_order = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let idx = r.u16()? as usize;
                let script = Script::new(r.var_bytes()?);
                htlcs_in_output_order.push((idx, script));
            }
            let to_broadcaster_index = r.opt(|r| r.u32())?;
            let to_countersignatory_index = r.opt(|r| r.u32())?;
            let counterparty_sig = r.sig()?;
            let n = r.u16()?;
            let mut counterparty_htlc_sigs = Vec::with_capacity(n as usize);
            for _ in 0..n {
                counterparty_htlc_sigs.push(r.sig()?);
            }
            let n = r.u16()?;
            let mut htlcs = Vec::with_capacity(n as usize);
            for _ in 0..n {
                htlcs.push(read_htlc(r)?);
            }
            let keys = TxCreationKeys {
                per_commitment_point: r.pubkey()?,
                revocation_key: r.pubkey()?,
                broadcaster_htlc_key: r.pubkey()?,
                countersignatory_htlc_key: r.pubkey()?,
                broadcaster_delayed_payment_key: r.pubkey()?,
            };
            let feerate = FeeRatePerKw(r.u32()?);
            Ok(HolderCommitment {
                number,
                built: BuiltCommitmentTx {
                    tx,
                    txid,
                    fee_sat,
                    htlc_output_indices,
                    htlcs_in_output_order,
                    to_broadcaster_index,
                    to_countersignatory_index,
                },
                counterparty_sig,
                counterparty_htlc_sigs,
                htlcs,
                keys,
                feerate,
            })
        })?;

        let holder_commitment_feerate = FeeRatePerKw(r.u32()?);
        let n = r.u16()?;
        let mut preimages = HashMap::with_capacity(n as usize);
        for _ in 0..n {
            let p = PaymentPreimage(r.array()?);
            preimages.insert(p.payment_hash(), p);
        }
        if !r.0.is_empty() {
            return Err(DecodeError::BadFormat("trailing bytes in monitor"));
        }

        Ok(ChannelMonitor {
            funding_outpoint,
            capacity_sat,
            obscure_factor,
            holder_pubkeys,
            counterparty_pubkeys,
            holder_selected_delay,
            counterparty_selected_delay,
            counterparty_secrets,
            counterparty_current,
            holder_commitment,
            holder_commitment_feerate,
            preimages,
        })
    }
}
