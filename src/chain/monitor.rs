//! On-chain enforcement for one channel.
//!
//! Given a confirmed spend of the funding output, classify it and build
//! the transactions that protect our funds:
//!
//! * **Revoked counterparty commitment** → justice transaction sweeping
//!   `to_local` and every HTLC output via the revocation key. This is the
//!   punishment that makes Lightning's whole security model work.
//! * **Their latest commitment** → sweep our static-remotekey `to_remote`
//!   output, claim received HTLCs whose preimage we know.
//! * **Our own commitment** → sweep `to_local` after the CSV delay and
//!   feed the pre-signed second-stage HTLC transactions.

use crate::bitcoin::{
    OutPoint, Script, SighashCache, SighashType, Transaction, TxIn, TxOut, Txid,
};
use crate::channel::{Channel, HolderCommitment};
use crate::commitment::{self, scripts, HtlcOutputInCommitment};
use crate::keys::{self, ChannelPublicKeys, TxCreationKeys};
use crate::shachain::{self, SecretStore};
use crate::sign::ChannelSigner;
use crate::types::*;
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashMap;

/// Everything the monitor needs about the counterparty's current
/// commitment (mirrors `channel::CounterpartyCommitmentInfo`).
#[derive(Debug, Clone)]
pub struct CounterpartyCommitmentData {
    pub number: u64,
    pub txid: Txid,
    pub per_commitment_point: PublicKey,
    pub htlcs: Vec<(HtlcOutputInCommitment, Option<u32>)>,
}

/// Classification of a confirmed funding-output spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingSpend {
    /// The negotiated cooperative close — nothing to do.
    CooperativeClose,
    /// Our own commitment transaction.
    HolderCommitment,
    /// The counterparty's *current* commitment — a legitimate force close.
    CounterpartyCurrent,
    /// A revoked counterparty commitment: punish it.
    CounterpartyRevoked { commitment_number: u64 },
    /// A commitment we cannot identify — likely we lost state.
    UnknownCommitment,
}

/// An action the embedder must take.
#[derive(Debug)]
pub enum MonitorResponse {
    /// Broadcast this. If `valid_after_height` is set, wait for that
    /// height first (CSV/CLTV-gated claims).
    Claim {
        tx: Transaction,
        valid_after_height: Option<u32>,
        what: &'static str,
    },
}

pub struct ChannelMonitor {
    pub funding_outpoint: OutPoint,
    pub capacity_sat: u64,
    pub obscure_factor: u64,
    pub holder_pubkeys: ChannelPublicKeys,
    pub counterparty_pubkeys: ChannelPublicKeys,
    /// CSV delay we chose — applies to *their* to_local outputs.
    pub holder_selected_delay: u16,
    /// CSV delay they chose — applies to *ours*.
    pub counterparty_selected_delay: u16,
    pub counterparty_secrets: SecretStore,
    pub counterparty_current: Option<CounterpartyCommitmentData>,
    pub holder_commitment: Option<HolderCommitment>,
    pub holder_commitment_feerate: FeeRatePerKw,
    /// Preimages learned while forwarding/receiving — claimable on-chain.
    pub preimages: HashMap<PaymentHash, PaymentPreimage>,
}

impl ChannelMonitor {
    /// Snapshot the enforcement state out of a live channel.
    pub fn from_channel<S: ChannelSigner>(channel: &Channel<S>) -> Option<ChannelMonitor> {
        let counterparty = channel.counterparty_pubkeys()?;
        Some(ChannelMonitor {
            funding_outpoint: channel.funding_outpoint()?,
            capacity_sat: channel.capacity_sat(),
            obscure_factor: channel.obscure_factor,
            holder_pubkeys: *channel.signer_pubkeys(),
            counterparty_pubkeys: *counterparty,
            holder_selected_delay: channel.params.holder_selected_delay,
            counterparty_selected_delay: channel.params.counterparty_selected_delay,
            counterparty_secrets: channel.counterparty_secrets.clone(),
            counterparty_current: channel.current_counterparty_commitment.as_ref().map(|c| {
                CounterpartyCommitmentData {
                    number: c.number,
                    txid: c.txid,
                    per_commitment_point: c.per_commitment_point,
                    htlcs: c.htlcs.clone(),
                }
            }),
            holder_commitment: channel.current_holder_commitment.clone(),
            holder_commitment_feerate: channel.feerate_holder,
            preimages: HashMap::new(),
        })
    }

    pub fn add_preimage(&mut self, preimage: PaymentPreimage) {
        self.preimages.insert(preimage.payment_hash(), preimage);
    }

    /// Does this transaction spend our funding output, and if so, what is it?
    pub fn classify(&self, tx: &Transaction) -> Option<FundingSpend> {
        let input = tx.input.iter().find(|i| i.previous_output == self.funding_outpoint)?;
        let txid = tx.txid();

        if let Some(hc) = &self.holder_commitment {
            if hc.built.txid == txid {
                return Some(FundingSpend::HolderCommitment);
            }
        }
        if let Some(cp) = &self.counterparty_current {
            if cp.txid == txid {
                return Some(FundingSpend::CounterpartyCurrent);
            }
        }
        // Commitment transactions are recognizable: locktime upper byte
        // 0x20 and sequence upper byte 0x80 (BOLT 3 obscured-number form).
        let is_commitment_shape =
            tx.lock_time >> 24 == 0x20 && input.sequence >> 24 == 0x80 && tx.version == 2;
        if !is_commitment_shape {
            return Some(FundingSpend::CooperativeClose);
        }
        let obscured = ((input.sequence as u64 & 0xff_ffff) << 24) | (tx.lock_time as u64 & 0xff_ffff);
        let commitment_number = obscured ^ self.obscure_factor;
        if self
            .counterparty_secrets
            .secret_for(shachain::index_for_commitment(commitment_number))
            .is_some()
        {
            return Some(FundingSpend::CounterpartyRevoked { commitment_number });
        }
        Some(FundingSpend::UnknownCommitment)
    }

    /// Full handling of a confirmed funding spend: classification plus the
    /// transactions to broadcast. `destination` receives all swept funds.
    pub fn handle_funding_spend<S: ChannelSigner>(
        &self,
        signer: &S,
        tx: &Transaction,
        destination: &Script,
        feerate: FeeRatePerKw,
        current_height: u32,
    ) -> Option<(FundingSpend, Vec<MonitorResponse>)> {
        let class = self.classify(tx)?;
        let responses = match &class {
            FundingSpend::CooperativeClose => Vec::new(),
            FundingSpend::CounterpartyRevoked { commitment_number } => {
                self.punish_revoked(signer, tx, *commitment_number, destination, feerate)
            }
            FundingSpend::CounterpartyCurrent => {
                self.claim_counterparty_outputs(signer, tx, destination, feerate)
            }
            FundingSpend::HolderCommitment => {
                self.claim_holder_outputs(signer, tx, destination, feerate, current_height)
            }
            FundingSpend::UnknownCommitment => Vec::new(),
        };
        Some((class, responses))
    }

    // ------------------------------------------------------------ justice

    /// Sweep every revocable output of a revoked counterparty commitment.
    fn punish_revoked<S: ChannelSigner>(
        &self,
        signer: &S,
        revoked_tx: &Transaction,
        commitment_number: u64,
        destination: &Script,
        feerate: FeeRatePerKw,
    ) -> Vec<MonitorResponse> {
        let secp = Secp256k1::new();
        let Some(secret) = self
            .counterparty_secrets
            .secret_for(shachain::index_for_commitment(commitment_number))
        else {
            return Vec::new();
        };
        let per_commitment_point = keys::per_commitment_point(&secret);
        // Their commitment: they are the broadcaster.
        let tx_keys = TxCreationKeys::derive(
            &secp,
            &per_commitment_point,
            &self.counterparty_pubkeys,
            &self.holder_pubkeys,
        );

        // Identify revocable outputs by reconstructing their scripts.
        let to_local_script = scripts::revocable_delayed(
            &tx_keys.revocation_key,
            self.holder_selected_delay,
            &tx_keys.broadcaster_delayed_payment_key,
        );
        let to_local_spk = Script::new_p2wsh(&to_local_script);

        struct In {
            vout: u32,
            value: u64,
            witness_script: Script,
            /// Second witness item (revocation key push for HTLC scripts,
            /// `1` for the to_local IF branch).
            control: Vec<u8>,
        }
        let mut inputs: Vec<In> = Vec::new();
        for (vout, out) in revoked_tx.output.iter().enumerate() {
            if out.script_pubkey == to_local_spk {
                inputs.push(In {
                    vout: vout as u32,
                    value: out.value,
                    witness_script: to_local_script.clone(),
                    control: vec![0x01],
                });
            }
        }
        // HTLC outputs: any P2WSH matching one of the known HTLC scripts.
        let mut htlc_scripts: Vec<Script> = Vec::new();
        if let Some(cp) = &self.counterparty_current {
            // The revoked tx may not be the current one; rebuild candidate
            // scripts from its own outputs by trying both directions for
            // every known HTLC.
            let _ = cp;
        }
        // Without stored per-commitment HTLC sets for *old* commitments we
        // reconstruct from the current set (covers the common race where
        // the revoked tx is the immediately-previous commitment).
        if let Some(cp) = &self.counterparty_current {
            for (htlc, _) in &cp.htlcs {
                htlc_scripts.push(scripts::htlc_witness_script(&tx_keys, htlc));
                let flipped = HtlcOutputInCommitment { offered: !htlc.offered, ..*htlc };
                htlc_scripts.push(scripts::htlc_witness_script(&tx_keys, &flipped));
            }
        }
        for script in htlc_scripts {
            let spk = Script::new_p2wsh(&script);
            for (vout, out) in revoked_tx.output.iter().enumerate() {
                if out.script_pubkey == spk {
                    inputs.push(In {
                        vout: vout as u32,
                        value: out.value,
                        witness_script: script.clone(),
                        control: tx_keys.revocation_key.serialize().to_vec(),
                    });
                }
            }
        }
        if inputs.is_empty() {
            return Vec::new();
        }

        let total: u64 = inputs.iter().map(|i| i.value).sum();
        let revoked_txid = revoked_tx.txid();
        let mut justice = Transaction {
            version: 2,
            lock_time: 0,
            input: inputs
                .iter()
                .map(|i| TxIn {
                    previous_output: OutPoint::new(revoked_txid, i.vout),
                    script_sig: vec![],
                    sequence: 0xffff_fffd,
                    witness: vec![],
                })
                .collect(),
            output: vec![TxOut { value: total, script_pubkey: destination.clone() }],
        };
        // Fee: sign once with dummy-size witnesses accounted, round up.
        let est_weight = justice.weight()
            + inputs.iter().map(|i| 80 + i.witness_script.len() as u64 + i.control.len() as u64).sum::<u64>();
        let fee = feerate.fee_for_weight(est_weight) + 1;
        justice.output[0].value = total.saturating_sub(fee);

        let cache = SighashCache::new(&justice);
        let mut witnesses = Vec::with_capacity(inputs.len());
        for (idx, input) in inputs.iter().enumerate() {
            let sighash = cache.segwit_v0_sighash(
                idx,
                &input.witness_script,
                input.value,
                SighashType::All,
            );
            let sig = signer.sign_revocation(&sighash, &secret);
            let mut der = sig.serialize_der().to_vec();
            der.push(0x01);
            witnesses.push(vec![der, input.control.clone(), input.witness_script.0.clone()]);
        }
        for (txin, w) in justice.input.iter_mut().zip(witnesses) {
            txin.witness = w;
        }
        vec![MonitorResponse::Claim {
            tx: justice,
            valid_after_height: None,
            what: "justice (revoked commitment punished)",
        }]
    }

    // ---------------------------------------------- their current commit

    fn claim_counterparty_outputs<S: ChannelSigner>(
        &self,
        signer: &S,
        commitment_tx: &Transaction,
        destination: &Script,
        feerate: FeeRatePerKw,
    ) -> Vec<MonitorResponse> {
        let mut responses = Vec::new();
        let txid = commitment_tx.txid();

        // Our to_remote: static remotekey pays straight to our payment
        // basepoint via P2WPKH.
        let our_spk =
            Script::new_p2wpkh_from_pubkey(&self.holder_pubkeys.payment_basepoint.serialize());
        for (vout, out) in commitment_tx.output.iter().enumerate() {
            if out.script_pubkey == our_spk {
                let mut sweep = Transaction {
                    version: 2,
                    lock_time: 0,
                    input: vec![TxIn {
                        previous_output: OutPoint::new(txid, vout as u32),
                        script_sig: vec![],
                        sequence: 0xffff_fffd,
                        witness: vec![],
                    }],
                    output: vec![TxOut { value: out.value, script_pubkey: destination.clone() }],
                };
                let fee = feerate.fee_for_weight(sweep.weight() + 110) + 1;
                sweep.output[0].value = out.value.saturating_sub(fee);
                let script_code = out.script_pubkey.p2wpkh_script_code().expect("p2wpkh");
                let sighash = SighashCache::new(&sweep).segwit_v0_sighash(
                    0,
                    &script_code,
                    out.value,
                    SighashType::All,
                );
                let sig = signer.sign_payment(&sighash);
                let mut der = sig.serialize_der().to_vec();
                der.push(0x01);
                sweep.input[0].witness =
                    vec![der, self.holder_pubkeys.payment_basepoint.serialize().to_vec()];
                responses.push(MonitorResponse::Claim {
                    tx: sweep,
                    valid_after_height: None,
                    what: "to_remote sweep (their force close)",
                });
            }
        }

        // HTLCs they offered us, where we know the preimage: claim now.
        let Some(cp) = &self.counterparty_current else { return responses };
        let secp = Secp256k1::new();
        let tx_keys = TxCreationKeys::derive(
            &secp,
            &cp.per_commitment_point,
            &self.counterparty_pubkeys,
            &self.holder_pubkeys,
        );
        for (htlc, vout) in &cp.htlcs {
            // `offered` is from their perspective; offered-to-us means we
            // claim with the preimage.
            if !htlc.offered {
                continue;
            }
            let Some(preimage) = self.preimages.get(&htlc.payment_hash) else { continue };
            let Some(vout) = vout else { continue };
            let witness_script = scripts::htlc_witness_script(&tx_keys, htlc);
            let value = htlc.amount_msat.to_sat_floor();
            let mut claim = Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: OutPoint::new(txid, *vout),
                    script_sig: vec![],
                    sequence: 0xffff_fffd,
                    witness: vec![],
                }],
                output: vec![TxOut { value, script_pubkey: destination.clone() }],
            };
            let fee = feerate.fee_for_weight(claim.weight() + 160 + witness_script.len() as u64) + 1;
            claim.output[0].value = value.saturating_sub(fee);
            let sighash = SighashCache::new(&claim).segwit_v0_sighash(
                0,
                &witness_script,
                value,
                SighashType::All,
            );
            let sig = signer.sign_htlc(&sighash, &cp.per_commitment_point);
            let mut der = sig.serialize_der().to_vec();
            der.push(0x01);
            claim.input[0].witness =
                vec![der, preimage.0.to_vec(), witness_script.0.clone()];
            responses.push(MonitorResponse::Claim {
                tx: claim,
                valid_after_height: None,
                what: "preimage claim (their force close)",
            });
        }
        responses
    }

    // ------------------------------------------------- our own commitment

    fn claim_holder_outputs<S: ChannelSigner>(
        &self,
        signer: &S,
        commitment_tx: &Transaction,
        destination: &Script,
        feerate: FeeRatePerKw,
        current_height: u32,
    ) -> Vec<MonitorResponse> {
        let Some(hc) = &self.holder_commitment else { return Vec::new() };
        let mut responses = Vec::new();
        let txid = commitment_tx.txid();

        // Our to_local: spendable after THEIR chosen CSV delay.
        if let Some(vout) = hc.built.to_broadcaster_index {
            let script = scripts::revocable_delayed(
                &hc.keys.revocation_key,
                self.counterparty_selected_delay,
                &hc.keys.broadcaster_delayed_payment_key,
            );
            let value = commitment_tx.output[vout as usize].value;
            let mut sweep = Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: OutPoint::new(txid, vout),
                    script_sig: vec![],
                    sequence: self.counterparty_selected_delay as u32,
                    witness: vec![],
                }],
                output: vec![TxOut { value, script_pubkey: destination.clone() }],
            };
            let fee = feerate.fee_for_weight(sweep.weight() + 120 + script.len() as u64) + 1;
            sweep.output[0].value = value.saturating_sub(fee);
            let sighash = SighashCache::new(&sweep).segwit_v0_sighash(
                0,
                &script,
                value,
                SighashType::All,
            );
            let sig = signer.sign_delayed_payment(&sighash, &hc.keys.per_commitment_point);
            let mut der = sig.serialize_der().to_vec();
            der.push(0x01);
            sweep.input[0].witness = vec![der, vec![], script.0.clone()];
            responses.push(MonitorResponse::Claim {
                tx: sweep,
                valid_after_height: Some(
                    current_height + self.counterparty_selected_delay as u32,
                ),
                what: "to_local sweep after CSV (our force close)",
            });
        }

        // Second-stage HTLC transactions, pre-signed by the counterparty.
        for (sig_idx, (htlc_idx, witness_script)) in
            hc.built.htlcs_in_output_order.iter().enumerate()
        {
            let htlc = &hc.htlcs[*htlc_idx];
            let vout = hc.built.htlc_output_indices[*htlc_idx].expect("untrimmed");
            let preimage = if htlc.offered {
                None // HTLC-timeout: needs the CLTV to pass.
            } else {
                match self.preimages.get(&htlc.payment_hash) {
                    Some(p) => Some(*p),
                    None => continue, // can't claim a received HTLC blind
                }
            };
            let htlc_tx = commitment::build_htlc_tx(
                &txid,
                vout,
                htlc,
                &hc.keys,
                self.counterparty_selected_delay,
                hc.feerate,
            );
            let sighash = SighashCache::new(&htlc_tx).segwit_v0_sighash(
                0,
                witness_script,
                htlc.amount_msat.to_sat_floor(),
                SighashType::All,
            );
            let our_sig = signer.sign_htlc(&sighash, &hc.keys.per_commitment_point);
            let their_sig = match hc.counterparty_htlc_sigs.get(sig_idx) {
                Some(s) => *s,
                None => continue,
            };
            let mut signed = htlc_tx;
            signed.input[0].witness = commitment::htlc_tx_witness(
                &their_sig,
                &our_sig,
                preimage.as_ref(),
                witness_script,
            );
            let gate = if htlc.offered { Some(htlc.cltv_expiry) } else { None };
            responses.push(MonitorResponse::Claim {
                tx: signed,
                valid_after_height: gate,
                what: if htlc.offered {
                    "HTLC-timeout (our force close)"
                } else {
                    "HTLC-success (our force close)"
                },
            });
        }
        responses
    }
}
