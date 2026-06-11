//! Reconnection: `channel_reestablish` exchange, retransmission of lost
//! messages, and rollback of updates that never made it into a signed
//! commitment.

use super::*;
use crate::wire::msgs::Message as WireMessage;

/// What to do after processing the peer's `channel_reestablish`.
#[derive(Debug, Default)]
pub struct ReestablishActions {
    /// Messages to retransmit, in order.
    pub messages: Vec<WireMessage>,
    /// True if the peer proved we lost state (`option_data_loss_protect`):
    /// we MUST NOT broadcast our (stale) commitment, and should wait for
    /// them to force-close.
    pub data_loss_detected: bool,
}

impl<S: ChannelSigner> Channel<S> {
    /// Call when the transport drops. Un-acknowledged updates are rolled
    /// back per BOLT 2 (they were never part of a signed commitment, so on
    /// reconnect both sides forget them). Outbound adds are re-queued in
    /// the holding cell; their un-signed updates are dropped entirely.
    pub fn on_disconnect(&mut self) {
        let in_flight: Vec<(bool, HtlcId)> = self
            .pending_counterparty_commitment
            .as_ref()
            .map(|p| p.included.clone())
            .unwrap_or_default();
        let in_flight_removed: Vec<(bool, HtlcId)> = self
            .pending_counterparty_commitment
            .as_ref()
            .map(|p| p.removed.clone())
            .unwrap_or_default();

        let mut requeue: Vec<HoldingCellOp> = Vec::new();
        self.htlcs.retain_mut(|h| {
            let snapshotted = in_flight.contains(&(h.outbound, h.id));
            match h.phase_counterparty {
                // Our add they never signed for: forget; re-offer later.
                HtlcPhase::Pending if h.outbound && !snapshotted => {
                    requeue.push(HoldingCellOp::Add {
                        amount_msat: h.amount_msat,
                        payment_hash: h.payment_hash,
                        cltv_expiry: h.cltv_expiry,
                        onion: h.onion.clone(),
                        source: h.source.clone().expect("outbound carries source"),
                    });
                    return false;
                }
                // Their add we acked but never entered their commitment:
                // phase regresses; they keep it in ours (it was signed), so
                // only the counterparty side resets.
                HtlcPhase::Pending if !h.outbound && !snapshotted => {
                    h.phase_counterparty = HtlcPhase::NotYet;
                }
                _ => {}
            }
            // Un-signed removals roll back to Committed on the relevant side.
            let removal_snapshotted = in_flight_removed.contains(&(h.outbound, h.id));
            if h.phase_counterparty == HtlcPhase::Removing && !removal_snapshotted {
                if !h.outbound {
                    // Our fulfill/fail: re-queue the operation.
                    match &h.resolution {
                        Some(HtlcResolution::Fulfill(p)) => {
                            requeue.push(HoldingCellOp::Fulfill { id: h.id, preimage: *p })
                        }
                        Some(HtlcResolution::Fail(r)) => {
                            requeue.push(HoldingCellOp::Fail { id: h.id, reason: r.clone() })
                        }
                        _ => {}
                    }
                    h.resolution = None;
                    h.phase_counterparty = HtlcPhase::Committed;
                } else {
                    // Their removal we acked: they will retransmit it.
                    h.resolution = None;
                    h.phase_counterparty = HtlcPhase::Committed;
                    h.phase_holder = HtlcPhase::Committed;
                }
            }
            // Their un-signed adds: they will retransmit after reconnect.
            if !h.outbound && h.phase_holder == HtlcPhase::Pending {
                // Never made it into our commitment.
                let in_our_current = self
                    .current_holder_commitment
                    .as_ref()
                    .map(|hc| {
                        hc.htlcs.iter().any(|x| {
                            !x.offered
                                && x.payment_hash == h.payment_hash
                                && x.amount_msat == h.amount_msat
                                && x.cltv_expiry == h.cltv_expiry
                        })
                    })
                    .unwrap_or(false);
                if !in_our_current {
                    self.next_counterparty_htlc_id = self.next_counterparty_htlc_id.min(h.id.0);
                    return false;
                }
            }
            // Their removals of our HTLCs that never got signed: rolled
            // back; they retransmit.
            if h.outbound && h.phase_holder == HtlcPhase::Removing {
                h.resolution = None;
                h.phase_holder = HtlcPhase::Committed;
            }
            true
        });
        // Re-queued ops go in front of anything already in the cell.
        requeue.extend(std::mem::take(&mut self.holding_cell));
        self.holding_cell = requeue;
        // A fee update they never signed for is forgotten too.
        if self.pending_fee_ack.take().is_some() {
            self.feerate_holder = self.feerate_counterparty;
        }
    }

    pub fn make_channel_reestablish(&self) -> ChannelReestablish {
        let next_revocation_number = self.counterparty_commitment_number;
        let your_last_per_commitment_secret = if next_revocation_number == 0 {
            [0u8; 32]
        } else {
            self.counterparty_secrets
                .secret_for(shachain::index_for_commitment(next_revocation_number - 1))
                .unwrap_or([0u8; 32])
        };
        ChannelReestablish {
            channel_id: self.channel_id,
            next_commitment_number: self.holder_commitment_number + 1,
            next_revocation_number,
            your_last_per_commitment_secret,
            my_current_per_commitment_point: self
                .signer
                .per_commitment_point(self.holder_commitment_number),
        }
    }

    pub fn on_channel_reestablish(
        &mut self,
        msg: &ChannelReestablish,
    ) -> Result<ReestablishActions, ChannelError> {
        let mut actions = ReestablishActions::default();

        // --- Their view of our revocations -----------------------------
        // next_revocation_number = the next RAA they expect from us, i.e.
        // the commitment of ours they expect us to revoke next.
        let our_next_revocation = self.holder_commitment_number;
        if msg.next_revocation_number == our_next_revocation.saturating_sub(1)
            && self.holder_commitment_number > 0
        {
            // They lost our last revoke_and_ack: retransmit it.
            let revoked = self.holder_commitment_number - 1;
            actions.messages.push(WireMessage::RevokeAndAck(RevokeAndAck {
                channel_id: self.channel_id,
                per_commitment_secret: self.signer.release_commitment_secret(revoked),
                next_per_commitment_point: self
                    .signer
                    .per_commitment_point(self.holder_commitment_number + 1),
            }));
        } else if msg.next_revocation_number > our_next_revocation {
            // They have revocations we never made: we lost state.
            actions.data_loss_detected = true;
            return Ok(actions);
        } else if msg.next_revocation_number != our_next_revocation {
            return close_err("peer requests an ancient revocation; unrecoverable");
        }

        // Validate their proof of our last released secret.
        if msg.next_revocation_number > 0 {
            let expected = self.signer.release_commitment_secret(msg.next_revocation_number - 1);
            if msg.your_last_per_commitment_secret != expected {
                return close_err("peer presented incorrect last per-commitment secret");
            }
        } else if msg.your_last_per_commitment_secret != [0u8; 32] {
            return close_err("peer presented a secret before any revocation");
        }

        // --- Their view of our commitment_signed -----------------------
        // next_commitment_number = the next CS they expect to receive.
        let our_last_sent = self.counterparty_commitment_number
            + if self.awaiting_raa { 1 } else { 0 };
        if msg.next_commitment_number == our_last_sent && self.awaiting_raa {
            // They never received our in-flight commitment: retransmit the
            // updates it covered, then the commitment_signed itself.
            let pending = self
                .pending_counterparty_commitment
                .as_ref()
                .expect("awaiting_raa implies pending");
            let mut adds: Vec<&Htlc> = Vec::new();
            let mut removals: Vec<&Htlc> = Vec::new();
            for (outbound, id) in &pending.included {
                if *outbound {
                    if let Some(h) =
                        self.htlcs.iter().find(|h| h.outbound == *outbound && h.id == *id)
                    {
                        adds.push(h);
                    }
                }
            }
            for (outbound, id) in &pending.removed {
                if !*outbound {
                    if let Some(h) =
                        self.htlcs.iter().find(|h| h.outbound == *outbound && h.id == *id)
                    {
                        removals.push(h);
                    }
                }
            }
            adds.sort_by_key(|h| h.id.0);
            for h in adds {
                actions.messages.push(WireMessage::UpdateAddHtlc(UpdateAddHtlc {
                    channel_id: self.channel_id,
                    id: h.id.0,
                    amount_msat: h.amount_msat,
                    payment_hash: h.payment_hash,
                    cltv_expiry: h.cltv_expiry,
                    onion_routing_packet: h.onion.clone(),
                }));
            }
            for h in removals {
                match &h.resolution {
                    Some(HtlcResolution::Fulfill(p)) => {
                        actions.messages.push(WireMessage::UpdateFulfillHtlc(UpdateFulfillHtlc {
                            channel_id: self.channel_id,
                            id: h.id.0,
                            payment_preimage: *p,
                        }))
                    }
                    Some(HtlcResolution::Fail(r)) => {
                        actions.messages.push(WireMessage::UpdateFailHtlc(UpdateFailHtlc {
                            channel_id: self.channel_id,
                            id: h.id.0,
                            reason: r.clone(),
                        }))
                    }
                    Some(HtlcResolution::FailMalformed(sha, code)) => actions.messages.push(
                        WireMessage::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc {
                            channel_id: self.channel_id,
                            id: h.id.0,
                            sha256_of_onion: *sha,
                            failure_code: *code,
                        }),
                    ),
                    None => {}
                }
            }
            if let Some(fee) = pending.fee_update {
                actions.messages.push(WireMessage::UpdateFee(UpdateFee {
                    channel_id: self.channel_id,
                    feerate_per_kw: fee.0,
                }));
            }
            // Re-sign: the commitment is deterministic, so this reproduces
            // the lost message bit-for-bit.
            let number = self.counterparty_commitment_number + 1;
            let point = self
                .counterparty_next_point
                .ok_or(ChannelError::InvalidState("missing next point on reestablish"))?;
            let (built, keys, htlcs) = self.build_counterparty_commitment_at(number, point)?;
            let signature = self.sign_counterparty_commitment_tx(&built)?;
            let mut htlc_signatures = Vec::new();
            for (htlc_idx, witness_script) in &built.htlcs_in_output_order {
                let htlc = &htlcs[*htlc_idx];
                let vout = built.htlc_output_indices[*htlc_idx].expect("untrimmed");
                let htlc_tx = crate::commitment::build_htlc_tx(
                    &built.txid,
                    vout,
                    htlc,
                    &keys,
                    self.params.holder_selected_delay,
                    self.feerate_counterparty,
                );
                let sighash = SighashCache::new(&htlc_tx).segwit_v0_sighash(
                    0,
                    witness_script,
                    htlc.amount_msat.to_sat_floor(),
                    SighashType::All,
                );
                htlc_signatures.push(self.signer.sign_htlc(&sighash, &point));
            }
            actions.messages.push(WireMessage::CommitmentSigned(CommitmentSigned {
                channel_id: self.channel_id,
                signature,
                htlc_signatures,
            }));
        } else if msg.next_commitment_number == our_last_sent + 1 {
            // In sync (they have everything we sent).
        } else if msg.next_commitment_number > our_last_sent + 1 {
            actions.data_loss_detected = true;
            return Ok(actions);
        } else {
            return close_err("peer expects an ancient commitment; unrecoverable");
        }

        // Funding-locked retransmission: a fresh channel with no commitment
        // exchange yet.
        if msg.next_commitment_number == 1
            && self.holder_commitment_number == 0
            && self.channel_ready_sent
        {
            actions.messages.insert(
                0,
                WireMessage::ChannelReady(ChannelReady {
                    channel_id: self.channel_id,
                    second_per_commitment_point: self.signer.per_commitment_point(1),
                    short_channel_id_alias: None,
                }),
            );
        }
        Ok(actions)
    }
}
