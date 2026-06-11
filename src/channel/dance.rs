//! The commitment dance: `update_add_htlc` / `update_fulfill_htlc` /
//! `update_fail_htlc` / `update_fee`, `commitment_signed`, and
//! `revoke_and_ack`.
//!
//! Phase discipline (see [`super::HtlcPhase`]): an update mutates the
//! *counterparty* phase when we send it and the *holder* phase when we
//! receive it; the opposite phase changes only at the revocation that
//! acknowledges it. Updates issued while a `commitment_signed` of ours is
//! in flight wait in the holding cell and are flushed by the peer's
//! `revoke_and_ack`.

use super::*;
use crate::commitment::build_htlc_tx;
use crate::wire::msgs::Message as WireMessage;

/// How an HTLC was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtlcResolution {
    Fulfill(PaymentPreimage),
    /// Encrypted error onion to relay backwards.
    Fail(Vec<u8>),
    /// BADONION: sha256 of the onion plus the failure code.
    FailMalformed([u8; 32], u16),
}

/// An inbound HTLC that is now irrevocably committed on both commitment
/// transactions — safe for the node layer to claim or forward.
#[derive(Debug, Clone)]
pub struct CommittedInboundHtlc {
    pub id: HtlcId,
    pub amount_msat: Msat,
    pub payment_hash: PaymentHash,
    pub cltv_expiry: u32,
    pub onion: Vec<u8>,
}

/// Everything a `revoke_and_ack` triggered.
#[derive(Debug, Default)]
pub struct RaaOutcome {
    /// Update messages re-issued from the holding cell.
    pub messages: Vec<WireMessage>,
    /// The `commitment_signed` covering them, if any were flushed.
    pub commitment_signed: Option<CommitmentSigned>,
    /// Inbound HTLCs that just became safe to forward/claim.
    pub forwardable: Vec<CommittedInboundHtlc>,
    /// Holding-cell adds that no longer fit (caller must fail them
    /// upstream/locally).
    pub failed_adds: Vec<(HtlcSource, &'static str)>,
}

impl<S: ChannelSigner> Channel<S> {
    // ----------------------------------------------------- sending updates

    /// Offer an HTLC. Returns `Ok(None)` if parked in the holding cell.
    pub fn send_add_htlc(
        &mut self,
        amount_msat: Msat,
        payment_hash: PaymentHash,
        cltv_expiry: u32,
        onion: Vec<u8>,
        source: HtlcSource,
    ) -> Result<Option<UpdateAddHtlc>, ChannelError> {
        if self.state != ChannelState::Normal {
            return Err(ChannelError::Ignore("channel not in normal state".into()));
        }
        if self.shutdown_sent || self.shutdown_received {
            return Err(ChannelError::Ignore("channel is shutting down".into()));
        }
        if self.awaiting_raa {
            self.holding_cell.push(HoldingCellOp::Add {
                amount_msat,
                payment_hash,
                cltv_expiry,
                onion,
                source,
            });
            return Ok(None);
        }
        self.validate_outbound_add(amount_msat, cltv_expiry)?;

        let id = HtlcId(self.next_holder_htlc_id);
        self.next_holder_htlc_id += 1;
        self.htlcs.push(Htlc {
            outbound: true,
            id,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion: onion.clone(),
            source: Some(source),
            resolution: None,
            phase_holder: HtlcPhase::NotYet,
            phase_counterparty: HtlcPhase::Pending,
            processed: false,
        });
        self.counterparty_dirty = true;
        Ok(Some(UpdateAddHtlc {
            channel_id: self.channel_id,
            id: id.0,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion_routing_packet: onion,
        }))
    }

    fn validate_outbound_add(
        &self,
        amount_msat: Msat,
        cltv_expiry: u32,
    ) -> Result<(), ChannelError> {
        if amount_msat == Msat::ZERO {
            return Err(ChannelError::Ignore("zero-amount HTLC".into()));
        }
        if amount_msat < self.params.counterparty_htlc_minimum_msat {
            return Err(ChannelError::Ignore("below counterparty htlc_minimum".into()));
        }
        if cltv_expiry >= 500_000_000 {
            return Err(ChannelError::Ignore("cltv_expiry too large".into()));
        }
        let live_outbound: Vec<&Htlc> = self
            .htlcs
            .iter()
            .filter(|h| h.outbound && h.resolution.is_none())
            .collect();
        if live_outbound.len() as u16 >= self.params.counterparty_max_accepted_htlcs {
            return Err(ChannelError::Ignore("counterparty max_accepted_htlcs reached".into()));
        }
        let in_flight: Msat =
            live_outbound.iter().map(|h| h.amount_msat).sum::<Msat>() + amount_msat;
        if in_flight > self.params.counterparty_max_htlc_value_in_flight_msat {
            return Err(ChannelError::Ignore(
                "counterparty max_htlc_value_in_flight exceeded".into(),
            ));
        }
        // Affordability on their commitment (where the add lands first):
        // our balance after the add must cover the reserve they chose for
        // us, plus commitment fees if we're the opener.
        let (to_holder, _) = self.balances_for(false);
        let mut needed = amount_msat
            + Msat::from_sat(self.params.counterparty_selected_reserve_sat);
        if self.role == ChannelRole::Opener {
            let untrimmed = self
                .htlcs
                .iter()
                .filter(|h| h.phase_counterparty.included())
                .count() as u64;
            // One extra HTLC of headroom guards against a fee-spike dance
            // deadlock (the spec's "fee spike buffer" advice).
            let fee = self.feerate_counterparty.fee_for_weight(
                commitment::COMMITMENT_TX_BASE_WEIGHT
                    + commitment::COMMITMENT_TX_WEIGHT_PER_HTLC * (untrimmed + 2),
            );
            needed = needed + Msat::from_sat(fee);
        }
        if to_holder < needed {
            return Err(ChannelError::Ignore("insufficient balance for HTLC".into()));
        }
        Ok(())
    }

    /// Fulfill an inbound HTLC (we know the preimage).
    pub fn send_fulfill_htlc(
        &mut self,
        id: HtlcId,
        preimage: PaymentPreimage,
    ) -> Result<Option<UpdateFulfillHtlc>, ChannelError> {
        if self.awaiting_raa {
            self.holding_cell.push(HoldingCellOp::Fulfill { id, preimage });
            return Ok(None);
        }
        let channel_id = self.channel_id;
        let htlc = self.inbound_committed_mut(id)?;
        if preimage.payment_hash() != htlc.payment_hash {
            return Err(ChannelError::InvalidState("preimage does not match payment hash"));
        }
        htlc.resolution = Some(HtlcResolution::Fulfill(preimage));
        htlc.phase_counterparty = HtlcPhase::Removing;
        self.counterparty_dirty = true;
        Ok(Some(UpdateFulfillHtlc { channel_id, id: id.0, payment_preimage: preimage }))
    }

    /// Fail an inbound HTLC with an encrypted error onion.
    pub fn send_fail_htlc(
        &mut self,
        id: HtlcId,
        reason: Vec<u8>,
    ) -> Result<Option<UpdateFailHtlc>, ChannelError> {
        if self.awaiting_raa {
            self.holding_cell.push(HoldingCellOp::Fail { id, reason });
            return Ok(None);
        }
        let channel_id = self.channel_id;
        let htlc = self.inbound_committed_mut(id)?;
        htlc.resolution = Some(HtlcResolution::Fail(reason.clone()));
        htlc.phase_counterparty = HtlcPhase::Removing;
        self.counterparty_dirty = true;
        Ok(Some(UpdateFailHtlc { channel_id, id: id.0, reason }))
    }

    /// Fail an inbound HTLC whose onion we could not even decrypt
    /// (no shared secret → no error onion; the peer builds one for us).
    pub fn send_fail_malformed_htlc(
        &mut self,
        id: HtlcId,
        sha256_of_onion: [u8; 32],
        failure_code: u16,
    ) -> Result<Option<UpdateFailMalformedHtlc>, ChannelError> {
        if self.awaiting_raa {
            self.holding_cell
                .push(HoldingCellOp::FailMalformed { id, sha256_of_onion, failure_code });
            return Ok(None);
        }
        let channel_id = self.channel_id;
        let htlc = self.inbound_committed_mut(id)?;
        htlc.resolution = Some(HtlcResolution::FailMalformed(sha256_of_onion, failure_code));
        htlc.phase_counterparty = HtlcPhase::Removing;
        self.counterparty_dirty = true;
        Ok(Some(UpdateFailMalformedHtlc {
            channel_id,
            id: id.0,
            sha256_of_onion,
            failure_code,
        }))
    }

    fn inbound_committed_mut(&mut self, id: HtlcId) -> Result<&mut Htlc, ChannelError> {
        let htlc = self
            .htlcs
            .iter_mut()
            .find(|h| !h.outbound && h.id == id)
            .ok_or(ChannelError::InvalidState("unknown inbound HTLC id"))?;
        if htlc.resolution.is_some() {
            return Err(ChannelError::InvalidState("HTLC already resolved"));
        }
        if htlc.phase_holder != HtlcPhase::Committed
            || htlc.phase_counterparty != HtlcPhase::Committed
        {
            return Err(ChannelError::InvalidState("HTLC not irrevocably committed"));
        }
        Ok(htlc)
    }

    /// Opener only: change the commitment feerate.
    pub fn send_update_fee(
        &mut self,
        feerate: FeeRatePerKw,
    ) -> Result<Option<UpdateFee>, ChannelError> {
        if self.role != ChannelRole::Opener {
            return Err(ChannelError::InvalidState("only the opener sends update_fee"));
        }
        if self.state != ChannelState::Normal {
            return Err(ChannelError::Ignore("channel not in normal state".into()));
        }
        if self.awaiting_raa {
            // Rare enough that we simply refuse rather than holding-cell it.
            return Err(ChannelError::Ignore("commitment in flight; retry after RAA".into()));
        }
        if feerate.0 < 253 {
            return Err(ChannelError::Ignore("feerate below floor".into()));
        }
        self.feerate_counterparty = feerate;
        self.counterparty_dirty = true;
        Ok(Some(UpdateFee { channel_id: self.channel_id, feerate_per_kw: feerate.0 }))
    }

    // --------------------------------------------------- receiving updates

    pub fn on_update_add_htlc(&mut self, msg: &UpdateAddHtlc) -> Result<(), ChannelError> {
        if self.state != ChannelState::Normal {
            return close_err("update_add_htlc outside normal operation");
        }
        if self.shutdown_sent || self.shutdown_received {
            return close_err("update_add_htlc during shutdown");
        }
        if msg.id != self.next_counterparty_htlc_id {
            return close_err(format!(
                "non-sequential htlc id {} (expected {})",
                msg.id, self.next_counterparty_htlc_id
            ));
        }
        if msg.amount_msat == Msat::ZERO {
            return close_err("zero-amount HTLC");
        }
        if msg.amount_msat < self.params.holder_htlc_minimum_msat {
            return close_err("HTLC below our htlc_minimum");
        }
        if msg.cltv_expiry >= 500_000_000 {
            return close_err("cltv_expiry too large");
        }
        let live_inbound: Vec<&Htlc> = self
            .htlcs
            .iter()
            .filter(|h| !h.outbound && h.resolution.is_none())
            .collect();
        if live_inbound.len() as u16 >= self.params.holder_max_accepted_htlcs {
            return close_err("our max_accepted_htlcs exceeded");
        }
        let in_flight: Msat =
            live_inbound.iter().map(|h| h.amount_msat).sum::<Msat>() + msg.amount_msat;
        if in_flight > self.params.holder_max_htlc_value_in_flight_msat {
            return close_err("our max_htlc_value_in_flight exceeded");
        }
        // Affordability on our commitment (where their add lands first).
        let (_, to_counterparty) = self.balances_for(true);
        let mut needed = msg.amount_msat
            + Msat::from_sat(self.params.holder_selected_reserve_sat);
        if self.role == ChannelRole::Accepter {
            // They are the opener and pay commitment fees.
            let untrimmed = self
                .htlcs
                .iter()
                .filter(|h| h.phase_holder.included())
                .count() as u64;
            let fee = self.feerate_holder.fee_for_weight(
                commitment::COMMITMENT_TX_BASE_WEIGHT
                    + commitment::COMMITMENT_TX_WEIGHT_PER_HTLC * (untrimmed + 1),
            );
            needed = needed + Msat::from_sat(fee);
        }
        if to_counterparty < needed {
            return close_err("peer cannot afford HTLC");
        }

        self.next_counterparty_htlc_id += 1;
        self.htlcs.push(Htlc {
            outbound: false,
            id: HtlcId(msg.id),
            amount_msat: msg.amount_msat,
            payment_hash: msg.payment_hash,
            cltv_expiry: msg.cltv_expiry,
            onion: msg.onion_routing_packet.clone(),
            source: None,
            resolution: None,
            phase_holder: HtlcPhase::Pending,
            phase_counterparty: HtlcPhase::NotYet,
            processed: false,
        });
        Ok(())
    }

    /// Returns the source of the fulfilled HTLC so the node layer can
    /// settle upstream (forwarded) or complete a payment (ours).
    pub fn on_update_fulfill_htlc(
        &mut self,
        msg: &UpdateFulfillHtlc,
    ) -> Result<(HtlcSource, Msat), ChannelError> {
        let htlc = self.outbound_committed_mut(HtlcId(msg.id))?;
        if msg.payment_preimage.payment_hash() != htlc.payment_hash {
            return close_err("fulfill preimage does not match payment hash");
        }
        htlc.resolution = Some(HtlcResolution::Fulfill(msg.payment_preimage));
        htlc.phase_holder = HtlcPhase::Removing;
        let source = htlc.source.clone().expect("outbound HTLCs always carry a source");
        let amount = htlc.amount_msat;
        Ok((source, amount))
    }

    pub fn on_update_fail_htlc(
        &mut self,
        msg: &UpdateFailHtlc,
    ) -> Result<(HtlcSource, Msat), ChannelError> {
        let htlc = self.outbound_committed_mut(HtlcId(msg.id))?;
        htlc.resolution = Some(HtlcResolution::Fail(msg.reason.clone()));
        htlc.phase_holder = HtlcPhase::Removing;
        let source = htlc.source.clone().expect("outbound HTLCs always carry a source");
        let amount = htlc.amount_msat;
        Ok((source, amount))
    }

    pub fn on_update_fail_malformed_htlc(
        &mut self,
        msg: &UpdateFailMalformedHtlc,
    ) -> Result<(HtlcSource, Msat), ChannelError> {
        if msg.failure_code & 0x8000 == 0 {
            return close_err("update_fail_malformed_htlc without BADONION bit");
        }
        let htlc = self.outbound_committed_mut(HtlcId(msg.id))?;
        htlc.resolution =
            Some(HtlcResolution::FailMalformed(msg.sha256_of_onion, msg.failure_code));
        htlc.phase_holder = HtlcPhase::Removing;
        let source = htlc.source.clone().expect("outbound HTLCs always carry a source");
        let amount = htlc.amount_msat;
        Ok((source, amount))
    }

    fn outbound_committed_mut(&mut self, id: HtlcId) -> Result<&mut Htlc, ChannelError> {
        let htlc = self
            .htlcs
            .iter_mut()
            .find(|h| h.outbound && h.id == id)
            .ok_or(ChannelError::Close(format!("unknown outbound HTLC id {}", id.0)))?;
        if htlc.resolution.is_some() {
            return Err(ChannelError::Close(format!("HTLC {} resolved twice", id.0)));
        }
        if htlc.phase_holder != HtlcPhase::Committed
            || htlc.phase_counterparty != HtlcPhase::Committed
        {
            return Err(ChannelError::Close(format!(
                "HTLC {} resolved before being irrevocably committed",
                id.0
            )));
        }
        Ok(htlc)
    }

    /// Opener peer changed the feerate. Applied to our commitment now, to
    /// theirs when we acknowledge.
    pub fn on_update_fee(&mut self, msg: &UpdateFee) -> Result<(), ChannelError> {
        if self.role == ChannelRole::Opener {
            return close_err("non-opener sent update_fee");
        }
        if msg.feerate_per_kw < 253 {
            return close_err("update_fee below floor");
        }
        if msg.feerate_per_kw > 10_000_000 {
            return close_err("update_fee absurdly high");
        }
        self.feerate_holder = FeeRatePerKw(msg.feerate_per_kw);
        self.pending_fee_ack = Some(FeeRatePerKw(msg.feerate_per_kw));
        Ok(())
    }

    // ------------------------------------------------- commitment_signed

    /// True if we have changes to sign and no commitment in flight.
    pub fn can_send_commitment(&self) -> bool {
        self.counterparty_dirty
            && !self.awaiting_raa
            && self.counterparty_next_point.is_some()
            && matches!(
                self.state,
                ChannelState::Normal | ChannelState::ShuttingDown
            )
    }

    /// Sign the counterparty's next commitment, covering every update we
    /// have sent (and every update of theirs we have acknowledged).
    pub fn send_commitment_signed(&mut self) -> Result<CommitmentSigned, ChannelError> {
        if self.awaiting_raa {
            return Err(ChannelError::InvalidState("commitment already in flight"));
        }
        if !self.counterparty_dirty {
            return Err(ChannelError::InvalidState("no changes to sign"));
        }
        let number = self.counterparty_commitment_number + 1;
        let point = self
            .counterparty_next_point
            .ok_or(ChannelError::InvalidState("next per-commitment point unknown"))?;
        let (built, keys, htlcs) = self.build_counterparty_commitment_at(number, point)?;
        let signature = self.sign_counterparty_commitment_tx(&built)?;

        // HTLC signatures, in commitment-output order. These sign *their*
        // second-stage transactions, so the CSV delay is the one we chose
        // and the keys are derived from their per-commitment point.
        let mut htlc_signatures = Vec::with_capacity(built.htlcs_in_output_order.len());
        for (htlc_idx, witness_script) in &built.htlcs_in_output_order {
            let htlc = &htlcs[*htlc_idx];
            let vout = built.htlc_output_indices[*htlc_idx].expect("untrimmed HTLC has an index");
            let htlc_tx = build_htlc_tx(
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

        let included = self
            .htlcs
            .iter()
            .filter(|h| h.phase_counterparty == HtlcPhase::Pending)
            .map(|h| (h.outbound, h.id))
            .collect();
        let removed = self
            .htlcs
            .iter()
            .filter(|h| h.phase_counterparty == HtlcPhase::Removing)
            .map(|h| (h.outbound, h.id))
            .collect();
        let fee_update = (self.feerate_holder != self.feerate_counterparty
            && self.role == ChannelRole::Opener)
            .then_some(self.feerate_counterparty);

        self.pending_counterparty_commitment = Some(PendingCounterpartyCommitment {
            info: self.counterparty_info_from_built(number, point, &built, &htlcs),
            included,
            removed,
            fee_update,
        });
        self.awaiting_raa = true;
        self.counterparty_dirty = false;

        Ok(CommitmentSigned { channel_id: self.channel_id, signature, htlc_signatures })
    }

    /// Verify their signatures over our next commitment and produce the
    /// `revoke_and_ack` releasing the previous one.
    pub fn on_commitment_signed(
        &mut self,
        msg: &CommitmentSigned,
    ) -> Result<RevokeAndAck, ChannelError> {
        if !matches!(self.state, ChannelState::Normal | ChannelState::ShuttingDown) {
            return close_err("commitment_signed outside normal operation");
        }
        let number = self.holder_commitment_number + 1;
        let (built, keys, htlcs) = self.build_holder_commitment_at(number)?;
        self.verify_counterparty_funding_sig(&built, &msg.signature)?;

        if msg.htlc_signatures.len() != built.htlcs_in_output_order.len() {
            return close_err(format!(
                "expected {} htlc signatures, got {}",
                built.htlcs_in_output_order.len(),
                msg.htlc_signatures.len()
            ));
        }
        for (sig, (htlc_idx, witness_script)) in
            msg.htlc_signatures.iter().zip(built.htlcs_in_output_order.iter())
        {
            let htlc = &htlcs[*htlc_idx];
            let vout = built.htlc_output_indices[*htlc_idx].expect("untrimmed HTLC has an index");
            let htlc_tx = build_htlc_tx(
                &built.txid,
                vout,
                htlc,
                &keys,
                self.params.counterparty_selected_delay,
                self.feerate_holder,
            );
            let sighash = SighashCache::new(&htlc_tx).segwit_v0_sighash(
                0,
                witness_script,
                htlc.amount_msat.to_sat_floor(),
                SighashType::All,
            );
            self.secp
                .verify_ecdsa(
                    &Message::from_digest(sighash),
                    sig,
                    &keys.countersignatory_htlc_key,
                )
                .map_err(|_| ChannelError::Close("invalid htlc signature".into()))?;
        }

        self.current_holder_commitment = Some(HolderCommitment {
            number,
            built,
            counterparty_sig: msg.signature,
            counterparty_htlc_sigs: msg.htlc_signatures.clone(),
            htlcs,
            keys,
            feerate: self.feerate_holder,
        });
        self.holder_commitment_number = number;

        // Lock in phase transitions on our side, then acknowledge their
        // updates so they may enter their commitment.
        for h in self.htlcs.iter_mut() {
            match h.phase_holder {
                HtlcPhase::Pending => h.phase_holder = HtlcPhase::Committed,
                HtlcPhase::Removing => h.phase_holder = HtlcPhase::Gone,
                _ => {}
            }
        }
        let mut dirty = false;
        for h in self.htlcs.iter_mut() {
            // Their adds, now in our commitment: allowed into theirs.
            if !h.outbound
                && h.phase_counterparty == HtlcPhase::NotYet
                && h.phase_holder == HtlcPhase::Committed
            {
                h.phase_counterparty = HtlcPhase::Pending;
                dirty = true;
            }
            // Their removals of our outbound HTLCs: acknowledged.
            if h.outbound
                && h.resolution.is_some()
                && h.phase_holder == HtlcPhase::Gone
                && h.phase_counterparty == HtlcPhase::Committed
            {
                h.phase_counterparty = HtlcPhase::Removing;
                dirty = true;
            }
        }
        if let Some(fee) = self.pending_fee_ack.take() {
            self.feerate_counterparty = fee;
            dirty = true;
        }
        if dirty {
            self.counterparty_dirty = true;
        }
        self.gc_htlcs();

        let revoked = number - 1;
        let per_commitment_secret = self.signer.release_commitment_secret(revoked);
        let next_per_commitment_point = self.signer.per_commitment_point(number + 1);
        Ok(RevokeAndAck {
            channel_id: self.channel_id,
            per_commitment_secret,
            next_per_commitment_point,
        })
    }

    // --------------------------------------------------- revoke_and_ack

    pub fn on_revoke_and_ack(&mut self, msg: &RevokeAndAck) -> Result<RaaOutcome, ChannelError> {
        if !self.awaiting_raa {
            return close_err("unexpected revoke_and_ack");
        }
        let pending = self
            .pending_counterparty_commitment
            .take()
            .expect("awaiting_raa implies a pending commitment");

        // The revealed secret must be the discrete log of their current
        // per-commitment point.
        let expected_point = self
            .counterparty_current_point
            .expect("current point known while a commitment is in flight");
        let revealed = crate::keys::per_commitment_point(&msg.per_commitment_secret);
        if revealed != expected_point {
            self.pending_counterparty_commitment = Some(pending);
            return close_err("revoked secret does not match per-commitment point");
        }
        let index = shachain::index_for_commitment(self.counterparty_commitment_number);
        if self.counterparty_secrets.insert(index, msg.per_commitment_secret).is_err() {
            self.pending_counterparty_commitment = Some(pending);
            return close_err("per-commitment secret inconsistent with chain");
        }

        self.counterparty_commitment_number += 1;
        self.counterparty_current_point = self.counterparty_next_point;
        self.counterparty_next_point = Some(msg.next_per_commitment_point);
        self.current_counterparty_commitment = Some(pending.info);
        self.awaiting_raa = false;

        // Their commitment is locked: apply the snapshotted transitions.
        for (outbound, id) in &pending.included {
            if let Some(h) = self.htlc_mut(*outbound, *id) {
                if h.phase_counterparty == HtlcPhase::Pending {
                    h.phase_counterparty = HtlcPhase::Committed;
                }
                // Our adds are now acknowledged → eligible for our side.
                if *outbound && h.phase_holder == HtlcPhase::NotYet {
                    h.phase_holder = HtlcPhase::Pending;
                }
            }
        }
        for (outbound, id) in &pending.removed {
            if let Some(h) = self.htlc_mut(*outbound, *id) {
                if h.phase_counterparty == HtlcPhase::Removing {
                    h.phase_counterparty = HtlcPhase::Gone;
                }
                // Our removals are acknowledged → drop from our side too.
                if !*outbound && h.phase_holder == HtlcPhase::Committed {
                    h.phase_holder = HtlcPhase::Removing;
                }
            }
        }
        if let Some(fee) = pending.fee_update {
            self.feerate_holder = fee;
        }
        self.gc_htlcs();

        let mut outcome = RaaOutcome::default();
        self.collect_forwardable(&mut outcome.forwardable);

        // Flush the holding cell.
        let ops = std::mem::take(&mut self.holding_cell);
        for op in ops {
            match op {
                HoldingCellOp::Add { amount_msat, payment_hash, cltv_expiry, onion, source } => {
                    match self.send_add_htlc(
                        amount_msat,
                        payment_hash,
                        cltv_expiry,
                        onion,
                        source.clone(),
                    ) {
                        Ok(Some(msg)) => outcome.messages.push(WireMessage::UpdateAddHtlc(msg)),
                        Ok(None) => unreachable!("not awaiting RAA during flush"),
                        Err(ChannelError::Ignore(_)) => {
                            outcome.failed_adds.push((source, "no longer routable on flush"))
                        }
                        Err(e) => return Err(e),
                    }
                }
                HoldingCellOp::Fulfill { id, preimage } => {
                    match self.send_fulfill_htlc(id, preimage) {
                        Ok(Some(msg)) => {
                            outcome.messages.push(WireMessage::UpdateFulfillHtlc(msg))
                        }
                        Ok(None) => unreachable!("not awaiting RAA during flush"),
                        // HTLC vanished (e.g. peer failed it concurrently).
                        Err(ChannelError::InvalidState(_)) | Err(ChannelError::Ignore(_)) => {}
                        Err(e) => return Err(e),
                    }
                }
                HoldingCellOp::Fail { id, reason } => match self.send_fail_htlc(id, reason) {
                    Ok(Some(msg)) => outcome.messages.push(WireMessage::UpdateFailHtlc(msg)),
                    Ok(None) => unreachable!("not awaiting RAA during flush"),
                    Err(ChannelError::InvalidState(_)) | Err(ChannelError::Ignore(_)) => {}
                    Err(e) => return Err(e),
                },
                HoldingCellOp::FailMalformed { id, sha256_of_onion, failure_code } => {
                    match self.send_fail_malformed_htlc(id, sha256_of_onion, failure_code) {
                        Ok(Some(msg)) => {
                            outcome.messages.push(WireMessage::UpdateFailMalformedHtlc(msg))
                        }
                        Ok(None) => unreachable!("not awaiting RAA during flush"),
                        Err(ChannelError::InvalidState(_)) | Err(ChannelError::Ignore(_)) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        if self.can_send_commitment() {
            outcome.commitment_signed = Some(self.send_commitment_signed()?);
        }
        Ok(outcome)
    }

    fn htlc_mut(&mut self, outbound: bool, id: HtlcId) -> Option<&mut Htlc> {
        self.htlcs.iter_mut().find(|h| h.outbound == outbound && h.id == id)
    }

    fn collect_forwardable(&mut self, out: &mut Vec<CommittedInboundHtlc>) {
        for h in self.htlcs.iter_mut() {
            if !h.outbound
                && !h.processed
                && h.resolution.is_none()
                && h.phase_holder == HtlcPhase::Committed
                && h.phase_counterparty == HtlcPhase::Committed
            {
                h.processed = true;
                out.push(CommittedInboundHtlc {
                    id: h.id,
                    amount_msat: h.amount_msat,
                    payment_hash: h.payment_hash,
                    cltv_expiry: h.cltv_expiry,
                    onion: h.onion.clone(),
                });
            }
        }
    }

    /// Live (unresolved) HTLC count — used to gate closing negotiation.
    pub fn live_htlc_count(&self) -> usize {
        self.htlcs.len()
    }
}
