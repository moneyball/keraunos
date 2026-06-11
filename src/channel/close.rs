//! Cooperative close: `shutdown` and the `closing_signed` fee negotiation
//! (legacy + `fee_range` fast path).

use super::*;
use crate::commitment::{build_closing_tx, funding_spend_witness, CLOSING_TX_WEIGHT_BOUND};

/// What `on_closing_signed` decided.
#[derive(Debug)]
pub enum ClosingSignedOutcome {
    /// Send this reply; if a transaction is attached, negotiation is over —
    /// broadcast it.
    Reply(ClosingSigned, Option<Transaction>),
    /// Their message completed negotiation at a fee we already proposed.
    Done(Transaction),
}

impl<S: ChannelSigner> Channel<S> {
    /// Begin (or reciprocate) shutdown. `script` is the address we want
    /// paid on close.
    pub fn send_shutdown(&mut self, script: Script) -> Result<Shutdown, ChannelError> {
        if !matches!(
            self.state,
            ChannelState::Normal | ChannelState::AwaitingChannelReady | ChannelState::ShuttingDown
        ) {
            return Err(ChannelError::InvalidState("shutdown in wrong state"));
        }
        if self.shutdown_sent {
            return Err(ChannelError::InvalidState("shutdown already sent"));
        }
        if !script.is_witness_program() {
            return Err(ChannelError::InvalidState("shutdown script must be a witness program"));
        }
        self.holder_shutdown_script = Some(script.clone());
        self.shutdown_sent = true;
        if self.state == ChannelState::Normal {
            self.state = ChannelState::ShuttingDown;
        }
        Ok(Shutdown { channel_id: self.channel_id, scriptpubkey: script.0 })
    }

    /// Peer wants to close. Returns our reciprocal `shutdown` if we hadn't
    /// sent one (using `our_script`).
    pub fn on_shutdown(
        &mut self,
        msg: &Shutdown,
        our_script: &Script,
    ) -> Result<Option<Shutdown>, ChannelError> {
        if !matches!(
            self.state,
            ChannelState::Normal | ChannelState::AwaitingChannelReady | ChannelState::ShuttingDown
        ) {
            return close_err("shutdown in wrong state");
        }
        let script = Script::new(msg.scriptpubkey.clone());
        if !script.is_witness_program() {
            return close_err("shutdown script is not a witness program");
        }
        self.counterparty_shutdown_script = Some(script);
        self.shutdown_received = true;
        if matches!(self.state, ChannelState::Normal | ChannelState::AwaitingChannelReady) {
            self.state = ChannelState::ShuttingDown;
        }
        if self.shutdown_sent {
            return Ok(None);
        }
        let reply = self.send_shutdown(our_script.clone())?;
        Ok(Some(reply))
    }

    /// True once both `shutdown`s are exchanged, all HTLCs are resolved,
    /// and no commitment exchange is in flight.
    pub fn ready_to_negotiate_close(&self) -> bool {
        matches!(self.state, ChannelState::ShuttingDown | ChannelState::NegotiatingClose)
            && self.shutdown_sent
            && self.shutdown_received
            && self.htlcs.is_empty()
            && !self.awaiting_raa
            && !self.counterparty_dirty
            && self.holding_cell.is_empty()
    }

    /// The fee range we are willing to accept, centered on the embedder's
    /// target feerate.
    fn closing_fee_bounds(&self, target_feerate: FeeRatePerKw) -> (u64, u64, u64) {
        let fee = target_feerate.fee_for_weight(CLOSING_TX_WEIGHT_BOUND);
        let min = FeeRatePerKw(253).fee_for_weight(CLOSING_TX_WEIGHT_BOUND);
        let (to_holder, _) = self.balances_for(true);
        // Never offer more than the funder output can pay.
        let funder_balance = if self.role == ChannelRole::Opener {
            to_holder.to_sat_floor()
        } else {
            u64::MAX
        };
        let max = (fee * 2).min(funder_balance);
        (fee.clamp(min, max), min, max)
    }

    fn build_and_sign_closing(
        &self,
        fee_sat: u64,
    ) -> Result<(Transaction, Signature), ChannelError> {
        let holder_script = self
            .holder_shutdown_script
            .as_ref()
            .ok_or(ChannelError::InvalidState("no holder shutdown script"))?;
        let counterparty_script = self
            .counterparty_shutdown_script
            .as_ref()
            .ok_or(ChannelError::InvalidState("no counterparty shutdown script"))?;
        let funding = self
            .funding_outpoint
            .ok_or(ChannelError::InvalidState("no funding outpoint"))?;

        let (to_holder, to_counterparty) = self.balances_for(true);
        let mut holder_sat = to_holder.to_sat_floor();
        let mut counterparty_sat = to_counterparty.to_sat_floor();
        match self.role {
            ChannelRole::Opener => holder_sat = holder_sat.saturating_sub(fee_sat),
            ChannelRole::Accepter => counterparty_sat = counterparty_sat.saturating_sub(fee_sat),
        }
        let dust = self.params.holder_dust_limit_sat.max(546);
        let tx = build_closing_tx(
            funding,
            holder_sat,
            counterparty_sat,
            holder_script,
            counterparty_script,
            dust,
        );
        if tx.output.is_empty() {
            return Err(ChannelError::InvalidState("closing tx would have no outputs"));
        }
        let sighash = self.funding_sighash(&tx)?;
        Ok((tx, self.signer.sign_with_funding_key(&sighash)))
    }

    fn verify_their_closing_sig(&self, fee_sat: u64, sig: &Signature) -> Result<Transaction, ChannelError> {
        let (tx, _) = self.build_and_sign_closing(fee_sat)?;
        let cp = self.counterparty()?;
        let sighash = self.funding_sighash(&tx)?;
        self.secp
            .verify_ecdsa(&Message::from_digest(sighash), sig, &cp.funding_pubkey)
            .map_err(|_| ChannelError::Close("invalid closing signature".into()))?;
        Ok(tx)
    }

    fn finalize_closing(
        &mut self,
        fee_sat: u64,
        their_sig: &Signature,
    ) -> Result<Transaction, ChannelError> {
        let (mut tx, our_sig) = self.build_and_sign_closing(fee_sat)?;
        let cp = self.counterparty()?;
        tx.input[0].witness = funding_spend_witness(
            &self.holder_pubkeys.funding_pubkey,
            &cp.funding_pubkey,
            &our_sig,
            their_sig,
        );
        self.closing_tx = Some(tx.clone());
        self.state = ChannelState::Closed;
        Ok(tx)
    }

    /// The funder kicks off (or continues) negotiation once the channel is
    /// quiescent.
    pub fn maybe_send_closing_signed(
        &mut self,
        target_feerate: FeeRatePerKw,
    ) -> Result<Option<ClosingSigned>, ChannelError> {
        if !self.ready_to_negotiate_close() {
            return Ok(None);
        }
        // The funder speaks first; the non-funder replies from
        // `on_closing_signed`.
        if self.role != ChannelRole::Opener || self.last_closing_fee_proposal.is_some() {
            return Ok(None);
        }
        let (fee, min, max) = self.closing_fee_bounds(target_feerate);
        let (_, sig) = self.build_and_sign_closing(fee)?;
        self.state = ChannelState::NegotiatingClose;
        self.last_closing_fee_proposal = Some(fee);
        Ok(Some(ClosingSigned {
            channel_id: self.channel_id,
            fee_satoshis: fee,
            signature: sig,
            fee_range: Some(ClosingSignedFeeRange {
                min_fee_satoshis: min,
                max_fee_satoshis: max,
            }),
        }))
    }

    pub fn on_closing_signed(
        &mut self,
        msg: &ClosingSigned,
        target_feerate: FeeRatePerKw,
    ) -> Result<ClosingSignedOutcome, ChannelError> {
        if !self.ready_to_negotiate_close() {
            return close_err("closing_signed before channel is quiescent");
        }
        self.state = ChannelState::NegotiatingClose;
        let their_fee = msg.fee_satoshis;
        self.verify_their_closing_sig(their_fee, &msg.signature)?;

        // Agreement: they echoed (or matched) a fee we proposed.
        if Some(their_fee) == self.last_closing_fee_proposal {
            let tx = self.finalize_closing(their_fee, &msg.signature)?;
            return Ok(ClosingSignedOutcome::Done(tx));
        }

        let (our_fee, our_min, our_max) = self.closing_fee_bounds(target_feerate);
        if let Some(range) = &msg.fee_range {
            // Modern path: pick inside the overlap.
            let lo = our_min.max(range.min_fee_satoshis);
            let hi = our_max.min(range.max_fee_satoshis);
            if lo > hi {
                return Err(ChannelError::Ignore(
                    "no overlap between closing fee ranges".into(),
                ));
            }
            if self.role == ChannelRole::Opener {
                // Funder must accept the non-funder's choice if in range.
                if their_fee < lo || their_fee > hi {
                    return close_err("closing fee outside negotiated range");
                }
                let tx = self.finalize_closing(their_fee, &msg.signature)?;
                let (_, sig) = self.build_and_sign_closing(their_fee)?;
                self.last_closing_fee_proposal = Some(their_fee);
                return Ok(ClosingSignedOutcome::Reply(
                    ClosingSigned {
                        channel_id: self.channel_id,
                        fee_satoshis: their_fee,
                        signature: sig,
                        fee_range: Some(ClosingSignedFeeRange {
                            min_fee_satoshis: our_min,
                            max_fee_satoshis: our_max,
                        }),
                    },
                    Some(tx),
                ));
            }
            // Non-funder: propose once, inside the overlap.
            if let Some(sent) = self.last_closing_fee_proposal {
                if their_fee != sent {
                    return close_err("funder moved fee after our range proposal");
                }
                let tx = self.finalize_closing(their_fee, &msg.signature)?;
                return Ok(ClosingSignedOutcome::Done(tx));
            }
            let fee = our_fee.clamp(lo, hi);
            self.last_closing_fee_proposal = Some(fee);
            if fee == their_fee {
                let tx = self.finalize_closing(fee, &msg.signature)?;
                let (_, sig) = self.build_and_sign_closing(fee)?;
                return Ok(ClosingSignedOutcome::Reply(
                    ClosingSigned {
                        channel_id: self.channel_id,
                        fee_satoshis: fee,
                        signature: sig,
                        fee_range: Some(ClosingSignedFeeRange {
                            min_fee_satoshis: our_min,
                            max_fee_satoshis: our_max,
                        }),
                    },
                    Some(tx),
                ));
            }
            let (_, sig) = self.build_and_sign_closing(fee)?;
            return Ok(ClosingSignedOutcome::Reply(
                ClosingSigned {
                    channel_id: self.channel_id,
                    fee_satoshis: fee,
                    signature: sig,
                    fee_range: Some(ClosingSignedFeeRange {
                        min_fee_satoshis: our_min,
                        max_fee_satoshis: our_max,
                    }),
                },
                None,
            ));
        }

        // Legacy path: converge by strictly-between proposals.
        let our_next = match self.last_closing_fee_proposal {
            None => our_fee,
            Some(sent) => {
                if their_fee.abs_diff(sent) <= 1 {
                    their_fee
                } else {
                    (their_fee + sent) / 2
                }
            }
        };
        self.last_closing_fee_proposal = Some(our_next);
        if our_next == their_fee {
            let tx = self.finalize_closing(their_fee, &msg.signature)?;
            let (_, sig) = self.build_and_sign_closing(their_fee)?;
            return Ok(ClosingSignedOutcome::Reply(
                ClosingSigned {
                    channel_id: self.channel_id,
                    fee_satoshis: their_fee,
                    signature: sig,
                    fee_range: None,
                },
                Some(tx),
            ));
        }
        let (_, sig) = self.build_and_sign_closing(our_next)?;
        Ok(ClosingSignedOutcome::Reply(
            ClosingSigned {
                channel_id: self.channel_id,
                fee_satoshis: our_next,
                signature: sig,
                fee_range: None,
            },
            None,
        ))
    }

    /// The fully-signed cooperative close transaction, once negotiated.
    pub fn closing_transaction(&self) -> Option<&Transaction> {
        self.closing_tx.as_ref()
    }
}
