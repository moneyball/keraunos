//! The BOLT 2 channel state machine.
//!
//! A [`Channel`] is a pure state machine: it consumes peer messages and
//! local commands, and returns messages to send plus facts the caller
//! (the [`crate::node`] orchestrator) needs to act on. It does no I/O, no
//! time reads, no randomness — and it talks to keys only through
//! [`ChannelSigner`].
//!
//! Concurrency discipline (same one LDK uses): at most one
//! `commitment_signed` in flight per direction. Local updates issued while
//! we await the peer's `revoke_and_ack` queue in a holding cell and flush
//! when it arrives. This is spec-compliant (the spec permits batching) and
//! collapses the htlc state space to something a human can verify.

mod close;
mod dance;
mod reestablish;
#[cfg(test)]
pub(crate) mod tests;

pub use close::ClosingSignedOutcome;
pub use dance::{CommittedInboundHtlc, HtlcResolution, RaaOutcome};
pub use reestablish::ReestablishActions;

use crate::bitcoin::{OutPoint, Script, SighashCache, SighashType, Transaction, Txid};
use crate::commitment::{
    self, build_commitment_tx, htlc_is_trimmed, scripts, BuiltCommitmentTx, CommitmentTxParams,
    HtlcOutputInCommitment,
};
use crate::keys::{ChannelPublicKeys, TxCreationKeys};
use crate::shachain::{self, SecretStore};
use crate::sign::ChannelSigner;
use crate::types::*;
use crate::wire::msgs::*;
use secp256k1::ecdsa::Signature;
use secp256k1::{All, Message, PublicKey, Secp256k1};

pub const MAX_HTLCS_PER_SIDE: u16 = 483;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Peer violated the protocol — fail the channel.
    Close(String),
    /// Request can't be satisfied right now — no state change.
    Ignore(String),
    /// API misuse by the embedder.
    InvalidState(&'static str),
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ChannelError::Close(s) => write!(f, "channel failure: {s}"),
            ChannelError::Ignore(s) => write!(f, "ignored: {s}"),
            ChannelError::InvalidState(s) => write!(f, "invalid state: {s}"),
        }
    }
}

impl std::error::Error for ChannelError {}

fn close_err<T>(msg: impl Into<String>) -> Result<T, ChannelError> {
    Err(ChannelError::Close(msg.into()))
}

/// Local policy knobs for new channels.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    pub announce: bool,
    pub dust_limit_sat: u64,
    /// Reserve we require of the peer, in parts-per-million of capacity
    /// (clamped up to our dust limit).
    pub reserve_ppm: u32,
    pub htlc_minimum_msat: Msat,
    pub to_self_delay: u16,
    pub max_accepted_htlcs: u16,
    pub max_htlc_value_in_flight_ppm: u32,
    pub minimum_depth: u32,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        ChannelConfig {
            announce: true,
            dust_limit_sat: 546,
            reserve_ppm: 10_000,                  // 1%
            htlc_minimum_msat: Msat(1),
            to_self_delay: 144,
            max_accepted_htlcs: 50,
            max_htlc_value_in_flight_ppm: 1_000_000, // 100%
            minimum_depth: 3,
        }
    }
}

/// Negotiated parameters. Fields named by *who chose the value*; comments
/// say *what it constrains*.
#[derive(Debug, Clone)]
pub struct ChannelParams {
    /// Our dust limit (applies to outputs of *our* commitment tx).
    pub holder_dust_limit_sat: u64,
    /// Their dust limit (their commitment tx).
    pub counterparty_dust_limit_sat: u64,
    /// Reserve we demand *they* keep.
    pub holder_selected_reserve_sat: u64,
    /// Reserve they demand *we* keep.
    pub counterparty_selected_reserve_sat: u64,
    /// Cap they put on *our* total offered-and-unresolved HTLC value.
    pub counterparty_max_htlc_value_in_flight_msat: Msat,
    /// Cap we put on theirs.
    pub holder_max_htlc_value_in_flight_msat: Msat,
    /// Minimum HTLC they accept from us.
    pub counterparty_htlc_minimum_msat: Msat,
    /// Minimum we accept from them.
    pub holder_htlc_minimum_msat: Msat,
    /// Max count of HTLCs we may have offered-and-unresolved toward them.
    pub counterparty_max_accepted_htlcs: u16,
    /// Max count we accept from them.
    pub holder_max_accepted_htlcs: u16,
    /// CSV delay on *their* to_local output (we chose it).
    pub holder_selected_delay: u16,
    /// CSV delay on *our* to_local output (they chose it).
    pub counterparty_selected_delay: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    /// We sent `open_channel` (we fund and pay commitment fees).
    Opener,
    Accepter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Opener: `open_channel` sent.
    OpenSent,
    /// Accepter: `accept_channel` sent.
    AcceptSent,
    /// Opener: `funding_created` sent.
    FundingCreatedSent,
    /// Funding tx exists and both initial commitments are signed; waiting
    /// for confirmation + both `channel_ready`s.
    AwaitingChannelReady,
    /// Open for business.
    Normal,
    /// `shutdown` exchanged (or initiated); draining HTLCs.
    ShuttingDown,
    /// HTLCs drained; `closing_signed` negotiation running.
    NegotiatingClose,
    /// Cooperative close tx seen (or negotiation finished).
    Closed,
}

/// Where an outbound HTLC came from — the node layer uses this to route
/// resolutions (settle upstream channel vs. complete a local payment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtlcSource {
    /// Locally initiated payment.
    Outbound { payment_id: [u8; 32] },
    /// Forwarded: settle back to this inbound HTLC.
    Forwarded { inbound_channel: ChannelId, inbound_htlc: HtlcId },
}

/// Lifecycle of an HTLC *on one side's commitment transaction*.
///
/// BOLT 2's central asymmetry: an update applies to the **other node's
/// commitment transaction** as soon as it is sent, and to the sender's own
/// commitment only once the other node acknowledges it via
/// `revoke_and_ack`. Tracking each side separately is what makes
/// concurrently-crossing `commitment_signed` messages verify on both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HtlcPhase {
    /// Not yet part of this side's commitment (add not acknowledged here).
    NotYet,
    /// Will be included in the next commitment built for this side.
    Pending,
    /// Included in this side's current (locked) commitment.
    Committed,
    /// Excluded from this side's next commitment; its resolution's balance
    /// effect applies here.
    Removing,
    /// A commitment without it is locked on this side.
    Gone,
}

impl HtlcPhase {
    pub(crate) fn included(self) -> bool {
        matches!(self, HtlcPhase::Pending | HtlcPhase::Committed)
    }
    pub(crate) fn credited(self) -> bool {
        matches!(self, HtlcPhase::Removing | HtlcPhase::Gone)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Htlc {
    pub outbound: bool,
    pub id: HtlcId,
    pub amount_msat: Msat,
    pub payment_hash: PaymentHash,
    pub cltv_expiry: u32,
    /// Onion blob: inbound — to peel once committed; outbound — sent.
    pub onion: Vec<u8>,
    pub source: Option<HtlcSource>,
    pub resolution: Option<HtlcResolution>,
    /// Phase on *our* commitment transaction.
    pub phase_holder: HtlcPhase,
    /// Phase on *their* commitment transaction.
    pub phase_counterparty: HtlcPhase,
    /// Inbound only: handed to the node layer for forwarding/claiming.
    pub processed: bool,
}

impl Htlc {
    /// The balance effect of this HTLC for one side's commitment, applied
    /// to working copies of the base balances (which never have HTLC
    /// amounts deducted — that happens here, per phase).
    fn apply_balance(&self, phase: HtlcPhase, to_holder: &mut Msat, to_counterparty: &mut Msat) {
        if phase.included() {
            // In escrow: debited from the offerer, paid to the HTLC output.
            if self.outbound {
                *to_holder = to_holder.saturating_sub(self.amount_msat);
            } else {
                *to_counterparty = to_counterparty.saturating_sub(self.amount_msat);
            }
        } else if phase.credited() {
            match &self.resolution {
                // Fulfilled: the amount moves offerer → recipient.
                Some(HtlcResolution::Fulfill(_)) => {
                    if self.outbound {
                        *to_holder = to_holder.saturating_sub(self.amount_msat);
                        *to_counterparty = *to_counterparty + self.amount_msat;
                    } else {
                        *to_counterparty = to_counterparty.saturating_sub(self.amount_msat);
                        *to_holder = *to_holder + self.amount_msat;
                    }
                }
                // Failed: refunded to the offerer — already in the base.
                Some(_) => {}
                None => debug_assert!(false, "removing HTLC without resolution"),
            }
        }
    }
}

/// Everything the chain monitor needs about one counterparty commitment.
#[derive(Debug, Clone)]
pub struct CounterpartyCommitmentInfo {
    pub number: u64,
    pub txid: Txid,
    pub per_commitment_point: PublicKey,
    /// (htlc, output index) — offered is from *their* perspective.
    pub htlcs: Vec<(HtlcOutputInCommitment, Option<u32>)>,
    pub to_holder_msat: Msat,
    pub to_counterparty_msat: Msat,
    pub feerate: FeeRatePerKw,
}

/// Our current local commitment with everything needed to broadcast it.
#[derive(Debug, Clone)]
pub struct HolderCommitment {
    pub number: u64,
    pub built: BuiltCommitmentTx,
    pub counterparty_sig: Signature,
    pub counterparty_htlc_sigs: Vec<Signature>,
    /// (htlc, source) in output order, offered from *our* perspective.
    pub htlcs: Vec<HtlcOutputInCommitment>,
    pub keys: TxCreationKeys,
    pub feerate: FeeRatePerKw,
}

#[derive(Debug, Clone)]
pub(crate) enum HoldingCellOp {
    Add {
        amount_msat: Msat,
        payment_hash: PaymentHash,
        cltv_expiry: u32,
        onion: Vec<u8>,
        source: HtlcSource,
    },
    Fulfill { id: HtlcId, preimage: PaymentPreimage },
    Fail { id: HtlcId, reason: Vec<u8> },
    FailMalformed { id: HtlcId, sha256_of_onion: [u8; 32], failure_code: u16 },
}

/// Snapshot of an in-flight `commitment_signed` we sent, applied when the
/// peer's `revoke_and_ack` arrives. The phase sets are snapshotted because
/// the peer can legitimately send us updates (and a crossing
/// `commitment_signed`) while we wait, mutating live phases.
#[derive(Debug, Clone)]
pub(crate) struct PendingCounterpartyCommitment {
    pub info: CounterpartyCommitmentInfo,
    /// HTLCs newly included (were `Pending` on their side at build time).
    pub included: Vec<(bool, HtlcId)>,
    /// HTLCs newly excluded (were `Removing` on their side at build time).
    pub removed: Vec<(bool, HtlcId)>,
    /// `update_fee` covered by this commitment, if any.
    pub fee_update: Option<FeeRatePerKw>,
}

pub struct Channel<S: ChannelSigner> {
    pub(crate) secp: Secp256k1<All>,
    pub(crate) signer: S,
    pub(crate) role: ChannelRole,
    pub(crate) state: ChannelState,
    #[allow(dead_code)] // kept for channel persistence / inspection APIs
    pub(crate) config: ChannelConfig,
    pub(crate) params: ChannelParams,

    pub(crate) temporary_channel_id: ChannelId,
    pub(crate) channel_id: ChannelId,
    pub(crate) funding_outpoint: Option<OutPoint>,
    pub(crate) funding_amount_sat: u64,
    #[allow(dead_code)] // kept for channel persistence / inspection APIs
    pub(crate) push_msat: Msat,
    pub(crate) holder_pubkeys: ChannelPublicKeys,
    pub(crate) counterparty_pubkeys: Option<ChannelPublicKeys>,
    pub(crate) obscure_factor: u64,
    /// Feerate in force on *our* commitment (changes at our RAA-ack of
    /// their `update_fee`, or at their RAA for ours).
    pub(crate) feerate_holder: FeeRatePerKw,
    /// Feerate in force on *their* commitment.
    pub(crate) feerate_counterparty: FeeRatePerKw,
    /// An `update_fee` received from the (opener) peer, applied to the
    /// counterparty side when we next acknowledge via `revoke_and_ack`.
    pub(crate) pending_fee_ack: Option<FeeRatePerKw>,
    pub(crate) announce: bool,

    /// Base balances (msat): all *settled* HTLC outcomes baked in, no live
    /// HTLC amounts deducted. Per-commitment balances are derived via
    /// [`Self::balances_for`].
    pub(crate) to_holder_msat: Msat,
    pub(crate) to_counterparty_msat: Msat,

    /// True when their next commitment would differ from their current one
    /// (something to sign).
    pub(crate) counterparty_dirty: bool,

    pub(crate) htlcs: Vec<Htlc>,
    pub(crate) next_holder_htlc_id: u64,
    pub(crate) next_counterparty_htlc_id: u64,

    /// Number of our current local commitment.
    pub(crate) holder_commitment_number: u64,
    /// Number of their current commitment.
    pub(crate) counterparty_commitment_number: u64,
    /// Point for their *current* commitment.
    pub(crate) counterparty_current_point: Option<PublicKey>,
    /// Point for the next commitment we'll sign for them.
    pub(crate) counterparty_next_point: Option<PublicKey>,
    pub(crate) counterparty_secrets: SecretStore,

    pub(crate) current_holder_commitment: Option<HolderCommitment>,
    pub(crate) current_counterparty_commitment: Option<CounterpartyCommitmentInfo>,
    pub(crate) pending_counterparty_commitment: Option<PendingCounterpartyCommitment>,
    pub(crate) awaiting_raa: bool,
    pub(crate) holding_cell: Vec<HoldingCellOp>,

    pub(crate) short_channel_id: Option<ShortChannelId>,
    pub(crate) funding_confirmed: bool,
    pub(crate) channel_ready_sent: bool,
    pub(crate) channel_ready_received: bool,

    // Shutdown / close state.
    pub(crate) holder_shutdown_script: Option<Script>,
    pub(crate) counterparty_shutdown_script: Option<Script>,
    pub(crate) shutdown_sent: bool,
    pub(crate) shutdown_received: bool,
    pub(crate) last_closing_fee_proposal: Option<u64>,
    pub(crate) closing_tx: Option<Transaction>,
}

impl<S: ChannelSigner> Channel<S> {
    // ---------------------------------------------------------- opening

    /// Start an outbound channel: returns the channel and the
    /// `open_channel` message to send.
    #[allow(clippy::too_many_arguments)]
    pub fn new_outbound(
        signer: S,
        config: ChannelConfig,
        network: Network,
        temporary_channel_id: ChannelId,
        funding_amount_sat: u64,
        push_msat: Msat,
        feerate: FeeRatePerKw,
    ) -> Result<(Channel<S>, OpenChannel), ChannelError> {
        if push_msat.0 > funding_amount_sat * 1000 {
            return Err(ChannelError::InvalidState("push exceeds funding"));
        }
        let secp = Secp256k1::new();
        let holder_pubkeys = *signer.pubkeys();
        let reserve = reserve_for(&config, funding_amount_sat);
        let max_in_flight =
            Msat(funding_amount_sat as u128 as u64 / 1_000_000 * config.max_htlc_value_in_flight_ppm as u64 * 1000);

        let first_point = signer.per_commitment_point(0);
        let msg = OpenChannel {
            chain_hash: network.chain_hash(),
            temporary_channel_id,
            funding_satoshis: funding_amount_sat,
            push_msat,
            dust_limit_satoshis: config.dust_limit_sat,
            max_htlc_value_in_flight_msat: max_in_flight,
            channel_reserve_satoshis: reserve,
            htlc_minimum_msat: config.htlc_minimum_msat,
            feerate_per_kw: feerate.0,
            to_self_delay: config.to_self_delay,
            max_accepted_htlcs: config.max_accepted_htlcs,
            basepoints: basepoints_msg(&holder_pubkeys),
            first_per_commitment_point: first_point,
            channel_flags: if config.announce { 1 } else { 0 },
            upfront_shutdown_script: None,
            channel_type: Some(static_remotekey_channel_type()),
        };

        let params = ChannelParams {
            holder_dust_limit_sat: config.dust_limit_sat,
            counterparty_dust_limit_sat: 0,
            holder_selected_reserve_sat: reserve,
            counterparty_selected_reserve_sat: 0,
            counterparty_max_htlc_value_in_flight_msat: Msat(0),
            holder_max_htlc_value_in_flight_msat: max_in_flight,
            counterparty_htlc_minimum_msat: Msat(0),
            holder_htlc_minimum_msat: config.htlc_minimum_msat,
            counterparty_max_accepted_htlcs: 0,
            holder_max_accepted_htlcs: config.max_accepted_htlcs,
            holder_selected_delay: config.to_self_delay,
            counterparty_selected_delay: 0,
        };

        let announce = config.announce;
        let chan = Channel {
            secp,
            signer,
            role: ChannelRole::Opener,
            state: ChannelState::OpenSent,
            config,
            params,
            temporary_channel_id,
            channel_id: temporary_channel_id,
            funding_outpoint: None,
            funding_amount_sat,
            push_msat,
            holder_pubkeys,
            counterparty_pubkeys: None,
            obscure_factor: 0,
            feerate_holder: feerate,
            feerate_counterparty: feerate,
            pending_fee_ack: None,
            announce,
            to_holder_msat: Msat(funding_amount_sat * 1000) - push_msat,
            to_counterparty_msat: push_msat,
            counterparty_dirty: false,
            htlcs: Vec::new(),
            next_holder_htlc_id: 0,
            next_counterparty_htlc_id: 0,
            holder_commitment_number: 0,
            counterparty_commitment_number: 0,
            counterparty_current_point: None,
            counterparty_next_point: None,
            counterparty_secrets: SecretStore::new(),
            current_holder_commitment: None,
            current_counterparty_commitment: None,
            pending_counterparty_commitment: None,
            awaiting_raa: false,
            holding_cell: Vec::new(),
            short_channel_id: None,
            funding_confirmed: false,
            channel_ready_sent: false,
            channel_ready_received: false,
            holder_shutdown_script: None,
            counterparty_shutdown_script: None,
            shutdown_sent: false,
            shutdown_received: false,
            last_closing_fee_proposal: None,
            closing_tx: None,
        };
        Ok((chan, msg))
    }

    /// Accept an inbound `open_channel`.
    pub fn new_inbound(
        signer: S,
        config: ChannelConfig,
        network: Network,
        msg: &OpenChannel,
    ) -> Result<(Channel<S>, AcceptChannel), ChannelError> {
        if msg.chain_hash != network.chain_hash() {
            return close_err("unknown chain");
        }
        if msg.push_msat.0 > msg.funding_satoshis * 1000 {
            return close_err("push exceeds funding");
        }
        if msg.dust_limit_satoshis > msg.channel_reserve_satoshis {
            return close_err("dust limit above reserve");
        }
        if msg.to_self_delay > 2016 {
            return close_err("to_self_delay unreasonably large");
        }
        if msg.max_accepted_htlcs > MAX_HTLCS_PER_SIDE {
            return close_err("max_accepted_htlcs above 483");
        }
        if msg.feerate_per_kw < 253 {
            return close_err("feerate too low");
        }
        if let Some(ct) = &msg.channel_type {
            // We speak exactly static_remotekey (bit 12); refuse others so
            // we never construct commitments we don't implement.
            if ct.as_bytes() != static_remotekey_channel_type().as_bytes() {
                return close_err("unsupported channel_type");
            }
        }

        let secp = Secp256k1::new();
        let holder_pubkeys = *signer.pubkeys();
        let reserve = reserve_for(&config, msg.funding_satoshis);
        if reserve < msg.dust_limit_satoshis {
            return close_err("our reserve below their dust limit");
        }
        let max_in_flight = Msat(
            msg.funding_satoshis / 1_000_000 * config.max_htlc_value_in_flight_ppm as u64 * 1000,
        );

        let accept = AcceptChannel {
            temporary_channel_id: msg.temporary_channel_id,
            dust_limit_satoshis: config.dust_limit_sat,
            max_htlc_value_in_flight_msat: max_in_flight,
            channel_reserve_satoshis: reserve,
            htlc_minimum_msat: config.htlc_minimum_msat,
            minimum_depth: config.minimum_depth,
            to_self_delay: config.to_self_delay,
            max_accepted_htlcs: config.max_accepted_htlcs,
            basepoints: basepoints_msg(&holder_pubkeys),
            first_per_commitment_point: signer.per_commitment_point(0),
            upfront_shutdown_script: None,
            channel_type: msg.channel_type.clone(),
        };

        let counterparty_pubkeys = pubkeys_from_msg(&msg.basepoints);
        let obscure_factor = commitment::commit_number_obscure_factor(
            &msg.basepoints.payment,
            &holder_pubkeys.payment_basepoint,
        );

        let params = ChannelParams {
            holder_dust_limit_sat: config.dust_limit_sat,
            counterparty_dust_limit_sat: msg.dust_limit_satoshis,
            holder_selected_reserve_sat: reserve,
            counterparty_selected_reserve_sat: msg.channel_reserve_satoshis,
            counterparty_max_htlc_value_in_flight_msat: msg.max_htlc_value_in_flight_msat,
            holder_max_htlc_value_in_flight_msat: max_in_flight,
            counterparty_htlc_minimum_msat: msg.htlc_minimum_msat,
            holder_htlc_minimum_msat: config.htlc_minimum_msat,
            counterparty_max_accepted_htlcs: msg.max_accepted_htlcs,
            holder_max_accepted_htlcs: config.max_accepted_htlcs,
            holder_selected_delay: config.to_self_delay,
            counterparty_selected_delay: msg.to_self_delay,
        };

        let announce_requested = msg.channel_flags & 1 != 0;
        let announce = announce_requested && config.announce;
        let chan = Channel {
            secp,
            signer,
            role: ChannelRole::Accepter,
            state: ChannelState::AcceptSent,
            config,
            params,
            temporary_channel_id: msg.temporary_channel_id,
            channel_id: msg.temporary_channel_id,
            funding_outpoint: None,
            funding_amount_sat: msg.funding_satoshis,
            push_msat: msg.push_msat,
            holder_pubkeys,
            counterparty_pubkeys: Some(counterparty_pubkeys),
            obscure_factor,
            feerate_holder: FeeRatePerKw(msg.feerate_per_kw),
            feerate_counterparty: FeeRatePerKw(msg.feerate_per_kw),
            pending_fee_ack: None,
            announce,
            to_holder_msat: msg.push_msat,
            to_counterparty_msat: Msat(msg.funding_satoshis * 1000) - msg.push_msat,
            counterparty_dirty: false,
            htlcs: Vec::new(),
            next_holder_htlc_id: 0,
            next_counterparty_htlc_id: 0,
            holder_commitment_number: 0,
            counterparty_commitment_number: 0,
            counterparty_current_point: Some(msg.first_per_commitment_point),
            counterparty_next_point: None,
            counterparty_secrets: SecretStore::new(),
            current_holder_commitment: None,
            current_counterparty_commitment: None,
            pending_counterparty_commitment: None,
            awaiting_raa: false,
            holding_cell: Vec::new(),
            short_channel_id: None,
            funding_confirmed: false,
            channel_ready_sent: false,
            channel_ready_received: false,
            holder_shutdown_script: None,
            counterparty_shutdown_script: None,
            shutdown_sent: false,
            shutdown_received: false,
            last_closing_fee_proposal: None,
            closing_tx: None,
        };
        Ok((chan, accept))
    }

    /// Opener: process `accept_channel`. The caller must then construct a
    /// funding transaction paying [`Self::funding_script_pubkey`] and call
    /// [`Self::funding_created`].
    pub fn on_accept_channel(&mut self, msg: &AcceptChannel) -> Result<(), ChannelError> {
        if self.state != ChannelState::OpenSent {
            return close_err("accept_channel in wrong state");
        }
        if msg.temporary_channel_id != self.temporary_channel_id {
            return close_err("accept_channel for unknown channel");
        }
        if msg.dust_limit_satoshis > self.params.holder_selected_reserve_sat {
            return close_err("their dust limit above our selected reserve");
        }
        if msg.channel_reserve_satoshis < self.params.holder_dust_limit_sat {
            return close_err("their reserve below our dust limit");
        }
        if msg.to_self_delay > 2016 {
            return close_err("to_self_delay unreasonably large");
        }
        if msg.minimum_depth > 144 {
            return close_err("minimum_depth unreasonably large");
        }
        if msg.max_accepted_htlcs > MAX_HTLCS_PER_SIDE {
            return close_err("max_accepted_htlcs above 483");
        }

        let cp = pubkeys_from_msg(&msg.basepoints);
        self.obscure_factor = commitment::commit_number_obscure_factor(
            &self.holder_pubkeys.payment_basepoint,
            &cp.payment_basepoint,
        );
        self.counterparty_pubkeys = Some(cp);
        self.counterparty_current_point = Some(msg.first_per_commitment_point);
        self.params.counterparty_dust_limit_sat = msg.dust_limit_satoshis;
        self.params.counterparty_selected_reserve_sat = msg.channel_reserve_satoshis;
        self.params.counterparty_max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
        self.params.counterparty_htlc_minimum_msat = msg.htlc_minimum_msat;
        self.params.counterparty_max_accepted_htlcs = msg.max_accepted_htlcs;
        self.params.counterparty_selected_delay = msg.to_self_delay;
        Ok(())
    }

    /// The P2WSH script the funding transaction must pay to.
    pub fn funding_script_pubkey(&self) -> Result<Script, ChannelError> {
        let cp = self.counterparty()?;
        Ok(Script::new_p2wsh(&scripts::funding_redeemscript(
            &self.holder_pubkeys.funding_pubkey,
            &cp.funding_pubkey,
        )))
    }

    /// Opener: bind the funding outpoint and produce `funding_created`
    /// (containing our signature on *their* commitment #0).
    pub fn funding_created(
        &mut self,
        funding_txid: Txid,
        funding_output_index: u16,
    ) -> Result<FundingCreated, ChannelError> {
        if self.state != ChannelState::OpenSent || self.role != ChannelRole::Opener {
            return Err(ChannelError::InvalidState("funding_created in wrong state"));
        }
        if self.counterparty_pubkeys.is_none() {
            return Err(ChannelError::InvalidState("accept_channel not processed"));
        }
        let outpoint = OutPoint::new(funding_txid, funding_output_index as u32);
        self.funding_outpoint = Some(outpoint);
        self.channel_id = channel_id_from_funding(&funding_txid, funding_output_index);

        let point = self.counterparty_current_point.expect("checked above");
        let (built, _, htlcs) = self.build_counterparty_commitment_at(0, point)?;
        let sig = self.sign_counterparty_commitment_tx(&built)?;
        self.current_counterparty_commitment =
            Some(self.counterparty_info_from_built(0, point, &built, &htlcs));
        self.state = ChannelState::FundingCreatedSent;

        Ok(FundingCreated {
            temporary_channel_id: self.temporary_channel_id,
            funding_txid: funding_txid.0,
            funding_output_index,
            signature: sig,
        })
    }

    /// Accepter: process `funding_created` — verify their signature on our
    /// commitment #0, sign their commitment #0.
    pub fn on_funding_created(
        &mut self,
        msg: &FundingCreated,
    ) -> Result<FundingSigned, ChannelError> {
        if self.state != ChannelState::AcceptSent {
            return close_err("funding_created in wrong state");
        }
        let txid = Txid(msg.funding_txid);
        let outpoint = OutPoint::new(txid, msg.funding_output_index as u32);
        self.funding_outpoint = Some(outpoint);
        self.channel_id = channel_id_from_funding(&txid, msg.funding_output_index);

        // Verify their signature over OUR commitment #0.
        let (built, keys, htlcs) = self.build_holder_commitment_at(0)?;
        self.verify_counterparty_funding_sig(&built, &msg.signature)?;
        self.current_holder_commitment = Some(HolderCommitment {
            number: 0,
            built: built.clone(),
            counterparty_sig: msg.signature,
            counterparty_htlc_sigs: vec![],
            htlcs,
            keys,
            feerate: self.feerate_holder,
        });

        // Sign THEIR commitment #0.
        let point = self.counterparty_current_point.expect("set at accept");
        let (their_built, _, their_htlcs) = self.build_counterparty_commitment_at(0, point)?;
        let sig = self.sign_counterparty_commitment_tx(&their_built)?;
        self.current_counterparty_commitment =
            Some(self.counterparty_info_from_built(0, point, &their_built, &their_htlcs));
        self.state = ChannelState::AwaitingChannelReady;

        Ok(FundingSigned { channel_id: self.channel_id, signature: sig })
    }

    /// Opener: process `funding_signed`. On success the funding tx is safe
    /// to broadcast.
    pub fn on_funding_signed(&mut self, msg: &FundingSigned) -> Result<(), ChannelError> {
        if self.state != ChannelState::FundingCreatedSent {
            return close_err("funding_signed in wrong state");
        }
        if msg.channel_id != self.channel_id {
            return close_err("funding_signed wrong channel id");
        }
        let (built, keys, htlcs) = self.build_holder_commitment_at(0)?;
        self.verify_counterparty_funding_sig(&built, &msg.signature)?;
        self.current_holder_commitment = Some(HolderCommitment {
            number: 0,
            built,
            counterparty_sig: msg.signature,
            counterparty_htlc_sigs: vec![],
            htlcs,
            keys,
            feerate: self.feerate_holder,
        });
        self.state = ChannelState::AwaitingChannelReady;
        Ok(())
    }

    /// The funding tx reached our required depth at `short_channel_id`.
    /// Returns the `channel_ready` to send (once).
    pub fn funding_confirmed(
        &mut self,
        short_channel_id: ShortChannelId,
    ) -> Result<Option<ChannelReady>, ChannelError> {
        if !matches!(self.state, ChannelState::AwaitingChannelReady | ChannelState::Normal) {
            return Err(ChannelError::InvalidState("funding_confirmed in wrong state"));
        }
        self.short_channel_id = Some(short_channel_id);
        self.funding_confirmed = true;
        if self.channel_ready_sent {
            return Ok(None);
        }
        self.channel_ready_sent = true;
        let msg = ChannelReady {
            channel_id: self.channel_id,
            second_per_commitment_point: self.signer.per_commitment_point(1),
            short_channel_id_alias: None,
        };
        self.maybe_become_normal();
        Ok(Some(msg))
    }

    pub fn on_channel_ready(&mut self, msg: &ChannelReady) -> Result<(), ChannelError> {
        if !matches!(self.state, ChannelState::AwaitingChannelReady | ChannelState::Normal) {
            return close_err("channel_ready in wrong state");
        }
        // A retransmission after the dance has started must not clobber
        // the (rotated) next per-commitment point.
        if self.counterparty_commitment_number > 0 || self.awaiting_raa {
            return Ok(());
        }
        // Their next point (#1): they gave it to us here.
        self.counterparty_next_point = Some(msg.second_per_commitment_point);
        self.channel_ready_received = true;
        self.maybe_become_normal();
        Ok(())
    }

    fn maybe_become_normal(&mut self) {
        if self.state == ChannelState::AwaitingChannelReady
            && self.channel_ready_sent
            && self.channel_ready_received
        {
            self.state = ChannelState::Normal;
        }
    }

    // ------------------------------------------------------- accessors

    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    pub fn state(&self) -> ChannelState {
        self.state
    }

    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn is_usable(&self) -> bool {
        self.state == ChannelState::Normal
    }

    pub fn announce_channel(&self) -> bool {
        self.announce
    }

    pub fn short_channel_id(&self) -> Option<ShortChannelId> {
        self.short_channel_id
    }

    pub fn funding_outpoint(&self) -> Option<OutPoint> {
        self.funding_outpoint
    }

    pub fn capacity_sat(&self) -> u64 {
        self.funding_amount_sat
    }

    pub fn counterparty_pubkeys(&self) -> Option<&ChannelPublicKeys> {
        self.counterparty_pubkeys.as_ref()
    }

    pub fn holder_funding_pubkey(&self) -> PublicKey {
        self.holder_pubkeys.funding_pubkey
    }

    pub fn signer_pubkeys(&self) -> &ChannelPublicKeys {
        &self.holder_pubkeys
    }

    /// Sign a `channel_announcement` digest with our funding key.
    pub fn sign_announcement(&self, double_sha: &[u8; 32]) -> Signature {
        self.signer.sign_announcement_with_funding_key(double_sha)
    }

    /// Balance we could theoretically spend right now (before reserve/fees).
    pub fn holder_balance_msat(&self) -> Msat {
        self.to_holder_msat
    }

    /// Conservative spendable estimate honoring reserve and (for the
    /// opener) commitment fees.
    pub fn available_to_send_msat(&self) -> Msat {
        let reserve = Msat::from_sat(self.params.counterparty_selected_reserve_sat);
        let (to_holder, _) = self.balances_for(false);
        let mut avail = to_holder.saturating_sub(reserve);
        if self.role == ChannelRole::Opener {
            let fee = self.feerate_counterparty.fee_for_weight(
                commitment::COMMITMENT_TX_BASE_WEIGHT
                    + commitment::COMMITMENT_TX_WEIGHT_PER_HTLC * (self.htlcs.len() as u64 + 1),
            );
            avail = avail.saturating_sub(Msat::from_sat(fee));
        }
        avail
    }

    pub(crate) fn counterparty(&self) -> Result<&ChannelPublicKeys, ChannelError> {
        self.counterparty_pubkeys
            .as_ref()
            .ok_or(ChannelError::InvalidState("counterparty keys not yet known"))
    }

    // --------------------------------------------- commitment building

    /// Effective balances for one side's *next* commitment: base balances
    /// with that side's live HTLC amounts deducted and resolved-but-unbaked
    /// HTLC credits applied.
    pub(crate) fn balances_for(&self, holder_side: bool) -> (Msat, Msat) {
        let mut to_holder = self.to_holder_msat;
        let mut to_counterparty = self.to_counterparty_msat;
        for h in &self.htlcs {
            let phase = if holder_side { h.phase_holder } else { h.phase_counterparty };
            h.apply_balance(phase, &mut to_holder, &mut to_counterparty);
        }
        (to_holder, to_counterparty)
    }

    /// Drop HTLCs gone from both commitments, baking their balance effect
    /// into the base.
    pub(crate) fn gc_htlcs(&mut self) {
        let mut to_holder = self.to_holder_msat;
        let mut to_counterparty = self.to_counterparty_msat;
        self.htlcs.retain(|h| {
            if h.phase_holder == HtlcPhase::Gone && h.phase_counterparty == HtlcPhase::Gone {
                h.apply_balance(HtlcPhase::Gone, &mut to_holder, &mut to_counterparty);
                false
            } else {
                true
            }
        });
        self.to_holder_msat = to_holder;
        self.to_counterparty_msat = to_counterparty;
    }

    /// Build the holder (local) commitment with the *next* inclusion set.
    pub(crate) fn build_holder_commitment_at(
        &self,
        number: u64,
    ) -> Result<(BuiltCommitmentTx, TxCreationKeys, Vec<HtlcOutputInCommitment>), ChannelError>
    {
        let cp = self.counterparty()?;
        let point = self.signer.per_commitment_point(number);
        let keys = TxCreationKeys::derive(&self.secp, &point, &self.holder_pubkeys, cp);
        let htlcs: Vec<HtlcOutputInCommitment> = self
            .htlcs
            .iter()
            .filter(|h| h.phase_holder.included())
            .map(|h| htlc_in_commitment(h, true))
            .collect();
        let (to_holder, to_counterparty) = self.balances_for(true);
        let built = build_commitment_tx(&CommitmentTxParams {
            funding_outpoint: self.funding_outpoint.ok_or(ChannelError::InvalidState(
                "no funding outpoint",
            ))?,
            commitment_number: number,
            obscure_factor: self.obscure_factor,
            broadcaster_pays_fee: self.role == ChannelRole::Opener,
            feerate: self.feerate_holder,
            broadcaster_dust_limit_sat: self.params.holder_dust_limit_sat,
            to_self_delay: self.params.counterparty_selected_delay,
            keys: &keys,
            countersignatory_payment_basepoint: cp.payment_basepoint,
            to_broadcaster_msat: to_holder,
            to_countersignatory_msat: to_counterparty,
            htlcs: &htlcs,
        });
        Ok((built, keys, htlcs))
    }

    /// Build the counterparty commitment with the *next* inclusion set.
    pub(crate) fn build_counterparty_commitment_at(
        &self,
        number: u64,
        point: PublicKey,
    ) -> Result<(BuiltCommitmentTx, TxCreationKeys, Vec<HtlcOutputInCommitment>), ChannelError>
    {
        let cp = self.counterparty()?;
        let keys = TxCreationKeys::derive(&self.secp, &point, cp, &self.holder_pubkeys);
        let htlcs: Vec<HtlcOutputInCommitment> = self
            .htlcs
            .iter()
            .filter(|h| h.phase_counterparty.included())
            .map(|h| htlc_in_commitment(h, false))
            .collect();
        let (to_holder, to_counterparty) = self.balances_for(false);
        let built = build_commitment_tx(&CommitmentTxParams {
            funding_outpoint: self
                .funding_outpoint
                .ok_or(ChannelError::InvalidState("no funding outpoint"))?,
            commitment_number: number,
            obscure_factor: self.obscure_factor,
            broadcaster_pays_fee: self.role == ChannelRole::Accepter,
            feerate: self.feerate_counterparty,
            broadcaster_dust_limit_sat: self.params.counterparty_dust_limit_sat,
            to_self_delay: self.params.holder_selected_delay,
            keys: &keys,
            countersignatory_payment_basepoint: self.holder_pubkeys.payment_basepoint,
            to_broadcaster_msat: to_counterparty,
            to_countersignatory_msat: to_holder,
            htlcs: &htlcs,
        });
        Ok((built, keys, htlcs))
    }

    pub(crate) fn counterparty_info_from_built(
        &self,
        number: u64,
        point: PublicKey,
        built: &BuiltCommitmentTx,
        htlcs: &[HtlcOutputInCommitment],
    ) -> CounterpartyCommitmentInfo {
        let (to_holder, to_counterparty) = self.balances_for(false);
        CounterpartyCommitmentInfo {
            number,
            txid: built.txid,
            per_commitment_point: point,
            htlcs: htlcs
                .iter()
                .enumerate()
                .map(|(i, h)| (*h, built.htlc_output_indices.get(i).copied().flatten()))
                .collect(),
            to_holder_msat: to_holder,
            to_counterparty_msat: to_counterparty,
            feerate: self.feerate_counterparty,
        }
    }

    pub(crate) fn funding_sighash(&self, tx: &Transaction) -> Result<[u8; 32], ChannelError> {
        let cp = self.counterparty()?;
        let redeem =
            scripts::funding_redeemscript(&self.holder_pubkeys.funding_pubkey, &cp.funding_pubkey);
        let cache = SighashCache::new(tx);
        Ok(cache.segwit_v0_sighash(0, &redeem, self.funding_amount_sat, SighashType::All))
    }

    pub(crate) fn sign_counterparty_commitment_tx(
        &self,
        built: &BuiltCommitmentTx,
    ) -> Result<Signature, ChannelError> {
        let sighash = self.funding_sighash(&built.tx)?;
        Ok(self.signer.sign_with_funding_key(&sighash))
    }

    pub(crate) fn verify_counterparty_funding_sig(
        &self,
        built: &BuiltCommitmentTx,
        sig: &Signature,
    ) -> Result<(), ChannelError> {
        let cp = self.counterparty()?;
        let sighash = self.funding_sighash(&built.tx)?;
        self.secp
            .verify_ecdsa(&Message::from_digest(sighash), sig, &cp.funding_pubkey)
            .map_err(|_| ChannelError::Close("invalid commitment signature".into()))
    }

    /// Our current local commitment, fully signed, ready to broadcast
    /// (force close).
    pub fn signed_holder_commitment_tx(&self) -> Result<Transaction, ChannelError> {
        let hc = self
            .current_holder_commitment
            .as_ref()
            .ok_or(ChannelError::InvalidState("no holder commitment yet"))?;
        let cp = self.counterparty()?;
        let sighash = self.funding_sighash(&hc.built.tx)?;
        let our_sig = self.signer.sign_with_funding_key(&sighash);
        let mut tx = hc.built.tx.clone();
        tx.input[0].witness = commitment::funding_spend_witness(
            &self.holder_pubkeys.funding_pubkey,
            &cp.funding_pubkey,
            &our_sig,
            &hc.counterparty_sig,
        );
        Ok(tx)
    }
}

fn basepoints_msg(pk: &ChannelPublicKeys) -> ChannelBasepoints {
    ChannelBasepoints {
        funding_pubkey: pk.funding_pubkey,
        revocation: pk.revocation_basepoint,
        payment: pk.payment_basepoint,
        delayed_payment: pk.delayed_payment_basepoint,
        htlc: pk.htlc_basepoint,
    }
}

fn pubkeys_from_msg(bp: &ChannelBasepoints) -> ChannelPublicKeys {
    ChannelPublicKeys {
        funding_pubkey: bp.funding_pubkey,
        revocation_basepoint: bp.revocation,
        payment_basepoint: bp.payment,
        delayed_payment_basepoint: bp.delayed_payment,
        htlc_basepoint: bp.htlc,
    }
}

/// BOLT 2: funding txid XOR output index, applied to the last two bytes.
pub fn channel_id_from_funding(txid: &Txid, output_index: u16) -> ChannelId {
    let mut id = txid.0;
    id[30] ^= (output_index >> 8) as u8;
    id[31] ^= (output_index & 0xff) as u8;
    ChannelId(id)
}

fn reserve_for(config: &ChannelConfig, funding_sat: u64) -> u64 {
    (funding_sat * config.reserve_ppm as u64 / 1_000_000).max(config.dust_limit_sat)
}

fn static_remotekey_channel_type() -> crate::wire::Features {
    let mut f = crate::wire::Features::empty();
    f.set(12); // option_static_remotekey (required form in channel_type)
    f
}

pub(crate) fn htlc_in_commitment(h: &Htlc, holder_view: bool) -> HtlcOutputInCommitment {
    HtlcOutputInCommitment {
        offered: if holder_view { h.outbound } else { !h.outbound },
        amount_msat: h.amount_msat,
        cltv_expiry: h.cltv_expiry,
        payment_hash: h.payment_hash,
    }
}

#[allow(unused)]
pub(crate) fn dust_relevant(
    h: &HtlcOutputInCommitment,
    feerate: FeeRatePerKw,
    dust: u64,
) -> bool {
    !htlc_is_trimmed(h, feerate, dust)
}
