//! The node orchestrator: one deterministic, sans-I/O state machine that
//! speaks the entire protocol.
//!
//! Everything is an explicit input (socket bytes, blocks, time, commands)
//! or an explicit [`Output`] (bytes to write, transactions to broadcast,
//! [`Event`]s for the application). The embedder owns sockets, disks,
//! clocks and threads:
//!
//! ```text
//! socket bytes ──▶ peer_input()                    ┌▶ Output::Wire ──▶ socket
//! blocks ────────▶ funding_confirmed()             ├▶ Output::Broadcast ──▶ bitcoind
//! unix time ─────▶ tick()              Node ───────┤
//! commands ──────▶ open/pay/claim/close...         └▶ Output::Event ──▶ application
//! ```

mod peer;

pub use peer::PeerId;

use crate::bitcoin::{sha256d, OutPoint, Script, Transaction, Txid};
use crate::channel::{
    channel_id_from_funding, Channel, ChannelConfig, ChannelError, ChannelState,
    ClosingSignedOutcome, HtlcSource,
};
use crate::graph::NetworkGraph;
use crate::invoice::{Bolt11Invoice, Description, InvoiceBuilder};
use crate::noise::{Initiator, Responder};
use crate::onion::{self, payload::HopPayload, OnionPacket, Peeled};
use crate::router::{self, DefaultScorer, FirstHop, PathScorer, RouteParams};
use crate::sign::{ChannelSigner, EntropySource, NodeSigner, SignerProvider};
use crate::types::*;
use crate::util::logger::{log_debug, log_error, log_info, log_warn, Logger, NullLogger};
use crate::wire::msgs::{self, Message as WireMessage};
use crate::wire::Features;
use peer::Peer;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::{HashMap, VecDeque};

// BOLT 4 failure codes.
const UPDATE: u16 = 0x1000;
const PERM: u16 = 0x4000;
const BADONION: u16 = 0x8000;
const FAIL_TEMPORARY_CHANNEL_FAILURE: u16 = UPDATE | 7;
const FAIL_UNKNOWN_NEXT_PEER: u16 = PERM | 10;
const FAIL_FEE_INSUFFICIENT: u16 = UPDATE | 12;
const FAIL_INCORRECT_CLTV_EXPIRY: u16 = UPDATE | 13;
const FAIL_INCORRECT_OR_UNKNOWN_PAYMENT: u16 = PERM | 15;
const FAIL_FINAL_INCORRECT_CLTV: u16 = 18;
const FAIL_FINAL_INCORRECT_AMOUNT: u16 = 19;
const FAIL_INVALID_ONION_HMAC: u16 = BADONION | PERM | 5;

/// An opaque identifier for an outbound payment attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaymentId(pub [u8; 32]);

#[derive(Debug)]
pub enum NodeError {
    PeerNotFound,
    PeerNotReady,
    ChannelNotFound,
    NoUsableChannel,
    Noise(crate::noise::NoiseError),
    Wire(crate::wire::WireError),
    Channel(ChannelError),
    Route(crate::router::RouteError),
    Invoice(crate::invoice::InvoiceError),
    InvalidFundingTx(&'static str),
    DuplicatePayment,
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NodeError::PeerNotFound => write!(f, "peer not found"),
            NodeError::PeerNotReady => write!(f, "peer connection not ready"),
            NodeError::ChannelNotFound => write!(f, "channel not found"),
            NodeError::NoUsableChannel => write!(f, "no usable channel"),
            NodeError::Noise(e) => write!(f, "transport: {e}"),
            NodeError::Wire(e) => write!(f, "wire: {e}"),
            NodeError::Channel(e) => write!(f, "channel: {e}"),
            NodeError::Route(e) => write!(f, "routing: {e}"),
            NodeError::Invoice(e) => write!(f, "invoice: {e}"),
            NodeError::InvalidFundingTx(s) => write!(f, "funding tx: {s}"),
            NodeError::DuplicatePayment => write!(f, "payment already pending for this hash"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<ChannelError> for NodeError {
    fn from(e: ChannelError) -> NodeError {
        NodeError::Channel(e)
    }
}

/// Effects for the embedder, in order.
#[derive(Debug)]
pub enum Output {
    /// Write these (already encrypted) bytes to this peer's socket.
    Wire { peer: PeerId, bytes: Vec<u8> },
    /// Broadcast this transaction to the Bitcoin network.
    Broadcast(Transaction),
    /// Start watching this funding output for spends and confirmations.
    WatchFunding { channel_id: ChannelId, outpoint: OutPoint, script: Script },
    /// Something the application should know.
    Event(Event),
}

#[derive(Debug)]
pub enum Event {
    /// Handshake + init complete; the peer speaks our language.
    PeerConnected { peer: PeerId, node_id: PublicKey },
    PeerDisconnected { peer: PeerId },
    /// `accept_channel` arrived: build a funding transaction paying
    /// `script` exactly `value_sat` and call
    /// [`Node::provide_funding_transaction`].
    FundingRequired { channel_id: ChannelId, script: Script, value_sat: u64 },
    /// Funding flow done on our side; broadcast happens automatically.
    ChannelPending { channel_id: ChannelId, funding_txid: Txid },
    ChannelReady { channel_id: ChannelId, node_id: PublicKey },
    /// An HTLC paying one of our invoices is fully committed.
    PaymentClaimable { payment_hash: PaymentHash, amount_msat: Msat },
    PaymentClaimed { payment_hash: PaymentHash, amount_msat: Msat },
    PaymentSent { payment_id: PaymentId, payment_hash: PaymentHash, preimage: PaymentPreimage },
    PaymentFailed {
        payment_id: PaymentId,
        payment_hash: PaymentHash,
        /// BOLT 4 failure code, if the error onion decrypted.
        failure_code: Option<u16>,
        /// Index of the failing hop in the route (0 = our peer).
        erring_hop: Option<usize>,
    },
    /// We forwarded an HTLC and earned `fee_msat` when it settled.
    Forwarded { inbound_channel: ChannelId, outbound_channel: ChannelId, fee_msat: Msat },
    ChannelClosed { channel_id: ChannelId, reason: String, closing_txid: Option<Txid> },
    /// The peer proved we lost state. Do NOT broadcast our commitment.
    DataLossDetected { channel_id: ChannelId },
}

/// Our forwarding policy, advertised in `channel_update`s.
#[derive(Debug, Clone)]
pub struct ForwardingPolicy {
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
}

impl Default for ForwardingPolicy {
    fn default() -> Self {
        ForwardingPolicy {
            fee_base_msat: 1000,
            fee_proportional_millionths: 100,
            cltv_expiry_delta: 40,
        }
    }
}

pub struct NodeConfig {
    pub network: Network,
    pub channel: ChannelConfig,
    pub forwarding: ForwardingPolicy,
    /// Script we get paid to on cooperative close.
    pub close_script: Script,
    /// Feerate for new channels' commitments.
    pub commitment_feerate: FeeRatePerKw,
    /// Target feerate for cooperative closes.
    pub close_feerate: FeeRatePerKw,
    /// Claim incoming payments automatically when we hold the preimage.
    pub auto_claim: bool,
    /// Extra CLTV margin added on top of the invoice's `min_final_cltv`.
    pub final_cltv_margin: u32,
    /// Accept inbound channel opens.
    pub accept_inbound: bool,
}

impl NodeConfig {
    pub fn new(network: Network, close_script: Script) -> NodeConfig {
        NodeConfig {
            network,
            channel: ChannelConfig::default(),
            forwarding: ForwardingPolicy::default(),
            close_script,
            commitment_feerate: FeeRatePerKw(253),
            close_feerate: FeeRatePerKw(253),
            auto_claim: true,
            final_cltv_margin: 6,
            accept_inbound: true,
        }
    }
}

struct ChannelEntry<S: ChannelSigner> {
    channel: Channel<S>,
    node_id: PublicKey,
    /// Funding tx held until `funding_signed` arrives (opener only).
    funding_tx: Option<Transaction>,
    announced: bool,
    their_announcement_sigs: Option<msgs::AnnouncementSignatures>,
    sent_announcement_sigs: bool,
}

struct PendingPayment {
    payment_hash: PaymentHash,
    #[allow(dead_code)]
    amount_msat: Msat,
    shared_secrets: Vec<[u8; 32]>,
}

struct InvoiceEntry {
    preimage: PaymentPreimage,
    payment_secret: PaymentSecret,
    amount_msat: Option<Msat>,
    min_final_cltv: u32,
}

/// The whole node. `K` provides keys, `E` randomness; both injected so the
/// engine itself stays deterministic.
pub struct Node<K: NodeSigner + SignerProvider, E: EntropySource> {
    config: NodeConfig,
    keys: K,
    entropy: E,
    logger: Box<dyn Logger>,
    scorer: Box<dyn PathScorer>,

    peers: HashMap<PeerId, Peer>,
    by_node_id: HashMap<PublicKey, PeerId>,
    next_peer: u64,

    channels: HashMap<ChannelId, ChannelEntry<K::Signer>>,
    scid_index: HashMap<ShortChannelId, ChannelId>,
    channel_counter: u64,

    pub graph: NetworkGraph,
    payments: HashMap<PaymentId, PendingPayment>,
    invoices: HashMap<PaymentHash, InvoiceEntry>,
    claimable: HashMap<PaymentHash, (ChannelId, HtlcId, Msat)>,
    /// Onion shared secret per inbound HTLC, for error wrapping.
    inbound_onion_secrets: HashMap<(ChannelId, HtlcId), [u8; 32]>,
    /// Fee earned per outbound forwarded HTLC, claimed at settle time.
    forward_fees: HashMap<(ChannelId, HtlcId), (ChannelId, Msat)>,

    outputs: VecDeque<Output>,
    best_height: u32,
    now: u64,
}

impl<K: NodeSigner + SignerProvider, E: EntropySource> Node<K, E> {
    pub fn new(keys: K, entropy: E, config: NodeConfig) -> Node<K, E> {
        let graph = NetworkGraph::new(config.network);
        Node {

            config,
            keys,
            entropy,
            logger: Box::new(NullLogger),
            scorer: Box::new(DefaultScorer::default()),
            peers: HashMap::new(),
            by_node_id: HashMap::new(),
            next_peer: 1,
            channels: HashMap::new(),
            scid_index: HashMap::new(),
            channel_counter: 0,
            graph,
            payments: HashMap::new(),
            invoices: HashMap::new(),
            claimable: HashMap::new(),
            inbound_onion_secrets: HashMap::new(),
            forward_fees: HashMap::new(),
            outputs: VecDeque::new(),
            best_height: 0,
            now: 0,
        }
    }

    pub fn with_logger(mut self, logger: Box<dyn Logger>) -> Self {
        self.logger = logger;
        self
    }

    pub fn with_scorer(mut self, scorer: Box<dyn PathScorer>) -> Self {
        self.scorer = scorer;
        self
    }

    pub fn node_id(&self) -> PublicKey {
        self.keys.node_id()
    }

    pub fn network(&self) -> Network {
        self.config.network
    }

    /// Pop the next pending effect. Drive this to empty after every call.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    // ------------------------------------------------------------- peers

    /// Start an outbound connection: returns the token and act-1 bytes to
    /// write after opening the socket.
    pub fn connect_outbound(&mut self, remote: PublicKey) -> (PeerId, Vec<u8>) {
        let ephemeral = self.random_secret_key();
        // The initiator needs our static secret for ECDH. We keep node-key
        // operations inside the signer everywhere *except* the Noise
        // handshake, which libsecp's ECDH shape forces here; a remote-signer
        // build would inject an ECDH callback instead.
        let mut initiator = Initiator::new(self.node_secret_for_noise(), remote, ephemeral);
        let act1 = initiator.act_one().to_vec();
        let id = PeerId(self.next_peer);
        self.next_peer += 1;
        self.peers.insert(id, Peer::new_outbound(initiator, remote));
        self.by_node_id.insert(remote, id);
        (id, act1)
    }

    /// Register an accepted inbound connection.
    pub fn accept_inbound(&mut self) -> PeerId {
        let ephemeral = self.random_secret_key();
        let responder = Responder::new(self.node_secret_for_noise(), ephemeral);
        let id = PeerId(self.next_peer);
        self.next_peer += 1;
        self.peers.insert(id, Peer::new_inbound(responder));
        id
    }

    /// Feed bytes read from a peer's socket.
    pub fn peer_input(&mut self, peer_id: PeerId, data: &[u8]) -> Result<(), NodeError> {
        let peer = self.peers.get_mut(&peer_id).ok_or(NodeError::PeerNotFound)?;
        let was_ready = matches!(peer.transport, peer::PeerTransport::Ready(_));
        let (to_send, messages) = peer.input(data).map_err(NodeError::Noise)?;
        for bytes in to_send {
            self.outputs.push_back(Output::Wire { peer: peer_id, bytes });
        }
        let peer = self.peers.get_mut(&peer_id).expect("still there");
        let now_ready = matches!(peer.transport, peer::PeerTransport::Ready(_));
        if !was_ready && now_ready {
            if let Some(node_id) = peer.node_id {
                self.by_node_id.insert(node_id, peer_id);
            }
            self.send_init(peer_id)?;
        }
        for plaintext in messages {
            match WireMessage::decode(&plaintext) {
                Ok(msg) => self.handle_message(peer_id, msg)?,
                Err(e) => {
                    log_warn!(self.logger, "undecodable message from {peer_id:?}: {e}");
                    if let crate::wire::WireError::UnknownMessageType(t) = e {
                        self.send_warning(peer_id, format!("unknown required message type {t}"));
                    }
                }
            }
        }
        Ok(())
    }

    /// The transport dropped. Channels roll back un-signed updates and wait
    /// for reconnection.
    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.peers.remove(&peer_id) {
            if let Some(node_id) = peer.node_id {
                self.by_node_id.remove(&node_id);
                for entry in self.channels.values_mut() {
                    if entry.node_id == node_id {
                        entry.channel.on_disconnect();
                    }
                }
                self.outputs
                    .push_back(Output::Event(Event::PeerDisconnected { peer: peer_id }));
            }
        }
    }

    fn send_init(&mut self, peer_id: PeerId) -> Result<(), NodeError> {
        let init = msgs::Init {
            global_features: Features::empty(),
            features: Features::keraunos_default(),
            networks: Some(vec![self.config.network.chain_hash()]),
        };
        self.send_to_peer(peer_id, &WireMessage::Init(init))?;
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.init_sent = true;
        }
        Ok(())
    }

    fn send_to_peer(&mut self, peer_id: PeerId, msg: &WireMessage) -> Result<(), NodeError> {
        let peer = self.peers.get_mut(&peer_id).ok_or(NodeError::PeerNotFound)?;
        let bytes = peer.encrypt(&msg.encode()).map_err(NodeError::Noise)?;
        self.outputs.push_back(Output::Wire { peer: peer_id, bytes });
        Ok(())
    }

    fn send_to_node(&mut self, node_id: &PublicKey, msg: &WireMessage) -> Result<(), NodeError> {
        let peer_id = *self.by_node_id.get(node_id).ok_or(NodeError::PeerNotFound)?;
        self.send_to_peer(peer_id, msg)
    }

    fn send_warning(&mut self, peer_id: PeerId, text: String) {
        let msg = WireMessage::Warning(msgs::WarningMsg {
            channel_id: ChannelId([0; 32]),
            data: text.into_bytes(),
        });
        let _ = self.send_to_peer(peer_id, &msg);
    }

    fn broadcast_to_ready_peers(&mut self, msg: &WireMessage) {
        let ready: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, p)| p.is_ready())
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            let _ = self.send_to_peer(id, msg);
        }
    }

    fn random_secret_key(&mut self) -> SecretKey {
        loop {
            if let Ok(sk) = SecretKey::from_slice(&self.entropy.get_random_bytes()) {
                return sk;
            }
        }
    }

    fn node_secret_for_noise(&self) -> SecretKey {
        // See note in `connect_outbound`.
        self.keys.noise_secret()
    }

    // ------------------------------------------------------------ chain

    pub fn best_block_updated(&mut self, height: u32) {
        self.best_height = height;
    }

    pub fn best_height(&self) -> u32 {
        self.best_height
    }

    /// Logical/wall-clock time for pings, gossip timestamps, invoices.
    pub fn tick(&mut self, unix_now: u64) {
        self.now = unix_now;
        let ready: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, p)| p.is_ready() && p.last_ping_sent_at + 30 <= unix_now)
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            let ping = WireMessage::Ping(msgs::Ping { num_pong_bytes: 1, ignored: vec![] });
            let _ = self.send_to_peer(id, &ping);
            if let Some(p) = self.peers.get_mut(&id) {
                p.last_ping_sent_at = unix_now;
                p.awaiting_pong = true;
            }
        }
    }

    /// The funding tx for `channel_id` reached the channel's required depth.
    pub fn funding_confirmed(
        &mut self,
        channel_id: ChannelId,
        scid: ShortChannelId,
    ) -> Result<(), NodeError> {
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;
        if let Some(msg) = entry.channel.funding_confirmed(scid)? {
            self.scid_index.insert(scid, channel_id);
            self.send_to_node(&node_id, &WireMessage::ChannelReady(msg))?;
        } else {
            self.scid_index.insert(scid, channel_id);
        }
        self.after_channel_ready_change(channel_id)?;
        Ok(())
    }

    // --------------------------------------------------------- channels

    /// Open a channel to a connected peer. Returns the (temporary) channel
    /// id; a [`Event::FundingRequired`] follows once the peer accepts.
    pub fn open_channel(
        &mut self,
        node_id: PublicKey,
        capacity_sat: u64,
        push_msat: Msat,
    ) -> Result<ChannelId, NodeError> {
        let peer_id = *self.by_node_id.get(&node_id).ok_or(NodeError::PeerNotFound)?;
        if !self.peers.get(&peer_id).map(|p| p.is_ready()).unwrap_or(false) {
            return Err(NodeError::PeerNotReady);
        }
        let signer = self.keys.derive_channel_signer(self.channel_counter);
        self.channel_counter += 1;
        let temp_id = ChannelId(self.entropy.get_random_bytes());
        let (channel, open_msg) = Channel::new_outbound(
            signer,
            self.config.channel.clone(),
            self.config.network,
            temp_id,
            capacity_sat,
            push_msat,
            self.config.commitment_feerate,
        )?;
        self.channels.insert(
            temp_id,
            ChannelEntry {
                channel,
                node_id,
                funding_tx: None,
                announced: false,
                their_announcement_sigs: None,
                sent_announcement_sigs: false,
            },
        );
        self.send_to_peer(peer_id, &WireMessage::OpenChannel(open_msg))?;
        Ok(temp_id)
    }

    /// Provide the funding transaction requested by
    /// [`Event::FundingRequired`]. Returns the final channel id.
    pub fn provide_funding_transaction(
        &mut self,
        channel_id: ChannelId,
        tx: Transaction,
    ) -> Result<ChannelId, NodeError> {
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let script = entry.channel.funding_script_pubkey()?;
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == script)
            .ok_or(NodeError::InvalidFundingTx("no output pays the funding script"))?;
        if tx.output[vout].value != entry.channel.capacity_sat() {
            return Err(NodeError::InvalidFundingTx("funding output value mismatch"));
        }
        let txid = tx.txid();
        let msg = entry.channel.funding_created(txid, vout as u16)?;
        entry.funding_tx = Some(tx);
        let new_id = entry.channel.channel_id();
        let node_id = entry.node_id;
        let entry = self.channels.remove(&channel_id).expect("present");
        self.channels.insert(new_id, entry);
        self.send_to_node(&node_id, &WireMessage::FundingCreated(msg))?;
        self.outputs.push_back(Output::Event(Event::ChannelPending {
            channel_id: new_id,
            funding_txid: txid,
        }));
        Ok(new_id)
    }

    /// Begin cooperative close.
    pub fn close_channel(&mut self, channel_id: ChannelId) -> Result<(), NodeError> {
        let script = self.config.close_script.clone();
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;
        let msg = entry.channel.send_shutdown(script)?;
        self.send_to_node(&node_id, &WireMessage::Shutdown(msg))?;
        self.try_start_closing(channel_id)?;
        Ok(())
    }

    /// Unilaterally close: broadcast our commitment transaction.
    pub fn force_close(&mut self, channel_id: ChannelId, reason: &str) -> Result<(), NodeError> {
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let tx = entry.channel.signed_holder_commitment_tx()?;
        let txid = tx.txid();
        self.outputs.push_back(Output::Broadcast(tx));
        self.outputs.push_back(Output::Event(Event::ChannelClosed {
            channel_id,
            reason: reason.to_string(),
            closing_txid: Some(txid),
        }));
        Ok(())
    }

    pub fn channel_ids(&self) -> Vec<ChannelId> {
        self.channels.keys().copied().collect()
    }

    pub fn channel_state(&self, channel_id: &ChannelId) -> Option<ChannelState> {
        self.channels.get(channel_id).map(|e| e.channel.state())
    }

    pub fn channel_balance_msat(&self, channel_id: &ChannelId) -> Option<Msat> {
        self.channels.get(channel_id).map(|e| e.channel.holder_balance_msat())
    }

    // --------------------------------------------------------- payments

    /// Register an invoice and return its BOLT 11 encoding.
    pub fn create_invoice(
        &mut self,
        amount_msat: Option<Msat>,
        description: &str,
        expiry_secs: u64,
    ) -> Result<(String, PaymentHash), NodeError> {
        let preimage = PaymentPreimage(self.entropy.get_random_bytes());
        let payment_hash = preimage.payment_hash();
        let payment_secret = PaymentSecret(self.entropy.get_random_bytes());
        let min_final_cltv = 18;
        let builder = InvoiceBuilder {
            network: self.config.network,
            amount_msat,
            timestamp: self.now,
            payment_hash,
            payment_secret,
            description: Description::Direct(description.to_string()),
            expiry_secs: Some(expiry_secs),
            min_final_cltv_expiry_delta: Some(min_final_cltv),
            features: InvoiceBuilder::default_features(),
            route_hints: vec![],
        };
        let encoded = builder.encode_signed(|digest| self.keys.sign_invoice_digest(digest));
        self.invoices.insert(
            payment_hash,
            InvoiceEntry { preimage, payment_secret, amount_msat, min_final_cltv },
        );
        Ok((encoded, payment_hash))
    }

    /// Pay a BOLT 11 invoice. `amount_msat` overrides (and is required for
    /// zero-amount invoices).
    pub fn pay_invoice(
        &mut self,
        invoice: &Bolt11Invoice,
        amount_msat: Option<Msat>,
    ) -> Result<PaymentId, NodeError> {
        let amount = amount_msat
            .or(invoice.amount_msat)
            .ok_or(NodeError::Invoice(crate::invoice::InvoiceError::MissingField("amount")))?;
        if self.payments.values().any(|p| p.payment_hash == invoice.payment_hash) {
            return Err(NodeError::DuplicatePayment);
        }

        let first_hops: Vec<FirstHop> = self
            .channels
            .values()
            .filter(|e| e.channel.is_usable())
            .filter_map(|e| {
                Some(FirstHop {
                    peer: e.node_id,
                    short_channel_id: e.channel.short_channel_id()?,
                    available_msat: e.channel.available_to_send_msat(),
                })
            })
            .collect();

        let final_cltv = self.best_height
            + invoice.min_final_cltv_or_default()
            + self.config.final_cltv_margin;
        let params = RouteParams {
            payer: self.node_id(),
            payee: invoice.payee,
            amount_msat: amount,
            final_cltv_expiry: final_cltv,
            first_hops: &first_hops,
            route_hints: &invoice.route_hints,
            max_hops: 20,
        };
        let route = router::find_route(&self.graph, self.scorer.as_ref(), &params)
            .map_err(NodeError::Route)?;

        // Build the onion: forward payloads for intermediates, payment
        // data for the final hop.
        let mut payloads = Vec::with_capacity(route.hops.len());
        for (i, hop) in route.hops.iter().enumerate() {
            if i + 1 < route.hops.len() {
                let next = &route.hops[i + 1];
                payloads.push(
                    HopPayload::forward(next.amount_msat, next.cltv_expiry, next.short_channel_id)
                        .encode(),
                );
            } else {
                payloads.push(
                    HopPayload::final_hop(
                        hop.amount_msat,
                        hop.cltv_expiry,
                        invoice.payment_secret,
                        amount,
                    )
                    .encode(),
                );
            }
        }
        let path: Vec<PublicKey> = route.hops.iter().map(|h| h.node_id).collect();
        let session_key = self.random_secret_key();
        let shared_secrets = onion::shared_secrets_for_path(&session_key, &path);
        let packet = onion::construct(
            &session_key,
            &shared_secrets,
            &payloads,
            &invoice.payment_hash.0,
        );

        let payment_id = PaymentId(self.entropy.get_random_bytes());
        let first_scid = route.hops[0].short_channel_id;
        let channel_id =
            *self.scid_index.get(&first_scid).ok_or(NodeError::NoUsableChannel)?;
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;

        let add = entry.channel.send_add_htlc(
            route.first_hop_amount_msat,
            invoice.payment_hash,
            route.first_hop_cltv,
            packet.serialize(),
            HtlcSource::Outbound { payment_id: payment_id.0 },
        )?;
        self.payments.insert(
            payment_id,
            PendingPayment { payment_hash: invoice.payment_hash, amount_msat: amount, shared_secrets },
        );
        if let Some(add) = add {
            self.send_to_node(&node_id, &WireMessage::UpdateAddHtlc(add))?;
            self.flush_commitment(channel_id)?;
        }
        log_info!(
            self.logger,
            "paying {} msat to {} over {} hops",
            amount.0,
            invoice.payee,
            route.hops.len()
        );
        Ok(payment_id)
    }

    /// Claim a payment we announced as claimable.
    pub fn claim_payment(&mut self, payment_hash: PaymentHash) -> Result<(), NodeError> {
        let (channel_id, htlc_id, amount) =
            self.claimable.remove(&payment_hash).ok_or(NodeError::ChannelNotFound)?;
        let preimage = self
            .invoices
            .get(&payment_hash)
            .map(|i| i.preimage)
            .ok_or(NodeError::ChannelNotFound)?;
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;
        if let Some(msg) = entry.channel.send_fulfill_htlc(htlc_id, preimage)? {
            self.send_to_node(&node_id, &WireMessage::UpdateFulfillHtlc(msg))?;
            self.flush_commitment(channel_id)?;
        }
        self.outputs.push_back(Output::Event(Event::PaymentClaimed {
            payment_hash,
            amount_msat: amount,
        }));
        Ok(())
    }

    /// Send `commitment_signed` on a channel if there are changes.
    fn flush_commitment(&mut self, channel_id: ChannelId) -> Result<(), NodeError> {
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;
        if entry.channel.can_send_commitment() {
            let cs = entry.channel.send_commitment_signed()?;
            self.send_to_node(&node_id, &WireMessage::CommitmentSigned(cs))?;
        }
        Ok(())
    }

    // -------------------------------------------------- message handling

    fn handle_message(&mut self, peer_id: PeerId, msg: WireMessage) -> Result<(), NodeError> {
        use WireMessage::*;
        match msg {
            Init(init) => self.on_init(peer_id, init),
            Ping(ping) => {
                // BOLT 1: respond with exactly num_pong_bytes zero bytes
                // (peers verify the length), or stay silent for >= 65532.
                if ping.num_pong_bytes >= 65532 {
                    return Ok(());
                }
                let pong = msgs::Pong { ignored: vec![0; ping.num_pong_bytes as usize] };
                self.send_to_peer(peer_id, &Pong(pong))
            }
            Pong(_) => {
                if let Some(p) = self.peers.get_mut(&peer_id) {
                    p.awaiting_pong = false;
                }
                Ok(())
            }
            Error(e) => {
                let text = String::from_utf8_lossy(&e.data).to_string();
                log_error!(self.logger, "peer {peer_id:?} error: {text}");
                if e.channel_id != ChannelId([0; 32]) && self.channels.contains_key(&e.channel_id)
                {
                    self.force_close(e.channel_id, &format!("peer error: {text}"))?;
                }
                Ok(())
            }
            Warning(w) => {
                log_warn!(
                    self.logger,
                    "peer {peer_id:?} warning: {}",
                    String::from_utf8_lossy(&w.data)
                );
                Ok(())
            }
            OpenChannel(open) => self.on_open_channel(peer_id, open),
            AcceptChannel(accept) => self.on_accept_channel(peer_id, accept),
            FundingCreated(fc) => self.on_funding_created(peer_id, fc),
            FundingSigned(fs) => self.on_funding_signed(peer_id, fs),
            ChannelReady(cr) => {
                let channel_id = cr.channel_id;
                self.with_channel(peer_id, channel_id, |chan| chan.on_channel_ready(&cr))?;
                self.after_channel_ready_change(channel_id)
            }
            UpdateAddHtlc(add) => {
                let channel_id = add.channel_id;
                self.with_channel(peer_id, channel_id, |chan| chan.on_update_add_htlc(&add))
            }
            UpdateFulfillHtlc(ful) => {
                let channel_id = ful.channel_id;
                let preimage = ful.payment_preimage;
                let (source, amount) = self
                    .with_channel(peer_id, channel_id, |chan| chan.on_update_fulfill_htlc(&ful))?;
                self.on_htlc_fulfilled(source, preimage, amount)
            }
            UpdateFailHtlc(fail) => {
                let channel_id = fail.channel_id;
                let reason = fail.reason.clone();
                let (source, _) = self
                    .with_channel(peer_id, channel_id, |chan| chan.on_update_fail_htlc(&fail))?;
                self.on_htlc_failed(source, Some(reason), None)
            }
            UpdateFailMalformedHtlc(fail) => {
                let channel_id = fail.channel_id;
                let code = fail.failure_code;
                let (source, _) = self.with_channel(peer_id, channel_id, |chan| {
                    chan.on_update_fail_malformed_htlc(&fail)
                })?;
                self.on_htlc_failed(source, None, Some(code))
            }
            UpdateFee(uf) => {
                let channel_id = uf.channel_id;
                self.with_channel(peer_id, channel_id, |chan| chan.on_update_fee(&uf))
            }
            CommitmentSigned(cs) => {
                let channel_id = cs.channel_id;
                let raa = self
                    .with_channel(peer_id, channel_id, |chan| chan.on_commitment_signed(&cs))?;
                let node_id = self.channels[&channel_id].node_id;
                self.send_to_node(&node_id, &RevokeAndAck(raa))?;
                self.flush_commitment(channel_id)?;
                self.try_start_closing(channel_id)
            }
            RevokeAndAck(raa) => {
                let channel_id = raa.channel_id;
                let outcome = self
                    .with_channel(peer_id, channel_id, |chan| chan.on_revoke_and_ack(&raa))?;
                let node_id = self.channels[&channel_id].node_id;
                for m in &outcome.messages {
                    self.send_to_node(&node_id, m)?;
                }
                if let Some(cs) = outcome.commitment_signed {
                    self.send_to_node(&node_id, &CommitmentSigned(cs))?;
                }
                for (source, reason) in outcome.failed_adds {
                    self.on_htlc_failed_locally(source, reason)?;
                }
                for htlc in outcome.forwardable {
                    self.process_committed_htlc(channel_id, htlc)?;
                }
                self.try_start_closing(channel_id)
            }
            Shutdown(sd) => {
                let channel_id = sd.channel_id;
                let our_script = self.config.close_script.clone();
                let reply = self
                    .with_channel(peer_id, channel_id, |chan| chan.on_shutdown(&sd, &our_script))?;
                if let Some(reply) = reply {
                    let node_id = self.channels[&channel_id].node_id;
                    self.send_to_node(&node_id, &Shutdown(reply))?;
                }
                self.try_start_closing(channel_id)
            }
            ClosingSigned(cs) => self.on_closing_signed(peer_id, cs),
            ChannelReestablish(re) => {
                let channel_id = re.channel_id;
                let actions = self
                    .with_channel(peer_id, channel_id, |chan| chan.on_channel_reestablish(&re))?;
                if actions.data_loss_detected {
                    self.outputs
                        .push_back(Output::Event(Event::DataLossDetected { channel_id }));
                    return Ok(());
                }
                let node_id = self.channels[&channel_id].node_id;
                for m in &actions.messages {
                    self.send_to_node(&node_id, m)?;
                }
                Ok(())
            }
            AnnouncementSignatures(anns) => self.on_announcement_signatures(peer_id, anns),
            ChannelAnnouncement(ca) => {
                match self.graph.apply_channel_announcement(&ca, None) {
                    Ok(()) => self.broadcast_to_ready_peers(&ChannelAnnouncement(ca)),
                    Err(crate::graph::GossipError::Ignored) => {}
                    Err(e) => log_debug!(self.logger, "rejected channel_announcement: {e}"),
                }
                Ok(())
            }
            ChannelUpdate(cu) => {
                match self.graph.apply_channel_update(&cu) {
                    Ok(()) => self.broadcast_to_ready_peers(&ChannelUpdate(cu)),
                    Err(crate::graph::GossipError::Ignored)
                    | Err(crate::graph::GossipError::UnknownChannel) => {}
                    Err(e) => log_debug!(self.logger, "rejected channel_update: {e}"),
                }
                Ok(())
            }
            NodeAnnouncement(na) => {
                if self.graph.apply_node_announcement(&na).is_ok() {
                    self.broadcast_to_ready_peers(&NodeAnnouncement(na));
                }
                Ok(())
            }
            GossipTimestampFilter(_) => Ok(()),
            Unknown(t, _) => {
                if t % 2 == 0 {
                    self.send_warning(peer_id, format!("unknown even message type {t}"));
                }
                Ok(())
            }
        }
    }

    fn on_init(&mut self, peer_id: PeerId, init: msgs::Init) -> Result<(), NodeError> {
        let combined = init.features.or(&init.global_features);
        if let Some(bit) = combined.unknown_required_bits(Features::known_even_bits()) {
            self.send_warning(peer_id, format!("unsupported required feature bit {bit}"));
            self.peer_disconnected(peer_id);
            return Ok(());
        }
        if let Some(networks) = &init.networks {
            if !networks.contains(&self.config.network.chain_hash()) {
                self.send_warning(peer_id, "no chain in common".to_string());
                self.peer_disconnected(peer_id);
                return Ok(());
            }
        }
        let peer = self.peers.get_mut(&peer_id).ok_or(NodeError::PeerNotFound)?;
        peer.features = combined;
        peer.init_received = true;
        let node_id = peer.node_id;
        if peer.is_ready() {
            if let Some(node_id) = node_id {
                self.outputs
                    .push_back(Output::Event(Event::PeerConnected { peer: peer_id, node_id }));
                // Reestablish all channels with this peer.
                let to_reestablish: Vec<(ChannelId, msgs::ChannelReestablish)> = self
                    .channels
                    .iter()
                    .filter(|(_, e)| {
                        e.node_id == node_id
                            && !matches!(
                                e.channel.state(),
                                ChannelState::OpenSent | ChannelState::AcceptSent
                            )
                    })
                    .map(|(id, e)| (*id, e.channel.make_channel_reestablish()))
                    .collect();
                for (_, re) in to_reestablish {
                    self.send_to_peer(peer_id, &WireMessage::ChannelReestablish(re))?;
                }
            }
        }
        Ok(())
    }

    fn on_open_channel(&mut self, peer_id: PeerId, open: msgs::OpenChannel) -> Result<(), NodeError> {
        if !self.config.accept_inbound {
            self.send_warning(peer_id, "not accepting channels".into());
            return Ok(());
        }
        let node_id = self
            .peers
            .get(&peer_id)
            .and_then(|p| p.node_id)
            .ok_or(NodeError::PeerNotReady)?;
        let signer = self.keys.derive_channel_signer(self.channel_counter);
        self.channel_counter += 1;
        match Channel::new_inbound(signer, self.config.channel.clone(), self.config.network, &open)
        {
            Ok((channel, accept)) => {
                self.channels.insert(
                    open.temporary_channel_id,
                    ChannelEntry {
                        channel,
                        node_id,
                        funding_tx: None,
                        announced: false,
                        their_announcement_sigs: None,
                        sent_announcement_sigs: false,
                    },
                );
                self.send_to_peer(peer_id, &WireMessage::AcceptChannel(accept))
            }
            Err(e) => {
                let err = msgs::ErrorMsg {
                    channel_id: open.temporary_channel_id,
                    data: e.to_string().into_bytes(),
                };
                self.send_to_peer(peer_id, &WireMessage::Error(err))
            }
        }
    }

    fn on_accept_channel(
        &mut self,
        peer_id: PeerId,
        accept: msgs::AcceptChannel,
    ) -> Result<(), NodeError> {
        let channel_id = accept.temporary_channel_id;
        self.with_channel(peer_id, channel_id, |chan| chan.on_accept_channel(&accept))?;
        let entry = self.channels.get(&channel_id).expect("checked");
        let script = entry.channel.funding_script_pubkey()?;
        let value_sat = entry.channel.capacity_sat();
        self.outputs.push_back(Output::Event(Event::FundingRequired {
            channel_id,
            script,
            value_sat,
        }));
        Ok(())
    }

    fn on_funding_created(
        &mut self,
        peer_id: PeerId,
        fc: msgs::FundingCreated,
    ) -> Result<(), NodeError> {
        let temp_id = fc.temporary_channel_id;
        let reply = self.with_channel(peer_id, temp_id, |chan| chan.on_funding_created(&fc))?;
        // Re-key the map: the channel id is now funding-derived.
        let new_id = channel_id_from_funding(&Txid(fc.funding_txid), fc.funding_output_index);
        let entry = self.channels.remove(&temp_id).expect("checked");
        let node_id = entry.node_id;
        let outpoint = entry.channel.funding_outpoint().expect("set in funding_created");
        let script = entry.channel.funding_script_pubkey()?;
        self.channels.insert(new_id, entry);
        self.send_to_node(&node_id, &WireMessage::FundingSigned(reply))?;
        self.outputs.push_back(Output::WatchFunding { channel_id: new_id, outpoint, script });
        self.outputs.push_back(Output::Event(Event::ChannelPending {
            channel_id: new_id,
            funding_txid: Txid(fc.funding_txid),
        }));
        Ok(())
    }

    fn on_funding_signed(
        &mut self,
        peer_id: PeerId,
        fs: msgs::FundingSigned,
    ) -> Result<(), NodeError> {
        let channel_id = fs.channel_id;
        self.with_channel(peer_id, channel_id, |chan| chan.on_funding_signed(&fs))?;
        let entry = self.channels.get_mut(&channel_id).expect("checked");
        let tx = entry
            .funding_tx
            .take()
            .ok_or(NodeError::InvalidFundingTx("funding tx not held"))?;
        let outpoint = entry.channel.funding_outpoint().expect("bound");
        let script = entry.channel.funding_script_pubkey()?;
        self.outputs.push_back(Output::WatchFunding { channel_id, outpoint, script });
        self.outputs.push_back(Output::Broadcast(tx));
        Ok(())
    }

    fn on_closing_signed(
        &mut self,
        peer_id: PeerId,
        cs: msgs::ClosingSigned,
    ) -> Result<(), NodeError> {
        let channel_id = cs.channel_id;
        let target = self.config.close_feerate;
        let outcome =
            self.with_channel(peer_id, channel_id, |chan| chan.on_closing_signed(&cs, target))?;
        let node_id = self.channels[&channel_id].node_id;
        match outcome {
            ClosingSignedOutcome::Reply(reply, maybe_tx) => {
                self.send_to_peer(peer_id, &WireMessage::ClosingSigned(reply))?;
                if let Some(tx) = maybe_tx {
                    self.finish_cooperative_close(channel_id, tx);
                }
            }
            ClosingSignedOutcome::Done(tx) => {
                let _ = node_id;
                self.finish_cooperative_close(channel_id, tx);
            }
        }
        Ok(())
    }

    fn finish_cooperative_close(&mut self, channel_id: ChannelId, tx: Transaction) {
        let txid = tx.txid();
        self.outputs.push_back(Output::Broadcast(tx));
        self.outputs.push_back(Output::Event(Event::ChannelClosed {
            channel_id,
            reason: "cooperative close".into(),
            closing_txid: Some(txid),
        }));
    }

    /// Kick the closing negotiation if the channel just became quiescent
    /// (we're the funder, or we owe a reply).
    fn try_start_closing(&mut self, channel_id: ChannelId) -> Result<(), NodeError> {
        let target = self.config.close_feerate;
        let Some(entry) = self.channels.get_mut(&channel_id) else {
            return Ok(());
        };
        let node_id = entry.node_id;
        if let Some(msg) = entry.channel.maybe_send_closing_signed(target)? {
            self.send_to_node(&node_id, &WireMessage::ClosingSigned(msg))?;
        }
        Ok(())
    }

    fn after_channel_ready_change(&mut self, channel_id: ChannelId) -> Result<(), NodeError> {
        let Some(entry) = self.channels.get(&channel_id) else {
            return Ok(());
        };
        if !entry.channel.is_usable() {
            return Ok(());
        }
        let node_id = entry.node_id;
        self.outputs
            .push_back(Output::Event(Event::ChannelReady { channel_id, node_id }));
        self.maybe_announce_channel(channel_id)?;
        Ok(())
    }

    // ---------------------------------------------------------- gossip

    /// Build the unsigned channel_announcement for one of our channels.
    fn build_our_announcement(
        &self,
        channel_id: &ChannelId,
    ) -> Option<(msgs::ChannelAnnouncement, bool)> {
        let entry = self.channels.get(channel_id)?;
        let scid = entry.channel.short_channel_id()?;
        let our_node = self.node_id();
        let their_node = entry.node_id;
        let our_funding = entry.channel.holder_funding_pubkey();
        let their_funding = entry.channel.counterparty_pubkeys()?.funding_pubkey;
        let we_are_first = our_node.serialize() < their_node.serialize();
        let (n1, n2, b1, b2) = if we_are_first {
            (our_node, their_node, our_funding, their_funding)
        } else {
            (their_node, our_node, their_funding, our_funding)
        };
        let dummy = dummy_sig();
        Some((
            msgs::ChannelAnnouncement {
                node_signature_1: dummy,
                node_signature_2: dummy,
                bitcoin_signature_1: dummy,
                bitcoin_signature_2: dummy,
                features: Features::empty(),
                chain_hash: self.config.network.chain_hash(),
                short_channel_id: scid,
                node_id_1: n1,
                node_id_2: n2,
                bitcoin_key_1: b1,
                bitcoin_key_2: b2,
            },
            we_are_first,
        ))
    }

    /// Send announcement_signatures once the channel is ready+confirmed,
    /// and finish the announcement when we have both halves.
    fn maybe_announce_channel(&mut self, channel_id: ChannelId) -> Result<(), NodeError> {
        let Some(entry) = self.channels.get(&channel_id) else {
            return Ok(());
        };
        if !entry.channel.announce_channel() || !entry.channel.is_usable() {
            return Ok(());
        }
        let Some((unsigned, we_are_first)) = self.build_our_announcement(&channel_id) else {
            return Ok(());
        };
        let hash = sha256d(&unsigned.signed_payload());
        let entry = self.channels.get_mut(&channel_id).expect("checked");
        let scid = entry.channel.short_channel_id().expect("checked");
        let node_id = entry.node_id;

        if !entry.sent_announcement_sigs {
            let node_signature = self.keys.sign_gossip(&hash);
            let bitcoin_signature = entry.channel.sign_announcement(&hash);
            entry.sent_announcement_sigs = true;
            let msg = msgs::AnnouncementSignatures {
                channel_id,
                short_channel_id: scid,
                node_signature,
                bitcoin_signature,
            };
            self.send_to_node(&node_id, &WireMessage::AnnouncementSignatures(msg))?;
        }

        let entry = self.channels.get_mut(&channel_id).expect("checked");
        if entry.announced {
            return Ok(());
        }
        let Some(theirs) = entry.their_announcement_sigs.clone() else {
            return Ok(());
        };
        // Assemble the full announcement.
        let node_signature = self.keys.sign_gossip(&hash);
        let bitcoin_signature = entry.channel.sign_announcement(&hash);
        let mut full = unsigned;
        if we_are_first {
            full.node_signature_1 = node_signature;
            full.bitcoin_signature_1 = bitcoin_signature;
            full.node_signature_2 = theirs.node_signature;
            full.bitcoin_signature_2 = theirs.bitcoin_signature;
        } else {
            full.node_signature_2 = node_signature;
            full.bitcoin_signature_2 = bitcoin_signature;
            full.node_signature_1 = theirs.node_signature;
            full.bitcoin_signature_1 = theirs.bitcoin_signature;
        }
        let capacity = entry.channel.capacity_sat();
        entry.announced = true;
        if let Err(e) = self.graph.apply_channel_announcement(&full, Some(capacity)) {
            log_warn!(self.logger, "our own announcement failed validation: {e}");
            return Ok(());
        }
        self.broadcast_to_ready_peers(&WireMessage::ChannelAnnouncement(full));
        // And our directional policy.
        let update = self.build_our_channel_update(channel_id, we_are_first)?;
        let _ = self.graph.apply_channel_update(&update);
        self.broadcast_to_ready_peers(&WireMessage::ChannelUpdate(update));
        Ok(())
    }

    fn build_our_channel_update(
        &mut self,
        channel_id: ChannelId,
        we_are_first: bool,
    ) -> Result<msgs::ChannelUpdate, NodeError> {
        let entry = self.channels.get(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let scid = entry.channel.short_channel_id().ok_or(NodeError::ChannelNotFound)?;
        let mut update = msgs::ChannelUpdate {
            signature: dummy_sig(),
            chain_hash: self.config.network.chain_hash(),
            short_channel_id: scid,
            timestamp: self.now as u32,
            message_flags: 1,
            channel_flags: if we_are_first { 0 } else { 1 },
            cltv_expiry_delta: self.config.forwarding.cltv_expiry_delta,
            htlc_minimum_msat: Msat(1),
            fee_base_msat: self.config.forwarding.fee_base_msat,
            fee_proportional_millionths: self.config.forwarding.fee_proportional_millionths,
            htlc_maximum_msat: Msat(entry.channel.capacity_sat() * 1000),
        };
        let hash = sha256d(&update.signed_payload());
        update.signature = self.keys.sign_gossip(&hash);
        Ok(update)
    }

    fn on_announcement_signatures(
        &mut self,
        peer_id: PeerId,
        anns: msgs::AnnouncementSignatures,
    ) -> Result<(), NodeError> {
        let channel_id = anns.channel_id;
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        if self.peers.get(&peer_id).and_then(|p| p.node_id) != Some(entry.node_id) {
            return Err(NodeError::ChannelNotFound);
        }
        entry.their_announcement_sigs = Some(anns);
        self.maybe_announce_channel(channel_id)
    }

    // ------------------------------------------------ HTLC settlement

    fn on_htlc_fulfilled(
        &mut self,
        source: HtlcSource,
        preimage: PaymentPreimage,
        amount: Msat,
    ) -> Result<(), NodeError> {
        match source {
            HtlcSource::Outbound { payment_id } => {
                let payment_id = PaymentId(payment_id);
                if let Some(p) = self.payments.remove(&payment_id) {
                    self.outputs.push_back(Output::Event(Event::PaymentSent {
                        payment_id,
                        payment_hash: p.payment_hash,
                        preimage,
                    }));
                }
                Ok(())
            }
            HtlcSource::Forwarded { inbound_channel, inbound_htlc } => {
                // Pull the preimage backward.
                let entry = self
                    .channels
                    .get_mut(&inbound_channel)
                    .ok_or(NodeError::ChannelNotFound)?;
                let node_id = entry.node_id;
                if let Some(msg) = entry.channel.send_fulfill_htlc(inbound_htlc, preimage)? {
                    self.send_to_node(&node_id, &WireMessage::UpdateFulfillHtlc(msg))?;
                    self.flush_commitment(inbound_channel)?;
                }
                let _ = amount;
                Ok(())
            }
        }
    }

    fn on_htlc_failed(
        &mut self,
        source: HtlcSource,
        reason: Option<Vec<u8>>,
        malformed_code: Option<u16>,
    ) -> Result<(), NodeError> {
        match source {
            HtlcSource::Outbound { payment_id } => {
                let payment_id = PaymentId(payment_id);
                if let Some(p) = self.payments.remove(&payment_id) {
                    let mut failure_code = malformed_code;
                    let mut erring_hop = None;
                    if let Some(reason) = &reason {
                        if let Some((hop, msg)) =
                            onion::failure::decrypt(&p.shared_secrets, reason)
                        {
                            failure_code = onion::failure::parse_code(&msg);
                            erring_hop = Some(hop);
                        }
                    }
                    self.outputs.push_back(Output::Event(Event::PaymentFailed {
                        payment_id,
                        payment_hash: p.payment_hash,
                        failure_code,
                        erring_hop,
                    }));
                }
                Ok(())
            }
            HtlcSource::Forwarded { inbound_channel, inbound_htlc } => {
                // Relay the failure backward, re-wrapped for our hop.
                let key = (inbound_channel, inbound_htlc);
                let Some(ss) = self.inbound_onion_secrets.get(&key).copied() else {
                    return Ok(());
                };
                let packet = match (reason, malformed_code) {
                    (Some(mut r), _) => {
                        onion::failure::wrap(&ss, &mut r);
                        r
                    }
                    (None, Some(code)) => {
                        // Convert a malformed report into a fresh error.
                        onion::failure::build(&ss, &onion::failure::message(code, &[]))
                    }
                    (None, None) => onion::failure::build(
                        &ss,
                        &onion::failure::message(FAIL_TEMPORARY_CHANNEL_FAILURE, &[]),
                    ),
                };
                let entry = self
                    .channels
                    .get_mut(&inbound_channel)
                    .ok_or(NodeError::ChannelNotFound)?;
                let node_id = entry.node_id;
                if let Some(msg) = entry.channel.send_fail_htlc(inbound_htlc, packet)? {
                    self.send_to_node(&node_id, &WireMessage::UpdateFailHtlc(msg))?;
                    self.flush_commitment(inbound_channel)?;
                }
                Ok(())
            }
        }
    }

    fn on_htlc_failed_locally(
        &mut self,
        source: HtlcSource,
        reason: &str,
    ) -> Result<(), NodeError> {
        log_warn!(self.logger, "holding-cell HTLC dropped: {reason}");
        self.on_htlc_failed(source, None, None)
    }

    // ---------------------------------------------------- HTLC receive

    /// An inbound HTLC is irrevocably committed: peel its onion and either
    /// claim (final hop) or forward.
    fn process_committed_htlc(
        &mut self,
        channel_id: ChannelId,
        htlc: crate::channel::CommittedInboundHtlc,
    ) -> Result<(), NodeError> {
        let packet = match OnionPacket::parse(&htlc.onion) {
            Ok(p) => p,
            Err(_) => {
                return self.fail_inbound_malformed(channel_id, htlc.id, &htlc.onion);
            }
        };
        let ss = self.keys.ecdh(&packet.ephemeral_key);
        let peeled = match onion::peel_with_secret(&ss, &packet, &htlc.payment_hash.0) {
            Ok(p) => p,
            Err(_) => {
                return self.fail_inbound_malformed(channel_id, htlc.id, &htlc.onion);
            }
        };
        self.inbound_onion_secrets.insert((channel_id, htlc.id), ss);

        match peeled {
            Peeled::Final { payload } => {
                let payload = match HopPayload::decode(&payload) {
                    Ok(p) => p,
                    Err(_) => {
                        return self.fail_inbound(
                            channel_id,
                            htlc.id,
                            FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                            &incorrect_payment_data(htlc.amount_msat, self.best_height),
                        )
                    }
                };
                self.receive_final_htlc(channel_id, htlc, payload)
            }
            Peeled::Forward { payload, next } => {
                let payload = match HopPayload::decode(&payload) {
                    Ok(p) => p,
                    Err(_) => {
                        return self.fail_inbound(
                            channel_id,
                            htlc.id,
                            FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                            &[],
                        )
                    }
                };
                self.forward_htlc(channel_id, htlc, payload, next)
            }
        }
    }

    fn receive_final_htlc(
        &mut self,
        channel_id: ChannelId,
        htlc: crate::channel::CommittedInboundHtlc,
        payload: HopPayload,
    ) -> Result<(), NodeError> {
        let fail_data = incorrect_payment_data(htlc.amount_msat, self.best_height);
        let Some(invoice) = self.invoices.get(&htlc.payment_hash) else {
            return self.fail_inbound(
                channel_id,
                htlc.id,
                FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                &fail_data,
            );
        };
        // BOLT 4 final-hop checks.
        let Some(pd) = &payload.payment_data else {
            return self.fail_inbound(
                channel_id,
                htlc.id,
                FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                &fail_data,
            );
        };
        if pd.payment_secret != invoice.payment_secret {
            return self.fail_inbound(
                channel_id,
                htlc.id,
                FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                &fail_data,
            );
        }
        if payload.amt_to_forward > htlc.amount_msat {
            return self.fail_inbound(
                channel_id,
                htlc.id,
                FAIL_FINAL_INCORRECT_AMOUNT,
                &htlc.amount_msat.0.to_be_bytes(),
            );
        }
        if let Some(required) = invoice.amount_msat {
            // Accept [amount, 2*amount] (BOLT 4 overpayment tolerance).
            if htlc.amount_msat < required || htlc.amount_msat.0 > required.0 * 2 {
                return self.fail_inbound(
                    channel_id,
                    htlc.id,
                    FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                    &fail_data,
                );
            }
        }
        if payload.outgoing_cltv_value > htlc.cltv_expiry {
            return self.fail_inbound(
                channel_id,
                htlc.id,
                FAIL_FINAL_INCORRECT_CLTV,
                &htlc.cltv_expiry.to_be_bytes(),
            );
        }
        if htlc.cltv_expiry < self.best_height + invoice.min_final_cltv {
            return self.fail_inbound(
                channel_id,
                htlc.id,
                FAIL_INCORRECT_OR_UNKNOWN_PAYMENT,
                &fail_data,
            );
        }
        self.claimable
            .insert(htlc.payment_hash, (channel_id, htlc.id, htlc.amount_msat));
        self.outputs.push_back(Output::Event(Event::PaymentClaimable {
            payment_hash: htlc.payment_hash,
            amount_msat: htlc.amount_msat,
        }));
        if self.config.auto_claim {
            self.claim_payment(htlc.payment_hash)?;
        }
        Ok(())
    }

    fn forward_htlc(
        &mut self,
        in_channel: ChannelId,
        htlc: crate::channel::CommittedInboundHtlc,
        payload: HopPayload,
        next_packet: OnionPacket,
    ) -> Result<(), NodeError> {
        let Some(scid) = payload.short_channel_id else {
            return self.fail_inbound(in_channel, htlc.id, FAIL_UNKNOWN_NEXT_PEER, &[]);
        };
        let Some(&out_channel) = self.scid_index.get(&scid) else {
            return self.fail_inbound(in_channel, htlc.id, FAIL_UNKNOWN_NEXT_PEER, &[]);
        };
        // Fee and CLTV policy.
        let fee = Msat(
            self.config.forwarding.fee_base_msat as u64
                + payload.amt_to_forward.0
                    * self.config.forwarding.fee_proportional_millionths as u64
                    / 1_000_000,
        );
        if htlc.amount_msat < payload.amt_to_forward + fee {
            return self.fail_inbound(in_channel, htlc.id, FAIL_FEE_INSUFFICIENT, &[]);
        }
        if htlc.cltv_expiry
            < payload.outgoing_cltv_value + self.config.forwarding.cltv_expiry_delta as u32
        {
            return self.fail_inbound(in_channel, htlc.id, FAIL_INCORRECT_CLTV_EXPIRY, &[]);
        }
        let entry = self.channels.get_mut(&out_channel).ok_or(NodeError::ChannelNotFound)?;
        if !entry.channel.is_usable() {
            return self.fail_inbound(in_channel, htlc.id, FAIL_TEMPORARY_CHANNEL_FAILURE, &[]);
        }
        let node_id = entry.node_id;
        let result = entry.channel.send_add_htlc(
            payload.amt_to_forward,
            htlc.payment_hash,
            payload.outgoing_cltv_value,
            next_packet.serialize(),
            HtlcSource::Forwarded { inbound_channel: in_channel, inbound_htlc: htlc.id },
        );
        match result {
            Ok(Some(add)) => {
                let out_htlc = HtlcId(add.id);
                self.forward_fees.insert((out_channel, out_htlc), (in_channel, fee));
                self.send_to_node(&node_id, &WireMessage::UpdateAddHtlc(add))?;
                self.flush_commitment(out_channel)?;
                self.outputs.push_back(Output::Event(Event::Forwarded {
                    inbound_channel: in_channel,
                    outbound_channel: out_channel,
                    fee_msat: fee,
                }));
                Ok(())
            }
            Ok(None) => Ok(()), // parked in the holding cell
            Err(ChannelError::Ignore(_)) => {
                self.fail_inbound(in_channel, htlc.id, FAIL_TEMPORARY_CHANNEL_FAILURE, &[])
            }
            Err(e) => Err(e.into()),
        }
    }

    fn fail_inbound(
        &mut self,
        channel_id: ChannelId,
        htlc_id: HtlcId,
        code: u16,
        data: &[u8],
    ) -> Result<(), NodeError> {
        let Some(ss) = self.inbound_onion_secrets.get(&(channel_id, htlc_id)).copied() else {
            return Ok(());
        };
        let reason = onion::failure::build(&ss, &onion::failure::message(code, data));
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;
        if let Some(msg) = entry.channel.send_fail_htlc(htlc_id, reason)? {
            self.send_to_node(&node_id, &WireMessage::UpdateFailHtlc(msg))?;
            self.flush_commitment(channel_id)?;
        }
        Ok(())
    }

    /// We could not even derive an onion shared secret, so we cannot build
    /// an error onion — report malformed and let the upstream peer do it.
    fn fail_inbound_malformed(
        &mut self,
        channel_id: ChannelId,
        htlc_id: HtlcId,
        onion_bytes: &[u8],
    ) -> Result<(), NodeError> {
        let sha = crate::crypto::sha256(onion_bytes);
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let node_id = entry.node_id;
        if let Some(out) =
            entry.channel.send_fail_malformed_htlc(htlc_id, sha, FAIL_INVALID_ONION_HMAC)?
        {
            self.send_to_node(&node_id, &WireMessage::UpdateFailMalformedHtlc(out))?;
            self.flush_commitment(channel_id)?;
        }
        Ok(())
    }

    // ----------------------------------------------------------- helpers

    /// Run a channel operation; on protocol violation, send `error`,
    /// force-close, and surface the failure.
    fn with_channel<T>(
        &mut self,
        peer_id: PeerId,
        channel_id: ChannelId,
        f: impl FnOnce(&mut Channel<K::Signer>) -> Result<T, ChannelError>,
    ) -> Result<T, NodeError> {
        let entry = self.channels.get_mut(&channel_id).ok_or(NodeError::ChannelNotFound)?;
        let expected_peer = self.by_node_id.get(&entry.node_id).copied();
        if expected_peer != Some(peer_id) {
            return Err(NodeError::ChannelNotFound);
        }
        match f(&mut entry.channel) {
            Ok(v) => Ok(v),
            Err(ChannelError::Close(text)) => {
                log_error!(self.logger, "channel {channel_id:?} failed: {text}");
                let err = msgs::ErrorMsg { channel_id, data: text.clone().into_bytes() };
                let _ = self.send_to_peer(peer_id, &WireMessage::Error(err));
                let _ = self.force_close(channel_id, &text);
                Err(NodeError::Channel(ChannelError::Close(text)))
            }
            Err(e) => Err(NodeError::Channel(e)),
        }
    }
}

fn incorrect_payment_data(amount: Msat, height: u32) -> Vec<u8> {
    // incorrect_or_unknown_payment_details: [u64 htlc_msat][u32 height]
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&amount.0.to_be_bytes());
    v.extend_from_slice(&height.to_be_bytes());
    v
}

fn dummy_sig() -> secp256k1::ecdsa::Signature {
    let secp = Secp256k1::signing_only();
    let sk = SecretKey::from_slice(&[1u8; 32]).expect("valid");
    secp.sign_ecdsa(&secp256k1::Message::from_digest([0u8; 32]), &sk)
}

#[cfg(test)]
mod tests;
