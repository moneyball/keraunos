//! Interoperability test against rust-lightning (LDK).
//!
//! A real LDK `ChannelManager`/`PeerManager` talks to a keraunos `Node`
//! through an in-memory pipe: BOLT 8 handshake, init, channel open and
//! funding, payments in both directions, and cooperative close — every
//! byte produced by one implementation parsed and verified by the other.
#![recursion_limit = "256"]

use keraunos::bitcoin::{OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use keraunos::node::{Event as KEvent, Node, NodeConfig, Output, PeerId};
use keraunos::sign::{KeysManager as KKeysManager, TestEntropy};
use keraunos::types::{ChannelId, Msat, Network, ShortChannelId};

use bitcoin::block::{Header, Version};
use bitcoin::consensus::deserialize;
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::{chainmonitor, BestBlock, Confirm, Filter};
use lightning::events::{Event as LdkEvent, ReplayEvent};
use lightning::ln::channelmanager::{
    Bolt11InvoiceParameters, ChainParameters, ChannelManager, PaymentId as LdkPaymentId, Retry,
};
use lightning::routing::router::RouteParametersConfig;
use lightning::ln::msgs::SocketAddress;
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler, PeerManager, SocketDescriptor,
};
use lightning::onion_message::messenger::DefaultMessageRouter;
use lightning::routing::gossip::NetworkGraph;
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::{
    ProbabilisticScorer, ProbabilisticScoringDecayParameters, ProbabilisticScoringFeeParameters,
};
use lightning::sign::{EntropySource as _, KeysManager, NodeSigner as _, Recipient};
use lightning::util::config::UserConfig;
use lightning::util::logger::{Logger, Record};
use lightning::util::persist::KVStoreSync;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- LDK glue

struct TestLogger;
impl Logger for TestLogger {
    fn log(&self, record: Record) {
        use lightning::util::logger::Level;
        if record.level >= Level::Warn {
            eprintln!("LDK {}: {}", record.level, record.args);
        }
    }
}

struct TestFeeEstimator;
impl lightning::chain::chaininterface::FeeEstimator for TestFeeEstimator {
    fn get_est_sat_per_1000_weight(
        &self,
        _t: lightning::chain::chaininterface::ConfirmationTarget,
    ) -> u32 {
        253
    }
}

#[derive(Default)]
struct TestBroadcaster {
    txs: Mutex<Vec<bitcoin::Transaction>>,
}
impl lightning::chain::chaininterface::BroadcasterInterface for TestBroadcaster {
    fn broadcast_transactions(&self, txs: &[&bitcoin::Transaction]) {
        self.txs.lock().unwrap().extend(txs.iter().map(|t| (*t).clone()));
    }
}

/// Minimal in-memory KVStore for the monitor persister.
#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}
impl KVStoreSync for MemStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, lightning::io::Error> {
        let k = format!("{primary_namespace}/{secondary_namespace}/{key}");
        self.map
            .lock()
            .unwrap()
            .get(&k)
            .cloned()
            .ok_or_else(|| lightning::io::Error::new(lightning::io::ErrorKind::NotFound, "missing"))
    }
    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), lightning::io::Error> {
        let k = format!("{primary_namespace}/{secondary_namespace}/{key}");
        self.map.lock().unwrap().insert(k, buf);
        Ok(())
    }
    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        _lazy: bool,
    ) -> Result<(), lightning::io::Error> {
        let k = format!("{primary_namespace}/{secondary_namespace}/{key}");
        self.map.lock().unwrap().remove(&k);
        Ok(())
    }
    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, lightning::io::Error> {
        let prefix = format!("{primary_namespace}/{secondary_namespace}/");
        Ok(self
            .map
            .lock()
            .unwrap()
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(|s| s.to_string()))
            .collect())
    }
}

/// An in-memory "socket": LDK writes here, the pump drains into keraunos.
#[derive(Clone)]
struct PipeDescriptor {
    id: u64,
    outbox: Arc<Mutex<Vec<u8>>>,
}
impl PartialEq for PipeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for PipeDescriptor {}
impl std::hash::Hash for PipeDescriptor {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.id.hash(h)
    }
}
impl SocketDescriptor for PipeDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        self.outbox.lock().unwrap().extend_from_slice(data);
        data.len()
    }
    fn disconnect_socket(&mut self) {}
}

type Logger_ = Arc<TestLogger>;
type Monitor = ChainMonitor<
    lightning::sign::InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<TestBroadcaster>,
    Arc<TestFeeEstimator>,
    Logger_,
    Arc<lightning::util::persist::MonitorUpdatingPersister<
        Arc<MemStore>,
        Logger_,
        Arc<KeysManager>,
        Arc<KeysManager>,
        Arc<TestBroadcaster>,
        Arc<TestFeeEstimator>,
    >>,
    Arc<KeysManager>,
>;
type Graph = NetworkGraph<Logger_>;
type Scorer = ProbabilisticScorer<Arc<Graph>, Logger_>;
type Router = DefaultRouter<
    Arc<Graph>,
    Logger_,
    Arc<KeysManager>,
    Arc<Mutex<Scorer>>,
    ProbabilisticScoringFeeParameters,
    Scorer,
>;
type MsgRouter = DefaultMessageRouter<Arc<Graph>, Logger_, Arc<KeysManager>>;
type Manager = ChannelManager<
    Arc<Monitor>,
    Arc<TestBroadcaster>,
    Arc<KeysManager>,
    Arc<KeysManager>,
    Arc<KeysManager>,
    Arc<TestFeeEstimator>,
    Arc<Router>,
    Arc<MsgRouter>,
    Logger_,
>;
type Peers = PeerManager<
    PipeDescriptor,
    Arc<Manager>,
    IgnoringMessageHandler,
    IgnoringMessageHandler,
    Logger_,
    IgnoringMessageHandler,
    Arc<KeysManager>,
    IgnoringMessageHandler,
>;

struct LdkNode {
    keys: Arc<KeysManager>,
    manager: Arc<Manager>,
    peers: Arc<Peers>,
    monitor: Arc<Monitor>,
    broadcaster: Arc<TestBroadcaster>,
    events: Arc<Mutex<Vec<LdkEvent>>>,
    best_hash: BlockHash,
    height: u32,
}

fn fake_header(prev: BlockHash, time: u32) -> Header {
    Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::all_zeros(),
        time,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    }
}

impl LdkNode {
    fn new(seed: [u8; 32]) -> LdkNode {
        let logger: Logger_ = Arc::new(TestLogger);
        let fee = Arc::new(TestFeeEstimator);
        let broadcaster = Arc::new(TestBroadcaster::default());
        let keys = Arc::new(KeysManager::new(&seed, 42, 42, false));
        let store = Arc::new(MemStore::default());
        let persister = Arc::new(lightning::util::persist::MonitorUpdatingPersister::new(
            store,
            logger.clone(),
            5,
            keys.clone(),
            keys.clone(),
            broadcaster.clone(),
            fee.clone(),
        ));
        let monitor: Arc<Monitor> = Arc::new(chainmonitor::ChainMonitor::new(
            None,
            broadcaster.clone(),
            logger.clone(),
            fee.clone(),
            persister,
            keys.clone(),
            keys.get_peer_storage_key(),
        ));
        let graph = Arc::new(Graph::new(bitcoin::Network::Regtest, logger.clone()));
        let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
            ProbabilisticScoringDecayParameters::default(),
            graph.clone(),
            logger.clone(),
        )));
        let router = Arc::new(DefaultRouter::new(
            graph.clone(),
            logger.clone(),
            keys.clone(),
            scorer,
            ProbabilisticScoringFeeParameters::default(),
        ));
        let msg_router = Arc::new(DefaultMessageRouter::new(graph, keys.clone()));
        let mut config = UserConfig::default();
        config.channel_handshake_limits.force_announced_channel_preference = false;
        config.channel_handshake_config.minimum_depth = 1;
        let best = BestBlock::from_network(bitcoin::Network::Regtest);
        let manager: Arc<Manager> = Arc::new(ChannelManager::new(
            fee,
            monitor.clone(),
            broadcaster.clone(),
            router,
            msg_router,
            logger.clone(),
            keys.clone(),
            keys.clone(),
            keys.clone(),
            config,
            ChainParameters { network: bitcoin::Network::Regtest, best_block: best },
            42,
        ));
        let handler = MessageHandler {
            chan_handler: manager.clone(),
            route_handler: IgnoringMessageHandler {},
            onion_message_handler: IgnoringMessageHandler {},
            custom_message_handler: IgnoringMessageHandler {},
            send_only_message_handler: IgnoringMessageHandler {},
        };
        let peers = Arc::new(PeerManager::new(
            handler,
            42,
            &keys.get_secure_random_bytes(),
            logger,
            keys.clone(),
        ));
        LdkNode {
            keys,
            manager,
            peers,
            monitor,
            broadcaster,
            events: Arc::new(Mutex::new(Vec::new())),
            best_hash: best.block_hash,
            height: best.height,
        }
    }

    fn node_id(&self) -> bitcoin::secp256k1::PublicKey {
        self.keys.get_node_id(Recipient::Node).unwrap()
    }

    /// Process pending events into the stash. LDK gates some protocol
    /// progress (e.g. the post-claim RAA) on events being handled, so this
    /// must run *inside* the message pump, not just at assertion time.
    fn poll_events(&self) {
        let events = self.events.clone();
        let handler = move |event: LdkEvent| -> Result<(), ReplayEvent> {
            events.lock().unwrap().push(event);
            Ok(())
        };
        lightning::events::EventsProvider::process_pending_events(&*self.manager, &handler);
        lightning::events::EventsProvider::process_pending_events(&*self.monitor, &handler);
    }

    fn drain_events(&self) -> Vec<LdkEvent> {
        self.poll_events();
        std::mem::take(&mut self.events.lock().unwrap())
    }

    /// Mine `n` fake blocks, confirming `txs` in the first one.
    fn mine(&mut self, txs: &[&bitcoin::Transaction], n: u32) {
        for i in 0..n {
            let header = fake_header(self.best_hash, 1_700_000_000 + self.height + i);
            self.height += 1;
            self.best_hash = header.block_hash();
            if i == 0 && !txs.is_empty() {
                let txdata: Vec<(usize, &bitcoin::Transaction)> =
                    txs.iter().enumerate().map(|(j, tx)| (j + 1, *tx)).collect();
                self.manager.transactions_confirmed(&header, &txdata, self.height);
                self.monitor.transactions_confirmed(&header, &txdata, self.height);
            }
            self.manager.best_block_updated(&header, self.height);
            self.monitor.best_block_updated(&header, self.height);
        }
    }
}

// ------------------------------------------------------------- the harness

struct Interop {
    k: Node<KKeysManager, TestEntropy>,
    k_peer: PeerId,
    ldk: LdkNode,
    pipe: PipeDescriptor,
    k_events: Vec<KEvent>,
    k_broadcasts: Vec<Transaction>,
}

impl Interop {
    /// keraunos dials LDK.
    fn connect(k_seed: [u8; 32], ldk_seed: [u8; 32]) -> Interop {
        let close_script = Script::new_p2wpkh(&[0x77; 20]);
        let mut k = Node::new(
            KKeysManager::new(k_seed),
            TestEntropy::new([0x99; 32]),
            NodeConfig::new(Network::Regtest, close_script),
        );
        let ldk = LdkNode::new(ldk_seed);
        let ldk_id = keraunos_pubkey(&ldk.node_id());
        let (k_peer, act1) = k.connect_outbound(ldk_id);

        let pipe = PipeDescriptor { id: 1, outbox: Arc::new(Mutex::new(Vec::new())) };
        ldk.peers
            .new_inbound_connection(pipe.clone(), None::<SocketAddress>)
            .expect("inbound registered");
        let mut h = Interop {
            k,
            k_peer,
            ldk,
            pipe,
            k_events: Vec::new(),
            k_broadcasts: Vec::new(),
        };
        // The engine is sans-I/O: the embedder owns the clock. Without this,
        // invoices would be timestamped at the unix epoch.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        h.k.tick(now);
        h.ldk_read(&act1);
        h.pump();
        h
    }

    fn ldk_read(&mut self, data: &[u8]) {
        let mut desc = self.pipe.clone();
        self.ldk.peers.read_event(&mut desc, data).expect("LDK accepted bytes");
        self.ldk.peers.process_events();
    }

    /// Shuttle bytes both ways until quiescent.
    fn pump(&mut self) {
        let mut idle_rounds = 0;
        for _ in 0..200 {
            let mut moved = false;
            // keraunos → LDK
            while let Some(out) = self.k.poll_output() {
                match out {
                    Output::Wire { bytes, .. } => {
                        self.ldk_read(&bytes);
                        moved = true;
                    }
                    Output::Broadcast(tx) => self.k_broadcasts.push(tx),
                    Output::Event(e) => self.k_events.push(e),
                    Output::WatchFunding { .. } => {}
                }
            }
            // LDK → keraunos
            let bytes = std::mem::take(&mut *self.pipe.outbox.lock().unwrap());
            if !bytes.is_empty() {
                self.k.peer_input(self.k_peer, &bytes).expect("keraunos accepted bytes");
                moved = true;
            }
            // Stand-in for LDK's background processor. Monitor-update
            // completion releases messages in *stages*, each needing another
            // poll — so quiescence requires a few consecutive idle rounds.
            self.ldk.manager.process_pending_htlc_forwards();
            self.ldk.poll_events();
            self.ldk.peers.process_events();
            let outbox_pending = !self.pipe.outbox.lock().unwrap().is_empty();
            if !moved && !outbox_pending {
                idle_rounds += 1;
                if idle_rounds > 4 {
                    break;
                }
            } else {
                idle_rounds = 0;
            }
        }
    }

    fn take_k_events(&mut self) -> Vec<KEvent> {
        std::mem::take(&mut self.k_events)
    }

    /// keraunos opens a channel to LDK and both sides confirm it.
    fn open_channel(&mut self, sat: u64) -> (ChannelId, ShortChannelId) {
        let ldk_id = keraunos_pubkey(&self.ldk.node_id());
        let temp = self.k.open_channel(ldk_id, sat, Msat::ZERO).unwrap();
        self.pump();
        let (script, value) = self
            .take_k_events()
            .into_iter()
            .find_map(|e| match e {
                KEvent::FundingRequired { channel_id, script, value_sat }
                    if channel_id == temp =>
                {
                    Some((script, value_sat))
                }
                _ => None,
            })
            .expect("LDK accepted; funding requested");
        let funding_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid([0xaa; 32]), 0),
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: vec![],
            }],
            output: vec![TxOut { value, script_pubkey: script }],
        };
        let channel_id = self.k.provide_funding_transaction(temp, funding_tx.clone()).unwrap();
        self.pump();
        assert!(
            !self.k_broadcasts.is_empty(),
            "keraunos must broadcast the funding tx after funding_signed"
        );

        // Confirm on both sides: LDK mines it at the next height, index 1.
        let btc_funding: bitcoin::Transaction =
            deserialize(&funding_tx.serialize()).expect("valid tx bytes");
        let height = self.ldk.height + 1;
        self.ldk.mine(&[&btc_funding], 7);
        let scid = ShortChannelId::new(height, 1, 0);
        self.k.best_block_updated(self.ldk.height);
        self.k.funding_confirmed(channel_id, scid).unwrap();
        self.pump();
        // LDK should now consider the channel usable.
        let usable = self.ldk.manager.list_usable_channels();
        assert_eq!(usable.len(), 1, "LDK sees the channel as usable");
        (channel_id, scid)
    }
}

/// Convert an LDK secp pubkey (rust-bitcoin's secp) to keraunos's secp type.
fn keraunos_pubkey(pk: &bitcoin::secp256k1::PublicKey) -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_slice(&pk.serialize()).expect("valid point")
}

#[test]
fn handshake_init_and_ping() {
    let mut h = Interop::connect([1; 32], [2; 32]);
    let evs = h.take_k_events();
    assert!(
        evs.iter().any(|e| matches!(e, KEvent::PeerConnected { .. })),
        "handshake + init completed: {evs:?}"
    );
    assert_eq!(h.ldk.peers.list_peers().len(), 1, "LDK sees keraunos as a peer");

    // Keepalive across implementations.
    h.k.tick(1_000_000);
    h.pump();
    h.k.tick(1_000_031);
    h.pump();
    assert_eq!(h.ldk.peers.list_peers().len(), 1, "still connected after pings");
}

#[test]
fn open_channel_and_pay_both_directions() {
    let mut h = Interop::connect([3; 32], [4; 32]);
    let (channel_id, _scid) = h.open_channel(1_000_000);
    let evs = h.take_k_events();
    assert!(
        evs.iter().any(|e| matches!(e, KEvent::ChannelReady { .. })),
        "keraunos channel ready: {evs:?}"
    );
    let ldk_events = h.ldk.drain_events();
    assert!(
        ldk_events.iter().any(|e| matches!(e, LdkEvent::ChannelReady { .. })),
        "LDK channel ready: {ldk_events:?}"
    );

    // --- keraunos pays an LDK invoice (LDK-minted BOLT 11) ---------------
    // keraunos funded the channel, so it owns the initial liquidity.
    let ldk_invoice = h
        .ldk
        .manager
        .create_bolt11_invoice(Bolt11InvoiceParameters {
            amount_msats: Some(90_000_000),
            description: lightning_invoice::Bolt11InvoiceDescription::Direct(
                lightning_invoice::Description::new("keraunos->ldk".into()).unwrap(),
            ),
            ..Default::default()
        })
        .expect("LDK invoice");
    let invoice =
        keraunos::invoice::Bolt11Invoice::parse(&ldk_invoice.to_string()).expect("we parse LDK's invoice");
    h.k.pay_invoice(&invoice, None).expect("route to LDK exists");
    h.pump();
    let ldk_events = h.ldk.drain_events();
    let claimable = ldk_events.iter().find_map(|e| match e {
        LdkEvent::PaymentClaimable { purpose, .. } => purpose.preimage(),
        _ => None,
    });
    let preimage = claimable.expect("LDK saw the HTLC and knows the preimage");
    h.ldk.manager.claim_funds(preimage);
    h.ldk.peers.process_events();
    h.pump();
    let ldk_events = h.ldk.drain_events();
    assert!(
        ldk_events.iter().any(|e| matches!(e, LdkEvent::PaymentClaimed { .. })),
        "LDK claimed: {ldk_events:?}"
    );
    let evs = h.take_k_events();
    assert!(
        evs.iter().any(|e| matches!(e, KEvent::PaymentSent { .. })),
        "keraunos payment completed: {evs:?}"
    );
    assert_eq!(
        h.k.channel_balance_msat(&channel_id),
        Some(Msat(1_000_000_000 - 90_000_000)),
        "keraunos balance reflects the sent payment"
    );

    // --- LDK pays a keraunos invoice back (real BOLT 11 across stacks) ---
    let (encoded, _hash) = h.k.create_invoice(Some(Msat(80_000_000)), "ldk->keraunos", 3600).unwrap();
    let parsed: lightning_invoice::Bolt11Invoice = encoded.parse().expect("LDK parses our invoice");
    h.ldk
        .manager
        .pay_for_bolt11_invoice(
            &parsed,
            LdkPaymentId([7; 32]),
            None,
            RouteParametersConfig::default(),
            Retry::Attempts(0),
        )
        .expect("LDK initiated payment");
    h.ldk.peers.process_events();
    h.pump();
    // Claimable → claimed on the keraunos side (auto-claim).
    let evs = h.take_k_events();
    assert!(
        evs.iter().any(|e| matches!(
            e,
            KEvent::PaymentClaimed { amount_msat, .. } if *amount_msat == Msat(80_000_000)
        )),
        "keraunos claimed: {evs:?}"
    );
    h.pump();
    let ldk_events = h.ldk.drain_events();
    assert!(
        ldk_events.iter().any(|e| matches!(e, LdkEvent::PaymentSent { .. })),
        "LDK got the preimage back: {ldk_events:?}"
    );
    assert_eq!(
        h.k.channel_balance_msat(&channel_id),
        Some(Msat(1_000_000_000 - 90_000_000 + 80_000_000)),
        "keraunos balance reflects both payments"
    );

    // --- cooperative close ----------------------------------------------
    h.k.close_channel(channel_id).unwrap();
    h.pump();
    let evs = h.take_k_events();
    let k_close_txid = evs
        .iter()
        .find_map(|e| match e {
            KEvent::ChannelClosed { closing_txid, .. } => *closing_txid,
            _ => None,
        })
        .expect("keraunos negotiated the close");
    // Both implementations must broadcast the *same* transaction.
    let ldk_txs = h.ldk.broadcaster.txs.lock().unwrap();
    let ldk_close = ldk_txs
        .iter()
        .find(|tx| tx.compute_txid().to_string() == k_close_txid.to_display_hex());
    assert!(
        ldk_close.is_some(),
        "LDK broadcast the agreed closing tx {k_close_txid}; LDK txs: {}",
        ldk_txs.len()
    );
}
