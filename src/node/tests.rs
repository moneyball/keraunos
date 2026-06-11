//! Whole-node tests: an in-process network of real nodes exchanging real
//! encrypted wire bytes, opening channels and routing payments.

use super::*;
use crate::sign::{KeysManager, TestEntropy};
use std::collections::HashMap;

type TNode = Node<KeysManager, TestEntropy>;

struct Harness {
    nodes: Vec<TNode>,
    links: HashMap<(usize, PeerId), (usize, PeerId)>,
    events: Vec<Vec<Event>>,
    broadcasts: Vec<Vec<Transaction>>,
    scid_counter: u32,
}

impl Harness {
    fn new(n: usize) -> Harness {
        let nodes = (0..n)
            .map(|i| {
                let seed = [(i + 1) as u8; 32];
                let close_script = Script::new_p2wpkh(&[(i + 1) as u8; 20]);
                Node::new(
                    KeysManager::new(seed),
                    TestEntropy::new([(i + 0x40) as u8; 32]),
                    NodeConfig::new(Network::Regtest, close_script),
                )
            })
            .collect();
        Harness {
            nodes,
            links: HashMap::new(),
            events: (0..n).map(|_| Vec::new()).collect(),
            broadcasts: (0..n).map(|_| Vec::new()).collect(),
            scid_counter: 0,
        }
    }

    fn id(&self, i: usize) -> secp256k1::PublicKey {
        self.nodes[i].node_id()
    }

    /// TCP-ish: connect node `a` out to node `b` and run the handshake.
    fn connect(&mut self, a: usize, b: usize) {
        let b_node_id = self.id(b);
        let (pa, act1) = self.nodes[a].connect_outbound(b_node_id);
        let pb = self.nodes[b].accept_inbound();
        self.links.insert((a, pa), (b, pb));
        self.links.insert((b, pb), (a, pa));
        self.nodes[b].peer_input(pb, &act1).unwrap();
        self.pump();
    }

    /// Route Wire outputs across links until the network is quiescent.
    fn pump(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                while let Some(out) = self.nodes[i].poll_output() {
                    match out {
                        Output::Wire { peer, bytes } => {
                            let (j, pj) = *self
                                .links
                                .get(&(i, peer))
                                .unwrap_or_else(|| panic!("no link for node {i} peer {peer:?}"));
                            self.nodes[j].peer_input(pj, &bytes).unwrap();
                            moved = true;
                        }
                        Output::Broadcast(tx) => self.broadcasts[i].push(tx),
                        Output::WatchFunding { .. } => {}
                        Output::Event(ev) => self.events[i].push(ev),
                    }
                }
            }
            if !moved {
                break;
            }
        }
    }

    fn take_events(&mut self, i: usize) -> Vec<Event> {
        std::mem::take(&mut self.events[i])
    }

    /// Open and fully confirm a channel a→b. Returns the channel id.
    fn open_channel(&mut self, a: usize, b: usize, sat: u64) -> ChannelId {
        let b_node_id = self.id(b);
        let temp = self.nodes[a].open_channel(b_node_id, sat, Msat::ZERO).unwrap();
        self.pump();
        let (script, value) = self
            .take_events(a)
            .into_iter()
            .find_map(|e| match e {
                Event::FundingRequired { channel_id, script, value_sat }
                    if channel_id == temp =>
                {
                    Some((script, value_sat))
                }
                _ => None,
            })
            .expect("funding required event");
        // A make-believe wallet: one input from nowhere, one funding output.
        let funding_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![crate::bitcoin::TxIn {
                previous_output: OutPoint::new(Txid([self.scid_counter as u8 + 1; 32]), 0),
                script_sig: vec![],
                sequence: 0xffff_fffd,
                witness: vec![],
            }],
            output: vec![crate::bitcoin::TxOut { value, script_pubkey: script }],
        };
        let channel_id = self.nodes[a].provide_funding_transaction(temp, funding_tx).unwrap();
        self.pump();
        assert!(
            self.broadcasts[a]
                .iter()
                .any(|tx| crate::channel::channel_id_from_funding(&tx.txid(), 0) == channel_id),
            "opener must broadcast the funding tx"
        );
        // Both sides see the confirmation.
        self.scid_counter += 1;
        let scid = ShortChannelId::new(100 + self.scid_counter, 1, 0);
        self.nodes[a].funding_confirmed(channel_id, scid).unwrap();
        self.nodes[b].funding_confirmed(channel_id, scid).unwrap();
        self.pump();
        assert!(matches!(
            self.nodes[a].channel_state(&channel_id),
            Some(crate::channel::ChannelState::Normal)
        ));
        assert!(matches!(
            self.nodes[b].channel_state(&channel_id),
            Some(crate::channel::ChannelState::Normal)
        ));
        channel_id
    }

    fn pay(&mut self, from: usize, to: usize, amount: Msat, desc: &str) -> PaymentId {
        let (encoded, _hash) =
            self.nodes[to].create_invoice(Some(amount), desc, 3600).unwrap();
        let invoice = crate::invoice::Bolt11Invoice::parse(&encoded).unwrap();
        let id = self.nodes[from].pay_invoice(&invoice, None).unwrap();
        self.pump();
        id
    }
}

fn has_payment_sent(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::PaymentSent { .. }))
}

#[test]
fn two_nodes_open_pay_and_close() {
    let mut net = Harness::new(2);
    net.connect(0, 1);
    let evs = net.take_events(0);
    assert!(evs.iter().any(|e| matches!(e, Event::PeerConnected { .. })));

    let channel_id = net.open_channel(0, 1, 1_000_000);
    net.take_events(0);
    net.take_events(1);

    // 0 pays 1 directly.
    net.pay(0, 1, Msat(120_000_000), "two coffees");
    let evs0 = net.take_events(0);
    let evs1 = net.take_events(1);
    assert!(has_payment_sent(&evs0), "payer: {evs0:?}");
    assert!(evs1.iter().any(|e| matches!(
        e,
        Event::PaymentClaimed { amount_msat, .. } if *amount_msat == Msat(120_000_000)
    )));
    assert_eq!(
        net.nodes[1].channel_balance_msat(&channel_id),
        Some(Msat(120_000_000))
    );

    // And back the other way.
    net.pay(1, 0, Msat(20_000_000), "refund");
    assert!(has_payment_sent(&net.take_events(1)));
    assert_eq!(
        net.nodes[1].channel_balance_msat(&channel_id),
        Some(Msat(100_000_000))
    );

    // Cooperative close: both sides converge on one transaction.
    net.nodes[0].close_channel(channel_id).unwrap();
    net.pump();
    let closed0 = net.take_events(0);
    let closed1 = net.take_events(1);
    let txid0 = closed0.iter().find_map(|e| match e {
        Event::ChannelClosed { closing_txid, .. } => *closing_txid,
        _ => None,
    });
    let txid1 = closed1.iter().find_map(|e| match e {
        Event::ChannelClosed { closing_txid, .. } => *closing_txid,
        _ => None,
    });
    assert!(txid0.is_some());
    assert_eq!(txid0, txid1, "both sides agree on the closing tx");
    let close_tx = net.broadcasts[0]
        .iter()
        .find(|tx| Some(tx.txid()) == txid0)
        .expect("closing tx broadcast");
    // 900k/100k sat split minus the funder-paid fee.
    let total: u64 = close_tx.output.iter().map(|o| o.value).sum();
    assert!(total > 998_000 && total < 1_000_000, "fee from funder: {total}");
}

#[test]
fn three_nodes_forward_payment() {
    let mut net = Harness::new(3);
    net.connect(0, 1);
    net.connect(1, 2);
    let chan_ab = net.open_channel(0, 1, 1_000_000);
    let chan_bc = net.open_channel(1, 2, 1_000_000);
    for i in 0..3 {
        net.take_events(i);
    }
    // Gossip must have propagated the B↔C channel to node 0.
    assert!(
        net.nodes[0].graph.channel_count() >= 2,
        "node 0 knows {} channels",
        net.nodes[0].graph.channel_count()
    );

    // 0 → 1 → 2, with 1 charging its advertised fee.
    net.pay(0, 2, Msat(50_000_000), "routed");
    let evs0 = net.take_events(0);
    let evs1 = net.take_events(1);
    let evs2 = net.take_events(2);
    assert!(has_payment_sent(&evs0), "payer events: {evs0:?}");
    let forwarded_fee = evs1
        .iter()
        .find_map(|e| match e {
            Event::Forwarded { fee_msat, .. } => Some(*fee_msat),
            _ => None,
        })
        .expect("node 1 forwarded");
    // fee = 1000 base + 100ppm × 50M = 6000 msat.
    assert_eq!(forwarded_fee, Msat(6_000));
    assert!(evs2
        .iter()
        .any(|e| matches!(e, Event::PaymentClaimed { amount_msat, .. } if *amount_msat == Msat(50_000_000))));

    // Balance conservation: B's two channels net out to exactly the fee.
    let b_on_ab = net.nodes[1].channel_balance_msat(&chan_ab).unwrap();
    let b_on_bc = net.nodes[1].channel_balance_msat(&chan_bc).unwrap();
    assert_eq!(b_on_ab, Msat(50_006_000), "B received amount+fee");
    assert_eq!(b_on_bc, Msat(1_000_000_000 - 50_000_000), "B paid out the amount");
}

#[test]
fn underpayment_is_rejected_end_to_end() {
    let mut net = Harness::new(2);
    net.connect(0, 1);
    net.open_channel(0, 1, 1_000_000);
    net.take_events(0);
    net.take_events(1);

    // Invoice for 100k sat, pay only 40k: the recipient must refuse.
    let (encoded, _) = net.nodes[1]
        .create_invoice(Some(Msat(100_000_000)), "full price", 3600)
        .unwrap();
    let invoice = crate::invoice::Bolt11Invoice::parse(&encoded).unwrap();
    net.nodes[0].pay_invoice(&invoice, Some(Msat(40_000_000))).unwrap();
    net.pump();

    let evs0 = net.take_events(0);
    let failed = evs0
        .iter()
        .find_map(|e| match e {
            Event::PaymentFailed { failure_code, .. } => Some(*failure_code),
            _ => None,
        })
        .expect("payment must fail");
    assert_eq!(failed, Some(0x400F), "incorrect_or_unknown_payment_details");
    // Money came back.
    let evs1 = net.take_events(1);
    assert!(!evs1.iter().any(|e| matches!(e, Event::PaymentClaimed { .. })));
    let chan = net.nodes[0].channel_ids()[0];
    assert_eq!(
        net.nodes[0].channel_balance_msat(&chan),
        Some(Msat(1_000_000_000))
    );
}

#[test]
fn reconnect_preserves_channel() {
    let mut net = Harness::new(2);
    net.connect(0, 1);
    let channel_id = net.open_channel(0, 1, 1_000_000);
    // Big enough that node 1 stays above its 1% reserve when paying back.
    net.pay(0, 1, Msat(50_000_000), "before disconnect");

    // Drop the connection on both sides and reconnect.
    let links: Vec<((usize, PeerId), (usize, PeerId))> =
        net.links.iter().map(|(k, v)| (*k, *v)).collect();
    for ((i, pi), _) in links {
        net.nodes[i].peer_disconnected(pi);
    }
    net.links.clear();
    net.connect(0, 1);
    for i in 0..2 {
        net.take_events(i);
    }

    // The channel still works after reestablish.
    net.pay(1, 0, Msat(5_000_000), "after reconnect");
    assert!(has_payment_sent(&net.take_events(1)));
    assert_eq!(
        net.nodes[1].channel_balance_msat(&channel_id),
        Some(Msat(45_000_000))
    );
}
