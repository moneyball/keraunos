//! Router tests over a synthetic graph.

use super::*;
use crate::bitcoin::sha256d;
use crate::graph::NetworkGraph;
use crate::types::Network;
use crate::wire::msgs::{ChannelAnnouncement, ChannelUpdate};
use crate::wire::Features;
use secp256k1::{Message, Secp256k1, SecretKey};

struct TestNet {
    graph: NetworkGraph,
    keys: Vec<(SecretKey, PublicKey)>,
}

impl TestNet {
    fn new(n: u8) -> TestNet {
        let secp = Secp256k1::new();
        let keys = (1..=n)
            .map(|i| {
                let sk = SecretKey::from_slice(&[i; 32]).unwrap();
                (sk, sk.public_key(&secp))
            })
            .collect();
        TestNet { graph: NetworkGraph::new(Network::Regtest), keys }
    }

    fn node(&self, i: usize) -> PublicKey {
        self.keys[i].1
    }

    /// Bidirectional channel i<->j with per-direction (base, ppm, cltv).
    fn channel(
        &mut self,
        scid: u64,
        i: usize,
        j: usize,
        policy_ij: (u32, u32, u16),
        policy_ji: (u32, u32, u16),
    ) {
        let secp = Secp256k1::new();
        let scid = ShortChannelId(scid);
        let (a, b) = (&self.keys[i], &self.keys[j]);
        let (n1, n2, ij_is_one_to_two) = if a.1.serialize() < b.1.serialize() {
            (a, b, true)
        } else {
            (b, a, false)
        };
        let mut ann = ChannelAnnouncement {
            node_signature_1: dummy_sig(),
            node_signature_2: dummy_sig(),
            bitcoin_signature_1: dummy_sig(),
            bitcoin_signature_2: dummy_sig(),
            features: Features::empty(),
            chain_hash: Network::Regtest.chain_hash(),
            short_channel_id: scid,
            node_id_1: n1.1,
            node_id_2: n2.1,
            bitcoin_key_1: n1.1,
            bitcoin_key_2: n2.1,
        };
        let hash = sha256d(&ann.signed_payload());
        let m = Message::from_digest(hash);
        ann.node_signature_1 = secp.sign_ecdsa(&m, &n1.0);
        ann.node_signature_2 = secp.sign_ecdsa(&m, &n2.0);
        ann.bitcoin_signature_1 = secp.sign_ecdsa(&m, &n1.0);
        ann.bitcoin_signature_2 = secp.sign_ecdsa(&m, &n2.0);
        self.graph.apply_channel_announcement(&ann, Some(10_000_000)).unwrap();

        for (from_node_1, (base, ppm, cltv), signer) in [
            (ij_is_one_to_two, policy_ij, if ij_is_one_to_two { n1 } else { n2 }),
            (!ij_is_one_to_two, policy_ji, if ij_is_one_to_two { n2 } else { n1 }),
        ] {
            let mut upd = ChannelUpdate {
                signature: dummy_sig(),
                chain_hash: Network::Regtest.chain_hash(),
                short_channel_id: scid,
                timestamp: 100,
                message_flags: 1,
                channel_flags: if from_node_1 { 0 } else { 1 },
                cltv_expiry_delta: cltv,
                htlc_minimum_msat: Msat(1),
                fee_base_msat: base,
                fee_proportional_millionths: ppm,
                htlc_maximum_msat: Msat(10_000_000_000),
            };
            let hash = sha256d(&upd.signed_payload());
            upd.signature = secp.sign_ecdsa(&Message::from_digest(hash), &signer.0);
            self.graph.apply_channel_update(&upd).unwrap();
        }
    }
}

fn dummy_sig() -> secp256k1::ecdsa::Signature {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1; 32]).unwrap();
    secp.sign_ecdsa(&Message::from_digest([0; 32]), &sk)
}

fn first_hops(net: &TestNet, payer: usize, peers: &[(usize, u64, Msat)]) -> Vec<FirstHop> {
    let _ = payer;
    peers
        .iter()
        .map(|(peer, scid, avail)| FirstHop {
            peer: net.node(*peer),
            short_channel_id: ShortChannelId(*scid),
            available_msat: *avail,
        })
        .collect()
}

/// Diamond: 0 -(1)- 1 -(2)- 3, 0 -(3)- 2 -(4)- 3. Path through 1 is cheap,
/// through 2 is expensive.
#[test]
fn picks_cheaper_path() {
    let mut net = TestNet::new(4);
    net.channel(1, 0, 1, (0, 0, 6), (0, 0, 6));
    net.channel(2, 1, 3, (1_000, 100, 40), (1_000, 100, 40));
    net.channel(3, 0, 2, (0, 0, 6), (0, 0, 6));
    net.channel(4, 2, 3, (50_000, 5_000, 40), (50_000, 5_000, 40));

    let params = RouteParams {
        payer: net.node(0),
        payee: net.node(3),
        amount_msat: Msat(1_000_000),
        final_cltv_expiry: 800_000 + 18,
        first_hops: &first_hops(&net, 0, &[(1, 1, Msat(50_000_000)), (2, 3, Msat(50_000_000))]),
        route_hints: &[],
        max_hops: 20,
    };
    let route = find_route(&net.graph, &DefaultScorer::default(), &params).unwrap();
    assert_eq!(route.hops.len(), 2);
    assert_eq!(route.hops[0].node_id, net.node(1), "must route via the cheap node");
    assert_eq!(route.hops[1].node_id, net.node(3));
    // Last hop delivers exactly the requested amount at the final CLTV.
    assert_eq!(route.hops[1].amount_msat, Msat(1_000_000));
    assert_eq!(route.hops[1].cltv_expiry, 800_018);
    // First hop carries amount + node 1's fee (1000 base + 100ppm of 1M = 1100).
    assert_eq!(route.first_hop_amount_msat, Msat(1_001_100));
    assert_eq!(route.first_hop_cltv, 800_018 + 40);
}

#[test]
fn respects_first_hop_liquidity() {
    let mut net = TestNet::new(4);
    net.channel(1, 0, 1, (0, 0, 6), (0, 0, 6));
    net.channel(2, 1, 3, (1_000, 100, 40), (1_000, 100, 40));
    net.channel(3, 0, 2, (0, 0, 6), (0, 0, 6));
    net.channel(4, 2, 3, (50_000, 5_000, 40), (50_000, 5_000, 40));

    // The cheap peer has no liquidity: must fall back to the pricey path.
    let params = RouteParams {
        payer: net.node(0),
        payee: net.node(3),
        amount_msat: Msat(1_000_000),
        final_cltv_expiry: 800_018,
        first_hops: &first_hops(&net, 0, &[(1, 1, Msat(10)), (2, 3, Msat(50_000_000))]),
        route_hints: &[],
        max_hops: 20,
    };
    let route = find_route(&net.graph, &DefaultScorer::default(), &params).unwrap();
    assert_eq!(route.hops[0].node_id, net.node(2));
}

#[test]
fn no_route_without_first_hops() {
    let mut net = TestNet::new(2);
    net.channel(1, 0, 1, (0, 0, 6), (0, 0, 6));
    let params = RouteParams {
        payer: net.node(0),
        payee: net.node(1),
        amount_msat: Msat(1_000),
        final_cltv_expiry: 100,
        first_hops: &[],
        route_hints: &[],
        max_hops: 20,
    };
    assert_eq!(
        find_route(&net.graph, &DefaultScorer::default(), &params).unwrap_err(),
        RouteError::NoPath
    );
}

#[test]
fn route_hint_reaches_private_node() {
    // Public: 0 - 1. Private: 1 - 9 (only known via invoice hint).
    let mut net = TestNet::new(10);
    net.channel(1, 0, 1, (0, 0, 6), (0, 0, 6));
    let hint = vec![crate::invoice::RouteHintHop {
        src_node_id: net.node(1),
        short_channel_id: ShortChannelId(99),
        fee_base_msat: 200,
        fee_proportional_millionths: 0,
        cltv_expiry_delta: 12,
    }];
    let params = RouteParams {
        payer: net.node(0),
        payee: net.node(9),
        amount_msat: Msat(500_000),
        final_cltv_expiry: 800_018,
        first_hops: &first_hops(&net, 0, &[(1, 1, Msat(50_000_000))]),
        route_hints: &[hint],
        max_hops: 20,
    };
    let route = find_route(&net.graph, &DefaultScorer::default(), &params).unwrap();
    assert_eq!(route.hops.len(), 2);
    assert_eq!(route.hops[1].short_channel_id, ShortChannelId(99));
    assert_eq!(route.hops[1].amount_msat, Msat(500_000));
    // Node 1 charges its hint fee on the first hop.
    assert_eq!(route.first_hop_amount_msat, Msat(500_200));
}

#[test]
fn direct_payment_needs_no_graph() {
    // Payee is our direct peer: first-hop only, empty graph.
    let net = TestNet::new(2);
    let params = RouteParams {
        payer: net.node(0),
        payee: net.node(1),
        amount_msat: Msat(42_000),
        final_cltv_expiry: 123,
        first_hops: &first_hops(&net, 0, &[(1, 7, Msat(1_000_000))]),
        route_hints: &[],
        max_hops: 20,
    };
    let route = find_route(&net.graph, &DefaultScorer::default(), &params).unwrap();
    assert_eq!(route.hops.len(), 1);
    assert_eq!(route.first_hop_amount_msat, Msat(42_000));
    assert_eq!(route.first_hop_cltv, 123);
}
