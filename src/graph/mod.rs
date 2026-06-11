//! The BOLT 7 public network graph: validated gossip, stored as adjacency
//! for the router.

use crate::bitcoin::sha256d;
use crate::types::*;
use crate::wire::msgs::{ChannelAnnouncement, ChannelUpdate, NodeAnnouncement};
use secp256k1::ecdsa::Signature;
use secp256k1::{All, Message, PublicKey, Secp256k1};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipError {
    BadSignature,
    UnknownChannel,
    WrongChain,
    /// Stale or duplicate (not an error worth disconnecting over).
    Ignored,
}

impl core::fmt::Display for GossipError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            GossipError::BadSignature => write!(f, "invalid gossip signature"),
            GossipError::UnknownChannel => write!(f, "channel_update for unknown channel"),
            GossipError::WrongChain => write!(f, "gossip for another chain"),
            GossipError::Ignored => write!(f, "stale or duplicate gossip"),
        }
    }
}

impl std::error::Error for GossipError {}

/// One direction's forwarding policy (from a `channel_update`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectionalInfo {
    pub timestamp: u32,
    pub enabled: bool,
    pub cltv_expiry_delta: u16,
    pub htlc_minimum_msat: Msat,
    pub htlc_maximum_msat: Msat,
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
}

impl DirectionalInfo {
    /// The fee this direction charges to forward `amount`.
    pub fn fee_for(&self, amount: Msat) -> Msat {
        Msat(
            self.fee_base_msat as u64
                + amount.0 * self.fee_proportional_millionths as u64 / 1_000_000,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub node_1: PublicKey,
    pub node_2: PublicKey,
    pub capacity_sat: Option<u64>,
    /// Policy for forwarding *from* node_1 (direction bit 0).
    pub one_to_two: Option<DirectionalInfo>,
    /// Policy for forwarding *from* node_2 (direction bit 1).
    pub two_to_one: Option<DirectionalInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct NodeInfo {
    pub last_timestamp: u32,
    pub alias: [u8; 32],
    pub channels: Vec<ShortChannelId>,
}

pub struct NetworkGraph {
    secp: Secp256k1<All>,
    chain_hash: [u8; 32],
    channels: BTreeMap<ShortChannelId, ChannelInfo>,
    nodes: HashMap<PublicKey, NodeInfo>,
}

impl NetworkGraph {
    pub fn new(network: Network) -> NetworkGraph {
        NetworkGraph {
            secp: Secp256k1::new(),
            chain_hash: network.chain_hash(),
            channels: BTreeMap::new(),
            nodes: HashMap::new(),
        }
    }

    pub fn channel(&self, scid: &ShortChannelId) -> Option<&ChannelInfo> {
        self.channels.get(scid)
    }

    pub fn node(&self, id: &PublicKey) -> Option<&NodeInfo> {
        self.nodes.get(id)
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    fn verify(&self, sig: &Signature, msg_hash: &[u8; 32], key: &PublicKey) -> bool {
        self.secp.verify_ecdsa(&Message::from_digest(*msg_hash), sig, key).is_ok()
    }

    /// Validate and store a `channel_announcement`. The funding-output
    /// existence/value check is the embedder's job (it requires chain
    /// access); pass what you know in `capacity_sat`.
    pub fn apply_channel_announcement(
        &mut self,
        msg: &ChannelAnnouncement,
        capacity_sat: Option<u64>,
    ) -> Result<(), GossipError> {
        if msg.chain_hash != self.chain_hash {
            return Err(GossipError::WrongChain);
        }
        if self.channels.contains_key(&msg.short_channel_id) {
            return Err(GossipError::Ignored);
        }
        if msg.node_id_1.serialize() >= msg.node_id_2.serialize() {
            return Err(GossipError::BadSignature); // ordering is consensus
        }
        let hash = sha256d(&msg.signed_payload());
        if !self.verify(&msg.node_signature_1, &hash, &msg.node_id_1)
            || !self.verify(&msg.node_signature_2, &hash, &msg.node_id_2)
            || !self.verify(&msg.bitcoin_signature_1, &hash, &msg.bitcoin_key_1)
            || !self.verify(&msg.bitcoin_signature_2, &hash, &msg.bitcoin_key_2)
        {
            return Err(GossipError::BadSignature);
        }
        self.channels.insert(
            msg.short_channel_id,
            ChannelInfo {
                node_1: msg.node_id_1,
                node_2: msg.node_id_2,
                capacity_sat,
                one_to_two: None,
                two_to_one: None,
            },
        );
        for node in [msg.node_id_1, msg.node_id_2] {
            self.nodes.entry(node).or_default().channels.push(msg.short_channel_id);
        }
        Ok(())
    }

    pub fn apply_channel_update(&mut self, msg: &ChannelUpdate) -> Result<(), GossipError> {
        if msg.chain_hash != self.chain_hash {
            return Err(GossipError::WrongChain);
        }
        let chan = self
            .channels
            .get_mut(&msg.short_channel_id)
            .ok_or(GossipError::UnknownChannel)?;
        let from_node_1 = msg.channel_flags & 1 == 0;
        let signer = if from_node_1 { chan.node_1 } else { chan.node_2 };
        let hash = sha256d(&msg.signed_payload());
        let sig_ok = Secp256k1::verification_only()
            .verify_ecdsa(&Message::from_digest(hash), &msg.signature, &signer)
            .is_ok();
        if !sig_ok {
            return Err(GossipError::BadSignature);
        }
        let slot = if from_node_1 { &mut chan.one_to_two } else { &mut chan.two_to_one };
        if let Some(existing) = slot {
            if existing.timestamp >= msg.timestamp {
                return Err(GossipError::Ignored);
            }
        }
        *slot = Some(DirectionalInfo {
            timestamp: msg.timestamp,
            enabled: msg.channel_flags & 2 == 0,
            cltv_expiry_delta: msg.cltv_expiry_delta,
            htlc_minimum_msat: msg.htlc_minimum_msat,
            htlc_maximum_msat: msg.htlc_maximum_msat,
            fee_base_msat: msg.fee_base_msat,
            fee_proportional_millionths: msg.fee_proportional_millionths,
        });
        Ok(())
    }

    pub fn apply_node_announcement(&mut self, msg: &NodeAnnouncement) -> Result<(), GossipError> {
        let hash = sha256d(&msg.signed_payload());
        if !self.verify(&msg.signature, &hash, &msg.node_id) {
            return Err(GossipError::BadSignature);
        }
        let node = self.nodes.get_mut(&msg.node_id).ok_or(GossipError::UnknownChannel)?;
        if node.last_timestamp >= msg.timestamp {
            return Err(GossipError::Ignored);
        }
        node.last_timestamp = msg.timestamp;
        node.alias = msg.alias;
        Ok(())
    }

    /// Directed edges usable to *reach* `to` (for the backward router):
    /// `(scid, from_node, policy, capacity)`.
    pub fn edges_into(
        &self,
        to: &PublicKey,
    ) -> impl Iterator<Item = (ShortChannelId, PublicKey, &DirectionalInfo, Option<u64>)> + '_ {
        let to = *to;
        self.nodes
            .get(&to)
            .into_iter()
            .flat_map(|n| n.channels.iter())
            .filter_map(move |scid| {
                let chan = self.channels.get(scid)?;
                // The forwarding policy belongs to the node the HTLC comes FROM.
                let (from, policy) = if chan.node_1 == to {
                    (chan.node_2, chan.two_to_one.as_ref()?)
                } else {
                    (chan.node_1, chan.one_to_two.as_ref()?)
                };
                if !policy.enabled {
                    return None;
                }
                Some((*scid, from, policy, chan.capacity_sat))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Features;
    use secp256k1::SecretKey;

    fn keypair(n: u8) -> (SecretKey, PublicKey) {
        let sk = SecretKey::from_slice(&[n; 32]).unwrap();
        (sk, sk.public_key(&Secp256k1::new()))
    }

    fn announcement(
        scid: ShortChannelId,
        a: &(SecretKey, PublicKey),
        b: &(SecretKey, PublicKey),
    ) -> ChannelAnnouncement {
        let secp = Secp256k1::new();
        // node_1 must be the lesser key.
        let (n1, n2) = if a.1.serialize() < b.1.serialize() { (a, b) } else { (b, a) };
        let mut msg = ChannelAnnouncement {
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
        let hash = sha256d(&msg.signed_payload());
        let m = Message::from_digest(hash);
        msg.node_signature_1 = secp.sign_ecdsa(&m, &n1.0);
        msg.node_signature_2 = secp.sign_ecdsa(&m, &n2.0);
        msg.bitcoin_signature_1 = secp.sign_ecdsa(&m, &n1.0);
        msg.bitcoin_signature_2 = secp.sign_ecdsa(&m, &n2.0);
        msg
    }

    fn update(
        scid: ShortChannelId,
        signer: &(SecretKey, PublicKey),
        from_node_1: bool,
        timestamp: u32,
        fee_base: u32,
    ) -> ChannelUpdate {
        let secp = Secp256k1::new();
        let mut msg = ChannelUpdate {
            signature: dummy_sig(),
            chain_hash: Network::Regtest.chain_hash(),
            short_channel_id: scid,
            timestamp,
            message_flags: 1,
            channel_flags: if from_node_1 { 0 } else { 1 },
            cltv_expiry_delta: 40,
            htlc_minimum_msat: Msat(1),
            fee_base_msat: fee_base,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: Msat(10_000_000_000),
        };
        let hash = sha256d(&msg.signed_payload());
        msg.signature = secp.sign_ecdsa(&Message::from_digest(hash), &signer.0);
        msg
    }

    fn dummy_sig() -> Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1; 32]).unwrap();
        secp.sign_ecdsa(&Message::from_digest([0; 32]), &sk)
    }

    #[test]
    fn announcement_and_update_flow() {
        let mut graph = NetworkGraph::new(Network::Regtest);
        let a = keypair(11);
        let b = keypair(22);
        let scid = ShortChannelId::new(100, 1, 0);

        let ann = announcement(scid, &a, &b);
        graph.apply_channel_announcement(&ann, Some(1_000_000)).unwrap();
        assert_eq!(graph.channel_count(), 1);
        // Duplicate ignored.
        assert_eq!(
            graph.apply_channel_announcement(&ann, None),
            Err(GossipError::Ignored)
        );

        // Update from node_1.
        let n1_is_a = a.1.serialize() < b.1.serialize();
        let n1 = if n1_is_a { &a } else { &b };
        graph.apply_channel_update(&update(scid, n1, true, 100, 1000)).unwrap();
        let chan = graph.channel(&scid).unwrap();
        assert!(chan.one_to_two.is_some() && chan.two_to_one.is_none());
        // Stale timestamp rejected.
        assert_eq!(
            graph.apply_channel_update(&update(scid, n1, true, 99, 1)),
            Err(GossipError::Ignored)
        );
        // Wrong signer rejected.
        let n2 = if n1_is_a { &b } else { &a };
        assert_eq!(
            graph.apply_channel_update(&update(scid, n2, true, 101, 1)),
            Err(GossipError::BadSignature)
        );

        // Tampered announcement rejected.
        let mut bad = announcement(ShortChannelId::new(100, 2, 0), &a, &b);
        bad.short_channel_id = ShortChannelId::new(100, 3, 0);
        assert_eq!(
            graph.apply_channel_announcement(&bad, None),
            Err(GossipError::BadSignature)
        );
    }

    #[test]
    fn edges_into_respects_direction_and_enabled() {
        let mut graph = NetworkGraph::new(Network::Regtest);
        let a = keypair(11);
        let b = keypair(22);
        let scid = ShortChannelId::new(100, 1, 0);
        graph.apply_channel_announcement(&announcement(scid, &a, &b), None).unwrap();
        let n1_is_a = a.1.serialize() < b.1.serialize();
        let (n1, n2) = if n1_is_a { (&a, &b) } else { (&b, &a) };

        // Only node_1's direction is announced: reaching node_2 works,
        // reaching node_1 doesn't.
        graph.apply_channel_update(&update(scid, n1, true, 100, 10)).unwrap();
        assert_eq!(graph.edges_into(&n2.1).count(), 1);
        assert_eq!(graph.edges_into(&n1.1).count(), 0);

        // Disabled direction is filtered out.
        let mut upd = update(scid, n1, true, 101, 10);
        upd.channel_flags |= 2;
        let secp = Secp256k1::new();
        let hash = sha256d(&upd.signed_payload());
        upd.signature = secp.sign_ecdsa(&Message::from_digest(hash), &n1.0);
        graph.apply_channel_update(&upd).unwrap();
        assert_eq!(graph.edges_into(&n2.1).count(), 0);
    }
}
