//! Pathfinding: backward Dijkstra over the network graph with a pluggable
//! cost model.
//!
//! Searching from the destination toward the sender is the natural
//! direction for Lightning because fees compound: the amount a node must
//! *receive* depends on everything downstream of it.

use crate::graph::{DirectionalInfo, NetworkGraph};
use crate::invoice::RouteHintHop;
use crate::types::*;
use secp256k1::PublicKey;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

/// One hop of a finalized route. `amount_msat`/`cltv_expiry` are what must
/// arrive at *this hop's output* — exactly what goes into the onion payload
/// for the node forwarding over `short_channel_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHop {
    /// The node the HTLC is forwarded *to* over `short_channel_id`.
    pub node_id: PublicKey,
    pub short_channel_id: ShortChannelId,
    /// Amount this hop must receive.
    pub amount_msat: Msat,
    /// Absolute CLTV the HTLC toward this hop must carry.
    pub cltv_expiry: u32,
}

#[derive(Debug, Clone)]
pub struct Route {
    /// Hops in forward order (first = our direct peer).
    pub hops: Vec<RouteHop>,
    /// Amount we must send on the first hop (includes all fees).
    pub first_hop_amount_msat: Msat,
    /// CLTV for the first HTLC.
    pub first_hop_cltv: u32,
}

impl Route {
    pub fn fee_msat(&self, delivered: Msat) -> Msat {
        self.first_hop_amount_msat.saturating_sub(delivered)
    }
}

/// A channel of ours, usable as a first hop.
#[derive(Debug, Clone)]
pub struct FirstHop {
    pub peer: PublicKey,
    pub short_channel_id: ShortChannelId,
    pub available_msat: Msat,
}

/// Everything known about a candidate edge, for scoring.
#[derive(Debug, Clone)]
pub struct EdgeCandidate<'a> {
    pub short_channel_id: ShortChannelId,
    pub from: PublicKey,
    pub to: PublicKey,
    pub policy: &'a DirectionalInfo,
    pub capacity_sat: Option<u64>,
    pub amount_msat: Msat,
}

/// Pluggable routing cost. The router minimizes
/// `amount-at-source + penalty`, so penalties are in msat-equivalents.
pub trait PathScorer {
    fn penalty_msat(&self, edge: &EdgeCandidate<'_>) -> u64;
}

/// Default cost model: time-lock risk plus a small per-hop constant, plus a
/// proximity-to-capacity penalty (full channels fail more).
pub struct DefaultScorer {
    /// Penalty per block of added CLTV delta, in msat.
    pub cltv_penalty_per_block_msat: u64,
    /// Flat per-hop penalty, msat.
    pub base_penalty_msat: u64,
}

impl Default for DefaultScorer {
    fn default() -> Self {
        DefaultScorer { cltv_penalty_per_block_msat: 50, base_penalty_msat: 500 }
    }
}

impl PathScorer for DefaultScorer {
    fn penalty_msat(&self, edge: &EdgeCandidate<'_>) -> u64 {
        let mut penalty = self.base_penalty_msat
            + self.cltv_penalty_per_block_msat * edge.policy.cltv_expiry_delta as u64;
        if let Some(cap_msat) = edge.capacity_sat.map(|c| c * 1000).filter(|&c| c > 0) {
            // Quadratic in utilization: negligible when small, dominant
            // when the HTLC approaches the channel size.
            let used_ppm = edge.amount_msat.0.saturating_mul(1_000_000) / cap_msat;
            penalty += used_ppm * used_ppm / 1_000; // up to 1e9 msat at 100%
        }
        penalty
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NoPath,
    /// Destination unreachable within `max_cltv` or `max_hops`.
    LimitExceeded,
}

impl core::fmt::Display for RouteError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RouteError::NoPath => write!(f, "no route to destination"),
            RouteError::LimitExceeded => write!(f, "no route within limits"),
        }
    }
}

impl std::error::Error for RouteError {}

pub struct RouteParams<'a> {
    pub payer: PublicKey,
    pub payee: PublicKey,
    pub amount_msat: Msat,
    /// `min_final_cltv_expiry` from the invoice plus the current block
    /// height — the absolute CLTV the payee must see.
    pub final_cltv_expiry: u32,
    pub first_hops: &'a [FirstHop],
    /// BOLT 11 `r` field: private paths into the payee.
    pub route_hints: &'a [Vec<RouteHintHop>],
    pub max_hops: usize,
}

/// Find the cheapest route. Hints are grafted onto the graph as virtual
/// edges; first hops bypass policy checks (we don't charge ourselves).
pub fn find_route(
    graph: &NetworkGraph,
    scorer: &dyn PathScorer,
    params: &RouteParams<'_>,
) -> Result<Route, RouteError> {
    #[derive(Clone)]
    struct NodeState {
        /// Amount that must arrive at this node.
        amount: Msat,
        /// Absolute CLTV the HTLC into this node must carry.
        cltv: u32,
        /// Total cost (amount + penalties) for ordering.
        cost: u64,
        /// Next hop toward the payee.
        next: Option<RouteHop>,
        hops_to_payee: usize,
    }

    let mut best: HashMap<PublicKey, NodeState> = HashMap::new();
    let mut heap: BinaryHeap<(Reverse<u64>, [u8; 33])> = BinaryHeap::new();
    let mut keys: HashMap<[u8; 33], PublicKey> = HashMap::new();

    let push = |heap: &mut BinaryHeap<(Reverse<u64>, [u8; 33])>,
                    keys: &mut HashMap<[u8; 33], PublicKey>,
                    node: PublicKey,
                    cost: u64| {
        let ser = node.serialize();
        keys.insert(ser, node);
        heap.push((Reverse(cost), ser));
    };

    best.insert(
        params.payee,
        NodeState {
            amount: params.amount_msat,
            cltv: params.final_cltv_expiry,
            cost: params.amount_msat.0,
            next: None,
            hops_to_payee: 0,
        },
    );
    push(&mut heap, &mut keys, params.payee, params.amount_msat.0);

    // Hint policies, indexed by (from, scid): virtual directed edges.
    let mut hint_edges: HashMap<PublicKey, Vec<(ShortChannelId, PublicKey, DirectionalInfo)>> =
        HashMap::new();
    for path in params.route_hints {
        // A hint path lists forwarding nodes payee-ward: each entry's
        // `src_node_id` forwards toward the *next* entry's node (the last
        // forwards to the payee).
        for (i, hop) in path.iter().enumerate() {
            let to = if i + 1 < path.len() { path[i + 1].src_node_id } else { params.payee };
            hint_edges.entry(to).or_default().push((
                hop.short_channel_id,
                hop.src_node_id,
                DirectionalInfo {
                    timestamp: 0,
                    enabled: true,
                    cltv_expiry_delta: hop.cltv_expiry_delta,
                    htlc_minimum_msat: Msat(0),
                    htlc_maximum_msat: Msat(u64::MAX),
                    fee_base_msat: hop.fee_base_msat,
                    fee_proportional_millionths: hop.fee_proportional_millionths,
                },
            ));
        }
    }

    let first_hop_by_peer: HashMap<PublicKey, &FirstHop> =
        params.first_hops.iter().map(|fh| (fh.peer, fh)).collect();

    while let Some((Reverse(cost), node_ser)) = heap.pop() {
        let node = keys[&node_ser];
        let state = best[&node].clone();
        if state.cost < cost {
            continue; // stale heap entry
        }
        if state.hops_to_payee >= params.max_hops {
            continue;
        }

        // Can we start here? (node is one of our direct peers)
        if let Some(fh) = first_hop_by_peer.get(&node) {
            if fh.available_msat >= state.amount {
                let payer_state = NodeState {
                    amount: state.amount,
                    cltv: state.cltv,
                    cost: state.cost,
                    next: Some(RouteHop {
                        node_id: node,
                        short_channel_id: fh.short_channel_id,
                        amount_msat: state.amount,
                        cltv_expiry: state.cltv,
                    }),
                    hops_to_payee: state.hops_to_payee + 1,
                };
                let better = best
                    .get(&params.payer)
                    .map(|s| payer_state.cost < s.cost)
                    .unwrap_or(true);
                if better {
                    // Don't stop here: a cheaper path through another peer
                    // may still be in the heap.
                    best.insert(params.payer, payer_state);
                }
            }
        }

        // Relax graph edges and hint edges into `node`.
        let graph_edges = graph
            .edges_into(&node)
            .map(|(scid, from, policy, cap)| (scid, from, policy.clone(), cap));
        let hinted = hint_edges
            .get(&node)
            .into_iter()
            .flatten()
            .map(|(scid, from, policy)| (*scid, *from, policy.clone(), None));

        for (scid, from, policy, capacity_sat) in graph_edges.chain(hinted) {
            if from == params.payee {
                continue; // no loops through the destination
            }
            if from == params.payer {
                // Our own outgoing liquidity is described by `first_hops`,
                // not by gossip (which knows capacity, not balance).
                continue;
            }
            let fee = policy.fee_for(state.amount);
            let amount_in = state.amount + fee;
            if amount_in < policy.htlc_minimum_msat {
                continue;
            }
            if amount_in > policy.htlc_maximum_msat {
                continue;
            }
            if let Some(cap) = capacity_sat {
                if amount_in.0 > cap * 1000 {
                    continue;
                }
            }
            let edge = EdgeCandidate {
                short_channel_id: scid,
                from,
                to: node,
                policy: &policy,
                capacity_sat,
                amount_msat: amount_in,
            };
            let penalty = scorer.penalty_msat(&edge);
            let new_cost = state.cost.saturating_add(fee.0).saturating_add(penalty);
            let better = best.get(&from).map(|s| new_cost < s.cost).unwrap_or(true);
            if better {
                best.insert(
                    from,
                    NodeState {
                        amount: amount_in,
                        cltv: state.cltv + policy.cltv_expiry_delta as u32,
                        cost: new_cost,
                        next: Some(RouteHop {
                            node_id: node,
                            short_channel_id: scid,
                            amount_msat: state.amount,
                            cltv_expiry: state.cltv,
                        }),
                        hops_to_payee: state.hops_to_payee + 1,
                    },
                );
                push(&mut heap, &mut keys, from, new_cost);
            }
        }
    }

    // Walk payer → payee.
    let payer_state = best.get(&params.payer).ok_or(RouteError::NoPath)?;
    let mut hops = Vec::new();
    let mut cursor = payer_state.next.clone();
    while let Some(hop) = cursor {
        let next_node = hop.node_id;
        hops.push(hop);
        if next_node == params.payee {
            break;
        }
        cursor = best.get(&next_node).and_then(|s| s.next.clone());
        if hops.len() > params.max_hops {
            return Err(RouteError::LimitExceeded);
        }
    }
    if hops.last().map(|h| h.node_id) != Some(params.payee) {
        return Err(RouteError::NoPath);
    }
    Ok(Route {
        first_hop_amount_msat: payer_state.amount,
        first_hop_cltv: payer_state.cltv,
        hops,
    })
}

#[cfg(test)]
mod tests;
