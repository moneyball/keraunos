//! Shared two-party channel harness for in-crate tests (channel dance,
//! chain monitor, persistence).

use super::close::ClosingSignedOutcome;
use super::*;
use crate::sign::{InMemoryChannelSigner, KeysManager, SignerProvider};
use crate::types::Network;
use crate::wire::msgs::Message as WireMessage;

pub(crate) type Chan = Channel<InMemoryChannelSigner>;

pub(crate) fn test_onion() -> Vec<u8> {
    vec![0u8; crate::wire::msgs::ONION_PACKET_LEN]
}

pub(crate) fn preimage(n: u8) -> PaymentPreimage {
    PaymentPreimage([n; 32])
}

pub(crate) fn open_pair(funding_sat: u64, push: Msat) -> (Chan, Chan) {
    let km_a = KeysManager::new([0xaa; 32]);
    let km_b = KeysManager::new([0xbb; 32]);
    let config = ChannelConfig { minimum_depth: 1, ..Default::default() };

    let (mut a, open) = Channel::new_outbound(
        km_a.derive_channel_signer(0),
        config.clone(),
        Network::Regtest,
        ChannelId([0x42; 32]),
        funding_sat,
        push,
        FeeRatePerKw(253),
    )
    .unwrap();
    let (mut b, accept) =
        Channel::new_inbound(km_b.derive_channel_signer(0), config, Network::Regtest, &open)
            .unwrap();
    a.on_accept_channel(&accept).unwrap();

    // A "creates" a funding transaction (only the outpoint matters here).
    let funding_txid = Txid([0xfd; 32]);
    let fc = a.funding_created(funding_txid, 0).unwrap();
    let fs = b.on_funding_created(&fc).unwrap();
    a.on_funding_signed(&fs).unwrap();

    let scid = ShortChannelId::new(100, 1, 0);
    let ready_a = a.funding_confirmed(scid).unwrap().unwrap();
    let ready_b = b.funding_confirmed(scid).unwrap().unwrap();
    a.on_channel_ready(&ready_b).unwrap();
    b.on_channel_ready(&ready_a).unwrap();
    assert_eq!(a.state(), ChannelState::Normal);
    assert_eq!(b.state(), ChannelState::Normal);
    (a, b)
}

/// Deliver one message to a channel, collecting replies. Returns inbound
/// HTLCs that became forwardable.
pub(crate) fn deliver(
    chan: &mut Chan,
    msg: &WireMessage,
    out: &mut Vec<WireMessage>,
) -> Vec<super::dance::CommittedInboundHtlc> {
    let mut forwardable = Vec::new();
    match msg {
        WireMessage::UpdateAddHtlc(m) => chan.on_update_add_htlc(m).unwrap(),
        WireMessage::UpdateFulfillHtlc(m) => {
            chan.on_update_fulfill_htlc(m).unwrap();
        }
        WireMessage::UpdateFailHtlc(m) => {
            chan.on_update_fail_htlc(m).unwrap();
        }
        WireMessage::CommitmentSigned(m) => {
            let raa = chan.on_commitment_signed(m).unwrap();
            out.push(WireMessage::RevokeAndAck(raa));
            if chan.can_send_commitment() {
                out.push(WireMessage::CommitmentSigned(chan.send_commitment_signed().unwrap()));
            }
        }
        WireMessage::RevokeAndAck(m) => {
            let outcome = chan.on_revoke_and_ack(m).unwrap();
            forwardable = outcome.forwardable;
            out.extend(outcome.messages);
            if let Some(cs) = outcome.commitment_signed {
                out.push(WireMessage::CommitmentSigned(cs));
            }
        }
        WireMessage::ChannelReady(m) => chan.on_channel_ready(m).unwrap(),
        WireMessage::Shutdown(m) => {
            let our_script = Script::new_p2wpkh(&[0x55; 20]);
            if let Some(reply) = chan.on_shutdown(m, &our_script).unwrap() {
                out.push(WireMessage::Shutdown(reply));
            }
        }
        WireMessage::ClosingSigned(m) => {
            match chan.on_closing_signed(m, FeeRatePerKw(253)).unwrap() {
                ClosingSignedOutcome::Reply(reply, _maybe_tx) => {
                    out.push(WireMessage::ClosingSigned(reply))
                }
                ClosingSignedOutcome::Done(_tx) => {}
            }
        }
        other => panic!("unexpected message in test pump: {other:?}"),
    }
    // The funder starts closing as soon as the channel is quiescent.
    if let Some(cs) = chan.maybe_send_closing_signed(FeeRatePerKw(253)).unwrap() {
        out.push(WireMessage::ClosingSigned(cs));
    }
    forwardable
}

/// Pump queued messages between two channels until quiescent. Returns all
/// HTLCs that became forwardable on either side.
pub(crate) fn pump(
    a: &mut Chan,
    b: &mut Chan,
    mut to_b: Vec<WireMessage>,
    mut to_a: Vec<WireMessage>,
) -> (Vec<super::dance::CommittedInboundHtlc>, Vec<super::dance::CommittedInboundHtlc>) {
    let mut fwd_a = Vec::new();
    let mut fwd_b = Vec::new();
    while !to_a.is_empty() || !to_b.is_empty() {
        let mut next_to_a = Vec::new();
        let mut next_to_b = Vec::new();
        for msg in to_b.drain(..) {
            fwd_b.extend(deliver(b, &msg, &mut next_to_a));
        }
        for msg in to_a.drain(..) {
            fwd_a.extend(deliver(a, &msg, &mut next_to_b));
        }
        to_a = next_to_a;
        to_b = next_to_b;
    }
    (fwd_a, fwd_b)
}

pub(crate) fn add_and_settle(a: &mut Chan, b: &mut Chan, amount: Msat, pre: PaymentPreimage) {
    let hash = pre.payment_hash();
    let add = a
        .send_add_htlc(amount, hash, 500_000, test_onion(), HtlcSource::Outbound {
            payment_id: [9; 32],
        })
        .unwrap()
        .expect("not awaiting raa");
    let cs = a.send_commitment_signed().unwrap();
    let (_, fwd_b) = pump(
        a,
        b,
        vec![WireMessage::UpdateAddHtlc(add), WireMessage::CommitmentSigned(cs)],
        vec![],
    );
    assert_eq!(fwd_b.len(), 1, "B must see the committed inbound HTLC");
    assert_eq!(fwd_b[0].payment_hash, hash);

    let fulfill = b.send_fulfill_htlc(fwd_b[0].id, pre).unwrap().expect("not awaiting raa");
    let cs = b.send_commitment_signed().unwrap();
    pump(a, b, vec![], vec![
        WireMessage::UpdateFulfillHtlc(fulfill),
        WireMessage::CommitmentSigned(cs),
    ]);
}
