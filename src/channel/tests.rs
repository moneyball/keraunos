//! Two-party channel state machine tests: the full lifecycle, the
//! commitment dance (including crossed commitments and the holding cell),
//! cooperative close, and reestablish.

use super::close::ClosingSignedOutcome;
use super::*;
use crate::sign::{InMemoryChannelSigner, KeysManager, SignerProvider};
use crate::types::Network;
use crate::wire::msgs::Message as WireMessage;

pub(crate) type Chan = Channel<InMemoryChannelSigner>;

fn test_onion() -> Vec<u8> {
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
fn deliver(
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
fn pump(
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

#[test]
fn payment_settles_and_balances_move() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    let before_a = a.holder_balance_msat();
    assert_eq!(before_a, Msat::from_sat(1_000_000));
    assert_eq!(b.holder_balance_msat(), Msat::ZERO);

    add_and_settle(&mut a, &mut b, Msat(100_000_000), preimage(1));

    // All HTLCs resolved and garbage-collected on both sides.
    assert_eq!(a.live_htlc_count(), 0);
    assert_eq!(b.live_htlc_count(), 0);
    assert_eq!(a.holder_balance_msat(), Msat(900_000_000));
    assert_eq!(b.holder_balance_msat(), Msat(100_000_000));
    // Commitment numbers advanced in lockstep.
    assert_eq!(a.holder_commitment_number, b.counterparty_commitment_number);
    assert_eq!(b.holder_commitment_number, a.counterparty_commitment_number);
    // Both sides can produce a broadcastable commitment.
    a.signed_holder_commitment_tx().unwrap();
    b.signed_holder_commitment_tx().unwrap();
}

#[test]
fn failed_htlc_refunds_offerer() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    let pre = preimage(2);
    let add = a
        .send_add_htlc(Msat(50_000_000), pre.payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [1; 32] })
        .unwrap()
        .unwrap();
    let cs = a.send_commitment_signed().unwrap();
    let (_, fwd_b) = pump(
        &mut a,
        &mut b,
        vec![WireMessage::UpdateAddHtlc(add), WireMessage::CommitmentSigned(cs)],
        vec![],
    );
    let fail = b.send_fail_htlc(fwd_b[0].id, vec![0xde, 0xad]).unwrap().unwrap();
    let cs = b.send_commitment_signed().unwrap();
    pump(&mut a, &mut b, vec![], vec![
        WireMessage::UpdateFailHtlc(fail),
        WireMessage::CommitmentSigned(cs),
    ]);
    assert_eq!(a.holder_balance_msat(), Msat::from_sat(1_000_000));
    assert_eq!(b.holder_balance_msat(), Msat::ZERO);
    assert_eq!(a.live_htlc_count(), 0);
}

#[test]
fn holding_cell_flushes_on_raa() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    let p1 = preimage(3);
    let p2 = preimage(4);

    let add1 = a
        .send_add_htlc(Msat(10_000_000), p1.payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [1; 32] })
        .unwrap()
        .unwrap();
    let cs1 = a.send_commitment_signed().unwrap();
    // While the commitment is in flight, the second add parks.
    let parked = a
        .send_add_htlc(Msat(20_000_000), p2.payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [2; 32] })
        .unwrap();
    assert!(parked.is_none(), "second add must wait in the holding cell");

    let (_, fwd_b) = pump(
        &mut a,
        &mut b,
        vec![WireMessage::UpdateAddHtlc(add1), WireMessage::CommitmentSigned(cs1)],
        vec![],
    );
    // Both HTLCs end up committed at B.
    assert_eq!(fwd_b.len(), 2);
    assert_eq!(a.live_htlc_count(), 2);
    assert_eq!(b.live_htlc_count(), 2);
    // In-flight amounts are debited from A's spendable view.
    let (to_a, _) = a.balances_for(false);
    assert_eq!(to_a, Msat::from_sat(1_000_000) - Msat(30_000_000));
}

#[test]
fn crossed_commitment_signed_converges() {
    // Both sides add an HTLC and sign concurrently; the messages cross.
    let (mut a, mut b) = open_pair(1_000_000, Msat(400_000_000));
    let pa = preimage(5);
    let pb = preimage(6);

    let add_a = a
        .send_add_htlc(Msat(25_000_000), pa.payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [1; 32] })
        .unwrap()
        .unwrap();
    let cs_a = a.send_commitment_signed().unwrap();
    let add_b = b
        .send_add_htlc(Msat(35_000_000), pb.payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [2; 32] })
        .unwrap()
        .unwrap();
    let cs_b = b.send_commitment_signed().unwrap();

    let (fwd_a, fwd_b) = pump(
        &mut a,
        &mut b,
        vec![WireMessage::UpdateAddHtlc(add_a), WireMessage::CommitmentSigned(cs_a)],
        vec![WireMessage::UpdateAddHtlc(add_b), WireMessage::CommitmentSigned(cs_b)],
    );
    assert_eq!(fwd_a.len(), 1, "A sees B's HTLC committed");
    assert_eq!(fwd_b.len(), 1, "B sees A's HTLC committed");
    assert_eq!(a.live_htlc_count(), 2);
    assert_eq!(b.live_htlc_count(), 2);
    assert_eq!(a.holder_commitment_number, b.counterparty_commitment_number);
    assert_eq!(b.holder_commitment_number, a.counterparty_commitment_number);

    // Settle both.
    let f_b = b.send_fulfill_htlc(fwd_b[0].id, pa).unwrap().unwrap();
    let cs = b.send_commitment_signed().unwrap();
    pump(&mut a, &mut b, vec![], vec![
        WireMessage::UpdateFulfillHtlc(f_b),
        WireMessage::CommitmentSigned(cs),
    ]);
    let f_a = a.send_fulfill_htlc(fwd_a[0].id, pb).unwrap().unwrap();
    let cs = a.send_commitment_signed().unwrap();
    pump(&mut a, &mut b, vec![
        WireMessage::UpdateFulfillHtlc(f_a),
        WireMessage::CommitmentSigned(cs),
    ], vec![]);

    assert_eq!(a.live_htlc_count(), 0);
    assert_eq!(b.live_htlc_count(), 0);
    // A started with 600k sat (1M minus 400k pushed), paid 25k msat... =
    // 600_000_000 msat - 25M + 35M.
    assert_eq!(a.holder_balance_msat(), Msat(600_000_000 - 25_000_000 + 35_000_000));
    assert_eq!(b.holder_balance_msat(), Msat(400_000_000 + 25_000_000 - 35_000_000));
}

#[test]
fn cooperative_close_agrees_on_one_transaction() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    add_and_settle(&mut a, &mut b, Msat(100_000_000), preimage(7));

    let script_a = Script::new_p2wpkh(&[0xaa; 20]);
    let shutdown_a = a.send_shutdown(script_a).unwrap();
    pump(&mut a, &mut b, vec![WireMessage::Shutdown(shutdown_a)], vec![]);
    // The funder kicks off closing inside the pump; drive to completion.
    let kick = a.maybe_send_closing_signed(FeeRatePerKw(253)).unwrap();
    if let Some(cs) = kick {
        pump(&mut a, &mut b, vec![WireMessage::ClosingSigned(cs)], vec![]);
    }
    assert_eq!(a.state(), ChannelState::Closed);
    assert_eq!(b.state(), ChannelState::Closed);
    let tx_a = a.closing_transaction().expect("A has the closing tx");
    let tx_b = b.closing_transaction().expect("B has the closing tx");
    assert_eq!(tx_a.txid(), tx_b.txid(), "both sides agree on the close");
    // Fee comes out of the funder's output: total out < funding.
    let total_out: u64 = tx_a.output.iter().map(|o| o.value).sum();
    assert!(total_out < 1_000_000 && total_out > 990_000);
}

#[test]
fn reestablish_retransmits_lost_commitment() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    let pre = preimage(8);

    // A sends add + CS, but they are lost before B sees them.
    let _lost_add = a
        .send_add_htlc(Msat(40_000_000), pre.payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [1; 32] })
        .unwrap()
        .unwrap();
    let _lost_cs = a.send_commitment_signed().unwrap();

    // Disconnect and reconnect.
    a.on_disconnect();
    b.on_disconnect();
    let re_a = a.make_channel_reestablish();
    let re_b = b.make_channel_reestablish();
    let actions_a = a.on_channel_reestablish(&re_b).unwrap();
    let actions_b = b.on_channel_reestablish(&re_a).unwrap();
    assert!(!actions_a.data_loss_detected && !actions_b.data_loss_detected);
    // Commitment numbers are still 0/1, so both retransmit channel_ready
    // (BOLT 2); A additionally retransmits the lost add + commitment.
    assert_eq!(actions_b.messages.len(), 1);
    assert!(matches!(actions_b.messages[0], WireMessage::ChannelReady(_)));
    assert_eq!(actions_a.messages.len(), 3);
    assert!(matches!(actions_a.messages[0], WireMessage::ChannelReady(_)));
    assert!(matches!(actions_a.messages[1], WireMessage::UpdateAddHtlc(_)));
    assert!(matches!(actions_a.messages[2], WireMessage::CommitmentSigned(_)));

    let (_, fwd_b) = pump(&mut a, &mut b, actions_a.messages, actions_b.messages);
    assert_eq!(fwd_b.len(), 1, "HTLC commits after retransmission");

    // And the channel still works.
    let fulfill = b.send_fulfill_htlc(fwd_b[0].id, pre).unwrap().unwrap();
    let cs = b.send_commitment_signed().unwrap();
    pump(&mut a, &mut b, vec![], vec![
        WireMessage::UpdateFulfillHtlc(fulfill),
        WireMessage::CommitmentSigned(cs),
    ]);
    assert_eq!(a.holder_balance_msat(), Msat(1_000_000_000 - 40_000_000));
}

#[test]
fn bogus_revocation_secret_is_rejected() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    let add = a
        .send_add_htlc(Msat(10_000_000), preimage(9).payment_hash(), 500_000, test_onion(),
            HtlcSource::Outbound { payment_id: [1; 32] })
        .unwrap()
        .unwrap();
    let cs = a.send_commitment_signed().unwrap();
    b.on_update_add_htlc(&add).unwrap();
    let mut raa = b.on_commitment_signed(&cs).unwrap();
    raa.per_commitment_secret = [0x99; 32];
    let err = a.on_revoke_and_ack(&raa).unwrap_err();
    assert!(matches!(err, ChannelError::Close(_)));
}

#[test]
fn unsolicited_messages_fail_the_channel() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    // Fulfill for an unknown HTLC id.
    let bad = UpdateFulfillHtlc {
        channel_id: a.channel_id(),
        id: 7,
        payment_preimage: preimage(1),
    };
    assert!(matches!(a.on_update_fulfill_htlc(&bad), Err(ChannelError::Close(_))));
    // Non-sequential add id.
    let bad_add = UpdateAddHtlc {
        channel_id: b.channel_id(),
        id: 5,
        amount_msat: Msat(1_000_000),
        payment_hash: PaymentHash([1; 32]),
        cltv_expiry: 100,
        onion_routing_packet: test_onion(),
    };
    assert!(matches!(b.on_update_add_htlc(&bad_add), Err(ChannelError::Close(_))));
}
