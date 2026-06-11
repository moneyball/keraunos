//! Monitor tests: drive two real channels into interesting on-chain
//! situations and verify the enforcement transactions cryptographically.

use super::monitor::{ChannelMonitor, FundingSpend, MonitorResponse};
use crate::bitcoin::{Script, SighashCache, SighashType};
use crate::channel::tests::{add_and_settle, open_pair, preimage};
use crate::commitment::scripts;
use crate::keys::{self, TxCreationKeys};
use crate::types::*;
use secp256k1::{Message, Secp256k1};

fn dest() -> Script {
    Script::new_p2wpkh(&[0x77; 20])
}

#[test]
fn revoked_commitment_is_classified_and_punished() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    // Give B a balance, then capture B's commitment and revoke it with
    // another payment.
    add_and_settle(&mut a, &mut b, Msat(300_000_000), preimage(1));
    let revoked_tx = b.signed_holder_commitment_tx().unwrap();
    add_and_settle(&mut a, &mut b, Msat(50_000_000), preimage(2));

    let monitor = ChannelMonitor::from_channel(&a).expect("funded channel");

    // B's *current* commitment is fine...
    let current = b.signed_holder_commitment_tx().unwrap();
    assert_eq!(monitor.classify(&current), Some(FundingSpend::CounterpartyCurrent));
    // ...the old one is recognized as revoked, with its number recovered
    // from the obscured locktime/sequence bits.
    let class = monitor.classify(&revoked_tx).expect("spends our funding");
    let FundingSpend::CounterpartyRevoked { commitment_number } = class else {
        panic!("expected revoked classification, got {class:?}");
    };

    // Build the justice transaction.
    let (_, responses) = monitor
        .handle_funding_spend(&a.signer, &revoked_tx, &dest(), FeeRatePerKw(1000), 150)
        .expect("handled");
    let justice = responses
        .iter()
        .find_map(|r| {
            let MonitorResponse::Claim { tx, valid_after_height: None, what } = r else {
                return None;
            };
            what.contains("justice").then_some(tx)
        })
        .expect("justice transaction");

    // It must spend B's to_local output (the revocable one).
    let secret = monitor
        .counterparty_secrets
        .secret_for(crate::shachain::index_for_commitment(commitment_number))
        .expect("revealed");
    let point = keys::per_commitment_point(&secret);
    let secp = Secp256k1::new();
    let tx_keys = TxCreationKeys::derive(
        &secp,
        &point,
        &monitor.counterparty_pubkeys,
        &monitor.holder_pubkeys,
    );
    let to_local_script = scripts::revocable_delayed(
        &tx_keys.revocation_key,
        monitor.holder_selected_delay,
        &tx_keys.broadcaster_delayed_payment_key,
    );
    let to_local_spk = Script::new_p2wsh(&to_local_script);
    let to_local_vout = revoked_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == to_local_spk)
        .expect("revoked tx has B's to_local") as u32;
    assert!(
        justice.input.iter().any(|i| i.previous_output.vout == to_local_vout
            && i.previous_output.txid == revoked_tx.txid()),
        "justice must sweep to_local"
    );

    // The witness signature must verify under the *revocation* key —
    // the key B can never have without A's secret.
    let input_value = revoked_tx.output[to_local_vout as usize].value;
    let sighash = SighashCache::new(justice).segwit_v0_sighash(
        0,
        &to_local_script,
        input_value,
        SighashType::All,
    );
    let wit = &justice.input[0].witness;
    assert_eq!(wit.len(), 3, "sig, IF-branch flag, script");
    assert_eq!(wit[1], vec![0x01], "revocation branch selected");
    assert_eq!(wit[2], to_local_script.0, "witness script matches");
    let sig = secp256k1::ecdsa::Signature::from_der(&wit[0][..wit[0].len() - 1]).unwrap();
    secp.verify_ecdsa(&Message::from_digest(sighash), &sig, &tx_keys.revocation_key)
        .expect("justice signature valid under the revocation key");

    // Economically sane: sweeps most of B's balance to our destination.
    assert_eq!(justice.output.len(), 1);
    assert_eq!(justice.output[0].script_pubkey, dest());
    assert!(justice.output[0].value > input_value - 2_000);
}

#[test]
fn their_force_close_sweeps_to_remote() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    add_and_settle(&mut a, &mut b, Msat(250_000_000), preimage(3));

    // B force-closes with its current commitment. A's to_remote (static
    // remotekey P2WPKH) must be swept.
    let their_tx = b.signed_holder_commitment_tx().unwrap();
    let monitor = ChannelMonitor::from_channel(&a).unwrap();
    let (class, responses) = monitor
        .handle_funding_spend(&a.signer, &their_tx, &dest(), FeeRatePerKw(1000), 150)
        .unwrap();
    assert_eq!(class, FundingSpend::CounterpartyCurrent);

    let sweep = responses
        .iter()
        .find_map(|r| {
            let MonitorResponse::Claim { tx, what, .. } = r;
            what.contains("to_remote").then_some(tx)
        })
        .expect("to_remote sweep");
    // Find A's P2WPKH output on their commitment.
    let our_spk =
        Script::new_p2wpkh_from_pubkey(&monitor.holder_pubkeys.payment_basepoint.serialize());
    let vout = their_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == our_spk)
        .expect("to_remote present") as u32;
    assert_eq!(sweep.input[0].previous_output.vout, vout);

    // Verify the P2WPKH signature against our payment basepoint.
    let value = their_tx.output[vout as usize].value;
    let script_code = our_spk.p2wpkh_script_code().unwrap();
    let sighash =
        SighashCache::new(sweep).segwit_v0_sighash(0, &script_code, value, SighashType::All);
    let secp = Secp256k1::new();
    let sig = secp256k1::ecdsa::Signature::from_der(
        &sweep.input[0].witness[0][..sweep.input[0].witness[0].len() - 1],
    )
    .unwrap();
    secp.verify_ecdsa(
        &Message::from_digest(sighash),
        &sig,
        &monitor.holder_pubkeys.payment_basepoint,
    )
    .expect("sweep signed by our payment key");
    // ~750k sat back to us.
    assert!(sweep.output[0].value > 740_000);
}

#[test]
fn our_force_close_waits_out_the_csv_delay() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    add_and_settle(&mut a, &mut b, Msat(100_000_000), preimage(4));

    let our_tx = a.signed_holder_commitment_tx().unwrap();
    let monitor = ChannelMonitor::from_channel(&a).unwrap();
    let height = 222;
    let (class, responses) = monitor
        .handle_funding_spend(&a.signer, &our_tx, &dest(), FeeRatePerKw(1000), height)
        .unwrap();
    assert_eq!(class, FundingSpend::HolderCommitment);

    let MonitorResponse::Claim { tx, valid_after_height, what } = responses
        .iter()
        .find(|r| {
            let MonitorResponse::Claim { what, .. } = r;
            what.contains("to_local")
        })
        .expect("to_local sweep");
    assert!(what.contains("CSV"));
    // Gated by the delay the counterparty chose, and the input encodes it.
    assert_eq!(
        *valid_after_height,
        Some(height + monitor.counterparty_selected_delay as u32)
    );
    assert_eq!(tx.input[0].sequence, monitor.counterparty_selected_delay as u32);
    // Spends our delayed output and pays our destination.
    assert_eq!(tx.output[0].script_pubkey, dest());
}

#[test]
fn restored_monitor_still_punishes() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    add_and_settle(&mut a, &mut b, Msat(300_000_000), preimage(6));
    let revoked_tx = b.signed_holder_commitment_tx().unwrap();
    add_and_settle(&mut a, &mut b, Msat(50_000_000), preimage(7));

    // Serialize, "crash", restore.
    let monitor = ChannelMonitor::from_channel(&a).unwrap();
    let blob = monitor.serialize();
    let restored = ChannelMonitor::deserialize(&blob).expect("roundtrip");
    assert_eq!(restored.serialize(), blob, "stable encoding");

    // The restored monitor classifies and punishes exactly the same.
    let class = restored.classify(&revoked_tx).expect("spend recognized");
    assert!(matches!(class, FundingSpend::CounterpartyRevoked { .. }), "{class:?}");
    let (_, responses) = restored
        .handle_funding_spend(&a.signer, &revoked_tx, &dest(), FeeRatePerKw(1000), 150)
        .unwrap();
    assert!(
        responses.iter().any(|r| {
            let MonitorResponse::Claim { what, .. } = r;
            what.contains("justice")
        }),
        "restored monitor must still produce the justice tx"
    );
    // Corrupt blobs are rejected, not misread.
    let mut bad = blob.clone();
    bad[0] = 99;
    assert!(ChannelMonitor::deserialize(&bad).is_err());
    assert!(ChannelMonitor::deserialize(&blob[..blob.len() - 3]).is_err());
}

#[test]
fn cooperative_close_is_left_alone() {
    let (mut a, mut b) = open_pair(1_000_000, Msat::ZERO);
    add_and_settle(&mut a, &mut b, Msat(100_000_000), preimage(5));
    let monitor = ChannelMonitor::from_channel(&a).unwrap();

    // Negotiate a real cooperative close.
    let script_a = Script::new_p2wpkh(&[0xaa; 20]);
    let shutdown = a.send_shutdown(script_a).unwrap();
    let script_b = Script::new_p2wpkh(&[0xbb; 20]);
    let reply = b.on_shutdown(&shutdown, &script_b).unwrap().unwrap();
    a.on_shutdown(&reply, &Script::new_p2wpkh(&[0xaa; 20]))
        .map(|_| ())
        .unwrap_or(());
    let cs = a.maybe_send_closing_signed(FeeRatePerKw(253)).unwrap().unwrap();
    let outcome = b.on_closing_signed(&cs, FeeRatePerKw(253)).unwrap();
    let close_tx = match outcome {
        crate::channel::ClosingSignedOutcome::Reply(reply, maybe) => {
            match a.on_closing_signed(&reply, FeeRatePerKw(253)).unwrap() {
                crate::channel::ClosingSignedOutcome::Done(tx) => tx,
                crate::channel::ClosingSignedOutcome::Reply(_, Some(tx)) => tx,
                other => maybe.unwrap_or_else(|| panic!("no close tx: {other:?}")),
            }
        }
        crate::channel::ClosingSignedOutcome::Done(tx) => tx,
    };

    let (class, responses) = monitor
        .handle_funding_spend(&a.signer, &close_tx, &dest(), FeeRatePerKw(1000), 150)
        .unwrap();
    assert_eq!(class, FundingSpend::CooperativeClose);
    assert!(responses.is_empty(), "nothing to enforce on a negotiated close");
}
