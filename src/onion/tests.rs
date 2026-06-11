//! BOLT 4 test vectors: full onion construction, per-hop peeling, and the
//! error-return trace.

use super::*;
use crate::util::hex;

const SESSION_KEY: [u8; 32] = [0x41; 32];
const ASSOC_DATA: [u8; 32] = [0x42; 32];

/// The five route nodes use private keys 0x41…, 0x42…, …, 0x45….
fn node_keys() -> Vec<SecretKey> {
    (0..5u8).map(|i| SecretKey::from_slice(&[0x41 + i; 32]).unwrap()).collect()
}

fn path() -> Vec<PublicKey> {
    let secp = Secp256k1::signing_only();
    node_keys().iter().map(|sk| sk.public_key(&secp)).collect()
}

fn vector_payloads() -> Vec<Vec<u8>> {
    include_str!("vectors/hops.txt")
        .lines()
        .map(|line| {
            let payload_hex = line.split_whitespace().nth(1).unwrap();
            let with_prefix = hex::decode(payload_hex).unwrap();
            // Strip the bigsize length prefix the vector file includes.
            let mut r = crate::wire::WireReader::new(&with_prefix);
            let len = crate::wire::bigsize::read(&mut r).unwrap() as usize;
            let payload = r.take(len).unwrap().to_vec();
            assert!(r.is_empty());
            payload
        })
        .collect()
}

#[test]
fn vector_pubkeys_match_known_secrets() {
    let expected = [
        "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
    ];
    for (pk, want) in path().iter().zip(expected) {
        assert_eq!(hex::encode(&pk.serialize()), want);
    }
}

#[test]
fn shared_secrets_match_bolt4_trace() {
    let session = SecretKey::from_slice(&SESSION_KEY).unwrap();
    let secrets = shared_secrets_for_path(&session, &path());
    let expected = [
        "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66",
        "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae",
        "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc",
        "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d",
        "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328",
    ];
    for (ss, want) in secrets.iter().zip(expected) {
        assert_eq!(hex::encode(ss), want);
    }
}

#[test]
fn onion_construction_matches_vector() {
    let session = SecretKey::from_slice(&SESSION_KEY).unwrap();
    let secrets = shared_secrets_for_path(&session, &path());
    let packet = construct(&session, &secrets, &vector_payloads(), &ASSOC_DATA);
    let expected = include_str!("vectors/onion_packet.hex").trim();
    assert_eq!(hex::encode(&packet.serialize()), expected);
}

#[test]
fn peel_all_hops() {
    let session = SecretKey::from_slice(&SESSION_KEY).unwrap();
    let secrets = shared_secrets_for_path(&session, &path());
    let payloads = vector_payloads();
    let mut packet = construct(&session, &secrets, &payloads, &ASSOC_DATA);

    let keys = node_keys();
    for (i, key) in keys.iter().enumerate() {
        let (peeled, ss) = peel(key, &packet, &ASSOC_DATA).unwrap();
        assert_eq!(ss, secrets[i], "shared secret at hop {i}");
        match peeled {
            Peeled::Forward { payload, next } => {
                assert!(i < keys.len() - 1, "hop {i} should not be final");
                assert_eq!(payload, payloads[i], "payload at hop {i}");
                packet = next;
            }
            Peeled::Final { payload } => {
                assert_eq!(i, keys.len() - 1, "final at wrong hop");
                assert_eq!(payload, payloads[i]);
                return;
            }
        }
    }
    panic!("never reached final hop");
}

#[test]
fn peel_rejects_tampering() {
    let session = SecretKey::from_slice(&SESSION_KEY).unwrap();
    let secrets = shared_secrets_for_path(&session, &path());
    let packet = construct(&session, &secrets, &vector_payloads(), &ASSOC_DATA);
    let keys = node_keys();

    // Flip a payload byte.
    let mut bad = packet.clone();
    bad.payloads[100] ^= 1;
    assert_eq!(peel(&keys[0], &bad, &ASSOC_DATA).map(|_| ()), Err(OnionError::InvalidHmac));
    // Wrong associated data.
    assert_eq!(
        peel(&keys[0], &packet, &[0u8; 32]).map(|_| ()),
        Err(OnionError::InvalidHmac)
    );
    // Wrong node key.
    assert_eq!(
        peel(&keys[1], &packet, &ASSOC_DATA).map(|_| ()),
        Err(OnionError::InvalidHmac)
    );
}

/// The BOLT 4 "Returning Errors" trace: node 4 fails with
/// `incorrect_or_unknown_payment_details`, the error onion travels back
/// through nodes 3..0, and the origin attributes it to hop 4.
#[test]
fn error_onion_matches_vectors() {
    let session = SecretKey::from_slice(&SESSION_KEY).unwrap();
    let secrets = shared_secrets_for_path(&session, &path());

    // failuremsg = 0x400f || htlc_msat=100 (u64) || height=800000 (u32)
    //              || tlv(34001, 300 * 0x80)
    let mut msg = failure::message(failure::INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, &[]);
    msg.extend_from_slice(&100u64.to_be_bytes());
    msg.extend_from_slice(&800_000u32.to_be_bytes());
    let mut w = crate::wire::WireWriter::new();
    crate::wire::bigsize::write(&mut w, 34001);
    crate::wire::bigsize::write(&mut w, 300);
    w.bytes(&[0x80; 300]);
    msg.extend_from_slice(&w.finish());
    assert!(
        hex::encode(&msg).starts_with("400f0000000000000064000c3500fd84d1fd012c8080"),
        "failure message encoding"
    );

    let expected_packets: Vec<Vec<u8>> = include_str!("vectors/error_packets.hex")
        .lines()
        .map(|l| hex::decode(l.trim()).unwrap())
        .collect();

    // Node 4 (erring) builds; nodes 3, 2, 1, 0 each wrap on the way back.
    let mut packet = failure::build(&secrets[4], &msg);
    assert_eq!(packet, expected_packets[0], "packet leaving node 4");
    for (back, hop) in (0..4).rev().enumerate() {
        failure::wrap(&secrets[hop], &mut packet);
        assert_eq!(packet, expected_packets[back + 1], "packet leaving node {hop}");
    }

    // Origin decrypts and attributes.
    let (erring_hop, recovered) = failure::decrypt(&secrets, &packet).unwrap();
    assert_eq!(erring_hop, 4);
    assert_eq!(recovered, msg);
    assert_eq!(
        failure::parse_code(&recovered),
        Some(failure::INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS)
    );
}
