//! BOLT 11 example invoices (Appendix "Examples").

use super::*;
use crate::util::hex;

const PRIV_KEY: &str = "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
const PAYEE: &str = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
const TIMESTAMP: u64 = 1496314658;

const EX1_DONATION: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
const EX2_COFFEE: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const EX4_HASHED: &str = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44";

fn expected_payment_hash() -> PaymentHash {
    PaymentHash(
        hex::decode_array("0001020304050607080900010203040506070809000102030405060708090102")
            .unwrap(),
    )
}

fn expected_payment_secret() -> PaymentSecret {
    PaymentSecret(
        hex::decode_array("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap(),
    )
}

#[test]
fn parse_example_1_donation() {
    let inv = Bolt11Invoice::parse(EX1_DONATION).unwrap();
    assert_eq!(inv.network, Network::Bitcoin);
    assert_eq!(inv.amount_msat, None);
    assert_eq!(inv.timestamp, TIMESTAMP);
    assert_eq!(inv.payment_hash, expected_payment_hash());
    assert_eq!(inv.payment_secret, expected_payment_secret());
    assert_eq!(
        inv.description,
        Description::Direct("Please consider supporting this project".into())
    );
    assert_eq!(inv.expiry_secs, None);
    assert_eq!(hex::encode(&inv.payee.serialize()), PAYEE);
    // features b100000100000000: bits 8 and 14.
    assert!(inv.features.is_set(8) && inv.features.is_set(14));
}

#[test]
fn parse_example_2_coffee() {
    let inv = Bolt11Invoice::parse(EX2_COFFEE).unwrap();
    assert_eq!(inv.amount_msat, Some(Msat(250_000_000)));
    assert_eq!(inv.description, Description::Direct("1 cup coffee".into()));
    assert_eq!(inv.expiry_secs, Some(60));
    assert!(inv.is_expired_at(TIMESTAMP + 61));
    assert!(!inv.is_expired_at(TIMESTAMP + 59));
    assert_eq!(hex::encode(&inv.payee.serialize()), PAYEE);
}

#[test]
fn parse_example_4_hashed_description() {
    let inv = Bolt11Invoice::parse(EX4_HASHED).unwrap();
    assert_eq!(inv.amount_msat, Some(Msat(2_000_000_000)));
    assert_eq!(
        inv.description,
        Description::Hash(
            hex::decode_array("3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1")
                .unwrap()
        )
    );
    assert_eq!(hex::encode(&inv.payee.serialize()), PAYEE);
}

/// Re-create example invoices from scratch with the spec's private key —
/// byte-identical output proves encoding, field order, feature packing,
/// amount encoding, and signing all match the spec.
#[test]
fn encode_reproduces_example_1() {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&hex::decode_array::<32>(PRIV_KEY).unwrap()).unwrap();
    let mut features = Features::empty();
    features.set(8);
    features.set(14);
    let builder = InvoiceBuilder {
        network: Network::Bitcoin,
        amount_msat: None,
        timestamp: TIMESTAMP,
        payment_hash: expected_payment_hash(),
        payment_secret: expected_payment_secret(),
        description: Description::Direct("Please consider supporting this project".into()),
        expiry_secs: None,
        min_final_cltv_expiry_delta: None,
        features,
        route_hints: vec![],
    };
    assert_eq!(builder.encode_with_key(&secp, &key), EX1_DONATION);
}

#[test]
fn encode_reproduces_example_2() {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&hex::decode_array::<32>(PRIV_KEY).unwrap()).unwrap();
    let mut features = Features::empty();
    features.set(8);
    features.set(14);
    let builder = InvoiceBuilder {
        network: Network::Bitcoin,
        amount_msat: Some(Msat(250_000_000)),
        timestamp: TIMESTAMP,
        payment_hash: expected_payment_hash(),
        payment_secret: expected_payment_secret(),
        description: Description::Direct("1 cup coffee".into()),
        expiry_secs: Some(60),
        min_final_cltv_expiry_delta: None,
        features,
        route_hints: vec![],
    };
    assert_eq!(builder.encode_with_key(&secp, &key), EX2_COFFEE);
}

#[test]
fn encode_reproduces_example_4() {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&hex::decode_array::<32>(PRIV_KEY).unwrap()).unwrap();
    let mut features = Features::empty();
    features.set(8);
    features.set(14);
    let builder = InvoiceBuilder {
        network: Network::Bitcoin,
        amount_msat: Some(Msat(2_000_000_000)),
        timestamp: TIMESTAMP,
        payment_hash: expected_payment_hash(),
        payment_secret: expected_payment_secret(),
        description: Description::Hash(
            hex::decode_array("3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1")
                .unwrap(),
        ),
        expiry_secs: None,
        min_final_cltv_expiry_delta: None,
        features,
        route_hints: vec![],
    };
    assert_eq!(builder.encode_with_key(&secp, &key), EX4_HASHED);
}

#[test]
fn roundtrip_with_route_hints_and_cltv() {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&hex::decode_array::<32>(PRIV_KEY).unwrap()).unwrap();
    let hint_node = SecretKey::from_slice(&[9u8; 32]).unwrap().public_key(&secp);
    let builder = InvoiceBuilder {
        network: Network::Regtest,
        amount_msat: Some(Msat(123_456_001)),
        timestamp: 1_700_000_000,
        payment_hash: expected_payment_hash(),
        payment_secret: expected_payment_secret(),
        description: Description::Direct("hints".into()),
        expiry_secs: Some(7200),
        min_final_cltv_expiry_delta: Some(40),
        features: InvoiceBuilder::default_features(),
        route_hints: vec![vec![RouteHintHop {
            src_node_id: hint_node,
            short_channel_id: ShortChannelId::new(100, 1, 0),
            fee_base_msat: 1000,
            fee_proportional_millionths: 2500,
            cltv_expiry_delta: 144,
        }]],
    };
    let encoded = builder.encode_with_key(&secp, &key);
    let parsed = Bolt11Invoice::parse(&encoded).unwrap();
    assert_eq!(parsed.network, Network::Regtest);
    assert_eq!(parsed.amount_msat, Some(Msat(123_456_001)));
    assert_eq!(parsed.expiry_secs, Some(7200));
    assert_eq!(parsed.min_final_cltv_expiry_delta, Some(40));
    assert_eq!(parsed.route_hints.len(), 1);
    assert_eq!(parsed.route_hints[0][0].src_node_id, hint_node);
    assert_eq!(parsed.route_hints[0][0].cltv_expiry_delta, 144);
    assert_eq!(parsed.payee, key.public_key(&secp));
}

#[test]
fn invalid_invoices_rejected() {
    // Bad checksum (flipped final char of example 1).
    let mut s = EX1_DONATION.to_string();
    s.pop();
    s.push('m');
    assert!(Bolt11Invoice::parse(&s).is_err());
    // Not lightning.
    assert!(Bolt11Invoice::parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err());
    // Amount with bad multiplier (from the spec's invalid examples).
    assert!(Bolt11Invoice::parse("lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu7hqtk93pkf7sw55rdv4k9z2vj050rxdr6za9ekfs3nlt5lr89jqpdmxsmlj9urqumg0h9wzpqecw7th56tdms40p2ny9q4ddvjsedzcplva53s").is_err());
    // Truncated.
    assert!(Bolt11Invoice::parse("lnbc1pvjluez").is_err());
}
