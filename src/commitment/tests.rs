//! BOLT 3 Appendix C test vectors, byte-for-byte.

use super::*;
use crate::bitcoin::{SighashCache, SighashType};
use crate::keys::{self, ChannelPublicKeys, TxCreationKeys};
use crate::util::hex;
use secp256k1::{Message, Secp256k1, SecretKey};

const FUNDING_AMOUNT_SAT: u64 = 10_000_000;
const COMMITMENT_NUMBER: u64 = 42;
const TO_SELF_DELAY: u16 = 144;
const DUST_LIMIT_SAT: u64 = 546;

struct Harness {
    secp: Secp256k1<secp256k1::All>,
    keys: TxCreationKeys,
    funding_outpoint: OutPoint,
    obscure: u64,
    local_funding_sk: SecretKey,
    remote_funding_sk: SecretKey,
    local_funding_pk: PublicKey,
    remote_funding_pk: PublicKey,
    local_htlc_sk: SecretKey,
    remote_htlc_sk: SecretKey,
    remote_payment_basepoint: PublicKey,
}

fn sk(s: &str) -> SecretKey {
    SecretKey::from_slice(&hex::decode_array::<32>(s).unwrap()).unwrap()
}

fn harness() -> Harness {
    let secp = Secp256k1::new();

    let local_funding_sk =
        sk("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749");
    let remote_funding_sk =
        sk("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13");
    let local_payment_base_sk =
        sk("1111111111111111111111111111111111111111111111111111111111111111");
    let remote_payment_base_sk =
        sk("4444444444444444444444444444444444444444444444444444444444444444");
    let remote_revocation_base_sk =
        sk("2222222222222222222222222222222222222222222222222222222222222222");
    let local_delayed_base_sk =
        sk("3333333333333333333333333333333333333333333333333333333333333333");
    let per_commitment_secret =
        sk("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

    let local_payment_basepoint = local_payment_base_sk.public_key(&secp);
    let remote_payment_basepoint = remote_payment_base_sk.public_key(&secp);
    let per_commitment_point = per_commitment_secret.public_key(&secp);

    assert_eq!(
        hex::encode(&local_payment_basepoint.serialize()),
        "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
    );
    assert_eq!(
        hex::encode(&remote_payment_basepoint.serialize()),
        "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
    );
    assert_eq!(
        hex::encode(&per_commitment_point.serialize()),
        "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"
    );

    // Local broadcasts; both sides use payment basepoint as HTLC basepoint
    // in these vectors.
    let broadcaster = ChannelPublicKeys {
        funding_pubkey: local_funding_sk.public_key(&secp),
        revocation_basepoint: local_payment_basepoint, // unused here
        payment_basepoint: local_payment_basepoint,
        delayed_payment_basepoint: local_delayed_base_sk.public_key(&secp),
        htlc_basepoint: local_payment_basepoint,
    };
    let countersignatory = ChannelPublicKeys {
        funding_pubkey: remote_funding_sk.public_key(&secp),
        revocation_basepoint: remote_revocation_base_sk.public_key(&secp),
        payment_basepoint: remote_payment_basepoint,
        delayed_payment_basepoint: remote_payment_basepoint, // unused
        htlc_basepoint: remote_payment_basepoint,
    };

    let keys = TxCreationKeys::derive(&secp, &per_commitment_point, &broadcaster, &countersignatory);
    assert_eq!(
        hex::encode(&keys.revocation_key.serialize()),
        "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19"
    );
    assert_eq!(
        hex::encode(&keys.broadcaster_htlc_key.serialize()),
        "030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7"
    );
    assert_eq!(
        hex::encode(&keys.countersignatory_htlc_key.serialize()),
        "0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b"
    );
    assert_eq!(
        hex::encode(&keys.broadcaster_delayed_payment_key.serialize()),
        "03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c"
    );

    let local_htlc_sk = keys::derive_privkey(&local_payment_base_sk, &per_commitment_point);
    assert_eq!(
        hex::encode(&local_htlc_sk.secret_bytes()),
        "bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f274694491"
    );
    let remote_htlc_sk = keys::derive_privkey(&remote_payment_base_sk, &per_commitment_point);

    let obscure = commit_number_obscure_factor(&local_payment_basepoint, &remote_payment_basepoint);
    assert_eq!(obscure, 0x2bb038521914);

    let local_funding_pk = local_funding_sk.public_key(&secp);
    let remote_funding_pk = remote_funding_sk.public_key(&secp);
    assert_eq!(
        hex::encode(&local_funding_pk.serialize()),
        "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
    );
    assert_eq!(
        hex::encode(&remote_funding_pk.serialize()),
        "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"
    );
    assert_eq!(
        hex::encode(
            scripts::funding_redeemscript(&local_funding_pk, &remote_funding_pk).as_bytes()
        ),
        "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b\
         623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"
    );

    Harness {
        secp,
        keys,
        funding_outpoint: OutPoint::new(
            Txid::from_display_hex(
                "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be",
            )
            .unwrap(),
            0,
        ),
        obscure,
        local_funding_sk,
        remote_funding_sk,
        local_funding_pk,
        remote_funding_pk,
        local_htlc_sk,
        remote_htlc_sk,
        remote_payment_basepoint,
    }
}

/// (offered, amount_msat, expiry, preimage_byte)
const HTLCS: [(bool, u64, u32, u8); 7] = [
    (false, 1_000_000, 500, 0x00),
    (false, 2_000_000, 501, 0x01),
    (true, 2_000_000, 502, 0x02),
    (true, 3_000_000, 503, 0x03),
    (false, 4_000_000, 504, 0x04),
    (true, 5_000_000, 506, 0x05),
    (true, 5_000_001, 505, 0x05),
];

fn htlc(i: usize) -> HtlcOutputInCommitment {
    let (offered, amount, expiry, pre) = HTLCS[i];
    HtlcOutputInCommitment {
        offered,
        amount_msat: Msat(amount),
        cltv_expiry: expiry,
        payment_hash: PaymentPreimage([pre; 32]).payment_hash(),
    }
}

struct Case {
    to_local_msat: u64,
    to_remote_msat: u64,
    feerate: u32,
    htlc_indices: &'static [usize],
    expected_commit_tx: &'static str,
    /// (htlc_index, expected_signed_htlc_tx_hex), in output order.
    htlc_txs: &'static [(usize, &'static str)],
}

fn run_case(case: &Case) {
    let h = harness();
    let htlcs: Vec<HtlcOutputInCommitment> =
        case.htlc_indices.iter().map(|&i| htlc(i)).collect();
    let built = build_commitment_tx(&CommitmentTxParams {
        funding_outpoint: h.funding_outpoint,
        commitment_number: COMMITMENT_NUMBER,
        obscure_factor: h.obscure,
        broadcaster_pays_fee: true,
        feerate: FeeRatePerKw(case.feerate),
        broadcaster_dust_limit_sat: DUST_LIMIT_SAT,
        to_self_delay: TO_SELF_DELAY,
        keys: &h.keys,
        countersignatory_payment_basepoint: h.remote_payment_basepoint,
        to_broadcaster_msat: Msat(case.to_local_msat),
        to_countersignatory_msat: Msat(case.to_remote_msat),
        htlcs: &htlcs,
    });

    // Sign the funding spend with both keys.
    let redeem = scripts::funding_redeemscript(&h.local_funding_pk, &h.remote_funding_pk);
    let cache = SighashCache::new(&built.tx);
    let sighash = cache.segwit_v0_sighash(0, &redeem, FUNDING_AMOUNT_SAT, SighashType::All);
    let msg = Message::from_digest(sighash);
    let local_sig = h.secp.sign_ecdsa(&msg, &h.local_funding_sk);
    let remote_sig = h.secp.sign_ecdsa(&msg, &h.remote_funding_sk);

    let mut signed = built.tx.clone();
    signed.input[0].witness =
        funding_spend_witness(&h.local_funding_pk, &h.remote_funding_pk, &local_sig, &remote_sig);
    assert_eq!(hex::encode(&signed.serialize()), case.expected_commit_tx, "commitment tx hex");

    // Second-stage HTLC transactions (cases with an empty list only check
    // the commitment tx itself).
    if case.htlc_txs.is_empty() {
        return;
    }
    assert_eq!(built.htlcs_in_output_order.len(), case.htlc_txs.len(), "untrimmed HTLC count");
    for (pos, (input_idx, witness_script)) in built.htlcs_in_output_order.iter().enumerate() {
        let (expected_htlc_index, expected_hex) = case.htlc_txs[pos];
        assert_eq!(
            case.htlc_indices[*input_idx], expected_htlc_index,
            "HTLC order at output position {pos}"
        );
        let this = &htlcs[*input_idx];
        let vout = built.htlc_output_indices[*input_idx].unwrap();
        let mut htlc_tx = build_htlc_tx(
            &built.txid,
            vout,
            this,
            &h.keys,
            TO_SELF_DELAY,
            FeeRatePerKw(case.feerate),
        );
        let cache = SighashCache::new(&htlc_tx);
        let sighash = cache.segwit_v0_sighash(
            0,
            witness_script,
            this.amount_msat.to_sat_floor(),
            SighashType::All,
        );
        let msg = Message::from_digest(sighash);
        let local_sig = h.secp.sign_ecdsa(&msg, &h.local_htlc_sk);
        let remote_sig = h.secp.sign_ecdsa(&msg, &h.remote_htlc_sk);
        let preimage_byte = HTLCS[expected_htlc_index].3;
        let preimage = PaymentPreimage([preimage_byte; 32]);
        htlc_tx.input[0].witness = htlc_tx_witness(
            &remote_sig,
            &local_sig,
            (!this.offered).then_some(&preimage),
            witness_script,
        );
        assert_eq!(
            hex::encode(&htlc_tx.serialize()),
            expected_hex,
            "HTLC tx hex for htlc #{expected_htlc_index}"
        );
    }
}

#[test]
fn no_htlcs_case_produces_two_outputs() {
    let h = harness();
    let built = build_commitment_tx(&CommitmentTxParams {
        funding_outpoint: h.funding_outpoint,
        commitment_number: COMMITMENT_NUMBER,
        obscure_factor: h.obscure,
        broadcaster_pays_fee: true,
        feerate: FeeRatePerKw(15000),
        broadcaster_dust_limit_sat: DUST_LIMIT_SAT,
        to_self_delay: TO_SELF_DELAY,
        keys: &h.keys,
        countersignatory_payment_basepoint: h.remote_payment_basepoint,
        to_broadcaster_msat: Msat(7_000_000_000),
        to_countersignatory_msat: Msat(3_000_000_000),
        htlcs: &[],
    });
    assert!(built.htlcs_in_output_order.is_empty());
    assert_eq!(built.tx.output.len(), 2);
}

#[test]
fn simple_commitment_tx_with_no_htlcs() {
    run_case(&Case {
        to_local_msat: 7_000_000_000,
        to_remote_msat: 3_000_000_000,
        feerate: 15000,
        htlc_indices: &[],
        expected_commit_tx: "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e48454a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae05564714201483045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
        htlc_txs: &[],
    });
}

#[test]
fn commitment_tx_with_all_five_htlcs_untrimmed_minimum_feerate() {
    run_case(&Case {
        to_local_msat: 6_988_000_000,
        to_remote_msat: 3_000_000_000,
        feerate: 0,
        htlc_indices: &[0, 1, 2, 3, 4],
        expected_commit_tx: "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402206fc2d1f10ea59951eefac0b4b7c396a3c3d87b71ff0b019796ef4535beaf36f902201765b0181e514d04f4c8ad75659d7037be26cdb3f8bb6f78fe61decef484c3ea01473044022009b048187705a8cbc9ad73adbe5af148c3d012e1f067961486c822c7af08158c022006d66f3704cfab3eb2dc49dae24e4aa22a6910fc9b424007583204e3621af2e501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
        htlc_txs: &[
            (0, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b00000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100d9e29616b8f3959f1d3d7f7ce893ffedcdc407717d0de8e37d808c91d3a7c50d022078c3033f6d00095c8720a4bc943c1b45727818c082e4e3ddbc6d3116435b624b014730440220636de5682ef0c5b61f124ec74e8aa2461a69777521d6998295dcea36bc3338110220165285594b23c50b28b82df200234566628a27bcd17f7f14404bd865354eb3ce012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000"),
            (2, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b01000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220649fe8b20e67e46cbb0d09b4acea87dbec001b39b08dee7bdd0b1f03922a8640022037c462dff79df501cecfdb12ea7f4de91f99230bb544726f6e04527b1f89600401483045022100803159dee7935dba4a1d36a61055ce8fd62caa528573cc221ae288515405a252022029c59e7cffce374fe860100a4a63787e105c3cf5156d40b12dd53ff55ac8cf3f01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868f6010000"),
            (1, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b02000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220770fc321e97a19f38985f2e7732dd9fe08d16a2efa4bcbc0429400a447faf49102204d40b417f3113e1b0944ae0986f517564ab4acd3d190503faf97a6e420d4335201483045022100a437cc2ce77400ecde441b3398fea3c3ad8bdad8132be818227fe3c5b8345989022069d45e7fa0ae551ec37240845e2c561ceb2567eacf3076a6a43a502d05865faa012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000"),
            (3, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b03000000000000000001b80b0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207bcbf4f60a9829b05d2dbab84ed593e0291836be715dc7db6b72a64caf646af802201e489a5a84f7c5cc130398b841d138d031a5137ac8f4c49c770a4959dc3c13630147304402203121d9b9c055f354304b016a36662ee99e1110d9501cb271b087ddb6f382c2c80220549882f3f3b78d9c492de47543cb9a697cecc493174726146536c5954dac748701008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868f7010000"),
            (4, "02000000000101ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b04000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022076dca5cb81ba7e466e349b7128cdba216d4d01659e29b96025b9524aaf0d1899022060de85697b88b21c749702b7d2cfa7dfeaa1f472c8f1d7d9c23f2bf968464b8701483045022100d9080f103cc92bac15ec42464a95f070c7fb6925014e673ee2ea1374d36a7f7502200c65294d22eb20d48564954d5afe04a385551919d8b2ddb4ae2459daaeee1d95012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000"),
        ],
    });
}

#[test]
fn commitment_tx_with_six_outputs_untrimmed_minimum_feerate() {
    // feerate 648: HTLC #0 (1000 sat) is trimmed (success fee 455 + dust 546 > 1000).
    run_case(&Case {
        to_local_msat: 6_988_000_000,
        to_remote_msat: 3_000_000_000,
        feerate: 648,
        htlc_indices: &[0, 1, 2, 3, 4],
        expected_commit_tx: "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e4844e9d6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100b15f72908ba3382a34ca5b32519240a22300cc6015b6f9418635fb41f3d01d8802207adb331b9ed1575383dca0f2355e86c173802feecf8298fbea53b9d4610583e90147304402203948f900a5506b8de36a4d8502f94f21dd84fd9c2314ab427d52feaa7a0a19f2022059b6a37a4adaa2c5419dc8aea63c6e2a2ec4c4bde46207f6dc1fcd22152fc6e501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
        // (HTLC tx vectors for this case omitted here; covered by the
        // feerate-0 and same-preimage cases.)
        htlc_txs: &[],
    });
}

#[test]
fn commitment_tx_same_amount_and_preimage_cltv_tiebreak() {
    // HTLCs 5 and 6 produce byte-identical outputs; ordering must fall
    // back to cltv_expiry (505 before 506).
    run_case(&Case {
        to_local_msat: 6_987_999_999,
        to_remote_msat: 3_000_000_000,
        feerate: 253,
        htlc_indices: &[1, 5, 6],
        expected_commit_tx: "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2d8813000000000000220020305c12e1a0bc21e283c131cea1c66d68857d28b7b2fce0a6fbc40c164852121b8813000000000000220020305c12e1a0bc21e283c131cea1c66d68857d28b7b2fce0a6fbc40c164852121bc0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e484a69f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402200d10bf5bc5397fc59d7188ae438d80c77575595a2d488e41bd6363a810cc8d72022012b57e714fbbfdf7a28c47d5b370cb8ac37c8545f596216e5b21e9b236ef457c0147304402207d0870964530f97b62497b11153c551dca0a1e226815ef0a336651158da0f82402200f5378beee0e77759147b8a0a284decd11bfd2bc55c8fafa41c134fe996d43c801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
        htlc_txs: &[
            (1, "020000000001014bdccf28653066a2c554cafeffdfe1e678e64a69b056684deb0c4fba909423ec000000000000000000011f070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100b470fe12e5b7fea9eccb8cbff1972cea4f96758041898982a02bcc7f9d56d50b0220338a75b2afaab4ec00cdd2d9273c68c7581ff5a28bcbb40c4d138b81f1d45ce501473044022017b90c65207522a907fb6a137f9dd528b3389465a8ae72308d9e1d564f512cf402204fc917b4f0e88604a3e994f85bfae7c7c1f9d9e9f78e8cd112e0889720d9405b012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000"),
            (6, "020000000001014bdccf28653066a2c554cafeffdfe1e678e64a69b056684deb0c4fba909423ec01000000000000000001e1120000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100b575379f6d8743cb0087648f81cfd82d17a97fbf8f67e058c65ce8b9d25df9500220554a210d65b02d9f36c6adf0f639430ca8293196ba5089bf67cc3a9813b7b00a01483045022100ee2e16b90930a479b13f8823a7f14b600198c838161160b9436ed086d3fc57e002202a66fa2324f342a17129949c640bfe934cbc73a869ba7c06aa25c5a3d0bfb53d01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9142002cc93ebefbb1b73f0af055dcc27a0b504ad7688ac6868f9010000"),
            (5, "020000000001014bdccf28653066a2c554cafeffdfe1e678e64a69b056684deb0c4fba909423ec02000000000000000001e1120000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220471c9f3ad92e49b13b7b8059f43ecf8f7887b0dccbb9fdb54bfe23d62a8ae332022024bd22fae0740e86a44228c35330da9526fd7306dffb2b9dc362d5e78abef7cc0147304402207157f452f2506d73c315192311893800cfb3cc235cc1185b1cfcc136b55230db022014be242dbc6c5da141fec4034e7f387f74d6ff1899453d72ba957467540e1ecb01008576a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9142002cc93ebefbb1b73f0af055dcc27a0b504ad7688ac6868fa010000"),
        ],
    });
}

#[test]
fn closing_tx_shape() {
    let h = harness();
    let a_script = Script::new_p2wpkh(&[0x11; 20]);
    let b_script = Script::new_p2wpkh(&[0x22; 20]);
    let tx = build_closing_tx(h.funding_outpoint, 7_000_000, 3_000_000, &a_script, &b_script, 546);
    assert_eq!(tx.version, 2);
    assert_eq!(tx.lock_time, 0);
    assert_eq!(tx.input[0].sequence, 0xffff_ffff);
    // Sorted by value.
    assert_eq!(tx.output[0].value, 3_000_000);
    assert_eq!(tx.output[1].value, 7_000_000);
    // Dust dropped.
    let tx = build_closing_tx(h.funding_outpoint, 100, 3_000_000, &a_script, &b_script, 546);
    assert_eq!(tx.output.len(), 1);
}
