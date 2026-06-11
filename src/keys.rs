//! BOLT 3 key derivation: per-commitment tweaks of the channel basepoints
//! and the doubly-blinded revocation key.

use crate::crypto::sha256::Sha256;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification};

/// The five public keys a peer contributes when opening a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPublicKeys {
    pub funding_pubkey: PublicKey,
    pub revocation_basepoint: PublicKey,
    pub payment_basepoint: PublicKey,
    pub delayed_payment_basepoint: PublicKey,
    pub htlc_basepoint: PublicKey,
}

/// The per-commitment key set for one specific commitment transaction,
/// from the perspective of the side that can broadcast it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxCreationKeys {
    pub per_commitment_point: PublicKey,
    /// Pays to the *other* side if this commitment is revoked.
    pub revocation_key: PublicKey,
    /// The broadcaster's HTLC key.
    pub broadcaster_htlc_key: PublicKey,
    /// The other side's HTLC key.
    pub countersignatory_htlc_key: PublicKey,
    /// The broadcaster's CSV-delayed to_local key.
    pub broadcaster_delayed_payment_key: PublicKey,
}

impl TxCreationKeys {
    /// Derive the full key set for a commitment held by `broadcaster`.
    pub fn derive<C: Verification>(
        secp: &Secp256k1<C>,
        per_commitment_point: &PublicKey,
        broadcaster: &ChannelPublicKeys,
        countersignatory: &ChannelPublicKeys,
    ) -> TxCreationKeys {
        TxCreationKeys {
            per_commitment_point: *per_commitment_point,
            revocation_key: derive_revocation_pubkey(
                secp,
                &countersignatory.revocation_basepoint,
                per_commitment_point,
            ),
            broadcaster_htlc_key: derive_pubkey(secp, &broadcaster.htlc_basepoint, per_commitment_point),
            countersignatory_htlc_key: derive_pubkey(
                secp,
                &countersignatory.htlc_basepoint,
                per_commitment_point,
            ),
            broadcaster_delayed_payment_key: derive_pubkey(
                secp,
                &broadcaster.delayed_payment_basepoint,
                per_commitment_point,
            ),
        }
    }
}

fn tweak(a: &PublicKey, b: &PublicKey) -> Scalar {
    let mut h = Sha256::new();
    h.update(&a.serialize());
    h.update(&b.serialize());
    Scalar::from_be_bytes(h.finalize()).expect("SHA256 output below curve order with overwhelming probability")
}

/// `pubkey = basepoint + SHA256(per_commitment_point || basepoint) * G`
pub fn derive_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    basepoint
        .add_exp_tweak(secp, &tweak(per_commitment_point, basepoint))
        .expect("tweak addition cannot fail for valid keys")
}

/// `privkey = basepoint_secret + SHA256(per_commitment_point || basepoint)`
pub fn derive_privkey(base_secret: &SecretKey, per_commitment_point: &PublicKey) -> SecretKey {
    let basepoint = base_secret.public_key(&Secp256k1::signing_only());
    base_secret
        .add_tweak(&tweak(per_commitment_point, &basepoint))
        .expect("tweak addition cannot fail for valid keys")
}

/// `revocationpubkey = revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point)
///                   + per_commitment_point * SHA256(per_commitment_point || revocation_basepoint)`
pub fn derive_revocation_pubkey<C: Verification>(
    secp: &Secp256k1<C>,
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let a = revocation_basepoint
        .mul_tweak(secp, &tweak(revocation_basepoint, per_commitment_point))
        .expect("mul tweak");
    let b = per_commitment_point
        .mul_tweak(secp, &tweak(per_commitment_point, revocation_basepoint))
        .expect("mul tweak");
    a.combine(&b).expect("point addition of distinct points")
}

/// `revocationprivkey = revocation_basepoint_secret * SHA256(revocation_basepoint || per_commitment_point)
///                    + per_commitment_secret * SHA256(per_commitment_point || revocation_basepoint)`
pub fn derive_revocation_privkey(
    revocation_base_secret: &SecretKey,
    per_commitment_secret: &SecretKey,
) -> SecretKey {
    let signing = Secp256k1::signing_only();
    let revocation_basepoint = revocation_base_secret.public_key(&signing);
    let per_commitment_point = per_commitment_secret.public_key(&signing);

    let a = revocation_base_secret
        .mul_tweak(&tweak(&revocation_basepoint, &per_commitment_point))
        .expect("mul tweak");
    let b = per_commitment_secret
        .mul_tweak(&tweak(&per_commitment_point, &revocation_basepoint))
        .expect("mul tweak");
    a.add_tweak(&Scalar::from(b)).expect("scalar addition")
}

/// `per_commitment_point = per_commitment_secret * G`
pub fn per_commitment_point(per_commitment_secret: &[u8; 32]) -> PublicKey {
    let sk = SecretKey::from_slice(per_commitment_secret).expect("valid secret");
    sk.public_key(&Secp256k1::signing_only())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    fn sk(s: &str) -> SecretKey {
        SecretKey::from_slice(&hex::decode_array::<32>(s).unwrap()).unwrap()
    }
    fn pk(s: &str) -> PublicKey {
        PublicKey::from_slice(&hex::decode(s).unwrap()).unwrap()
    }

    const BASE_SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PER_COMMITMENT_SECRET: &str =
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
    const BASE_POINT: &str = "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2";
    const PER_COMMITMENT_POINT: &str =
        "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486";

    // BOLT 3 Appendix E.
    #[test]
    fn pubkey_derivation() {
        let secp = Secp256k1::new();
        let derived = derive_pubkey(&secp, &pk(BASE_POINT), &pk(PER_COMMITMENT_POINT));
        assert_eq!(
            hex::encode(&derived.serialize()),
            "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"
        );
    }

    #[test]
    fn privkey_derivation() {
        let derived = derive_privkey(&sk(BASE_SECRET), &pk(PER_COMMITMENT_POINT));
        assert_eq!(
            hex::encode(&derived.secret_bytes()),
            "cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f"
        );
        // And it must be the discrete log of the derived pubkey.
        let secp = Secp256k1::new();
        assert_eq!(
            derived.public_key(&secp),
            derive_pubkey(&secp, &pk(BASE_POINT), &pk(PER_COMMITMENT_POINT))
        );
    }

    #[test]
    fn revocation_pubkey_derivation() {
        let secp = Secp256k1::new();
        let derived = derive_revocation_pubkey(&secp, &pk(BASE_POINT), &pk(PER_COMMITMENT_POINT));
        assert_eq!(
            hex::encode(&derived.serialize()),
            "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"
        );
    }

    #[test]
    fn revocation_privkey_derivation() {
        let derived =
            derive_revocation_privkey(&sk(BASE_SECRET), &sk(PER_COMMITMENT_SECRET));
        assert_eq!(
            hex::encode(&derived.secret_bytes()),
            "d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110"
        );
        let secp = Secp256k1::new();
        assert_eq!(
            derived.public_key(&secp),
            derive_revocation_pubkey(&secp, &pk(BASE_POINT), &pk(PER_COMMITMENT_POINT))
        );
    }
}
