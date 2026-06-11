//! Key management abstraction.
//!
//! Every secret-key operation the node performs flows through these traits,
//! so keys can live in-process ([`KeysManager`]), in an HSM, or on a remote
//! signer. The engine itself never sees raw node/channel secrets except
//! through this interface.

use crate::crypto::hkdf;
use crate::keys::{self, ChannelPublicKeys};
use crate::shachain;
use secp256k1::ecdsa::{RecoverableSignature, Signature};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

/// Source of cryptographic randomness. The engine *never* calls OS RNGs
/// directly — inject [`OsEntropy`] for production or a deterministic
/// source for reproducible tests/fuzzing.
pub trait EntropySource {
    fn get_random_bytes(&mut self) -> [u8; 32];
}

/// OS-backed entropy.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn get_random_bytes(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("OS RNG unavailable");
        b
    }
}

/// Deterministic entropy for tests: SHA256(seed || counter).
pub struct TestEntropy {
    seed: [u8; 32],
    counter: u64,
}

impl TestEntropy {
    pub fn new(seed: [u8; 32]) -> TestEntropy {
        TestEntropy { seed, counter: 0 }
    }
}

impl EntropySource for TestEntropy {
    fn get_random_bytes(&mut self) -> [u8; 32] {
        let mut h = crate::crypto::sha256::Sha256::new();
        h.update(&self.seed);
        h.update(&self.counter.to_be_bytes());
        self.counter += 1;
        h.finalize()
    }
}

/// Node-level signing: identity key operations.
pub trait NodeSigner {
    fn node_id(&self) -> PublicKey;
    /// ECDH with the node identity key (onion peeling).
    fn ecdh(&self, other: &PublicKey) -> [u8; 32];
    /// Sign a BOLT 7 gossip message (digest = double-SHA256 of payload).
    fn sign_gossip(&self, double_sha: &[u8; 32]) -> Signature;
    /// Sign a BOLT 11 invoice digest, recoverably.
    fn sign_invoice_digest(&self, digest: &[u8; 32]) -> RecoverableSignature;
    /// The node identity secret, used *only* to drive the BOLT 8 Noise
    /// handshake. A remote-signer deployment would return a session-scoped
    /// key here and route channel/gossip signing through the other methods;
    /// the transport key cannot leak channel funds.
    fn noise_secret(&self) -> SecretKey;
}

/// Per-channel signing. One instance per channel, derived deterministically
/// so channels can be restored from the node seed.
pub trait ChannelSigner {
    fn pubkeys(&self) -> &ChannelPublicKeys;
    /// Our per-commitment point for holder commitment `n`.
    fn per_commitment_point(&self, n: u64) -> PublicKey;
    /// Reveal the per-commitment secret for holder commitment `n` —
    /// only called once `n` is being revoked.
    fn release_commitment_secret(&self, n: u64) -> [u8; 32];
    /// Sign with the funding key (commitment/closing txs).
    fn sign_with_funding_key(&self, sighash: &[u8; 32]) -> Signature;
    /// Sign with the HTLC key derived for `per_commitment_point`.
    fn sign_htlc(&self, sighash: &[u8; 32], per_commitment_point: &PublicKey) -> Signature;
    /// Sign with the delayed-payment key (sweeping our `to_local` after CSV).
    fn sign_delayed_payment(&self, sighash: &[u8; 32], per_commitment_point: &PublicKey)
        -> Signature;
    /// Sign with the payment key (sweeping `to_remote` on their commitment;
    /// static remotekey means this is just the payment basepoint key).
    fn sign_payment(&self, sighash: &[u8; 32]) -> Signature;
    /// Sign with the revocation key derived from a revealed counterparty
    /// per-commitment secret (justice transactions).
    fn sign_revocation(
        &self,
        sighash: &[u8; 32],
        counterparty_per_commitment_secret: &[u8; 32],
    ) -> Signature;
    /// Sign a channel_announcement with the funding key.
    fn sign_announcement_with_funding_key(&self, double_sha: &[u8; 32]) -> Signature;
}

/// Derives per-channel signers from the node seed.
pub trait SignerProvider {
    type Signer: ChannelSigner;
    fn derive_channel_signer(&self, channel_index: u64) -> Self::Signer;
}

/// In-memory signer holding raw channel secrets.
#[derive(Clone)]
pub struct InMemoryChannelSigner {
    pub funding_key: SecretKey,
    pub revocation_base_key: SecretKey,
    pub payment_key: SecretKey,
    pub delayed_payment_base_key: SecretKey,
    pub htlc_base_key: SecretKey,
    pub commitment_seed: [u8; 32],
    pubkeys: ChannelPublicKeys,
    secp: Secp256k1<secp256k1::All>,
}

impl InMemoryChannelSigner {
    pub fn new(
        funding_key: SecretKey,
        revocation_base_key: SecretKey,
        payment_key: SecretKey,
        delayed_payment_base_key: SecretKey,
        htlc_base_key: SecretKey,
        commitment_seed: [u8; 32],
    ) -> InMemoryChannelSigner {
        let secp = Secp256k1::new();
        let pubkeys = ChannelPublicKeys {
            funding_pubkey: funding_key.public_key(&secp),
            revocation_basepoint: revocation_base_key.public_key(&secp),
            payment_basepoint: payment_key.public_key(&secp),
            delayed_payment_basepoint: delayed_payment_base_key.public_key(&secp),
            htlc_basepoint: htlc_base_key.public_key(&secp),
        };
        InMemoryChannelSigner {
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            pubkeys,
            secp,
        }
    }
}

impl ChannelSigner for InMemoryChannelSigner {
    fn pubkeys(&self) -> &ChannelPublicKeys {
        &self.pubkeys
    }

    fn per_commitment_point(&self, n: u64) -> PublicKey {
        let secret =
            shachain::generate_from_seed(&self.commitment_seed, shachain::index_for_commitment(n));
        SecretKey::from_slice(&secret).expect("valid secret").public_key(&self.secp)
    }

    fn release_commitment_secret(&self, n: u64) -> [u8; 32] {
        shachain::generate_from_seed(&self.commitment_seed, shachain::index_for_commitment(n))
    }

    fn sign_with_funding_key(&self, sighash: &[u8; 32]) -> Signature {
        self.secp.sign_ecdsa(&Message::from_digest(*sighash), &self.funding_key)
    }

    fn sign_htlc(&self, sighash: &[u8; 32], per_commitment_point: &PublicKey) -> Signature {
        let key = keys::derive_privkey(&self.htlc_base_key, per_commitment_point);
        self.secp.sign_ecdsa(&Message::from_digest(*sighash), &key)
    }

    fn sign_delayed_payment(
        &self,
        sighash: &[u8; 32],
        per_commitment_point: &PublicKey,
    ) -> Signature {
        let key = keys::derive_privkey(&self.delayed_payment_base_key, per_commitment_point);
        self.secp.sign_ecdsa(&Message::from_digest(*sighash), &key)
    }

    fn sign_payment(&self, sighash: &[u8; 32]) -> Signature {
        self.secp.sign_ecdsa(&Message::from_digest(*sighash), &self.payment_key)
    }

    fn sign_revocation(
        &self,
        sighash: &[u8; 32],
        counterparty_per_commitment_secret: &[u8; 32],
    ) -> Signature {
        let cp_secret = SecretKey::from_slice(counterparty_per_commitment_secret)
            .expect("valid per-commitment secret");
        let key = keys::derive_revocation_privkey(&self.revocation_base_key, &cp_secret);
        self.secp.sign_ecdsa(&Message::from_digest(*sighash), &key)
    }

    fn sign_announcement_with_funding_key(&self, double_sha: &[u8; 32]) -> Signature {
        self.secp.sign_ecdsa(&Message::from_digest(*double_sha), &self.funding_key)
    }
}

/// Seed-based key manager: implements [`NodeSigner`] and [`SignerProvider`].
///
/// Derivation (all HKDF-SHA256 from the 32-byte seed):
/// `node` → node identity key; `channel/<index>` → the five channel base
/// keys and the commitment seed.
pub struct KeysManager {
    seed: [u8; 32],
    node_secret: SecretKey,
    node_pubkey: PublicKey,
    secp: Secp256k1<secp256k1::All>,
}

impl KeysManager {
    pub fn new(seed: [u8; 32]) -> KeysManager {
        let secp = Secp256k1::new();
        let node_secret = derive_key(&seed, b"keraunos/node identity", 0, 0);
        let node_pubkey = node_secret.public_key(&secp);
        KeysManager { seed, node_secret, node_pubkey, secp }
    }

    pub fn node_secret(&self) -> &SecretKey {
        &self.node_secret
    }
}

fn derive_key(seed: &[u8; 32], label: &[u8], index: u64, sub: u8) -> SecretKey {
    let prk = hkdf::extract(label, seed);
    let mut info = Vec::with_capacity(9);
    info.extend_from_slice(&index.to_be_bytes());
    info.push(sub);
    // Loop until a valid scalar (probability of retry ~2^-128).
    let mut okm = [0u8; 32];
    let mut salt = 0u8;
    loop {
        let mut full_info = info.clone();
        full_info.push(salt);
        hkdf::expand(&prk, &full_info, &mut okm);
        if let Ok(sk) = SecretKey::from_slice(&okm) {
            return sk;
        }
        salt = salt.wrapping_add(1);
    }
}

impl NodeSigner for KeysManager {
    fn node_id(&self) -> PublicKey {
        self.node_pubkey
    }

    fn ecdh(&self, other: &PublicKey) -> [u8; 32] {
        secp256k1::ecdh::SharedSecret::new(other, &self.node_secret).secret_bytes()
    }

    fn sign_gossip(&self, double_sha: &[u8; 32]) -> Signature {
        self.secp.sign_ecdsa(&Message::from_digest(*double_sha), &self.node_secret)
    }

    fn sign_invoice_digest(&self, digest: &[u8; 32]) -> RecoverableSignature {
        self.secp.sign_ecdsa_recoverable(&Message::from_digest(*digest), &self.node_secret)
    }

    fn noise_secret(&self) -> SecretKey {
        self.node_secret
    }
}

impl SignerProvider for KeysManager {
    type Signer = InMemoryChannelSigner;

    fn derive_channel_signer(&self, channel_index: u64) -> InMemoryChannelSigner {
        let label: &[u8] = b"keraunos/channel keys";
        let funding = derive_key(&self.seed, label, channel_index, 0);
        let revocation = derive_key(&self.seed, label, channel_index, 1);
        let payment = derive_key(&self.seed, label, channel_index, 2);
        let delayed = derive_key(&self.seed, label, channel_index, 3);
        let htlc = derive_key(&self.seed, label, channel_index, 4);
        let commitment_seed = derive_key(&self.seed, label, channel_index, 5).secret_bytes();
        InMemoryChannelSigner::new(funding, revocation, payment, delayed, htlc, commitment_seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let km1 = KeysManager::new([7u8; 32]);
        let km2 = KeysManager::new([7u8; 32]);
        assert_eq!(km1.node_id(), km2.node_id());
        let s1 = km1.derive_channel_signer(3);
        let s2 = km2.derive_channel_signer(3);
        assert_eq!(s1.pubkeys(), s2.pubkeys());
        assert_eq!(s1.per_commitment_point(0), s2.per_commitment_point(0));
        // Different channels → different keys.
        let s3 = km1.derive_channel_signer(4);
        assert_ne!(s1.pubkeys().funding_pubkey, s3.pubkeys().funding_pubkey);
        // Different seeds → different node ids.
        assert_ne!(KeysManager::new([8u8; 32]).node_id(), km1.node_id());
    }

    #[test]
    fn commitment_secret_chain_is_consistent() {
        let signer = KeysManager::new([1u8; 32]).derive_channel_signer(0);
        // Point n must equal the public key of secret n.
        for n in [0u64, 1, 2, 100] {
            let secret = signer.release_commitment_secret(n);
            let point = crate::keys::per_commitment_point(&secret);
            assert_eq!(point, signer.per_commitment_point(n));
        }
        // And secrets must verify in a SecretStore in reveal order.
        let mut store = crate::shachain::SecretStore::new();
        for n in 0..10u64 {
            store
                .insert(
                    crate::shachain::index_for_commitment(n),
                    signer.release_commitment_secret(n),
                )
                .expect("consistent chain");
        }
    }
}
