//! BOLT 8: encrypted-and-authenticated transport.
//!
//! `Noise_XK_secp256k1_ChaChaPoly_SHA256`, exactly as the spec lays it
//! out: a 3-act handshake proving knowledge of the responder's static key
//! (the node id you dialed) and hiding the initiator's identity until
//! act 3, then a length-framed AEAD stream with key rotation every 1000
//! cipher operations per direction.
//!
//! Everything here is sans-I/O: the handshake types consume/produce fixed
//! 50/66-byte acts, and [`Transport`] is fed raw socket bytes, yielding
//! whole decrypted Lightning messages.

use crate::crypto::{aead, hkdf, sha256::Sha256};
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};

pub const ACT_ONE_LEN: usize = 50;
pub const ACT_TWO_LEN: usize = 50;
pub const ACT_THREE_LEN: usize = 66;
/// Maximum Lightning message body (u16 length prefix).
pub const MAX_MSG_LEN: usize = 65535;
const KEY_ROTATION_INTERVAL: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    BadVersion(u8),
    BadPubkey,
    BadTag,
    /// Internal misuse — acts driven in the wrong order.
    WrongState,
    MessageTooLong,
}

impl core::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NoiseError::BadVersion(v) => write!(f, "unknown handshake version {v}"),
            NoiseError::BadPubkey => write!(f, "invalid public key in handshake"),
            NoiseError::BadTag => write!(f, "AEAD tag verification failed"),
            NoiseError::WrongState => write!(f, "handshake act out of order"),
            NoiseError::MessageTooLong => write!(f, "message exceeds 65535 bytes"),
        }
    }
}

impl std::error::Error for NoiseError {}

/// `SHA256(SHA256(protocolName) || "lightning")`-seeded symmetric state.
struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
}

impl SymmetricState {
    fn new(responder_static: &PublicKey) -> SymmetricState {
        let proto = Sha256::digest(b"Noise_XK_secp256k1_ChaChaPoly_SHA256");
        let mut h = Sha256::new();
        h.update(&proto);
        h.update(b"lightning");
        let mut st = SymmetricState { h: h.finalize(), ck: proto };
        // XK pre-message: the responder's static key is mixed by both sides.
        st.mix_hash(&responder_static.serialize());
        st
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut h = Sha256::new();
        h.update(&self.h);
        h.update(data);
        self.h = h.finalize();
    }

    /// `ck, k = HKDF(ck, input)`
    fn mix_key(&mut self, input: &[u8]) -> [u8; 32] {
        let (ck, k) = hkdf::hkdf_two_keys(&self.ck, input);
        self.ck = ck;
        k
    }
}

fn ecdh(pubkey: &PublicKey, privkey: &SecretKey) -> [u8; 32] {
    // libsecp256k1's default ECDH: SHA256 of the compressed shared point —
    // exactly BOLT 8's definition.
    secp256k1::ecdh::SharedSecret::new(pubkey, privkey).secret_bytes()
}

/// Initiator side of the handshake. Construct, send [`Self::act_one`],
/// feed the peer's act 2 to get act 3, then [`Self::into_transport`].
pub struct Initiator {
    st: SymmetricState,
    local_static: SecretKey,
    ephemeral: SecretKey,
    remote_static: PublicKey,
    temp_k2: Option<[u8; 32]>,
    done: bool,
    secp: Secp256k1<SignOnly>,
}

impl Initiator {
    pub fn new(local_static: SecretKey, remote_static: PublicKey, ephemeral: SecretKey) -> Initiator {
        Initiator {
            st: SymmetricState::new(&remote_static),
            local_static,
            ephemeral,
            remote_static,
            temp_k2: None,
            done: false,
            secp: Secp256k1::signing_only(),
        }
    }

    pub fn act_one(&mut self) -> [u8; ACT_ONE_LEN] {
        let e_pub = PublicKey::from_secret_key(&self.secp, &self.ephemeral);
        self.st.mix_hash(&e_pub.serialize());
        let ss = ecdh(&self.remote_static, &self.ephemeral);
        let temp_k1 = self.st.mix_key(&ss);
        let c = aead::encrypt(&temp_k1, &aead::nonce_from_counter(0), &self.st.h, &[]);
        self.st.mix_hash(&c);

        let mut out = [0u8; ACT_ONE_LEN];
        out[0] = 0;
        out[1..34].copy_from_slice(&e_pub.serialize());
        out[34..].copy_from_slice(&c);
        out
    }

    /// Process act 2 and produce act 3.
    pub fn act_two(&mut self, act2: &[u8; ACT_TWO_LEN]) -> Result<[u8; ACT_THREE_LEN], NoiseError> {
        if act2[0] != 0 {
            return Err(NoiseError::BadVersion(act2[0]));
        }
        let re = PublicKey::from_slice(&act2[1..34]).map_err(|_| NoiseError::BadPubkey)?;
        let c = &act2[34..];

        self.st.mix_hash(&re.serialize());
        let ss = ecdh(&re, &self.ephemeral);
        let temp_k2 = self.st.mix_key(&ss);
        aead::decrypt(&temp_k2, &aead::nonce_from_counter(0), &self.st.h, c)
            .map_err(|_| NoiseError::BadTag)?;
        self.st.mix_hash(c);
        self.temp_k2 = Some(temp_k2);

        // Act 3.
        let s_pub = PublicKey::from_secret_key(&self.secp, &self.local_static);
        let c3 = aead::encrypt(
            &temp_k2,
            &aead::nonce_from_counter(1),
            &self.st.h,
            &s_pub.serialize(),
        );
        self.st.mix_hash(&c3);
        let ss3 = ecdh(&re, &self.local_static);
        let temp_k3 = self.st.mix_key(&ss3);
        let t = aead::encrypt(&temp_k3, &aead::nonce_from_counter(0), &self.st.h, &[]);

        let mut out = [0u8; ACT_THREE_LEN];
        out[0] = 0;
        out[1..50].copy_from_slice(&c3);
        out[50..].copy_from_slice(&t);
        self.done = true;
        Ok(out)
    }

    pub fn into_transport(self) -> Result<Transport, NoiseError> {
        if !self.done {
            return Err(NoiseError::WrongState);
        }
        let (sk, rk) = hkdf::hkdf_two_keys(&self.st.ck, &[]);
        Ok(Transport::new(self.st.ck, sk, rk))
    }
}

/// Responder side. Feed act 1 to get act 2; feed act 3 to learn the
/// initiator's node id and obtain the transport.
pub struct Responder {
    st: SymmetricState,
    local_static: SecretKey,
    ephemeral: SecretKey,
    remote_ephemeral: Option<PublicKey>,
    temp_k2: Option<[u8; 32]>,
    secp: Secp256k1<SignOnly>,
}

impl Responder {
    pub fn new(local_static: SecretKey, ephemeral: SecretKey) -> Responder {
        let secp = Secp256k1::signing_only();
        let ls_pub = PublicKey::from_secret_key(&secp, &local_static);
        Responder {
            st: SymmetricState::new(&ls_pub),
            local_static,
            ephemeral,
            remote_ephemeral: None,
            temp_k2: None,
            secp,
        }
    }

    /// True once act 1 has been processed (act 3 is what's awaited).
    pub fn acted_one(&self) -> bool {
        self.remote_ephemeral.is_some()
    }

    pub fn act_one(&mut self, act1: &[u8; ACT_ONE_LEN]) -> Result<[u8; ACT_TWO_LEN], NoiseError> {
        if act1[0] != 0 {
            return Err(NoiseError::BadVersion(act1[0]));
        }
        let re = PublicKey::from_slice(&act1[1..34]).map_err(|_| NoiseError::BadPubkey)?;
        let c = &act1[34..];

        self.st.mix_hash(&re.serialize());
        let ss = ecdh(&re, &self.local_static);
        let temp_k1 = self.st.mix_key(&ss);
        aead::decrypt(&temp_k1, &aead::nonce_from_counter(0), &self.st.h, c)
            .map_err(|_| NoiseError::BadTag)?;
        self.st.mix_hash(c);
        self.remote_ephemeral = Some(re);

        // Act 2.
        let e_pub = PublicKey::from_secret_key(&self.secp, &self.ephemeral);
        self.st.mix_hash(&e_pub.serialize());
        let ss2 = ecdh(&re, &self.ephemeral);
        let temp_k2 = self.st.mix_key(&ss2);
        let c2 = aead::encrypt(&temp_k2, &aead::nonce_from_counter(0), &self.st.h, &[]);
        self.st.mix_hash(&c2);
        self.temp_k2 = Some(temp_k2);

        let mut out = [0u8; ACT_TWO_LEN];
        out[0] = 0;
        out[1..34].copy_from_slice(&e_pub.serialize());
        out[34..].copy_from_slice(&c2);
        Ok(out)
    }

    /// Returns the initiator's static public key (its node id) and the
    /// ready transport.
    pub fn act_three(
        mut self,
        act3: &[u8; ACT_THREE_LEN],
    ) -> Result<(PublicKey, Transport), NoiseError> {
        let temp_k2 = self.temp_k2.take().ok_or(NoiseError::WrongState)?;
        if act3[0] != 0 {
            return Err(NoiseError::BadVersion(act3[0]));
        }
        let c = &act3[1..50];
        let t = &act3[50..];

        let rs_bytes = aead::decrypt(&temp_k2, &aead::nonce_from_counter(1), &self.st.h, c)
            .map_err(|_| NoiseError::BadTag)?;
        let rs = PublicKey::from_slice(&rs_bytes).map_err(|_| NoiseError::BadPubkey)?;
        self.st.mix_hash(c);
        let ss = ecdh(&rs, &self.ephemeral);
        let temp_k3 = self.st.mix_key(&ss);
        aead::decrypt(&temp_k3, &aead::nonce_from_counter(0), &self.st.h, t)
            .map_err(|_| NoiseError::BadTag)?;

        let (rk, sk) = hkdf::hkdf_two_keys(&self.st.ck, &[]);
        Ok((rs, Transport::new(self.st.ck, sk, rk)))
    }
}

/// One direction of the transport cipher with BOLT 8 key rotation.
struct CipherState {
    key: [u8; 32],
    ck: [u8; 32],
    nonce: u64,
}

impl CipherState {
    fn process(&mut self) -> ([u8; 32], [u8; 12]) {
        if self.nonce == KEY_ROTATION_INTERVAL {
            let (ck, key) = hkdf::hkdf_two_keys(&self.ck, &self.key);
            self.ck = ck;
            self.key = key;
            self.nonce = 0;
        }
        let n = aead::nonce_from_counter(self.nonce);
        self.nonce += 1;
        (self.key, n)
    }
}

/// Post-handshake encrypted transport. Sans-I/O: feed it socket bytes,
/// pull whole messages; encrypt messages, write the returned bytes.
pub struct Transport {
    send: CipherState,
    recv: CipherState,
    buffer: Vec<u8>,
    /// Decrypted body length awaiting its ciphertext.
    pending_len: Option<usize>,
}

impl Transport {
    fn new(ck: [u8; 32], sk: [u8; 32], rk: [u8; 32]) -> Transport {
        Transport {
            send: CipherState { key: sk, ck, nonce: 0 },
            recv: CipherState { key: rk, ck, nonce: 0 },
            buffer: Vec::new(),
            pending_len: None,
        }
    }

    /// Encrypt one Lightning message: 18-byte encrypted length prefix then
    /// the encrypted body.
    pub fn encrypt_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if msg.len() > MAX_MSG_LEN {
            return Err(NoiseError::MessageTooLong);
        }
        let mut out = Vec::with_capacity(18 + msg.len() + 16);
        let (k, n) = self.send.process();
        out.extend_from_slice(&aead::encrypt(&k, &n, &[], &(msg.len() as u16).to_be_bytes()));
        let (k, n) = self.send.process();
        out.extend_from_slice(&aead::encrypt(&k, &n, &[], msg));
        Ok(out)
    }

    /// Feed raw bytes from the wire.
    pub fn read_input(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Pop the next complete decrypted message, if a whole frame arrived.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, NoiseError> {
        if self.pending_len.is_none() {
            if self.buffer.len() < 18 {
                return Ok(None);
            }
            let (k, n) = self.recv.process();
            let len_bytes = aead::decrypt(&k, &n, &[], &self.buffer[..18])
                .map_err(|_| NoiseError::BadTag)?;
            self.buffer.drain(..18);
            self.pending_len =
                Some(u16::from_be_bytes(len_bytes.try_into().expect("2 bytes")) as usize);
        }
        let body_len = self.pending_len.expect("set above");
        if self.buffer.len() < body_len + 16 {
            return Ok(None);
        }
        let (k, n) = self.recv.process();
        let msg = aead::decrypt(&k, &n, &[], &self.buffer[..body_len + 16])
            .map_err(|_| NoiseError::BadTag)?;
        self.buffer.drain(..body_len + 16);
        self.pending_len = None;
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    fn sk(hexs: &str) -> SecretKey {
        SecretKey::from_slice(&hex::decode_array::<32>(hexs).unwrap()).unwrap()
    }

    fn pk(hexs: &str) -> PublicKey {
        PublicKey::from_slice(&hex::decode(hexs).unwrap()).unwrap()
    }

    const RS_PUB: &str = "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7";
    const LS_PRIV: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const I_EPH: &str = "1212121212121212121212121212121212121212121212121212121212121212";
    const R_PRIV: &str = "2121212121212121212121212121212121212121212121212121212121212121";
    const R_EPH: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    const ACT1: &str = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
    const ACT2: &str = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
    const ACT3: &str = "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";

    // BOLT 8 Appendix A: transport-initiator successful handshake.
    #[test]
    fn initiator_handshake_vectors() {
        let mut init = Initiator::new(sk(LS_PRIV), pk(RS_PUB), sk(I_EPH));
        assert_eq!(hex::encode(&init.act_one()), ACT1);
        let act2: [u8; 50] = hex::decode_array(ACT2).unwrap();
        let act3 = init.act_two(&act2).unwrap();
        assert_eq!(hex::encode(&act3), ACT3);
        let t = init.into_transport().unwrap();
        assert_eq!(
            hex::encode(&t.send.key),
            "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
        );
        assert_eq!(
            hex::encode(&t.recv.key),
            "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"
        );
    }

    // BOLT 8 Appendix A: transport-responder successful handshake.
    #[test]
    fn responder_handshake_vectors() {
        let mut resp = Responder::new(sk(R_PRIV), sk(R_EPH));
        let act1: [u8; 50] = hex::decode_array(ACT1).unwrap();
        let act2 = resp.act_one(&act1).unwrap();
        assert_eq!(hex::encode(&act2), ACT2);
        let act3: [u8; 66] = hex::decode_array(ACT3).unwrap();
        let (initiator_id, t) = resp.act_three(&act3).unwrap();
        assert_eq!(
            hex::encode(&initiator_id.serialize()),
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );
        assert_eq!(
            hex::encode(&t.recv.key),
            "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
        );
        assert_eq!(
            hex::encode(&t.send.key),
            "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"
        );
    }

    // Appendix A error cases.
    #[test]
    fn handshake_error_cases() {
        // initiator: act2 bad version
        let mut init = Initiator::new(sk(LS_PRIV), pk(RS_PUB), sk(I_EPH));
        init.act_one();
        let mut act2: [u8; 50] = hex::decode_array(ACT2).unwrap();
        act2[0] = 1;
        assert_eq!(init.act_two(&act2), Err(NoiseError::BadVersion(1)));

        // initiator: act2 bad key serialization (0x04 prefix)
        let mut init = Initiator::new(sk(LS_PRIV), pk(RS_PUB), sk(I_EPH));
        init.act_one();
        let mut act2: [u8; 50] = hex::decode_array(ACT2).unwrap();
        act2[1] = 0x04;
        assert_eq!(init.act_two(&act2), Err(NoiseError::BadPubkey));

        // initiator: act2 bad MAC (last byte 0xae→0xaf)
        let mut init = Initiator::new(sk(LS_PRIV), pk(RS_PUB), sk(I_EPH));
        init.act_one();
        let mut act2: [u8; 50] = hex::decode_array(ACT2).unwrap();
        act2[49] ^= 0x01;
        assert_eq!(init.act_two(&act2), Err(NoiseError::BadTag));

        // responder: act1 bad version / pubkey / MAC
        let act1_good: [u8; 50] = hex::decode_array(ACT1).unwrap();
        let mut bad = act1_good;
        bad[0] = 1;
        assert_eq!(
            Responder::new(sk(R_PRIV), sk(R_EPH)).act_one(&bad),
            Err(NoiseError::BadVersion(1))
        );
        let mut bad = act1_good;
        bad[1] = 0x04;
        assert_eq!(
            Responder::new(sk(R_PRIV), sk(R_EPH)).act_one(&bad),
            Err(NoiseError::BadPubkey)
        );
        let mut bad = act1_good;
        bad[49] ^= 0x01;
        assert_eq!(
            Responder::new(sk(R_PRIV), sk(R_EPH)).act_one(&bad),
            Err(NoiseError::BadTag)
        );

        // responder: act3 bad version
        let mut resp = Responder::new(sk(R_PRIV), sk(R_EPH));
        resp.act_one(&act1_good).unwrap();
        let mut act3: [u8; 66] = hex::decode_array(ACT3).unwrap();
        act3[0] = 1;
        assert_eq!(
            resp.act_three(&act3).map(|_| ()),
            Err(NoiseError::BadVersion(1))
        );
    }

    // BOLT 8 Appendix A: transport-message test with two key rotations.
    #[test]
    fn message_encryption_and_rotation_vectors() {
        let ck = hex::decode_array::<32>(
            "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01",
        )
        .unwrap();
        let sk_key = hex::decode_array::<32>(
            "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9",
        )
        .unwrap();
        let rk = hex::decode_array::<32>(
            "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442",
        )
        .unwrap();
        let mut sender = Transport::new(ck, sk_key, rk);
        // Mirror receiver: swap send/recv keys.
        let mut receiver = Transport::new(ck, rk, sk_key);

        let expected = [
            (0, "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95"),
            (1, "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1"),
            (500, "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8"),
            (501, "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd"),
            (1000, "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09"),
            (1001, "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36"),
        ];

        let mut idx = 0;
        for i in 0..=1001 {
            let frame = sender.encrypt_message(b"hello").unwrap();
            if idx < expected.len() && expected[idx].0 == i {
                assert_eq!(hex::encode(&frame), expected[idx].1, "message {i}");
                idx += 1;
            }
            // Stream the frame to the receiver in two arbitrary chunks to
            // exercise buffering.
            receiver.read_input(&frame[..10]);
            assert!(receiver.next_message().unwrap().is_none());
            receiver.read_input(&frame[10..]);
            assert_eq!(receiver.next_message().unwrap().unwrap(), b"hello");
            assert!(receiver.next_message().unwrap().is_none());
        }
        assert_eq!(idx, expected.len(), "hit all six expected outputs");
    }
}
