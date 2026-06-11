//! BOLT 4: Sphinx onion routing — packet construction, per-hop peeling,
//! and the encrypted error-return channel.

pub mod payload;

use crate::crypto::chacha20::ChaCha20;
use crate::crypto::hmac::{hmac_sha256, HmacSha256};
use crate::crypto::sha256::Sha256;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

pub const PAYLOADS_LEN: usize = 1300;
pub const PACKET_LEN: usize = 1 + 33 + PAYLOADS_LEN + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnionError {
    /// BADONION|PERM|4
    InvalidVersion,
    /// BADONION|PERM|6
    InvalidPubkey,
    /// BADONION|PERM|5
    InvalidHmac,
    BadLength,
    BadPayload,
}

impl core::fmt::Display for OnionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            OnionError::InvalidVersion => write!(f, "unknown onion version"),
            OnionError::InvalidPubkey => write!(f, "invalid ephemeral pubkey"),
            OnionError::InvalidHmac => write!(f, "onion HMAC verification failed"),
            OnionError::BadLength => write!(f, "onion packet has wrong length"),
            OnionError::BadPayload => write!(f, "malformed hop payload"),
        }
    }
}

impl std::error::Error for OnionError {}

#[derive(Clone, PartialEq, Eq)]
pub struct OnionPacket {
    pub version: u8,
    pub ephemeral_key: PublicKey,
    pub payloads: Box<[u8; PAYLOADS_LEN]>,
    pub hmac: [u8; 32],
}

impl core::fmt::Debug for OnionPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "OnionPacket(eph={})", self.ephemeral_key)
    }
}

impl OnionPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PACKET_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.ephemeral_key.serialize());
        out.extend_from_slice(&self.payloads[..]);
        out.extend_from_slice(&self.hmac);
        out
    }

    pub fn parse(data: &[u8]) -> Result<OnionPacket, OnionError> {
        if data.len() != PACKET_LEN {
            return Err(OnionError::BadLength);
        }
        let version = data[0];
        if version != 0 {
            return Err(OnionError::InvalidVersion);
        }
        let ephemeral_key =
            PublicKey::from_slice(&data[1..34]).map_err(|_| OnionError::InvalidPubkey)?;
        let mut payloads = Box::new([0u8; PAYLOADS_LEN]);
        payloads.copy_from_slice(&data[34..34 + PAYLOADS_LEN]);
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&data[34 + PAYLOADS_LEN..]);
        Ok(OnionPacket { version, ephemeral_key, payloads, hmac })
    }
}

/// `HMAC-SHA256(key_type, shared_secret)` per BOLT 4.
fn generate_key(key_type: &[u8], secret: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(key_type, secret)
}

fn cipher_stream(key: &[u8; 32], len: usize) -> Vec<u8> {
    ChaCha20::keystream(key, &[0u8; 12], 0, len)
}

fn ecdh(pk: &PublicKey, sk: &SecretKey) -> [u8; 32] {
    secp256k1::ecdh::SharedSecret::new(pk, sk).secret_bytes()
}

/// Sender-side: derive the shared secret for every hop from the session
/// key, blinding the ephemeral key at each step.
pub fn shared_secrets_for_path(session_key: &SecretKey, path: &[PublicKey]) -> Vec<[u8; 32]> {
    let secp = Secp256k1::signing_only();
    let mut secrets = Vec::with_capacity(path.len());
    let mut ephemeral = *session_key;
    for hop_pk in path {
        let ss = ecdh(hop_pk, &ephemeral);
        let epk = ephemeral.public_key(&secp);
        let mut h = Sha256::new();
        h.update(&epk.serialize());
        h.update(&ss);
        let blinding =
            Scalar::from_be_bytes(h.finalize()).expect("blinding factor below curve order");
        ephemeral = ephemeral.mul_tweak(&blinding).expect("nonzero blinded key");
        secrets.push(ss);
    }
    secrets
}

fn shift_size(payload_len: usize) -> usize {
    crate::wire::bigsize::len(payload_len as u64) + payload_len + 32
}

/// Construct a payment onion. `hops` are `(payload_tlv_bytes)` in route
/// order (no length prefix; final hop last); `shared_secrets` from
/// [`shared_secrets_for_path`]. `assoc_data` is the payment hash.
pub fn construct(
    session_key: &SecretKey,
    shared_secrets: &[[u8; 32]],
    payloads: &[Vec<u8>],
    assoc_data: &[u8],
) -> OnionPacket {
    assert_eq!(shared_secrets.len(), payloads.len());
    assert!(!payloads.is_empty());
    let num_hops = payloads.len();
    let total_shift: usize = payloads.iter().map(|p| shift_size(p.len())).sum();
    assert!(total_shift <= PAYLOADS_LEN, "route payloads exceed onion capacity");

    // Filler: the accumulated stream garbage covering all but the final
    // hop's payload region.
    let filler_len: usize = payloads[..num_hops - 1].iter().map(|p| shift_size(p.len())).sum();
    let mut filler = vec![0u8; filler_len];
    let mut covered = 0usize;
    for (i, payload) in payloads[..num_hops - 1].iter().enumerate() {
        let this_shift = shift_size(payload.len());
        let rho = generate_key(b"rho", &shared_secrets[i]);
        let stream = cipher_stream(&rho, PAYLOADS_LEN + this_shift);
        let start = PAYLOADS_LEN - covered;
        for (k, idx) in (start..PAYLOADS_LEN + this_shift).enumerate() {
            filler[k] ^= stream[idx];
        }
        covered += this_shift;
    }

    // Start with deterministic random bytes from the pad key.
    let pad_key = generate_key(b"pad", &session_key.secret_bytes());
    let mut mix: Vec<u8> = cipher_stream(&pad_key, PAYLOADS_LEN);
    let mut next_hmac = [0u8; 32];

    for i in (0..num_hops).rev() {
        let rho = generate_key(b"rho", &shared_secrets[i]);
        let mu = generate_key(b"mu", &shared_secrets[i]);

        // Right-shift and prepend `bigsize(len) || payload || hmac`.
        let mut frame = {
            let mut w = crate::wire::WireWriter::new();
            crate::wire::bigsize::write(&mut w, payloads[i].len() as u64);
            w.bytes(&payloads[i]);
            w.bytes(&next_hmac);
            w.finish()
        };
        let this_shift = frame.len();
        debug_assert_eq!(this_shift, shift_size(payloads[i].len()));
        mix.truncate(PAYLOADS_LEN - this_shift);
        frame.extend_from_slice(&mix);
        mix = frame;

        let stream = cipher_stream(&rho, PAYLOADS_LEN);
        for (b, s) in mix.iter_mut().zip(stream.iter()) {
            *b ^= s;
        }

        if i == num_hops - 1 && filler_len > 0 {
            mix[PAYLOADS_LEN - filler_len..].copy_from_slice(&filler);
        }

        let mut mac = HmacSha256::new(&mu);
        mac.update(&mix);
        mac.update(assoc_data);
        next_hmac = mac.finalize();
    }

    let mut payloads_arr = Box::new([0u8; PAYLOADS_LEN]);
    payloads_arr.copy_from_slice(&mix);
    OnionPacket {
        version: 0,
        ephemeral_key: session_key.public_key(&Secp256k1::signing_only()),
        payloads: payloads_arr,
        hmac: next_hmac,
    }
}

/// The outcome of peeling one onion layer.
pub enum Peeled {
    /// We are an intermediate hop; pass `next` on.
    Forward { payload: Vec<u8>, next: OnionPacket },
    /// We are the final hop.
    Final { payload: Vec<u8> },
}

/// Peel one layer with our node secret key. Returns the hop payload, the
/// shared secret (needed later for error wrapping), and what to do next.
pub fn peel(
    node_key: &SecretKey,
    packet: &OnionPacket,
    assoc_data: &[u8],
) -> Result<(Peeled, [u8; 32]), OnionError> {
    let ss = ecdh(&packet.ephemeral_key, node_key);
    let peeled = peel_with_secret(&ss, packet, assoc_data)?;
    Ok((peeled, ss))
}

/// Peel with an externally computed shared secret (HSM-style ECDH).
pub fn peel_with_secret(
    shared_secret: &[u8; 32],
    packet: &OnionPacket,
    assoc_data: &[u8],
) -> Result<Peeled, OnionError> {
    if packet.version != 0 {
        return Err(OnionError::InvalidVersion);
    }
    let mu = generate_key(b"mu", shared_secret);
    let mut mac = HmacSha256::new(&mu);
    mac.update(&packet.payloads[..]);
    mac.update(assoc_data);
    if !crate::crypto::ct_eq(&mac.finalize(), &packet.hmac) {
        return Err(OnionError::InvalidHmac);
    }

    // Decrypt over payloads || 1300 zeros.
    let rho = generate_key(b"rho", shared_secret);
    let mut buf = vec![0u8; PAYLOADS_LEN * 2];
    buf[..PAYLOADS_LEN].copy_from_slice(&packet.payloads[..]);
    let stream = cipher_stream(&rho, PAYLOADS_LEN * 2);
    for (b, s) in buf.iter_mut().zip(stream.iter()) {
        *b ^= s;
    }

    let mut r = crate::wire::WireReader::new(&buf);
    let payload_len =
        crate::wire::bigsize::read(&mut r).map_err(|_| OnionError::BadPayload)? as usize;
    if !(2..=PAYLOADS_LEN - 32).contains(&payload_len) {
        return Err(OnionError::BadPayload);
    }
    let payload = r.take(payload_len).map_err(|_| OnionError::BadPayload)?.to_vec();
    let next_hmac: [u8; 32] = r.array().map_err(|_| OnionError::BadPayload)?;
    let consumed = PAYLOADS_LEN * 2 - r.remaining();

    if next_hmac == [0u8; 32] {
        return Ok(Peeled::Final { payload });
    }

    // Blind the ephemeral key for the next hop.
    let mut h = Sha256::new();
    h.update(&packet.ephemeral_key.serialize());
    h.update(shared_secret);
    let blinding = Scalar::from_be_bytes(h.finalize()).expect("below curve order");
    let next_ephemeral = packet
        .ephemeral_key
        .mul_tweak(&Secp256k1::verification_only(), &blinding)
        .map_err(|_| OnionError::InvalidPubkey)?;

    let mut next_payloads = Box::new([0u8; PAYLOADS_LEN]);
    next_payloads.copy_from_slice(&buf[consumed..consumed + PAYLOADS_LEN]);
    Ok(Peeled::Forward {
        payload,
        next: OnionPacket {
            version: 0,
            ephemeral_key: next_ephemeral,
            payloads: next_payloads,
            hmac: next_hmac,
        },
    })
}

// ------------------------------------------------------------- failures

pub mod failure {
    //! BOLT 4 failure codes and the encrypted error-return onion.

    pub const BADONION: u16 = 0x8000;
    pub const PERM: u16 = 0x4000;
    pub const NODE: u16 = 0x2000;
    pub const UPDATE: u16 = 0x1000;

    pub const TEMPORARY_NODE_FAILURE: u16 = NODE | 2;
    pub const PERMANENT_NODE_FAILURE: u16 = PERM | NODE | 2;
    pub const INVALID_ONION_VERSION: u16 = BADONION | PERM | 4;
    pub const INVALID_ONION_HMAC: u16 = BADONION | PERM | 5;
    pub const INVALID_ONION_KEY: u16 = BADONION | PERM | 6;
    pub const TEMPORARY_CHANNEL_FAILURE: u16 = UPDATE | 7;
    pub const PERMANENT_CHANNEL_FAILURE: u16 = PERM | 8;
    pub const UNKNOWN_NEXT_PEER: u16 = PERM | 10;
    pub const AMOUNT_BELOW_MINIMUM: u16 = UPDATE | 11;
    pub const FEE_INSUFFICIENT: u16 = UPDATE | 12;
    pub const INCORRECT_CLTV_EXPIRY: u16 = UPDATE | 13;
    pub const EXPIRY_TOO_SOON: u16 = UPDATE | 14;
    pub const INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS: u16 = PERM | 15;
    pub const FINAL_INCORRECT_CLTV_EXPIRY: u16 = 18;
    pub const FINAL_INCORRECT_HTLC_AMOUNT: u16 = 19;
    pub const EXPIRY_TOO_FAR: u16 = 21;
    pub const INVALID_ONION_PAYLOAD: u16 = PERM | 22;
    pub const MPP_TIMEOUT: u16 = 23;

    use super::*;

    /// Build the erring node's return packet (already ammag-wrapped once):
    /// `hmac_um || u16 failure_len || failuremsg || u16 pad_len || pad`.
    pub fn build(shared_secret: &[u8; 32], failuremsg: &[u8]) -> Vec<u8> {
        // Pad total message body to 256 (or 1024 for oversize messages, the
        // convention modern implementations use to avoid length leaks).
        let target: usize = if failuremsg.len() <= 256 { 256 } else { 1024 };
        let pad_len = target.saturating_sub(failuremsg.len());

        let um = generate_key(b"um", shared_secret);
        let mut body = Vec::with_capacity(4 + failuremsg.len() + pad_len);
        body.extend_from_slice(&(failuremsg.len() as u16).to_be_bytes());
        body.extend_from_slice(failuremsg);
        body.extend_from_slice(&(pad_len as u16).to_be_bytes());
        body.extend_from_slice(&vec![0u8; pad_len]);

        let mut packet = hmac_sha256(&um, &body).to_vec();
        packet.extend_from_slice(&body);
        wrap(shared_secret, &mut packet);
        packet
    }

    /// XOR the packet with this hop's ammag stream — done by the erring
    /// node and by every node forwarding the error back.
    pub fn wrap(shared_secret: &[u8; 32], packet: &mut [u8]) {
        let ammag = generate_key(b"ammag", shared_secret);
        let stream = cipher_stream(&ammag, packet.len());
        for (b, s) in packet.iter_mut().zip(stream.iter()) {
            *b ^= s;
        }
    }

    /// Origin-side: unwrap layer by layer (shared secrets in route order)
    /// until an HMAC verifies. Returns `(erring_hop_index, failuremsg)`.
    pub fn decrypt(shared_secrets: &[[u8; 32]], packet: &[u8]) -> Option<(usize, Vec<u8>)> {
        let mut data = packet.to_vec();
        for (i, ss) in shared_secrets.iter().enumerate() {
            wrap(ss, &mut data);
            if data.len() < 34 {
                return None;
            }
            let um = generate_key(b"um", ss);
            let (mac, body) = data.split_at(32);
            if crate::crypto::ct_eq(&hmac_sha256(&um, body), mac) {
                let failure_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                if 2 + failure_len > body.len() {
                    return None;
                }
                return Some((i, body[2..2 + failure_len].to_vec()));
            }
        }
        None
    }

    /// Build the failure message bytes for a code with raw data appended.
    pub fn message(code: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + data.len());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Parse `code` from a decrypted failure message.
    pub fn parse_code(failuremsg: &[u8]) -> Option<u16> {
        if failuremsg.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([failuremsg[0], failuremsg[1]]))
    }
}

#[cfg(test)]
mod tests;
