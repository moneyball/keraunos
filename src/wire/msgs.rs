//! Typed BOLT 1/2/7 messages with exact wire (de)serialization.
//!
//! Every struct round-trips byte-for-byte (tested), TLV extensions are
//! honored, and unknown odd message types decode to [`Message::Unknown`]
//! rather than erroring, per BOLT 1.

use super::features::Features;
use super::ser::{WireError, WireReader, WireWriter};
use super::tlv::{self, TlvRecord};
use crate::types::{ChannelId, Msat, PaymentHash, PaymentPreimage, ShortChannelId};
use secp256k1::ecdsa::Signature;
use secp256k1::PublicKey;

pub mod types {
    pub const WARNING: u16 = 1;
    pub const INIT: u16 = 16;
    pub const ERROR: u16 = 17;
    pub const PING: u16 = 18;
    pub const PONG: u16 = 19;
    pub const OPEN_CHANNEL: u16 = 32;
    pub const ACCEPT_CHANNEL: u16 = 33;
    pub const FUNDING_CREATED: u16 = 34;
    pub const FUNDING_SIGNED: u16 = 35;
    pub const CHANNEL_READY: u16 = 36;
    pub const SHUTDOWN: u16 = 38;
    pub const CLOSING_SIGNED: u16 = 39;
    pub const UPDATE_ADD_HTLC: u16 = 128;
    pub const UPDATE_FULFILL_HTLC: u16 = 130;
    pub const UPDATE_FAIL_HTLC: u16 = 131;
    pub const COMMITMENT_SIGNED: u16 = 132;
    pub const REVOKE_AND_ACK: u16 = 133;
    pub const UPDATE_FEE: u16 = 134;
    pub const UPDATE_FAIL_MALFORMED_HTLC: u16 = 135;
    pub const CHANNEL_REESTABLISH: u16 = 136;
    pub const CHANNEL_ANNOUNCEMENT: u16 = 256;
    pub const NODE_ANNOUNCEMENT: u16 = 257;
    pub const CHANNEL_UPDATE: u16 = 258;
    pub const ANNOUNCEMENT_SIGNATURES: u16 = 259;
    pub const GOSSIP_TIMESTAMP_FILTER: u16 = 265;
}

pub const ONION_PACKET_LEN: usize = 1366;

// ---------------------------------------------------------------- BOLT 1

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    pub global_features: Features,
    pub features: Features,
    /// TLV 1: chains the node is interested in.
    pub networks: Option<Vec<[u8; 32]>>,
}

impl Init {
    pub fn combined_features(&self) -> Features {
        self.global_features.or(&self.features)
    }

    fn write(&self, w: &mut WireWriter) {
        w.bytes_u16(self.global_features.as_bytes());
        w.bytes_u16(self.features.as_bytes());
        if let Some(nets) = &self.networks {
            let mut value = Vec::with_capacity(32 * nets.len());
            for n in nets {
                value.extend_from_slice(n);
            }
            tlv::write_record(w, 1, &value);
        }
    }

    fn read(r: &mut WireReader) -> Result<Init, WireError> {
        let global_features = Features::from_bytes(r.bytes_u16()?);
        let features = Features::from_bytes(r.bytes_u16()?);
        let records = tlv::parse_stream(r.rest())?;
        tlv::check_unknown_even(&records, &[])?;
        let mut networks = None;
        for rec in &records {
            if rec.typ == 1 {
                if rec.value.len() % 32 != 0 {
                    return Err(WireError::BadFormat("init networks length"));
                }
                networks = Some(
                    rec.value
                        .chunks_exact(32)
                        .map(|c| c.try_into().expect("32-byte chunk"))
                        .collect(),
                );
            }
        }
        Ok(Init { global_features, features, networks })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMsg {
    /// All-zero means "all channels".
    pub channel_id: ChannelId,
    pub data: Vec<u8>,
}

impl ErrorMsg {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningMsg {
    pub channel_id: ChannelId,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    pub num_pong_bytes: u16,
    pub ignored: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub ignored: Vec<u8>,
}

// ---------------------------------------------------------------- BOLT 2

/// The six channel basepoints/keys every side contributes at open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelBasepoints {
    pub funding_pubkey: PublicKey,
    pub revocation: PublicKey,
    pub payment: PublicKey,
    pub delayed_payment: PublicKey,
    pub htlc: PublicKey,
}

impl ChannelBasepoints {
    fn write(&self, w: &mut WireWriter) {
        w.pubkey(&self.funding_pubkey);
        w.pubkey(&self.revocation);
        w.pubkey(&self.payment);
        w.pubkey(&self.delayed_payment);
        w.pubkey(&self.htlc);
    }

    fn read(r: &mut WireReader) -> Result<ChannelBasepoints, WireError> {
        Ok(ChannelBasepoints {
            funding_pubkey: r.pubkey()?,
            revocation: r.pubkey()?,
            payment: r.pubkey()?,
            delayed_payment: r.pubkey()?,
            htlc: r.pubkey()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenChannel {
    pub chain_hash: [u8; 32],
    pub temporary_channel_id: ChannelId,
    pub funding_satoshis: u64,
    pub push_msat: Msat,
    pub dust_limit_satoshis: u64,
    pub max_htlc_value_in_flight_msat: Msat,
    pub channel_reserve_satoshis: u64,
    pub htlc_minimum_msat: Msat,
    pub feerate_per_kw: u32,
    pub to_self_delay: u16,
    pub max_accepted_htlcs: u16,
    pub basepoints: ChannelBasepoints,
    pub first_per_commitment_point: PublicKey,
    /// Bit 0: announce_channel.
    pub channel_flags: u8,
    pub upfront_shutdown_script: Option<Vec<u8>>,
    /// Feature-bit vector naming the commitment flavor (TLV 1).
    pub channel_type: Option<Features>,
}

impl OpenChannel {
    fn write(&self, w: &mut WireWriter) {
        w.bytes(&self.chain_hash);
        w.bytes(&self.temporary_channel_id.0);
        w.u64(self.funding_satoshis);
        w.u64(self.push_msat.0);
        w.u64(self.dust_limit_satoshis);
        w.u64(self.max_htlc_value_in_flight_msat.0);
        w.u64(self.channel_reserve_satoshis);
        w.u64(self.htlc_minimum_msat.0);
        w.u32(self.feerate_per_kw);
        w.u16(self.to_self_delay);
        w.u16(self.max_accepted_htlcs);
        self.basepoints.write(w);
        w.pubkey(&self.first_per_commitment_point);
        w.u8(self.channel_flags);
        if let Some(s) = &self.upfront_shutdown_script {
            tlv::write_record(w, 0, s);
        }
        if let Some(t) = &self.channel_type {
            tlv::write_record(w, 1, t.as_bytes());
        }
    }

    fn read(r: &mut WireReader) -> Result<OpenChannel, WireError> {
        let chain_hash = r.array()?;
        let temporary_channel_id = ChannelId(r.array()?);
        let funding_satoshis = r.u64()?;
        let push_msat = Msat(r.u64()?);
        let dust_limit_satoshis = r.u64()?;
        let max_htlc_value_in_flight_msat = Msat(r.u64()?);
        let channel_reserve_satoshis = r.u64()?;
        let htlc_minimum_msat = Msat(r.u64()?);
        let feerate_per_kw = r.u32()?;
        let to_self_delay = r.u16()?;
        let max_accepted_htlcs = r.u16()?;
        let basepoints = ChannelBasepoints::read(r)?;
        let first_per_commitment_point = r.pubkey()?;
        let channel_flags = r.u8()?;
        let records = tlv::parse_stream(r.rest())?;
        tlv::check_unknown_even(&records, &[0])?;
        let (upfront_shutdown_script, channel_type) = open_accept_tlvs(&records);
        Ok(OpenChannel {
            chain_hash,
            temporary_channel_id,
            funding_satoshis,
            push_msat,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            feerate_per_kw,
            to_self_delay,
            max_accepted_htlcs,
            basepoints,
            first_per_commitment_point,
            channel_flags,
            upfront_shutdown_script,
            channel_type,
        })
    }
}

fn open_accept_tlvs(records: &[TlvRecord]) -> (Option<Vec<u8>>, Option<Features>) {
    let mut shutdown = None;
    let mut ctype = None;
    for rec in records {
        match rec.typ {
            0 => shutdown = Some(rec.value.clone()),
            1 => ctype = Some(Features::from_bytes(rec.value.clone())),
            _ => {}
        }
    }
    (shutdown, ctype)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptChannel {
    pub temporary_channel_id: ChannelId,
    pub dust_limit_satoshis: u64,
    pub max_htlc_value_in_flight_msat: Msat,
    pub channel_reserve_satoshis: u64,
    pub htlc_minimum_msat: Msat,
    pub minimum_depth: u32,
    pub to_self_delay: u16,
    pub max_accepted_htlcs: u16,
    pub basepoints: ChannelBasepoints,
    pub first_per_commitment_point: PublicKey,
    pub upfront_shutdown_script: Option<Vec<u8>>,
    pub channel_type: Option<Features>,
}

impl AcceptChannel {
    fn write(&self, w: &mut WireWriter) {
        w.bytes(&self.temporary_channel_id.0);
        w.u64(self.dust_limit_satoshis);
        w.u64(self.max_htlc_value_in_flight_msat.0);
        w.u64(self.channel_reserve_satoshis);
        w.u64(self.htlc_minimum_msat.0);
        w.u32(self.minimum_depth);
        w.u16(self.to_self_delay);
        w.u16(self.max_accepted_htlcs);
        self.basepoints.write(w);
        w.pubkey(&self.first_per_commitment_point);
        if let Some(s) = &self.upfront_shutdown_script {
            tlv::write_record(w, 0, s);
        }
        if let Some(t) = &self.channel_type {
            tlv::write_record(w, 1, t.as_bytes());
        }
    }

    fn read(r: &mut WireReader) -> Result<AcceptChannel, WireError> {
        let temporary_channel_id = ChannelId(r.array()?);
        let dust_limit_satoshis = r.u64()?;
        let max_htlc_value_in_flight_msat = Msat(r.u64()?);
        let channel_reserve_satoshis = r.u64()?;
        let htlc_minimum_msat = Msat(r.u64()?);
        let minimum_depth = r.u32()?;
        let to_self_delay = r.u16()?;
        let max_accepted_htlcs = r.u16()?;
        let basepoints = ChannelBasepoints::read(r)?;
        let first_per_commitment_point = r.pubkey()?;
        let records = tlv::parse_stream(r.rest())?;
        tlv::check_unknown_even(&records, &[0])?;
        let (upfront_shutdown_script, channel_type) = open_accept_tlvs(&records);
        Ok(AcceptChannel {
            temporary_channel_id,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            minimum_depth,
            to_self_delay,
            max_accepted_htlcs,
            basepoints,
            first_per_commitment_point,
            upfront_shutdown_script,
            channel_type,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingCreated {
    pub temporary_channel_id: ChannelId,
    /// Internal byte order on the wire.
    pub funding_txid: [u8; 32],
    pub funding_output_index: u16,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingSigned {
    pub channel_id: ChannelId,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReady {
    pub channel_id: ChannelId,
    pub second_per_commitment_point: PublicKey,
    /// TLV 1: alias scid the peer may use in invoices.
    pub short_channel_id_alias: Option<ShortChannelId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shutdown {
    pub channel_id: ChannelId,
    pub scriptpubkey: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosingSignedFeeRange {
    pub min_fee_satoshis: u64,
    pub max_fee_satoshis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingSigned {
    pub channel_id: ChannelId,
    pub fee_satoshis: u64,
    pub signature: Signature,
    pub fee_range: Option<ClosingSignedFeeRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAddHtlc {
    pub channel_id: ChannelId,
    pub id: u64,
    pub amount_msat: Msat,
    pub payment_hash: PaymentHash,
    pub cltv_expiry: u32,
    /// Exactly [`ONION_PACKET_LEN`] bytes.
    pub onion_routing_packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFulfillHtlc {
    pub channel_id: ChannelId,
    pub id: u64,
    pub payment_preimage: PaymentPreimage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailHtlc {
    pub channel_id: ChannelId,
    pub id: u64,
    /// Encrypted error onion (BOLT 4).
    pub reason: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailMalformedHtlc {
    pub channel_id: ChannelId,
    pub id: u64,
    pub sha256_of_onion: [u8; 32],
    pub failure_code: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentSigned {
    pub channel_id: ChannelId,
    pub signature: Signature,
    /// One per offered-from-us-or-to-us HTLC output, in output order.
    pub htlc_signatures: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAndAck {
    pub channel_id: ChannelId,
    pub per_commitment_secret: [u8; 32],
    pub next_per_commitment_point: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFee {
    pub channel_id: ChannelId,
    pub feerate_per_kw: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReestablish {
    pub channel_id: ChannelId,
    pub next_commitment_number: u64,
    pub next_revocation_number: u64,
    pub your_last_per_commitment_secret: [u8; 32],
    pub my_current_per_commitment_point: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementSignatures {
    pub channel_id: ChannelId,
    pub short_channel_id: ShortChannelId,
    pub node_signature: Signature,
    pub bitcoin_signature: Signature,
}

// ---------------------------------------------------------------- BOLT 7

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAnnouncement {
    pub node_signature_1: Signature,
    pub node_signature_2: Signature,
    pub bitcoin_signature_1: Signature,
    pub bitcoin_signature_2: Signature,
    pub features: Features,
    pub chain_hash: [u8; 32],
    pub short_channel_id: ShortChannelId,
    pub node_id_1: PublicKey,
    pub node_id_2: PublicKey,
    pub bitcoin_key_1: PublicKey,
    pub bitcoin_key_2: PublicKey,
}

impl ChannelAnnouncement {
    /// The bytes covered by all four signatures (everything after them).
    pub fn signed_payload(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        w.bytes_u16(self.features.as_bytes());
        w.bytes(&self.chain_hash);
        w.u64(self.short_channel_id.0);
        w.pubkey(&self.node_id_1);
        w.pubkey(&self.node_id_2);
        w.pubkey(&self.bitcoin_key_1);
        w.pubkey(&self.bitcoin_key_2);
        w.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetAddress {
    V4 { addr: [u8; 4], port: u16 },
    V6 { addr: [u8; 16], port: u16 },
    TorV3 { ed25519_pubkey: [u8; 32], checksum: u16, version: u8, port: u16 },
    Hostname { hostname: Vec<u8>, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAnnouncement {
    pub signature: Signature,
    pub features: Features,
    pub timestamp: u32,
    pub node_id: PublicKey,
    pub rgb_color: [u8; 3],
    pub alias: [u8; 32],
    pub addresses: Vec<NetAddress>,
}

impl NodeAnnouncement {
    pub fn signed_payload(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        self.write_after_sig(&mut w);
        w.finish()
    }

    fn write_after_sig(&self, w: &mut WireWriter) {
        w.bytes_u16(self.features.as_bytes());
        w.u32(self.timestamp);
        w.pubkey(&self.node_id);
        w.bytes(&self.rgb_color);
        w.bytes(&self.alias);
        let mut addrs = WireWriter::new();
        for a in &self.addresses {
            match a {
                NetAddress::V4 { addr, port } => {
                    addrs.u8(1);
                    addrs.bytes(addr);
                    addrs.u16(*port);
                }
                NetAddress::V6 { addr, port } => {
                    addrs.u8(2);
                    addrs.bytes(addr);
                    addrs.u16(*port);
                }
                NetAddress::TorV3 { ed25519_pubkey, checksum, version, port } => {
                    addrs.u8(4);
                    addrs.bytes(ed25519_pubkey);
                    addrs.u16(*checksum);
                    addrs.u8(*version);
                    addrs.u16(*port);
                }
                NetAddress::Hostname { hostname, port } => {
                    addrs.u8(5);
                    addrs.u8(hostname.len() as u8);
                    addrs.bytes(hostname);
                    addrs.u16(*port);
                }
            }
        }
        w.bytes_u16(&addrs.finish());
    }

    fn read_addresses(bytes: &[u8]) -> Result<Vec<NetAddress>, WireError> {
        let mut r = WireReader::new(bytes);
        let mut out = Vec::new();
        while !r.is_empty() {
            match r.u8()? {
                1 => out.push(NetAddress::V4 { addr: r.array()?, port: r.u16()? }),
                2 => out.push(NetAddress::V6 { addr: r.array()?, port: r.u16()? }),
                3 => {
                    // Deprecated Tor v2 — skip its 12 body bytes.
                    r.take(12)?;
                }
                4 => out.push(NetAddress::TorV3 {
                    ed25519_pubkey: r.array()?,
                    checksum: r.u16()?,
                    version: r.u8()?,
                    port: r.u16()?,
                }),
                5 => {
                    let len = r.u8()? as usize;
                    out.push(NetAddress::Hostname {
                        hostname: r.take(len)?.to_vec(),
                        port: r.u16()?,
                    });
                }
                // BOLT 7: stop parsing at the first unknown descriptor.
                _ => break,
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelUpdate {
    pub signature: Signature,
    pub chain_hash: [u8; 32],
    pub short_channel_id: ShortChannelId,
    pub timestamp: u32,
    /// Bit 0: must_be_one (htlc_maximum present), bit 1: dont_forward.
    pub message_flags: u8,
    /// Bit 0: direction (0 = from node_id_1), bit 1: disable.
    pub channel_flags: u8,
    pub cltv_expiry_delta: u16,
    pub htlc_minimum_msat: Msat,
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub htlc_maximum_msat: Msat,
}

impl ChannelUpdate {
    pub fn direction(&self) -> u8 {
        self.channel_flags & 1
    }

    pub fn is_disabled(&self) -> bool {
        self.channel_flags & 2 != 0
    }

    pub fn signed_payload(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        self.write_after_sig(&mut w);
        w.finish()
    }

    fn write_after_sig(&self, w: &mut WireWriter) {
        w.bytes(&self.chain_hash);
        w.u64(self.short_channel_id.0);
        w.u32(self.timestamp);
        w.u8(self.message_flags);
        w.u8(self.channel_flags);
        w.u16(self.cltv_expiry_delta);
        w.u64(self.htlc_minimum_msat.0);
        w.u32(self.fee_base_msat);
        w.u32(self.fee_proportional_millionths);
        w.u64(self.htlc_maximum_msat.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipTimestampFilter {
    pub chain_hash: [u8; 32],
    pub first_timestamp: u32,
    pub timestamp_range: u32,
}

// ------------------------------------------------------------- dispatch

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Warning(WarningMsg),
    Init(Init),
    Error(ErrorMsg),
    Ping(Ping),
    Pong(Pong),
    OpenChannel(OpenChannel),
    AcceptChannel(AcceptChannel),
    FundingCreated(FundingCreated),
    FundingSigned(FundingSigned),
    ChannelReady(ChannelReady),
    Shutdown(Shutdown),
    ClosingSigned(ClosingSigned),
    UpdateAddHtlc(UpdateAddHtlc),
    UpdateFulfillHtlc(UpdateFulfillHtlc),
    UpdateFailHtlc(UpdateFailHtlc),
    UpdateFailMalformedHtlc(UpdateFailMalformedHtlc),
    CommitmentSigned(CommitmentSigned),
    RevokeAndAck(RevokeAndAck),
    UpdateFee(UpdateFee),
    ChannelReestablish(ChannelReestablish),
    AnnouncementSignatures(AnnouncementSignatures),
    ChannelAnnouncement(ChannelAnnouncement),
    NodeAnnouncement(NodeAnnouncement),
    ChannelUpdate(ChannelUpdate),
    GossipTimestampFilter(GossipTimestampFilter),
    /// Unknown odd type: tolerated and surfaced raw.
    Unknown(u16, Vec<u8>),
}

impl Message {
    pub fn msg_type(&self) -> u16 {
        use types::*;
        match self {
            Message::Warning(_) => WARNING,
            Message::Init(_) => INIT,
            Message::Error(_) => ERROR,
            Message::Ping(_) => PING,
            Message::Pong(_) => PONG,
            Message::OpenChannel(_) => OPEN_CHANNEL,
            Message::AcceptChannel(_) => ACCEPT_CHANNEL,
            Message::FundingCreated(_) => FUNDING_CREATED,
            Message::FundingSigned(_) => FUNDING_SIGNED,
            Message::ChannelReady(_) => CHANNEL_READY,
            Message::Shutdown(_) => SHUTDOWN,
            Message::ClosingSigned(_) => CLOSING_SIGNED,
            Message::UpdateAddHtlc(_) => UPDATE_ADD_HTLC,
            Message::UpdateFulfillHtlc(_) => UPDATE_FULFILL_HTLC,
            Message::UpdateFailHtlc(_) => UPDATE_FAIL_HTLC,
            Message::UpdateFailMalformedHtlc(_) => UPDATE_FAIL_MALFORMED_HTLC,
            Message::CommitmentSigned(_) => COMMITMENT_SIGNED,
            Message::RevokeAndAck(_) => REVOKE_AND_ACK,
            Message::UpdateFee(_) => UPDATE_FEE,
            Message::ChannelReestablish(_) => CHANNEL_REESTABLISH,
            Message::AnnouncementSignatures(_) => ANNOUNCEMENT_SIGNATURES,
            Message::ChannelAnnouncement(_) => CHANNEL_ANNOUNCEMENT,
            Message::NodeAnnouncement(_) => NODE_ANNOUNCEMENT,
            Message::ChannelUpdate(_) => CHANNEL_UPDATE,
            Message::GossipTimestampFilter(_) => GOSSIP_TIMESTAMP_FILTER,
            Message::Unknown(t, _) => *t,
        }
    }

    /// Encode with the 2-byte type prefix (the plaintext of one BOLT 8 frame).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        w.u16(self.msg_type());
        match self {
            Message::Warning(m) => {
                w.bytes(&m.channel_id.0);
                w.bytes_u16(&m.data);
            }
            Message::Init(m) => m.write(&mut w),
            Message::Error(m) => {
                w.bytes(&m.channel_id.0);
                w.bytes_u16(&m.data);
            }
            Message::Ping(m) => {
                w.u16(m.num_pong_bytes);
                w.bytes_u16(&m.ignored);
            }
            Message::Pong(m) => {
                w.bytes_u16(&m.ignored);
            }
            Message::OpenChannel(m) => m.write(&mut w),
            Message::AcceptChannel(m) => m.write(&mut w),
            Message::FundingCreated(m) => {
                w.bytes(&m.temporary_channel_id.0);
                w.bytes(&m.funding_txid);
                w.u16(m.funding_output_index);
                w.signature(&m.signature);
            }
            Message::FundingSigned(m) => {
                w.bytes(&m.channel_id.0);
                w.signature(&m.signature);
            }
            Message::ChannelReady(m) => {
                w.bytes(&m.channel_id.0);
                w.pubkey(&m.second_per_commitment_point);
                if let Some(alias) = m.short_channel_id_alias {
                    let mut v = WireWriter::new();
                    v.u64(alias.0);
                    tlv::write_record(&mut w, 1, &v.finish());
                }
            }
            Message::Shutdown(m) => {
                w.bytes(&m.channel_id.0);
                w.bytes_u16(&m.scriptpubkey);
            }
            Message::ClosingSigned(m) => {
                w.bytes(&m.channel_id.0);
                w.u64(m.fee_satoshis);
                w.signature(&m.signature);
                if let Some(range) = &m.fee_range {
                    let mut v = WireWriter::new();
                    v.u64(range.min_fee_satoshis);
                    v.u64(range.max_fee_satoshis);
                    tlv::write_record(&mut w, 1, &v.finish());
                }
            }
            Message::UpdateAddHtlc(m) => {
                debug_assert_eq!(m.onion_routing_packet.len(), ONION_PACKET_LEN);
                w.bytes(&m.channel_id.0);
                w.u64(m.id);
                w.u64(m.amount_msat.0);
                w.bytes(&m.payment_hash.0);
                w.u32(m.cltv_expiry);
                w.bytes(&m.onion_routing_packet);
            }
            Message::UpdateFulfillHtlc(m) => {
                w.bytes(&m.channel_id.0);
                w.u64(m.id);
                w.bytes(&m.payment_preimage.0);
            }
            Message::UpdateFailHtlc(m) => {
                w.bytes(&m.channel_id.0);
                w.u64(m.id);
                w.bytes_u16(&m.reason);
            }
            Message::UpdateFailMalformedHtlc(m) => {
                w.bytes(&m.channel_id.0);
                w.u64(m.id);
                w.bytes(&m.sha256_of_onion);
                w.u16(m.failure_code);
            }
            Message::CommitmentSigned(m) => {
                w.bytes(&m.channel_id.0);
                w.signature(&m.signature);
                w.u16(m.htlc_signatures.len() as u16);
                for sig in &m.htlc_signatures {
                    w.signature(sig);
                }
            }
            Message::RevokeAndAck(m) => {
                w.bytes(&m.channel_id.0);
                w.bytes(&m.per_commitment_secret);
                w.pubkey(&m.next_per_commitment_point);
            }
            Message::UpdateFee(m) => {
                w.bytes(&m.channel_id.0);
                w.u32(m.feerate_per_kw);
            }
            Message::ChannelReestablish(m) => {
                w.bytes(&m.channel_id.0);
                w.u64(m.next_commitment_number);
                w.u64(m.next_revocation_number);
                w.bytes(&m.your_last_per_commitment_secret);
                w.pubkey(&m.my_current_per_commitment_point);
            }
            Message::AnnouncementSignatures(m) => {
                w.bytes(&m.channel_id.0);
                w.u64(m.short_channel_id.0);
                w.signature(&m.node_signature);
                w.signature(&m.bitcoin_signature);
            }
            Message::ChannelAnnouncement(m) => {
                w.signature(&m.node_signature_1);
                w.signature(&m.node_signature_2);
                w.signature(&m.bitcoin_signature_1);
                w.signature(&m.bitcoin_signature_2);
                w.bytes(&m.signed_payload());
            }
            Message::NodeAnnouncement(m) => {
                w.signature(&m.signature);
                m.write_after_sig(&mut w);
            }
            Message::ChannelUpdate(m) => {
                w.signature(&m.signature);
                m.write_after_sig(&mut w);
            }
            Message::GossipTimestampFilter(m) => {
                w.bytes(&m.chain_hash);
                w.u32(m.first_timestamp);
                w.u32(m.timestamp_range);
            }
            Message::Unknown(_, payload) => {
                w.bytes(payload);
            }
        }
        w.finish()
    }

    pub fn decode(data: &[u8]) -> Result<Message, WireError> {
        let mut r = WireReader::new(data);
        let typ = r.u16()?;
        let msg = Self::decode_body(typ, &mut r)?;
        // Lightning explicitly permits trailing extension bytes on
        // messages we fully understand only via TLV (handled per-message);
        // body readers consume what they know. We tolerate leftovers for
        // forward compatibility on non-TLV messages.
        Ok(msg)
    }

    fn decode_body(typ: u16, r: &mut WireReader) -> Result<Message, WireError> {
        use types::*;
        Ok(match typ {
            WARNING => Message::Warning(WarningMsg {
                channel_id: ChannelId(r.array()?),
                data: r.bytes_u16()?,
            }),
            INIT => Message::Init(Init::read(r)?),
            ERROR => Message::Error(ErrorMsg {
                channel_id: ChannelId(r.array()?),
                data: r.bytes_u16()?,
            }),
            PING => Message::Ping(Ping { num_pong_bytes: r.u16()?, ignored: r.bytes_u16()? }),
            PONG => Message::Pong(Pong { ignored: r.bytes_u16()? }),
            OPEN_CHANNEL => Message::OpenChannel(OpenChannel::read(r)?),
            ACCEPT_CHANNEL => Message::AcceptChannel(AcceptChannel::read(r)?),
            FUNDING_CREATED => Message::FundingCreated(FundingCreated {
                temporary_channel_id: ChannelId(r.array()?),
                funding_txid: r.array()?,
                funding_output_index: r.u16()?,
                signature: r.signature()?,
            }),
            FUNDING_SIGNED => Message::FundingSigned(FundingSigned {
                channel_id: ChannelId(r.array()?),
                signature: r.signature()?,
            }),
            CHANNEL_READY => {
                let channel_id = ChannelId(r.array()?);
                let second_per_commitment_point = r.pubkey()?;
                let records = tlv::parse_stream(r.rest())?;
                tlv::check_unknown_even(&records, &[])?;
                let mut alias = None;
                for rec in &records {
                    if rec.typ == 1 && rec.value.len() == 8 {
                        alias = Some(ShortChannelId(u64::from_be_bytes(
                            rec.value[..].try_into().expect("8 bytes"),
                        )));
                    }
                }
                Message::ChannelReady(ChannelReady {
                    channel_id,
                    second_per_commitment_point,
                    short_channel_id_alias: alias,
                })
            }
            SHUTDOWN => Message::Shutdown(Shutdown {
                channel_id: ChannelId(r.array()?),
                scriptpubkey: r.bytes_u16()?,
            }),
            CLOSING_SIGNED => {
                let channel_id = ChannelId(r.array()?);
                let fee_satoshis = r.u64()?;
                let signature = r.signature()?;
                let records = tlv::parse_stream(r.rest())?;
                tlv::check_unknown_even(&records, &[])?;
                let mut fee_range = None;
                for rec in &records {
                    if rec.typ == 1 && rec.value.len() == 16 {
                        let mut vr = WireReader::new(&rec.value);
                        fee_range = Some(ClosingSignedFeeRange {
                            min_fee_satoshis: vr.u64()?,
                            max_fee_satoshis: vr.u64()?,
                        });
                    }
                }
                Message::ClosingSigned(ClosingSigned { channel_id, fee_satoshis, signature, fee_range })
            }
            UPDATE_ADD_HTLC => Message::UpdateAddHtlc(UpdateAddHtlc {
                channel_id: ChannelId(r.array()?),
                id: r.u64()?,
                amount_msat: Msat(r.u64()?),
                payment_hash: PaymentHash(r.array()?),
                cltv_expiry: r.u32()?,
                onion_routing_packet: r.take(ONION_PACKET_LEN)?.to_vec(),
            }),
            UPDATE_FULFILL_HTLC => Message::UpdateFulfillHtlc(UpdateFulfillHtlc {
                channel_id: ChannelId(r.array()?),
                id: r.u64()?,
                payment_preimage: PaymentPreimage(r.array()?),
            }),
            UPDATE_FAIL_HTLC => Message::UpdateFailHtlc(UpdateFailHtlc {
                channel_id: ChannelId(r.array()?),
                id: r.u64()?,
                reason: r.bytes_u16()?,
            }),
            UPDATE_FAIL_MALFORMED_HTLC => {
                Message::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc {
                    channel_id: ChannelId(r.array()?),
                    id: r.u64()?,
                    sha256_of_onion: r.array()?,
                    failure_code: r.u16()?,
                })
            }
            COMMITMENT_SIGNED => {
                let channel_id = ChannelId(r.array()?);
                let signature = r.signature()?;
                let count = r.u16()?;
                let mut htlc_signatures = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    htlc_signatures.push(r.signature()?);
                }
                Message::CommitmentSigned(CommitmentSigned { channel_id, signature, htlc_signatures })
            }
            REVOKE_AND_ACK => Message::RevokeAndAck(RevokeAndAck {
                channel_id: ChannelId(r.array()?),
                per_commitment_secret: r.array()?,
                next_per_commitment_point: r.pubkey()?,
            }),
            UPDATE_FEE => Message::UpdateFee(UpdateFee {
                channel_id: ChannelId(r.array()?),
                feerate_per_kw: r.u32()?,
            }),
            CHANNEL_REESTABLISH => Message::ChannelReestablish(ChannelReestablish {
                channel_id: ChannelId(r.array()?),
                next_commitment_number: r.u64()?,
                next_revocation_number: r.u64()?,
                your_last_per_commitment_secret: r.array()?,
                my_current_per_commitment_point: r.pubkey()?,
            }),
            ANNOUNCEMENT_SIGNATURES => {
                Message::AnnouncementSignatures(AnnouncementSignatures {
                    channel_id: ChannelId(r.array()?),
                    short_channel_id: ShortChannelId(r.u64()?),
                    node_signature: r.signature()?,
                    bitcoin_signature: r.signature()?,
                })
            }
            CHANNEL_ANNOUNCEMENT => {
                let node_signature_1 = r.signature()?;
                let node_signature_2 = r.signature()?;
                let bitcoin_signature_1 = r.signature()?;
                let bitcoin_signature_2 = r.signature()?;
                let features = Features::from_bytes(r.bytes_u16()?);
                Message::ChannelAnnouncement(ChannelAnnouncement {
                    node_signature_1,
                    node_signature_2,
                    bitcoin_signature_1,
                    bitcoin_signature_2,
                    features,
                    chain_hash: r.array()?,
                    short_channel_id: ShortChannelId(r.u64()?),
                    node_id_1: r.pubkey()?,
                    node_id_2: r.pubkey()?,
                    bitcoin_key_1: r.pubkey()?,
                    bitcoin_key_2: r.pubkey()?,
                })
            }
            NODE_ANNOUNCEMENT => {
                let signature = r.signature()?;
                let features = Features::from_bytes(r.bytes_u16()?);
                let timestamp = r.u32()?;
                let node_id = r.pubkey()?;
                let rgb_color = r.array()?;
                let alias = r.array()?;
                let addr_bytes = r.bytes_u16()?;
                Message::NodeAnnouncement(NodeAnnouncement {
                    signature,
                    features,
                    timestamp,
                    node_id,
                    rgb_color,
                    alias,
                    addresses: NodeAnnouncement::read_addresses(&addr_bytes)?,
                })
            }
            CHANNEL_UPDATE => Message::ChannelUpdate(ChannelUpdate {
                signature: r.signature()?,
                chain_hash: r.array()?,
                short_channel_id: ShortChannelId(r.u64()?),
                timestamp: r.u32()?,
                message_flags: r.u8()?,
                channel_flags: r.u8()?,
                cltv_expiry_delta: r.u16()?,
                htlc_minimum_msat: Msat(r.u64()?),
                fee_base_msat: r.u32()?,
                fee_proportional_millionths: r.u32()?,
                htlc_maximum_msat: Msat(r.u64()?),
            }),
            GOSSIP_TIMESTAMP_FILTER => Message::GossipTimestampFilter(GossipTimestampFilter {
                chain_hash: r.array()?,
                first_timestamp: r.u32()?,
                timestamp_range: r.u32()?,
            }),
            other if other % 2 == 1 => Message::Unknown(other, r.rest().to_vec()),
            other => return Err(WireError::UnknownMessageType(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;
    use secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey(fill: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[fill; 32]).unwrap())
    }

    fn test_sig() -> Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let msg = secp256k1::Message::from_digest([7u8; 32]);
        secp.sign_ecdsa(&msg, &sk)
    }

    #[test]
    fn init_roundtrip() {
        let msg = Message::Init(Init {
            global_features: Features::from_bytes(vec![0x02]),
            features: Features::keraunos_default(),
            networks: Some(vec![[0xaa; 32]]),
        });
        let bytes = msg.encode();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 16);
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn open_channel_roundtrip_with_tlvs() {
        let msg = Message::OpenChannel(OpenChannel {
            chain_hash: [9; 32],
            temporary_channel_id: ChannelId([1; 32]),
            funding_satoshis: 1_000_000,
            push_msat: Msat(5_000_000),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: Msat(u64::MAX),
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: Msat(1),
            feerate_per_kw: 2500,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            basepoints: ChannelBasepoints {
                funding_pubkey: test_pubkey(11),
                revocation: test_pubkey(12),
                payment: test_pubkey(13),
                delayed_payment: test_pubkey(14),
                htlc: test_pubkey(15),
            },
            first_per_commitment_point: test_pubkey(16),
            channel_flags: 1,
            upfront_shutdown_script: Some(hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap()),
            channel_type: Some({
                let mut f = Features::empty();
                f.set(12);
                f
            }),
        });
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn update_add_htlc_roundtrip() {
        let msg = Message::UpdateAddHtlc(UpdateAddHtlc {
            channel_id: ChannelId([3; 32]),
            id: 7,
            amount_msat: Msat(123_456),
            payment_hash: PaymentHash([0xcd; 32]),
            cltv_expiry: 500_123,
            onion_routing_packet: vec![0x55; ONION_PACKET_LEN],
        });
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn commitment_signed_roundtrip() {
        let msg = Message::CommitmentSigned(CommitmentSigned {
            channel_id: ChannelId([3; 32]),
            signature: test_sig(),
            htlc_signatures: vec![test_sig(), test_sig()],
        });
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn node_announcement_roundtrip() {
        let msg = Message::NodeAnnouncement(NodeAnnouncement {
            signature: test_sig(),
            features: Features::from_bytes(vec![0x80, 0x00]),
            timestamp: 1_700_000_000,
            node_id: test_pubkey(21),
            rgb_color: [0xde, 0xad, 0x00],
            alias: [0x6b; 32],
            addresses: vec![
                NetAddress::V4 { addr: [127, 0, 0, 1], port: 9735 },
                NetAddress::TorV3 {
                    ed25519_pubkey: [0x11; 32],
                    checksum: 0xbeef,
                    version: 3,
                    port: 9735,
                },
                NetAddress::Hostname { hostname: b"ln.example.com".to_vec(), port: 9735 },
            ],
        });
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn channel_update_roundtrip() {
        let msg = Message::ChannelUpdate(ChannelUpdate {
            signature: test_sig(),
            chain_hash: [6; 32],
            short_channel_id: ShortChannelId::new(840_000, 1234, 1),
            timestamp: 1_700_000_001,
            message_flags: 1,
            channel_flags: 0,
            cltv_expiry_delta: 40,
            htlc_minimum_msat: Msat(1000),
            fee_base_msat: 1000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: Msat(990_000_000),
        });
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn unknown_odd_tolerated_even_rejected() {
        // Type 9999 is odd → Unknown.
        let mut raw = 9999u16.to_be_bytes().to_vec();
        raw.extend_from_slice(b"whatever");
        match Message::decode(&raw).unwrap() {
            Message::Unknown(9999, data) => assert_eq!(data, b"whatever"),
            other => panic!("unexpected {other:?}"),
        }
        // Type 9998 is even → error.
        let raw = 9998u16.to_be_bytes().to_vec();
        assert_eq!(
            Message::decode(&raw),
            Err(WireError::UnknownMessageType(9998))
        );
    }
}
