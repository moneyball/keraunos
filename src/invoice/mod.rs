//! BOLT 11 invoices: parse, verify, and create/sign.

pub mod bech32;

use crate::types::{Msat, Network, PaymentHash, PaymentSecret, ShortChannelId};
use crate::wire::Features;
use bech32::{convert_bits, Bech32Error};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

// Tagged-field type values (bech32 charset positions of the letters).
const TAG_PAYMENT_HASH: u8 = 1; // p
const TAG_ROUTE_HINT: u8 = 3; // r
const TAG_FEATURES: u8 = 5; // 9
const TAG_EXPIRY: u8 = 6; // x
const TAG_FALLBACK: u8 = 9; // f
const TAG_DESCRIPTION: u8 = 13; // d
const TAG_PAYMENT_SECRET: u8 = 16; // s
const TAG_PAYEE_NODE: u8 = 19; // n
const TAG_DESCRIPTION_HASH: u8 = 23; // h
const TAG_MIN_FINAL_CLTV: u8 = 24; // c
const TAG_METADATA: u8 = 27; // m

pub const DEFAULT_EXPIRY_SECS: u64 = 3600;
pub const DEFAULT_MIN_FINAL_CLTV: u32 = 18;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvoiceError {
    Bech32(Bech32Error),
    BadPrefix,
    BadAmount,
    TooShort,
    MissingField(&'static str),
    BadField(&'static str),
    BadSignature,
}

impl From<Bech32Error> for InvoiceError {
    fn from(e: Bech32Error) -> Self {
        InvoiceError::Bech32(e)
    }
}

impl core::fmt::Display for InvoiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            InvoiceError::Bech32(e) => write!(f, "bech32: {e}"),
            InvoiceError::BadPrefix => write!(f, "not an ln invoice for a known chain"),
            InvoiceError::BadAmount => write!(f, "malformed amount"),
            InvoiceError::TooShort => write!(f, "invoice data too short"),
            InvoiceError::MissingField(s) => write!(f, "missing required field: {s}"),
            InvoiceError::BadField(s) => write!(f, "malformed field: {s}"),
            InvoiceError::BadSignature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for InvoiceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Description {
    Direct(String),
    /// SHA256 of a longer description transmitted out of band.
    Hash([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteHintHop {
    pub src_node_id: PublicKey,
    pub short_channel_id: ShortChannelId,
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
}

pub type RouteHint = Vec<RouteHintHop>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bolt11Invoice {
    pub network: Network,
    pub amount_msat: Option<Msat>,
    pub timestamp: u64,
    pub payment_hash: PaymentHash,
    pub payment_secret: PaymentSecret,
    pub description: Description,
    pub expiry_secs: Option<u64>,
    pub min_final_cltv_expiry_delta: Option<u32>,
    pub features: Features,
    pub route_hints: Vec<RouteHint>,
    /// Recovered (or explicit `n`-field) payee node id.
    pub payee: PublicKey,
}

impl Bolt11Invoice {
    pub fn expiry_secs_or_default(&self) -> u64 {
        self.expiry_secs.unwrap_or(DEFAULT_EXPIRY_SECS)
    }

    pub fn min_final_cltv_or_default(&self) -> u32 {
        self.min_final_cltv_expiry_delta.unwrap_or(DEFAULT_MIN_FINAL_CLTV)
    }

    pub fn is_expired_at(&self, unix_time: u64) -> bool {
        unix_time > self.timestamp.saturating_add(self.expiry_secs_or_default())
    }

    pub fn parse(s: &str) -> Result<Bolt11Invoice, InvoiceError> {
        let (hrp, data) = bech32::decode(s)?;
        if !hrp.starts_with("ln") {
            return Err(InvoiceError::BadPrefix);
        }
        let after_ln = &hrp[2..];
        // Longest-prefix match: bcrt before bc, tbs before tb.
        let (network, amount_str) = if let Some(rest) = after_ln.strip_prefix("bcrt") {
            (Network::Regtest, rest)
        } else if let Some(rest) = after_ln.strip_prefix("tbs") {
            (Network::Signet, rest)
        } else if let Some(rest) = after_ln.strip_prefix("tb") {
            (Network::Testnet, rest)
        } else if let Some(rest) = after_ln.strip_prefix("bc") {
            (Network::Bitcoin, rest)
        } else {
            return Err(InvoiceError::BadPrefix);
        };
        let amount_msat = parse_amount(amount_str)?;

        if data.len() < 7 + 104 {
            return Err(InvoiceError::TooShort);
        }
        let (head, sig_part) = data.split_at(data.len() - 104);
        let timestamp = head[..7].iter().fold(0u64, |acc, &v| acc << 5 | v as u64);

        // Signature: 64 bytes compact + 1 recovery byte from 104 5-bit chars.
        let sig_bytes = convert_bits(sig_part, 5, 8, false).map_err(InvoiceError::Bech32)?;
        debug_assert_eq!(sig_bytes.len(), 65);
        let recovery =
            RecoveryId::from_i32(sig_bytes[64] as i32).map_err(|_| InvoiceError::BadSignature)?;
        let rsig = RecoverableSignature::from_compact(&sig_bytes[..64], recovery)
            .map_err(|_| InvoiceError::BadSignature)?;

        // The signed message: hrp bytes || data-part (without signature)
        // packed from 5-bit groups into bytes (zero-padded).
        let mut preimage = hrp.as_bytes().to_vec();
        preimage.extend_from_slice(&convert_bits(head, 5, 8, true).map_err(InvoiceError::Bech32)?);
        let msg = Message::from_digest(crate::crypto::sha256(&preimage));

        let secp = Secp256k1::new();
        let recovered = secp.recover_ecdsa(&msg, &rsig).map_err(|_| InvoiceError::BadSignature)?;

        // Tagged fields.
        let mut fields = &head[7..];
        let mut payment_hash = None;
        let mut payment_secret = None;
        let mut description = None;
        let mut expiry = None;
        let mut min_final_cltv = None;
        let mut features = Features::empty();
        let mut route_hints = Vec::new();
        let mut explicit_payee: Option<PublicKey> = None;

        while !fields.is_empty() {
            if fields.len() < 3 {
                return Err(InvoiceError::BadField("truncated tagged field"));
            }
            let tag = fields[0];
            let len = (fields[1] as usize) * 32 + fields[2] as usize;
            if fields.len() < 3 + len {
                return Err(InvoiceError::BadField("tagged field overruns data"));
            }
            let body = &fields[3..3 + len];
            fields = &fields[3 + len..];

            match tag {
                TAG_PAYMENT_HASH if len == 52 => {
                    let bytes = convert_bits(body, 5, 8, true)?;
                    payment_hash =
                        Some(PaymentHash(bytes[..32].try_into().expect("52*5/8 >= 32")));
                }
                TAG_PAYMENT_SECRET if len == 52 => {
                    let bytes = convert_bits(body, 5, 8, true)?;
                    payment_secret =
                        Some(PaymentSecret(bytes[..32].try_into().expect("32 bytes")));
                }
                TAG_DESCRIPTION => {
                    let bytes = convert_bits(body, 5, 8, false)
                        .map_err(|_| InvoiceError::BadField("description"))?;
                    let text = String::from_utf8(bytes)
                        .map_err(|_| InvoiceError::BadField("description utf8"))?;
                    description = Some(Description::Direct(text));
                }
                TAG_DESCRIPTION_HASH if len == 52 => {
                    let bytes = convert_bits(body, 5, 8, true)?;
                    description =
                        Some(Description::Hash(bytes[..32].try_into().expect("32 bytes")));
                }
                TAG_EXPIRY => {
                    expiry = Some(body.iter().fold(0u64, |acc, &v| acc << 5 | v as u64));
                }
                TAG_MIN_FINAL_CLTV => {
                    min_final_cltv =
                        Some(body.iter().fold(0u32, |acc, &v| acc << 5 | v as u32));
                }
                TAG_FEATURES => {
                    features = Features::from_bytes(five_bit_to_bytes_be(body));
                }
                TAG_PAYEE_NODE if len == 53 => {
                    let bytes = convert_bits(body, 5, 8, true)?;
                    explicit_payee = PublicKey::from_slice(&bytes[..33]).ok();
                }
                TAG_ROUTE_HINT => {
                    let bytes = convert_bits(body, 5, 8, false)
                        .map_err(|_| InvoiceError::BadField("route hint"))?;
                    if bytes.len() % 51 != 0 {
                        return Err(InvoiceError::BadField("route hint length"));
                    }
                    let mut hint = Vec::with_capacity(bytes.len() / 51);
                    for chunk in bytes.chunks_exact(51) {
                        hint.push(RouteHintHop {
                            src_node_id: PublicKey::from_slice(&chunk[..33])
                                .map_err(|_| InvoiceError::BadField("route hint pubkey"))?,
                            short_channel_id: ShortChannelId(u64::from_be_bytes(
                                chunk[33..41].try_into().expect("8 bytes"),
                            )),
                            fee_base_msat: u32::from_be_bytes(
                                chunk[41..45].try_into().expect("4 bytes"),
                            ),
                            fee_proportional_millionths: u32::from_be_bytes(
                                chunk[45..49].try_into().expect("4 bytes"),
                            ),
                            cltv_expiry_delta: u16::from_be_bytes(
                                chunk[49..51].try_into().expect("2 bytes"),
                            ),
                        });
                    }
                    route_hints.push(hint);
                }
                TAG_FALLBACK | TAG_METADATA => { /* parsed but unused */ }
                _ => { /* unknown tags are skipped per spec */ }
            }
        }

        // If an explicit payee was given, the signature must verify against
        // it; otherwise the recovered key is the payee.
        let payee = match explicit_payee {
            Some(pk) => {
                let plain = rsig.to_standard();
                secp.verify_ecdsa(&msg, &plain, &pk)
                    .map_err(|_| InvoiceError::BadSignature)?;
                pk
            }
            None => recovered,
        };

        Ok(Bolt11Invoice {
            network,
            amount_msat,
            timestamp,
            payment_hash: payment_hash.ok_or(InvoiceError::MissingField("payment_hash"))?,
            payment_secret: payment_secret.ok_or(InvoiceError::MissingField("payment_secret"))?,
            description: description.ok_or(InvoiceError::MissingField("description"))?,
            expiry_secs: expiry,
            min_final_cltv_expiry_delta: min_final_cltv,
            features,
            route_hints,
            payee,
        })
    }
}

fn parse_amount(s: &str) -> Result<Option<Msat>, InvoiceError> {
    if s.is_empty() {
        return Ok(None);
    }
    let (digits, multiplier) = match s.chars().last().expect("nonempty") {
        'm' => (&s[..s.len() - 1], 100_000_000u64),
        'u' => (&s[..s.len() - 1], 100_000),
        'n' => (&s[..s.len() - 1], 100),
        'p' => (&s[..s.len() - 1], 0), // handled specially: 0.1 msat units
        c if c.is_ascii_digit() => (s, 100_000_000_000),
        _ => return Err(InvoiceError::BadAmount),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InvoiceError::BadAmount);
    }
    let value: u64 = digits.parse().map_err(|_| InvoiceError::BadAmount)?;
    if multiplier == 0 {
        // pico-bitcoin: 1 p = 0.1 msat; last digit must be 0.
        if value % 10 != 0 {
            return Err(InvoiceError::BadAmount);
        }
        return Ok(Some(Msat(value / 10)));
    }
    value
        .checked_mul(multiplier)
        .map(|v| Some(Msat(v)))
        .ok_or(InvoiceError::BadAmount)
}

fn encode_amount(msat: Msat) -> String {
    let m = msat.0;
    if m % 100_000_000 == 0 {
        format!("{}m", m / 100_000_000)
    } else if m % 100_000 == 0 {
        format!("{}u", m / 100_000)
    } else if m % 100 == 0 {
        format!("{}n", m / 100)
    } else {
        format!("{}p", m * 10)
    }
}

/// Feature vector → minimal big-endian 5-bit groups.
fn bytes_to_five_bit_be(bytes: &[u8]) -> Vec<u8> {
    // Interpret as a big integer; emit base-32 digits.
    let total_bits = bytes.len() * 8;
    let groups = total_bits.div_ceil(5);
    let mut out = vec![0u8; groups];
    for bit in 0..total_bits {
        // bit N counted from the LSB end.
        let byte = bytes[bytes.len() - 1 - bit / 8];
        if byte & (1 << (bit % 8)) != 0 {
            let g = groups - 1 - bit / 5;
            out[g] |= 1 << (bit % 5);
        }
    }
    // Strip leading zero groups.
    let first_nonzero = out.iter().position(|&g| g != 0).unwrap_or(out.len());
    out.split_off(first_nonzero)
}

/// 5-bit groups → minimal big-endian bytes (inverse of the above).
fn five_bit_to_bytes_be(groups: &[u8]) -> Vec<u8> {
    let total_bits = groups.len() * 5;
    let nbytes = total_bits.div_ceil(8);
    let mut out = vec![0u8; nbytes];
    for bit in 0..total_bits {
        let g = groups[groups.len() - 1 - bit / 5];
        if g & (1 << (bit % 5)) != 0 {
            let b = nbytes - 1 - bit / 8;
            out[b] |= 1 << (bit % 8);
        }
    }
    let first_nonzero = out.iter().position(|&b| b != 0).unwrap_or(out.len());
    out.split_off(first_nonzero)
}

/// Everything needed to mint an invoice; signing is injected so keys can
/// live behind a [`crate::sign::NodeSigner`].
pub struct InvoiceBuilder {
    pub network: Network,
    pub amount_msat: Option<Msat>,
    pub timestamp: u64,
    pub payment_hash: PaymentHash,
    pub payment_secret: PaymentSecret,
    pub description: Description,
    pub expiry_secs: Option<u64>,
    pub min_final_cltv_expiry_delta: Option<u32>,
    pub features: Features,
    pub route_hints: Vec<RouteHint>,
}

impl InvoiceBuilder {
    /// Standard invoice features: payment_secret and var_onion required,
    /// basic_mpp optional.
    pub fn default_features() -> Features {
        let mut f = Features::empty();
        f.set(8); // var_onion_optin (required)
        f.set(14); // payment_secret (required)
        f.set(17); // basic_mpp (optional)
        f
    }

    pub fn encode_signed(
        &self,
        sign: impl FnOnce(&[u8; 32]) -> RecoverableSignature,
    ) -> String {
        let mut hrp = format!("ln{}", self.network.invoice_hrp());
        if let Some(amt) = self.amount_msat {
            hrp.push_str(&encode_amount(amt));
        }

        let mut data: Vec<u8> = Vec::with_capacity(400);
        for i in (0..7).rev() {
            data.push(((self.timestamp >> (5 * i)) & 31) as u8);
        }

        let mut tagged = |tag: u8, body: &[u8]| {
            data.push(tag);
            data.push((body.len() / 32) as u8);
            data.push((body.len() % 32) as u8);
            data.extend_from_slice(body);
        };

        // Field order mirrors the spec examples: s, p, d/h, x, c, r, 9.
        tagged(
            TAG_PAYMENT_SECRET,
            &convert_bits(&self.payment_secret.0, 8, 5, true).expect("8->5"),
        );
        tagged(
            TAG_PAYMENT_HASH,
            &convert_bits(&self.payment_hash.0, 8, 5, true).expect("8->5"),
        );
        match &self.description {
            Description::Direct(text) => {
                tagged(TAG_DESCRIPTION, &convert_bits(text.as_bytes(), 8, 5, true).expect("8->5"));
            }
            Description::Hash(h) => {
                tagged(TAG_DESCRIPTION_HASH, &convert_bits(h, 8, 5, true).expect("8->5"));
            }
        }
        if let Some(x) = self.expiry_secs {
            tagged(TAG_EXPIRY, &minimal_base32_be(x));
        }
        if let Some(c) = self.min_final_cltv_expiry_delta {
            tagged(TAG_MIN_FINAL_CLTV, &minimal_base32_be(c as u64));
        }
        for hint in &self.route_hints {
            let mut bytes = Vec::with_capacity(51 * hint.len());
            for hop in hint {
                bytes.extend_from_slice(&hop.src_node_id.serialize());
                bytes.extend_from_slice(&hop.short_channel_id.0.to_be_bytes());
                bytes.extend_from_slice(&hop.fee_base_msat.to_be_bytes());
                bytes.extend_from_slice(&hop.fee_proportional_millionths.to_be_bytes());
                bytes.extend_from_slice(&hop.cltv_expiry_delta.to_be_bytes());
            }
            tagged(TAG_ROUTE_HINT, &convert_bits(&bytes, 8, 5, true).expect("8->5"));
        }
        if !self.features.as_bytes().is_empty() {
            tagged(TAG_FEATURES, &bytes_to_five_bit_be(self.features.as_bytes()));
        }

        // Sign hrp || packed data.
        let mut preimage = hrp.as_bytes().to_vec();
        preimage.extend_from_slice(&convert_bits(&data, 5, 8, true).expect("5->8"));
        let digest = crate::crypto::sha256(&preimage);
        let rsig = sign(&digest);
        let (rec_id, compact) = rsig.serialize_compact();
        let mut sig65 = compact.to_vec();
        sig65.push(rec_id.to_i32() as u8);
        data.extend_from_slice(&convert_bits(&sig65, 8, 5, true).expect("8->5"));

        bech32::encode(&hrp, &data)
    }

    /// Convenience: sign with a raw secret key.
    pub fn encode_with_key(&self, secp: &Secp256k1<secp256k1::All>, key: &SecretKey) -> String {
        self.encode_signed(|digest| {
            secp.sign_ecdsa_recoverable(&Message::from_digest(*digest), key)
        })
    }
}

fn minimal_base32_be(mut v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let mut out = Vec::new();
    while v > 0 {
        out.push((v & 31) as u8);
        v >>= 5;
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests;
