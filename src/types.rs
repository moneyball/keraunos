//! Core protocol newtypes.
//!
//! Everything that is "just bytes" or "just an integer" on the wire gets a
//! distinct type here so the compiler enforces what the spec only states in
//! prose: millisatoshis don't mix with satoshis, payment hashes don't mix
//! with txids, HTLC ids don't mix with commitment numbers.

use crate::util::hex;
use core::fmt;

/// Millisatoshi amount — the native unit of Lightning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Msat(pub u64);

impl Msat {
    pub const ZERO: Msat = Msat(0);

    pub fn from_sat(sat: u64) -> Msat {
        Msat(sat * 1000)
    }
    /// Whole satoshis, rounding down (the direction the spec always rounds).
    pub fn to_sat_floor(self) -> u64 {
        self.0 / 1000
    }
    pub fn checked_add(self, other: Msat) -> Option<Msat> {
        self.0.checked_add(other.0).map(Msat)
    }
    pub fn checked_sub(self, other: Msat) -> Option<Msat> {
        self.0.checked_sub(other.0).map(Msat)
    }
    pub fn saturating_sub(self, other: Msat) -> Msat {
        Msat(self.0.saturating_sub(other.0))
    }
}

impl core::ops::Add for Msat {
    type Output = Msat;
    fn add(self, rhs: Msat) -> Msat {
        Msat(self.0 + rhs.0)
    }
}

impl core::ops::Sub for Msat {
    type Output = Msat;
    fn sub(self, rhs: Msat) -> Msat {
        Msat(self.0 - rhs.0)
    }
}

impl core::iter::Sum for Msat {
    fn sum<I: Iterator<Item = Msat>>(iter: I) -> Msat {
        Msat(iter.map(|m| m.0).sum())
    }
}

impl fmt::Display for Msat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}msat", self.0)
    }
}

macro_rules! byte_array_newtype {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn from_hex(s: &str) -> Result<Self, hex::HexError> {
                Ok(Self(hex::decode_array(s)?))
            }
            pub fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

byte_array_newtype!(
    /// Channel identifier: funding txid XOR funding output index (BOLT 2),
    /// or a temporary random id before the funding tx exists.
    ChannelId, 32
);
byte_array_newtype!(
    /// SHA-256 of a payment preimage; the HTLC condition.
    PaymentHash, 32
);
byte_array_newtype!(
    /// The 32-byte secret whose SHA-256 is the payment hash.
    PaymentPreimage, 32
);
byte_array_newtype!(
    /// BOLT 11 `payment_secret`: defeats probing by intermediate nodes,
    /// carried in the final onion payload.
    PaymentSecret, 32
);

impl PaymentPreimage {
    pub fn payment_hash(&self) -> PaymentHash {
        PaymentHash(crate::crypto::sha256::Sha256::digest(&self.0))
    }
}

/// BOLT 7 short channel id: block height (3 bytes) | tx index (3 bytes) |
/// output index (2 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortChannelId(pub u64);

impl ShortChannelId {
    pub fn new(block: u32, tx_index: u32, vout: u16) -> ShortChannelId {
        debug_assert!(block < (1 << 24) && tx_index < (1 << 24));
        ShortChannelId(((block as u64) << 40) | ((tx_index as u64) << 16) | vout as u64)
    }
    pub fn block(&self) -> u32 {
        (self.0 >> 40) as u32
    }
    pub fn tx_index(&self) -> u32 {
        ((self.0 >> 16) & 0xff_ffff) as u32
    }
    pub fn vout(&self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

impl fmt::Debug for ShortChannelId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}x{}x{}", self.block(), self.tx_index(), self.vout())
    }
}

impl fmt::Display for ShortChannelId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}x{}x{}", self.block(), self.tx_index(), self.vout())
    }
}

/// Per-channel, per-direction HTLC sequence number (BOLT 2 `id` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HtlcId(pub u64);

/// Block height.
pub type BlockHeight = u32;

/// Which blockchain a channel lives on. The wire identifies chains by
/// genesis-block hash in internal byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn chain_hash(&self) -> [u8; 32] {
        // Genesis hashes, internal (reversed-display) byte order.
        let hex = match self {
            Network::Bitcoin => "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            Network::Testnet => "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000",
            Network::Signet => "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000",
            Network::Regtest => "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
        };
        hex::decode_array(hex).expect("static hex")
    }

    /// BOLT 11 human-readable-part currency prefix.
    pub fn invoice_hrp(&self) -> &'static str {
        match self {
            Network::Bitcoin => "bc",
            Network::Testnet => "tb",
            Network::Signet => "tbs",
            Network::Regtest => "bcrt",
        }
    }
}

/// Feerate in satoshis per 1000 weight units, as used by BOLT 2/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeeRatePerKw(pub u32);

impl FeeRatePerKw {
    /// Fee for a transaction of the given weight: `feerate * weight / 1000`,
    /// rounded down (BOLT 3).
    pub fn fee_for_weight(&self, weight: u64) -> u64 {
        (self.0 as u64) * weight / 1000
    }
}
