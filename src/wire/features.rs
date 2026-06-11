//! BOLT 9 feature bits.
//!
//! Bit N lives in byte `len - 1 - N/8` at position `N % 8` (the vector is
//! big-endian as a whole). Even bit = required ("the spec is law"), odd bit
//! = optional ("it's OK to be odd").

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureBit {
    DataLossProtect = 0,
    InitialRoutingSync = 3, // odd-only historical bit
    UpfrontShutdownScript = 4,
    GossipQueries = 6,
    VarOnionOptin = 8,
    GossipQueriesEx = 10,
    StaticRemoteKey = 12,
    PaymentSecret = 14,
    BasicMpp = 16,
    Wumbo = 18,
    AnchorsZeroFeeHtlcTx = 22,
    RouteBlinding = 24,
    ShutdownAnySegwit = 26,
    ChannelType = 44,
    ScidAlias = 46,
    PaymentMetadata = 48,
    ZeroConf = 50,
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Features(Vec<u8>);

impl Features {
    pub fn empty() -> Features {
        Features(Vec::new())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Features {
        Features(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// What this implementation speaks. Everything is advertised optional;
    /// we *use* static_remotekey, var_onion and payment_secret on every
    /// channel/payment we make.
    pub fn keraunos_default() -> Features {
        let mut f = Features::empty();
        f.set(FeatureBit::DataLossProtect as u16 + 1); // optional
        f.set(FeatureBit::VarOnionOptin as u16);       // required: all onions are TLV
        f.set(FeatureBit::StaticRemoteKey as u16);     // required: all our channels use it
        f.set(FeatureBit::PaymentSecret as u16);       // required on receive
        f.set(FeatureBit::ShutdownAnySegwit as u16 + 1);
        f.set(FeatureBit::ChannelType as u16 + 1);
        f
    }

    pub fn set(&mut self, bit: u16) {
        let byte_from_end = (bit / 8) as usize;
        if self.0.len() <= byte_from_end {
            let grow = byte_from_end + 1 - self.0.len();
            // Prepend zeros: the vector is big-endian.
            let mut v = vec![0u8; grow];
            v.extend_from_slice(&self.0);
            self.0 = v;
        }
        let idx = self.0.len() - 1 - byte_from_end;
        self.0[idx] |= 1 << (bit % 8);
    }

    pub fn is_set(&self, bit: u16) -> bool {
        let byte_from_end = (bit / 8) as usize;
        if self.0.len() <= byte_from_end {
            return false;
        }
        let idx = self.0.len() - 1 - byte_from_end;
        self.0[idx] & (1 << (bit % 8)) != 0
    }

    /// Either the required or optional bit of the pair.
    pub fn supports(&self, feature: FeatureBit) -> bool {
        let even = feature as u16 & !1;
        self.is_set(even) || self.is_set(even + 1)
    }

    pub fn requires(&self, feature: FeatureBit) -> bool {
        self.is_set(feature as u16 & !1)
    }

    /// BOLT 1: a node receiving unknown *even* bits in `init` must
    /// disconnect. Returns the first offending bit.
    pub fn unknown_required_bits(&self, known_even_bits: &[u16]) -> Option<u16> {
        for byte_from_end in 0..self.0.len() {
            let byte = self.0[self.0.len() - 1 - byte_from_end];
            for bit_in_byte in 0..8u16 {
                let bit = byte_from_end as u16 * 8 + bit_in_byte;
                if bit % 2 == 0 && byte & (1 << bit_in_byte) != 0 && !known_even_bits.contains(&bit)
                {
                    return Some(bit);
                }
            }
        }
        None
    }

    /// The even bits this implementation understands.
    pub fn known_even_bits() -> &'static [u16] {
        &[0, 4, 6, 8, 12, 14, 16, 22, 26, 44, 46, 48, 50]
    }

    /// OR of two feature vectors (BOLT 9 init: globalfeatures | features).
    pub fn or(&self, other: &Features) -> Features {
        let len = self.0.len().max(other.0.len());
        let mut out = vec![0u8; len];
        for (i, b) in out.iter_mut().enumerate() {
            let from_end = len - 1 - i;
            let a = self.0.len().checked_sub(1 + from_end).map(|j| self.0[j]).unwrap_or(0);
            let c = other.0.len().checked_sub(1 + from_end).map(|j| other.0[j]).unwrap_or(0);
            *b = a | c;
        }
        Features(out)
    }
}

impl core::fmt::Debug for Features {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Features({})", crate::util::hex::encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_layout() {
        let mut f = Features::empty();
        f.set(0);
        assert_eq!(f.as_bytes(), &[0b0000_0001]);
        f.set(9);
        // Bit 9 → second byte from the end, bit 1.
        assert_eq!(f.as_bytes(), &[0b0000_0010, 0b0000_0001]);
        assert!(f.is_set(0) && f.is_set(9) && !f.is_set(1) && !f.is_set(8));
    }

    #[test]
    fn supports_pair() {
        let mut f = Features::empty();
        f.set(FeatureBit::StaticRemoteKey as u16 + 1); // optional bit 13
        assert!(f.supports(FeatureBit::StaticRemoteKey));
        assert!(!f.requires(FeatureBit::StaticRemoteKey));
    }

    #[test]
    fn unknown_required_detection() {
        let mut f = Features::empty();
        f.set(100); // unknown even bit
        assert_eq!(f.unknown_required_bits(Features::known_even_bits()), Some(100));
        let mut f = Features::empty();
        f.set(101); // odd → fine
        assert_eq!(f.unknown_required_bits(Features::known_even_bits()), None);
        let defaults = Features::keraunos_default();
        assert_eq!(defaults.unknown_required_bits(Features::known_even_bits()), None);
    }

    #[test]
    fn or_combines() {
        let mut a = Features::empty();
        a.set(0);
        let mut b = Features::empty();
        b.set(13);
        let c = a.or(&b);
        assert!(c.is_set(0) && c.is_set(13));
        assert_eq!(c.as_bytes().len(), 2);
    }
}
