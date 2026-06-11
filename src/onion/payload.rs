//! TLV hop payloads for payment onions (BOLT 4 `payload` format).

use crate::types::{Msat, PaymentSecret, ShortChannelId};
use crate::wire::ser::{WireError, WireWriter};
use crate::wire::tlv;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentData {
    pub payment_secret: PaymentSecret,
    pub total_msat: Msat,
}

/// A payment-onion hop payload.
///
/// Intermediate hops carry `short_channel_id` (where to forward);
/// the final hop instead carries `payment_data` (secret + MPP total).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopPayload {
    /// Type 2: amount to forward (or final amount).
    pub amt_to_forward: Msat,
    /// Type 4: outgoing CLTV (or final expiry).
    pub outgoing_cltv_value: u32,
    /// Type 6: next channel (intermediate hops only).
    pub short_channel_id: Option<ShortChannelId>,
    /// Type 8: payment secret + total amount (final hop only).
    pub payment_data: Option<PaymentData>,
    /// Type 16: opaque metadata from the invoice (final hop only).
    pub payment_metadata: Option<Vec<u8>>,
}

impl HopPayload {
    pub fn forward(amt: Msat, cltv: u32, scid: ShortChannelId) -> HopPayload {
        HopPayload {
            amt_to_forward: amt,
            outgoing_cltv_value: cltv,
            short_channel_id: Some(scid),
            payment_data: None,
            payment_metadata: None,
        }
    }

    pub fn final_hop(
        amt: Msat,
        cltv: u32,
        payment_secret: PaymentSecret,
        total_msat: Msat,
    ) -> HopPayload {
        HopPayload {
            amt_to_forward: amt,
            outgoing_cltv_value: cltv,
            short_channel_id: None,
            payment_data: Some(PaymentData { payment_secret, total_msat }),
            payment_metadata: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        tlv::write_record(&mut w, 2, &tlv::write_tu64(self.amt_to_forward.0));
        tlv::write_record(&mut w, 4, &tlv::write_tu32(self.outgoing_cltv_value));
        if let Some(scid) = self.short_channel_id {
            tlv::write_record(&mut w, 6, &scid.0.to_be_bytes());
        }
        if let Some(pd) = &self.payment_data {
            let mut v = Vec::with_capacity(40);
            v.extend_from_slice(&pd.payment_secret.0);
            v.extend_from_slice(&tlv::write_tu64(pd.total_msat.0));
            tlv::write_record(&mut w, 8, &v);
        }
        if let Some(md) = &self.payment_metadata {
            tlv::write_record(&mut w, 16, md);
        }
        w.finish()
    }

    pub fn decode(payload: &[u8]) -> Result<HopPayload, WireError> {
        let records = tlv::parse_stream(payload)?;
        tlv::check_unknown_even(&records, &[2, 4, 6, 8, 16])?;
        let mut amt = None;
        let mut cltv = None;
        let mut scid = None;
        let mut payment_data = None;
        let mut payment_metadata = None;
        for rec in &records {
            match rec.typ {
                2 => amt = Some(Msat(tlv::read_tu64(&rec.value)?)),
                4 => cltv = Some(tlv::read_tu32(&rec.value)?),
                6 => {
                    if rec.value.len() != 8 {
                        return Err(WireError::BadFormat("short_channel_id length"));
                    }
                    scid = Some(ShortChannelId(u64::from_be_bytes(
                        rec.value[..].try_into().expect("8 bytes"),
                    )));
                }
                8 => {
                    if rec.value.len() < 32 {
                        return Err(WireError::BadFormat("payment_data too short"));
                    }
                    let secret =
                        PaymentSecret(rec.value[..32].try_into().expect("32 bytes"));
                    let total = Msat(tlv::read_tu64(&rec.value[32..])?);
                    payment_data = Some(PaymentData { payment_secret: secret, total_msat: total });
                }
                16 => payment_metadata = Some(rec.value.clone()),
                _ => {}
            }
        }
        Ok(HopPayload {
            amt_to_forward: amt.ok_or(WireError::BadFormat("missing amt_to_forward"))?,
            outgoing_cltv_value: cltv.ok_or(WireError::BadFormat("missing outgoing_cltv"))?,
            short_channel_id: scid,
            payment_data,
            payment_metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    #[test]
    fn roundtrip_forward() {
        let p = HopPayload::forward(Msat(15000), 800_042, ShortChannelId::new(100, 2, 3));
        assert_eq!(HopPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn roundtrip_final() {
        let p = HopPayload::final_hop(
            Msat(123_456_789),
            800_000,
            PaymentSecret([0x42; 32]),
            Msat(123_456_789),
        );
        assert_eq!(HopPayload::decode(&p.encode()).unwrap(), p);
    }

    // The first hop payload of the BOLT 4 onion vector:
    // 02023a98 (amt 15000) 040205dc (cltv 1500) 06080000000000000001 (scid).
    #[test]
    fn bolt4_vector_payload_parses() {
        let raw = hex::decode("02023a98040205dc06080000000000000001").unwrap();
        let p = HopPayload::decode(&raw).unwrap();
        assert_eq!(p.amt_to_forward, Msat(15000));
        assert_eq!(p.outgoing_cltv_value, 1500);
        assert_eq!(p.short_channel_id, Some(ShortChannelId(1)));
        assert_eq!(p.encode(), raw);
    }
}
