//! BOLT 1/2/7 wire format: message framing, BigSize, TLV streams, feature
//! bits, and typed message structs.
//!
//! Lightning wire integers are **big-endian** (unlike Bitcoin consensus
//! encoding, which is little-endian — both appear in this codebase, so the
//! two layers keep separate reader/writer types on purpose).

pub mod bigsize;
pub mod features;
pub mod msgs;
pub mod ser;
pub mod tlv;

pub use features::{FeatureBit, Features};
pub use msgs::Message;
pub use ser::{WireError, WireReader, WireWriter};
