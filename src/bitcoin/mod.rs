//! A minimal, self-contained Bitcoin layer: just enough consensus-correct
//! transaction handling for Lightning — serialization, txids, scripts, and
//! the BIP-143 segwit v0 sighash. No wallet, no mempool policy, no script
//! interpreter; Lightning only ever *constructs* a handful of well-known
//! script templates and signs them.

pub mod encode;
pub mod script;
pub mod sighash;
pub mod tx;

pub use script::{Script, ScriptBuilder};
pub use sighash::{SighashCache, SighashType};
pub use tx::{OutPoint, Transaction, TxIn, TxOut, Txid, Witness};

use crate::crypto::sha256::Sha256;

/// Bitcoin's double-SHA256.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(&Sha256::digest(data))
}
