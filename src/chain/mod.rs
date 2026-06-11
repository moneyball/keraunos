//! Chain interfaces and on-chain enforcement.
//!
//! [`ChannelMonitor`] is the safety net: given any confirmed spend of the
//! funding output it classifies what happened and produces the
//! transactions that protect our funds — most importantly the justice
//! transaction that punishes a revoked commitment broadcast.

pub mod monitor;
pub mod persist;
#[cfg(test)]
mod tests;

pub use monitor::{ChannelMonitor, FundingSpend, MonitorResponse};

use crate::types::FeeRatePerKw;

/// What a feerate is for — embedders map these to their fee source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeTarget {
    /// Pre-signed commitment transactions.
    Commitment,
    /// Cooperative close.
    Close,
    /// Sweeps that race a CSV/CLTV deadline (justice, HTLC claims).
    Urgent,
}

/// Source of feerates. The engine never talks to a fee API itself.
pub trait FeeEstimator {
    fn feerate(&self, target: FeeTarget) -> FeeRatePerKw;
}

/// A fixed-rate estimator, fine for tests and regtest.
pub struct StaticFeeEstimator(pub FeeRatePerKw);

impl FeeEstimator for StaticFeeEstimator {
    fn feerate(&self, _target: FeeTarget) -> FeeRatePerKw {
        self.0
    }
}
