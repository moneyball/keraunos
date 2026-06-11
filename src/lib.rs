//! # keraunos
//!
//! A from-scratch implementation of the Lightning Network protocol (the
//! [BOLT specifications](https://github.com/lightning/bolts)) in Rust.
//!
//! ## Design philosophy
//!
//! The protocol engine is **sans-I/O and deterministic**: it never touches
//! sockets, disks, clocks, threads, locks, or random number generators. All
//! effects are *inputs* (bytes received, blocks connected, time advanced,
//! entropy provided) or *outputs* (bytes to send, transactions to broadcast,
//! events for the application). This makes the entire node embeddable in any
//! runtime — async or sync, single- or multi-threaded — and, more
//! importantly, makes it *replayable*: a sequence of inputs always produces
//! the same outputs, which is the property that fuzzing, simulation and
//! deterministic tests are built on.
//!
//! Layering, bottom to top:
//!
//! * [`crypto`] — hand-written primitives (SHA-256, RIPEMD-160, HMAC, HKDF,
//!   ChaCha20, Poly1305) verified against RFC test vectors. Elliptic-curve
//!   operations come from libsecp256k1 via the `secp256k1` crate.
//! * [`bitcoin`] — minimal Bitcoin: transactions, scripts, consensus
//!   serialization, BIP-143 segwit sighash.
//! * [`wire`] — BOLT 1/2/7 message (de)serialization, BigSize, TLV streams,
//!   BOLT 9 feature bits.
//! * [`noise`] — BOLT 8 Noise_XK transport, as a pure state machine.
//! * [`shachain`] / [`keys`] / [`commitment`] — BOLT 3: revocation-secret
//!   trees, commitment-point key derivation, commitment/HTLC/closing
//!   transaction construction.
//! * [`onion`] — BOLT 4 Sphinx packet construction, peeling, and error
//!   onions.
//! * [`channel`] — the BOLT 2 channel state machine: open/accept, funding,
//!   the commitment-update dance, shutdown and cooperative close.
//! * [`graph`] / [`router`] — BOLT 7 gossip validation, the public network
//!   graph, and pathfinding with a pluggable scorer.
//! * [`invoice`] — BOLT 11 invoices (bech32 from scratch).
//! * [`chain`] — chain-interface traits and the on-chain enforcement monitor
//!   (commitment broadcast classification, revocation punishment, HTLC
//!   claims).
//! * [`sign`] — signer abstraction: every secret-key operation a node
//!   performs goes through the [`sign::NodeSigner`] / [`sign::ChannelSigner`]
//!   traits, so keys can live in an HSM or remote signer.
//! * [`node`] — the orchestrator: peers, channels, HTLC forwarding,
//!   payments, and the [`node::Output`] queue that drives your event loop.

pub mod bitcoin;
pub mod chain;
pub mod channel;
pub mod commitment;
pub mod crypto;
pub mod graph;
pub mod invoice;
pub mod keys;
pub mod node;
pub mod noise;
pub mod onion;
pub mod router;
pub mod shachain;
pub mod sign;
pub mod types;
pub mod util;
pub mod wire;

pub use types::*;
