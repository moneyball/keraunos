# keraunos

*κεραυνός — thunderbolt. An implementation of the BOLTs.*

A from-scratch implementation of the [Lightning Network protocol](https://github.com/lightning/bolts)
in Rust: the wire format, the Noise transport, commitment transactions, the
channel state machine, Sphinx onion routing, gossip, pathfinding, invoices,
and on-chain enforcement — built directly from the BOLT specifications and
**verified against real LND and LDK nodes**.

```
$ cargo test                                      # 106 tests, incl. LDK interop
$ cargo test --test lnd_interop -- --ignored      # full lifecycle vs real LND on regtest
```

## What "from scratch" means here

**Implemented from the specs, in this repo:**

| Layer | Spec | Ground truth |
|---|---|---|
| SHA-256, RIPEMD-160, HMAC, HKDF, ChaCha20, Poly1305, AEAD | FIPS 180-4, RFC 2104/5869/8439 | official RFC/NIST vectors |
| bech32 | BIP-173 | official vectors |
| Bitcoin tx serialization, txids, script, segwit sighash | BIP-141/143/144 | BIP-143 vectors |
| Message framing, BigSize, TLV streams | BOLT 1 | spec vectors |
| Feature bits | BOLT 9 | — |
| Noise_XK transport with key rotation | BOLT 8 | spec Appendix A, byte-for-byte |
| Channel open/funding/commitment dance/close/reestablish | BOLT 2 | two-party state-machine tests |
| Commitment/HTLC/closing transactions, key derivation, shachain | BOLT 3 | Appendices C/D/E, byte-for-byte |
| Sphinx onions + error onions | BOLT 4 | spec vectors |
| Gossip validation, network graph | BOLT 7 | signature/staleness tests |
| Invoices | BOLT 11 | spec example invoices |
| Force-close handling, justice transactions, sweeps | BOLT 5 | cryptographic verification in tests |

**Deliberately not from scratch:** secp256k1 elliptic-curve arithmetic, which
comes from [libsecp256k1](https://github.com/bitcoin-core/secp256k1) via the
`secp256k1` crate — the same C library Bitcoin Core and LDK use. Hand-rolled
EC field math is how funds get lost; hashes and stream ciphers with public
test vectors are a different risk class. Total runtime dependencies: **two**
(`secp256k1`, `getrandom`).

## Interoperability — the success criteria

Test-vector compliance proves you can *encode*; interop proves you can
*converse*. Both are part of the test suite:

* **LDK** (`tests/ldk_interop.rs`, runs in `cargo test`): a real
  rust-lightning v0.2 `ChannelManager`/`PeerManager` is wired to a keraunos
  node through an in-memory pipe. BOLT 8 handshake, `init`, channel open
  with funding confirmations, **payments in both directions**, all over real
  encrypted wire bytes.
* **LND** (`tests/lnd_interop.rs`, `--ignored` because it spawns daemons):
  a real `lnd` v0.21 against a real `bitcoind` on regtest, connected over
  TCP. Handshake + `init` + ping, channel open with mined confirmations,
  **keraunos pays an LND invoice, LND pays a keraunos invoice**, cooperative
  close confirmed on-chain. Binaries land in `interop/bin` (LND) and
  Homebrew (`bitcoin`).

## Design: a sans-I/O, deterministic core

The entire node is a pure state machine — no sockets, no disk, no clocks, no
threads, no locks, and no RNG inside the engine. This is the
[`quinn-proto`](https://docs.rs/quinn-proto)/sans-I/O architecture applied to
Lightning, and it is the main place this API diverges from (and, we'd argue,
improves on) LDK, which couples a sans-I/O-ish `PeerManager` to a
`ChannelManager` full of internal locking:

```text
socket bytes ──▶ peer_input()                      ┌─▶ Output::Wire ─────▶ socket
blocks ────────▶ funding_confirmed()               ├─▶ Output::Broadcast ▶ bitcoind
unix time ─────▶ tick()                 Node ──────┼─▶ Output::WatchFunding
commands ──────▶ open / pay / claim / close        └─▶ Output::Event ────▶ application
```

Everything the node wants to do comes out of `poll_output()` as an explicit
value. Consequences:

* **Bring your own runtime.** Tokio, async-std, threads-and-blocking-sockets,
  a single-threaded select loop, WASM — the engine doesn't care. The LND
  interop test drives it with two plain `std::net::TcpStream`s.
* **Determinism.** Same inputs ⇒ same outputs, always. The whole-node tests
  run a three-node network entirely in-process, byte-identical on every run.
  This is the property fuzzers and simulators are built on.
* **No deadlocks, no lock-ordering bugs** — there are no locks.

### Everything is a trait at the trust boundaries

```rust
pub trait EntropySource { fn get_random_bytes(&mut self) -> [u8; 32]; }
pub trait NodeSigner    { fn node_id(&self) -> PublicKey; fn ecdh(..); fn sign_gossip(..); .. }
pub trait ChannelSigner { fn per_commitment_point(..); fn sign_htlc(..); fn sign_revocation(..); .. }
pub trait SignerProvider{ type Signer: ChannelSigner; fn derive_channel_signer(..) -> Self::Signer; }
pub trait FeeEstimator  { fn feerate(&self, target: FeeTarget) -> FeeRatePerKw; }
pub trait PathScorer    { fn penalty_msat(&self, edge: &EdgeCandidate<'_>) -> u64; }
pub trait Logger        { fn log(&self, record: Record<'_>); }
```

Keys can live in an HSM (`ChannelSigner` is the only thing that ever touches
channel secrets), routing penalties are pluggable per-edge, randomness is
injected (the tests use a deterministic source). A seed-based
`KeysManager` implements the key traits in-memory.

### Layered like the spec

Every layer is a public module usable on its own — if you only want BOLT 3
transaction construction, or just the Sphinx implementation, or only the
Noise transport, take that module and ignore the rest:

```
crypto      hand-written primitives           bitcoin   minimal consensus layer
wire        BOLT 1/9 + all messages           noise     BOLT 8 state machine
shachain    revocation-secret tree            keys      BOLT 3 key derivation
commitment  BOLT 3 tx construction            channel   BOLT 2 state machine
onion       BOLT 4 Sphinx                     graph     BOLT 7 validation + storage
router      Dijkstra + pluggable scorer       invoice   BOLT 11 + bech32
chain       monitor: classify/punish/sweep    sign      signer traits + KeysManager
node        the orchestrator that ties it together
```

### A taste of the API

```rust
use keraunos::node::{Event, Node, NodeConfig, Output};
use keraunos::sign::{KeysManager, OsEntropy};
use keraunos::types::{Msat, Network};

let keys = KeysManager::new(seed);
let mut node = Node::new(keys, OsEntropy, NodeConfig::new(Network::Regtest, my_close_script));

// Outbound connection: you own the socket, the node owns the protocol.
let (peer, act1) = node.connect_outbound(remote_node_id);
socket.write_all(&act1)?;
loop {
    let n = socket.read(&mut buf)?;
    node.peer_input(peer, &buf[..n])?;
    while let Some(out) = node.poll_output() {
        match out {
            Output::Wire { bytes, .. } => socket.write_all(&bytes)?,
            Output::Broadcast(tx) => bitcoind.send_raw_transaction(&tx)?,
            Output::WatchFunding { outpoint, .. } => watcher.add(outpoint),
            Output::Event(Event::FundingRequired { channel_id, script, value_sat }) => {
                let tx = wallet.build_funding(script, value_sat)?;
                node.provide_funding_transaction(channel_id, tx)?;
            }
            Output::Event(Event::PaymentSent { preimage, .. }) => println!("paid! {preimage}"),
            Output::Event(ev) => println!("{ev:?}"),
        }
    }
}

// Payments are two calls.
let (invoice_string, _hash) = node.create_invoice(Some(Msat(50_000_000)), "consulting", 3600)?;
let id = node.pay_invoice(&Bolt11Invoice::parse(&peer_invoice)?, None)?;
```

### On-chain enforcement

`chain::ChannelMonitor` is the crash-safe enforcement state, snapshotted from
a live channel and serializable (`serialize`/`deserialize`, versioned). Given
any confirmed spend of the funding output it classifies what happened —
cooperative close, our commitment, their current commitment, or a **revoked**
commitment (recovered from the obscured commitment-number bits) — and emits
ready-to-broadcast transactions: justice sweeps via the revocation key,
`to_remote` sweeps, CSV-gated `to_local` sweeps, and pre-signed second-stage
HTLC transactions. The tests verify the signatures cryptographically and
that a deserialized monitor still punishes.

## Scope and honesty

This is a working protocol implementation, not yet a production wallet.
Real-money deployment would still want:

* **Anchor outputs** (`option_anchors_zero_fee_htlc_tx`) — modern fee
  management for force closes. The commitment layer is structured for it
  (the BOLT 3 vectors for anchors are a test-table away) but only
  `static_remotekey` channels are negotiated today.
* **Watchtower-grade monitor depth** — the monitor punishes revoked
  commitments using current-state HTLC reconstruction; per-revoked-commitment
  HTLC archives (what LDK's `ChannelMonitor` carries) are the production
  version of the same machinery.
* **MPP, BOLT 12, dual funding, splicing, taproot channels** — protocol
  extensions, in roughly that order of value.
* **Persistence of full channel state** — monitors (the funds-safety part)
  serialize today; live-channel serialization for seamless restarts is
  scaffolded by the same encoding layer.
* A real fee estimator, an integrated wallet, and the operational hardening
  (DoS limits, dust exposure caps, fee-spike buffers beyond the one
  implemented) that years of mainnet abuse have taught the older
  implementations.

## Layout

```
src/            the library (no_std-ready core is future work; std today)
tests/          ldk_interop.rs (in cargo test), lnd_interop.rs (--ignored, spawns daemons)
interop/bin/    LND binary for the regtest harness
specs/          downloaded BOLT specifications (gitignored reference)
```

## License

MIT OR Apache-2.0, at your option.
