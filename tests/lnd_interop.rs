//! Interoperability test against LND on a private regtest network.
//!
//! Spawns real `bitcoind` and `lnd` daemons, connects keraunos over real
//! TCP, and runs the full lifecycle: handshake/init/ping, channel open
//! with on-chain confirmations, payments in both directions (each side
//! paying an invoice minted by the other), and cooperative close.
//!
//! Requirements (see `interop/`): `bitcoind` on PATH (brew install
//! bitcoin) and the LND release binaries in `interop/bin/`. Run with:
//!
//! ```sh
//! cargo test --test lnd_interop -- --ignored --nocapture
//! ```

use keraunos::bitcoin::Transaction;
use keraunos::invoice::Bolt11Invoice;
use keraunos::node::{Event, Node, NodeConfig, Output, PeerId};
use keraunos::sign::{KeysManager, OsEntropy};
use keraunos::types::{Msat, Network, ShortChannelId};
use keraunos::util::hex;

use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RPC_PORT: u16 = 18743;
const P2P_PORT: u16 = 18744;
const ZMQ_BLOCK: u16 = 28832;
const ZMQ_TX: u16 = 28833;
const LND_P2P: u16 = 19735;
const LND_RPC: u16 = 19009;

struct Daemons {
    bitcoind: Child,
    lnd: Child,
    dir: PathBuf,
}

impl Drop for Daemons {
    fn drop(&mut self) {
        let _ = self.lnd.kill();
        let _ = self.bitcoind.kill();
        let _ = self.lnd.wait();
        let _ = self.bitcoind.wait();
        // The directory is wiped at the *start* of each run instead, so
        // logs survive failures for post-mortem.
        let _ = &self.dir;
    }
}

fn project_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn btc(args: &[&str]) -> Value {
    let dir = std::env::temp_dir().join("keraunos-lnd-interop");
    let out = Command::new("bitcoin-cli")
        .args([
            "-regtest",
            &format!("-datadir={}", dir.join("bitcoind").display()),
            "-rpcuser=kuser",
            "-rpcpassword=kpass",
            &format!("-rpcport={RPC_PORT}"),
        ])
        .args(args)
        .output()
        .expect("bitcoin-cli runs");
    assert!(
        out.status.success(),
        "bitcoin-cli {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| Value::String(stdout.trim().to_string()))
}

fn lncli(args: &[&str]) -> Value {
    let dir = std::env::temp_dir().join("keraunos-lnd-interop");
    let out = Command::new(project_dir().join("interop/bin/lncli"))
        .args([
            &format!("--lnddir={}", dir.join("lnd").display()),
            "--network=regtest",
            &format!("--rpcserver=127.0.0.1:{LND_RPC}"),
        ])
        .args(args)
        .output()
        .expect("lncli runs");
    assert!(
        out.status.success(),
        "lncli {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| Value::String(stdout.trim().to_string()))
}

fn lncli_try(args: &[&str]) -> Option<Value> {
    let dir = std::env::temp_dir().join("keraunos-lnd-interop");
    let out = Command::new(project_dir().join("interop/bin/lncli"))
        .args([
            &format!("--lnddir={}", dir.join("lnd").display()),
            "--network=regtest",
            &format!("--rpcserver=127.0.0.1:{LND_RPC}"),
        ])
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

fn start_daemons() -> Daemons {
    let dir = std::env::temp_dir().join("keraunos-lnd-interop");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bitcoind")).unwrap();
    std::fs::create_dir_all(dir.join("lnd")).unwrap();

    let bitcoind = Command::new("bitcoind")
        .args([
            "-regtest",
            &format!("-datadir={}", dir.join("bitcoind").display()),
            "-rpcuser=kuser",
            "-rpcpassword=kpass",
            &format!("-rpcport={RPC_PORT}"),
            &format!("-port={P2P_PORT}"),
            &format!("-zmqpubrawblock=tcp://127.0.0.1:{ZMQ_BLOCK}"),
            &format!("-zmqpubrawtx=tcp://127.0.0.1:{ZMQ_TX}"),
            "-txindex",
            "-fallbackfee=0.0001",
            "-listen=1",
            "-server=1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("bitcoind starts (brew install bitcoin)");

    // Wait for RPC, create a miner wallet, mine spendable coins.
    wait_for(Duration::from_secs(30), "bitcoind RPC", || {
        Command::new("bitcoin-cli")
            .args([
                "-regtest",
                &format!("-datadir={}", dir.join("bitcoind").display()),
                "-rpcuser=kuser",
                "-rpcpassword=kpass",
                &format!("-rpcport={RPC_PORT}"),
                "getblockchaininfo",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    });
    btc(&["createwallet", "miner"]);
    let addr = btc(&["getnewaddress"]).as_str().unwrap().to_string();
    btc(&["generatetoaddress", "101", &addr]);

    let lnd = Command::new(project_dir().join("interop/bin/lnd"))
        .args([
            "--bitcoin.regtest",
            "--bitcoin.node=bitcoind",
            &format!("--bitcoind.rpchost=127.0.0.1:{RPC_PORT}"),
            "--bitcoind.rpcuser=kuser",
            "--bitcoind.rpcpass=kpass",
            &format!("--bitcoind.zmqpubrawblock=tcp://127.0.0.1:{ZMQ_BLOCK}"),
            &format!("--bitcoind.zmqpubrawtx=tcp://127.0.0.1:{ZMQ_TX}"),
            &format!("--lnddir={}", dir.join("lnd").display()),
            &format!("--listen=127.0.0.1:{LND_P2P}"),
            &format!("--rpclisten=127.0.0.1:{LND_RPC}"),
            "--norest",
            "--noseedbackup",
            "--debuglevel=info",
            "--trickledelay=50",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("lnd starts (see interop/bin)");

    wait_for(Duration::from_secs(60), "lnd RPC + chain sync", || {
        lncli_try(&["getinfo"])
            .map(|v| v["synced_to_chain"].as_bool().unwrap_or(false))
            .unwrap_or(false)
    });

    Daemons { bitcoind, lnd, dir }
}

fn wait_for(timeout: Duration, what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Encode a witness program as a regtest bech32 address (BIP 173).
fn script_to_address(script: &keraunos::bitcoin::Script) -> String {
    let bytes = script.as_bytes();
    assert_eq!(bytes[0], 0, "v0 witness program expected");
    let program = &bytes[2..];
    let mut data = vec![0u8];
    data.extend(keraunos::invoice::bech32::convert_bits(program, 8, 5, true).unwrap());
    keraunos::invoice::bech32::encode("bcrt", &data)
}

/// The real-I/O driver around the sans-I/O node: TCP in/out, broadcasts to
/// bitcoind, events collected.
struct Driver {
    node: Node<KeysManager, OsEntropy>,
    peer: PeerId,
    stream: TcpStream,
    events: Vec<Event>,
}

impl Driver {
    fn connect(lnd_node_id: secp256k1::PublicKey) -> Driver {
        let close_addr = btc(&["getnewaddress", "", "bech32"]);
        let _ = close_addr;
        // Close to a P2WPKH we don't need to spend in this test.
        let close_script = keraunos::bitcoin::Script::new_p2wpkh(&[0x42; 20]);
        let mut node = Node::new(
            KeysManager::new([0x4b; 32]),
            OsEntropy,
            NodeConfig::new(Network::Regtest, close_script),
        );
        node.tick(now_secs());
        let (peer, act1) = node.connect_outbound(lnd_node_id);
        let mut stream = TcpStream::connect(("127.0.0.1", LND_P2P)).expect("lnd is listening");
        stream.set_nonblocking(true).unwrap();
        stream.write_all(&act1).unwrap();
        Driver { node, peer, stream, events: Vec::new() }
    }

    /// One pump round: drain node outputs, read socket. Returns true if
    /// anything moved.
    fn pump_once(&mut self) -> bool {
        let mut moved = false;
        while let Some(out) = self.node.poll_output() {
            moved = true;
            match out {
                Output::Wire { bytes, .. } => {
                    self.stream.write_all(&bytes).expect("socket write");
                }
                Output::Broadcast(tx) => {
                    let hex_tx = hex::encode(&tx.serialize());
                    // Both sides may broadcast the same tx; duplicates are fine.
                    let _ = Command::new("bitcoin-cli")
                        .args([
                            "-regtest",
                            &format!(
                                "-datadir={}",
                                std::env::temp_dir()
                                    .join("keraunos-lnd-interop/bitcoind")
                                    .display()
                            ),
                            "-rpcuser=kuser",
                            "-rpcpassword=kpass",
                            &format!("-rpcport={RPC_PORT}"),
                            "sendrawtransaction",
                            &hex_tx,
                        ])
                        .output();
                }
                Output::Event(e) => self.events.push(e),
                Output::WatchFunding { .. } => {}
            }
        }
        let mut buf = [0u8; 65536];
        match self.stream.read(&mut buf) {
            Ok(0) => panic!("LND closed the connection"),
            Ok(n) => {
                self.node.peer_input(self.peer, &buf[..n]).expect("valid bytes from LND");
                moved = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("socket error: {e}"),
        }
        moved
    }

    /// Pump until `pred` matches an event (which is then returned).
    fn wait_event(
        &mut self,
        timeout: Duration,
        what: &str,
        mut pred: impl FnMut(&Event) -> bool,
    ) -> Event {
        let start = Instant::now();
        loop {
            self.pump_once();
            if let Some(i) = self.events.iter().position(&mut pred) {
                return self.events.remove(i);
            }
            if start.elapsed() > timeout {
                panic!("timed out waiting for {what}; events so far: {:?}", self.events);
            }
            self.node.tick(now_secs());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Pump for a fixed duration (letting background traffic settle).
    fn pump_for(&mut self, d: Duration) {
        let start = Instant::now();
        while start.elapsed() < d {
            if !self.pump_once() {
                std::thread::sleep(Duration::from_millis(20));
            }
            self.node.tick(now_secs());
        }
    }
}

fn mine(n: u32) -> u32 {
    let addr = btc(&["getnewaddress"]).as_str().unwrap().to_string();
    btc(&["generatetoaddress", &n.to_string(), &addr]);
    btc(&["getblockcount"]).as_u64().unwrap() as u32
}

#[test]
#[ignore = "requires bitcoind on PATH and lnd in interop/bin (run interop/run.sh)"]
fn lnd_full_lifecycle() {
    let _daemons = start_daemons();

    let info = lncli(&["getinfo"]);
    let lnd_id_hex = info["identity_pubkey"].as_str().unwrap();
    let lnd_id =
        secp256k1::PublicKey::from_slice(&hex::decode(lnd_id_hex).unwrap()).unwrap();
    eprintln!("LND node: {lnd_id_hex}");

    // ---- 1. transport + init + ping ------------------------------------
    let mut d = Driver::connect(lnd_id);
    let ev = d.wait_event(Duration::from_secs(10), "peer connected", |e| {
        matches!(e, Event::PeerConnected { .. })
    });
    eprintln!("✓ handshake + init with LND: {ev:?}");
    // Survive a keepalive exchange.
    d.pump_for(Duration::from_secs(2));
    let peers = lncli(&["listpeers"]);
    assert_eq!(
        peers["peers"].as_array().map(|a| a.len()),
        Some(1),
        "LND sees us as a peer: {peers}"
    );

    // ---- 2. open a channel (keraunos funds it) --------------------------
    let knode_id = d.node.node_id();
    let temp = d.node.open_channel(lnd_id, 1_000_000, Msat::ZERO).unwrap();
    let ev = d.wait_event(Duration::from_secs(10), "funding required", |e| {
        matches!(e, Event::FundingRequired { .. })
    });
    let Event::FundingRequired { channel_id: _, script, value_sat } = ev else { unreachable!() };
    let address = script_to_address(&script);
    let amount_btc = format!("{:.8}", value_sat as f64 / 100_000_000.0);

    // bitcoind wallet builds and signs the funding transaction.
    let raw = btc(&["createrawtransaction", "[]", &format!("{{\"{address}\":{amount_btc}}}")]);
    let funded = btc(&["fundrawtransaction", raw.as_str().unwrap()]);
    let signed = btc(&[
        "signrawtransactionwithwallet",
        funded["hex"].as_str().unwrap(),
    ]);
    let funding_tx =
        Transaction::deserialize(&hex::decode(signed["hex"].as_str().unwrap()).unwrap()).unwrap();
    let channel_id =
        d.node.provide_funding_transaction(temp, funding_tx.clone()).expect("funding bound");
    // Wait until our funding broadcast hits the mempool, then confirm it.
    let txid = funding_tx.txid().to_display_hex();
    wait_for(Duration::from_secs(10), "funding tx in mempool", || {
        d.pump_once();
        btc(&["getrawmempool"])
            .as_array()
            .map(|a| a.iter().any(|v| v.as_str() == Some(&txid)))
            .unwrap_or(false)
    });
    let tip = mine(6);
    d.node.best_block_updated(tip);

    // Locate the funding tx for the real short channel id.
    let txinfo = btc(&["getrawtransaction", &txid, "1"]);
    let blockhash = txinfo["blockhash"].as_str().unwrap();
    let block = btc(&["getblock", blockhash, "1"]);
    let height = block["height"].as_u64().unwrap() as u32;
    let tx_index = block["tx"]
        .as_array()
        .unwrap()
        .iter()
        .position(|t| t.as_str() == Some(&txid))
        .unwrap() as u32;
    let vout = funding_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == script)
        .unwrap() as u16;
    let scid = ShortChannelId::new(height, tx_index, vout);
    d.node.funding_confirmed(channel_id, scid).unwrap();

    let ev = d.wait_event(Duration::from_secs(30), "channel ready", |e| {
        matches!(e, Event::ChannelReady { .. })
    });
    eprintln!("✓ channel open with LND: {ev:?} scid={scid}");
    wait_for(Duration::from_secs(30), "LND lists channel active", || {
        d.pump_once();
        lncli_try(&["listchannels"])
            .and_then(|v| {
                v["channels"].as_array().map(|chans| {
                    chans
                        .iter()
                        .any(|c| c["active"].as_bool() == Some(true))
                })
            })
            .unwrap_or(false)
    });

    // ---- 3. keraunos pays an LND invoice --------------------------------
    let inv = lncli(&["addinvoice", "--amt", "90000", "--memo", "keraunos->lnd"]);
    let payreq = inv["payment_request"].as_str().unwrap();
    let parsed = Bolt11Invoice::parse(payreq).expect("we parse LND's invoice");
    d.node.tick(now_secs());
    d.node.pay_invoice(&parsed, None).expect("route to LND");
    let ev = d.wait_event(Duration::from_secs(20), "payment sent", |e| {
        matches!(e, Event::PaymentSent { .. })
    });
    eprintln!("✓ keraunos paid LND invoice: {ev:?}");
    let looked = lncli(&["lookupinvoice", inv["r_hash"].as_str().unwrap()]);
    assert_eq!(looked["state"].as_str(), Some("SETTLED"), "LND settled: {looked}");
    // The invoice settles before the HTLC-removal dance finishes; wait for
    // LND's spendable balance to reflect the payment before asking it to pay.
    wait_for(Duration::from_secs(20), "LND local balance settled", || {
        d.pump_once();
        d.node.tick(now_secs());
        lncli_try(&["listchannels"])
            .and_then(|v| {
                v["channels"][0]["local_balance"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .map(|bal| bal >= 90_000)
            .unwrap_or(false)
    });

    // ---- 4. LND pays a keraunos invoice ---------------------------------
    // LND's *link bandwidth* (used by its pathfinder) updates a beat after
    // its database balance; give the revocation dance time to finish.
    d.pump_for(Duration::from_secs(3));
    d.node.tick(now_secs());
    let (encoded, _hash) =
        d.node.create_invoice(Some(Msat(40_000_000)), "lnd->keraunos", 3600).unwrap();
    eprintln!("our invoice: {encoded}");
    // payinvoice blocks until resolution; run it in a thread while we pump.
    let pay_thread = std::thread::spawn({
        let encoded = encoded.clone();
        move || {
            let dir = std::env::temp_dir().join("keraunos-lnd-interop");
            Command::new(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("interop/bin/lncli"),
            )
            .args([
                &format!("--lnddir={}", dir.join("lnd").display()),
                "--network=regtest",
                &format!("--rpcserver=127.0.0.1:{LND_RPC}"),
                "payinvoice",
                "--force",
                &encoded,
            ])
            .output()
            .expect("lncli payinvoice")
        }
    });
    let ev = d.wait_event(Duration::from_secs(30), "payment claimed", |e| {
        matches!(e, Event::PaymentClaimed { amount_msat, .. } if *amount_msat == Msat(40_000_000))
    });
    eprintln!("✓ LND paid keraunos invoice: {ev:?}");
    let pay_out = pay_thread.join().unwrap();
    assert!(
        pay_out.status.success(),
        "lncli payinvoice: {}",
        String::from_utf8_lossy(&pay_out.stderr)
    );

    // ---- 5. cooperative close -------------------------------------------
    d.node.close_channel(channel_id).unwrap();
    let ev = d.wait_event(Duration::from_secs(30), "channel closed", |e| {
        matches!(e, Event::ChannelClosed { .. })
    });
    let Event::ChannelClosed { closing_txid: Some(close_txid), .. } = ev else {
        panic!("close must produce a txid")
    };
    d.pump_for(Duration::from_secs(1));
    mine(1);
    let confirmed = btc(&["getrawtransaction", &close_txid.to_display_hex(), "1"]);
    assert!(
        confirmed["blockhash"].as_str().is_some(),
        "negotiated closing tx confirmed on regtest"
    );
    eprintln!("✓ cooperative close confirmed: {close_txid}");
    let _ = knode_id;
}
