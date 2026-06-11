//! Per-peer connection state: BOLT 8 handshake progression, message
//! framing, and the init exchange.

use crate::noise::{Initiator, NoiseError, Responder, Transport, ACT_ONE_LEN, ACT_THREE_LEN, ACT_TWO_LEN};
use crate::wire::Features;
use secp256k1::PublicKey;

/// Bytes to write back to the socket plus decrypted complete messages.
pub(crate) type PeerInput = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Opaque connection token chosen by the node; one per TCP-level
/// connection, before and after the peer's identity is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u64);

pub(crate) enum PeerTransport {
    OutboundHandshake(Box<Initiator>),
    InboundHandshake(Box<Responder>),
    Ready(Box<Transport>),
    /// Transitional placeholder during state changes.
    Poisoned,
}

pub(crate) struct Peer {
    pub transport: PeerTransport,
    /// Raw bytes accumulated while still in handshake.
    pub handshake_buf: Vec<u8>,
    pub node_id: Option<PublicKey>,
    pub init_sent: bool,
    pub init_received: bool,
    pub features: Features,
    /// Outbound connections know the identity up front.
    #[allow(dead_code)]
    pub expected_node_id: Option<PublicKey>,
    pub last_ping_sent_at: u64,
    pub awaiting_pong: bool,
}

impl Peer {
    pub fn new_outbound(initiator: Initiator, remote: PublicKey) -> Peer {
        Peer {
            transport: PeerTransport::OutboundHandshake(Box::new(initiator)),
            handshake_buf: Vec::new(),
            node_id: Some(remote),
            init_sent: false,
            init_received: false,
            features: Features::empty(),
            expected_node_id: Some(remote),
            last_ping_sent_at: 0,
            awaiting_pong: false,
        }
    }

    pub fn new_inbound(responder: Responder) -> Peer {
        Peer {
            transport: PeerTransport::InboundHandshake(Box::new(responder)),
            handshake_buf: Vec::new(),
            node_id: None,
            init_sent: false,
            init_received: false,
            features: Features::empty(),
            expected_node_id: None,
            last_ping_sent_at: 0,
            awaiting_pong: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.transport, PeerTransport::Ready(_)) && self.init_sent && self.init_received
    }

    /// Feed raw socket bytes. Returns (bytes to write back, decrypted
    /// messages). Handshake transitions happen inside.
    pub fn input(
        &mut self,
        data: &[u8],
    ) -> Result<PeerInput, NoiseError> {
        let mut to_send = Vec::new();
        let mut messages = Vec::new();
        let mut data = data;

        // Drive the handshake with fixed-size acts.
        loop {
            match &mut self.transport {
                PeerTransport::OutboundHandshake(_) => {
                    self.handshake_buf.extend_from_slice(data);
                    data = &[];
                    if self.handshake_buf.len() < ACT_TWO_LEN {
                        return Ok((to_send, messages));
                    }
                    let act2: [u8; ACT_TWO_LEN] =
                        self.handshake_buf[..ACT_TWO_LEN].try_into().expect("len checked");
                    let rest = self.handshake_buf.split_off(ACT_TWO_LEN);
                    self.handshake_buf.clear();
                    let PeerTransport::OutboundHandshake(mut init) =
                        std::mem::replace(&mut self.transport, PeerTransport::Poisoned)
                    else {
                        unreachable!()
                    };
                    let act3 = init.act_two(&act2)?;
                    to_send.push(act3.to_vec());
                    let mut transport = init.into_transport()?;
                    transport.read_input(&rest);
                    self.transport = PeerTransport::Ready(Box::new(transport));
                }
                PeerTransport::InboundHandshake(_) => {
                    self.handshake_buf.extend_from_slice(data);
                    data = &[];
                    // Act 1 then act 3.
                    if !self.handshake_acted_one() {
                        if self.handshake_buf.len() < ACT_ONE_LEN {
                            return Ok((to_send, messages));
                        }
                        let act1: [u8; ACT_ONE_LEN] =
                            self.handshake_buf[..ACT_ONE_LEN].try_into().expect("len checked");
                        self.handshake_buf.drain(..ACT_ONE_LEN);
                        let PeerTransport::InboundHandshake(mut resp) =
                            std::mem::replace(&mut self.transport, PeerTransport::Poisoned)
                        else {
                            unreachable!()
                        };
                        let act2 = resp.act_one(&act1)?;
                        to_send.push(act2.to_vec());
                        self.transport = PeerTransport::InboundHandshake(resp);
                    }
                    if self.handshake_buf.len() < ACT_THREE_LEN {
                        return Ok((to_send, messages));
                    }
                    let act3: [u8; ACT_THREE_LEN] =
                        self.handshake_buf[..ACT_THREE_LEN].try_into().expect("len checked");
                    let rest = self.handshake_buf.split_off(ACT_THREE_LEN);
                    self.handshake_buf.clear();
                    let PeerTransport::InboundHandshake(resp) =
                        std::mem::replace(&mut self.transport, PeerTransport::Poisoned)
                    else {
                        unreachable!()
                    };
                    let (remote_id, mut transport) = resp.act_three(&act3)?;
                    self.node_id = Some(remote_id);
                    transport.read_input(&rest);
                    self.transport = PeerTransport::Ready(Box::new(transport));
                }
                PeerTransport::Ready(transport) => {
                    transport.read_input(data);
                    while let Some(msg) = transport.next_message()? {
                        messages.push(msg);
                    }
                    return Ok((to_send, messages));
                }
                PeerTransport::Poisoned => unreachable!("poisoned peer transport"),
            }
        }
    }

    fn handshake_acted_one(&self) -> bool {
        match &self.transport {
            PeerTransport::InboundHandshake(r) => r.acted_one(),
            _ => true,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &mut self.transport {
            PeerTransport::Ready(t) => t.encrypt_message(plaintext),
            _ => Err(NoiseError::WrongState),
        }
    }
}
