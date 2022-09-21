// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::NetworkError;
use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{info, warn, debug};
use rand::prelude::SliceRandom as _;
use rand::rngs::SmallRng;
use rand::SeedableRng as _;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::CHANNEL_CAPACITY;

#[cfg(test)]
#[path = "tests/simple_sender_tests.rs"]
pub mod simple_sender_tests;

#[derive(Debug, Clone)]
pub enum Command {
    Send(Bytes),
    Feed(Bytes),
    Flush
}

/// We keep alive one TCP connection per peer, each connection is handled by a separate task (called `Connection`).
/// We communicate with our 'connections' through a dedicated channel kept by the HashMap called `connections`.
pub struct SimpleSender {
    /// A map holding the channels to our connections.
    connections: Arc<RwLock<HashMap<SocketAddr, Sender<Command>>>>,
    /// Small RNG just used to shuffle nodes and randomize connections (not crypto related).
    rng: SmallRng,
}

impl std::default::Default for SimpleSender {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleSender {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            rng: SmallRng::from_entropy(),
        }
    }

    /// Helper function to spawn a new connection.
    fn spawn_connection(address: SocketAddr) -> Sender<Command> {
        let (tx, rx) = channel(CHANNEL_CAPACITY);
        Connection::spawn(address, rx);
        tx
    }

    pub async fn execute(&self, address: SocketAddr, cmd: Command) {
        // Try to re-use an existing connection if possible.
        if let Some(tx) = self.connections.read().await.get(&address) {
            if tx.send(cmd.clone()).await.is_ok() {
                return;
            }
        }

        debug!("[Simple] Openning a new connection to {}", address);
        // Otherwise make a new connection.
        let tx = Self::spawn_connection(address);
        if tx.send(cmd).await.is_ok() {
            self.connections.write().await.insert(address, tx);
        }
    }

    /// Try (best-effort) to send a message to a specific address.
    /// This is useful to answer sync requests.
    pub async fn send(&self, address: SocketAddr, data: Bytes) {
        // // Try to re-use an existing connection if possible.
        // if let Some(tx) = self.connections.read().await.get(&address) {
        //     if tx.send(Command::Send(data.clone())).await.is_ok() {
        //         return;
        //     }
        // }

        // info!("[Simple] Openning a new connection to {}", address);
        // // Otherwise make a new connection.
        // let tx = Self::spawn_connection(address);
        // if tx.send(Command::Send(data)).await.is_ok() {
        //     self.connections.write().await.insert(address, tx);
        // }
        self.execute(address, Command::Send(data)).await
    }

    pub async fn feed(&self, address: SocketAddr, data: Bytes) {
        self.execute(address, Command::Feed(data)).await
    }

    pub async fn flush(&self, address: SocketAddr) {
        self.execute(address, Command::Flush).await
    }

    /// Try (best-effort) to broadcast the message to all specified addresses.
    pub async fn broadcast(&mut self, addresses: Vec<SocketAddr>, data: Bytes) {
        for address in addresses {
            self.send(address, data.clone()).await;
        }
    }

    /// Try (best-effort) to broadcast the message to all specified addresses.
    pub async fn broadcast_feed(&mut self, addresses: Vec<SocketAddr>, data: Bytes) {
        for address in addresses {
            self.feed(address, data.clone()).await;
        }
    }

    /// Try (best-effort) to broadcast the message to all specified addresses.
    pub async fn broadcast_flush(&mut self, addresses: Vec<SocketAddr>) {
        for address in addresses {
            self.flush(address).await;
        }
    }

    /// Pick a few addresses at random (specified by `nodes`) and try (best-effort) to send the
    /// message only to them. This is useful to pick nodes with whom to sync.
    pub async fn lucky_broadcast(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
    ) {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast(addresses, data).await
    }

    /// Pick a few addresses at random (specified by `nodes`) and try (best-effort) to send the
    /// message only to them. This is useful to pick nodes with whom to sync.
    pub async fn lucky_broadcast_feed(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
    ) {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast_feed(addresses, data).await
    }
}

/// A connection is responsible to establish and keep alive (if possible) a connection with a single peer.
struct Connection {
    /// The destination address.
    address: SocketAddr,
    /// Channel from which the connection receives its commands.
    receiver: Receiver<Command>,
}

impl Connection {
    fn spawn(address: SocketAddr, receiver: Receiver<Command>) {
        tokio::spawn(async move {
            Self { address, receiver }.run().await;
        });
    }

    /// Main loop trying to connect to the peer and transmit messages.
    async fn run(&mut self) {
        // Try to connect to the peer.
        let (mut writer, mut reader) = match TcpStream::connect(self.address).await {
            Ok(stream) => Framed::new(stream, LengthDelimitedCodec::new()).split(),
            Err(e) => {
                warn!(
                    "{}",
                    NetworkError::FailedToConnect(self.address, /* retry */ 0, e)
                );
                return;
            }
        };
        debug!("Outgoing connection established with {}", self.address);

        // Transmit messages once we have established a connection.
        loop {
            // Check if there are any new messages to send or if we get an ACK for messages we already sent.
            tokio::select! {
                Some(data) = self.receiver.recv() => {
                    match data {
                        Command::Send(x) => {
                            if let Err(e) = writer.send(x).await {
                                warn!("{}", NetworkError::FailedToSendMessage(self.address, e));
                                return;
                            }
                        }
                        Command::Feed(x) => {
                            if let Err(e) = writer.feed(x).await {
                                warn!("{}", NetworkError::FailedToSendMessage(self.address, e));
                                return;
                            }
                        }
                        Command::Flush => {
                            if let Err(e) = writer.flush().await {
                                warn!("{}", NetworkError::FailedToSendMessage(self.address, e));
                                return;
                            }
                        }
                    }
                    
                },
                response = reader.next() => {
                    match response {
                        Some(Ok(_)) => {
                            // Sink the reply.
                        },
                        _ => {
                            // Something has gone wrong (either the channel dropped or we failed to read from it).
                            warn!("{}", NetworkError::FailedToReceiveAck(self.address));
                            return;
                        }
                    }
                },
            }
        }
    }
}
