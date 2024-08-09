// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::NetworkError;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::SplitSink;
use futures::stream::StreamExt as _;
use log::{info, warn, error, debug};
use std::error::Error;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use std::collections::HashMap;
use std::sync::{Arc};
use tokio::sync::{RwLock};
use crate::dvf_message::{DvfMessage, VERSION};
use futures::SinkExt;
use tokio::time::{sleep, Duration};

#[cfg(test)]
#[path = "tests/receiver_tests.rs"]
pub mod receiver_tests;

pub const INVALID_MESSAGE_DELAY: u64 = 10;

/// Convenient alias for the writer end of the TCP channel.
pub type Writer = SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>;
#[async_trait]
pub trait MessageHandler: Clone + Send + Sync + 'static {
    /// Defines how to handle an incoming message. A typical usage is to define a `MessageHandler` with a
    /// number of `Sender<T>` channels. Then implement `dispatch` to deserialize incoming messages and
    /// forward them through the appropriate delivery channel. Then `writer` can be used to send back
    /// responses or acknowledgements to the sender machine (see unit tests for examples).
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>>;
}

/// For each incoming request, we spawn a new runner responsible to receive messages and forward them
/// through the provided deliver channel.
pub struct Receiver<Handler: MessageHandler> {
    /// Address to listen to.
    address: SocketAddr,
    /// Struct responsible to define how to handle received messages.
    handler_map: Arc<RwLock<HashMap<u64, Handler>>>,
    name: &'static str,
}

impl<Handler: MessageHandler> Receiver<Handler> {
    /// Spawn a new network receiver handling connections from any incoming peer.
    pub fn spawn(address: SocketAddr, handler_map: Arc<RwLock<HashMap<u64, Handler>>>, name: &'static str) {
        tokio::spawn(async move {
            Self { address, handler_map, name}.run().await;
        });
    }

    /// Main loop responsible to accept incoming connections and spawn a new runner to handle it.
    async fn run(&self) {
        let listener = TcpListener::bind(&self.address)
            .await
            .expect(format!("Failed to bind TCP address {}", self.address).as_str());

        info!("Listening on {}. [{:?}]", self.address, self.name);
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(e) => {
                    warn!("{}", NetworkError::FailedToListen(e));
                    continue;
                }
            };
            debug!("Incoming connection established with {}. Local: {}. [{:?}]", peer, self.address, self.name);
            self.spawn_runner(socket, peer).await;
        }
    }

    async fn spawn_runner(&self, socket: TcpStream, peer: SocketAddr) {
        let handler_map = self.handler_map.clone(); 
        let name = self.name;

        tokio::spawn(async move {
            // let mut handler_opt: Option<Handler> = None;
            let transport = Framed::new(socket, LengthDelimitedCodec::new());
            let (mut writer, mut reader) = transport.split();
            while let Some(frame) = reader.next().await {
                match frame.map_err(|e| NetworkError::FailedToReceiveMessage(peer, e)) {
                    Ok(message) => {
                        // get validator
                        match bincode::deserialize::<DvfMessage>(&message[..]) {
                            Ok(dvf_message) => {
                                let validator_id = dvf_message.validator_id;
                                let version = dvf_message.version;
                                if version != VERSION {
                                    let _ = writer.send(Bytes::from("Version mismatch")).await;
                                    error!("[VA {}] Version mismatch: got ({}), expected ({})", validator_id, version, VERSION);
                                    sleep(Duration::from_secs(INVALID_MESSAGE_DELAY)).await;
                                    // [zico] Should we kill the connection here? 
                                    // If we kill it, then a reliable sender can resend the message because the ACK is not normal, but it may cause the 
                                    // sender to frequently retry the connection and resend the message when the VA is not ready, making the program to
                                    // print a lot of error logs.

                                    return;  // Kill the connection
                                    // continue;  // Keep the connection
                                }
                                
                                // Always acquire the handler from the handler_map. Don't keep the handler alive
                                // because we might delete it from the handler_map at any time.
                                let handler_opt = {
                                    handler_map.read().await.get(&validator_id).cloned()
                                };
                                match handler_opt.as_ref() {
                                    Some(handler) => {
                                        // trunctate the prefix
                                        let msg = dvf_message.message;
                                        if let Err(e) = handler.dispatch(&mut writer, Bytes::from(msg)).await {
                                            error!("[VA {}] Handler dispatch error ({})", validator_id, e);
                                            return;
                                        }
                                    },
                                    None => {
                                        // [zico] Constantly review this. For now, we sent back a message, which is different from a normal 'Ack' message
                                        let _ = writer.send(Bytes::from("No handler found")).await;
                                        warn!("[VA {}] Receive a message, but no handler found! [{:?}]", validator_id, name);
                                        sleep(Duration::from_secs(INVALID_MESSAGE_DELAY)).await;
                                        // [zico] Should we kill the connection here? 
                                        // If we kill it, then a reliable sender can resend the message because the ACK is not normal, but it may cause the 
                                        // sender to frequently retry the connection and resend the message when the VA is not ready, making the program to
                                        // print a lot of error logs.

                                        return;  // Kill the connection
                                    }
                                }
                            },
                            Err(e) => {
                                let _ = writer.send(Bytes::from("Invalid message")).await;
                                warn!("can't deserialize {}", e);
                                sleep(Duration::from_secs(INVALID_MESSAGE_DELAY)).await;
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                        return;
                    }
                }
            }
            debug!("Connection closed by peer {}", peer);
        });
    }
}
