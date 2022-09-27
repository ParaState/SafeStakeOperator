// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::NetworkError;
use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{info, warn, debug};
use rand::prelude::SliceRandom as _;
use rand::rngs::SmallRng;
use rand::SeedableRng as _;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{oneshot, RwLock};
use tokio::time::{sleep, Duration};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use std::sync::Arc;
use crate::CHANNEL_CAPACITY;
use utils::monitored_channel::{MonitoredChannel, MonitoredSender};

#[cfg(test)]
#[path = "tests/reliable_sender_tests.rs"]
pub mod reliable_sender_tests;

/// Convenient alias for cancel handlers returned to the caller task.
pub type CancelHandler = oneshot::Receiver<Bytes>;

/// We keep alive one TCP connection per peer, each connection is handled by a separate task (called `Connection`).
/// We communicate with our 'connections' through a dedicated channel kept by the HashMap called `connections`.
/// This sender is 'reliable' in the sense that it keeps trying to re-transmit messages for which it didn't
/// receive an ACK back (until they succeed or are canceled).
/// [zico] Update: We have modified it to be non-fully reliable. If the ReliableSender instance is dropped, then everything 
/// will be destroyed and any message in the buffer will be ignored. So, don't wait for the CancelHanler to receive an ACK
/// if you have already dropped the ReliableSender instance.
pub struct ReliableSender {
    /// A map holding the channels to our connections.
    connections: Arc<RwLock<HashMap<SocketAddr, MonitoredSender<InnerMessage>>>>,
    /// Small RNG just used to shuffle nodes and randomize connections (not crypto related).
    rng: SmallRng,

    signal: Option<exit_future::Signal>,
    exit: exit_future::Exit,
}

impl std::default::Default for ReliableSender {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ReliableSender {
    fn drop(&mut self) {
        if let Some(signal) = self.signal.take() {
            let _ = signal.fire();
        } 
    }
}

impl ReliableSender {
    pub fn new() -> Self {
        let (signal, exit) = exit_future::signal();
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            rng: SmallRng::from_entropy(),
            signal: Some(signal),
            exit,
        }
    }

    /// Helper function to spawn a new connection.
    fn spawn_connection(&self, address: SocketAddr) -> MonitoredSender<InnerMessage> {
        debug!("[Reliable] Openning a new connection to {}", address);
        let (tx, rx) = MonitoredChannel::new(CHANNEL_CAPACITY, format!("reliable-{}", address), "info");
        Connection::spawn(address, rx, self.exit.clone());
        tx
    }

    /// Reliably send a message to a specific address.
    pub async fn send(&self, address: SocketAddr, data: Bytes) -> CancelHandler {
        let (sender, receiver) = oneshot::channel();
        self.connections
            .write()
            .await
            .entry(address)
            .or_insert_with(|| self.spawn_connection(address))
            .send(InnerMessage {
                data,
                cancel_handler: sender,
            })
            .await
            .expect("Failed to send internal message");
        receiver
    }

    /// Broadcast the message to all specified addresses in a reliable manner. It returns a vector of
    /// cancel handlers ordered as the input `addresses` vector.
    pub async fn broadcast(
        &mut self,
        addresses: Vec<SocketAddr>,
        data: Bytes,
    ) -> Vec<CancelHandler> {
        let mut handlers = Vec::new();
        for address in addresses {
            let handler = self.send(address, data.clone()).await;
            handlers.push(handler);
        }
        handlers
    }

    /// Pick a few addresses at random (specified by `nodes`) and send the message only to them.
    /// It returns a vector of cancel handlers with no specific order.
    pub async fn lucky_broadcast(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
    ) -> Vec<CancelHandler> {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast(addresses, data).await
    }
}

/// Simple message used by `ReliableSender` to communicate with its connections.
#[derive(Debug)]
struct InnerMessage {
    /// The data to transmit.
    data: Bytes,
    /// The cancel handler allowing the caller task to cancel the transmission of this message
    /// and to be notified of its successfully transmission.
    cancel_handler: oneshot::Sender<Bytes>,
}

/// A connection is responsible to reliably establish (and keep alive) a connection with a single peer.
struct Connection {
    /// The destination address.
    address: SocketAddr,
    /// Channel from which the connection receives its commands.
    receiver: Receiver<InnerMessage>,
    /// The initial delay to wait before re-attempting a connection (in ms).
    retry_delay: u64,
    /// Buffer keeping all messages that need to be re-transmitted.
    buffer: VecDeque<(Bytes, oneshot::Sender<Bytes>)>,

    exit: exit_future::Exit,
}

impl Connection {
    fn spawn(address: SocketAddr, receiver: Receiver<InnerMessage>, exit: exit_future::Exit) {
        tokio::spawn(async move {
            Self {
                address,
                receiver,
                retry_delay: 200,
                buffer: VecDeque::new(),
                exit,
            }
            .run()
            .await;
        });
    }

    /// Main loop trying to connect to the peer and transmit messages.
    async fn run(&mut self) {
        let mut delay = self.retry_delay;
        let mut retry = 0;
        loop {
            match TcpStream::connect(self.address).await {
                Ok(stream) => {
                    debug!("Outgoing connection established with {}", self.address);

                    // Reset the delay.
                    delay = self.retry_delay;
                    retry = 0;

                    // Try to transmit all messages in the buffer and keep transmitting incoming messages.
                    // The following function only returns if there is an error.
                    let error = self.keep_alive(stream).await;
                    warn!("{}", error);
                    match error {
                        NetworkError::TokioChannelClosed => {
                            return;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    warn!("{}", NetworkError::FailedToConnect(self.address, retry, e));
                    let timer = sleep(Duration::from_millis(delay));
                    tokio::pin!(timer);

                    'waiter: loop {
                        let exit = self.exit.clone();
                        tokio::select! {
                            // Wait an increasing delay before attempting to reconnect.
                            () = &mut timer => {
                                delay = min(2*delay, 60_000);
                                retry +=1;
                                // There is no need to retry connecting after a long time in our scenario.
                                // Messages that have are in buffer will simply be dropped and never get a reply.
                                if retry > 10 {
                                    return;
                                } 
                                break 'waiter;
                            },

                            // Drain the channel into the buffer to not saturate the channel and block the caller task.
                            // The caller is responsible to cleanup the buffer through the cancel handlers.
                            message = self.receiver.recv() => {
                                match message {
                                    Some(InnerMessage{data, cancel_handler}) => {
                                        self.buffer.push_back((data, cancel_handler));
                                        self.buffer.retain(|(_, handler)| !handler.is_closed());
                                    }
                                    None => {
                                        // Channel has been closed. This only happens when the reliable sender is dropped.
                                        // Therefore, no one cares about the replies any more, just return.
                                        return;
                                    }
                                }
                            }

                            () = exit => {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Transmit messages once we have established a connection.
    async fn keep_alive(&mut self, stream: TcpStream) -> NetworkError {
        // This buffer keeps all messages and handlers that we have successfully transmitted but for
        // which we are still waiting to receive an ACK.
        let mut pending_replies = VecDeque::new();

        let (mut writer, mut reader) = Framed::new(stream, LengthDelimitedCodec::new()).split();
        let error = 'connection: loop {
            let exit = self.exit.clone();
            // Try to send all messages of the buffer.
            while let Some((data, handler)) = self.buffer.pop_front() {
                // Skip messages that have been cancelled.
                if handler.is_closed() {
                    continue;
                }

                // Try to send the message.
                match writer.send(data.clone()).await {
                    Ok(()) => {
                        // The message has been sent, we remove it from the buffer and add it to
                        // `pending_replies` while we wait for an ACK.
                        pending_replies.push_back((data, handler));
                    }
                    Err(e) => {
                        // We failed to send the message, we put it back into the buffer.
                        self.buffer.push_front((data, handler));
                        break 'connection NetworkError::FailedToSendMessage(self.address, e);
                    }
                }
            }

            // Check if there are any new messages to send or if we get an ACK for messages we already sent.
            tokio::select! {
                message = self.receiver.recv() => {
                    match message {
                        Some(InnerMessage{data, cancel_handler}) => {
                            self.buffer.push_back((data, cancel_handler));
                        }
                        None => {
                            // Channel has been closed. This only happens when the reliable sender is dropped.
                            // Therefore, no one cares about the replies any more, just return.
                            break 'connection NetworkError::TokioChannelClosed;
                        }
                    }
                }
                
                response = reader.next() => {
                    let (data, handler) = match pending_replies.pop_front() {
                        Some(message) => message,
                        None => break 'connection NetworkError::UnexpectedAck(self.address)
                    };
                    match response {
                        Some(Ok(bytes)) => {
                            // Notify the handler that the message has been successfully sent.
                            let _ = handler.send(bytes.freeze());
                        },
                        _ => {
                            // Something has gone wrong (either the channel dropped or we failed to read from it).
                            // Put the message back in the buffer, we will try to send it again.
                            pending_replies.push_front((data, handler));
                            break 'connection NetworkError::FailedToReceiveAck(self.address);
                        }
                    }
                },
                () = exit => {
                    break 'connection NetworkError::TokioChannelClosed;
                }
            }
        };

        // If we reach this code, it means something went wrong. Put the messages for which we didn't receive an ACK
        // back into the sending buffer, we will try to send them again once we manage to establish a new connection.
        while let Some(message) = pending_replies.pop_back() {
            self.buffer.push_front(message);
        }
        error
    }
}
