use tokio::sync::mpsc::{channel, Receiver, Sender};
use crate::DEFAULT_CHANNEL_CAPACITY;
use async_trait::async_trait;
use std::collections::HashMap;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{RwLock};
use futures::stream::{SplitSink, SplitStream};
use futures::stream::StreamExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use futures::SinkExt;
use std::net::{SocketAddr, IpAddr};
use log::{info, warn, error, debug};
use tokio::task::JoinHandle;

#[async_trait]
pub trait IOChannel {
    async fn send(&self, message: Bytes);
    async fn recv(&self) -> Bytes;
}

pub struct MemIOChannel {
    sender: Sender<Bytes>,
    receiver: Arc<RwLock<Receiver<Bytes>>>,
}

impl MemIOChannel {
    pub fn new(sender: Sender<Bytes>, receiver:Receiver<Bytes>) -> Self {
        Self {
            sender,
            receiver: Arc::new(RwLock::new(receiver)),
        }
    }
}

#[async_trait]
impl IOChannel for MemIOChannel {

    async fn send(&self, message: Bytes) {
        if let Err(e) = self.sender.send(message).await {
            panic!("Failed to send message. Error: {}", e);
        }
    }

    async fn recv(&self) -> Bytes {
        let mut receiver = self.receiver.write().await;
        if let Some(message) = receiver.recv().await {
            message
        }
        else {
            panic!("Failed to recv message.");
        }
    }
}

pub struct ConnectionManager {
    /// Address to listen to.
    address: SocketAddr,
    /// Struct responsible to define how to handle received messages.
    connections: Arc<RwLock<HashMap<IpAddr, TcpStream>>>,
    thread_handle: JoinHandle<()>,
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        info!("Shutting down connection manager");
        self.thread_handle.abort();
    }
}

impl ConnectionManager {
    pub fn new(address: SocketAddr) -> Self {
        let connections: Arc<RwLock<HashMap<IpAddr, TcpStream>>> = 
            Arc::new(RwLock::new(HashMap::default()));
        let connections_clone = connections.clone();
        let address_clone = address.clone();
        let thread_handle = tokio::spawn(async move {
            let listener = TcpListener::bind(&address_clone)
                .await
                .expect(format!("Failed to bind TCP address {}", address_clone).as_str());

            info!("Listening on {}. [DKG]", address_clone);
            loop {
                let (socket, peer) = match listener.accept().await {
                    Ok(value) => value,
                    Err(e) => {
                        warn!("Failed to accept connection: {}", e);
                        continue;
                    }
                };
                let mut connections = connections_clone.write().await;
                connections.insert(peer.ip(), socket);
            }
        });

        Self {
            address,
            connections,
            thread_handle,
        }
    }

    pub async fn acquire_connection(&mut self, ip: IpAddr) -> Option<TcpStream> {
        self.connections.write().await.remove(&ip)
    }
}

type Writer = SplitSink<Framed<TcpStream, LengthDelimitedCodec>, Bytes>;
type Reader = SplitStream<Framed<TcpStream, LengthDelimitedCodec>>;

pub struct NetIOChannel {
    writer: Arc<RwLock<Writer>>,
    reader: Arc<RwLock<Reader>>,
}

impl NetIOChannel {
    pub fn new(socket: TcpStream) -> Self {
        let transport = Framed::new(socket, LengthDelimitedCodec::new());
        let (writer, reader) = transport.split();
        Self {
            writer: Arc::new(RwLock::new(writer)),
            reader: Arc::new(RwLock::new(reader)),
        }
    }
}

#[async_trait]
impl IOChannel for NetIOChannel {

    async fn send(&self, message: Bytes) {
        let mut writer = self.writer.write().await;
        if let Err(e) = writer.send(message).await {
            panic!("Failed to send message. Error: {}", e);
        }
    }

    async fn recv(&self) -> Bytes {
        let mut reader = self.reader.write().await;
        if let Some(Ok(message)) = reader.next().await {
            message.freeze()
        }
        else {
            panic!("Failed to recv message.");
        }
    }
}

pub trait IOCommittee<T> {
    fn channel(&self, from: u64, to: u64) -> &T;
    fn ids(&self) -> &[u64];
}

pub struct MemIOCommittee {
    ids: Vec<u64>,
    channels: HashMap<u64, HashMap<u64, MemIOChannel>>,
}

impl MemIOCommittee {
    pub fn new(ids: &[u64]) -> MemIOCommittee {
        let mut channels: HashMap<u64, HashMap<u64, MemIOChannel>> = Default::default();
        let n = ids.len();
        for i in 0..n {
            channels.insert(ids[i], HashMap::default());
            for j in 0..n {
                let (sender, receiver) = channel(DEFAULT_CHANNEL_CAPACITY);
                channels.get_mut(&ids[i]).unwrap().insert(ids[j], MemIOChannel::new(sender, receiver));
            }
        }
        Self {
            ids: ids.to_vec(),
            channels,
        }
    }
}

impl IOCommittee<MemIOChannel> for MemIOCommittee {

    fn ids(&self) -> &[u64] {
        self.ids.as_slice()
    }

    fn channel(&self, from: u64, to: u64) -> &MemIOChannel {
        self.channels
            .get(&from)
            .unwrap()
            .get(&to)
            .unwrap()
    }
}

/// Network IO committee
pub struct NetIOCommittee {
    ids: Vec<u64>,
    channels: HashMap<u64, HashMap<u64, NetIOChannel>>,
}

impl NetIOCommittee {
    pub fn new(ids: &[u64], addresses: &[SocketAddr]) -> MemIOCommittee {
        let mut channels: HashMap<u64, HashMap<u64, NetIOChannel>> = Default::default();
        let n = ids.len();
        for i in 0..n {
            channels.insert(ids[i], HashMap::default());
            for j in 0..n {
                let (sender, receiver) = channel(DEFAULT_CHANNEL_CAPACITY);
                channels.get_mut(&ids[i]).unwrap().insert(ids[j], MemIOChannel::new(sender, receiver));
            }
        }
        Self {
            ids: ids.to_vec(),
            channels,
        }
    }
}

impl IOCommittee<MemIOChannel> for MemIOCommittee {

    fn ids(&self) -> &[u64] {
        self.ids.as_slice()
    }

    fn channel(&self, from: u64, to: u64) -> &MemIOChannel {
        self.channels
            .get(&from)
            .unwrap()
            .get(&to)
            .unwrap()
    }
}