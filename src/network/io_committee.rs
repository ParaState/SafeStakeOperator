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
use tokio::sync::{Mutex, Notify};
use lazy_static::lazy_static;


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
    connections: Arc<RwLock<HashMap<u64, NetIOChannel>>>,
    notifications: Arc<RwLock<HashMap<u64, Arc<Notify>>>>,
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
        let connections: Arc<RwLock<HashMap<u64, NetIOChannel>>> = 
            Arc::new(RwLock::new(HashMap::default()));
        let connections_clone = connections.clone();

        let notifications: Arc<RwLock<HashMap<u64, Arc<Notify>>>> = 
        Arc::new(RwLock::new(HashMap::default()));
        let notifications_clone = notifications.clone();

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
                let channel = NetIOChannel::new(socket);
                let peer = bincode::deserialize::<u64>(&channel.recv().await[..]).unwrap();
                let mut connections = connections_clone.write().await;
                let mut notifications = notifications_clone.write().await;
                connections.insert(peer, channel);
                if let Some(notify) = notifications.get(&peer) {
                    notify.notify_one();
                }
                else {
                    let notify = Arc::new(Notify::new());
                    notify.notify_one();
                    notifications.insert(peer, notify);
                }
            }
            drop(listener);
        });

        Self {
            address,
            connections,
            notifications,
            thread_handle,
        }
    }

    /// Connect from `party` to a peer with `peer_address`.
    /// The `party` id is sent to the peer right after connection to identify itself.
    pub async fn connect(party: u64, peer_address: SocketAddr) -> Option<NetIOChannel> {
        match TcpStream::connect(peer_address).await {
            Ok(stream) => {
                let channel = NetIOChannel::new(stream);
                channel.send(Bytes::from(bincode::serialize(&party).unwrap())).await;
                Some(channel)
            },
            Err(e) => {
                warn!("Failed to connect to {}", peer_address);
                None
            }
        }
    }

    /// Accept connection from `peer`
    pub async fn accept(&mut self, peer: u64) -> Option<NetIOChannel> {
        let notify = {
            let mut notifications = self.notifications.write().await; 
            if let Some(notify) = notifications.get(&peer) {
                notify.clone()
            }
            else {
                let notify = Arc::new(Notify::new());
                notifications.insert(peer, notify.clone());
                notify
            }
        };

        notify.notified().await;
        let mut notifications = self.notifications.write().await;
        notifications.remove(&peer);

        self.connections.write().await.remove(&peer)
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
    /// Return a channel that is used to for transmitting message from `from` to `to`.
    fn channel(&self, from: u64, to: u64) -> &T;
    fn ids(&self) -> &[u64];
}

/// Simulate the communication among parties with memory channels.
/// Suitable to be used in test.
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
    party: u64,
    ids: Vec<u64>,
    channels: HashMap<u64, NetIOChannel>,
}

impl NetIOCommittee {
    /// Construct a network IO committee for `party` who is listening on `port`.
    /// The committee is identified by the id set `ids` and the address set `addresses`.
    pub async fn new(party: u64, port: u16, ids: &[u64], addresses: &[SocketAddr]) -> NetIOCommittee {
        let mut connection_manager = ConnectionManager::new(SocketAddr::new("0.0.0.0".parse().unwrap(), port));
        let mut channels: HashMap<u64, NetIOChannel> = Default::default();
        let n = ids.len();
        for i in 0..n {
            if ids[i] == party {
                continue;
            }
            let channel = {
                if ids[i] < party {
                    ConnectionManager::connect(party, addresses[i]).await.unwrap()
                }
                else {
                    connection_manager.accept(ids[i]).await.unwrap()
                }
            };
            channels.insert(ids[i], channel);
        }
        Self {
            party,
            ids: ids.to_vec(),
            channels,
        }
    }
}

impl IOCommittee<NetIOChannel> for NetIOCommittee {

    fn ids(&self) -> &[u64] {
        self.ids.as_slice()
    }

    fn channel(&self, from: u64, to: u64) -> &NetIOChannel {
        if from == to || (from != self.party && to != self.party) {
            panic!("Invalid channel");
        }
        if from == self.party {
            self.channels
                .get(&to)
                .unwrap()
        }
        else {
            self.channels
                .get(&from)
                .unwrap()
        }
    }
}