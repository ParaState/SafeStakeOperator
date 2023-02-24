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
use std::net::{SocketAddr};
use log::{info, warn, debug};
use tokio::task::JoinHandle;
use tokio::sync::{Notify};
use tokio::time::{sleep, Duration};
use std::cmp::min;
use sha256::{digest_bytes};
use aes_gcm::{Aes128Gcm, Key, Nonce, Error};
use aes_gcm::aead::{Aead, NewAead};
use rand::Rng;
use crate::utils::blst_utils::{blst_sk_to_pk, 
    bytes_to_blst_p1, blst_p1_to_bytes, 
    blst_ecdh_shared_secret, blst_scalar_to_blst_sk,
    blst_p1_to_pk, blst_p1_mult, random_blst_scalar};
use blst::{blst_scalar, blst_p1, BLST_ERROR};
use blst::min_pk::{Signature};
use bls::{INFINITY_SIGNATURE};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";


pub trait PrivateChannel {
    fn encrypt_with_key(message: Bytes, key: Bytes) -> Bytes;
    fn encrypt(&self, message: Bytes) -> Bytes;
    fn decrypt_with_key(message: Bytes, key: Bytes) -> Bytes;
    fn decrypt(&self, message: Bytes) -> Bytes;
    fn shared_secret(&self) -> blst_p1;
    fn self_private_key(&self) -> blst_scalar;
    fn self_public_key(&self) -> blst_p1;
    fn partner_public_key(&self) -> blst_p1;
    fn sign(&self, message: Bytes) -> Signature;
    fn verify_partner(&self, message: Bytes, sig: Signature) -> bool;
}

#[async_trait]
pub trait IOChannel: Sync + Send  {
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
    _address: SocketAddr,
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
                let (socket, _peer) = match listener.accept().await {
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
        });

        Self {
            _address: address,
            connections,
            notifications,
            thread_handle,
        }
    }

    /// Connect from `party` to a peer with `peer_address`.
    /// The `party` id is sent to the peer right after connection to identify itself.
    pub async fn connect(party: u64, peer_address: SocketAddr) -> Option<NetIOChannel> {
        let mut delay = 200;
        let mut retry = 0;
        loop {
            match TcpStream::connect(peer_address).await {
                Ok(stream) => {
                    let channel = NetIOChannel::new(stream);
                    channel.send(Bytes::from(bincode::serialize(&party).unwrap())).await;
                    return Some(channel);
                },
                Err(_e) => {
                    warn!("connection-manager: Failed to connect to {}. Try({}).", peer_address, retry);
                    sleep(Duration::from_millis(delay)).await;

                    // Wait an increasing delay before attempting to reconnect.
                    delay = min(2*delay, 60_000);
                    retry +=1;
                }
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


#[async_trait]
pub trait IOCommittee<T>: Sync + Send {
    /// Return a channel that is used to for transmitting message from `from` to `to`.
    fn channel(&self, from: u64, to: u64) -> &T;
    fn ids(&self) -> &[u64];
    async fn broadcast(&self, message: Bytes);
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

#[async_trait]
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

    async fn broadcast(&self, message: Bytes) {

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
        debug!("{:?}", ids);
        debug!("{:?}", addresses);
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

    // pub async fn broadcast(&self, message: Bytes) {
    //     for i in 0..self.ids.len() {
    //         if self.ids[i] == self.party {
    //             continue;
    //         }
    //         let send_channel = self.channel(self.party, self.ids[i]);
    //         send_channel.send(message.clone()).await;
    //     }
    // }

    pub fn unwrap(self) -> (u64, Vec<u64>, HashMap<u64, NetIOChannel>) {
        (self.party, self.ids, self.channels)
    }
    
}

#[async_trait]
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

    async fn broadcast(&self, message: Bytes) {
        for i in 0..self.ids.len() {
            if self.ids[i] == self.party {
                continue;
            }
            let send_channel = self.channel(self.party, self.ids[i]);
            send_channel.send(message.clone()).await;
        }
    }
}


/// Secure network IO committee
pub struct SecureNetIOCommittee {
    party: u64,
    sk: blst_scalar,
    ids: Vec<u64>,
    channels: HashMap<u64, SecureNetIOChannel>,
}

impl SecureNetIOCommittee {
    /// Construct a secure network IO committee for `party` who is listening on `port`.
    /// The committee is identified by the id set `ids` and the address set `addresses`.
    /// The communication is also secured.
    pub async fn new(
        party: u64, 
        port: u16,
        ids: &[u64],
        addresses: &[SocketAddr]) -> SecureNetIOCommittee {
        let plain_committee = NetIOCommittee::new(party, port, ids, addresses).await;
        let sk = random_blst_scalar();
        let pk = blst_sk_to_pk(&sk);

        let pk_bytes = blst_p1_to_bytes(&pk);
        plain_committee.broadcast(pk_bytes).await;
        let (_, _, mut channels) = plain_committee.unwrap();
        let mut sec_channels : HashMap<u64, SecureNetIOChannel> = Default::default();
        
        for i in 0..ids.len() {
            if ids[i] == party {
                continue;
            }
            else {
                let recv_channel = channels.remove(&ids[i]).unwrap();
                let other_pk_bytes = recv_channel.recv().await;
                let other_pk = bytes_to_blst_p1(other_pk_bytes);
                let sec_channel = SecureNetIOChannel::new(recv_channel, sk.clone(), other_pk);
                sec_channels.insert(ids[i], sec_channel);
            }
        }
        Self {
            party,
            sk,
            ids: ids.to_vec(),
            channels: sec_channels,
        }
    }
}

pub struct SecureNetIOChannel {
    channel: NetIOChannel,
    sk: blst_scalar,
    other_pk: blst_p1,
}

impl SecureNetIOChannel {
    pub fn new(channel: NetIOChannel, sk: blst_scalar, other_pk: blst_p1) -> Self {
        Self {
            channel,
            sk,
            other_pk,
        }
    }
}

#[async_trait]
impl IOChannel for SecureNetIOChannel {

    async fn send(&self, message: Bytes) {
        let enc_msg = self.encrypt(message);
        self.channel.send(enc_msg).await;
    }

    async fn recv(&self) -> Bytes {
        let enc_msg = self.channel.recv().await;   
        self.decrypt(enc_msg)
    }
}

impl PrivateChannel for SecureNetIOChannel {
    fn encrypt_with_key(message: Bytes, key: Bytes) -> Bytes {
        let secret = hex::decode(digest_bytes(key.as_ref())).unwrap(); 

        let key = Key::from_slice(&secret.as_slice()[0..16]); 
        let cipher = Aes128Gcm::new(key);

        let mut nonce_bytes = vec![0u8; 12]; // 96-bit nonce
        rand::thread_rng().fill(&mut nonce_bytes[..]);
        let nonce = Nonce::from_slice(nonce_bytes.as_slice());

        let aes_ct = cipher.encrypt(nonce, message.as_ref()).expect("AES encryption failed!");
        let aes_ct = [nonce_bytes, aes_ct].concat();

        let enc_msg = Bytes::from(aes_ct);
        enc_msg
    }

    fn encrypt(&self, message: Bytes) -> Bytes {
        let point = self.shared_secret();
        let point_bytes = blst_p1_to_bytes(&point);
        Self::encrypt_with_key(message, point_bytes)
    }

    fn decrypt_with_key(enc_msg: Bytes, key: Bytes) -> Bytes {
        let secret = hex::decode(digest_bytes(key.as_ref())).unwrap(); 

        let key = Key::from_slice(&secret.as_slice()[0..16]); 
        let cipher = Aes128Gcm::new(key);

        let nonce_bytes = &enc_msg.as_ref()[0..12];
        let nonce = Nonce::from_slice(nonce_bytes);

        let aes_ct = &enc_msg.as_ref()[12..];
        let msg = cipher.decrypt(nonce, aes_ct).expect("AES decryption failed!");
        Bytes::from(msg)
    }

    fn decrypt(&self, enc_msg: Bytes) -> Bytes {
        let point = self.shared_secret();
        let point_bytes = blst_p1_to_bytes(&point);
        Self::decrypt_with_key(enc_msg, point_bytes)
    }

    fn shared_secret(&self) -> blst_p1 {
        blst_ecdh_shared_secret(&self.other_pk, &self.sk)
    }
    fn self_private_key(&self) -> blst_scalar {
        self.sk.clone()
    }
    fn self_public_key(&self) -> blst_p1 {
        blst_sk_to_pk(&self.sk)
    }
    fn partner_public_key(&self) -> blst_p1 {
        self.other_pk
    }
    fn sign(&self, message: Bytes) -> Signature {
        let sk = blst_scalar_to_blst_sk(&self.sk);
        sk.sign(message.as_ref(), DST, &[])
    }
    fn verify_partner(&self, message: Bytes, sig: Signature) -> bool {
        let pk = blst_p1_to_pk(&self.other_pk);
        sig.verify(true, message.as_ref(), DST, &[], &pk, false) == BLST_ERROR::BLST_SUCCESS
    }
}

#[async_trait]
impl IOCommittee<SecureNetIOChannel> for SecureNetIOCommittee {

    fn ids(&self) -> &[u64] {
        self.ids.as_slice()
    }

    fn channel(&self, from: u64, to: u64) -> &SecureNetIOChannel {
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

    async fn broadcast(&self, message: Bytes) {
        for i in 0..self.ids.len() {
            if self.ids[i] == self.party {
                continue;
            }
            let send_channel = self.channel(self.party, self.ids[i]);
            send_channel.send(message.clone()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::io_committee::{SecureNetIOCommittee};
    use futures::future::join_all;
    use crate::utils::blst_utils::{random_blst_scalar};

    const t: usize = 3;
    const ids: [u64; 4] = [1, 2, 3, 4];

    #[tokio::test(flavor = "multi_thread")]
    async fn test_secure_net_committee() {
        let ports: Vec<u16> = ids.iter().map(|id| (25000 + *id) as u16).collect();
        let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

        let ports_ref = &ports;
        let addrs_ref = &addrs;
        let futs = (0..ids.len()).map(|i| async move {
            let io = &Arc::new(SecureNetIOCommittee::new(ids[i], ports_ref[i], ids.as_slice(), addrs_ref.as_slice()).await);
            io.broadcast(Bytes::copy_from_slice(format!("hello from {}", ids[i]).as_bytes())).await;
            for j in 0..ids.len() {
                if i == j {
                    continue;
                }
                let recv_channel = io.channel(ids[j], ids[i]);
                let msg = recv_channel.recv().await;
                println!("Party {} receive: {}", ids[i], String::from_utf8(msg.to_vec()).unwrap());
            }
            println!("all messages received");
        });

        join_all(futs).await;
    }
}