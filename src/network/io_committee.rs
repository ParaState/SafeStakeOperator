use tokio::sync::mpsc::{channel, Receiver, Sender};
use crate::DEFAULT_CHANNEL_CAPACITY;
use async_trait::async_trait;
use std::collections::HashMap;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{RwLock};

#[async_trait]
pub trait IOChannel {
    async fn send(&mut self, message: Bytes);
    async fn recv(&mut self) -> Bytes;
}

pub struct MemIOChannel {
    sender: Sender<Bytes>,
    receiver: Receiver<Bytes>,
}

impl MemIOChannel {
    pub fn new(sender: Sender<Bytes>, receiver:Receiver<Bytes>) -> Self {
        Self {
            sender,
            receiver,
        }
    }
}

#[async_trait]
impl IOChannel for MemIOChannel {

    async fn send(&mut self, message: Bytes) {
        if let Err(e) = self.sender.send(message).await {
            panic!("Failed to send message. Error: {}", e);
        }
    }

    async fn recv(&mut self) -> Bytes {
        if let Some(message) = self.receiver.recv().await {
            message
        }
        else {
            panic!("Failed to recv message.");
        }
    }
}

pub trait IOCommittee<T> {
    fn channel(&self, from: u64, to: u64) -> Arc<RwLock<T>>;
    fn ids(&self) -> &[u64];
}

pub struct MemIOCommittee {
    ids: Vec<u64>,
    channels: HashMap<u64, HashMap<u64, Arc<RwLock<MemIOChannel>>>>,
}

impl MemIOCommittee {
    pub fn new(ids: &[u64]) -> MemIOCommittee {
        let mut channels: HashMap<u64, HashMap<u64, Arc<RwLock<MemIOChannel>>>> = Default::default();
        let n = ids.len();
        for i in 0..n {
            channels.insert(ids[i], HashMap::default());
            for j in 0..n {
                let (sender, receiver) = channel(DEFAULT_CHANNEL_CAPACITY);
                channels.get_mut(&ids[i]).unwrap().insert(ids[j], Arc::new(RwLock::new(MemIOChannel::new(sender, receiver))));
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

    fn channel(&self, from: u64, to: u64) -> Arc<RwLock<MemIOChannel>> {
        self.channels
            .get(&from)
            .unwrap()
            .get(&to)
            .unwrap()
            .clone()
    }
}