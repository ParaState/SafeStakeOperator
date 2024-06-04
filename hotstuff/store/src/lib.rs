use std::collections::{HashMap, VecDeque};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use rocksdb::{DB, Options, LogLevel};
use log::{info, warn, error};
use std::fmt::Display;
use std::error::Error;

#[cfg(test)]
#[path = "tests/store_tests.rs"]
pub mod store_tests;

// pub type StoreError = rocksdb::Error;
#[derive(Debug)]
pub enum StoreError {
    RocksdbError(rocksdb::Error),
    OtherError(String),
}
impl Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            self
        )
    }
}
impl Error for StoreError {}

type StoreResult<T> = Result<T, StoreError>;

type Key = Vec<u8>;
type Value = Vec<u8>;

pub enum StoreCommand {
    Write(Key, Value),
    Read(Key, oneshot::Sender<StoreResult<Option<Value>>>),
    NotifyRead(Key, oneshot::Sender<StoreResult<Value>>),
    NotifyDestroy(oneshot::Sender<bool>),
    Delete(Key),
    Exit(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct Store {
    channel: Sender<StoreCommand>,
}

impl Store {
    pub fn new(path: &str) -> StoreResult<Self> {
        // let db = rocksdb::DB::open_default(path)?;
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_log_file_time_to_roll(60);
        options.set_log_level(LogLevel::Error);
        options.set_keep_log_file_num(5);
        options.set_max_log_file_size(1024 * 1024 * 3);
        options.set_recycle_log_file_num(5);
        options.set_max_total_wal_size(1024 * 1024 * 5);
        options.set_wal_size_limit_mb(10);
        options.set_write_buffer_size(1024 * 1024 * 2);
        options.set_max_write_buffer_number(1);
        options.set_db_write_buffer_size(1024 * 1024 * 2);
        
        let db = rocksdb::DB::open(&options, path).map_err(StoreError::RocksdbError)?;
        let mut obligations = HashMap::<_, VecDeque<oneshot::Sender<_>>>::new();
        let (tx, mut rx) = channel(1_000);
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    StoreCommand::Write(key, value) => {
                        let _ = db.put(&key, &value);
                        if let Some(mut senders) = obligations.remove(&key) {
                            while let Some(s) = senders.pop_front() {
                                let _ = s.send(Ok(value.clone()));
                            }
                        }
                    }
                    StoreCommand::Read(key, sender) => {
                        let response = db.get(&key).map_err(|e| StoreError::RocksdbError(e));
                        let _ = sender.send(response);
                    }
                    StoreCommand::NotifyRead(key, sender) => {
                        let response = db.get(&key).map_err(|e| StoreError::RocksdbError(e));
                        match response {
                            Ok(None) => obligations
                                .entry(key)
                                .or_insert_with(VecDeque::new)
                                .push_back(sender),
                            _ => {
                                let _ = sender.send(response.map(|x| x.unwrap()));
                            }
                        }
                    }
                    StoreCommand::NotifyDestroy(sender) => {
                        let p = db.path().to_path_buf();
                        // drop(db);
                        let result = DB::destroy(&Options::default(), p); 
                        match result {
                             Ok(()) => {
                                info!("DB deleted success");
                                let _ = sender.send(true);
                             }
                             Err(e) => {
                                warn!("DB deleted failure: {}", e);
                                let _ = sender.send(false);
                             }
                        }
                        break;
                    }
                    StoreCommand::Delete(key) => {
                        let _ = db.delete(key);
                    }
                    StoreCommand::Exit(sender) => {
                        info!("Store receives exit signal");
                        let _ = sender.send(());
                        break;
                    }
                }
            }
            let p = db.path().to_path_buf();
            drop(db);
            info!("RocksDB is closed: {:?}", p);
        });
        Ok(Self { channel: tx })
    }

    pub async fn write(&self, key: Key, value: Value) {
        if let Err(e) = self.channel.send(StoreCommand::Write(key, value)).await {
            error!("Failed to send Write command to store: {}", e);
        }
    }

    pub async fn read(&self, key: Key) -> StoreResult<Option<Value>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::Read(key, sender)).await {
            error!("Failed to send Read command to store: {}", e);
        }
        receiver
            .await
            // .expect("Failed to receive reply to Read command from store")
            .unwrap_or(Err(StoreError::OtherError("Failed to receive reply to Read command from store".to_string())))
    }

    pub async fn delete(&self, key: Key) {
        if let Err(e) = self.channel.send(StoreCommand::Delete(key)).await {
            error!("Failed to send Delete command to store: {}", e);
        }
    }

    pub async fn notify_read(&self, key: Key) -> StoreResult<Value> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(StoreCommand::NotifyRead(key, sender))
            .await
        {
            error!("Failed to send NotifyRead command to store: {}", e);
        }
        receiver
            .await
            // .expect("Failed to receive reply to NotifyRead command from store")
            .unwrap_or(Err(StoreError::OtherError("Failed to receive reply to NotifyRead command from store".to_string())))
    }

    pub async fn notify_destroy(&self) {
        let (sender, _receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(StoreCommand::NotifyDestroy(sender))
            .await
        {
            error!("Failed to send NotifyDestroy command to store: {}", e);
        }
    }

    pub async fn exit(&self) {
        let (sender, _receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::Exit(sender)).await {
            error!("Failed to send Exit command to store: {}", e);
        }
    }
}
