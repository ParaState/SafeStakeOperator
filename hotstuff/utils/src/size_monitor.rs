use tokio::sync::mpsc::{channel, Sender, Receiver};
use tokio::sync::mpsc::error::SendError;
use tokio::time::{sleep, Duration};
use tokio::task::JoinHandle;
use tokio::sync::oneshot;
use tokio::sync::{RwLock};
use std::sync::{Arc};
use log::{info, debug};
use std::collections::HashMap;
use std::marker::Send;

pub struct SizeMonitor;

impl SizeMonitor {

    pub fn monitor_hashmap<K: Send + Sync + 'static, V: Send + Sync + 'static>(x: HashMap<K, V>, tag: String) -> Arc<RwLock<HashMap<K, V>>> {
        let y = Arc::new(RwLock::new(x));
        let y_copy = y.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(60_000)).await;
                info!("[{}] monitored size: {}", tag, y_copy.read().await.len());
            }
        });
        y
    }

}