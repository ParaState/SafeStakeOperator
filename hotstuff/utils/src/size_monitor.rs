use tokio::time::{sleep, Duration};
use tokio::sync::{RwLock};
use std::sync::{Arc};
use log::{info, debug};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::marker::Send;

pub struct SizeMonitor;

impl SizeMonitor {

    pub fn monitor_hashmap<K: Send + Sync + 'static, V: Send + Sync + 'static>(x: HashMap<K, V>, tag: String, level: String) -> Arc<RwLock<HashMap<K, V>>> {
        let y = Arc::new(RwLock::new(x));
        let y_copy = y.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(60_000)).await;
                if level == "debug" {
                    debug!("[{}] monitored hashmap size: {}", tag, y_copy.read().await.len());
                }
                else {
                    info!("[{}] monitored hashmap size: {}", tag, y_copy.read().await.len());
                }
            }
        });
        y
    }

    pub fn monitor_vecdeque<T: Send + Sync + 'static>(x: VecDeque<T>, tag: String, level: String) -> Arc<RwLock<VecDeque<T>>> {
        let y = Arc::new(RwLock::new(x));
        let y_copy = y.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(60_000)).await;
                if level == "debug" {
                    debug!("[{}] monitored vecdeque size: {}", tag, y_copy.read().await.len());
                }
                else {
                    info!("[{}] monitored vecdeque size: {}", tag, y_copy.read().await.len());
                }
            }
        });
        y
    }

}