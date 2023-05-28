use std::fs::remove_dir_all;
use store::Store;
use env_logger::Env;
use log::{info};

pub async fn func1() {
    let store = Store::new("/home/ubuntu/zico/dvf/data/store/").expect("Failed to create store");
    info!("store created");
    store.write(Vec::from("key1".as_bytes()), Vec::from("value1".as_bytes())).await;
    info!("key1 written");
    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
    store.write(Vec::from("key2".as_bytes()), Vec::from("value2".as_bytes())).await;
    info!("key2 written");
    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
    store.write(Vec::from("key3".as_bytes()), Vec::from("value3".as_bytes())).await;
    info!("key3 written");

    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
    store.exit().await;
    info!("store exit");

    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
    let _ = store.read(Vec::from("key3".as_bytes())).await;
    info!("key3 read");
    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
    let _ = store.read(Vec::from("key2".as_bytes())).await;
    info!("key2 read");
    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;
}

pub async fn func2() {
    info!("func2: enter func2");
    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
    remove_dir_all("/home/ubuntu/zico/dvf/data/store/").unwrap();
    info!("func2: dir removed");
    tokio::time::sleep(std::time::Duration::from_millis(20000)).await;
    let _store = Store::new("/home/ubuntu/zico/dvf/data/store/").expect("Failed to create store");
    info!("func2: create another store");
}


pub async fn func3() {
    info!("func3: enter func3");
    tokio::time::sleep(std::time::Duration::from_millis(40000)).await;
    let _store = Store::new("/home/ubuntu/zico/dvf/data/store/").expect("Failed to create store");
    info!("func3: create another store");
}

fn main() {
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10) 
        .enable_all()
        .build()
        .unwrap();
    let _handle1 = runtime.spawn(async move {
        func1().await;
    });
    std::thread::sleep(std::time::Duration::from_millis(1000));
    let _handle2 = runtime.spawn(async move {
        func2().await;
    });
    let _handle3 = runtime.spawn(async move {
        func3().await;
    });
    std::thread::sleep(std::time::Duration::from_millis(60000));
}

