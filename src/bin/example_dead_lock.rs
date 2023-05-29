use parking_lot::RwLock;
use std::sync::Arc;

pub async fn func1(v: Arc<RwLock<i64>>) {
    let mut x = v.write();
    println!("func1 has write lock");
    *x = 1;
    let _ = tokio::task::spawn_blocking(move || {
        std::thread::sleep(std::time::Duration::from_millis(10000));
        println!("Slept successfully");
    })
    .await;
    println!("func1 after spawn blocking");
}

pub async fn func2(v: Arc<RwLock<i64>>) {
    println!("func2 try to acquire read lock");
    let x = v.read();
    println!("func2 has read lock");
    println!("func2 x: {}", *x);
}

pub async fn func3(v: Arc<RwLock<i64>>) {
    println!("func3 try to acquire read lock");
    let x = v.read();
    println!("func3 has read lock");
    println!("func3 x: {}", *x);
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2) // This program will dead lock with #core threads = 2, but will be fine if > 2.
        .enable_all()
        .build()
        .unwrap();
    let v = Arc::new(RwLock::new(5 as i64));
    let v1 = v.clone();
    let _handle1 = runtime.spawn(async move {
        func1(v1).await;
    });
    std::thread::sleep(std::time::Duration::from_millis(1000));
    let v2 = v.clone();
    let _handle2 = runtime.spawn(async move {
        println!("before entering func2");
        func2(v2).await;
    });
    let v3 = v.clone();
    let _handle3 = runtime.spawn(async move {
        println!("before entering func3");
        func3(v3).await;
    });

    std::thread::sleep(std::time::Duration::from_millis(10000));
}

