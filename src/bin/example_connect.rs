use dvf::network::io_committee::ConnectionManager;
use env_logger::Env;
use log::info;

pub async fn func1() {
    let channel = ConnectionManager::connect(0, 0, "127.0.0.1:0".parse().unwrap()).await;
    info!("Channel established: {}", channel.is_some());
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
    let _ = runtime.spawn(async move {
        func1().await;
    });
    std::thread::sleep(std::time::Duration::from_millis(10000));
}
