use env_logger::Env;
use log::info;
use serde_derive::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SomeDef {
    pub total: u64,
    pub operator_ids: Vec<u64>,
    pub base_socket_addresses: Vec<Option<SocketAddr>>,
}

pub fn func1() {
    let def = SomeDef {
        total: 5,
        operator_ids: vec![5, 4, 7],
        base_socket_addresses: vec![
            Some(SocketAddr::new("127.0.0.1".parse().unwrap(), 1251)),
            None,
            Some(SocketAddr::new("127.0.0.1".parse().unwrap(), 141)),
            None,
        ],
    };
    info!("{}", serde_yaml::to_string(&def).unwrap());
    let s = serde_yaml::to_string(&def).unwrap();
    let def: SomeDef = serde_yaml::from_str(s.as_str()).unwrap();
    info!("{:?}", def);
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
        func1();
    });
    std::thread::sleep(std::time::Duration::from_millis(60000));
}
