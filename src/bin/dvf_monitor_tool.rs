use network::{DvfMessage, ReliableSender};
use dvf_version::VERSION;
use std::fs::File;
use dvf::node::config::{BOOT_ENRS_CONFIG_FILE, base_to_signature_addr, base_to_duties_addr, base_to_active_addr};
use lighthouse_network::discv5::enr::{Enr, CombinedKey};
use std::net::{IpAddr, SocketAddr};
use bytes::Bytes;
use log::{error, info};
use std::net::TcpStream;

fn all_equal<T: PartialEq>(array: &[T]) -> bool {
    if let Some(first) = array.first() {
        array.iter().all(|x| x == first)
    } else {
        true
    }
}

async fn query_socket_address_from_boot(enrs: Vec<Enr<CombinedKey>>, op_pk: Vec<u8>) -> Vec<SocketAddr> {
    // query socket address of the operator
    let dvf_message = DvfMessage {
        version: VERSION,
        validator_id: 0,
        message: op_pk.clone(),
    };
    let serialized_msg = bincode::serialize(&dvf_message).unwrap();
    let boot_socketaddrs: Vec<SocketAddr> = enrs.iter().map(|e| {
        SocketAddr::new(
            IpAddr::V4(e.ip4().expect("boot enr ip should not be empty")),
            e.udp4().expect("boot enr port should not be empty"))
    }).collect();
    let network_sender = ReliableSender::new();
    let mut result = Vec::new();
    for addr in boot_socketaddrs {
        match network_sender
                .send(addr, Bytes::from(serialized_msg.clone()))
                .await.await {
            Ok(data) => {
                let op_base_socketaddr = bincode::deserialize::<SocketAddr>(&data).unwrap();
                result.push(op_base_socketaddr);
            },
            Err(e) => {
                error!("failed to query op socket addr from boot {}", e)
            }
        } 
    }
    result
}

fn check_all_ports(base_addr: SocketAddr) -> bool {
    TcpStream::connect(base_to_signature_addr(base_addr)).is_ok() && 
    TcpStream::connect(base_to_duties_addr(base_addr)).is_ok() &&
    TcpStream::connect(base_to_active_addr(base_addr)).is_ok() 
}

#[tokio::main]
async fn main() {
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();
    log::info!("------dvf_monitor_tool------");

    let op_pk_str = std::env::args()
        .nth(1)
        .expect("ERROR: there is no valid operator public key argument");

    let op_pk = hex::decode(&op_pk_str[2..]).expect("decode failed, op pk should be in hex format");

    let file = File::options()
            .read(true)
            .write(false)
            .create(false)
            .open(BOOT_ENRS_CONFIG_FILE)
            .expect(
                format!(
                    "Unable to open the boot enrs config file: {:?}",
                    BOOT_ENRS_CONFIG_FILE
                )
                .as_str(),
            );
    let boot_enrs: Vec<Enr<CombinedKey>> =
        serde_yaml::from_reader(file).expect("Unable to parse boot enr");
    
    let op_addrs = query_socket_address_from_boot(boot_enrs, op_pk).await;
    info!("node addre {:?}", op_addrs);
    if op_addrs.is_empty() {
        panic!("failed to query op socket address from boot node");
    }
    if !all_equal(&op_addrs) {
        panic!("the op addresses from different boot nodes are not same {:?}", op_addrs)
    }
    let base_addr = op_addrs.first().unwrap();
    if !check_all_ports(base_addr.clone()) {
        panic!("ports checking failed")
    }
    info!("op {} is ready", op_pk_str);
}