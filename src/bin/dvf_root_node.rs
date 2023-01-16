use discv5::enr::EnrPublicKey;
use discv5::{
    enr,
    enr::{CombinedKey},
    Discv5, Discv5ConfigBuilder, Discv5Event,
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use log::{error, info, debug};
use env_logger::Env;
use std::io::Write;
use store::Store;
use chrono::Local;
use hsconfig::{Secret};
use hsconfig::Export as _;
use std::fs;
use bytes::Bytes;
use network::{Receiver as NetworkReceiver, MessageHandler, Writer as NetworkWriter};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use async_trait::async_trait;
use std::error::Error;
use futures::SinkExt;

pub const DEFAULT_SECRET_DIR: &str = "node_key.json";
pub const DEFAULT_STORE_DIR: &str = "boot_store";
pub const DEFAULT_ROOT_DIR: &str = ".lighthouse";

#[derive(Clone)]
pub struct IpQueryReceiverHandler {
    store: Store
}

#[async_trait]
impl MessageHandler for IpQueryReceiverHandler {
    async fn dispatch(&self, writer: &mut NetworkWriter, message: Bytes) -> Result<(), Box<dyn Error>> {
        let msg: Vec<u8> = message.slice(..).to_vec();  
        // message contains the public key
        match self.store.read(msg).await {
            Ok(value) => {
                match value {
                    Some(data) => {
                        let _  = writer.send(Bytes::from(data)).await;
                    }
                    None => {
                        let _ = writer.send(Bytes::from("can't find signature, please wait")).await;
                    }
                 }
            },
            Err(e) => {
                let _ = writer.send(Bytes::from("can't read database, please wait")).await;
                error!("can't read database, {}", e)
            }
        }
        Ok(())  
    }
}

#[tokio::main]
async fn main() {
    
    let network = std::env::args().nth(1).expect("ERRPR: there is no valid network argument");
    let base_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_ROOT_DIR)
        .join(&network);
    let store_dir = base_dir.join(DEFAULT_STORE_DIR);
    let store = Store::new(store_dir.to_str().unwrap()).unwrap();
    let secret_dir = base_dir.join(DEFAULT_SECRET_DIR);

    let _logger = env_logger::Builder::from_env(Env::default().default_filter_or("info")).format(|buf, record| {
        let level = { buf.default_styled_level(record.level()) };
        writeln!(
            buf,
            "{} {} [{}:{}] {}",
            Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            format_args!("{:>5}", level),
            record.module_path().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            &record.args()
        )
    }).init();

    let address = std::env::args()
        .nth(2)
        .map(|addr| addr.parse::<Ipv4Addr>().unwrap()).unwrap();

    let port: u16 = std::env::args()
        .nth(3)
        .map(|udp_port| udp_port.parse().unwrap()).unwrap();

    let secret = if secret_dir.exists() {
        info!("secret file has been generated, path: {}", &secret_dir.to_str().unwrap());
        Secret::read(secret_dir.to_str().unwrap()).unwrap()
    } else {
        let secret = Secret::new();
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).unwrap_or_else(|why| {
                panic!("can't create dir {:?}", why.kind());
            });
        }
        secret.write(secret_dir.to_str().unwrap()).unwrap();
        secret
    };
    info!("node public key {}", secret.name.encode_base64());
    let mut secret_key = secret.secret.0[..].to_vec();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key).unwrap();

    // construct a local ENR
    let enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        builder.ip(address.into());
        builder.udp4(port);
        builder.build(&enr_key).unwrap()
    };

    info!("Base64 ENR: {}", enr.to_base64());
    info!("IP: {}, UDP_PORT:{}", enr.ip4().unwrap(), enr.udp4().unwrap());

    let config = Discv5ConfigBuilder::new().build();

    // the address to listen on
    let socket_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), port);

    // construct the discv5 server
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

    // start the discv5 service
    discv5.start(socket_addr).await.unwrap();

    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(60));
    let mut ip_set: HashSet<Ipv4Addr> = HashSet::new();
    let mut event_stream = discv5.event_stream().await.unwrap();
    let mut handler_map : HashMap<u64, IpQueryReceiverHandler> = HashMap::new();
    handler_map.insert(0, IpQueryReceiverHandler{ store: store.clone()});

    let handler_map = Arc::new(RwLock::new(handler_map));

    NetworkReceiver::spawn(
        socket_addr,
        handler_map,
        "boot node",
    );

    loop {
        tokio::select! {
            _ = query_interval.tick() => {
                // pick a random node target
                let target_random_node_id = enr::NodeId::random();
                // execute a FINDNODE query
                match discv5.find_node(target_random_node_id).await {
                    Err(e) => info!("Find Node result failed: {:?}", e),
                    Ok(v) => {
                        // found a list of ENR's print their NodeIds
                        info!("current ip set size: {}, found {} peers", ip_set.len(), v.len());
                        for enr in &v {
                            match enr.ip4() {
                                Some(ip) => {
                                    ip_set.insert(ip);
                                    debug!("{:?}", ip);
                                },
                                None => { }
                            }
                        }
                    }
                }
            }
            Some(event) = event_stream.recv() => match event {
                Discv5Event::SessionEstablished(enr,  addr) => {
                    if let Some(enr_ip) =  enr.ip4() {
                        if enr_ip != addr.ip()  {
                            error!("ip doesn't match enr {:?} addr {:?}", enr_ip, addr.ip());
                            continue;
                        }
                        info!("A peer has established session: public key: {}, ip: {:?}", base64::encode(enr.public_key().encode()), enr_ip);
                        // store binary data
                        store.write(enr.public_key().encode(), enr_ip.octets().to_vec()).await;
                        ip_set.insert(enr_ip);
                    }
                }
                _ => {}
            }
        }
    }
}
