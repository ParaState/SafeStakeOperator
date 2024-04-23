use async_trait::async_trait;
use bytes::Bytes;
use dvf::utils::ip_util::get_public_ip;
use futures::prelude::*;
use hsconfig::Export as _;
use hsconfig::Secret;
use lighthouse_network::discv5::enr::EnrPublicKey;
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr},
    ConfigBuilder, Discv5, Event, ListenConfig,
};
use log::{error, info};
use network::{MessageHandler, Receiver as NetworkReceiver, Writer as NetworkWriter};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use store::Store;
use tokio::sync::RwLock;

pub const DEFAULT_SECRET_DIR: &str = "node_key.json";
pub const DEFAULT_STORE_DIR: &str = "boot_store";
pub const DEFAULT_ROOT_DIR: &str = ".lighthouse";
pub const DEFAULT_PORT: u16 = 9005;
pub const DISCOVERY_PORT_OFFSET: u16 = 4;

#[derive(Clone)]
pub struct IpQueryReceiverHandler {
    store: Store,
}

#[async_trait]
impl MessageHandler for IpQueryReceiverHandler {
    async fn dispatch(
        &self,
        writer: &mut NetworkWriter,
        message: Bytes,
    ) -> Result<(), Box<dyn Error>> {
        let msg: Vec<u8> = message.slice(..).to_vec();
        // message contains the public key
        match self.store.read(msg).await {
            Ok(value) => match value {
                Some(data) => {
                    let _ = writer.send(Bytes::from(data)).await;
                }
                None => {
                    let _ = writer
                        .send(Bytes::from("can't find address, please wait"))
                        .await;
                }
            },
            Err(e) => {
                let _ = writer
                    .send(Bytes::from("can't read database, please wait"))
                    .await;
                error!("can't read database, {}", e)
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // tracing_subscriber::fmt().json().init();
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();

    let network = std::env::args()
        .nth(1)
        .expect("ERRPR: there is no valid network argument");
    let base_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_ROOT_DIR)
        .join(&network);
    let store_dir = base_dir.join(DEFAULT_STORE_DIR);
    let store = Store::new(store_dir.to_str().unwrap()).unwrap();
    let secret_dir = base_dir.join(DEFAULT_SECRET_DIR);

    let default_public_ip: Ipv4Addr = get_public_ip().parse().expect("valid ip");
    let ip = std::env::args()
        .nth(2)
        .map(|addr| addr.parse::<Ipv4Addr>().unwrap())
        .unwrap_or(default_public_ip);

    let port = {
        if let Some(udp_port) = std::env::args().nth(3) {
            udp_port.parse().unwrap_or(DEFAULT_PORT)
        } else {
            DEFAULT_PORT
        }
    };

    let secret = if secret_dir.exists() {
        info!("Loading secret file: {}", &secret_dir.to_str().unwrap());
        Secret::read(secret_dir.to_str().unwrap()).unwrap()
    } else {
        info!("Generating secret file: {}", &secret_dir.to_str().unwrap());
        let secret = Secret::new();
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).unwrap_or_else(|why| {
                panic!("can't create dir {:?}", why.kind());
            });
        }
        secret.write(secret_dir.to_str().unwrap()).unwrap();
        secret
    };
    let mut secret_key = secret.secret.0[..].to_vec();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key).unwrap();

    // construct a local ENR
    let local_enr = {
        let mut builder = Enr::builder();
        builder.ip(ip.into());
        builder.udp4(port);
        builder.build(&enr_key).unwrap()
    };

    info!("Boot node ENR ip: {}, port: {}", ip, port);
    info!("Boot node public key: {}", secret.name.encode_base64());
    info!(
        "Boot node id: {}",
        base64::encode(local_enr.node_id().raw())
    );
    info!("Boot node ENR: {:?}", local_enr.to_base64());

    let config = ConfigBuilder::new(ListenConfig::Ipv4 {
        ip: "0.0.0.0".parse().unwrap(),
        port: port,
    })
    .build();

    // construct the discv5 server
    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, config).unwrap();

    // start the discv5 service
    let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), port);
    let _ = discv5.start().await;

    let mut event_stream = discv5.event_stream().await.unwrap();
    let mut handler_map: HashMap<u64, IpQueryReceiverHandler> = HashMap::new();
    handler_map.insert(
        0,
        IpQueryReceiverHandler {
            store: store.clone(),
        },
    );

    let handler_map = Arc::new(RwLock::new(handler_map));

    NetworkReceiver::spawn(listen_addr, handler_map, "boot node");

    loop {
        tokio::select! {
            Some(event) = event_stream.recv() => {
                match event {
                    Event::Discovered(enr) => {
                        if let Some(enr_ip) =  enr.ip4() {
                            if let Some(discv_port) = enr.udp4() {
                                store.write(enr.public_key().encode(), bincode::serialize(&SocketAddr::new(IpAddr::V4(enr_ip), discv_port - DISCOVERY_PORT_OFFSET)).unwrap()).await;
                            }
                        }
                    },
                    Event::SessionEstablished(enr,  _addr) => {

                        if let Some(enr_ip) =  enr.ip4() {
                            if let Some(discv_port) = enr.udp4() {
                                let socketaddr = SocketAddr::new(IpAddr::V4(enr_ip), discv_port - DISCOVERY_PORT_OFFSET);
                                info!("A peer has established session: public key: {}, base addr: {:?}",
                                base64::encode(enr.public_key().encode()), socketaddr);
                                store.write(enr.public_key().encode(), bincode::serialize(&socketaddr).unwrap()).await;
                            }
                        }
                    },
                    Event::SocketUpdated(addr) => {
                        info!("Event::SocketUpdated: local ENR IP address has been updated, addr:{}", addr);
                        // zico: Is there any way to broadcast this news?
                    },
                    Event::EnrAdded { .. }
                    | Event::NodeInserted { .. }
                    | Event::TalkRequest(_) => {}, // Ignore all other discv5 server events
                };
            }
        }
    }
}
