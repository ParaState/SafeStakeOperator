use super::config::BOOT_SOCKETADDR;
use lighthouse_network::discv5::{
    self,
    enr::{CombinedKey, Enr, EnrPublicKey, NodeId},
    Discv5, Discv5ConfigBuilder, Discv5Event,
};
use hsconfig::Secret;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr::{self, V4, V6}},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, timeout};
use tracing::{error, info, warn};
use crate::DEFAULT_CHANNEL_CAPACITY;
use store::Store;
use std::path::PathBuf;
use network::{DvfMessage, ReliableSender};
use dvf_version::VERSION;
use bytes::Bytes;
use tokio::task::JoinHandle;

pub const DEFAULT_DISCOVERY_IP_STORE: &str = "discovery_ip_store";
pub const DISCOVER_HEARTBEAT_INTERVAL: u64 = 20;

pub struct Discovery {
    secret: Secret,
    heartbeat: Interval,
    query_sender: mpsc::Sender<(NodeId, oneshot::Sender<()>)>,
    store: Store,
    discv5_service_handle: JoinHandle<()>,
}

impl Drop for Discovery {
    fn drop(&mut self) {
        info!("Shutting down discovery service");
        self.discv5_service_handle.abort();
    }
}

impl Discovery {
    pub async fn spawn(
        ip: IpAddr,
        udp_port: u16,
        secret: Secret,
        boot_enr: String,
        base_dir: PathBuf,
    ) -> Self {
        let mut secret_key = secret.secret.0[..].to_vec();
        let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();

        let local_enr = {
            let mut builder = discv5::enr::EnrBuilder::new("v4");
            builder.ip(ip);
            builder.udp4(udp_port);
            builder.build(&enr_key).unwrap()
        };

        info!("Node ENR ip: {}, port: {}", ip, udp_port);
        info!("Node public key: {}", secret.name.encode_base64());
        info!("Node id: {}", base64::encode(local_enr.node_id().raw()));
        info!("Node ENR: {:?}", local_enr.to_base64());

        // default configuration without packet filtering
        let config = Discv5ConfigBuilder::new().build();

        // construct the discv5 server
        let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, config).unwrap();

        match boot_enr.parse::<Enr<CombinedKey>>() {
            Ok(enr) => {
                info!(
                    "Boot ENR Read. ip: {:?}, undp_port {:?}, tcp_port: {:?}, public_key: {}",
                    enr.ip4(),
                    enr.udp4(),
                    enr.tcp4(),
                    base64::encode(&enr.public_key().encode()[..])
                );

                BOOT_SOCKETADDR
                    .set(SocketAddr::new(
                        IpAddr::V4(enr.ip4().expect("boot enr ip should not be empty")),
                        enr.udp4().expect("boot enr port should not be empty"),
                    ))
                    .unwrap();

                if let Err(e) = discv5.add_enr(enr) {
                    info!("Boot ENR was not added: {}", e);
                }
            }
            Err(e) => {
                error!("Decoding ENR failed: {}", e);
            }
        }

        let store_path = base_dir.join(DEFAULT_DISCOVERY_IP_STORE);
        let store = Store::new(&store_path.to_str().unwrap()).unwrap();
        let store_clone = store.clone();
        let (tx, mut rx) = mpsc::channel::<(NodeId, oneshot::Sender<()>)>(DEFAULT_CHANNEL_CAPACITY);
        let heartbeat = tokio::time::interval(Duration::from_secs(DISCOVER_HEARTBEAT_INTERVAL));

        store_clone.write(local_enr.public_key().encode(), local_enr.ip4().unwrap().octets().to_vec()).await;

        let discv5_service_handle = tokio::spawn(async move {
            // start the discv5 service
            let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), udp_port);
            let _ = discv5.start(listen_addr).await;
            let mut event_stream = discv5.event_stream().await.unwrap();
            loop {
                tokio::select! {
                    Some((node_id, notification)) = rx.recv() => {
                        info!("Searching for peers...");
                        // execute a FINDNODE query
                        match discv5.find_node(node_id).await {
                            Err(e) => error!("Find Node result failed: {:?}", e),
                            Ok(v) => {
                                info!("Find Node result succeeded: {} nodes", v.len());
                                // found a list of ENR's print their NodeIds
                                for enr in v {
                                    if let Some(ip) = enr.ip4() {
                                        // update public key ip
                                        store.write(enr.public_key().encode(), ip.octets().to_vec()).await;
                                    };
                                };
                            }
                        }
                        let _ = notification.send(());
                    }
                    Some(event) = event_stream.recv() => {
                        match event {
                            Discv5Event::Discovered(enr) => {
                                if let Some(ip) = enr.ip4() {
                                    // update public key ip
                                    store.write(enr.public_key().encode(), ip.octets().to_vec()).await;
                                };
                            },
                            Discv5Event::SessionEstablished(enr, _addr) => {
                                if let Some(ip) = enr.ip4() {
                                    // update public key ip
                                    store.write(enr.public_key().encode(), ip.octets().to_vec()).await;
                                };
                            },
                            Discv5Event::SocketUpdated(addr) => {
                                info!("Discv5Event::SocketUpdated: local ENR IP address has been updated, addr:{}", addr);
                                match addr {
                                    V4(v4addr) => {
                                        store.write(local_enr.public_key().encode(), v4addr.ip().octets().to_vec()).await;
                                    }
                                    V6(_) => {}
                                }
                                // zico: Is there any way to broadcast this news?
                            },
                            Discv5Event::EnrAdded { .. } 
                            | Discv5Event::NodeInserted { .. } 
                            | Discv5Event::TalkRequest(_) => {}, // Ignore all other discv5 server events
                        };
                    }
                }
            }
        });

        let discovery = Self {
            secret,
            heartbeat,
            query_sender: tx,
            store: store_clone,
            discv5_service_handle,
        };

        // immediately initiate a discover request to annouce ourself
        let random_node_id = NodeId::random();
        discovery.discover(random_node_id).await;

        discovery
    }

    pub async fn discover(&self, node_id: NodeId) {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.query_sender.send((node_id, sender)).await {
            error!("Failed to send query command to discovery: {}", e);
        }
        let _ = receiver.await;
    }

    pub async fn query_addrs(&mut self, pks: &Vec<Vec<u8>>, base_port: u16) -> Vec<Option<SocketAddr>> {
        self.query_ips(pks)
            .await
            .into_iter()
            .map(|x| x.map(|ip| SocketAddr::new(ip, base_port)))
            .collect()
    }

    pub async fn query_ips(&mut self, pks: &Vec<Vec<u8>>) -> Vec<Option<IpAddr>> {
        let mut ips: Vec<Option<IpAddr>> = Default::default();
        for i in 0..pks.len() {
            ips.push(self.query_ip(&pks[i]).await);
        }
        ips
    }

    /// This function may update local store with network searching.
    /// Use `query_ip_from_local_store` if you want the result immediately 
    /// from local store without network searching.
    pub async fn query_ip(&mut self, pk: &[u8]) -> Option<IpAddr> {
        // Three ways to query the ip:
        // 1. from local store
        // 2. initiate a discv5 find node
        // 3. from boot node
        // TODO: do we need to add a discovery for random node ID?

        // No need to query remotely for self IP
        if self.secret.name.0.as_slice() == pk {
            return self.query_ip_from_local_store(pk).await;
        }

        let node_id = secp256k1::PublicKey::from_slice(pk).map(NodeId::from);
        if node_id.is_err() {
            error!("Failed to construct secp256k1 public key from the slice");
            return None;
        };
        let node_id = node_id.unwrap();

        // If we can't find the pk in local store, immediately issue network requests to search for it;
        // otherwise, should wait for heartbeat signal so that we don't flood the network with frequent requests.
        if let Some(_) = self.query_ip_from_local_store(pk).await {
            self.heartbeat.tick().await;
        }
        self.discover(node_id).await;
        self.query_ip_from_boot(pk).await;
        
        self.query_ip_from_local_store(pk).await
    }

    pub async fn query_ip_from_local_store(&self, pk: &[u8]) -> Option<IpAddr> {
        match self.store.read(pk.into()).await {
            Ok(value) => {
                if let Some(data) = value {
                    if data.len() != 4 {
                        error!("Discovery database is corrupted");
                        None
                    } else {
                        Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
                    }
                }
                else {
                    error!("Discovery database is corrupted: empty IP for the pk");
                    None
                }
            }
            Err(e) => {
                error!("Can't read discovery database, {}", e);
                None
            }
        }
    }

    pub async fn query_ip_from_boot(&self, pk: &[u8]) -> Option<IpAddr> {
        let dvf_message = DvfMessage {
            version: VERSION,
            validator_id: 0,
            message: pk.into(),
        };
        let timeout_mill: u64 = 3000;
        let serialized_msg = bincode::serialize(&dvf_message).unwrap();
        let network_sender = ReliableSender::new();
        let socketaddr = BOOT_SOCKETADDR.get().unwrap().clone();
        let receiver = network_sender.send(socketaddr, Bytes::from(serialized_msg)).await;
        let result = timeout(Duration::from_millis(timeout_mill), receiver).await;
    
        let base64_pk = base64::encode(pk);
        let ipaddr: Option<IpAddr> = match result {
            Ok(output) => {
                match output {
                    Ok(data) => {
                        if data.len() != 4 {
                            error!("Boot node IP response is corrupted");
                            None
                        } else {
                            info!("Get ip from boot node, pk {}, ip {:?}", &base64_pk, data);
                            self.store.write(pk.into(), data.to_vec()).await;
                            Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
                        }
                    }
                    Err(_) => {
                        warn!("Boot node query is interrupted.");
                        None
                    }
                }
            }
            Err(_) => {
                warn!("Timeout for querying ip from boot for op {}", &base64_pk);
                None
            }
        };
        ipaddr
    }
}
