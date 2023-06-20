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
use log::{error, info, warn};
use crate::DEFAULT_CHANNEL_CAPACITY;
use store::Store;
use std::path::PathBuf;
use network::{DvfMessage, ReliableSender};
use dvf_version::VERSION;
use bytes::Bytes;
use tokio::task::JoinHandle;
use tokio::sync::RwLock;
use std::collections::HashMap;

pub const DEFAULT_DISCOVERY_IP_STORE: &str = "discovery_ip_store";
pub const DISCOVER_HEARTBEAT_INTERVAL: u64 = 60;

pub struct Discovery {
    secret: Secret,
    heartbeats: RwLock<HashMap<secp256k1::PublicKey, Interval>>,
    query_sender: mpsc::Sender<(NodeId, oneshot::Sender<()>)>,
    store: Store,
    boot_enrs: Vec<Enr<CombinedKey>>,
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
        boot_enrs: Vec<Enr<CombinedKey>>,
        base_dir: PathBuf,
    ) -> Self {
        let store_path = base_dir.join(DEFAULT_DISCOVERY_IP_STORE);
        let store = Store::new(&store_path.to_str().unwrap()).unwrap();
        let store_clone = store.clone();

        let seq: u64 = {
            match store.read("seq".as_bytes().to_vec()).await {
                Ok(Some(value)) => {
                    if value.len() != 8 {
                        panic!("Discovery database corrupted: unable to read ENR seq number.");
                    }
                    let new_seq = u64::from_le_bytes(value.try_into().unwrap()) + 1;
                    store.write("seq".as_bytes().to_vec(), new_seq.to_le_bytes().into()).await;
                    info!("Node ENR seq updated to: {}", new_seq);
                    new_seq
                }
                _ => {
                    1
                }
            }
        };

        let mut secret_key = secret.secret.0[..].to_vec();
        let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();

        let local_enr = {
            let mut builder = discv5::enr::EnrBuilder::new("v4");
            builder.ip(ip);
            builder.udp4(udp_port);
            builder.seq(seq);
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

        for boot_enr in &boot_enrs {
            if let Err(e) = discv5.add_enr(boot_enr.clone()) {
                panic!("Boot ENR was not added: {}", e);
            }
            info!("Added boot enr: {:?}", boot_enr.to_base64());
        }

        let (tx, mut rx) = mpsc::channel::<(NodeId, oneshot::Sender<()>)>(DEFAULT_CHANNEL_CAPACITY);

        store.write(local_enr.public_key().encode(), local_enr.ip4().unwrap().octets().to_vec()).await;

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
            heartbeats: <_>::default(),
            query_sender: tx,
            store: store_clone,
            boot_enrs,
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

    pub async fn update_ip(&self, pk: &[u8]) -> Option<IpAddr> {
        let curve_pk = secp256k1::PublicKey::from_slice(pk);
        if curve_pk.is_err() {
            error!("Failed to construct secp256k1 public key from the slice");
            return None;
        };
        let curve_pk = curve_pk.unwrap();
        let node_id = NodeId::from(curve_pk);
        self.discover(node_id).await;
        // Randomly pick a boot node
        let boot_idx = rand::random::<usize>() % self.boot_enrs.len();
        self.query_ip_from_boot(boot_idx, pk).await;
        
        self.query_ip_from_local_store(pk).await
    }

    pub async fn query_addrs(&self, pks: &Vec<Vec<u8>>, base_port: u16) -> Vec<Option<SocketAddr>> {
        self.query_ips(pks)
            .await
            .into_iter()
            .map(|x| x.map(|ip| SocketAddr::new(ip, base_port)))
            .collect()
    }

    pub async fn query_ips(&self, pks: &Vec<Vec<u8>>) -> Vec<Option<IpAddr>> {
        let mut ips: Vec<Option<IpAddr>> = Default::default();
        for i in 0..pks.len() {
            ips.push(self.query_ip(&pks[i]).await);
        }
        ips
    }

    /// This function may update local store with network searching.
    /// Use `query_ip_from_local_store` if you want the result immediately 
    /// from local store without network searching.
    pub async fn query_ip(&self, pk: &[u8]) -> Option<IpAddr> {
        // Three ways to query the ip:
        // 1. from local store
        // 2. initiate a discv5 find node
        // 3. from boot node
        // TODO: do we need to add a discovery for random node ID?

        // No need to update for self IP
        if self.secret.name.0.as_slice() == pk {
            return self.query_ip_from_local_store(pk).await;
        }

        let curve_pk = secp256k1::PublicKey::from_slice(pk);
        if curve_pk.is_err() {
            error!("Failed to construct secp256k1 public key from the slice");
            return None;
        };
        let curve_pk = curve_pk.unwrap();
        let mut heartbeats = self.heartbeats.write().await;
        if !heartbeats.contains_key(&curve_pk) {
            let mut ht = tokio::time::interval(Duration::from_secs(DISCOVER_HEARTBEAT_INTERVAL));
            ht.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            heartbeats.insert(curve_pk.clone(), ht);
        }

        let heartbeat = heartbeats.get_mut(&curve_pk).unwrap();
        let ready = std::future::ready(());
        tokio::select!{
            biased; // Poll from top to bottom
            _ = heartbeat.tick() => {
                // Updating IP takes time, so we can release the hashmap lock here.
                drop(heartbeats);
                // only update when heartbeat is ready
                self.update_ip(pk).await
            }
            _ = ready => {
                self.query_ip_from_local_store(pk).await
            }
        }
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

    pub async fn query_ip_from_boot(&self, boot_idx: usize, pk: &[u8]) -> Option<IpAddr> {
        if boot_idx >= self.boot_enrs.len() {
            error!("Invalid boot index");
            return None;
        }
        let dvf_message = DvfMessage {
            version: VERSION,
            validator_id: 0,
            message: pk.into(),
        };
        let timeout_mill: u64 = 3000;
        let serialized_msg = bincode::serialize(&dvf_message).unwrap();
        let network_sender = ReliableSender::new();
        let socketaddr = SocketAddr::new(
            IpAddr::V4(self.boot_enrs[boot_idx].ip4().expect("boot enr ip should not be empty")),
            self.boot_enrs[boot_idx].udp4().expect("boot enr port should not be empty"),
        );
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
