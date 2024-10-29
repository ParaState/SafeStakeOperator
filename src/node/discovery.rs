use crate::node::config::{DEFAULT_BASE_PORT, DISCOVERY_PORT_OFFSET};
use crate::DEFAULT_CHANNEL_CAPACITY;
use bytes::Bytes;
use dvf_version::VERSION;
use hsconfig::Secret;
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr, EnrPublicKey, NodeId},
    ConfigBuilder, Discv5, Event, ListenConfig,
};
use log::{debug, error, info, warn};
use network::{DvfMessage, ReliableSender};
use std::collections::HashMap;
use std::path::PathBuf;
use std::{
    net::{
        IpAddr, Ipv4Addr,
        SocketAddr::{self, V4, V6},
    },
    time::Duration,
};
use store::Store;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Interval};
pub const DEFAULT_DISCOVERY_IP_STORE: &str = "discovery_ip_store";
pub const DISCOVER_HEARTBEAT_INTERVAL: u64 = 60 * 5;
pub const DEFAULT_DISCOVERY_PORT: u16 = 26004;
pub struct Discovery {
    secret: Secret,
    heartbeats: RwLock<HashMap<secp256k1::PublicKey, Interval>>,
    query_sender: mpsc::Sender<(NodeId, oneshot::Sender<()>)>,
    store: Store,
    boot_enrs: Vec<Enr<CombinedKey>>,
    discv5_service_handle: JoinHandle<()>,
    base_port: u16,
}

impl Drop for Discovery {
    fn drop(&mut self) {
        info!("Shutting down discovery service");
        self.discv5_service_handle.abort();
    }
}

impl Discovery {
    pub async fn process_enr(store: &Store, enr: Enr<CombinedKey>) {
        // check seq in the enr
        let pk = enr.public_key().encode();
        let seq = enr.seq();
        let mut seq_key = pk.clone();
        seq_key.append(&mut "seq number".as_bytes().to_vec());
        if store
            .read(seq_key.clone())
            .await
            .unwrap()
            .map_or(true, |read_seq| {
                let read_seq = u64::from_le_bytes(read_seq.try_into().unwrap());
                seq > read_seq
            })
        {
            store.write(seq_key, seq.to_le_bytes().to_vec()).await;
            if let Some(ip) = enr.ip4() {
                let discv_port = match enr.udp4() {
                    Some(port) => match port.checked_sub(DISCOVERY_PORT_OFFSET) {
                        Some(p) => p,
                        None => {
                            error!("error happens when get port {}", port);
                            return;
                        }
                    },
                    None => DEFAULT_BASE_PORT,
                };
                store
                    .write(
                        enr.public_key().encode(),
                        bincode::serialize(&SocketAddr::new(IpAddr::V4(ip), discv_port)).unwrap(),
                    )
                    .await;
                info!(
                    "{} seq set to {}, socket address {}:{}",
                    base64::encode(enr.public_key().encode()),
                    seq,
                    ip,
                    discv_port
                );
            }
        }
    }

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
                    new_seq
                }
                _ => 2,
            }
        };
        store
            .write("seq".as_bytes().to_vec(), seq.to_le_bytes().into())
            .await;
        info!("Node ENR seq updated to: {}", seq);

        let mut secret_key = secret.secret.0[..].to_vec();
        let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();

        let local_enr = {
            let mut builder = Enr::builder();
            builder.ip(ip);
            if udp_port != DEFAULT_BASE_PORT {
                builder.udp4(udp_port.checked_add(DISCOVERY_PORT_OFFSET).unwrap());
            }
            builder.seq(seq);
            builder.build(&enr_key).unwrap()
        };
        let base_address = SocketAddr::new(ip, udp_port);
        info!("Node ENR ip: {}, port: {}", ip, udp_port);
        info!("Node public key: {}", secret.name.encode_base64());
        info!("Node id: {}", base64::encode(local_enr.node_id().raw()));
        info!("Node ENR: {:?}", local_enr.to_base64());

        // default configuration without packet filtering
        let config = ConfigBuilder::new(ListenConfig::Ipv4 {
            ip: "0.0.0.0".parse().unwrap(),
            port: udp_port.checked_add(DISCOVERY_PORT_OFFSET).unwrap(),
        })
        .build();

        // construct the discv5 server
        let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, config).unwrap();

        for boot_enr in &boot_enrs {
            if let Err(e) = discv5.add_enr(boot_enr.clone()) {
                panic!("Boot ENR was not added: {}", e);
            }
            info!("Added boot enr: {:?}", boot_enr.to_base64());
        }

        let (tx, mut rx) = mpsc::channel::<(NodeId, oneshot::Sender<()>)>(DEFAULT_CHANNEL_CAPACITY);

        store
            .write(
                local_enr.public_key().encode(),
                bincode::serialize(&base_address).unwrap(),
            )
            .await;

        let discv5_service_handle = tokio::spawn(async move {
            // start the discv5 service
            // let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), udp_port);
            // let _ = discv5.start(listen_addr).await;
            let _ = discv5.start().await;
            let mut event_stream = discv5.event_stream().await.unwrap();
            loop {
                tokio::select! {
                    Some((node_id, notification)) = rx.recv() => {
                        match discv5.find_node(node_id).await {
                            Err(e) => error!("Find Node result failed: {:?}", e),
                            Ok(v) => {
                                debug!("Find Node result succeeded: {} nodes", v.len());
                                // found a list of ENR's print their NodeIds
                                for enr in v {
                                    Discovery::process_enr(&store, enr).await;
                                };
                            }
                        }
                        let _ = notification.send(());
                    }
                    Some(event) = event_stream.recv() => {
                        match event {
                            Event::Discovered(enr) => {
                                Discovery::process_enr(&store, enr).await;
                            },
                            Event::SessionEstablished(enr, _addr) => {
                                Discovery::process_enr(&store, enr).await;
                            },
                            Event::SocketUpdated(addr) => {
                                info!("Discv5Event::SocketUpdated: local ENR IP address has been updated, addr:{}", addr);
                                match addr {
                                    V4(v4addr) => {
                                        match v4addr.port().checked_sub(DISCOVERY_PORT_OFFSET) {
                                            Some(port) => {
                                                store.write(local_enr.public_key().encode(), bincode::serialize(&SocketAddr::new(IpAddr::V4(v4addr.ip().clone()), port)).unwrap()).await;
                                            }
                                            None => {}
                                        }
                                    }
                                    V6(_) => {}
                                }
                                // zico: Is there any way to broadcast this news?
                            },
                            Event::EnrAdded { .. }
                            | Event::NodeInserted { .. }
                            | Event::TalkRequest(_) => {}, // Ignore all other discv5 server events
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
            base_port: udp_port,
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

    pub async fn update_addr(&self, pk: &[u8]) -> Option<SocketAddr> {
        // let curve_pk = secp256k1::PublicKey::from_slice(pk);
        // if curve_pk.is_err() {
        //     error!("Failed to construct secp256k1 public key from the slice");
        //     return None;
        // };
        // let curve_pk = curve_pk.unwrap();
        let node_id = NodeId::parse(&keccak_hash::keccak(pk).0).unwrap();
        self.discover(node_id).await;
        // Randomly pick a boot node
        let boot_idx = rand::random::<usize>() % self.boot_enrs.len();
        self.query_addr_from_boot(boot_idx, pk).await;

        self.query_addr_from_local_store(pk).await
    }

    pub async fn query_addrs(&self, pks: &Vec<Vec<u8>>) -> Vec<Option<SocketAddr>> {
        let mut socket_address: Vec<Option<SocketAddr>> = Default::default();
        for i in 0..pks.len() {
            socket_address.push(self.query_addr(&pks[i]).await);
        }
        socket_address
    }

    /// This function may update local store with network searching.
    /// Use `query_ip_from_local_store` if you want the result immediately
    /// from local store without network searching.
    pub async fn query_addr(&self, pk: &[u8]) -> Option<SocketAddr> {
        // Three ways to query the ip:
        // 1. from local store
        // 2. initiate a discv5 find node
        // 3. from boot node
        // TODO: do we need to add a discovery for random node ID?

        // No need to update for self IP
        if self.secret.name.0.as_slice() == pk {
            return Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                self.base_port,
            ));
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
        tokio::select! {
            biased; // Poll from top to bottom
            _ = heartbeat.tick() => {
                // Updating IP takes time, so we can release the hashmap lock here.
                drop(heartbeats);
                // only update when heartbeat is ready
                self.update_addr(pk).await
            }
            _ = ready => {
                self.query_addr_from_local_store(pk).await
            }
        }
    }

    pub async fn query_addr_from_local_store(&self, pk: &[u8]) -> Option<SocketAddr> {
        match self.store.read(pk.into()).await {
            Ok(value) => {
                if let Some(data) = value {
                    match bincode::deserialize::<SocketAddr>(&data) {
                        Ok(addr) => Some(addr),
                        Err(_) => {
                            error!("Discovery database is corrupted");
                            None
                        }
                    }
                } else {
                    error!("Discovery database cannot find pk: empty IP for the pk");
                    None
                }
            }
            Err(e) => {
                error!("Can't read discovery database, {}", e);
                None
            }
        }
    }

    pub async fn query_addr_from_boot(&self, boot_idx: usize, pk: &[u8]) -> Option<SocketAddr> {
        if self.secret.name.0.as_slice() == pk {
            return Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                self.base_port,
            ));
        }

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
            IpAddr::V4(
                self.boot_enrs[boot_idx]
                    .ip4()
                    .expect("boot enr ip should not be empty"),
            ),
            self.boot_enrs[boot_idx]
                .udp4()
                .expect("boot enr port should not be empty"),
        );
        let receiver = network_sender
            .send(socketaddr, Bytes::from(serialized_msg))
            .await;
        let result = timeout(Duration::from_millis(timeout_mill), receiver).await;

        let base64_pk = base64::encode(pk);
        let addr: Option<SocketAddr> = match result {
            Ok(output) => match output {
                Ok(data) => match bincode::deserialize::<SocketAddr>(&data) {
                    Ok(addr) => {
                        info!(
                            "Get base address from boot node, pk {}, socket address {:?}",
                            &base64_pk, addr
                        );
                        self.store
                            .write(pk.into(), bincode::serialize(&addr).unwrap())
                            .await;
                        Some(addr)
                    }
                    Err(_) => {
                        error!(
                            "Boot node IP response is corrupted {:?}",
                            String::from_utf8(data.to_vec())
                        );
                        None
                    }
                },
                Err(_) => {
                    warn!("Boot node query is interrupted.");
                    None
                }
            },
            Err(_) => {
                warn!("Timeout for querying ip from boot for op {}", &base64_pk);
                None
            }
        };
        addr
    }
}

#[tokio::test]
async fn test_query_boot() {
    let pk = base64::decode("A2trBAZoZsNEOrpqzXF4E2mv04IapvtdJ3kiPSZDyNAz").unwrap();
    let dvf_message = DvfMessage {
        version: VERSION,
        validator_id: 0,
        message: pk.clone(),
    };
    let timeout_mill: u64 = 3000;
    let serialized_msg = bincode::serialize(&dvf_message).unwrap();
    let network_sender = ReliableSender::new();
    let file = std::fs::File::options()
        .read(true)
        .write(false)
        .create(false)
        .open("boot_config/boot_enrs.yaml")
        .expect(
            format!(
                "Unable to open the boot enrs config file: {:?}",
                "boot_config/boot_enrs.yaml"
            )
            .as_str(),
        );
    let boot_enrs: Vec<Enr<CombinedKey>> =
        serde_yaml::from_reader(file).expect("Unable to parse boot enr");
    let socketaddr = SocketAddr::new(
        IpAddr::V4(boot_enrs[1].ip4().expect("boot enr ip should not be empty")),
        boot_enrs[1]
            .udp4()
            .expect("boot enr port should not be empty"),
    );
    let receiver = network_sender
        .send(socketaddr, Bytes::from(serialized_msg))
        .await;
    let result = timeout(Duration::from_millis(timeout_mill), receiver).await;

    let base64_pk = base64::encode(pk);
    match result {
        Ok(output) => match output {
            Ok(data) => match bincode::deserialize::<SocketAddr>(&data) {
                Ok(addr) => {
                    println!(
                        "Get base address from boot node, pk {}, socket address {:?}",
                        &base64_pk, addr
                    );
                }
                Err(_) => {
                    println!(
                        "Boot node IP response is corrupted {:?}",
                        String::from_utf8(data.to_vec())
                    );
                }
            },
            Err(_) => {
                println!("Boot node query is interrupted.");
            }
        },
        Err(_) => {
            println!("Timeout for querying ip from boot for op {}", &base64_pk);
        }
    };
}

#[tokio::test]
async fn test_connect_boot() {
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();
    let ip: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(124, 90, 93, 210));
    let udp_port = 26004;
    let seq = 1;

    let mut secret = Secret::new();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret.secret.0).unwrap();

    let local_enr = {
        let mut builder = Enr::builder();
        builder.ip(ip);
        if udp_port != DEFAULT_DISCOVERY_PORT {
            builder.udp4(udp_port);
        }
        builder.seq(seq);
        builder.build(&enr_key).unwrap()
    };

    let config = ConfigBuilder::new(ListenConfig::Ipv4 {
        ip: "0.0.0.0".parse().unwrap(),
        port: udp_port,
    })
    .build();

    // construct the discv5 server
    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, config).unwrap();

    let file = std::fs::File::options()
        .read(true)
        .write(false)
        .create(false)
        .open("boot_config/boot_enrs.yaml")
        .expect(
            format!(
                "Unable to open the boot enrs config file: {:?}",
                "boot_config/boot_enrs.yaml"
            )
            .as_str(),
        );
    let boot_enrs: Vec<Enr<CombinedKey>> =
        serde_yaml::from_reader(file).expect("Unable to parse boot enr");
    for boot_enr in &boot_enrs {
        if let Err(e) = discv5.add_enr(boot_enr.clone()) {
            panic!("Boot ENR was not added: {}", e);
        }
        info!("Added boot enr: {:?}", boot_enr.to_base64());
    }
    let _ = discv5.start().await;

    for boot_enr in &boot_enrs {
        let res = discv5.find_node(boot_enr.node_id()).await;
        match res {
            Ok(nodes) => {
                info!(
                    "Boot ENR was added successfully, finds nodes: {}",
                    nodes.len()
                );
            }
            Err(e) => {
                error!("Can't connect to boot and run query: {}", e);
            }
        }
    }
}
