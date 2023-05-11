use env_logger::Env;
use log::{info, error};
use dvf::utils::ip_util::get_public_ip;
use lighthouse_network::discv5::{Enr, enr, enr::NodeId, enr::CombinedKey, enr::EnrPublicKey, enr::CombinedPublicKey, Discv5, Discv5ConfigBuilder, Discv5Event};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::Duration;
use hsconfig::Secret;
use futures::executor::block_on;
use futures::future::join_all;
use eth2_network_config::Eth2NetworkConfig;
use dvf::node::config::NodeConfig;

pub fn read_boot_enrs() {
    let config = NodeConfig::default();
    info!("Enrs: {:?}", config.boot_enrs);
}

pub fn load_lighthouse_network_config() -> Eth2NetworkConfig {
    Eth2NetworkConfig::constant("prater").unwrap().unwrap()
}

pub async fn boot_node() {
    let discv5_config = Discv5ConfigBuilder::new()
        .incoming_bucket_limit(8) // half the bucket size
        .build();
    
    let port = 9000;
    let address: Ipv4Addr = get_public_ip().parse().expect("valid ip");
    // let address: Ipv4Addr = "127.0.0.1".parse().expect("valid ip");
    
    let secret = {
        let secret = Secret::new();
        secret
    };
    info!("boot node public key {}", secret.name.encode_base64());
    let mut secret_key = secret.secret.0[..].to_vec();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key).unwrap();

    // construct a local ENR
    let local_enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        builder.ip(address.into());
        builder.udp4(port);
        builder.build(&enr_key).unwrap()
    };
    info!("Boot ENR: {:?}", local_enr.to_base64());
    info!("Boot node id: {:?}", base64::encode(local_enr.node_id().raw()));

    // the address to listen on
    let socket_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), port);

    // construct the discv5 server
    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, discv5_config).unwrap();

    // start the discv5 service
    discv5.start(socket_addr).await.unwrap();

    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(60));
    let mut event_stream = discv5.event_stream().await.unwrap();

    loop {
        tokio::select! {
            _ = query_interval.tick() => {
                // pick a random node target
                let target_random_node_id = enr::NodeId::random();
                // execute a FINDNODE query
                match discv5.find_node(target_random_node_id).await {
                    Err(e) => error!("Find Node result failed: {:?}", e),
                    Ok(v) => {
                        info!("Find Node result succeeded: {} nodes", v.len());
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
                        info!("A peer has established session: public key: {}, ip: {:?}, port: {:?}, node id: {:?}", 
                            base64::encode(enr.public_key().encode()), enr_ip, enr.udp4().unwrap(), base64::encode(enr.node_id().raw()));
                        info!("Current enrs ({}): {:?}", discv5.table_entries_id().len(), discv5.table_entries_id().iter().map(|x| base64::encode(x.raw())).collect::<Vec<String>>());
                    }
                }
                _ => {}
            }
        }
    }
}

pub fn node_enr(port: u16) -> (CombinedKey, Enr) {
    let address: Ipv4Addr = get_public_ip().parse().expect("valid ip");
    // let address: Ipv4Addr = "127.0.0.1".parse().expect("valid ip");
    
    let secret = {
        let secret = Secret::new();
        secret
    };
    let mut secret_key = secret.secret.0[..].to_vec();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key).unwrap();

    // construct a local ENR
    let local_enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        builder.ip(address.into());
        builder.udp4(port);
        builder.build(&enr_key).unwrap()
    };

    (enr_key, local_enr)
}

pub fn decode_enr(enr: String) -> Enr {
    match enr.parse::<Enr>() {
        Ok(enr) => {
            info!(
                "Boot ENR Read. ip: {:?}, undp_port {:?}, tcp_port: {:?}, public_key: {}",
                enr.ip4(),
                enr.udp4(),
                enr.tcp4(),
                base64::encode(&enr.public_key().encode()[..])
            );

            enr
        }
        Err(e) => {
            panic!("Decoding ENR failed: {}", e);
        }
    }
}

pub async fn normal_node(enr_key: CombinedKey, local_enr: Enr, boot_enrs: Vec<Enr>, targets: Vec<CombinedPublicKey>) {
    info!("Normal node id: {:?}", base64::encode(local_enr.node_id().raw()));
    let discv5_config = Discv5ConfigBuilder::new()
        .incoming_bucket_limit(8) // half the bucket size
        .build();
    
    // the address to listen on
    let socket_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), local_enr.udp4().unwrap());

    // construct the discv5 server
    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, discv5_config).unwrap();

    // start the discv5 service
    discv5.start(socket_addr).await.unwrap();

    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(10));
    let mut event_stream = discv5.event_stream().await.unwrap();

    for boot_enr in boot_enrs {
        if let Err(e) = discv5.add_enr(boot_enr) {
            panic!("ENR was not added: {}", e);
        }
    }

    let node_id = base64::encode(local_enr.node_id().raw());
    let mut i = 0;
    loop {
        tokio::select! {
            _ = query_interval.tick() => {
                info!("[{:?}] --- unsolved targets: {}", node_id, targets.len() - i);
                // pick a node target
                let target_node_id = NodeId::from(targets[i].clone());
                if target_node_id == local_enr.node_id() {
                    i += 1;
                    info!("[{:?}] --- {} solved target node id: {:?}", node_id, i, base64::encode(target_node_id.raw()));
                }
                else if let Some(_enr) = discv5.find_enr(&target_node_id) {
                    i += 1;
                    info!("[{:?}] --- {} solved target node id: {:?}", node_id, i, base64::encode(target_node_id.raw()));
                }
                else {
                    // execute a FINDNODE query
                    match discv5.find_node(target_node_id).await {
                        Err(e) => error!("[{:?}] Find Node result failed: {:?}", node_id, e),
                        Ok(v) => {
                            // info!("[{:?}] Find Node result succeeded: {:?}", node_id, v);
                            for enr in v {
                                if enr.node_id() == target_node_id {
                                    i += 1;
                                    info!("[{:?}] --- {} solved target node id: {:?}", node_id, i, base64::encode(target_node_id.raw()));
                                    break;
                                }
                            }
                        }
                    }
                }
                if i >= targets.len() {
                    break;
                }
            }
            Some(event) = event_stream.recv() => match event {
                Discv5Event::SessionEstablished(enr,  addr) => {
                    if let Some(enr_ip) =  enr.ip4() {
                        if enr_ip != addr.ip()  {
                            error!("[{:?}] ip doesn't match enr {:?} addr {:?}", node_id, enr_ip, addr.ip());
                            continue;
                        }
                        info!("[{:?}] A peer has established session: public key: {}, ip: {:?}, port: {:?}, node id: {:?}", 
                            node_id, base64::encode(enr.public_key().encode()), enr_ip, enr.udp4().unwrap(), base64::encode(enr.node_id().raw()));
                    }
                }
                _ => {}
            }
        }
    }
    info!("[{:?}] done.", node_id);
    tokio::time::sleep(tokio::time::Duration::from_secs(60000)).await;
}

fn main() {
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16) 
        .enable_all()
        .build()
        .unwrap();

    let mode = std::env::args().nth(1).expect("ERRPR: there is no valid argument");
    if mode == "boot" {
        let handle = runtime.spawn(async move {
            boot_node().await;
        });
        let _ = block_on(handle);
    }
    else if mode == "normal" {
        let boot_enrs = {
            if let Some(boot_enr) = std::env::args().nth(2) {
                vec![decode_enr(boot_enr)]
            }
            else {
                load_lighthouse_network_config().boot_enr.unwrap()
            }
        };
        info!("Boot enrs: {:?}", boot_enrs);
        // let boot_enr = std::env::args().nth(2).expect("ERRPR: there is no valid argument");
        // let boot_enrs = ;
        let n = 100;

        let mut nodes: Vec<(CombinedKey, Enr)> = Default::default();
        for i in 0..n {
            nodes.push(node_enr(9001 + i));
        }
        let targets: Vec<CombinedPublicKey> = nodes.iter().map(|(_, enr)| enr.public_key()).collect();
        info!("Targets: {:?}", targets.iter().map(|x| base64::encode(NodeId::from(x.clone()).raw())).collect::<Vec<_>>());
        let mut handles: Vec<_> = Default::default();
        for _i in 0 ..n {
            let (enr_key, enr) = nodes.remove(0);
            let targets_clone = targets.clone();
            let boot_enrs_clone = boot_enrs.clone();
            let handle = runtime.spawn(async move {
                normal_node(enr_key, enr, boot_enrs_clone, targets_clone).await;
            });
            handles.push(handle);
        }
        block_on(join_all(handles));
    }
    else {
        read_boot_enrs();
    }

    std::thread::sleep(std::time::Duration::from_millis(10000));
}


