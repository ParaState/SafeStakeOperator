use super::config::BOOT_SOCKETADDR;
use lighthouse_network::discv5::enr::EnrPublicKey;
use lighthouse_network::discv5::{
    self,
    enr::{CombinedKey, Enr},
    Discv5, Discv5ConfigBuilder, Discv5Event,
};
use hsconfig::Secret;
use std::collections::HashMap;
use std::sync::Arc;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info};

pub struct Discovery {}

impl Discovery {
    pub fn spawn(
        ip: IpAddr,
        udp_port: u16,
        key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
        secret: Secret,
        boot_enr: String,
    ) {
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
                    "------remote enr: {} , remote base64 enr:{}",
                    enr,
                    enr.to_base64()
                );

                BOOT_SOCKETADDR
                    .set(SocketAddr::new(
                        IpAddr::V4(enr.ip4().expect("boot enr ip should not be empty")),
                        enr.udp4().expect("boot enr port should not be empty"),
                    ))
                    .unwrap();

                info!("------discv5 will add remote enr");
                if let Err(e) = discv5.add_enr(enr) {
                    info!("------remote enr was not added: {e}");
                }
            }
            Err(e) => {
                error!("Decoding ENR failed: {}", e);
            }
        }

        tokio::spawn(async move {
            // start the discv5 service
            let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), udp_port);
            let _ = discv5.start(listen_addr).await;
            // construct a 30 second interval to search for new peers.
            let mut query_interval = tokio::time::interval(Duration::from_secs(30));
            let mut event_stream = discv5.event_stream().await.unwrap();
            loop {
                tokio::select! {
                    _ = query_interval.tick() => {
                        info!("Searching for peers...");
                        // pick a random node target
                        let target_random_node_id = discv5::enr::NodeId::random();
                        // execute a FINDNODE query
                        match discv5.find_node(target_random_node_id).await {
                            Err(e) => error!("Find Node result failed: {:?}", e),
                            Ok(v) => {
                                info!("Find Node result succeeded: {} nodes", v.len());
                                // found a list of ENR's print their NodeIds
                                let mut m = key_ip_map.write().await;
                                for enr in v {
                                    if let Some(ip) = enr.ip4() {
                                        let public_key = base64::encode(&enr.public_key().encode()[..]);
                                        // update public key ip
                                        m.insert(public_key, IpAddr::V4(ip));
                                    };
                                };
                            }
                        }
                    }
                    Some(event) = event_stream.recv() => {
                        match event {
                            Discv5Event::Discovered(enr) => {
                                let mut m = key_ip_map.write().await;
                                if let Some(ip) = enr.ip4() {
                                    let public_key = base64::encode(&enr.public_key().encode()[..]);
                                    // update public key ip
                                    m.insert(public_key, IpAddr::V4(ip));
                                };
                            },
                            Discv5Event::SessionEstablished(enr, _addr) => {
                                let mut m = key_ip_map.write().await;
                                if let Some(ip) = enr.ip4() {
                                    let public_key = base64::encode(&enr.public_key().encode()[..]);
                                    // update public key ip
                                    m.insert(public_key, IpAddr::V4(ip));
                                };
                            },
                            Discv5Event::SocketUpdated(addr) => {
                                info!("Discv5Event::SocketUpdated: local ENR IP address has been updated, addr:{}", addr);
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
    }
}
