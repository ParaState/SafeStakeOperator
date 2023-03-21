use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::collections::HashMap;
use std::sync::Arc;

use discv5::{
    Discv5,
    Discv5ConfigBuilder, enr::{CombinedKey, Enr},
};
use discv5::enr::EnrPublicKey;
use hsconfig::Secret;
use tokio::sync::RwLock;
use tracing::{debug, error, info, log, warn};

use super::config::BOOT_SOCKETADDR;

pub struct Discovery {}

impl Discovery {
    pub fn spawn(
        ip_address: IpAddr,
        udp_port: u16,
        key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
        secret: Secret,
        boot_enr: String,
    ) {
        // let mut enr_key = CombinedKey::generate_secp256k1();
        let mut secret_key = secret.secret.0[..].to_vec();
        let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();

        let self_enr = {
            let mut builder = discv5::enr::EnrBuilder::new("v4");
            builder.ip(ip_address);
            // don't need to set udp port
            builder.udp4(udp_port);
            builder.build(&enr_key).unwrap()
        };
        info!(
            "------local enr: {}, local base64 enr: {}",
            self_enr,
            self_enr.to_base64()
        );

        // default configuration without packet filtering
        let config = Discv5ConfigBuilder::new().build();

        // the address to listen on
        let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), udp_port);

        // construct the discv5 server
        let mut discv5: Discv5 = Discv5::new(self_enr, enr_key, config).unwrap();

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
            discv5.start(listen_addr).await.unwrap();
            // construct a 30 second interval to search for new peers.
            let mut query_interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                  _ = query_interval.tick() => {
                    // get metrics
                    let metrics = discv5.metrics();
                    let connected_peers = discv5.connected_peers();
                    info!("------Connected peers: {}, Active sessions: {}, Unsolicited requests/s: {:.2}", connected_peers, metrics.active_sessions, metrics.unsolicited_requests_per_second);
                    info!("------Searching for peers...");

                    // pick a random node target
                    let target_random_node_id = discv5::enr::NodeId::random();
                    // execute a FINDNODE query
                    match discv5.find_node(target_random_node_id).await {
                      Err(e) => error!("Find Node result failed: {:?}", e),
                      Ok(v) => {
                        // found a list of ENR's print their NodeIds
                        let node_ids = v.iter().map(|enr| enr.node_id()).collect::<Vec<_>>();
                        info!("------Nodes found: {}", node_ids.len());

                        let mut m = key_ip_map.write().await;
                        for enr in v {
                          info!("------node enr: {} , node base64 enr:{}",
                            enr,
                            enr.to_base64()
                          );

                          if let Some(ip) = enr.ip4() {
                            info!("------enr ipv4:{}",ip);
                            let public_key = base64::encode(&enr.public_key().encode()[..]);
                            // update public key ip
                            m.insert(public_key, IpAddr::V4(ip));
                          };
                        };
                      }
                    }
                  }
                }
            }
        });
    }
}
