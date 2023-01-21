use super::config::BOOT_SOCKETADDR;
use discv5::enr::EnrPublicKey;
use discv5::{
    enr::{CombinedKey, Enr},
    Discv5, Discv5ConfigBuilder,
};
use hsconfig::Secret;
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::sync::RwLock;
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
            builder.udp(udp_port);
            builder.build(&enr_key).unwrap()
        };
        info!(
            "Base64 ENR: {}, IP: {:?}",
            self_enr.to_base64(),
            self_enr.ip4().unwrap()
        );

        // default configuration without packet filtering
        let config = Discv5ConfigBuilder::new().build();

        // the address to listen on
        let socket_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), udp_port);

        // construct the discv5 server
        let mut discv5 = Discv5::new(self_enr, enr_key, config).unwrap();

        match boot_enr.parse::<Enr<CombinedKey>>() {
            Ok(enr) => {
                info!(
                    "ENR Read. ip: {:?}, undp_port {:?}, tcp_port: {:?}, public_key: {}",
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
                    panic!("ENR was not added: {}", e);
                }
            }
            Err(e) => {
                panic!("Decoding ENR failed: {}", e);
            }
        }

        tokio::spawn(async move {
            discv5.start(socket_addr).await.unwrap();
            // construct a 30 second interval to search for new peers.
            let mut query_interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                  _ = query_interval.tick() => {
                    // pick a random node target
                    let target_random_node_id = discv5::enr::NodeId::random();
                    // execute a FINDNODE query
                    match discv5.find_node(target_random_node_id).await {
                      Err(e) => error!("Find Node result failed: {:?}", e),
                      Ok(v) => {
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
                }
            }
        });
    }
}
