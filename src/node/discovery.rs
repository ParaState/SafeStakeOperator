
use discv5::enr::EnrPublicKey;
use discv5::{
    enr::{CombinedKey, Enr},
    Discv5, Discv5ConfigBuilder,
};
use log::{info, error};
use std::sync::{Arc};
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::{
  net::{SocketAddr, IpAddr},
  time::Duration,
};
use std::option::Option;
use hsconfig::Secret;

pub struct Discovery {
  // enr: Enr<CombinedKey>,
  // enr_key: CombinedKey
}
impl Discovery {
  pub fn spawn (
    ip_address: IpAddr,
    udp_port: u16,
    key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
    secret: Secret,
    boot_enr: Option<String>,
  ) {

    // let mut enr_key = CombinedKey::generate_secp256k1();
    let mut secret_key = secret.secret.0[..].to_vec();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();

    let self_enr = {
      let mut builder = discv5::enr::EnrBuilder::new("v4");
      builder.ip(ip_address);
      builder.udp(udp_port);
      builder.build(&enr_key).unwrap()
    };
    info!("Base64 ENR: {}, IP: {:?}", self_enr.to_base64(), self_enr.ip().unwrap());
    // default configuration with packet filtering
    // let config = Discv5ConfigBuilder::new().enable_packet_filter().build();

    // default configuration without packet filtering
    let config = Discv5ConfigBuilder::new().build();
    
    // the address to listen on
    let socket_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), udp_port);

    // construct the discv5 server
    let mut discv5 = Discv5::new(self_enr, enr_key, config).unwrap();

    match boot_enr {
      Some(boot_enr_value) => {
        match boot_enr_value.parse::<Enr<CombinedKey>>() {
          Ok(enr) => {
            info!("ENR Read. ip: {:?}, undp_port {:?}, tcp_port: {:?}, public_key: {}", enr.ip(), enr.udp(), enr.tcp(), base64::encode(&enr.public_key().encode()[..]));
            if let Err(e) = discv5.add_enr(enr) {
              error!("ENR was not added: {}", e);
            }
          }
          Err(e) => {
            error!("Decoding ENR failed: {}", e);
          }
        }
      }
      None => { info!("Start as a boot node."); }
    }

    tokio::spawn(async move {
      // start the discv5 service
      discv5.start(socket_addr).await.unwrap();
      // construct a 30 second interval to search for new peers.
      let mut query_interval = tokio::time::interval(Duration::from_secs(15));
      loop {
        tokio::select! {
          _ = query_interval.tick() => {
            // pick a random node target
            let target_random_node_id = discv5::enr::NodeId::random();
            let metrics = discv5.metrics();
            let connected_peers = discv5.connected_peers();
            info!("Connected peers: {}, Active sessions: {}, Unsolicited requests/s: {:.2}", connected_peers, metrics.active_sessions, metrics.unsolicited_requests_per_second);
            info!("Searching for peers...");
            // execute a FINDNODE query
            match discv5.find_node(target_random_node_id).await {
              Err(e) => error!("Find Node result failed: {:?}", e),
              Ok(v) => {
                // found a list of ENR's print their NodeIds
                let mut m = key_ip_map.write().await;
                for enr in v {
                  if let Some(ip) = enr.ip() {
                    let public_key = base64::encode(&enr.public_key().encode()[..]);
                    // update public key ip
                    // TODO: replace itwith a more efiicient solution
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