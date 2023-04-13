use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::net::{IpAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use discv5::enr::EnrPublicKey;
use discv5::{enr, enr::CombinedKey, Discv5, Discv5ConfigBuilder, Discv5Event};
use futures::{future::Either, prelude::*, select};
use hsconfig::Export as _;
use hsconfig::Secret;
use network::{MessageHandler, Receiver as NetworkReceiver, Writer as NetworkWriter};
use store::Store;
use tokio::sync::RwLock;
use tracing::{debug, error, info, log};
use libp2p::{
    gossipsub, identity, mdns, noise,
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
};
use dvf::node::config::TOPIC_NODE_INFO;
use dvf::node::gossipsub_event::{gossipsub_listen, init_gossipsub,MyBehaviourEvent};

pub const DEFAULT_SECRET_DIR: &str = "node_key.json";
pub const DEFAULT_STORE_DIR: &str = "boot_store";
pub const DEFAULT_ROOT_DIR: &str = ".lighthouse";

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
                        .send(Bytes::from("can't find signature, please wait"))
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
async fn main() -> Result<(), Box<dyn Error>>{
    tracing_subscriber::fmt().json().init();
    log::info!("------dvf_root_node------");
    
    let (local_peer_id, transport, mut gossipsub) = init_gossipsub();
    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new(TOPIC_NODE_INFO);
    // subscribes to our topic
    gossipsub.subscribe(&topic)?;
    info!("gossipsub subscribe topic {}", topic);
    
    let mut swarm = gossipsub_listen(local_peer_id, transport, gossipsub);
    
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

    let address = std::env::args()
        .nth(2)
        .map(|addr| addr.parse::<Ipv4Addr>().unwrap());

    let port = {
        if let Some(udp_port) = std::env::args().nth(3) {
            udp_port.parse().unwrap()
        } else {
            9000
        }
    };

    let secret = if secret_dir.exists() {
        info!(
            "secret file has been generated, path: {}",
            &secret_dir.to_str().unwrap()
        );
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
    let local_enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        // if an IP was specified, use it
        if let Some(external_address) = address {
            builder.ip4(external_address);
        }
        // if a port was specified, use it
        if std::env::args().nth(3).is_some() {
            builder.udp4(port);
        }
        builder.build(&enr_key).unwrap()
    };

    // if the ENR is useful print it
    info!("------node_id: {}", local_enr.node_id());
    if local_enr.udp4_socket().is_none() {
        info!("------local enr is not printed as no IP:PORT was specified");
    }
    info!(
        "------local enr: {} , local base64 enr:{}",
        local_enr,
        local_enr.to_base64()
    );

    let config = Discv5ConfigBuilder::new().build();

    // the address to listen on
    let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), port);

    // construct the discv5 server
    let mut discv5:Discv5 = Discv5::new(local_enr, enr_key, config).unwrap();

    // start the discv5 service
    discv5.start(listen_addr).await.unwrap();

    // construct a 60 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(60));
    let mut ip_set: HashSet<Ipv4Addr> = HashSet::new();
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
            _ = query_interval.tick() => {
                 // get metrics
                let metrics = discv5.metrics();
                let connected_peers = discv5.connected_peers();
                info!("------Connected peers: {}, Active sessions: {}, Unsolicited requests/s: {:.2}", connected_peers, metrics.active_sessions, metrics.unsolicited_requests_per_second);
                info!("------Searching for peers...");

                // pick a random node target
                let target_random_node_id = enr::NodeId::random();
                // execute a FINDNODE query
                match discv5.find_node(target_random_node_id).await {
                    Err(e) => info!("Find Node result failed: {:?}", e),
                    Ok(v) => {
                        // found a list of ENR's print their NodeIds
                        let node_ids = v.iter().map(|enr| enr.node_id()).collect::<Vec<_>>();
                        info!("------Nodes found: {}", node_ids.len());
                        // found a list of ENR's print their NodeIds
                        info!("------current ip set size: {}, found {} peers", ip_set.len(), v.len());
                        for enr in &v {
                            info!("------node enr: {} , node base64 enr:{}",enr,enr.to_base64());
                            match enr.ip4() {
                                Some(ip) => {
                                    ip_set.insert(ip);
                                    debug!("------ip_set.insert:{:?}", ip);
                                },
                                None => { }
                            };
                        }
                        
                        let curr_pub_ip=dvf::utils::ip_util::get_public_ip();
                        info!("------curr_pub_ip:{}",curr_pub_ip);
                        
                        let str_socket_addr=[curr_pub_ip,port.to_string()].join(":");
                        // TODO
                        swarm.behaviour_mut().gossipsub.publish(topic.clone(), str_socket_addr.as_bytes());
                        info!("gossipsub publish topic: {},msg:{}", topic,str_socket_addr);
                    }
                }
            }
            Some(event) = event_stream.recv() => {
                match event {
                    Discv5Event::Discovered(enr) => {
                        info!("------Discovered,enr: {}", enr);
                        info!("------Discovered,base64 enr:{}",enr.to_base64());
                        if let Some(enr_ip) =  enr.ip4() {
                            info!("------Discv5Event::Discovered: public key: {}, ip: {:?}", base64::encode(enr.public_key().encode()), enr_ip);
                            // store binary data
                            store.write(enr.public_key().encode(), enr_ip.octets().to_vec()).await;
                            ip_set.insert(enr_ip);
                        }
                    },
                    Discv5Event::SessionEstablished(enr,  _addr) => {
                        info!("------Discv5Event::SessionEstablished,enr:{},base64 enr:{}", enr,enr.to_base64());
                        if let Some(enr_ip) =  enr.ip4() {
                            // if enr_ip != addr.ip()  {
                            //     error!("------ip doesn't match enr {:?} addr {:?}", enr_ip, addr.ip());
                            //     continue;
                            // }
                            info!("------A peer has established session: public key: {}, ip: {:?}", base64::encode(enr.public_key().encode()), enr_ip);
                            // store binary data
                            store.write(enr.public_key().encode(), enr_ip.octets().to_vec()).await;
                            ip_set.insert(enr_ip);
                        }
                    },
                    Discv5Event::EnrAdded { enr, replaced: _ } => info!("------Discv5Event::EnrAdded,enr:{},base64 enr:{}", enr,enr.to_base64()),
                    Discv5Event::NodeInserted { node_id, replaced: _ } => info!("------Discv5Event::NodeInserted, node_id:{}", node_id),
                    Discv5Event::SocketUpdated(addr) => {
                        info!("------Discv5Event::SocketUpdated,Our local ENR IP address has been updated,addr:{}", addr);
                        let ip_addr=addr.ip();
                        match ip_addr {
                            IpAddr::V4(ip4) => {
                                info!("ipv4: {}, octets: {:?}", ip4, ip4.octets());
                            },
                            IpAddr::V6(ip6) => info!("ipv6: {}, segments: {:?}", ip6, ip6.segments()),
                        }
                    },
                    Discv5Event::TalkRequest(t_req) => info!("------Discv5Event::TalkRequest,TalkRequest:{:?}",t_req),
                };
            }
            
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        info!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        info!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => info!(
                        "Got message: '{}' with id: {id} from peer: {peer_id}",
                        String::from_utf8_lossy(&message.data),
                    ),
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("------Local node is listening on {address}");
                }
                _ => {}
            }
            
        }
    }
}

/// tracing_test https://docs.rs/tracing-test/latest/tracing_test/
/// https://stackoverflow.com/questions/72884779/how-to-print-tracing-output-in-tests
#[cfg(test)]
mod tests {
    use tracing::debug;
    use tracing_test::traced_test;
    
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    
    #[traced_test]
    #[test]
    fn test() {
        println!("Testing")
    }
}
