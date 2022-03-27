
use libp2p::NetworkBehaviour;
use libp2p:: {
  core::{PublicKey},
  gossipsub::{self, Gossipsub, GossipsubEvent, GossipsubMessage, MessageAuthenticity, MessageId, ValidationMode},
  kad::{self, record::store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent},
  identity::{Keypair},
  identify::{Identify, IdentifyConfig, IdentifyEvent, IdentifyInfo},
  swarm::NetworkBehaviourEventProcess,
  PeerId
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::{time::Duration};
use log::{info, debug};
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct DvfNetorkBehaviour {
  pub gossipsub: Gossipsub,
  pub kademlia: Kademlia<MemoryStore>,
  pub identify: Identify,
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for DvfNetorkBehaviour {
  fn inject_event(&mut self, event: GossipsubEvent) {
    if let GossipsubEvent::Message {
      propagation_source: peer_id, 
      message_id: id, 
      message,
    } = event {
      // store message to file
      info!("Got message: {} with id {} from peer: {:?}", String::from_utf8_lossy(&message.data), id, peer_id);
    }
  }
}

impl NetworkBehaviourEventProcess<IdentifyEvent> for DvfNetorkBehaviour {
  fn inject_event(&mut self, event: IdentifyEvent) {
    match event {
      IdentifyEvent::Received {
        peer_id,
        info:
          IdentifyInfo {
            listen_addrs,
            protocols,
            ..
          },
      } => {
        if protocols.iter().any(|p| p.as_bytes() == kad::protocol::DEFAULT_PROTO_NAME)
        {
          for addr in listen_addrs {
            info!("new peer: id {} address {}", &peer_id, &addr);
            self.kademlia.add_address(&peer_id, addr);
          }
        }
      }
      _ => {}
    }
  }
}

impl NetworkBehaviourEventProcess<KademliaEvent> for DvfNetorkBehaviour {
  fn inject_event(&mut self, event: KademliaEvent) { 
    debug!("event {:?}", event);
  }
}

pub fn create_gossipsub_behavior(id_keys: Keypair) -> Gossipsub {
  // To content-address message, we can take the hash of message and use it as an ID.
  let message_id_fn = |message: &GossipsubMessage| {
      let mut s = DefaultHasher::new();
      message.data.hash(&mut s);
      MessageId::from(s.finish().to_string())
  };

  // Set a custom gossipsub
  let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
      .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
      .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
      .message_id_fn(message_id_fn) // content-address messages. No two messages of the
      .do_px()
      // same content will be propagated.
      .build()
      .expect("Valid config");
  gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
      .expect("Correct configuration")
}

pub fn create_kademlia_behavior(local_peer_id: PeerId) -> Kademlia<MemoryStore> {
  // Create a Kademlia behaviour.
  let mut cfg = KademliaConfig::default();
  cfg.set_query_timeout(Duration::from_secs(5 * 60));
  let store = MemoryStore::new(local_peer_id);
  Kademlia::with_config(local_peer_id, store, cfg)
}

pub fn create_identify_behavior(local_public_key: PublicKey) -> Identify {
  Identify::new(IdentifyConfig::new("/ipfs/1.0.0".into(), local_public_key))
}



