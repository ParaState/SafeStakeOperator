
use super::behaviour::{DvfNetorkBehaviour };

use super::behaviour::{create_gossipsub_behavior, create_identify_behavior, create_kademlia_behavior};
use log::{info, error};
use libp2p::{
  core::{upgrade}, 
  identity::Keypair,
  PeerId, Swarm,
  swarm::SwarmBuilder,
  tcp::TokioTcpConfig,
  noise,
  mplex,
  Transport,
  gossipsub::{IdentTopic},
  Multiaddr
};
use std::error::Error;
pub struct DvfNode {
  key : Keypair,
  peerid : PeerId,
  pub swarm : Swarm<DvfNetorkBehaviour>,
  topic : IdentTopic
}

impl DvfNode {
  // use a keypair to new a boot node
  pub fn new(key: Keypair, topic:  IdentTopic, boot_addr: Multiaddr, boot_peerid: PeerId) -> Self {

    let peerid = PeerId::from(key.clone().public());
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&key)
        .expect("Signing libp2p-noise static DH keypair failed.");
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let mut swarm : Swarm<DvfNetorkBehaviour> = {
      let mut behaviour = DvfNetorkBehaviour {
        gossipsub: create_gossipsub_behavior(key.clone()),
        kademlia: create_kademlia_behavior(peerid),
        identify: create_identify_behavior(key.public())
      };
      // subscribes to our topic
      behaviour.gossipsub.subscribe(&topic).unwrap();
      // Reach out to another node
      behaviour.kademlia.add_address(&boot_peerid, boot_addr);
      SwarmBuilder::new(transport, behaviour, peerid).executor(Box::new(|fut| {
        tokio::spawn(fut);
      })).build()
    };
    Self {
      key : key.clone(),
      peerid : PeerId::from(key.public()),
      swarm : swarm,
      topic : topic
    }
  }

  // start a swarm for all interfaces
  pub fn listen (&mut self) -> Result<(), Box<dyn Error>>{
    self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?).unwrap();
    // Order Kademlia to search for a peer.
    let to_search: PeerId = Keypair::generate_ed25519().public().into();
    info!("Searching for the closest peers to {:?}", to_search);
    self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);
    Ok(())
  }

  pub fn send (&mut self, data: &[u8]) {
    if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(self.topic.clone(), data) {
      error!("send data error {:?}", e);
    }
  }
}