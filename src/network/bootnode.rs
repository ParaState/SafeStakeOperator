
use super::behaviour::DvfNetorkBehaviour;
use super::behaviour::{create_gossipsub_behavior, create_identify_behavior, create_kademlia_behavior};
use log::{info};
use libp2p::{
  core::{upgrade}, 
  identity::Keypair,
  PeerId, Swarm,
  swarm::SwarmBuilder,
  tcp::TokioTcpConfig,
  noise,
  mplex,
  Transport,
  gossipsub::{IdentTopic}
};
use std::error::Error;
pub struct BootNode {
  key : Keypair,
  peerid : PeerId,
  pub swarm : Swarm<DvfNetorkBehaviour>
}

impl BootNode {
  // use a keypair to new a boot node
  pub fn new(key : Keypair) -> Self {
    let peerid = PeerId::from(key.clone().public());
    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&key)
        .expect("Signing libp2p-noise static DH keypair failed.");

    // Create a tokio-based TCP transport use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
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
        identify: create_identify_behavior(key.clone().public())
      };
      // Order Kademlia to search for a peer.
      
      // subscribes to our topic
      let gossipsub_topic = IdentTopic::new("boot");
      behaviour.gossipsub.subscribe(&gossipsub_topic).unwrap();
      SwarmBuilder::new(transport, behaviour, peerid)
        .executor(Box::new(|fut| {
          tokio::spawn(fut);
        }))
        .build()
    };
    Self {
      key ,
      peerid,
      swarm 
    }
  }

  // start a swarm for all interfaces
  pub fn listen (&mut self) -> Result<(), Box<dyn Error>>{
    self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?).unwrap();
    let to_search: PeerId = Keypair::generate_ed25519().public().into();
    info!("Searching for the closest peers to {:?}", to_search);
    self.swarm.behaviour_mut().kademlia.get_closest_peers(to_search);
    Ok(())
  }
}