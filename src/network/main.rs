mod network;
use network::dvfnode::DvfNode;
use network::bootnode::BootNode;
use std::{env::args, error::Error};
use log::{info, error};
use libp2p::{identity::{Keypair}, gossipsub::{IdentTopic },PeerId, Multiaddr, swarm::SwarmEvent};
use libp2p::futures::StreamExt;
use tokio::io::{self, AsyncBufReadExt};
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  env_logger::init();
  let boot_addr: Option<Multiaddr> = args().nth(1).map(|a| a.parse().unwrap());
  let boot_peerid: Option<PeerId> = args().nth(2).map(|a| a.parse().unwrap());
  let key = Keypair::generate_ed25519();

  if let Some(boot_addr) = boot_addr {
    // create a dvf node
    // use for test
    let gossipsub_topic = IdentTopic::new("chat");
    let dvf_node = DvfNode::new(key, gossipsub_topic, boot_addr, boot_peerid.unwrap());
    tokio::spawn(run_dvf(dvf_node)).await.unwrap();
  } else {
    // create a boot node
    let boot_node = BootNode::new(key);
    tokio::spawn(run_boot(boot_node)).await.unwrap();
  }

  Ok(())
}

async fn run_boot(mut node: BootNode) {
  if let Err(e) = node.listen() {
    error!("error when listen {}", e);
  }
  loop {
    tokio::select! {
      event = node.swarm.select_next_some() => {
        if let SwarmEvent::NewListenAddr { address, .. } = event {
            let peer_id = node.swarm.local_peer_id();
            println!("Listening on address {:?}, peerid {:?}", address, peer_id);
        }
      }
    }
  }
}

async fn run_dvf (mut node: DvfNode) {
  if let Err(e) = node.listen() {
    error!("error when listen {}", e);
  }
  let mut listening = false;
  let mut stdin = io::BufReader::new(io::stdin()).lines();
  loop {
    if !listening {
      for addr in node.swarm.listeners() {
          let peer_id = node.swarm.local_peer_id();
          println!("Listening on address {:?}, peerid {:?}", addr, peer_id);
          listening = true;
      }
    }
    let to_send = {
      tokio::select! {
        line = stdin.next_line() => {
          let line = line.unwrap().expect("stdin closed");
          if !line.is_empty()  {
            Some(line)
          } else {
            println!("{}", line);
            None
          }
        }
        _ = node.swarm.select_next_some() => {
          None
        }
      }
    };
    if let Some(line) = to_send {
      node.send(line.as_bytes())
    }
  };
}