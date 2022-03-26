mod network;
use network::NodeType;
use network::dvfnode::DvfNode;
use network::bootnode::BootNode;
use std::{env::args, error::Error, time::Duration};
use log::{info, error};
use libp2p::{identity::{self, Keypair}, gossipsub::{IdentTopic },PeerId, Multiaddr, Swarm, gossipsub::Gossipsub};
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
    let mut dvf_node = DvfNode::new(key, gossipsub_topic, boot_addr, boot_peerid.unwrap());
    if let Err(e) = dvf_node.listen() {
      error!("error when listen {}", e);
    }
    tokio::spawn(run_dvf(dvf_node)).await.unwrap();
  } else {


    // create a boot node
    let mut boot_node = BootNode::new(key);
    if let Err(e) = boot_node.listen() {
      error!("error when listen {}", e);
    }
    tokio::spawn(run_boot(boot_node)).await.unwrap();
  }

  Ok(())
}

async fn run_boot(mut node: BootNode) {
  let mut listening = false;
  loop {
    
  }
}

async fn run_dvf (mut node: DvfNode) {
  let mut stdin = io::BufReader::new(io::stdin()).lines();
  loop {
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
      }
    };

    if let Some(line) = to_send {
      node.send(line.as_bytes())
    }
  };
}