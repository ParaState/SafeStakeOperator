use dvf::network::bootnode::BootNode;
use libp2p::{identity::Keypair};

macro_rules! aw {
  ($e:expr) => {
      tokio_test::block_on($e)
  };
}

#[test]
fn test_bootnode() {
  let id_keys = Keypair::generate_ed25519();
  let mut bootnode = BootNode::new(id_keys);
  if let Err(e) = aw!(bootnode.listen()) {
    println!("listen error {}", e);
  }
  // blocking on
  bootnode.serving();
}