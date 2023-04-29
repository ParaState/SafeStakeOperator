
use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use std::path::PathBuf;
use lighthouse_network::discv5::{enr::CombinedKey};

use dvf_version::{VERSION};
use std::net::SocketAddr;

pub const DEFAULT_DVF_ROOT_DIR: &str = ".dvf";
pub const NODE_KEY_FILENAME: &str = "node_key.json";

pub fn open_or_create_secret(path: PathBuf) -> Result<Secret, ConfigError> {
  if path.exists() {
      println!("{:?}", path);
      Secret::read(path.to_str().unwrap())
  }
  else {
      let secret = Secret::new();
      secret.write(path.to_str().unwrap())?;
      Ok(secret)
  }
}

pub fn test1() {
  let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_DVF_ROOT_DIR);
  let node_key_path = base_dir.join(NODE_KEY_FILENAME);
  let secret = open_or_create_secret(node_key_path).unwrap();

  let mut secret_key = secret.secret.0[..].to_vec();
  let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();
  println!("enr key {:?}", base64::encode(enr_key.encode()));
}

pub fn test2() {
  println!("version: {}", VERSION);
}

pub fn test3() {
  let mut x: Option<SocketAddr> = Some("127.0.0.1:9000".parse().unwrap());
  if let Some(socket) = x.as_mut() {
    socket.set_ip("192.168.0.1".parse().unwrap());
  }
  println!("x: {:?}", x);
  x.as_mut().unwrap().set_ip("192.168.0.2".parse().unwrap());
  println!("x: {:?}", x);
}

pub fn test4() {
  let a = vec![1, 2, 3];
  let b = vec![1, 2, 3];
  let x: &[u8] = a.as_slice();
  let y: &[u8] = b.as_slice();
  println!("x==y: {}", x==y);
}

// test read node secret to init discovery process
fn main() {
  // test1();
  // test2();
  test3();
  test4();
}