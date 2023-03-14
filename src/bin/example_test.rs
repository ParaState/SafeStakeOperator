
use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use std::path::PathBuf;
use discv5::{enr::CombinedKey};

use dvf_version::{VERSION};

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

// test read node secret to init discovery process
fn main() {
  // test1();
  test2();
}