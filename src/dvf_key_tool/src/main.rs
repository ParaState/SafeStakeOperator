
use std::fs;

use dvf_utils::ROOT_VERSION;
use safestake_crypto::secret::Export as _;
use safestake_crypto::secret::Secret;

pub const DEFAULT_SECRET_DIR: &str = "node_key.json";
pub const DEFAULT_ROOT_DIR: &str = ".lighthouse";


fn main() {
    println!("------dvf_key_tool------");

    let network = std::env::args()
        .nth(1)
        .expect("ERROR: there is no valid network argument");
    let base_dir = dirs::home_dir()
        .expect("ERROR: home dir is valid")
        .join(DEFAULT_ROOT_DIR)
        .join(format!("v{}", ROOT_VERSION))
        .join(&network);
    let secret_dir = base_dir.join(DEFAULT_SECRET_DIR);

    //generate secret key if not exists
    if secret_dir.exists() {
        println!(
            "INFO: secret file has been generated, path: {}",
            &secret_dir.to_str().unwrap()
        );
        let secret = Secret::read(&secret_dir)
            .expect("ERROR: can't read secret file, unexpect error happened.");
        println!("INFO: node public key {}", secret.name.base64());
    } else {
        let secret = Secret::new();
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).unwrap_or_else(|why| {
                println!("ERROR: can't create dir {:?}", why.kind());
                return;
            });
        }
        secret
            .write(&secret_dir)
            .expect("ERROR: Can't write to file");
        println!("INFO: node public key {}", secret.name.base64());
    }
}
