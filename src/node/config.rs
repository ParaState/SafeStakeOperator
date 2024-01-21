use std::fs::create_dir_all;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use directory::{DEFAULT_ROOT_DIR, DEFAULT_SECRET_DIR, DEFAULT_VALIDATOR_DIR};
use lazy_static::lazy_static;
use lighthouse_network::discv5::enr::{CombinedKey, Enr};
use log::warn;
use sensitive_url::SensitiveUrl;
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use tokio::sync::OnceCell;
/// The file name for the serialized `OperatorCommitteeDefinition` struct.
pub const NODE_KEY_FILENAME: &str = "node_key.json";
pub const DB_FILENAME: &str = "dvf_node_db";

pub const DEFAULT_BASE_PORT: u16 = 25_000;
pub const TRANSACTION_PORT_OFFSET: u16 = 0;
pub const MEMPOOL_PORT_OFFSET: u16 = 1;
pub const CONSENSUS_PORT_OFFSET: u16 = 2;
pub const SIGNATURE_PORT_OFFSET: u16 = 3;
pub const DISCOVERY_PORT_OFFSET: u16 = 4;
pub const DKG_PORT_OFFSET: u16 = 5;
pub const BASE_ADDRESS: [u8; 4] = [127, 0, 0, 1];
pub static API_ADDRESS: OnceCell<String> = OnceCell::const_new();
pub const COLLECT_PERFORMANCE_URL: &str = "collect_performance";
pub const VALIDATOR_PK_URL: &str = "validator_pk";
pub const PRESTAKE_SIGNATURE_URL: &str = "prestake_signature";
pub const STAKE_SIGNATURE_URL: &str = "stake_signature";
pub const TOPIC_NODE_INFO: &str = "dvf/topic_node_info";
const BOOT_ENRS_CONFIG_FILE: &str = "boot_config/boot_enrs.yaml";

lazy_static! {
    // [Issue] SocketAddr::new is not yet a const fn in stable release.
    // Can change this variable to const once it becomes stable.
    // Tracking issue: https://doc.rust-lang.org/std/net/enum.SocketAddr.html#method.new
    pub static ref INVALID_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
}

pub fn invalid_addr() -> SocketAddr {
    return *INVALID_ADDR;
}

pub fn is_addr_invalid(addr: SocketAddr) -> bool {
    if addr == *INVALID_ADDR {
        return true;
    }
    return false;
}

pub fn base_to_transaction_addr(base_addr: SocketAddr) -> SocketAddr {
    if is_addr_invalid(base_addr) {
        base_addr
    } else {
        SocketAddr::new(base_addr.ip(), base_addr.port() + TRANSACTION_PORT_OFFSET)
    }
}

pub fn base_to_mempool_addr(base_addr: SocketAddr) -> SocketAddr {
    if is_addr_invalid(base_addr) {
        base_addr
    } else {
        SocketAddr::new(base_addr.ip(), base_addr.port() + MEMPOOL_PORT_OFFSET)
    }
}

pub fn base_to_consensus_addr(base_addr: SocketAddr) -> SocketAddr {
    if is_addr_invalid(base_addr) {
        base_addr
    } else {
        SocketAddr::new(base_addr.ip(), base_addr.port() + CONSENSUS_PORT_OFFSET)
    }
}

pub fn base_to_signature_addr(base_addr: SocketAddr) -> SocketAddr {
    if is_addr_invalid(base_addr) {
        base_addr
    } else {
        SocketAddr::new(base_addr.ip(), base_addr.port() + SIGNATURE_PORT_OFFSET)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub base_address: SocketAddr,
    pub base_store_path: PathBuf,
    pub node_key_path: PathBuf,
    pub validator_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub boot_enrs: Vec<Enr<CombinedKey>>,
    pub beacon_nodes: Vec<SensitiveUrl>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self::new(
            1,
            IpAddr::V4(Ipv4Addr::new(
                BASE_ADDRESS[0],
                BASE_ADDRESS[1],
                BASE_ADDRESS[2],
                BASE_ADDRESS[3],
            )),
            DEFAULT_BASE_PORT,
        )
    }
}

impl NodeConfig {
    pub fn new(id: u64, ip: IpAddr, base_port: u16) -> Self {
        if id == 0 {
            warn!("Invalid id");
        }

        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR);

        let base_store_path = base_dir.join(DB_FILENAME);
        let node_key_path = base_dir.join(NODE_KEY_FILENAME);
        let validator_dir = base_dir.join(DEFAULT_VALIDATOR_DIR);
        let secrets_dir = base_dir.join(DEFAULT_SECRET_DIR);

        let file = File::options()
            .read(true)
            .write(false)
            .create(false)
            .open(BOOT_ENRS_CONFIG_FILE)
            .expect(
                format!(
                    "Unable to open the boot enrs config file: {:?}",
                    BOOT_ENRS_CONFIG_FILE
                )
                .as_str(),
            );
        let boot_enrs: Vec<Enr<CombinedKey>> =
            serde_yaml::from_reader(file).expect("Unable to parse boot enr");

        Self {
            base_address: SocketAddr::new(ip.clone(), base_port),
            base_store_path,
            node_key_path,
            validator_dir,
            secrets_dir,
            boot_enrs,
            beacon_nodes: Vec::new(),
        }
    }

    pub fn set_base_dir(mut self, path: PathBuf) -> Self {
        if !path.exists() {
            let _ = create_dir_all(&path);
        }
        self.base_store_path = path.join(DB_FILENAME);
        self.node_key_path = path.join(NODE_KEY_FILENAME);
        self
    }

    pub fn set_base_port(mut self, new_port: u16) -> Self {
        self.base_address.set_port(new_port);
        // self.transaction_address.set_port(new_port + TRANSACTION_PORT_OFFSET);
        // self.mempool_address.set_port(new_port + MEMPOOL_PORT_OFFSET);
        // self.consensus_address.set_port(new_port + CONSENSUS_PORT_OFFSET);
        // self.signature_address.set_port(new_port + SIGNATURE_PORT_OFFSET);
        self
    }

    pub fn set_validator_dir(mut self, validator_dir: PathBuf) -> Self {
        self.validator_dir = validator_dir;
        self
    }

    pub fn set_secret_dir(mut self, secret_dir: PathBuf) -> Self {
        self.secrets_dir = secret_dir;
        self
    }

    pub fn set_node_key_path(mut self, base_dir: PathBuf) -> Self {
        self.node_key_path = base_dir.join(NODE_KEY_FILENAME);
        self
    }

    pub fn set_store_path(mut self, base_dir: PathBuf) -> Self {
        self.base_store_path = base_dir.join(DB_FILENAME);
        self
    }

    pub fn set_beacon_nodes(mut self, beacon_nodes: Vec<SensitiveUrl>) -> Self {
        self.beacon_nodes = beacon_nodes;
        self
    }
}
