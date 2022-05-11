//! Provides easy ways to run a beacon node or validator client in-process.
//!
//! Intended to be used for testing and simulation purposes. Not for production.


pub mod local_beacon_node;
pub mod local_validator_client;
pub mod local_network;
pub mod validator_files;
pub mod checks;

pub use crate::validation::Config as ValidatorConfig;

use beacon_node::{ClientGenesis, ClientConfig};
use std::time::{SystemTime, UNIX_EPOCH};


pub fn testing_client_config() -> ClientConfig {
    let mut client_config = ClientConfig::default();

    // Setting ports to `0` means that the OS will choose some available port.
    client_config.network.libp2p_port = 0;
    client_config.network.discovery_port = 0;
    client_config.network.upnp_enabled = false;
    client_config.http_api.enabled = true;
    client_config.http_api.listen_port = 0;

    client_config.dummy_eth1_backend = true;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("should get system time")
        .as_secs();

    client_config.genesis = ClientGenesis::Interop {
        validator_count: 8,
        genesis_time: now,
    };

    client_config
}

pub fn testing_validator_config() -> ValidatorConfig {
    ValidatorConfig {
        init_slashing_protection: true,
        disable_auto_discover: false,
        ..ValidatorConfig::default()
    }
}
