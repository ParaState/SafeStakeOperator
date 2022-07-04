use crate::validation::validator_dir::share_builder::build_deterministic_distributed_validator_dirs;
//use crate::validation::validator_dir::share_builder::build_deterministic_committees_file;
use tempfile::{Builder as TempBuilder, TempDir};
use validator_dir::insecure_keys::build_deterministic_validator_dirs;
use crate::node::config::NODE_KEY_FILENAME;
use hsconfig::Secret;
use hsconfig::Export;
use std::collections::HashMap;
use std::net::SocketAddr;
use log::{info};

pub use beacon_node::{ClientConfig, ClientGenesis, ProductionClient};
pub use environment;
pub use eth2;

/// Contains the directories for a `LocalValidatorClient`.
///
/// This struct is separate to `LocalValidatorClient` to allow for pre-computation of validator
/// keypairs since the task is quite resource intensive.
pub struct ValidatorFiles {
    pub validator_dir: TempDir,
    pub secrets_dir: TempDir,
    pub node_dir: TempDir, 
    pub node_id: u64,
}

impl ValidatorFiles {
    /// Creates temporary data and secrets dirs.
    pub fn new(node_id: u64) -> Result<Self, String> {
        // The created dirs will be located in a temporary location specified by `std::env::temp_dir()` according to:
        // https://docs.rs/tempfile/latest/tempfile/struct.TempDir.html
        // On Unix, this location is the value of the `TMPDIR` environment variable.

        let datadir = TempBuilder::new()
            .prefix("lighthouse-validator-client")
            .tempdir()
            .map_err(|e| format!("Unable to create VC data dir: {:?}", e))?;

        let secrets_dir = TempBuilder::new()
            .prefix("lighthouse-validator-client-secrets")
            .tempdir()
            .map_err(|e| format!("Unable to create VC secrets dir: {:?}", e))?;

        let node_dir = TempBuilder::new()
            .prefix("dvf-node")
            .tempdir()
            .map_err(|e| format!("Unable to create dvf node dir: {:?}", e))?;

        Ok(Self {
            validator_dir: datadir,
            secrets_dir,
            node_dir,
            node_id,
        })
    }

    /// Creates temporary data and secrets dirs, preloaded with keystores.
    pub fn with_keystores(keypair_indices: &[usize]) -> Result<Self, String> {
        let this = Self::new(1)?;

        build_deterministic_validator_dirs(
            this.validator_dir.path().into(),
            this.secrets_dir.path().into(),
            keypair_indices,
        )
        .map_err(|e| format!("Unable to build validator directories: {:?}", e))?;

        Ok(this)
    }

    ///// Creates temporary data and secrets dirs, preloaded with keystores.
    //pub fn with_keystore_shares(keypair_indices: &[usize], share_ids: &[u64]) -> Result<Self, String> {
        //let this = Self::new()?;

        //build_deterministic_validator_share_dirs(
            //this.validator_dir.path().into(),
            //this.secrets_dir.path().into(),
            //keypair_indices,
            //share_ids,
        //)
        //.map_err(|e| format!("Unable to build validator share directories: {:?}", e))?;

        //Ok(this)
    //}

    /// Creates temporary data and secrets dirs, preloaded with keystores.
    pub fn with_distributed_keystores(
        node_id: u64,
        validator_ids: &[u64], 
        operator_ids: &[u64], 
        threshold: usize, 
        node_secret: Secret, 
        node_public_keys: &HashMap<u64, hscrypto::PublicKey>,
        node_base_addresses: &HashMap<u64, SocketAddr>,
    ) -> Result<Self, String> {
        let this = Self::new(node_id)?;

        node_secret.write(this.node_dir.path().join(NODE_KEY_FILENAME).to_str().unwrap())
            .map_err(|e| format!("Unable to write node secret: {:?}", e))?;
        info!("Write out node secret");

        build_deterministic_distributed_validator_dirs(
            this.validator_dir.path().into(),
            this.secrets_dir.path().into(),
            validator_ids,
            operator_ids,
            threshold,
            node_public_keys,
            node_base_addresses,
        )
        .map_err(|e| format!("Unable to build distributed validator directories: {:?}", e))?;
        info!("Built operator");

        //build_deterministic_committees_file(
            //this.committees_dir.path().into(),
            //keypair_indices,
            //threshold, 
            //total_splits,
        //)
        //.map_err(|e| format!("Unable to build committees file: {:?}", e))?;

        Ok(this)
    }
}

