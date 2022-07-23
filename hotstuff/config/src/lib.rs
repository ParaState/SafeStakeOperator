use consensus::{Committee as ConsensusCommittee, Parameters as ConsensusParameters};
use crypto::{generate_secp256k_keypair, generate_production_keypair, PublicKey, SecretKey};
use mempool::{Committee as MempoolCommittee, Parameters as MempoolParameters};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::BufWriter;
use std::io::Write as _;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file '{file}': {message}")]
    ReadError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    WriteError { file: String, message: String },
}

pub trait Export: Serialize + DeserializeOwned {

    fn read(path: &str) -> Result<Self, ConfigError> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| ConfigError::ReadError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }

    fn write(&self, path: &str) -> Result<(), ConfigError> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| ConfigError::WriteError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Parameters {
    pub consensus: ConsensusParameters,
    pub mempool: MempoolParameters,
}

impl Export for Parameters {}

#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub name: PublicKey,
    pub secret: SecretKey,
}

impl Secret {
    pub fn new() -> Self {
        let (name, secret) = generate_production_keypair();
        Self { name, secret }
    }

    pub fn insecure() -> Self {
        // let mut rng = StdRng::seed_from_u64(state);
        let (name, secret) = generate_secp256k_keypair();
        Self { name, secret }
    }
}

impl Export for Secret {}

impl Default for Secret {
    fn default() -> Self {
        Self::insecure() 
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Committee {
    pub consensus: ConsensusCommittee,
    pub mempool: MempoolCommittee,
}

impl Export for Committee {}
