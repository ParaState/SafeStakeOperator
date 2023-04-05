//! Provides a file format for defining validators that should be initialized by this validator.
//!
//! Serves as the source-of-truth of which validators this validator client should attempt (or not
//! attempt) to load into the `crate::intialized_validators::InitializedValidators` struct.

use crate::validation::account_utils::{write_file_via_temporary};
use directory::ensure_dir_exists;
use serde_derive::{Deserialize, Serialize};
use std::fs::{File};
use std::io;
use std::path::{Path, PathBuf};
use types::{PublicKey};
use std::net::{SocketAddr};

/// The file name for the serialized `OperatorCommitteeDefinition` struct.
pub const OPERATOR_COMMITTEE_DEFINITION_FILENAME: &str = "operator_committee_definition.yml";

/// The file name for the serialized `ValidatorDefinitions` struct.
pub const CONFIG_FILENAME: &str = "operator_committee_definitions.yml";

/// The temporary file name for the serialized `ValidatorDefinitions` struct.
///
/// This is used to achieve an atomic update of the contents on disk, without truncation.
/// See: https://github.com/sigp/lighthouse/issues/2159
pub const CONFIG_TEMP_FILENAME: &str = ".operator_committee_definitions.yml.tmp";


#[derive(Debug)]
pub enum Error {
    /// The config file could not be opened.
    UnableToOpenFile(io::Error),
    /// The config file could not be parsed as YAML.
    UnableToParseFile(serde_yaml::Error),
    /// The config file could not be serialized as YAML.
    UnableToEncodeFile(serde_yaml::Error),
    /// The config file or temp file could not be written to the filesystem.
    UnableToWriteFile(filesystem::Error),
    /// The committee directory could not be created.
    UnableToCreateCommitteeDir(PathBuf),
    /// Invalid file
    InvalidFile,
}



/// A validator that may be initialized by this validator client.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorCommitteeDefinition {
    pub total: u64,
    pub threshold: u64,
    pub validator_id: u64,
    pub validator_public_key: PublicKey,
    pub operator_ids: Vec<u64>,
    pub operator_public_keys: Vec<PublicKey>,
    pub node_public_keys: Vec<hscrypto::PublicKey>,
    pub base_socket_addresses: Vec<Option<SocketAddr>>,
}

impl OperatorCommitteeDefinition {
    /// Instantiates `self` by reading a file at `path`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::options()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
            .map_err(Error::UnableToOpenFile)?;
        serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .map_err(Error::UnableToOpenFile)?;
        serde_yaml::to_writer(file, self).map_err(Error::UnableToEncodeFile)
    }
}

/// A list of `OperatorCommitteeDefinition` that serves as a serde-able configuration file which defines a
/// list of operator committees.
#[derive(Default, Serialize, Deserialize)]
pub struct OperatorCommitteeDefinitions(Vec<OperatorCommitteeDefinition>);

impl From<Vec<OperatorCommitteeDefinition>> for OperatorCommitteeDefinitions {
    fn from(vec: Vec<OperatorCommitteeDefinition>) -> Self {
        Self(vec)
    }
}

impl OperatorCommitteeDefinitions {
    /// Open an existing file or create a new, empty one if it does not exist.
    pub fn open_or_create<P: AsRef<Path>>(committees_dir: P) -> Result<Self, Error> {
        ensure_dir_exists(committees_dir.as_ref()).map_err(|_| {
            Error::UnableToCreateCommitteeDir(PathBuf::from(committees_dir.as_ref()))
        })?;
        let config_path = committees_dir.as_ref().join(CONFIG_FILENAME);
        if !config_path.exists() {
            let this = Self::default();
            this.save(&committees_dir)?;
        }
        Self::open(committees_dir)
    }

    /// Open an existing file, returning an error if the file does not exist.
    pub fn open<P: AsRef<Path>>(committees_dir: P) -> Result<Self, Error> {
        let config_path = committees_dir.as_ref().join(CONFIG_FILENAME);
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(false)
            .open(&config_path)
            .map_err(Error::UnableToOpenFile)?;
        let defs: Self = serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)?;
        // Validate simple constraints
        for i in 0..defs.0.len() {
            if defs.0[i].operator_ids.len() != (defs.0[i].total as usize) {
                return Err(Error::InvalidFile);
            }
            if defs.0[i].operator_public_keys.len() != (defs.0[i].total as usize) {
                return Err(Error::InvalidFile);
            }
            if defs.0[i].node_public_keys.len() != (defs.0[i].total as usize) {
                return Err(Error::InvalidFile);
            }
            if defs.0[i].base_socket_addresses.len() != (defs.0[i].total as usize) {
                return Err(Error::InvalidFile);
            }
        }
        Ok(defs)
    }

    /// Returns a slice of all `OperatorCommitteeDefinition` in `self`.
    pub fn as_slice(&self) -> &[OperatorCommitteeDefinition] {
        self.0.as_slice()
    }

    /// Encodes `self` as a YAML string and atomically writes it to the `CONFIG_FILENAME` file in
    /// the `committees_dir` directory.
    ///
    /// Will create a new file if it does not exist or overwrite any existing file.
    pub fn save<P: AsRef<Path>>(&self, committees_dir: P) -> Result<(), Error> {
        let config_path = committees_dir.as_ref().join(CONFIG_FILENAME);
        let temp_path = committees_dir.as_ref().join(CONFIG_TEMP_FILENAME);
        let bytes = serde_yaml::to_vec(self).map_err(Error::UnableToEncodeFile)?;

        write_file_via_temporary(&config_path, &temp_path, &bytes)
            .map_err(Error::UnableToWriteFile)?;

        Ok(())
    }

    /// Adds a new `OperatorCommitteeDefinition` to `self`.
    pub fn push(&mut self, def: OperatorCommitteeDefinition) {
        self.0.push(def)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_committee_checks() {
        let oc_str = r#"---
        total: 3
        threshold: 1
        committee_index: 5
        voting_public_key: 0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7 
        ids: [1, 2, 3]
        public_keys: ["0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007", "0xaa440c566fcf34dedf233baf56cf5fb05bb420d9663b4208272545608c27c13d5b08174518c758ecd814f158f2b4a337", "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"]
        base_socket_addresses: ["127.0.0.1:12", "127.0.0.1:2523", "127.0.0.1:89"]
        "#;
        let def: OperatorCommitteeDefinition = serde_yaml::from_str(oc_str).unwrap();
        assert_eq!(def.total, 3);
        assert_eq!(def.threshold, 1);
        // assert_eq!(def.committee_index, 5);
        // assert_eq!(def.voting_public_key.as_hex_string(), "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7");
        // assert_eq!(def.public_keys[0].as_hex_string(), "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"); 
        // assert_eq!(def.public_keys[1].as_hex_string(), "0xaa440c566fcf34dedf233baf56cf5fb05bb420d9663b4208272545608c27c13d5b08174518c758ecd814f158f2b4a337"); 
        // assert_eq!(def.public_keys[2].as_hex_string(), "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"); 
        // assert_eq!(def.socket_addresses[0].to_string(), "127.0.0.1:12");
        // assert_eq!(def.socket_addresses[1].to_string(), "127.0.0.1:2523");
        // assert_eq!(def.socket_addresses[2].to_string(), "127.0.0.1:89");
    }

    #[test]
    fn test_add_valid_operator_committee() {
        let oc_str = r#"---
        total: 10
        threshold: 5
        validator_id: 4
        validator_public_key: 0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e 
        ids: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        operator_public_keys: ["0xb3251b4920e44d934c757abee918fd6a4d2c35e04b2a6a61d165fb5c9cf93823bdcfd944d5de530d613a1f5cff1b9f32", "0x99de1824808e1d60d98b6c0e9116954d7e8df769c0ec61b4f1a0e6055aa5690a8e6bf78d69954e99dd0a78ceb2fcb962", "0x953aae269caa88654660abf65158cfa8671ab5a99440d6962ae93efac05261607448c9d9b0254362dfe65ab4c4782cab","0xa183f7351c6addce02d16cc021c914c2cda5b7d4df7c4020059668aeb7c8a392514a35035f1695ad73bce239c5bec8d3","0x92654abc1faccdcb4b1d4c9ea97356f52798026c31d90104a80561dc164317071f39d94152d964ddf8b5207da9991ca0","0xad3067733ade535c72043ab24715d33bf533a00c8c3e3c992832517c4f1fa08f80a71b02b05a315035262eca36465dc8","0x8cff5a31fa55d3f5db9e1c6075581b11c67c5d9a0e41d5e10b9a0e97d39e551f6b10fbeaae7e11036d9cb94eab947218","0x96b871bf391eaed3a3f5ba8860feddbb0a0d96f1ca76e5278f111be57564bf7915b75d5f991c98f0e5416dda1fdb2838","0xb6c3ec9f710ac05032f24694b839b4026821769fd48feaaa676e4d2aa1cade7b79e8f2943d3ede5e4adc627776c275f3","0xa9c50b8467534b0229e2a2e2f1918985fad68716d8e33814463e76aa6d4388069b13a3452006fa054176146794fa0b1f"]
        base_socket_addresses: ["127.0.0.1:4001", "127.0.0.1:4002", "127.0.0.1:4003", "127.0.0.1:4004", "127.0.0.1:4005", "127.0.0.1:4006", "127.0.0.1:4007", "127.0.0.1:4008", "127.0.0.1:4009", "127.0.0.1:4010"]
        "#;
        let def: OperatorCommitteeDefinition = serde_yaml::from_str(oc_str).unwrap();
        //let committees_dir = TempBuilder::new()
            //.prefix("lighthouse-operator-committees")
            //.tempdir()
            //.map_err(|e| format!("Unable to create operator committees dir: {:?}", e))
            //.unwrap()
            //.path();
        //println!("====== Directory: {:?}", committees_dir);
        //let mut defs = OperatorCommitteeDefinitions::open_or_create(committees_dir).unwrap();
        //defs.push(def);
        //defs.save(committees_dir).unwrap();
        let committees_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("lighthouse-tmp");
        println!("====== Directory: {:?}", &committees_dir);
        let mut defs = OperatorCommitteeDefinitions::open_or_create(&committees_dir).unwrap();
        defs.push(def);
        defs.save(&committees_dir).unwrap();
         
    }
}


