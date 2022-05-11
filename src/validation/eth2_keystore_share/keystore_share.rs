//! Reference: lighthouse/crypto/eth2_keystore::keystore
//!
//! Provides a JSON keystore share for a BLS keypair

use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use eth2_keystore::{Keystore, Uuid};
use bls::PublicKey;

use eth2_keystore::Error as KeyStoreError;

/// Provides a BLS keystore share.
///
/// Use `KeystoreShareBuilder` to create a new keystore share.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreShare {
    pub keystore: Keystore,
    pub master_public_key: PublicKey,
    pub master_id: u64,
    pub share_id: u64,
}

impl KeystoreShare {

    pub fn new(keystore: Keystore, master_public_key: PublicKey, master_id: u64, share_id: u64) -> Self {
        Self {
            keystore,
            master_public_key,
            master_id,
            share_id,
        }
    }

    /// Returns the UUID for the keystore.
    pub fn uuid(&self) -> &Uuid {
        self.keystore.uuid()
    }

    /// Encodes `self` as a JSON object.
    pub fn to_json_string(&self) -> Result<String, KeyStoreError> {
        serde_json::to_string(self).map_err(|e| KeyStoreError::UnableToSerialize(format!("{}", e)))
    }

    /// Returns `self` from an encoded JSON object.
    pub fn from_json_str(json_string: &str) -> Result<Self, KeyStoreError> {
        serde_json::from_str(json_string).map_err(|e| KeyStoreError::InvalidJson(format!("{}", e)))
    }

    /// Encodes self as a JSON object to the given `writer`.
    pub fn to_json_writer<W: Write>(&self, writer: W) -> Result<(), KeyStoreError> {
        serde_json::to_writer(writer, self).map_err(|e| KeyStoreError::WriteError(format!("{}", e)))
    }

    /// Instantiates `self` from a JSON `reader`.
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, KeyStoreError> {
        serde_json::from_reader(reader).map_err(|e| KeyStoreError::ReadError(format!("{}", e)))
    }

    /// Instantiates `self` by reading a JSON file at `path`.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyStoreError> {
        File::options()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
            .map_err(|e| KeyStoreError::ReadError(format!("{}", e)))
            .and_then(Self::from_json_reader)
    }
}

