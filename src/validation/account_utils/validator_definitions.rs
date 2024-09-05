//! Provides a file format for defining validators that should be initialized by this validator.
//!
//! Serves as the source-of-truth of which validators this validator client should attempt (or not
//! attempt) to load into the `crate::intialized_validators::InitializedValidators` struct.

use crate::validation::account_utils::{
    default_keystore_password_path, default_keystore_share_password_path,
    default_operator_committee_definition_path, write_file_via_temporary, ZeroizeString,
};
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::validator_dir::share_builder::VOTING_KEYSTORE_SHARE_FILE;
use directory::ensure_dir_exists;
use eth2_keystore::Keystore;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use slog::{error, Logger};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use types::{graffiti::GraffitiString, Address, PublicKey};
use validator_dir::VOTING_KEYSTORE_FILE;

/// The file name for the serialized `ValidatorDefinitions` struct.
pub const CONFIG_FILENAME: &str = "validator_definitions.yml";

/// The temporary file name for the serialized `ValidatorDefinitions` struct.
///
/// This is used to achieve an atomic update of the contents on disk, without truncation.
/// See: https://github.com/sigp/lighthouse/issues/2159
pub const CONFIG_TEMP_FILENAME: &str = ".validator_definitions.yml.tmp";

#[derive(Debug)]
pub enum Error {
    /// The config file could not be opened.
    UnableToOpenFile(io::Error),
    /// The config file could not be parsed as YAML.
    UnableToParseFile(serde_yaml::Error),
    /// There was an error whilst performing the recursive keystore search function.
    UnableToSearchForKeystores(io::Error),
    /// The config file could not be serialized as YAML.
    UnableToEncodeFile(serde_yaml::Error),
    /// The config file or temp file could not be written to the filesystem.
    UnableToWriteFile(filesystem::Error),
    /// The public key from the keystore is invalid.
    InvalidKeystorePubkey,
    /// The keystore was unable to be opened.
    UnableToOpenKeystore(eth2_keystore::Error),
    /// The validator directory could not be created.
    UnableToCreateValidatorDir(PathBuf),
    UnableToReadKeystorePassword(String),
    KeystoreWithoutPassword,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub struct Web3SignerDefinition {
    pub url: String,
    /// Path to a .pem file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_certificate_path: Option<PathBuf>,
    /// Specifies a request timeout.
    ///
    /// The timeout is applied from when the request starts connecting until the response body has finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,

    /// Path to a PKCS12 file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_identity_path: Option<PathBuf>,

    /// Password for the PKCS12 file.
    ///
    /// An empty password will be used if this is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_identity_password: Option<String>,
}

/// Defines how the validator client should attempt to sign messages for this validator.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SigningDefinition {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    #[serde(rename = "local_keystore")]
    LocalKeystore {
        voting_keystore_path: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        voting_keystore_password_path: Option<PathBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        voting_keystore_password: Option<ZeroizeString>,
    },
   /// A validator that defers to a Web3Signer HTTP server for signing.
    ///
    /// https://github.com/ConsenSys/web3signer
    #[serde(rename = "web3signer")]
    Web3Signer(Web3SignerDefinition),
    /// A validator whose key is distributed among a set of operators.
    #[serde(rename = "distributed_keystore")]
    DistributedKeystore {
        voting_keystore_share_path: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        voting_keystore_share_password_path: Option<PathBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        voting_keystore_share_password: Option<ZeroizeString>,
        #[serde(skip_serializing_if = "Option::is_none")]
        operator_committee_definition_path: Option<PathBuf>,
        operator_committee_index: u64,
        operator_id: u64,
    },
}

impl SigningDefinition {
    pub fn is_local_keystore(&self) -> bool {
        matches!(self, SigningDefinition::LocalKeystore { .. })
    }

    pub fn is_distributed_keystore(&self) -> bool {
        matches!(self, SigningDefinition::DistributedKeystore { .. })
    }
}

/// A validator that may be initialized by this validator client.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorDefinition {
    pub enabled: bool,
    pub voting_public_key: PublicKey,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee_recipient: Option<Address>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_boost_factor: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer_builder_proposals: Option<bool>,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub signing_definition: SigningDefinition,
}

impl ValidatorDefinition {
    /// Create a new definition for a voting keystore at the given `voting_keystore_path` that can
    /// be unlocked with `voting_keystore_password`.
    ///
    /// ## Notes
    ///
    /// This function does not check the password against the keystore.
    pub fn new_keystore_with_password<P: AsRef<Path>>(
        voting_keystore_path: P,
        voting_keystore_password: Option<ZeroizeString>,
        graffiti: Option<GraffitiString>,
        suggested_fee_recipient: Option<Address>,
        gas_limit: Option<u64>,
        builder_proposals: Option<bool>,
        builder_boost_factor: Option<u64>,
        prefer_builder_proposals: Option<bool>,
    ) -> Result<Self, Error> {
        let voting_keystore_path = voting_keystore_path.as_ref().into();
        let keystore =
            Keystore::from_json_file(&voting_keystore_path).map_err(Error::UnableToOpenKeystore)?;
        let voting_public_key = keystore.public_key().ok_or(Error::InvalidKeystorePubkey)?;

        Ok(ValidatorDefinition {
            enabled: true,
            voting_public_key,
            description: keystore.description().unwrap_or("").to_string(),
            graffiti,
            suggested_fee_recipient,
            gas_limit,
            builder_proposals,
            builder_boost_factor,
            prefer_builder_proposals,
            signing_definition: SigningDefinition::LocalKeystore {
                voting_keystore_path,
                voting_keystore_password_path: None,
                voting_keystore_password,
            },
        })
    }

    /// Create a new definition for a voting keystore share at the given `voting_keystore_share_path` that can
    /// be unlocked with password stored at `voting_keystore_share_password_path`.
    ///
    /// ## Notes
    ///
    /// This function does not check the password against the keystore.
    pub fn new_keystore_share_with_password_path<P: AsRef<Path>>(
        voting_keystore_share_path: P,
        voting_keystore_share_password_path: P,
        graffiti: Option<GraffitiString>,
        suggested_fee_recipient: Option<Address>,
        gas_limit: Option<u64>,
        builder_proposals: Option<bool>,
        builder_boost_factor: Option<u64>,
        prefer_builder_proposals: Option<bool>,
        operator_committee_definition_path: P,
        operator_committee_index: u64,
        operator_id: u64,
    ) -> Result<Self, Error> {
        let voting_keystore_share_path = voting_keystore_share_path.as_ref().into();
        let keystore_share = KeystoreShare::from_json_file(&voting_keystore_share_path)
            .map_err(Error::UnableToOpenKeystore)?;
        let voting_public_key = keystore_share.master_public_key;

        Ok(ValidatorDefinition {
            enabled: true,
            voting_public_key,
            description: keystore_share
                .keystore
                .description()
                .unwrap_or("")
                .to_string(),
            graffiti,
            suggested_fee_recipient,
            gas_limit,
            builder_proposals,
            builder_boost_factor,
            prefer_builder_proposals,
            signing_definition: SigningDefinition::DistributedKeystore {
                voting_keystore_share_path,
                voting_keystore_share_password_path: Some(
                    voting_keystore_share_password_path.as_ref().into(),
                ),
                voting_keystore_share_password: None,
                operator_committee_definition_path: Some(
                    operator_committee_definition_path.as_ref().into(),
                ),
                operator_committee_index,
                operator_id,
            },
        })
    }
}

/// A list of `ValidatorDefinition` that serves as a serde-able configuration file which defines a
/// list of validators to be initialized by this validator client.
#[derive(Default, Serialize, Deserialize)]
pub struct ValidatorDefinitions(Vec<ValidatorDefinition>);

impl From<Vec<ValidatorDefinition>> for ValidatorDefinitions {
    fn from(vec: Vec<ValidatorDefinition>) -> Self {
        Self(vec)
    }
}

impl ValidatorDefinitions {
    /// Open an existing file or create a new, empty one if it does not exist.
    pub fn open_or_create<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        ensure_dir_exists(validators_dir.as_ref()).map_err(|_| {
            Error::UnableToCreateValidatorDir(PathBuf::from(validators_dir.as_ref()))
        })?;
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        if !config_path.exists() {
            let this = Self::default();
            this.save(&validators_dir)?;
        }
        Self::open(validators_dir)
    }

    /// Open an existing file, returning an error if the file does not exist.
    pub fn open<P: AsRef<Path>>(validators_dir: P) -> Result<Self, Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(false)
            .open(&config_path)
            .map_err(Error::UnableToOpenFile)?;
        serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)
    }

    /// Perform a recursive, exhaustive search through `validators_dir` and add any keystores
    /// matching the `validator_dir::VOTING_KEYSTORE_FILE` file name.
    ///
    /// Returns the count of *new* keystores that were added to `self` during this search.
    ///
    /// ## Notes
    ///
    /// Determines the path for the password file based upon the scheme defined by
    /// `account_utils::default_keystore_password_path`.
    ///
    /// If a keystore cannot be parsed the function does not exit early. Instead it logs an `error`
    /// and continues searching.
    pub fn discover_local_keystores<P: AsRef<Path>>(
        &mut self,
        validators_dir: P,
        secrets_dir: P,
        log: &Logger,
    ) -> Result<usize, Error> {
        let mut keystore_paths = vec![];
        recursively_find_voting_keystores(validators_dir, &mut keystore_paths)
            .map_err(Error::UnableToSearchForKeystores)?;

        let known_paths: HashSet<&PathBuf> = self
            .0
            .iter()
            .filter_map(|def| match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_path,
                    ..
                } => Some(voting_keystore_path),
                // A Web3Signer validator does not use a local keystore file.
                SigningDefinition::Web3Signer { .. } => None,
                // [Zico]TODO: to be revised
                SigningDefinition::DistributedKeystore { .. } => None,
            })
            .collect();

        let known_pubkeys: HashSet<PublicKey> = self
            .0
            .iter()
            .map(|def| def.voting_public_key.clone())
            .collect();

        let mut new_defs = keystore_paths
            .into_iter()
            .filter_map(|voting_keystore_path| {
                if known_paths.contains(&voting_keystore_path) {
                    return None;
                }

                let keystore_result = File::options()
                    .read(true)
                    .create(false)
                    .open(&voting_keystore_path)
                    .map_err(|e| format!("{:?}", e))
                    .and_then(|file| {
                        Keystore::from_json_reader(file).map_err(|e| format!("{:?}", e))
                    });

                let keystore = match keystore_result {
                    Ok(keystore) => keystore,
                    Err(e) => {
                        error!(
                            log,
                            "Unable to read validator keystore";
                            "error" => e,
                            "keystore" => format!("{:?}", voting_keystore_path)
                        );
                        return None;
                    }
                };

                let voting_keystore_password_path = Some(default_keystore_password_path(
                    &keystore,
                    secrets_dir.as_ref(),
                ))
                .filter(|path| path.exists());

                let voting_public_key = match keystore.public_key() {
                    Some(pubkey) => {
                        if known_pubkeys.contains(&pubkey) {
                            return None;
                        } else {
                            pubkey
                        }
                    }
                    None => {
                        error!(
                            log,
                            "Invalid keystore public key";
                            "keystore" => format!("{:?}", voting_keystore_path)
                        );
                        return None;
                    }
                };

                Some(ValidatorDefinition {
                    enabled: true,
                    voting_public_key,
                    description: keystore.description().unwrap_or("").to_string(),
                    graffiti: None,
                    suggested_fee_recipient: None,
                    gas_limit: None,
                    builder_proposals: None,
                    builder_boost_factor: None,
                    prefer_builder_proposals: None,
                    signing_definition: SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        voting_keystore_password_path,
                        voting_keystore_password: None,
                    },
                })
            })
            .collect::<Vec<_>>();

        let new_defs_count = new_defs.len();

        self.0.append(&mut new_defs);

        Ok(new_defs_count)
    }

    /// Perform a recursive, exhaustive search through `validators_dir` and add any keystores
    /// matching the `validator_dir::VOTING_KEYSTORE_FILE` file name.
    ///
    /// Returns the count of *new* keystores that were added to `self` during this search.
    ///
    /// ## Notes
    ///
    /// Determines the path for the password file based upon the scheme defined by
    /// `account_utils::default_keystore_password_path`.
    ///
    /// If a keystore cannot be parsed the function does not exit early. Instead it logs an `error`
    /// and continues searching.
    pub fn discover_distributed_keystores<P: AsRef<Path>>(
        &mut self,
        validators_dir: P,
        secrets_dir: P,
        log: &Logger,
    ) -> Result<usize, Error> {
        let mut keystore_share_paths = vec![];
        recursively_find_voting_keystore_shares(validators_dir.as_ref(), &mut keystore_share_paths)
            .map_err(Error::UnableToSearchForKeystores)?;

        let known_paths: HashSet<&PathBuf> = self
            .0
            .iter()
            .filter_map(|def| match &def.signing_definition {
                SigningDefinition::LocalKeystore { .. } => None,
                SigningDefinition::Web3Signer { .. } => None,
                // [Zico]TODO: to be revised
                SigningDefinition::DistributedKeystore {
                    voting_keystore_share_path,
                    ..
                } => Some(voting_keystore_share_path),
            })
            .collect();

        let known_pubkeys: HashSet<PublicKey> = self
            .0
            .iter()
            .map(|def| def.voting_public_key.clone())
            .collect();

        let mut new_defs = keystore_share_paths
            .into_iter()
            .filter_map(|voting_keystore_share_path| {
                if known_paths.contains(&voting_keystore_share_path) {
                    return None;
                }

                let keystore_share_result = File::options()
                    .read(true)
                    .create(false)
                    .open(&voting_keystore_share_path)
                    .map_err(|e| format!("{:?}", e))
                    .and_then(|file| {
                        KeystoreShare::from_json_reader(file).map_err(|e| format!("{:?}", e))
                    });

                let keystore_share = match keystore_share_result {
                    Ok(keystore_share) => keystore_share,
                    Err(e) => {
                        error!(
                            log,
                            "Unable to read validator keystore share";
                            "error" => e,
                            "keystore share" => format!("{:?}", voting_keystore_share_path)
                        );
                        return None;
                    }
                };

                let voting_keystore_share_password_path = Some(
                    default_keystore_share_password_path(&keystore_share, secrets_dir.as_ref()),
                )
                .filter(|path| path.exists());

                let operator_committee_definition_path =
                    Some(default_operator_committee_definition_path(
                        &keystore_share.master_public_key,
                        validators_dir.as_ref(),
                    ))
                    .filter(|path| path.exists());

                // Extract validator (operator committee) index
                let operator_committee_index = keystore_share.master_id;
                // Extract operator id
                let operator_id = keystore_share.share_id;

                // Get the voting public key
                //let voting_public_key = get_validator_public_key(operator_committee_index);
                let voting_public_key = keystore_share.master_public_key.clone();
                if known_pubkeys.contains(&voting_public_key) {
                    return None;
                }

                Some(ValidatorDefinition {
                    enabled: true,
                    voting_public_key,
                    description: keystore_share
                        .keystore
                        .description()
                        .unwrap_or("")
                        .to_string(),
                    graffiti: None,
                    suggested_fee_recipient: None,
                    gas_limit: None,
                    builder_proposals: None,
                    builder_boost_factor: None,
                    prefer_builder_proposals: None,
                    signing_definition: SigningDefinition::DistributedKeystore {
                        voting_keystore_share_path,
                        voting_keystore_share_password_path,
                        voting_keystore_share_password: None,
                        operator_committee_definition_path,
                        operator_committee_index,
                        operator_id,
                    },
                })
            })
            .collect::<Vec<_>>();

        let new_defs_count = new_defs.len();

        self.0.append(&mut new_defs);

        Ok(new_defs_count)
    }

    /// Encodes `self` as a YAML string and atomically writes it to the `CONFIG_FILENAME` file in
    /// the `validators_dir` directory.
    ///
    /// Will create a new file if it does not exist or overwrite any existing file.
    pub fn save<P: AsRef<Path>>(&self, validators_dir: P) -> Result<(), Error> {
        let config_path = validators_dir.as_ref().join(CONFIG_FILENAME);
        let temp_path = validators_dir.as_ref().join(CONFIG_TEMP_FILENAME);
        let bytes = serde_yaml::to_vec(self).map_err(Error::UnableToEncodeFile)?;

        write_file_via_temporary(&config_path, &temp_path, &bytes)
            .map_err(Error::UnableToWriteFile)?;

        Ok(())
    }

    /// Retain only the definitions matching the given predicate.
    pub fn retain(&mut self, f: impl FnMut(&ValidatorDefinition) -> bool) {
        self.0.retain(f);
    }

    /// Adds a new `ValidatorDefinition` to `self`.
    pub fn push(&mut self, def: ValidatorDefinition) {
        self.0.push(def)
    }

    /// Returns a slice of all `ValidatorDefinition` in `self`.
    pub fn as_slice(&self) -> &[ValidatorDefinition] {
        self.0.as_slice()
    }

    /// Returns a mutable slice of all `ValidatorDefinition` in `self`.
    pub fn as_mut_slice(&mut self) -> &mut [ValidatorDefinition] {
        self.0.as_mut_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Perform an exhaustive tree search of `dir`, adding any discovered voting keystore paths to
/// `matches`.
///
/// ## Errors
///
/// Returns with an error immediately if any filesystem error is raised.
pub fn recursively_find_voting_keystores<P: AsRef<Path>>(
    dir: P,
    matches: &mut Vec<PathBuf>,
) -> Result<(), io::Error> {
    fs::read_dir(dir)?.try_for_each(|dir_entry| {
        let dir_entry = dir_entry?;
        let file_type = dir_entry.file_type()?;
        if file_type.is_dir() {
            recursively_find_voting_keystores(dir_entry.path(), matches)?
        } else if file_type.is_file()
            && dir_entry
                .file_name()
                .to_str()
                .map_or(false, is_voting_keystore)
        {
            matches.push(dir_entry.path())
        }
        Ok(())
    })
}

/// Perform an exhaustive tree search of `dir`, adding any discovered voting keystore share paths to
/// `matches`.
///
/// ## Errors
///
/// Returns with an error immediately if any filesystem error is raised.
pub fn recursively_find_voting_keystore_shares<P: AsRef<Path>>(
    dir: P,
    matches: &mut Vec<PathBuf>,
) -> Result<(), io::Error> {
    fs::read_dir(dir)?.try_for_each(|dir_entry| {
        let dir_entry = dir_entry?;
        let file_type = dir_entry.file_type()?;
        if file_type.is_dir() {
            recursively_find_voting_keystore_shares(dir_entry.path(), matches)?
        } else if file_type.is_file()
            && dir_entry
                .file_name()
                .to_str()
                .map_or(false, is_voting_keystore_share)
        {
            matches.push(dir_entry.path())
        }
        Ok(())
    })
}

/// Returns `true` if we should consider the `file_name` to represent a voting keystore.
pub fn is_voting_keystore(file_name: &str) -> bool {
    // All formats end with `.json`.
    if !file_name.ends_with(".json") {
        return false;
    }

    // The format used by Lighthouse.
    if file_name == VOTING_KEYSTORE_FILE {
        return true;
    }

    // The format exported by the `eth2.0-deposit-cli` library.
    //
    // Reference to function that generates keystores:
    //
    // https://github.com/ethereum/eth2.0-deposit-cli/blob/7cebff15eac299b3b1b090c896dd3410c8463450/eth2deposit/credentials.py#L58-L62
    //
    // Since we include the key derivation path of `m/12381/3600/x/0/0` this should only ever match
    // with a voting keystore and never a withdrawal keystore.
    //
    // Key derivation path reference:
    //
    // https://eips.ethereum.org/EIPS/eip-2334
    if Regex::new("keystore-m_12381_3600_[0-9]+_0_0-[0-9]+.json")
        .expect("regex is valid")
        .is_match(file_name)
    {
        return true;
    }

    // The format exported by Prysm. I don't have a reference for this, but it was shared via
    // Discord to Paul H.
    if Regex::new("keystore-[0-9]+.json")
        .expect("regex is valid")
        .is_match(file_name)
    {
        return true;
    }

    false
}

/// Returns `true` if we should consider the `file_name` to represent a voting keystore share.
pub fn is_voting_keystore_share(file_name: &str) -> bool {
    //if Regex::new(VOTING_KEYSTORE_SHARE_FILE)
    //.expect("regex is valid")
    //.is_match(file_name)
    //{
    //return true;
    //}

    // The format used by SafeStake.
    if file_name == VOTING_KEYSTORE_SHARE_FILE {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn voting_keystore_filename_lighthouse() {
        assert!(is_voting_keystore(VOTING_KEYSTORE_FILE));
    }

    #[test]
    fn voting_keystore_filename_launchpad() {
        assert!(!is_voting_keystore("cats"));
        assert!(!is_voting_keystore(&format!("a{}", VOTING_KEYSTORE_FILE)));
        assert!(!is_voting_keystore(&format!("{}b", VOTING_KEYSTORE_FILE)));
        assert!(is_voting_keystore(
            "keystore-m_12381_3600_0_0_0-1593476250.json"
        ));
        assert!(is_voting_keystore(
            "keystore-m_12381_3600_1_0_0-1593476250.json"
        ));
        assert!(is_voting_keystore("keystore-m_12381_3600_1_0_0-1593.json"));
        assert!(!is_voting_keystore(
            "keystore-m_12381_3600_0_0-1593476250.json"
        ));
        assert!(!is_voting_keystore(
            "keystore-m_12381_3600_1_0-1593476250.json"
        ));
    }

    #[test]
    fn voting_keystore_filename_prysm() {
        assert!(is_voting_keystore("keystore-0.json"));
        assert!(is_voting_keystore("keystore-1.json"));
        assert!(is_voting_keystore("keystore-101238259.json"));
        assert!(!is_voting_keystore("keystore-.json"));
        assert!(!is_voting_keystore("keystore-0a.json"));
        assert!(!is_voting_keystore("keystore-cats.json"));
    }

    #[test]
    fn graffiti_checks() {
        let no_graffiti = r#"---
        description: ""
        enabled: true
        type: local_keystore
        voting_keystore_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        "#;
        let def: ValidatorDefinition = serde_yaml::from_str(no_graffiti).unwrap();
        assert!(def.graffiti.is_none());

        let invalid_graffiti = r#"---
        description: ""
        enabled: true
        type: local_keystore
        graffiti: "mrfwasheremrfwasheremrfwasheremrf"
        voting_keystore_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        "#;

        let def: Result<ValidatorDefinition, _> = serde_yaml::from_str(invalid_graffiti);
        assert!(def.is_err());

        let valid_graffiti = r#"---
        description: ""
        enabled: true
        type: local_keystore
        graffiti: "mrfwashere"
        voting_keystore_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        "#;

        let def: ValidatorDefinition = serde_yaml::from_str(valid_graffiti).unwrap();
        assert_eq!(
            def.graffiti,
            Some(GraffitiString::from_str("mrfwashere").unwrap())
        );
    }

    #[test]
    fn suggested_fee_recipient_checks() {
        let no_suggested_fee_recipient = r#"---
        description: ""
        enabled: true
        type: local_keystore
        voting_keystore_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        "#;
        let def: ValidatorDefinition = serde_yaml::from_str(no_suggested_fee_recipient).unwrap();
        assert!(def.suggested_fee_recipient.is_none());

        let invalid_suggested_fee_recipient = r#"---
        description: ""
        enabled: true
        type: local_keystore
        suggested_fee_recipient: "foopy"
        voting_keystore_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        "#;

        let def: Result<ValidatorDefinition, _> =
            serde_yaml::from_str(invalid_suggested_fee_recipient);
        assert!(def.is_err());

        let valid_suggested_fee_recipient = r#"---
        description: ""
        enabled: true
        type: local_keystore
        suggested_fee_recipient: "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"
        voting_keystore_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        "#;

        let def: ValidatorDefinition = serde_yaml::from_str(valid_suggested_fee_recipient).unwrap();
        assert_eq!(
            def.suggested_fee_recipient,
            Some(Address::from_str("0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d").unwrap())
        );
    }

    #[test]
    fn distributed_keystore_checks() {
        let dk_str = r#"---
        description: ""
        enabled: true
        type: distributed_keystore
        voting_keystore_share_path: ""
        voting_public_key: "0xaf3c7ddab7e293834710fca2d39d068f884455ede270e0d0293dc818e4f2f0f975355067e8437955cb29aec674e5c9e7"
        operator_committee_definition_path: ""
        operator_committee_index: 3
        operator_id: 5
        "#;
        let def: ValidatorDefinition = serde_yaml::from_str(dk_str).unwrap();
        match &def.signing_definition {
            SigningDefinition::DistributedKeystore {
                operator_committee_index,
                operator_id,
                ..
            } => {
                assert_eq!(*operator_committee_index, 3 as u64);
                assert_eq!(*operator_id, 5 as u64);
            }
            SigningDefinition::LocalKeystore { .. } => {
                panic!("Deserialization wrong");
            }
            SigningDefinition::Web3Signer { .. } => {
                panic!("Deserialization wrong");
            }
        };
    }
}
