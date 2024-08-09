//! Reference: lighthouse/validator_client/initialized_validators.rs
//!
//! Provides management of "initialized" validators.
//!
//! A validator is "initialized" if it is ready for signing blocks, attestations, etc in this
//! validator client.
//!
//! The `InitializedValidators` struct in this file serves as the source-of-truth of which
//! validators are managed by this validator client.
use crate::node::dvfcore::DvfSigner;
use crate::node::node::Node;
use crate::validation::account_utils::{
    read_password, read_password_from_user,
    validator_definitions::{
        self, SigningDefinition, ValidatorDefinition, ValidatorDefinitions, CONFIG_FILENAME,
    },
    ZeroizeString,
};
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::key_cache;
use crate::validation::key_cache::KeyCache;
use crate::validation::operator_committee_definitions::{self, OperatorCommitteeDefinition};
use crate::validation::signing_method::SigningMethod;
use crate::validation::validator_dir::share_builder::ShareBuilder;
use eth2::lighthouse_vc::std_types::DeleteKeystoreStatus;
use eth2_keystore::Keystore;
use lighthouse_metrics::set_gauge;
use lockfile::{Lockfile, LockfileError};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use reqwest::{Certificate, Error as ReqwestError};
use slog::{debug, error, info, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use types::graffiti::GraffitiString;
use types::{Address, EthSpec, Graffiti, Keypair, PublicKey, PublicKeyBytes};
use validator_dir::Builder as ValidatorDirBuilder;

// Use TTY instead of stdin to capture passwords from users.
const USE_STDIN: bool = false;

#[derive(Debug)]
pub enum Error {
    /// Refused to open a validator with an existing lockfile since that validator may be in-use by
    /// another process.
    Lockfile(LockfileError),
    /// The voting public key in the definition did not match the one in the keystore.
    VotingPublicKeyMismatch {
        definition: Box<PublicKey>,
        keystore: Box<PublicKey>,
    },
    /// There was a filesystem error when opening the keystore.
    UnableToOpenVotingKeystore(io::Error),
    UnableToOpenKeyCache(key_cache::Error),
    /// The keystore path is not as expected. It should be a file, not `..` or something obscure
    /// like that.
    BadVotingKeystorePath(PathBuf),
    BadKeyCachePath(PathBuf),
    /// The keystore could not be parsed, it is likely bad JSON.
    UnableToParseVotingKeystore(eth2_keystore::Error),
    /// The keystore could not be decrypted. The password might be wrong.
    UnableToDecryptKeystore(eth2_keystore::Error),
    /// There was a filesystem error when reading the keystore password from disk.
    UnableToReadVotingKeystorePassword(io::Error),
    /// There was an error updating the on-disk validator definitions file.
    UnableToSaveDefinitions(validator_definitions::Error),
    /// It is not legal to try and initialize a disabled validator definition.
    UnableToInitializeDisabledValidator,
    /// There was an error while deleting a keystore file.
    UnableToDeleteKeystore(PathBuf, io::Error),
    /// There was an error while deleting a validator dir.
    UnableToDeleteValidatorDir(PathBuf, io::Error),
    /// There was an error reading from stdin.
    UnableToReadPasswordFromUser(String),
    /// There was an error running a tokio async task.
    TokioJoin(tokio::task::JoinError),
    /// Cannot initialize the same validator twice.
    DuplicatePublicKey,
    /// The public key does not exist in the set of initialized validators.
    ValidatorNotInitialized(PublicKey),
    /// Unable to read the slot clock.
    SlotClock,
    /// The URL for the remote signer cannot be parsed.
    InvalidWeb3SignerUrl(String),
    /// Unable to read the root certificate file for the remote signer.
    InvalidWeb3SignerRootCertificateFile(io::Error),
    InvalidWeb3SignerRootCertificate(ReqwestError),
    /// Unable to read the client certificate for the remote signer.
    MissingWeb3SignerClientIdentityCertificateFile,
    MissingWeb3SignerClientIdentityPassword,
    InvalidWeb3SignerClientIdentityCertificateFile(io::Error),
    InvalidWeb3SignerClientIdentityCertificate(ReqwestError),
    UnableToBuildWeb3SignerClient(ReqwestError),
    /// Unable to apply an action to a validator.
    InvalidActionOnValidator,
    UnableToReadValidatorPassword(String),
    UnableToReadKeystoreFile(eth2_keystore::Error),
    UnableToSaveKeyCache(key_cache::Error),
    UnableToDecryptKeyCache(key_cache::Error),
    UnableToDeletePasswordFile(PathBuf, io::Error),

    NoCommitteeDefinition,
    UnableToParseCommitteeDefinition(operator_committee_definitions::Error),
    UnableToBuildCommittee,
    /// Unable to apply an action to a validator because it is using a remote signer.
    InvalidActionOnRemoteValidator,
    /// Error propogated from Dvf
    DvfError(String),
}

impl From<LockfileError> for Error {
    fn from(error: LockfileError) -> Self {
        Self::Lockfile(error)
    }
}

/// A validator that is ready to sign messages.
pub struct InitializedValidator {
    signing_method: Arc<SigningMethod>,
    graffiti: Option<Graffiti>,
    suggested_fee_recipient: Option<Address>,
    gas_limit: Option<u64>,
    builder_proposals: Option<bool>,
    builder_boost_factor: Option<u64>,
    prefer_builder_proposals: Option<bool>,
    /// The validators index in `state.validators`, to be updated by an external service.
    index: Option<u64>,
}

impl InitializedValidator {
    /// Return a reference to this validator's lockfile if it has one.
    pub fn keystore_lockfile(&self) -> Option<MappedMutexGuard<Lockfile>> {
        match self.signing_method.as_ref() {
            SigningMethod::LocalKeystore {
                ref voting_keystore_lockfile,
                ..
            } => MutexGuard::try_map(voting_keystore_lockfile.lock(), |option_lockfile| {
                option_lockfile.as_mut()
            })
            .ok(),
            // Web3Signer validators do not have any lockfiles.
            SigningMethod::Web3Signer { .. } => None,
            // [Zico]TODO: Should distributed validator have any lockfile?
            SigningMethod::DistributedKeystore {
                ref voting_keystore_share_lockfile,
                ..
            } => MutexGuard::try_map(voting_keystore_share_lockfile.lock(), |option_lockfile| {
                option_lockfile.as_mut()
            })
            .ok(),
        }
    }

    pub fn get_suggested_fee_recipient(&self) -> Option<Address> {
        self.suggested_fee_recipient
    }

    pub fn get_gas_limit(&self) -> Option<u64> {
        self.gas_limit
    }

    pub fn get_builder_boost_factor(&self) -> Option<u64> {
        self.builder_boost_factor
    }

    pub fn get_prefer_builder_proposals(&self) -> Option<bool> {
        self.prefer_builder_proposals
    }

    pub fn get_builder_proposals(&self) -> Option<bool> {
        self.builder_proposals
    }

    pub fn get_index(&self) -> Option<u64> {
        self.index
    }

    pub fn get_graffiti(&self) -> Option<Graffiti> {
        self.graffiti
    }
}

fn open_keystore(path: &Path) -> Result<Keystore, Error> {
    let keystore_file = File::open(path).map_err(Error::UnableToOpenVotingKeystore)?;
    Keystore::from_json_reader(keystore_file).map_err(Error::UnableToParseVotingKeystore)
}

fn open_keystore_share(path: &Path) -> Result<KeystoreShare, Error> {
    let keystore_share_file = File::open(path).map_err(Error::UnableToOpenVotingKeystore)?;
    KeystoreShare::from_json_reader(keystore_share_file).map_err(Error::UnableToParseVotingKeystore)
}

fn get_lockfile_path(file_path: &Path) -> Option<PathBuf> {
    file_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .map(|filename| file_path.with_file_name(format!("{}.lock", filename)))
}

impl InitializedValidator {
    /// Instantiate `self` from a `ValidatorDefinition`.
    ///
    /// If `stdin.is_some()` any missing passwords will result in a prompt requesting input on
    /// stdin (prompts published to stderr).
    ///
    /// ## Errors
    ///
    /// If the validator is unable to be initialized for whatever reason.
    async fn from_definition<T: EthSpec>(
        def: ValidatorDefinition,
        key_cache: &mut KeyCache,
        key_stores: &mut HashMap<PathBuf, Keystore>,
        node: Option<Arc<RwLock<Node<T>>>>,
    ) -> Result<Self, Error> {
        if !def.enabled {
            return Err(Error::UnableToInitializeDisabledValidator);
        }

        let signing_method = match def.signing_definition {
            // Load the keystore, password, decrypt the keypair and create a lockfile for a
            // EIP-2335 keystore on the local filesystem.
            SigningDefinition::LocalKeystore {
                voting_keystore_path,
                voting_keystore_password_path,
                voting_keystore_password,
            } => {
                use std::collections::hash_map::Entry::*;
                let voting_keystore = match key_stores.entry(voting_keystore_path.clone()) {
                    Vacant(entry) => entry.insert(open_keystore(&voting_keystore_path)?),
                    Occupied(entry) => entry.into_mut(),
                };

                let voting_keypair = if let Some(keypair) = key_cache.get(voting_keystore.uuid()) {
                    keypair
                } else {
                    let keystore = voting_keystore.clone();
                    let keystore_path = voting_keystore_path.clone();
                    // Decoding a local keystore can take several seconds, therefore it's best
                    // to keep if off the core executor. This also has the fortunate effect of
                    // interrupting the potentially long-running task during shut down.
                    let (password, keypair) = tokio::task::spawn_blocking(move || {
                        Result::<_, Error>::Ok(
                            match (voting_keystore_password_path, voting_keystore_password) {
                                // If the password is supplied, use it and ignore the path
                                // (if supplied).
                                (_, Some(password)) => (
                                    password.as_ref().to_vec().into(),
                                    keystore
                                        .decrypt_keypair(password.as_ref())
                                        .map_err(Error::UnableToDecryptKeystore)?,
                                ),
                                // If only the path is supplied, use the path.
                                (Some(path), None) => {
                                    let password = read_password(path)
                                        .map_err(Error::UnableToReadVotingKeystorePassword)?;
                                    let keypair = keystore
                                        .decrypt_keypair(password.as_bytes())
                                        .map_err(Error::UnableToDecryptKeystore)?;
                                    (password, keypair)
                                }
                                // If there is no password available, maybe prompt for a password.
                                (None, None) => {
                                    let (password, keypair) = unlock_keystore_via_stdin_password(
                                        &keystore,
                                        &keystore_path,
                                    )?;
                                    (password.as_ref().to_vec().into(), keypair)
                                }
                            },
                        )
                    })
                    .await
                    .map_err(Error::TokioJoin)??;
                    key_cache.add(keypair.clone(), voting_keystore.uuid(), password);
                    keypair
                };

                if voting_keypair.pk != def.voting_public_key {
                    return Err(Error::VotingPublicKeyMismatch {
                        definition: Box::new(def.voting_public_key),
                        keystore: Box::new(voting_keypair.pk),
                    });
                }

                // Append a `.lock` suffix to the voting keystore.
                let lockfile_path = get_lockfile_path(&voting_keystore_path)
                    .ok_or_else(|| Error::BadVotingKeystorePath(voting_keystore_path.clone()))?;

                let voting_keystore_lockfile = Mutex::new(Some(Lockfile::new(lockfile_path)?));

                SigningMethod::LocalKeystore {
                    voting_keystore_path,
                    voting_keystore_lockfile,
                    voting_keystore: voting_keystore.clone(),
                    voting_keypair: Arc::new(voting_keypair),
                }
            }

            SigningDefinition::Web3Signer { .. } => {
                return Err(Error::InvalidActionOnRemoteValidator)
            }

            // [Zico]TODO: To be revised
            SigningDefinition::DistributedKeystore {
                voting_keystore_share_path,
                voting_keystore_share_password_path,
                voting_keystore_share_password,
                operator_committee_definition_path,
                operator_committee_index: _,
                operator_id: _,
            } => {
                // [TODO] Zico: Start copying from LocalKeystore. Find a way to reuse.
                use std::collections::hash_map::Entry::*;
                let voting_keystore_share = open_keystore_share(&voting_keystore_share_path)?;
                let voting_keystore = match key_stores.entry(voting_keystore_share_path.clone()) {
                    Vacant(entry) => entry.insert(voting_keystore_share.keystore.clone()),
                    Occupied(entry) => entry.into_mut(),
                };

                let voting_keypair = if let Some(keypair) = key_cache.get(voting_keystore.uuid()) {
                    keypair
                } else {
                    let keystore = voting_keystore.clone();
                    let keystore_path = voting_keystore_share_path.clone();
                    // Decoding a keystore can take several seconds, therefore it's best
                    // to keep if off the core executor. This also has the fortunate effect of
                    // interrupting the potentially long-running task during shut down.
                    let (password, keypair) = tokio::task::spawn_blocking(move || {
                        Result::<_, Error>::Ok(
                            match (
                                voting_keystore_share_password_path,
                                voting_keystore_share_password,
                            ) {
                                // If the password is supplied, use it and ignore the path
                                // (if supplied).
                                (_, Some(password)) => (
                                    password.as_ref().to_vec().into(),
                                    keystore
                                        .decrypt_keypair(password.as_ref())
                                        .map_err(Error::UnableToDecryptKeystore)?,
                                ),
                                // If only the path is supplied, use the path.
                                (Some(path), None) => {
                                    let password = read_password(path)
                                        .map_err(Error::UnableToReadVotingKeystorePassword)?;
                                    let keypair = keystore
                                        .decrypt_keypair(password.as_bytes())
                                        .map_err(Error::UnableToDecryptKeystore)?;
                                    (password, keypair)
                                }
                                // If there is no password available, maybe prompt for a password.
                                (None, None) => {
                                    let (password, keypair) = unlock_keystore_via_stdin_password(
                                        &keystore,
                                        &keystore_path,
                                    )?;
                                    (password.as_ref().to_vec().into(), keypair)
                                }
                            },
                        )
                    })
                    .await
                    .map_err(Error::TokioJoin)??;
                    key_cache.add(keypair.clone(), voting_keystore.uuid(), password);
                    keypair
                };
                // [TODO] Zico: revisit this check, because def.voting_public_key is the master public key, while voting_keypair is a share.
                //if voting_keypair.pk != def.voting_public_key {
                //return Err(Error::VotingPublicKeyMismatch {
                //definition: Box::new(def.voting_public_key),
                //keystore: Box::new(voting_keypair.pk),
                //});
                //}

                // Append a `.lock` suffix to the voting keystore.
                let lockfile_path =
                    get_lockfile_path(&voting_keystore_share_path).ok_or_else(|| {
                        Error::BadVotingKeystorePath(voting_keystore_share_path.clone())
                    })?;
                let voting_keystore_share_lockfile =
                    Mutex::new(Some(Lockfile::new(lockfile_path)?));
                // [TODO] Zico: End copying from LocalKeystore. Find a way to reuse.
                let committee_def_path =
                    operator_committee_definition_path.ok_or(Error::NoCommitteeDefinition)?;
                let committee_def = OperatorCommitteeDefinition::from_file(committee_def_path)
                    .map_err(Error::UnableToParseCommitteeDefinition)?;
                let validator_public_key = committee_def.validator_public_key.clone();
                let signer = DvfSigner::spawn(node.unwrap(), voting_keypair, committee_def)
                    .await
                    .map_err(|e| Error::DvfError(format!("{:?}", e)))?;

                SigningMethod::DistributedKeystore {
                    voting_keystore_share_path,
                    voting_keystore_share_lockfile,
                    voting_keystore_share,
                    voting_public_key: validator_public_key,
                    dvf_signer: signer,
                }
            }
        };

        Ok(Self {
            signing_method: Arc::new(signing_method),
            graffiti: def.graffiti.map(Into::into),
            suggested_fee_recipient: def.suggested_fee_recipient,
            gas_limit: def.gas_limit,
            builder_proposals: def.builder_proposals,
            builder_boost_factor: def.builder_boost_factor,
            prefer_builder_proposals: def.prefer_builder_proposals,
            index: None,
        })
    }

    /// Returns the voting public key for this validator.
    pub fn voting_public_key(&self) -> &PublicKey {
        match self.signing_method.as_ref() {
            SigningMethod::LocalKeystore { voting_keypair, .. } => &voting_keypair.pk,
            SigningMethod::Web3Signer {
                voting_public_key, ..
            } => voting_public_key,
            // [Zico]TODO: To be revised
            SigningMethod::DistributedKeystore {
                voting_public_key, ..
            } => voting_public_key,
        }
    }
}

pub fn load_pem_certificate<P: AsRef<Path>>(pem_path: P) -> Result<Certificate, Error> {
    let mut buf = Vec::new();
    File::open(&pem_path)
        .map_err(Error::InvalidWeb3SignerRootCertificateFile)?
        .read_to_end(&mut buf)
        .map_err(Error::InvalidWeb3SignerRootCertificateFile)?;
    Certificate::from_pem(&buf).map_err(Error::InvalidWeb3SignerRootCertificate)
}

/// Try to unlock `keystore` at `keystore_path` by prompting the user via `stdin`.
fn unlock_keystore_via_stdin_password(
    keystore: &Keystore,
    keystore_path: &Path,
) -> Result<(ZeroizeString, Keypair), Error> {
    eprintln!();
    eprintln!(
        "The {} file does not contain either of the following fields for {:?}:",
        CONFIG_FILENAME, keystore_path
    );
    eprintln!();
    eprintln!(" - voting_keystore_password");
    eprintln!(" - voting_keystore_password_path");
    eprintln!();
    eprintln!(
        "You may exit and update {} or enter a password. \
                            If you choose to enter a password now then this prompt \
                            will be raised next time the validator is started.",
        CONFIG_FILENAME
    );
    eprintln!();
    eprintln!("Enter password (or press Ctrl+c to exit):");

    loop {
        let password =
            read_password_from_user(USE_STDIN).map_err(Error::UnableToReadPasswordFromUser)?;

        eprintln!();

        match keystore.decrypt_keypair(password.as_ref()) {
            Ok(keystore) => break Ok((password, keystore)),
            Err(eth2_keystore::Error::InvalidPassword) => {
                eprintln!("Invalid password, try again (or press Ctrl+c to exit):");
            }
            Err(e) => return Err(Error::UnableToDecryptKeystore(e)),
        }
    }
}

/// A set of `InitializedValidator` objects which is initialized from a list of
/// `ValidatorDefinition`. The `ValidatorDefinition` file is maintained as `self` is modified.
///
/// Forms the fundamental list of validators that are managed by this validator client instance.
///
pub struct InitializedValidators<T: EthSpec> {
    /// A list of validator definitions which can be stored on-disk.
    definitions: ValidatorDefinitions,
    /// The directory that the `self.definitions` will be saved into.
    validators_dir: PathBuf,
    /// The canonical set of validators.
    validators: HashMap<PublicKeyBytes, InitializedValidator>,
    /// The hotstuff node (only used for decentralized signing)
    node: Option<Arc<RwLock<Node<T>>>>,
    /// For logging via `slog`.
    log: Logger,
}

impl<T: EthSpec> InitializedValidators<T> {
    /// Instantiates `Self`, initializing all validators in `definitions`.
    pub async fn from_definitions(
        definitions: ValidatorDefinitions,
        validators_dir: PathBuf,
        node: Option<Arc<RwLock<Node<T>>>>,
        log: Logger,
    ) -> Result<Self, Error> {
        let mut this = Self {
            validators_dir,
            definitions,
            validators: HashMap::<PublicKeyBytes, InitializedValidator>::default(),
            node,
            log,
        };
        this.update_validators().await?;
        Ok(this)
    }

    /// The count of enabled validators contained in `self`.
    pub fn num_enabled(&self) -> usize {
        self.validators.len()
    }

    /// The total count of enabled and disabled validators contained in `self`.
    pub fn num_total(&self) -> usize {
        self.definitions.as_slice().len()
    }

    /// Iterate through all voting public keys in `self` that should be used when querying for duties.
    pub fn iter_voting_pubkeys(&self) -> impl Iterator<Item = &PublicKeyBytes> {
        self.validators.iter().map(|(pubkey, _)| pubkey)
    }

    /// Returns the voting `Keypair` for a given voting `PublicKey`, if all are true:
    ///
    ///  - The validator is known to `self`.
    ///  - The validator is enabled.
    pub fn signing_method(&self, voting_public_key: &PublicKeyBytes) -> Option<Arc<SigningMethod>> {
        self.validators
            .get(voting_public_key)
            .map(|v| v.signing_method.clone())
    }

    /// Add a validator definition to `self`, replacing any disabled definition with the same
    /// voting public key.
    ///
    /// The on-disk representation of the validator definitions & the key cache will both be
    /// updated.
    pub async fn add_definition_replace_disabled(
        &mut self,
        def: ValidatorDefinition,
    ) -> Result<(), Error> {
        // Drop any disabled definitions with the same public key.
        let delete_def = |existing_def: &ValidatorDefinition| {
            !existing_def.enabled && existing_def.voting_public_key == def.voting_public_key
        };
        self.definitions.retain(|def| !delete_def(def));

        // Add the definition.
        self.add_definition(def).await
    }

    /// Add a validator definition to `self`, overwriting the on-disk representation of `self`.
    pub async fn add_definition(&mut self, def: ValidatorDefinition) -> Result<(), Error> {
        if self
            .definitions
            .as_slice()
            .iter()
            .any(|existing| existing.voting_public_key == def.voting_public_key)
        {
            return Err(Error::DuplicatePublicKey);
        }

        self.definitions.push(def);

        self.update_validators().await?;
        info!(self.log, "update_validators returned");
        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Delete the validator definition and keystore for `pubkey`.
    ///
    /// The delete is carried out in stages so that the filesystem is never left in an inconsistent
    /// state, even in case of errors or crashes.
    pub async fn delete_definition_and_keystore(
        &mut self,
        pubkey: &PublicKey,
    ) -> Result<DeleteKeystoreStatus, Error> {
        // 1. Disable the validator definition.
        //
        // We disable before removing so that in case of a crash the auto-discovery mechanism
        // won't re-activate the keystore.
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| &def.voting_public_key == pubkey)
        {
            // [Zico]TODO: to be revised
            if def.signing_definition.is_local_keystore()
                || def.signing_definition.is_distributed_keystore()
            {
                def.enabled = false;
                self.definitions
                    .save(&self.validators_dir)
                    .map_err(Error::UnableToSaveDefinitions)?;
            } else {
                return Err(Error::InvalidActionOnRemoteValidator);
            }
        } else {
            return Ok(DeleteKeystoreStatus::NotFound);
        }

        // 2. Delete from `self.validators`, which holds the signing method.
        //    Delete the keystore files.
        if let Some(initialized_validator) = self.validators.remove(&pubkey.compress()) {
            if let SigningMethod::LocalKeystore {
                ref voting_keystore_path,
                ref voting_keystore_lockfile,
                ref voting_keystore,
                ..
            } = *initialized_validator.signing_method
            {
                // Drop the lock file so that it may be deleted. This is particularly important on
                // Windows where the lockfile will fail to be deleted if it is still open.
                drop(voting_keystore_lockfile.lock().take());

                self.delete_keystore_or_validator_dir(voting_keystore_path, voting_keystore)?;
            }

            // [Zico]TODO: to be revised
            if let SigningMethod::DistributedKeystore {
                ref voting_keystore_share_path,
                ref voting_keystore_share_lockfile,
                ref voting_keystore_share,
                ..
            } = *initialized_validator.signing_method
            {
                drop(voting_keystore_share_lockfile.lock().take());
                self.delete_keystore_share_or_validator_dir(
                    voting_keystore_share_path,
                    voting_keystore_share,
                )?;
            }
        }

        // 3. Delete from validator definitions entirely.
        self.definitions
            .retain(|def| &def.voting_public_key != pubkey);
        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(DeleteKeystoreStatus::Deleted)
    }

    // enable a keystore
    pub async fn enable_keystore(&mut self, pubkey: &PublicKey) -> Result<(), Error> {
        self.set_validator_definition_fields(pubkey, Some(true), None, None)
            .await?;
        Ok(())
    }

    // remove keystore but preserve definition
    pub async fn disable_keystore(
        &mut self,
        pubkey: &PublicKey,
    ) -> Result<DeleteKeystoreStatus, Error> {
        // 1. Disable the validator definition.
        //
        // We disable before removing so that in case of a crash the auto-discovery mechanism
        // won't re-activate the keystore.
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| &def.voting_public_key == pubkey)
        {
            // [Zico]TODO: to be revised
            if def.signing_definition.is_local_keystore()
                || def.signing_definition.is_distributed_keystore()
            {
                def.enabled = false;
                self.definitions
                    .save(&self.validators_dir)
                    .map_err(Error::UnableToSaveDefinitions)?;
            } else {
                return Err(Error::InvalidActionOnRemoteValidator);
            }
        } else {
            return Ok(DeleteKeystoreStatus::NotFound);
        }

        // 2. Delete from `self.validators`, which holds the signing method.
        //    Delete the keystore files.
        if let Some(initialized_validator) = self.validators.remove(&pubkey.compress()) {
            if let SigningMethod::LocalKeystore {
                ref voting_keystore_lockfile,
                ..
            } = *initialized_validator.signing_method
            {
                // Drop the lock file so that it may be deleted. This is particularly important on
                // Windows where the lockfile will fail to be deleted if it is still open.
                drop(voting_keystore_lockfile.lock().take());
            }

            // [Zico]TODO: to be revised
            if let SigningMethod::DistributedKeystore {
                ref voting_keystore_share_lockfile,
                ..
            } = *initialized_validator.signing_method
            {
                drop(voting_keystore_share_lockfile.lock().take());
            }
        }
        Ok(DeleteKeystoreStatus::Deleted)
    }

    /// Attempt to delete the voting keystore file, or its entire validator directory.
    ///
    /// Some parts of the VC assume the existence of a validator based on the existence of a
    /// directory in the validators dir named like a public key.
    fn delete_keystore_or_validator_dir(
        &self,
        voting_keystore_path: &Path,
        voting_keystore: &Keystore,
    ) -> Result<(), Error> {
        // If the parent directory is a `ValidatorDir` within `self.validators_dir`, then
        // delete the entire directory so that it may be recreated if the keystore is
        // re-imported.
        if let Some(validator_dir) = voting_keystore_path.parent() {
            if validator_dir
                == ValidatorDirBuilder::get_dir_path(&self.validators_dir, voting_keystore)
            {
                fs::remove_dir_all(validator_dir)
                    .map_err(|e| Error::UnableToDeleteValidatorDir(validator_dir.into(), e))?;
                return Ok(());
            }
        }
        // Otherwise just delete the keystore file.
        fs::remove_file(voting_keystore_path)
            .map_err(|e| Error::UnableToDeleteKeystore(voting_keystore_path.into(), e))?;
        Ok(())
    }

    /// Attempt to delete the voting keystore file, or its entire validator directory.
    ///
    /// Some parts of the VC assume the existence of a validator based on the existence of a
    /// directory in the validators dir named like a public key.
    fn delete_keystore_share_or_validator_dir(
        &self,
        voting_keystore_share_path: &Path,
        voting_keystore_share: &KeystoreShare,
    ) -> Result<(), Error> {
        // If the parent directory is a `ValidatorDir` within `self.validators_dir`, then
        // delete the entire directory so that it may be recreated if the keystore is
        // re-imported.
        if let Some(validator_dir) = voting_keystore_share_path.parent() {
            if validator_dir
                == ShareBuilder::get_dir_path(&self.validators_dir, voting_keystore_share)
            {
                fs::remove_dir_all(validator_dir)
                    .map_err(|e| Error::UnableToDeleteValidatorDir(validator_dir.into(), e))?;
                return Ok(());
            }
        }
        // Otherwise just delete the keystore file.
        fs::remove_file(voting_keystore_share_path)
            .map_err(|e| Error::UnableToDeleteKeystore(voting_keystore_share_path.into(), e))?;
        Ok(())
    }

    /// Returns a slice of all defined validators (regardless of their enabled state).
    pub fn validator_definitions(&self) -> &[ValidatorDefinition] {
        self.definitions.as_slice()
    }

    pub fn validator_definitions_(&mut self) -> &mut ValidatorDefinitions {
        &mut self.definitions
    }

    /// Indicates if the `voting_public_key` exists in self and if it is enabled.
    pub fn is_enabled(&self, voting_public_key: &PublicKey) -> Option<bool> {
        self.definitions
            .as_slice()
            .iter()
            .find(|def| def.voting_public_key == *voting_public_key)
            .map(|def| def.enabled)
    }

    /// Returns the `graffiti` for a given public key specified in the `ValidatorDefinitions`.
    pub fn graffiti(&self, public_key: &PublicKeyBytes) -> Option<Graffiti> {
        self.validators.get(public_key).and_then(|v| v.graffiti)
    }

    /// Sets the `InitializedValidator` and `ValidatorDefinition` `graffiti` values.
    ///
    /// ## Notes
    ///
    /// Setting a validator `graffiti` will cause `self.definitions` to be updated and saved to
    /// disk.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn set_graffiti(
        &mut self,
        voting_public_key: &PublicKey,
        graffiti: GraffitiString,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.graffiti = Some(graffiti.clone());
        }

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            val.graffiti = Some(graffiti.into());
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;
        Ok(())
    }

    /// Removes the `InitializedValidator` and `ValidatorDefinition` `graffiti` values.
    ///
    /// ## Notes
    ///
    /// Removing a validator `graffiti` will cause `self.definitions` to be updated and saved to
    /// disk. The graffiti for the validator will then fall back to the process level default if
    /// it is set.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn delete_graffiti(&mut self, voting_public_key: &PublicKey) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.graffiti = None;
        }

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            val.graffiti = None;
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Returns a `HashMap` of `public_key` -> `graffiti` for all initialized validators.
    pub fn get_all_validators_graffiti(&self) -> HashMap<&PublicKeyBytes, Option<Graffiti>> {
        let mut result = HashMap::new();
        for public_key in self.validators.keys() {
            result.insert(public_key, self.graffiti(public_key));
        }
        result
    }

    /// Returns the `suggested_fee_recipient` for a given public key specified in the
    /// `ValidatorDefinitions`.
    pub fn suggested_fee_recipient(&self, public_key: &PublicKeyBytes) -> Option<Address> {
        self.validators
            .get(public_key)
            .and_then(|v| v.suggested_fee_recipient)
    }

    /// Returns the `gas_limit` for a given public key specified in the
    /// `ValidatorDefinitions`.
    pub fn gas_limit(&self, public_key: &PublicKeyBytes) -> Option<u64> {
        self.validators.get(public_key).and_then(|v| v.gas_limit)
    }

    /// Returns the `builder_proposals` for a given public key specified in the
    /// `ValidatorDefinitions`.
    pub fn builder_proposals(&self, public_key: &PublicKeyBytes) -> Option<bool> {
        self.validators
            .get(public_key)
            .and_then(|v| v.builder_proposals)
    }

    /// Returns the `builder_boost_factor` for a given public key specified in the
    /// `ValidatorDefinitions`.
    pub fn builder_boost_factor(&self, public_key: &PublicKeyBytes) -> Option<u64> {
        self.validators
            .get(public_key)
            .and_then(|v| v.builder_boost_factor)
    }

    /// Returns the `prefer_builder_proposals` for a given public key specified in the
    /// `ValidatorDefinitions`.
    pub fn prefer_builder_proposals(&self, public_key: &PublicKeyBytes) -> Option<bool> {
        self.validators
            .get(public_key)
            .and_then(|v| v.prefer_builder_proposals)
    }

    /// Returns an `Option` of a reference to an `InitializedValidator` for a given public key specified in the
    /// `ValidatorDefinitions`.
    pub fn validator(&self, public_key: &PublicKeyBytes) -> Option<&InitializedValidator> {
        self.validators.get(public_key)
    }

    /// Sets the `InitializedValidator` and `ValidatorDefinition` `enabled`, `gas_limit`, and `builder_proposals`
    /// values.
    ///
    /// ## Notes
    ///
    /// Enabling or disabling a validator will cause `self.definitions` to be updated and saved to
    /// disk. A newly enabled validator will be added to `self.validators`, whilst a newly disabled
    /// validator will be removed from `self.validators`.
    ///
    /// If a `gas_limit` is included in the call to this function, it will also be updated and saved
    /// to disk. If `gas_limit` is `None` the `gas_limit` *will not* be unset in `ValidatorDefinition`
    /// or `InitializedValidator`. The same logic applies to `builder_proposals`.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub async fn set_validator_definition_fields(
        &mut self,
        voting_public_key: &PublicKey,
        enabled: Option<bool>,
        gas_limit: Option<u64>,
        builder_proposals: Option<bool>,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            // Don't overwrite fields if they are not set in this request.
            if let Some(enabled) = enabled {
                def.enabled = enabled;
            }
            if let Some(gas_limit) = gas_limit {
                def.gas_limit = Some(gas_limit);
            }
            if let Some(builder_proposals) = builder_proposals {
                def.builder_proposals = Some(builder_proposals);
            }
        }

        self.update_validators().await?;

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            // Don't overwrite fields if they are not set in this request.
            if let Some(gas_limit) = gas_limit {
                val.gas_limit = Some(gas_limit);
            }
            if let Some(builder_proposals) = builder_proposals {
                val.builder_proposals = Some(builder_proposals);
            }
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Sets the `InitializedValidator` and `ValidatorDefinition` `suggested_fee_recipient` values.
    ///
    /// ## Notes
    ///
    /// Setting a validator `fee_recipient` will cause `self.definitions` to be updated and saved to
    /// disk.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn set_validator_fee_recipient(
        &mut self,
        voting_public_key: &PublicKey,
        fee_recipient: Address,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.suggested_fee_recipient = Some(fee_recipient);
        }

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            val.suggested_fee_recipient = Some(fee_recipient);
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Removes the `InitializedValidator` and `ValidatorDefinition` `suggested_fee_recipient` values.
    ///
    /// ## Notes
    ///
    /// Removing a validator `fee_recipient` will cause `self.definitions` to be updated and saved to
    /// disk. The fee_recipient for the validator will then fall back to the process level default if
    /// it is set.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn delete_validator_fee_recipient(
        &mut self,
        voting_public_key: &PublicKey,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.suggested_fee_recipient = None;
        }

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            val.suggested_fee_recipient = None;
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Sets the `InitializedValidator` and `ValidatorDefinition` `gas_limit` values.
    ///
    /// ## Notes
    ///
    /// Setting a validator `gas_limit` will cause `self.definitions` to be updated and saved to
    /// disk.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn set_validator_gas_limit(
        &mut self,
        voting_public_key: &PublicKey,
        gas_limit: u64,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.gas_limit = Some(gas_limit);
        }

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            val.gas_limit = Some(gas_limit);
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Removes the `InitializedValidator` and `ValidatorDefinition` `gas_limit` values.
    ///
    /// ## Notes
    ///
    /// Removing a validator `gas_limit` will cause `self.definitions` to be updated and saved to
    /// disk. The gas_limit for the validator will then fall back to the process level default if
    /// it is set.
    ///
    /// Saves the `ValidatorDefinitions` to file, even if no definitions were changed.
    pub fn delete_validator_gas_limit(
        &mut self,
        voting_public_key: &PublicKey,
    ) -> Result<(), Error> {
        if let Some(def) = self
            .definitions
            .as_mut_slice()
            .iter_mut()
            .find(|def| def.voting_public_key == *voting_public_key)
        {
            def.gas_limit = None;
        }

        if let Some(val) = self
            .validators
            .get_mut(&PublicKeyBytes::from(voting_public_key))
        {
            val.gas_limit = None;
        }

        self.definitions
            .save(&self.validators_dir)
            .map_err(Error::UnableToSaveDefinitions)?;

        Ok(())
    }

    /// Tries to decrypt the key cache.
    ///
    /// Returns the decrypted cache if decryption was successful, or an error if a required password
    /// wasn't provided and couldn't be read interactively.
    ///
    /// In the case that the cache contains UUIDs for unknown validator definitions then it cannot
    /// be decrypted and will be replaced by a new empty cache.
    ///
    /// The mutable `key_stores` argument will be used to accelerate decyption by bypassing
    /// filesystem accesses for keystores that are already known. In the case that a keystore
    /// from the validator definitions is not yet in this map, it will be loaded from disk and
    /// inserted into the map.
    async fn decrypt_key_cache(
        &self,
        mut cache: KeyCache,
        key_stores: &mut HashMap<PathBuf, Keystore>,
    ) -> Result<KeyCache, Error> {
        // Read relevant key stores from the filesystem.
        let mut definitions_map = HashMap::new();
        for def in self.definitions.as_slice().iter().filter(|def| def.enabled) {
            match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_path,
                    ..
                } => {
                    use std::collections::hash_map::Entry::*;
                    let key_store = match key_stores.entry(voting_keystore_path.clone()) {
                        Vacant(entry) => entry.insert(open_keystore(voting_keystore_path)?),
                        Occupied(entry) => entry.into_mut(),
                    };
                    definitions_map.insert(*key_store.uuid(), def);
                }
                // Remote signer validators don't interact with the key cache.
                SigningDefinition::Web3Signer { .. } => (),
                // [Zico]TODO: to be revised
                SigningDefinition::DistributedKeystore { .. } => (),
            }
        }

        //check if all paths are in the definitions_map
        for uuid in cache.uuids() {
            if !definitions_map.contains_key(uuid) {
                debug!(
                    self.log,
                    "Resetting the key cache";
                    "keystore_uuid" => %uuid,
                    "reason" => "impossible to decrypt due to missing keystore",
                );
                return Ok(KeyCache::new());
            }
        }

        //collect passwords
        let mut passwords = Vec::new();
        let mut public_keys = Vec::new();
        for uuid in cache.uuids() {
            let def = definitions_map.get(uuid).expect("Existence checked before");
            match &def.signing_definition {
                SigningDefinition::LocalKeystore {
                    voting_keystore_password_path,
                    voting_keystore_password,
                    voting_keystore_path,
                } => {
                    let pw = if let Some(p) = voting_keystore_password {
                        p.as_ref().to_vec().into()
                    } else if let Some(path) = voting_keystore_password_path {
                        read_password(path).map_err(Error::UnableToReadVotingKeystorePassword)?
                    } else {
                        let keystore = open_keystore(voting_keystore_path)?;
                        unlock_keystore_via_stdin_password(&keystore, voting_keystore_path)?
                            .0
                            .as_ref()
                            .to_vec()
                            .into()
                    };
                    passwords.push(pw);
                    public_keys.push(def.voting_public_key.clone());
                }
                // Remote signer validators don't interact with the key cache.
                SigningDefinition::Web3Signer { .. } => (),
                // [Zico]TODO: to be revised
                SigningDefinition::DistributedKeystore { .. } => (),
            };
        }

        //decrypt
        tokio::task::spawn_blocking(move || match cache.decrypt(passwords, public_keys) {
            Ok(_) | Err(key_cache::Error::AlreadyDecrypted) => cache,
            _ => KeyCache::new(),
        })
        .await
        .map_err(Error::TokioJoin)
    }

    /// Scans `self.definitions` and attempts to initialize and validators which are not already
    /// initialized.
    ///
    /// The function exits early with an error if any enabled validator is unable to be
    /// initialized.
    ///
    /// ## Notes
    ///
    /// A validator is considered "already known" and skipped if the public key is already known.
    /// I.e., if there are two different definitions with the same public key then the second will
    /// be ignored.
    pub(crate) async fn update_validators(&mut self) -> Result<(), Error> {
        //use key cache if available
        let mut key_stores = HashMap::new();
        //let mut committee_cache = HashMap::new();

        // Create a lock file for the cache
        let key_cache_path = KeyCache::cache_file_path(&self.validators_dir);
        let cache_lockfile_path =
            get_lockfile_path(&key_cache_path).ok_or(Error::BadKeyCachePath(key_cache_path))?;
        let _cache_lockfile = Lockfile::new(cache_lockfile_path)?;

        let cache =
            KeyCache::open_or_create(&self.validators_dir).map_err(Error::UnableToOpenKeyCache)?;
        let mut key_cache = self.decrypt_key_cache(cache, &mut key_stores).await?;

        let mut disabled_uuids = HashSet::new();
        for def in self.definitions.as_slice() {
            if def.enabled {
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        ..
                    } => {
                        let pubkey_bytes = def.voting_public_key.compress();

                        if self.validators.contains_key(&pubkey_bytes) {
                            continue;
                        }

                        if let Some(key_store) = key_stores.get(voting_keystore_path) {
                            disabled_uuids.remove(key_store.uuid());
                        }

                        match InitializedValidator::from_definition::<T>(
                            def.clone(),
                            &mut key_cache,
                            &mut key_stores,
                            //&mut committee_cache,
                            None,
                        )
                        .await
                        {
                            Ok(init) => {
                                let existing_lockfile_path = init
                                    .keystore_lockfile()
                                    .as_ref()
                                    .filter(|l| l.file_existed())
                                    .map(|l| l.path().to_owned());

                                self.validators
                                    .insert(init.voting_public_key().compress(), init);
                                info!(
                                    self.log,
                                    "Enabled validator";
                                    "signing_method" => "local_keystore",
                                    "voting_pubkey" => format!("{:?}", def.voting_public_key),
                                );

                                if let Some(lockfile_path) = existing_lockfile_path {
                                    warn!(
                                        self.log,
                                        "Ignored stale lockfile";
                                        "path" => lockfile_path.display(),
                                        "cause" => "Ungraceful shutdown (harmless) OR \
                                                    non-Lighthouse client using this keystore \
                                                    (risky)"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to initialize validator";
                                    "error" => format!("{:?}", e),
                                    "signing_method" => "local_keystore",
                                    "validator" => format!("{:?}", def.voting_public_key)
                                );

                                // Exit on an invalid validator.
                                return Err(e);
                            }
                        }
                    }
                    SigningDefinition::Web3Signer { .. } => {
                        match InitializedValidator::from_definition::<T>(
                            def.clone(),
                            &mut key_cache,
                            &mut key_stores,
                            //&mut committee_cache,
                            None,
                        )
                        .await
                        {
                            Ok(init) => {
                                self.validators
                                    .insert(init.voting_public_key().compress(), init);

                                info!(
                                    self.log,
                                    "Enabled validator";
                                    "signing_method" => "remote_signer",
                                    "voting_pubkey" => format!("{:?}", def.voting_public_key),
                                );
                            }
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to initialize validator";
                                    "error" => format!("{:?}", e),
                                    "signing_method" => "remote_signer",
                                    "validator" => format!("{:?}", def.voting_public_key)
                                );

                                // Exit on an invalid validator.
                                return Err(e);
                            }
                        }
                    }
                    // [Zico]TODO: to be revised
                    SigningDefinition::DistributedKeystore {
                        voting_keystore_share_path,
                        operator_committee_index,
                        operator_id,
                        ..
                    } => {
                        let pubkey_bytes = def.voting_public_key.compress();

                        // [TODO] Zico: revisit here
                        if self.validators.contains_key(&pubkey_bytes) {
                            continue;
                        }

                        if let Some(key_store) = key_stores.get(voting_keystore_share_path) {
                            disabled_uuids.remove(key_store.uuid());
                        }

                        match InitializedValidator::from_definition(
                            def.clone(),
                            &mut key_cache,
                            &mut key_stores,
                            //&mut committee_cache,
                            self.node.clone(),
                        )
                        .await
                        {
                            Ok(init) => {
                                let existing_lockfile_path = init
                                    .keystore_lockfile()
                                    .as_ref()
                                    .filter(|l| l.file_existed())
                                    .map(|l| l.path().to_owned());

                                self.validators
                                    .insert(init.voting_public_key().compress(), init);
                                info!(
                                    self.log,
                                    "Enabled validator";
                                    "signing_method" => "distributed_keystore",
                                    "voting_pubkey" => format!("{:?}", def.voting_public_key),
                                    "operator/validator" => format!("{}/{}", operator_id, operator_committee_index),
                                );

                                if let Some(lockfile_path) = existing_lockfile_path {
                                    warn!(
                                        self.log,
                                        "Ignored stale lockfile";
                                        "path" => lockfile_path.display(),
                                        "cause" => "Ungraceful shutdown (harmless) OR \
                                                    non-Lighthouse client using this keystore \
                                                    (risky)"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to initialize validator";
                                    "error" => format!("{:?}", e),
                                    "signing_method" => "distributed_keystore",
                                    "validator" => format!("{:?}", def.voting_public_key),
                                    "operator/validator" => format!("{}/{}", operator_id, operator_committee_index),
                                );

                                // Exit on an invalid validator. zico: Do we need to?
                                // return Err(e);
                            }
                        }
                    }
                }
            } else {
                self.validators.remove(&def.voting_public_key.compress());
                match &def.signing_definition {
                    SigningDefinition::LocalKeystore {
                        voting_keystore_path,
                        ..
                    } => {
                        if let Some(key_store) = key_stores.get(voting_keystore_path) {
                            disabled_uuids.insert(*key_store.uuid());
                        }
                    }
                    // Remote signers do not interact with the key cache.
                    SigningDefinition::Web3Signer { .. } => (),
                    // [Zico]TODO: to be revised
                    SigningDefinition::DistributedKeystore {
                        voting_keystore_share_path,
                        ..
                    } => {
                        if let Some(key_store) = key_stores.get(voting_keystore_share_path) {
                            disabled_uuids.insert(*key_store.uuid());
                        }
                    }
                }

                info!(
                    self.log,
                    "Disabled validator";
                    "voting_pubkey" => format!("{:?}", def.voting_public_key)
                );
            }
        }

        for uuid in disabled_uuids {
            key_cache.remove(&uuid);
        }

        let validators_dir = self.validators_dir.clone();
        let log = self.log.clone();
        if key_cache.is_modified() {
            tokio::task::spawn_blocking(move || {
                match key_cache.save(validators_dir) {
                    Err(e) => warn!(
                        log,
                        "Error during saving of key_cache";
                        "err" => format!("{:?}", e)
                    ),
                    Ok(true) => info!(log, "Modified key_cache saved successfully"),
                    _ => {}
                };
            })
            .await
            .map_err(Error::TokioJoin)?;
        } else {
            debug!(log, "Key cache not modified");
        }
        info!(self.log, "After Modified key_cache saved successfully");
        // Update the enabled and total validator counts
        set_gauge(
            &crate::validation::http_metrics::metrics::ENABLED_VALIDATORS_COUNT,
            self.num_enabled() as i64,
        );
        set_gauge(
            &crate::validation::http_metrics::metrics::TOTAL_VALIDATORS_COUNT,
            self.num_total() as i64,
        );
        info!(self.log, "update Modified key_cache returned");
        Ok(())
    }

    pub fn get_index(&self, pubkey: &PublicKeyBytes) -> Option<u64> {
        self.validators.get(pubkey).and_then(|val| val.index)
    }

    pub fn set_index(&mut self, pubkey: &PublicKeyBytes, index: u64) {
        if let Some(val) = self.validators.get_mut(pubkey) {
            val.index = Some(index);
        }
    }
}
