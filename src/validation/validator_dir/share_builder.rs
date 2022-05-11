//! Reference: lighthouse/common/validator_dir::builder

use crate::crypto::{ThresholdSignature};
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::operator_committee_definitions::{OperatorCommitteeDefinition, OperatorCommitteeDefinitions};
use crate::validation::account_utils::{default_operator_committee_definition_path};
use validator_dir::{ValidatorDir, BuilderError};
use std::path::{Path, PathBuf};
use validator_dir::insecure_keys::{INSECURE_PASSWORD,};
use types::test_utils::generate_deterministic_keypair;
use eth2_keystore::{
    json_keystore::{Kdf, Scrypt},
    Keystore, KeystoreBuilder, PlainText, DKLEN,
};
use std::fs::{create_dir_all, File};
use filesystem::create_with_600_perms;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};


pub const VOTING_KEYSTORE_SHARE_FILE: &str = "voting-keystore-share.json";

/// A builder for creating a `ValidatorDir` that stores a share of a voting keystore.
pub struct ShareBuilder {
    base_validators_dir: PathBuf,
    password_dir: Option<PathBuf>,
    pub(crate) voting_keystore_share: Option<(KeystoreShare, PlainText)>,
}

impl ShareBuilder {
    /// Instantiate a new builder.
    pub fn new(base_validators_dir: PathBuf) -> Self {
        Self {
            base_validators_dir,
            password_dir: None,
            voting_keystore_share: None,
        }
    }

    /// Supply a directory in which to store the passwords for the validator keystores.
    pub fn password_dir<P: Into<PathBuf>>(mut self, password_dir: P) -> Self {
        self.password_dir = Some(password_dir.into());
        self
    }

    /// Build the `ValidatorDir` use the given `keystore` which can be unlocked with `password`.
    ///
    /// The builder will not necessarily check that `password` can unlock `keystore`.
    pub fn voting_keystore_share(mut self, keystore_share: KeystoreShare, password: &[u8]) -> Self {
        self.voting_keystore_share = Some((keystore_share, password.to_vec().into()));
        self
    }

    /// Return the path to the validator dir to be built, i.e. `base_dir/pubkey`.
    pub fn get_dir_path(base_validators_dir: &Path, voting_keystore_share: &Keystore) -> PathBuf {
        base_validators_dir.join(format!("0x{}", voting_keystore_share.pubkey()))
    }

    /// Consumes `self`, returning a `ValidatorDir` if no error is encountered.
    pub fn build(self) -> Result<ValidatorDir, BuilderError> {
        let (voting_keystore_share, voting_password) = self
            .voting_keystore_share
            .ok_or(BuilderError::UninitializedVotingKeystore)?;
        let voting_public_key = &voting_keystore_share.master_public_key;

        let dir = self.base_validators_dir
            .join(format!("{}", &voting_public_key))
            .join(format!("{}", voting_keystore_share.share_id));

        if dir.exists() {
            return Err(BuilderError::DirectoryAlreadyExists(dir));
        } else {
            create_dir_all(&dir).map_err(BuilderError::UnableToCreateDir)?;
        }

        if let Some(password_dir) = self.password_dir.as_ref() {
            // Write the voting password to file.
            write_password_to_file(
                password_dir.join(format!("{}_{}", &voting_public_key, voting_keystore_share.share_id)),
                voting_password.as_bytes(),
            )?;
        }

        // Write the voting keystore share to file.
        write_keystore_share_to_file(dir.join(VOTING_KEYSTORE_SHARE_FILE), &voting_keystore_share)?;

        ValidatorDir::open(dir).map_err(BuilderError::UnableToOpenDir)
    }

    ///// Generate the voting keystore share using a deterministic, well-known, **unsafe** keypair.
    /////
    ///// **NEVER** use these keys in production!
    //fn insecure_voting_keypair_share(
        //mut self,
        //deterministic_key_index: usize,
        //share_id: u64,
    //) -> Result<Self, BuilderError> {
        //let keypair = generate_deterministic_keypair(deterministic_key_index);

        //let t = 5;
        //let n = 10;
        //let mut m_threshold = ThresholdSignature::new(t);  
        //let (kps, ids) = m_threshold.deterministic_key_split(&keypair.sk, n);

        //let keystore = KeystoreBuilder::new(&kps[share_id as usize], INSECURE_PASSWORD, "".into())
            //.map_err(|e| BuilderError::InsecureKeysError(format!("Unable to create keystore builder: {:?}", e)))?
            //.kdf(insecure_kdf())
            //.build()
            //.map_err(|e| BuilderError::InsecureKeysError(format!("Unable to build keystore: {:?}", e)))?;
        //let keystore_share = KeystoreShare::new(keystore, keypair.pk, deterministic_key_index as u64, share_idx);

        //Ok(self.voting_keystore_share(keystore_share, INSECURE_PASSWORD))
    //}


    /// Generate the voting keystore share using a deterministic, well-known, **unsafe** keypair.
    ///
    /// **NEVER** use these keys in production!
    fn build_insecure_distributed_voting_keypair(
        base_validators_dir: PathBuf,
        password_dir: PathBuf,
        deterministic_key_index: usize,        
        threshold: usize,
        total_splits: usize,
    ) -> Result<(), BuilderError> {
        let keypair = generate_deterministic_keypair(deterministic_key_index);

        let mut m_threshold = ThresholdSignature::new(threshold);  
        let (kps, ids) = m_threshold.deterministic_key_split(&keypair.sk, total_splits);

        for i in 0..total_splits {

            let keystore = KeystoreBuilder::new(&kps[i], INSECURE_PASSWORD, "".into())
                .map_err(|e| BuilderError::InsecureKeysError(format!("Unable to create keystore builder: {:?}", e)))?
                .kdf(insecure_kdf())
                .build()
                .map_err(|e| BuilderError::InsecureKeysError(format!("Unable to build keystore: {:?}", e)))?;
            let keystore_share = KeystoreShare::new(keystore, keypair.pk.clone(), deterministic_key_index as u64, ids[i]);

            ShareBuilder::new(base_validators_dir.clone())
                .password_dir(password_dir.clone())
                .voting_keystore_share(keystore_share, INSECURE_PASSWORD)
                .build()?;
        }

        let def = OperatorCommitteeDefinition {
            total: total_splits as u64,
            threshold: threshold as u64,
            committee_index: deterministic_key_index as u64,
            voting_public_key: keypair.pk.clone(),
            ids: ids,
            public_keys: kps.iter().map(|x| x.pk.clone()).collect(),
            socket_addresses: (0..total_splits).map(|j| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), (4000 + j) as u16)).collect(),
        };
        let committee_def_path = default_operator_committee_definition_path(
            &keypair.pk,
            <PathBuf as AsRef<Path>>::as_ref(&base_validators_dir),
        ); 
        def.to_file(committee_def_path).map_err(|e| BuilderError::InsecureKeysError("[TODO] Actually a Committee Definition Error".to_string()))
    }

}


/// Returns an INSECURE key derivation function.
///
/// **NEVER** use this KDF in production!
fn insecure_kdf() -> Kdf {
    Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        // `n` is set very low, making it cheap to encrypt/decrypt keystores.
        //
        // This is very insecure, only use during testing.
        n: 2,
        p: 1,
        r: 8,
        salt: vec![1; 32].into(),
    })
}

/// Writes a JSON keystore to file.
fn write_keystore_share_to_file(path: PathBuf, keystore_share: &KeystoreShare) -> Result<(), BuilderError> {
    if path.exists() {
        Err(BuilderError::KeystoreAlreadyExists(path))
    } else {
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .map_err(BuilderError::UnableToSaveKeystore)?;

        keystore_share.to_json_writer(file).map_err(Into::into)
    }
}


/// Creates a file with `600 (-rw-------)` permissions.
pub fn write_password_to_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), BuilderError> {
    let path = path.as_ref();

    if path.exists() {
        return Err(BuilderError::PasswordAlreadyExists(path.into()));
    }

    create_with_600_perms(path, bytes).map_err(BuilderError::UnableToSavePassword)?;

    Ok(())
}


///// A helper function to use the `Builder` to generate deterministic, well-known, **unsafe**
///// validator directories for the given validator `indices`.
/////
///// **NEVER** use these keys in production!
//pub fn build_deterministic_validator_share_dirs(
    //validators_dir: PathBuf,
    //password_dir: PathBuf,
    //indices: &[usize],
    //share_indices: &[u64],
//) -> Result<(), String> {
    //if indices.len() != share_indices.len() {
        //return Err("# of keys != # of shares".to_string());
    //}
    //for i in 0..indices.len() {
        //ShareBuilder::new(validators_dir.clone())
            //.password_dir(password_dir.clone())
            //.insecure_voting_keypair_share(indices[i], share_indices[i])
            //.map_err(|e| format!("Unable to generate insecure keypair: {:?}", e))?
            //.build()
            //.map_err(|e| format!("Unable to build keystore: {:?}", e))?;
    //}

    //Ok(())
//}



/// A helper function to use the `Builder` to generate deterministic, well-known, **unsafe**
/// validator directories for the given validator `indices`.
///
/// **NEVER** use these keys in production!
pub fn build_deterministic_distributed_validator_dirs(
    validators_dir: PathBuf,
    password_dir: PathBuf,
    indices: &[usize],
    threshold: usize,
    total_splits: usize,
) -> Result<(), String> {

    for i in 0..indices.len() {
        ShareBuilder::build_insecure_distributed_voting_keypair(
            validators_dir.clone(),
            password_dir.clone(),
            indices[i],
            threshold,
            total_splits)
            .map_err(|e| format!("Unable to build distributed keystore: {:?}", e))?;
    }

    Ok(())
}


pub fn build_deterministic_committees_file(
    committees_dir: PathBuf,
    indices: &[usize],
    threshold: usize,
    total_splits: usize,
) -> Result<(), String> {
    
    let mut defs = Vec::<OperatorCommitteeDefinition>::new();
    for i in 0..indices.len() {
        let keypair = generate_deterministic_keypair(indices[i]);

        let mut m_threshold = ThresholdSignature::new(threshold);  
        let (kps, ids) = m_threshold.deterministic_key_split(&keypair.sk, total_splits);

        defs.push(
            OperatorCommitteeDefinition {
                total: total_splits as u64,
                threshold: threshold as u64,
                committee_index: indices[i] as u64,
                voting_public_key: keypair.pk.clone(),
                ids: ids,
                public_keys: kps.iter().map(|x| x.pk.clone()).collect(),
                socket_addresses: (0..total_splits).map(|j| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), (4000 + j) as u16)).collect(),
            }
        );
    } 
    OperatorCommitteeDefinitions::from(defs)
        .save(committees_dir)
        .map_err(|e| format!("Unable to build committee definitions file: {:?}", e))?;
    Ok(())
}
