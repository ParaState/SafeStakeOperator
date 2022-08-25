//! Reference: lighthouse/common/validator_dir::builder

use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::operator_committee_definitions::{OperatorCommitteeDefinition};
use crate::validation::account_utils::{default_operator_committee_definition_path};
use validator_dir::{ValidatorDir, BuilderError};
use std::path::{Path, PathBuf};
use validator_dir::insecure_keys::{INSECURE_PASSWORD,};
use eth2_keystore::{
    json_keystore::{Kdf, Scrypt},
    KeystoreBuilder, PlainText, DKLEN,
};
use std::fs::{create_dir_all, File};
use filesystem::create_with_600_perms;
use std::net::{SocketAddr};
use crate::test_utils::{generate_deterministic_threshold_keypairs};
use bls::{PublicKey, Keypair};
use std::collections::HashMap;
use crate::validation::account_utils::default_keystore_share_dir;
use crate::validation::account_utils::default_keystore_share_password_path;


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

    /// Return the path to the validator dir to be built, i.e. `base_dir/pubkey/operator_id`.
    pub fn get_dir_path(base_validators_dir: &Path, voting_keystore_share: &KeystoreShare) -> PathBuf {
        //base_validators_dir.join(format!("0x{}", voting_keystore_share.pubkey()))
        default_keystore_share_dir(voting_keystore_share, base_validators_dir)
    }

    /// Consumes `self`, returning a `ValidatorDir` if no error is encountered.
    pub fn build(self) -> Result<ValidatorDir, BuilderError> {
        let (voting_keystore_share, voting_password) = self
            .voting_keystore_share
            .ok_or(BuilderError::UninitializedVotingKeystore)?;
        //let voting_public_key = &voting_keystore_share.master_public_key;

        let keystore_share_dir = default_keystore_share_dir(&voting_keystore_share, self.base_validators_dir.clone());

        //let dir = self.base_validators_dir
            //.join(format!("{}", &voting_public_key))
            //.join(format!("{}", voting_keystore_share.share_id));

        if keystore_share_dir.exists() {
            return Err(BuilderError::DirectoryAlreadyExists(keystore_share_dir));
        } else {
            create_dir_all(&keystore_share_dir).map_err(BuilderError::UnableToCreateDir)?;
        }

        if let Some(password_dir) = self.password_dir.as_ref() {
            // Write the voting password to file.
            write_password_to_file(
                default_keystore_share_password_path(&voting_keystore_share, password_dir),
                //password_dir.join(format!("{}_{}", &voting_public_key, voting_keystore_share.share_id)),
                voting_password.as_bytes(),
            )?;
        }

        // Write the voting keystore share to file.
        write_keystore_share_to_file(keystore_share_dir.join(VOTING_KEYSTORE_SHARE_FILE), &voting_keystore_share)?;

        ValidatorDir::open(keystore_share_dir).map_err(BuilderError::UnableToOpenDir)
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
        validator_id: u64,
        validator_public_key: PublicKey,
        operator_id: u64,
        operator_key_pair: Keypair,
    ) -> Result<(), BuilderError> {


        let keystore = KeystoreBuilder::new(&operator_key_pair, INSECURE_PASSWORD, "".into())
            .map_err(|e| BuilderError::InsecureKeysError(format!("Unable to create keystore builder: {:?}", e)))?
            .kdf(insecure_kdf())
            .build()
            .map_err(|e| BuilderError::InsecureKeysError(format!("Unable to build keystore: {:?}", e)))?;
        let keystore_share = KeystoreShare::new(keystore, validator_public_key, validator_id as u64, operator_id);

        ShareBuilder::new(base_validators_dir.clone())
            .password_dir(password_dir.clone())
            .voting_keystore_share(keystore_share, INSECURE_PASSWORD)
            .build()?;
        Ok(()) 
    }

}


/// Returns an INSECURE key derivation function.
///
/// **NEVER** use this KDF in production!
pub fn insecure_kdf() -> Kdf {
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
    validator_ids: &[u64],
    operator_ids: &[u64],
    threshold: usize,
    node_public_keys: &HashMap<u64, hscrypto::PublicKey>, 
    node_base_addresses: &HashMap<u64, SocketAddr>,
) -> Result<(), String> {
    
    let node_ids: Vec<u64> = node_public_keys.keys().map(|k| *k).collect();
    for i in 0..validator_ids.len() {
        let key_pack = generate_deterministic_threshold_keypairs(validator_ids[i], &node_ids, threshold);

        ShareBuilder::build_insecure_distributed_voting_keypair(
            validators_dir.clone(),
            password_dir.clone(),
            validator_ids[i],
            key_pack.kp.pk.clone(),
            operator_ids[i],
            key_pack.kps.get(&operator_ids[i]).unwrap().clone(),
            )
            .map_err(|e| format!("Unable to build distributed keystore: {:?}", e))?;


        let def = OperatorCommitteeDefinition {
            total: node_ids.len() as u64,
            threshold: threshold as u64,
            validator_id: validator_ids[i],
            validator_public_key: key_pack.kp.pk.clone(),
            operator_ids: node_ids.clone(),
            operator_public_keys: node_ids.iter()
                .map(|id| key_pack.kps.get(id).unwrap().pk.clone())
                .collect(),
            node_public_keys: node_ids.iter()
                .map(|id| node_public_keys.get(id).unwrap().clone())
                .collect(),
            base_socket_addresses: node_ids.iter()
                .map(|id| node_base_addresses.get(id).unwrap().clone())
                .collect(),
                //.map(|j| SocketAddr::new("127.0.0.1".parse().unwrap(), (DEFAULT_BASE_PORT + j as u16 * 100) as u16)).collect(),
        };
        let committee_def_path = default_operator_committee_definition_path(
            &key_pack.kp.pk,
            <PathBuf as AsRef<Path>>::as_ref(&validators_dir),
        ); 
        def.to_file(committee_def_path)
            .map_err(|e| format!("Unable to save committee definition: {:?}", e))?;

    }

    Ok(())
}


//pub fn build_deterministic_committees_file(
    //committees_dir: PathBuf,
    //validator_ids: &[usize],
    //threshold: usize,
    //total_splits: usize,
//) -> Result<(), String> {
    
    //let mut defs = Vec::<OperatorCommitteeDefinition>::new();
    //for i in 0..validator_ids.len() {
        //let keypair = generate_deterministic_keypair(validator_ids[i]);

        //let mut m_threshold = ThresholdSignature::new(threshold);  
        //let (kps, ids) = m_threshold.deterministic_key_split(&keypair.sk, total_splits);

        //defs.push(
            //OperatorCommitteeDefinition {
                //total: total_splits as u64,
                //threshold: threshold as u64,
                //validator_id: validator_ids[i] as u64,
                //validator_public_key: keypair.pk.clone(),
                //operator_ids: ids,
                //operator_public_keys: kps.iter().map(|x| x.pk.clone()).collect(),
                //node_public_keys,
                //base_socket_addresses: (0..total_splits).map(|j| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), (4000 + j) as u16)).collect(),
            //}
        //);
    //} 
    //OperatorCommitteeDefinitions::from(defs)
        //.save(committees_dir)
        //.map_err(|e| format!("Unable to build committee definitions file: {:?}", e))?;
    //Ok(())
//}
