use crate::crypto::dkg::DKG;
use crate::crypto::elgamal::{Ciphertext, Elgamal};
use crate::network::io_committee::NetIOCommittee;
use crate::node::config::{
    NodeConfig, API_ADDRESS, BOOT_ENR, DB_FILENAME, DISCOVERY_PORT_OFFSET, DKG_PORT_OFFSET,
    PRESTAKE_SIGNATURE_URL, STAKE_SIGNATURE_URL, VALIDATOR_PK_URL,
};
use crate::node::discovery::Discovery;
/// The default channel capacity for this module.
use crate::node::dvfcore::DvfSignatureReceiverHandler;
use crate::node::new_contract::{
    ContractCommand, EncryptedSecretKeys, Initializer, OperatorPublicKeys, SharedPublicKeys,
    Validator, SELF_OPERATOR_ID, Contract,
};
use crate::node::utils::{get_operator_ips, request_to_web_server, ValidatorPkRequest};
use crate::validation::account_utils::default_keystore_share_password_path;
use crate::validation::account_utils::default_keystore_share_path;
use crate::validation::account_utils::default_operator_committee_definition_path;
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::validation::validator_dir::share_builder::{insecure_kdf, ShareBuilder};
use crate::validation::validator_store::ValidatorStore;
use crate::DEFAULT_CHANNEL_CAPACITY;
use bls::{Keypair as BlsKeypair, SecretKey as BlsSecretKey};
use consensus::ConsensusReceiverHandler;
use eth2_keystore::KeystoreBuilder;
use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use hsutils::monitored_channel::{MonitoredChannel, MonitoredSender};
use log::{error, info, warn};
use mempool::{MempoolReceiverHandler, TxReceiverHandler};
use network::{Receiver as NetworkReceiver, VERSION};
use parking_lot::RwLock as ParkingRwLock;
use slot_clock::SystemTimeSlotClock;
use std::collections::{HashMap, HashSet};
use std::fs::{remove_dir_all, remove_file};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use types::EthSpec;
use types::PublicKey;
use validator_dir::insecure_keys::INSECURE_PASSWORD;
const THRESHOLD: u64 = 3;
fn with_wildcard_ip(mut addr: SocketAddr) -> SocketAddr {
    addr.set_ip("0.0.0.0".parse().unwrap());
    addr
}

pub struct Node<T: EthSpec> {
    pub config: NodeConfig,
    pub secret: Secret,
    //pub rx_dvfinfo: Receiver<DvfInfo>,
    pub tx_handler_map: Arc<RwLock<HashMap<u64, TxReceiverHandler>>>,
    pub mempool_handler_map: Arc<RwLock<HashMap<u64, MempoolReceiverHandler>>>,
    pub consensus_handler_map: Arc<RwLock<HashMap<u64, ConsensusReceiverHandler>>>,
    pub signature_handler_map: Arc<RwLock<HashMap<u64, DvfSignatureReceiverHandler>>>,
    pub validator_store: Option<Arc<ValidatorStore<SystemTimeSlotClock, T>>>, 
}
// impl Send for Node{}
impl<T: EthSpec> Node<T> {
    pub fn new(config: NodeConfig) -> Result<Option<Arc<ParkingRwLock<Self>>>, ConfigError> {
        let self_address = config.base_address.ip();
        let secret_dir = config.secrets_dir.clone();
        let secret = Node::<T>::open_or_create_secret(config.node_key_path.clone())?;

        info!("node public key {}", secret.name.encode_base64());
        info!("dvf message version: {}", VERSION);

        let tx_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let mempool_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let consensus_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let signature_handler_map = Arc::new(RwLock::new(HashMap::new()));

        let key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>> =
            Arc::new(RwLock::new(HashMap::from([(
                base64::encode(&secret.name),
                config.base_address.ip().clone(),
            )])));

        let transaction_address = with_wildcard_ip(config.transaction_address.clone());
        NetworkReceiver::spawn(
            transaction_address,
            Arc::clone(&tx_handler_map),
            "transaction",
        );
        info!(
            "Node {} listening to client transactions on {}",
            secret.name, transaction_address
        );

        let mempool_address = with_wildcard_ip(config.mempool_address.clone());
        NetworkReceiver::spawn(mempool_address, Arc::clone(&mempool_handler_map), "mempool");
        info!(
            "Node {} listening to mempool messages on {}",
            secret.name, mempool_address
        );

        let consensus_address = with_wildcard_ip(config.consensus_address.clone());
        NetworkReceiver::spawn(
            consensus_address,
            Arc::clone(&consensus_handler_map),
            "consensus",
        );
        info!(
            "Node {} listening to consensus messages on {}",
            secret.name, consensus_address
        );

        let signature_address = with_wildcard_ip(config.signature_address.clone());
        NetworkReceiver::spawn(
            signature_address,
            Arc::clone(&signature_handler_map),
            "signature",
        );
        info!(
            "Node {} listening to signature messages on {}",
            secret.name, signature_address
        );

        let (tx_validator_command, rx_validator_command) = MonitoredChannel::new(
            DEFAULT_CHANNEL_CAPACITY,
            "contract-command".to_string(),
            "info",
        );

        info!("Node {} successfully booted", secret.name);
        let base_port = config.base_address.port();
        let node = Self {
            config,
            secret: secret.clone(),
            //rx_dvfinfo,
            tx_handler_map: Arc::clone(&tx_handler_map),
            mempool_handler_map: Arc::clone(&mempool_handler_map),
            consensus_handler_map: Arc::clone(&consensus_handler_map),
            signature_handler_map: Arc::clone(&signature_handler_map),
            validator_store: None,
        };
        Discovery::spawn(
            self_address,
            base_port + DISCOVERY_PORT_OFFSET,
            Arc::clone(&key_ip_map),
            node.secret.clone(),
            Some(BOOT_ENR.get().unwrap().clone()),
        );

        Contract::spawn(secret_dir.parent().unwrap().to_path_buf(), secret.name, tx_validator_command.clone());
        let node = Arc::new(ParkingRwLock::new(node));

        Node::process_contract_command(
            Arc::clone(&node),
            Arc::clone(&key_ip_map),
            rx_validator_command,
            tx_validator_command,
        );

        Ok(Some(node))
    }

    pub fn open_or_create_secret(path: PathBuf) -> Result<Secret, ConfigError> {
        if path.exists() {
            info!("{:?}", path);
            Secret::read(path.to_str().unwrap())
        } else {
            let secret = Secret::new();
            secret.write(path.to_str().unwrap())?;
            Ok(secret)
        }
    }

    pub fn process_contract_command(
        node: Arc<ParkingRwLock<Node<T>>>,
        operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
        mut rx_contract_command: Receiver<ContractCommand>,
        tx_contract_command: MonitoredSender<ContractCommand>,
    ) {
        tokio::spawn(async move {
            loop {
                match rx_contract_command.recv().await {
                    Some(validator_command) => match validator_command {
                        ContractCommand::StartValidator(
                            validator,
                            operator_pks,
                            shared_pks,
                            encrypted_sks,
                        ) => {
                            match new_add_validator(
                                node.clone(),
                                validator,
                                operator_pks,
                                shared_pks,
                                encrypted_sks,
                                operator_key_ip_map.clone(),
                                tx_contract_command.clone(),
                            )
                            .await
                            {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Failed to add validator: {}", e);
                                }
                            }
                        }
                        ContractCommand::StopValidator(validator) => {
                            match new_stop_validator(node.clone(), validator).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Failed to stop validator: {}", e);
                                }
                            }
                        }
                        ContractCommand::StartInitializer(initializer, operator_pks) => {
                            match start_initializer(
                                node.clone(),
                                initializer,
                                operator_pks,
                                operator_key_ip_map.clone(),
                                tx_contract_command.clone(),
                            )
                            .await
                            {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Failed to stop initializer: {}", e);
                                }
                            }
                        }
                        ContractCommand::MiniPoolCreated(
                            initializer_id,
                            validator_pk,
                            minipool_address,
                        ) => {}
                        ContractCommand::MiniPoolReady(
                            initializer_id,
                            validator_pk,
                            minipool_address,
                        ) => {}
                        _ => {}
                    },
                    None => {
                        error!("channel is closed unexpected");
                        break;
                    }
                }
            }
        });
    }
}

pub async fn new_add_validator<T: EthSpec>(
    node: Arc<ParkingRwLock<Node<T>>>,
    validator: Validator,
    operator_public_keys: OperatorPublicKeys,
    shared_public_keys: SharedPublicKeys,
    encrypted_secret_keys: EncryptedSecretKeys,
    operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
    tx_validator_command: MonitoredSender<ContractCommand>,
) -> Result<(), String> {
    let node = node.read();
    let base_port = node.config.base_address.port();
    let validator_dir = node.config.validator_dir.clone();
    let secret_dir = node.config.secrets_dir.clone();
    let secret = node.secret.clone();
    let sk = &secret.secret;
    let self_pk = &secret.name;
    let secret_key = secp256k1::SecretKey::from_slice(&sk.0).expect("Unable to load secret key");

    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("Unable to deserialize validator public key: {:?}", e))?;
    info!("[VA {}] adding validator {}", validator_id, validator_pk);
    let added_validator_dir = validator_dir.join(format!("{}", validator_pk));
    if added_validator_dir.exists() {
        return Err("Validator exists".to_string());
    }

    let operator_base_address =
        match get_operator_ips(operator_key_ip_map, &operator_public_keys, base_port).await {
            Ok(address) => address,
            Err(e) => {
                sleep(Duration::from_secs(10)).await;
                let _ = tx_validator_command
                    .send(ContractCommand::StartValidator(
                        validator,
                        operator_public_keys,
                        shared_public_keys,
                        encrypted_secret_keys,
                    ))
                    .await;
                info!("Will process the validator again");
                cleanup_validator_dir(&validator_dir, &validator_pk, validator_id)?;
                cleanup_password_dir(&secret_dir, &validator_pk, validator_id)?;
                return Err(e);
            }
        };

    let operator_ids: Vec<u64> = validator
        .releated_operators
        .iter()
        .map(|x| *x as u64)
        .collect();
    let operator_bls_pks: Vec<Result<PublicKey, String>> = operator_public_keys
        .iter()
        .map(|pk| {
            Ok(PublicKey::deserialize(&pk).map_err(|e| {
                error!("Unable to deserialize operator pk {:?}", e);
                format!("deserialize operator pk failed")
            })?)
        })
        .collect();
    if operator_bls_pks.iter().any(|x| !x.is_ok()) {
        return Err("Some operators pk can't be deserialized!".to_string());
    }
    let operator_bls_pks = operator_bls_pks.into_iter().map(|x| x.unwrap()).collect();
    let operator_node_pks: Vec<hscrypto::PublicKey> = shared_public_keys
        .into_iter()
        .map(|shared_pk| hscrypto::PublicKey(shared_pk.try_into().unwrap()))
        .collect();

    let self_index: Vec<usize> = operator_node_pks
        .iter()
        .enumerate()
        .filter(|&(_i, x)| *self_pk == *x)
        .map(|(i, _)| i)
        .collect();
    if self_index.len() != 1 {
        return Err("Can't find self public key".to_string());
    }

    // decrypt
    let shared_key_pair = {
        let rng = rand::thread_rng();
        let mut elgamal = Elgamal::new(rng);
        let ciphertext = Ciphertext::from_bytes(&encrypted_secret_keys[self_index[0]]);
        let plain_shared_key = elgamal.decrypt(&ciphertext, &secret_key).map_err(|_e| {
            format!(
                "Unable to decrypt: ciphertext({:?}), secret_key({})",
                hex::encode(&encrypted_secret_keys[self_index[0]]),
                secret_key.display_secret()
            )
        })?;
        let shared_secret_key = BlsSecretKey::deserialize(&plain_shared_key)
            .map_err(|e| format!("Unable to deserialize secret key: {:?}", e))?;
        let shared_public_key = shared_secret_key.public_key();
        BlsKeypair::from_components(shared_public_key.clone(), shared_secret_key)
    };

    let keystore = KeystoreBuilder::new(&shared_key_pair, INSECURE_PASSWORD, "".into())
        .map_err(|e| format!("Unable to create keystore builder: {:?}", e))?
        .kdf(insecure_kdf())
        .build()
        .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

    let keystore_share = KeystoreShare::new(
        keystore,
        validator_pk.clone(),
        validator_id,
        validator.releated_operators[self_index[0]] as u64,
    );

    match ShareBuilder::new(validator_dir.clone())
        .password_dir(secret_dir.clone())
        .voting_keystore_share(keystore_share.clone(), INSECURE_PASSWORD)
        .build()
    {
        Ok(va_dir) => {
            info!("build validator dir in {:?}", va_dir);
        }
        Err(e) => {
            return Err(format!("keystore share build failed: {:?}", e));
        }
    };

    // generate keypair
    let def = OperatorCommitteeDefinition {
        total: operator_public_keys.len() as u64,
        threshold: THRESHOLD,
        validator_id: validator_id,
        validator_public_key: validator_pk.clone(),
        operator_ids: operator_ids,
        operator_public_keys: operator_bls_pks,
        node_public_keys: operator_node_pks,
        base_socket_addresses: operator_base_address,
    };

    let committee_def_path =
        default_operator_committee_definition_path(&validator_pk, validator_dir.clone());
    info!("path {:?}, pk {:?}", &committee_def_path, &validator_pk);
    match def
        .to_file(committee_def_path.clone())
        .map_err(|e| format!("Unable to save committee definition: error:{:?}", e))
    {
        Ok(_) => {}
        Err(e) => {
            return Err(e.to_string());
        }
    }

    let voting_keystore_share_path =
        default_keystore_share_path(&keystore_share, validator_dir.clone());
    let voting_keystore_share_password_path =
        default_keystore_share_password_path(&keystore_share, secret_dir.clone());
    match &node.validator_store {
        Some(validator_store) => {
            let _ = validator_store
                .add_validator_keystore_share(
                    voting_keystore_share_path,
                    voting_keystore_share_password_path,
                    true,
                    None,
                    None,
                    None,
                    None,
                    committee_def_path,
                    keystore_share.master_id,
                    keystore_share.share_id,
                )
                .await;
            info!("[VA {}] added validator {}", validator_id, validator_pk);
        }
        _ => {
            error!(
                "[VA {}] failed to add validator {}. Error: no validator store is set.",
                validator_id, validator_pk
            );
        }
    }

    Ok(())
}

pub async fn new_stop_validator<T: EthSpec>(
    node: Arc<ParkingRwLock<Node<T>>>,
    validator: Validator,
) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("[VA {}] Deserialize error ({:?})", validator_id, e))?;
    info!(
        "[VA {}] stopping validator {}...",
        validator_id, validator_pk
    );
    let (validator_dir, secret_dir, validator_store) = {
        let node_ = node.read();
        let validator_dir = node_.config.validator_dir.clone();
        let secret_dir = node_.config.secrets_dir.clone();
        let validator_store = node_.validator_store.clone();

        (validator_dir, secret_dir, validator_store)
    };
    let base_dir = secret_dir.parent().ok_or(format!(
        "[VA {}] Failed to get parent of secret dir (possibly the root dir)",
        validator_id
    ))?;

    cleanup_handler(node.clone(), validator_id).await;
    cleanup_keystore(validator_store, &validator_pk).await;
    cleanup_db(base_dir, validator_id)?;
    cleanup_validator_dir(&validator_dir, &validator_pk, validator_id)?;
    cleanup_password_dir(&secret_dir, &validator_pk, validator_id)?;

    info!("[VA {}] stopped validator {}", validator_id, validator_pk);
    Ok(())
}

pub async fn start_initializer<T: EthSpec>(
    node: Arc<ParkingRwLock<Node<T>>>,
    initializer: Initializer,
    operator_public_keys: OperatorPublicKeys,
    operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
    tx_contract_command: MonitoredSender<ContractCommand>,
) -> Result<(), String> {
    let node = node.read();
    let base_port = node.config.base_address.port();
    let operator_ips =
        match get_operator_ips(operator_key_ip_map, &operator_public_keys, base_port).await {
            Ok(ips) => ips,
            Err(e) => {
                sleep(Duration::from_secs(10)).await;
                let _ = tx_contract_command
                    .send(ContractCommand::StartInitializer(
                        initializer,
                        operator_public_keys,
                    ))
                    .await;
                info!("Will process the validator again");
                return Err(e);
            }
        };
    let self_op_id = *SELF_OPERATOR_ID
        .get()
        .ok_or("Self operator has not been set".to_string())?;
    let op_ids: Vec<u64> = initializer
        .releated_operators
        .iter()
        .map(|x| *x as u64)
        .collect();
    let io = Arc::new(
        NetIOCommittee::new(
            self_op_id as u64,
            base_port + DKG_PORT_OFFSET,
            op_ids.as_slice(),
            operator_ips.as_slice(),
        )
        .await,
    );
    let dkg = DKG::new(self_op_id as u64, io, THRESHOLD as usize);
    // TODO: start consensus
    let (keypair, va_pk) = dkg
        .run()
        .await
        .map_err(|e| format!("run dkg failed {:?}", e))?;
    // push va pk to web server
    let request_body = ValidatorPkRequest {
        validator_pk: va_pk.as_hex_string(),
        initializer_id: initializer.id,
        initializer_address: format!("{0:0x}", initializer.owner_address),
        operators: op_ids,
    };
    let url_str = API_ADDRESS.get().unwrap().to_owned() + VALIDATOR_PK_URL;
    request_to_web_server(request_body, &url_str).await?;
    Ok(())
}

// TODO process minipool created event
pub async fn minipool_created() -> Result<(), String> {
    Ok(())
}

// TODO process minipool ready event
pub async fn minipool_ready() -> Result<(), String> {
    Ok(())
}

pub async fn cleanup_handler<T: EthSpec>(node: Arc<ParkingRwLock<Node<T>>>, validator_id: u64) {
    let node_ = node.read();
    let _ = node_.tx_handler_map.write().await.remove(&validator_id);
    let _ = node_
        .mempool_handler_map
        .write()
        .await
        .remove(&validator_id);
    let _ = node_
        .consensus_handler_map
        .write()
        .await
        .remove(&validator_id);
    let _ = node_
        .signature_handler_map
        .write()
        .await
        .remove(&validator_id);
}

pub async fn cleanup_keystore<T: EthSpec>(
    validator_store: Option<Arc<ValidatorStore<SystemTimeSlotClock, T>>>,
    validator_pk: &PublicKey,
) {
    match validator_store {
        Some(validator_store) => {
            validator_store.stop_validator_keystore(validator_pk).await;
        }
        _ => {}
    }
}

pub fn cleanup_db(base_dir: &Path, validator_id: u64) -> Result<(), String> {
    let db_dir = base_dir.join(DB_FILENAME).join(validator_id.to_string());
    if db_dir.exists() {
        remove_dir_all(&db_dir)
            .map_err(|e| format!("[VA {}] Failed to remove DB file ({})", validator_id, e))?;
    }
    Ok(())
}

pub fn cleanup_validator_dir(
    validator_dir: &Path,
    validator_pk: &PublicKey,
    validator_id: u64,
) -> Result<(), String> {
    let deleted_validator_dir = validator_dir.join(format!("{}", validator_pk));
    if deleted_validator_dir.exists() {
        remove_dir_all(&deleted_validator_dir).map_err(|e| {
            format!(
                "[VA {}] Failed to delete validator dir ({})",
                validator_id, e
            )
        })?;
    }
    Ok(())
}

pub fn cleanup_password_dir(
    secret_dir: &Path,
    validator_pk: &PublicKey,
    validator_id: u64,
) -> Result<(), String> {
    for password_file in secret_dir
        .read_dir()
        .map_err(|e| format!("[VA {}] Failed to read secret dir ({})", validator_id, e))?
    {
        let password_file_name = password_file
            .map_err(|e| format!("[VA {}] Failed to read secret entry ({})", validator_id, e))?
            .file_name()
            .into_string()
            .map_err(|e| {
                format!(
                    "[VA {}] Failed to convert secret entry path to string ({:?})",
                    validator_id, e
                )
            })?;
        let validator_pk_prefix = format!("{}", validator_pk);
        if password_file_name.starts_with(&validator_pk_prefix) {
            let password_file_dir = secret_dir.join(password_file_name);
            if password_file_dir.exists() {
                remove_file(&password_file_dir).map_err(|e| {
                    format!(
                        "[VA {}] Failed to delete password file ({})",
                        validator_id, e
                    )
                })?;
                info!(
                    "[VA {}] removed password file {:?}",
                    validator_id, password_file_dir
                );
                break;
            } else {
                warn!(
                    "[VA {}] password file does not exist: {:?}",
                    validator_id, password_file_dir
                );
            }
        }
    }
    Ok(())
}
