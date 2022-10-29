use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use hsutils::monitored_channel::{MonitoredChannel, MonitoredSender};
use log::{info, error, warn};
use consensus::{ConsensusReceiverHandler};
use mempool::{TxReceiverHandler, MempoolReceiverHandler};
use network::{Receiver as NetworkReceiver, VERSION};
use std::sync::{Arc};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use parking_lot::RwLock as ParkingRwLock;
use std::net::SocketAddr;
use tokio::sync::mpsc::{channel, Receiver, Sender};
/// The default channel capacity for this module.
use crate::node::dvfcore::{ DvfSignatureReceiverHandler};
use crate::node::config::{NodeConfig, DISCOVERY_PORT_OFFSET, DB_FILENAME};
use std::path::PathBuf;
use std::net::IpAddr;
use std::fs::{remove_file, remove_dir_all};
use crate::node::contract::{ValidatorCommand, Validator, Operator};
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::node::discovery::Discovery;
use crate::node::contract::{ListenContract, ContractConfig};
use types::PublicKey;
use crate::validation::account_utils::default_operator_committee_definition_path;
use types::EthSpec;
use crate::validation::validator_store::ValidatorStore;
use slot_clock::SystemTimeSlotClock;
use bls::{Keypair as BlsKeypair, SecretKey as BlsSecretKey};
use crate::crypto::elgamal::{Ciphertext, Elgamal};
use eth2_keystore::{KeystoreBuilder};
use validator_dir::insecure_keys::{INSECURE_PASSWORD};
use validator_dir::{BuilderError};
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::validator_dir::share_builder::{insecure_kdf, ShareBuilder};
use crate::validation::account_utils::default_keystore_share_password_path;
use crate::validation::account_utils::default_keystore_share_path;
use std::path::Path;
use crate::DEFAULT_CHANNEL_CAPACITY;

const THRESHOLD: u64 = 3;
fn with_wildcard_ip(mut addr: SocketAddr) -> SocketAddr {
    addr.set_ip("0.0.0.0".parse().unwrap());
    addr
}

pub struct Node<T: EthSpec> {
    pub config: NodeConfig,
    pub secret : Secret,
    //pub rx_dvfinfo: Receiver<DvfInfo>,
    pub tx_handler_map : Arc<RwLock<HashMap<u64, TxReceiverHandler>>>,
    pub mempool_handler_map : Arc<RwLock<HashMap<u64, MempoolReceiverHandler>>>,
    pub consensus_handler_map: Arc<RwLock<HashMap<u64, ConsensusReceiverHandler>>>,
    pub signature_handler_map: Arc<RwLock<HashMap<u64, DvfSignatureReceiverHandler>>>,
    pub validator_store: Option<Arc<ValidatorStore<SystemTimeSlotClock, T>>>
    // pub key_ip_map: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    // pub validators_map: Arc<RwLock<HashMap<u64, Validator>>>,
    // pub validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>
}
// impl Send for Node{}
impl<T: EthSpec> Node<T> {

    pub fn new(
        config: NodeConfig
    ) -> Result<Option<Arc<ParkingRwLock<Self>>>, ConfigError> {
        let self_address = config.base_address.ip();
        let secret_dir = config.secrets_dir.clone();
        let secret = Node::<T>::open_or_create_secret(config.node_key_path.clone())?;
        
        info!("node public key {}", secret.name.encode_base64());
        info!("dvf message version: {}", VERSION);

        let tx_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let mempool_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let consensus_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let signature_handler_map = Arc::new(RwLock::new(HashMap::new()));

        let key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>> = Arc::new(RwLock::new(HashMap::from([(base64::encode(&secret.name), config.base_address.ip().clone())])));
        let validators_map: Arc<RwLock<HashMap<u64, Validator>>> = Arc::new(RwLock::new(HashMap::new()));
        let validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>> = Arc::new(RwLock::new(HashMap::new()));

        let transaction_address = with_wildcard_ip(config.transaction_address.clone());
        NetworkReceiver::spawn(transaction_address, Arc::clone(&tx_handler_map), "transaction");
        info!("Node {} listening to client transactions on {}", secret.name, transaction_address);

        let mempool_address = with_wildcard_ip(config.mempool_address.clone());
        NetworkReceiver::spawn(mempool_address, Arc::clone(&mempool_handler_map), "mempool");
        info!("Node {} listening to mempool messages on {}", secret.name, mempool_address);

        let consensus_address = with_wildcard_ip(config.consensus_address.clone());
        NetworkReceiver::spawn(consensus_address, Arc::clone(&consensus_handler_map), "consensus");
        info!(
            "Node {} listening to consensus messages on {}",
            secret.name, consensus_address
        );

        let signature_address = with_wildcard_ip(config.signature_address.clone());
        NetworkReceiver::spawn(signature_address, Arc::clone(&signature_handler_map), "signature");
        info!(
            "Node {} listening to signature messages on {}",
            secret.name, signature_address
        );

        let (tx_validator_command, rx_validator_command) = MonitoredChannel::new(DEFAULT_CHANNEL_CAPACITY, "contract-command".to_string(), "info");
        //// set dvfcore handler map
        //let dvfcore_handler_map : Arc<RwLock<HashMap<u64, DvfReceiverHandler>>>= Arc::new(RwLock::new(HashMap::new()));
        //let (tx_dvfinfo, rx_dvfinfo) = channel(1);
        //{
            //let mut dvfcore_handlers = dvfcore_handler_map.write().await; 
            //let empty_id: u64 = 0;
            
            //dvfcore_handlers.insert(
                //empty_id,
                //DvfReceiverHandler {
                    //tx_dvfinfo
                //}
            //);
        //}
        
        //NetworkReceiver::spawn(config.dvfcore_network_address.clone(), Arc::clone(&dvfcore_handler_map));
        //info!("DvfCore listening to dvf messages on {}", config.dvfcore_network_address);
        

        info!("Node {} successfully booted", secret.name);
        let validator_dir = config.validator_dir.clone();
        let secrets_dir = config.secrets_dir.clone();
        let base_port = config.base_address.port();
        let node = Self { 
            config,
            secret, 
            //rx_dvfinfo, 
            tx_handler_map: Arc::clone(&tx_handler_map), 
            mempool_handler_map: Arc::clone(&mempool_handler_map), 
            consensus_handler_map: Arc::clone(&consensus_handler_map), 
            signature_handler_map: Arc::clone(&signature_handler_map),
            validator_store: None
        };
        Discovery::spawn(self_address, base_port + DISCOVERY_PORT_OFFSET, Arc::clone(&key_ip_map), node.secret.clone(), Some(node.config.boot_enr.to_string()));

        let contract_config = ContractConfig::default();
        let ethlog_hashset = Arc::new(RwLock::new(HashSet::new()));
        ListenContract::spawn(contract_config.clone(), node.secret.name.0.to_vec(), tx_validator_command.clone(), validators_map.clone(), validator_operators_map.clone(), ethlog_hashset.clone());
        ListenContract::pull_from_contract(contract_config, node.secret.name.0.to_vec(), tx_validator_command.clone(), validators_map.clone(), validator_operators_map.clone(), secret_dir.parent().unwrap().to_path_buf(), ethlog_hashset);

        let node = Arc::new(ParkingRwLock::new(node));
        Node::process_validator_command(Arc::clone(&node), validator_operators_map, Arc::clone(&key_ip_map), rx_validator_command, tx_validator_command);

        Ok(Some(node))
    }

    pub fn open_or_create_secret(path: PathBuf) -> Result<Secret, ConfigError> {
        if path.exists() {
            info!("{:?}", path);
            Secret::read(path.to_str().unwrap())
        }
        else {
            let secret = Secret::new();
            secret.write(path.to_str().unwrap())?;
            Ok(secret)
        }
    }

    pub fn process_validator_command(node: Arc<ParkingRwLock<Node<T>>>, 
        validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>, 
        operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,  
        mut rx_validator_command: Receiver<ValidatorCommand>, 
        tx_validator_command: MonitoredSender<ValidatorCommand>
    ) {

        tokio::spawn(async move {
            loop {
                match rx_validator_command.recv().await {
                    Some(validator_command) => {
                        match validator_command {
                            ValidatorCommand::Start(validator) => {
                                match add_validator(node.clone(), validator, validator_operators_map.clone(), operator_key_ip_map.clone(), tx_validator_command.clone()).await {
                                    Ok(_) => {},
                                    Err(e) => {
                                        error!("Failed to add validator: {}", e);
                                    }
                                }
                            },
                            ValidatorCommand::Stop(validator) => {
                                match stop_validator(node.clone(), validator).await {
                                    Ok(_) => {},
                                    Err(e) => {
                                        error!("Failed to stop validator: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        error!("channel is closed unexpected");
                        break;
                    }
                }
            }
        });
    }
}

pub async fn add_validator<T: EthSpec>(
    node: Arc<ParkingRwLock<Node<T>>>, 
    validator: Validator,
    validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>, 
    operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
    tx_validator_command: MonitoredSender<ValidatorCommand>,
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
    // check validator exists
    let validator_pk = PublicKey::deserialize(&validator.validator_public_key)
        .map_err(|e| format!("Unable to deserialize validator public key: {:?}", e))?;
    info!("[VA {}] adding validator {}", validator_id, validator_pk);
    let added_validator_dir = validator_dir.join(format!("{}", validator_pk));
    if added_validator_dir.exists() {
        return Err("Validator exists".to_string());
    }
    let validator_operators = validator_operators_map.read().await;
    let operators_vec = validator_operators.get(&validator_id);
    match operators_vec {
        Some(operators) => {
            let key_ip_map = operator_key_ip_map.read().await;

            let mut operator_base_address : Vec<SocketAddr> = Vec::default();
            let mut operator_ids: Vec<u64> = Vec::default();
            let mut operator_public_keys: Vec<PublicKey> = Vec::default();
            let mut node_public_keys: Vec<hscrypto::PublicKey> = Vec::default();
            
            let mut keystore_share: Option<KeystoreShare> = None;
            for operator in operators {

                let operator_public_key = base64::encode(operator.node_public_key.clone());
                let ip = key_ip_map.get(&operator_public_key);
                // get all ips from 
                match ip {
                    Some(ip) => {
                        operator_base_address.push(SocketAddr::new(ip.clone(), base_port));
                        operator_ids.push(operator.id);

                        let operator_pk = PublicKey::deserialize(&operator.shared_public_key)
                            .map_err(|e| format!("Unable to deserialize operator pk: {:?}", e))?;                                        
                        operator_public_keys.push(operator_pk);
                        let node_pk = hscrypto::PublicKey(operator.node_public_key.clone().try_into().unwrap());

                        if *self_pk == node_pk {
                            // decrypt 
                            let rng = rand::thread_rng();
                            let mut elgamal = Elgamal::new(rng);
                            
                            let ciphertext = Ciphertext::from_bytes(&operator.encrypted_key);
                            let plain_shared_key = elgamal.decrypt(&ciphertext, &secret_key)
                                .map_err(|_e| format!("Unable to decrypt: ciphertext({:?}), secret_key({})", 
                                                     hex::encode(operator.encrypted_key.as_slice()),
                                                     secret_key.display_secret())
                                )?;

                            let shared_secret_key = BlsSecretKey::deserialize(&plain_shared_key)
                                .map_err(|e| format!("Unable to deserialize secret key: {:?}", e))?;

                            let shared_public_key = shared_secret_key.public_key();

                            let shared_key_pair = BlsKeypair::from_components(shared_public_key.clone(), shared_secret_key);

                            let keystore = KeystoreBuilder::new(&shared_key_pair, INSECURE_PASSWORD, "".into())
                                .map_err(|e| format!("Unable to create keystore builder: {:?}", e))?
                                .kdf(insecure_kdf())
                                .build()
                                .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

                            keystore_share = Some(KeystoreShare::new(keystore, validator_pk.clone(), validator_id, operator.id));

                            match ShareBuilder::new(validator_dir.clone())
                                .password_dir(secret_dir.clone())
                                .voting_keystore_share(keystore_share.clone().unwrap(), INSECURE_PASSWORD)
                                .build() {
                                    Ok(va_dir) => {
                                        info!("build validator dir in {:?}", va_dir);
                                    }, 
                                    Err(e) => {
                                        return Err(format!("keystore share build failed: {:?}", e));
                                    }
                                };
                        }

                        node_public_keys.push(node_pk);
                    },
                    None => {
                        error!("can't discover the operator {}", operator_public_key);
                        break;
                    }
                }
            }
            if operator_base_address.len() != operators.len() {
                sleep(Duration::from_secs(10)).await;
                let _ = tx_validator_command.send(ValidatorCommand::Start(validator)).await;
                info!("Will process the validator again");
                cleanup_validator_dir(&validator_dir, &validator_pk, validator_id)?;
                cleanup_password_dir(&secret_dir, &validator_pk, validator_id)?;
                return Err("Insufficient operators discovered".to_string());
            }

            // generate keypair
            let def = OperatorCommitteeDefinition {
                total: operators.len() as u64,
                threshold: THRESHOLD,
                validator_id: validator_id,
                validator_public_key: validator_pk.clone(),
                operator_ids: operator_ids,
                operator_public_keys: operator_public_keys,
                node_public_keys: node_public_keys,
                base_socket_addresses: operator_base_address
            };

            let committee_def_path = default_operator_committee_definition_path(&validator_pk, validator_dir.clone());
            info!("path {:?}, pk {:?}", &committee_def_path, &validator_pk);
            match def.to_file(committee_def_path.clone()).map_err(|e| format!("Unable to save committee definition: error:{:?}", e)) {
                Ok(_) => { },
                Err(e) => {
                    return Err(e.to_string());
                }
            }

            let keystore_share = keystore_share.unwrap();
            let voting_keystore_share_path = default_keystore_share_path(&keystore_share, validator_dir.clone());
            let voting_keystore_share_password_path = default_keystore_share_password_path(&keystore_share, secret_dir.clone());
            match &node.validator_store {
                Some(validator_store) => {
                    let _ = validator_store.add_validator_keystore_share(
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
                    ).await;
                    info!("[VA {}] added validator {}", validator_id, validator_pk); 
                },
                _ => {
                    error!("[VA {}] failed to add validator {}. Error: no validator store is set.", validator_id, validator_pk); 
                }
            }
        }, 
        None => {
            error!("[VA {}] can't find validator's releated operators", validator_id);
        }   
    }
    Ok(())
}

pub async fn stop_validator<T: EthSpec>(node: Arc<ParkingRwLock<Node<T>>>, validator: Validator) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.validator_public_key).map_err(|e| format!("[VA {}] Deserialize error ({:?})", validator_id, e))?;
    info!("[VA {}] stopping validator {}...", validator_id, validator_pk);

    let (validator_dir, secret_dir, validator_store) = {
        let node_ = node.read();
        let validator_dir = node_.config.validator_dir.clone();
        let secret_dir = node_.config.secrets_dir.clone();
        let validator_store = node_.validator_store.clone();

        (validator_dir, secret_dir, validator_store)
    };
    let base_dir = secret_dir.parent().ok_or(format!("[VA {}] Failed to get parent of secret dir (possibly the root dir)", validator_id))?;

    cleanup_handler(node.clone(), validator_id).await;
    cleanup_keystore(validator_store, &validator_pk).await;
    cleanup_db(base_dir, validator_id)?;
    cleanup_validator_dir(&validator_dir, &validator_pk, validator_id)?;
    cleanup_password_dir(&secret_dir, &validator_pk, validator_id)?;

    info!("[VA {}] stopped validator {}", validator_id, validator_pk); 
    Ok(())
}

pub async fn cleanup_handler<T: EthSpec>(node: Arc<ParkingRwLock<Node<T>>>, validator_id: u64) {
    let node_ = node.read();
    let _ = node_.tx_handler_map.write().await.remove(&validator_id);
    let _ = node_.mempool_handler_map.write().await.remove(&validator_id);
    let _ = node_.consensus_handler_map.write().await.remove(&validator_id);
    let _ = node_.signature_handler_map.write().await.remove(&validator_id);
}

pub async fn cleanup_keystore<T: EthSpec>(validator_store: Option<Arc<ValidatorStore<SystemTimeSlotClock, T>>>, validator_pk: &PublicKey) {
    match validator_store {
        Some(validator_store) => {
            validator_store.stop_validator_keystore(validator_pk).await;
        }
        _ => {
        }
    }
}

pub fn cleanup_db(base_dir: &Path, validator_id: u64) -> Result<(), String> {
    let db_dir = base_dir.join(DB_FILENAME).join(validator_id.to_string());
    if db_dir.exists() {
        remove_dir_all(&db_dir).map_err(|e| format!("[VA {}] Failed to remove DB file ({})", validator_id, e))?;
    }
    Ok(())
}

pub fn cleanup_validator_dir(validator_dir: &Path, validator_pk: &PublicKey, validator_id: u64) -> Result<(), String> {
    let deleted_validator_dir = validator_dir.join(format!("{}", validator_pk));
    if deleted_validator_dir.exists() {
        remove_dir_all(&deleted_validator_dir).map_err(|e| format!("[VA {}] Failed to delete validator dir ({})", validator_id, e))?;
    }
    Ok(())
}

pub fn cleanup_password_dir(secret_dir: &Path, validator_pk: &PublicKey, validator_id: u64) -> Result<(), String> {
    for password_file in secret_dir.read_dir().map_err(|e| format!("[VA {}] Failed to read secret dir ({})", validator_id, e))? {
        let password_file_name = 
            password_file
            .map_err(|e| format!("[VA {}] Failed to read secret entry ({})", validator_id, e))?
            .file_name()
            .into_string()
            .map_err(|e| format!("[VA {}] Failed to convert secret entry path to string ({:?})", validator_id, e))?;
        let validator_pk_prefix = format!("{}", validator_pk);
        if password_file_name.starts_with(&validator_pk_prefix) {
            let password_file_dir = secret_dir.join(password_file_name);
            if password_file_dir.exists() {
                remove_file(&password_file_dir).map_err(|e| format!("[VA {}] Failed to delete password file ({})", validator_id, e))?;
                info!("[VA {}] removed password file {:?}", validator_id, password_file_dir);
                break;
            }
            else {
                warn!("[VA {}] password file does not exist: {:?}", validator_id, password_file_dir);
            }
        }
    }
    Ok(())
}