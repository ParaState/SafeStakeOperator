use std::collections::HashMap;
use std::fs::{remove_dir_all, remove_file};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bls::{Keypair as BlsKeypair, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use consensus::ConsensusReceiverHandler;
use eth2_keystore::KeystoreBuilder;
use hsconfig::{ConfigError, Secret};
use hsconfig::Export as _;
use mempool::{MempoolReceiverHandler, TxReceiverHandler};
use network::Receiver as NetworkReceiver;
use slot_clock::SystemTimeSlotClock;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use log::{error, info, warn};
use types::EthSpec;
use types::PublicKey;
use validator_dir::insecure_keys::INSECURE_PASSWORD;
use web3::types::H160;

use crate::crypto::dkg::{DKGSemiHonest, SimpleDistributedSigner, DKGTrait};

use crate::crypto::elgamal::{Ciphertext, Elgamal};
use crate::deposit::get_distributed_deposit;
use crate::network::io_committee::{NetIOChannel, NetIOCommittee};
use crate::node::config::{
    base_to_transaction_addr, base_to_mempool_addr, base_to_consensus_addr, base_to_signature_addr,
    API_ADDRESS, DB_FILENAME, DISCOVERY_PORT_OFFSET, DKG_PORT_OFFSET, NodeConfig,
    PRESTAKE_SIGNATURE_URL, STAKE_SIGNATURE_URL, VALIDATOR_PK_URL,
};
use crate::node::discovery::Discovery;
/// The default channel capacity for this module.
use crate::node::dvfcore::DvfSignatureReceiverHandler;
use crate::node::contract::{
    Contract, ContractCommand, EncryptedSecretKeys, Initiator, OperatorPublicKeys,
    SharedPublicKeys, Validator, SELF_OPERATOR_ID, OperatorIds, CONTRACT_DATABASE_FILE
};
use crate::node::db::Database;
use crate::node::utils::{request_to_web_server, convert_address_to_withdraw_crendentials, ValidatorPkRequest, DepositRequest};
use crate::validation::account_utils::default_keystore_share_password_path;
use crate::validation::account_utils::default_keystore_share_path;
use crate::validation::account_utils::default_operator_committee_definition_path;
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::validation::validator_dir::share_builder::{insecure_kdf, ShareBuilder};
use crate::validation::validator_store::ValidatorStore;

const THRESHOLD: u64 = 3;
pub const COMMITTEE_IP_HEARTBEAT_INTERVAL: u64 = 300;

type InitiatorStore =
    Arc<RwLock<HashMap<u32, (BlsKeypair, BlsPublicKey, HashMap<u64, BlsPublicKey>)>>>;

fn with_wildcard_ip(mut addr: SocketAddr) -> SocketAddr {
    addr.set_ip("0.0.0.0".parse().unwrap());
    addr
}

pub struct Node<T: EthSpec> {
    pub config: NodeConfig,
    pub secret: Secret,
    pub tx_handler_map: Arc<RwLock<HashMap<u64, TxReceiverHandler>>>,
    pub mempool_handler_map: Arc<RwLock<HashMap<u64, MempoolReceiverHandler>>>,
    pub consensus_handler_map: Arc<RwLock<HashMap<u64, ConsensusReceiverHandler>>>,
    pub signature_handler_map: Arc<RwLock<HashMap<u64, DvfSignatureReceiverHandler>>>,
    pub validator_store: Option<Arc<ValidatorStore<SystemTimeSlotClock, T>>>,
    pub discovery: Arc<RwLock<Discovery>>,
}

// impl Send for Node{}
impl<T: EthSpec> Node<T> {
    pub async fn new(config: NodeConfig) -> Result<Option<Arc<RwLock<Self>>>, ConfigError> {
        let self_address = config.base_address.ip();
        let secret_dir = config.secrets_dir.clone();
        let secret = Node::<T>::open_or_create_secret(config.node_key_path.clone())?;

        info!("node public key {}", secret.name.encode_base64());

        let tx_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let mempool_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let consensus_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let signature_handler_map = Arc::new(RwLock::new(HashMap::new()));

        let transaction_address = with_wildcard_ip(base_to_transaction_addr(config.base_address));
        NetworkReceiver::spawn(
            transaction_address,
            Arc::clone(&tx_handler_map),
            "transaction",
        );
        info!(
            "Node {} listening to client transactions on {}",
            secret.name, transaction_address
        );

        let mempool_address = with_wildcard_ip(base_to_mempool_addr(config.base_address));
        NetworkReceiver::spawn(mempool_address, Arc::clone(&mempool_handler_map), "mempool");
        info!(
            "Node {} listening to mempool messages on {}",
            secret.name, mempool_address
        );

        let consensus_address = with_wildcard_ip(base_to_consensus_addr(config.base_address));
        NetworkReceiver::spawn(
            consensus_address,
            Arc::clone(&consensus_handler_map),
            "consensus",
        );
        info!(
            "Node {} listening to consensus messages on {}",
            secret.name, consensus_address
        );

        let signature_address = with_wildcard_ip(base_to_signature_addr(config.base_address));
        NetworkReceiver::spawn(
            signature_address,
            Arc::clone(&signature_handler_map),
            "signature",
        );
        info!(
            "Node {} listening to signature messages on {}",
            secret.name, signature_address
        );

        let base_port = config.base_address.port();
        let discovery = Discovery::spawn(
            self_address,
            base_port + DISCOVERY_PORT_OFFSET,
            secret.clone(),
            config.boot_enrs.clone(),
            config.base_store_path.clone(),
        ).await;
        
        let node = Self {
            config,
            secret: secret.clone(),
            tx_handler_map: Arc::clone(&tx_handler_map),
            mempool_handler_map: Arc::clone(&mempool_handler_map),
            consensus_handler_map: Arc::clone(&consensus_handler_map),
            signature_handler_map: Arc::clone(&signature_handler_map),
            validator_store: None,
            discovery: Arc::new(RwLock::new(discovery)),
        };

        let base_dir = secret_dir.parent().unwrap().to_path_buf();
        let db = Database::new(base_dir.join(CONTRACT_DATABASE_FILE))
            .map_err(|e| {error!("can't create contract database {:?}", e); ConfigError::ReadError { file: CONTRACT_DATABASE_FILE.to_string(), message: "can't create contract database".to_string() }})?;
        Contract::spawn(
            base_dir,
            secret.name,
            db.clone()
        );
        let node = Arc::new(RwLock::new(node));
        let initializer_store = Arc::new(RwLock::new(HashMap::new()));
        Node::process_contract_command(
            Arc::clone(&node),
            db,
            initializer_store,
        );

        info!("Node {} successfully booted", secret.name);
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
        node: Arc<RwLock<Node<T>>>,
        db: Database,
        initializer_store: InitiatorStore,
    ) {
        tokio::spawn(async move {
            loop {
                let mut query_interval = tokio::time::interval(Duration::from_secs(12));
                query_interval.tick().await;
                match db.get_contract_command().await {
                    Ok((command, id)) => {
                        if id == 0 {
                            continue;
                        }
                        let cmd: ContractCommand = serde_json::from_str(&command).unwrap();
                        match cmd {
                            ContractCommand::StartValidator(
                                validator,
                                operator_pks,
                                shared_pks,
                                encrypted_sks,
                            ) => {
                                let va_id = validator.id;
                                info!("StartValidator");
                                match add_validator(
                                    node.clone(),
                                    validator,
                                    operator_pks,
                                    shared_pks,
                                    encrypted_sks,
                                )
                                    .await
                                {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to add validator: {} {}", e, va_id);
                                        // save va information to database
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::RemoveValidator(validator) => {
                                info!("RemoveValidator");
                                let va_id = validator.id;
                                match remove_validator(node.clone(), validator).await {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to remove validator:  {} {}", e, va_id);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::ActivateValidator(validator) => {
                                info!("ActivateValidator");
                                let va_id = validator.id;
                                match activate_validator(node.clone(), validator).await {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to active validator:  {} {}", e, va_id);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::StopValidator(validator) => {
                                info!("StopValidator");
                                let va_id = validator.id;
                                match stop_validator(node.clone(), validator).await {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to stop validator: {} {}", e, va_id);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::StartInitiator(initiator, operator_pks) => {
                                info!("StartInitiator");
                                let initiator_id = initiator.id;
                                match start_initializer(
                                    node.clone(),
                                    initiator,
                                    operator_pks,
                                    initializer_store.clone(),
                                )
                                    .await
                                {
                                    Ok(_) => { db.delete_contract_command(id).await; }
                                    Err(e) => {
                                        error!("Failed to start initiator:  {} {}", e, initiator_id);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::MiniPoolCreated(
                                initiator_id,
                                validator_pk,
                                op_pks,
                                op_ids,
                                minipool_address,
                            ) => {
                                info!("MiniPoolCreated");
                                match minipool_deposit(
                                    node.clone(),
                                    initiator_id,
                                    validator_pk,
                                    op_pks,
                                    op_ids,
                                    minipool_address,
                                    initializer_store.clone(),
                                    8,
                                )
                                    .await
                                {
                                    Ok(_) => { db.delete_contract_command(id).await; }
                                    Err(e) => {
                                        error!("Failed to process minpool created: {} {}", e, initiator_id);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::MiniPoolReady(
                                initiator_id,
                                validator_pk,
                                op_pks,
                                op_ids,
                                minipool_address,
                            ) => {
                                info!("MiniPoolReady");
                                match minipool_deposit(
                                    node.clone(),
                                    initiator_id,
                                    validator_pk,
                                    op_pks,
                                    op_ids,
                                    minipool_address,
                                    initializer_store.clone(),
                                    24,
                                )
                                    .await
                                {
                                    Ok(_) => { 
                                        db.delete_contract_command(id).await; 
                                        let _ = initializer_store.write().await.remove(&initiator_id);
                                    }
                                    Err(e) => {
                                        error!("Failed to process minpool ready: {} {}", e, initiator_id);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                                
                            }
                        }
                    },
                    Err(e) => {
                        error!("error happens when get contract command {}", e);
                    }
                }
            }
        });
    }

    pub fn spawn_committee_ip_monitor(
        node: Arc<RwLock<Node<T>>>, 
        mut committee_def: OperatorCommitteeDefinition, 
        exit: exit_future::Exit
    ) {
        tokio::spawn(async move {
            let (base_port, validator_dir) = {
                let node_ = node.read().await;
                (node_.config.base_address.port(), node_.config.validator_dir.clone())
                
            };
            let mut query_interval = tokio::time::interval(Duration::from_secs(COMMITTEE_IP_HEARTBEAT_INTERVAL));
            loop {
                let exit_clone = exit.clone();
                let validator_pk = committee_def.validator_public_key.clone();
                tokio::select! {
                    _ = query_interval.tick() => {
                        let node_lock = node.read().await;
                        let mut discovery = node_lock.discovery.write().await;
                        // Query IP for each operator in this committee. If any of them changed, should restart the VA.
                        let mut restart = false;
                        for i in 0..committee_def.node_public_keys.len() {
                            if let Some(ip) = discovery.query_ip(&committee_def.node_public_keys[i].0).await {
                                if let Some(socket) = committee_def.base_socket_addresses[i].as_mut() {
                                    if socket.ip() != ip {
                                        socket.set_ip(ip);
                                        restart = true;
                                    }
                                }
                                else {
                                    committee_def.base_socket_addresses[i] = Some(SocketAddr::new(ip, base_port));
                                    restart = true;
                                }
                            }
                        }
                        drop(discovery);
                        drop(node_lock);
                        if restart {
                            // Save the committee definition to file, as the file will be used to restart the VA.
                            let committee_def_path =
                                default_operator_committee_definition_path(&validator_pk, validator_dir.clone());
                            info!("Committee ip Changed. Saving definition file to path {:?}", &committee_def_path);
                            if let Err(e) = committee_def.to_file(committee_def_path) {
                                error!("Unable to save committee definition. Error: {:?}", e);
                                continue;
                            }

                            match restart_validator(node.clone(), committee_def.validator_id, committee_def.validator_public_key.clone()).await {
                                Ok(_) => {
                                    info!("Successfully restart validator: {}, pk: {}", 
                                        committee_def.validator_id, committee_def.validator_public_key);
                                }
                                Err(e) => {
                                    error!("Failed to restart validator: {}, pk: {}. Error: {}", 
                                        committee_def.validator_id, committee_def.validator_public_key, e);
                                }
                            };
                        }
                    }
                    () = exit_clone => {
                        break;
                    }
                }
            }
        });
    }
}

pub async fn add_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
    operator_public_keys: OperatorPublicKeys,
    shared_public_keys: SharedPublicKeys,
    encrypted_secret_keys: EncryptedSecretKeys,
    // tx_validator_command: MonitoredSender<ContractCommand>,
) -> Result<(), String> {
    let node = node.read().await;
    let base_port = node.config.base_address.port();
    let validator_dir = node.config.validator_dir.clone();
    let secret_dir = node.config.secrets_dir.clone();
    let secret = node.secret.clone();
    let sk = &secret.secret;
    let self_pk = &secret.name;
    let total = operator_public_keys.len();
    let secret_key = secp256k1::SecretKey::from_slice(&sk.0).expect("Unable to load secret key");

    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("Unable to deserialize validator public key: {:?}", e))?;
    info!("[VA {}] adding validator {}", validator_id, validator_pk);
    let added_validator_dir = validator_dir.join(format!("{}", validator_pk));
    if added_validator_dir.exists() {
        return Err("Validator exists".to_string());
    }

    let operator_base_address: Vec<Option<SocketAddr>> = {
        let mut discovery = node.discovery.write().await;
        discovery.query_addrs(&operator_public_keys, base_port).await
    };
        // match get_operator_ips(&operator_public_keys, base_port).await {
        //     Ok(address) => address,
        //     Err(e) => {
        //         info!("Will process the validator again");
        //         cleanup_validator_dir(&validator_dir, &validator_pk, validator_id)?;
        //         cleanup_password_dir(&secret_dir, &validator_pk, validator_id)?;
        //         return Err(e);
        //     }
        // };

    let operator_ids: Vec<u64> = validator
        .releated_operators
        .iter()
        .map(|x| *x as u64)
        .collect();
    let operator_bls_pks: Vec<Result<PublicKey, String>> = shared_public_keys
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
    let operator_node_pks: Vec<hscrypto::PublicKey> = operator_public_keys
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
        total: total as u64,
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
    def.to_file(committee_def_path.clone())
        .map_err(|e| format!("Unable to save committee definition: error:{:?}", e))?;

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

// pub async fn activate_validator<T: EthSpec>(
//     node: Arc<RwLock<Node<T>>>,
//     validator: Validator,
// ) -> Result<(), String> {
//     let node = node.read().await;
//     let validator_id = validator.id;
//     let validator_pk = PublicKey::deserialize(&validator.public_key)
//         .map_err(|e| format!("Unable to deserialize validator public key: {:?}", e))?;
//     let validator_dir = node.config.validator_dir.clone();
//     let secret_dir = node.config.secrets_dir.clone();

//     let committee_def_path =
//         default_operator_committee_definition_path(&validator_pk, validator_dir.clone());

//     let voting_keystore_share_path = validator_dir
//         .join(format!("{}", validator_pk))
//         .join(format!("{}", SELF_OPERATOR_ID.get().unwrap()));

//     let keystore_share =
//         KeystoreShare::from_json_file(&voting_keystore_share_path).map_err(|e| {
//             format!("failed to get keystore share from file, error: {:?}", e)
//         })?;
//     let voting_keystore_share_password_path =
//         default_keystore_share_password_path(&keystore_share, secret_dir.clone());
//     match &node.validator_store {
//         Some(validator_store) => {
//             let _ = validator_store
//                 .add_validator_keystore_share(
//                     voting_keystore_share_path,
//                     voting_keystore_share_password_path,
//                     true,
//                     None,
//                     None,
//                     None,
//                     None,
//                     committee_def_path,
//                     keystore_share.master_id,
//                     keystore_share.share_id,
//                 )
//                 .await;
//             info!("[VA {}] reactivate validator {}", validator_id, validator_pk);
//         }
//         _ => {
//             error!(
//                 "[VA {}] failed to add validator {}. Error: no validator store is set.",
//                 validator_id, validator_pk
//             );
//         }
//     }

//     Ok(())
// }

pub async fn activate_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("Unable to deserialize validator public key: {:?}", e))?;
    info!(
        "[VA {}] activating validator {}...",
        validator_id, validator_pk
    );
    let validator_store = {
        let node_ = node.read().await;
        node_.validator_store.clone()
    };

    match validator_store {
        Some(validator_store) => {
            validator_store.start_validator_keystore(&validator_pk).await;
            info!("[VA {}] validator {} activated", validator_id, validator_pk);
        }
        _ => {
            error!(
                "[VA {}] failed to activate validator {}. Error: no validator store is set.",
                validator_id, validator_pk
            );
        }
    }

    Ok(())
}

pub async fn remove_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("[VA {}] Deserialize error ({:?})", validator_id, e))?;
    info!(
        "[VA {}] removing validator {}...",
        validator_id, validator_pk
    );
    let (validator_dir, secret_dir, validator_store) = {
        let node_ = node.read().await;
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

    info!("[VA {}] removed validator {}", validator_id, validator_pk);
    Ok(())
}

pub async fn stop_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = PublicKey::deserialize(&validator.public_key).map_err(|e| format!("[VA {}] Deserialize error ({:?})", validator_id, e))?;
    info!(
        "[VA {}] stopping validator {}...",
        validator_id, validator_pk
    );
    let validator_store = {
        let node_ = node.read().await;
        node_.validator_store.clone()
    };

    cleanup_handler(node.clone(), validator_id).await;
    match validator_store {
        Some(validator_store) => {
            validator_store.stop_validator_keystore(&validator_pk).await;
        }
        _ => {}
    }
    info!("[VA {}] stopped validator {}", validator_id, validator_pk);
    Ok(())
}

pub async fn start_initializer<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    initiator: Initiator,
    operator_public_keys: OperatorPublicKeys,
    initializer_store: Arc<
        RwLock<HashMap<u32, (BlsKeypair, BlsPublicKey, HashMap<u64, BlsPublicKey>)>>,
    >,
    // tx_contract_command: MonitoredSender<ContractCommand>,
) -> Result<(), String> {
    let node = node.read().await;
    let base_port = node.config.base_address.port();
    let operator_ips: Vec<Option<IpAddr>> = {
        let mut discovery = node.discovery.write().await;
        discovery.query_ips(&operator_public_keys).await
    };
    // let operator_ips: Vec<Option<SocketAddr>> =
    //     match get_operator_ips(&operator_public_keys, base_port).await {
    //         Ok(ips) => ips,
    //         Err(e) => {
    //             sleep(Duration::from_secs(10)).await;
    //             // let _ = tx_contract_command
    //             //     .send(ContractCommand::StartInitiator(
    //             //         initiator,
    //             //         operator_public_keys,
    //             //     ))
    //             //     .await;
    //             // info!("Will process the initiator again");
    //             return Err(e);
    //         }
    //     };
    if operator_ips.iter().any(|x| x.is_none()) {
        sleep(Duration::from_secs(10)).await;
        return Err("StartInitializer: Insufficient operators discovered for DKG".to_string());
    }
    let operator_ips: Vec<SocketAddr> = operator_ips.iter().map(|x| {
        SocketAddr::new(x.unwrap(), base_port + DKG_PORT_OFFSET)
    }).collect();

    let self_op_id = *SELF_OPERATOR_ID
        .get()
        .ok_or("Self operator has not been set".to_string())?;
    let op_ids: Vec<u64> = initiator
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
    let dkg = DKGSemiHonest::new(self_op_id as u64, io, THRESHOLD as usize);
    let (keypair, va_pk, shared_pks) = dkg
        .run()
        .await
        .map_err(|e| format!("run dkg failed {:?}", e))?;
    let pk_str: String = va_pk.as_hex_string()[2..].to_string();
    // push va pk to web server
    let request_body = ValidatorPkRequest {
        validator_pk: pk_str,
        initiator_id: initiator.id,
        initializer_address: format!("{0:0x}", initiator.owner_address),
        operators: op_ids,
    };
    let url_str = API_ADDRESS.get().unwrap().to_owned() + VALIDATOR_PK_URL;
    request_to_web_server(request_body, &url_str).await?;
    // save to local storage
    initializer_store
        .write()
        .await
        .insert(initiator.id, (keypair, va_pk, shared_pks));
    info!("dkg success!");
    Ok(())
}

// TODO process minipool created event
pub async fn minipool_deposit<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    initiator_id: u32,
    validator_pk: Vec<u8>,
    operator_public_keys: OperatorPublicKeys,
    operator_ids: OperatorIds,
    minipool_address: H160,
    initializer_store: InitiatorStore,
    amount: u64
) -> Result<(), String> {
    let node = node.read().await;
    let base_port = node.config.base_address.port();
    let operator_ips: Vec<Option<IpAddr>> = {
        let mut discovery = node.discovery.write().await;
        discovery.query_ips(&operator_public_keys).await
    };
    // let operator_ips = match get_operator_ips(&operator_public_keys, base_port).await {
    //     Ok(ips) => ips,
    //     Err(e) => {
    //         error!("Some operators are not online, it's critical error, minipool exiting");
    //         initializer_store.write().await.remove(&initiator_id).ok_or(format!("can't remove initiator store id: {}", initiator_id))?;
    //         return Err(e);
    //     }
    // };
    if operator_ips.iter().any(|x| x.is_none()) {
        error!("Some operators are not online, it's critical error, minipool exiting");
        initializer_store.write().await.remove(&initiator_id).ok_or(format!("can't remove initiator store id: {}", initiator_id))?;
        return Err("MinipoolDeposit: Insufficient operators discovered for distributed signing".to_string());
    }
    let operator_ips: Vec<SocketAddr> = operator_ips.iter().map(|x| {
        SocketAddr::new(x.unwrap(), base_port + DKG_PORT_OFFSET)
    }).collect();

    let op_ids: Vec<u64> = operator_ids.into_iter().map(|x| x as u64).collect();
    let self_op_id = *SELF_OPERATOR_ID
        .get()
        .ok_or("Self operator has not been set".to_string())?;
    let store = initializer_store.read().await;
    let (keypair, va_pk, op_bls_pks) = store.get(&initiator_id).ok_or(format!("can't get initiator store id: {}", initiator_id))?;
    let io_committee = Arc::new(NetIOCommittee::new(self_op_id as u64, base_port + DKG_PORT_OFFSET, &op_ids, &operator_ips).await);
    let signer = SimpleDistributedSigner::new(self_op_id as u64, keypair.clone(), va_pk.clone(), op_bls_pks.clone(), io_committee, THRESHOLD as usize);
    let mpk = BlsPublicKey::deserialize(&validator_pk).map_err(|e| format!("Can't deserilize bls pk {:?}", e))?;
    if mpk != *va_pk {
        return Err(format!("validator pks don't match, local stored: {:?}, received {:?}", va_pk, mpk));
    }
    let withdraw_cret = convert_address_to_withdraw_crendentials(minipool_address);
    let deposit_data = get_distributed_deposit::<NetIOCommittee, NetIOChannel, T>(&signer, &withdraw_cret, amount).await.map_err(|e| {
        format!("Can't get distributed deposit data {:?}", e)
    })?;
    let request_body = DepositRequest::convert(deposit_data);
    let url = match amount {
        8 => PRESTAKE_SIGNATURE_URL,
        24 => STAKE_SIGNATURE_URL,
        _ => {
            error!("invalid amount");
            "error url"
        }
    };
    let url_str = API_ADDRESS.get().unwrap().to_owned() + url;
    request_to_web_server(request_body, &url_str).await.map_err(|e| format!("can't send request to server {:?}, url: {}", e, url_str))?;
    Ok(())
}

pub async fn restart_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>, 
    validator_id: u64,
    validator_pk: PublicKey
) -> Result<(), String> {

    info!(
        "[VA {}] restarting validator {}...",
        validator_id, validator_pk
    );
    let validator_store = {
        let node_ = node.read().await;
        node_.validator_store.clone()
    };

    cleanup_handler(node.clone(), validator_id).await;
    match validator_store {
        Some(validator_store) => {
            validator_store.restart_validator_keystore(&validator_pk).await;
        }
        _ => {}
    }
    Ok(())
}

pub async fn cleanup_handler<T: EthSpec>(node: Arc<RwLock<Node<T>>>, validator_id: u64) {
    let node_ = node.read().await;
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
            validator_store.remove_validator_keystore(validator_pk).await;
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
    info!("Dvf node db removed: {:?}", db_dir);
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
