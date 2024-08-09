use crate::crypto::dkg::{DKGMalicious, DKGTrait, SimpleDistributedSigner};
use crate::crypto::elgamal::{Ciphertext, Elgamal};
use crate::deposit::get_distributed_deposit;
use crate::exit::get_distributed_voluntary_exit;
use crate::network::io_committee::{SecureNetIOChannel, SecureNetIOCommittee};
use crate::node::config::{
    base_to_consensus_addr, base_to_mempool_addr, base_to_signature_addr, base_to_transaction_addr,
    NodeConfig, API_ADDRESS, DB_FILENAME, DISCOVERY_PORT_OFFSET, DKG_PORT_OFFSET,
    PRESTAKE_SIGNATURE_URL, STAKE_SIGNATURE_URL, VALIDATOR_PK_URL,
};
use crate::node::contract::{
    Contract, ContractCommand, EncryptedSecretKeys, Initiator, InitiatorStoreRecord, OperatorIds,
    OperatorPublicKeys, SharedPublicKeys, Validator, CONTRACT_DATABASE_FILE, DATABASE,
    SELF_OPERATOR_ID, THRESHOLD_MAP,
};
use crate::node::{
    db::{self, Database},
    discovery::Discovery,
    dvfcore::DvfSignatureReceiverHandler,
    status_report::StatusReport,
    utils::{
        convert_address_to_withdraw_crendentials, request_to_web_server, DepositRequest,
        SignDigest, ValidatorPkRequest,
    },
};
use crate::utils::error::DvfError;
use crate::validation::{
    account_utils::{
        default_keystore_share_password_path, default_keystore_share_path,
        default_operator_committee_definition_path,
    },
    eth2_keystore_share::keystore_share::KeystoreShare,
    http_metrics::metrics::{self, set_int_gauge},
    operator_committee_definitions::OperatorCommitteeDefinition,
    validator_dir::share_builder::{insecure_kdf, ShareBuilder},
    validator_store::ValidatorStore,
};
use bls::{Keypair as BlsKeypair, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use consensus::ConsensusReceiverHandler;
use eth2_keystore::KeystoreBuilder;
use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use log::{error, info, warn};
use mempool::{MempoolReceiverHandler, TxReceiverHandler};
use network::Receiver as NetworkReceiver;
use slot_clock::SystemTimeSlotClock;
use std::collections::HashMap;
use std::fs::{remove_dir_all, remove_file};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use types::EthSpec;
use validator_dir::insecure_keys::INSECURE_PASSWORD;
use web3::types::H160;

const THRESHOLD: u64 = 3;
pub const COMMITTEE_IP_HEARTBEAT_INTERVAL: u64 = 1800;
pub const BALANCE_USED_UP: i64 = 1;
pub const BALANCE_STILL_AVAILABLE: i64 = 0;
// type InitiatorStore =
//     Arc<RwLock<HashMap<u32, (BlsKeypair, BlsPublicKey, HashMap<u64, BlsPublicKey>)>>>;

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
    pub discovery: Arc<Discovery>,
    pub db: Database,
}

// impl Send for Node{}
impl<T: EthSpec> Node<T> {
    pub async fn new(config: NodeConfig) -> Result<Arc<RwLock<Self>>, ConfigError> {
        let base_address = config.base_address.clone();
        let self_ip = base_address.ip();

        let secret_dir = config.secrets_dir.clone();
        let secret = Node::<T>::open_or_create_secret(config.node_key_path.clone())?;
        create_node_key_hex_backup(config.node_key_hex_path.clone(), &secret)?;
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
            self_ip,
            base_port + DISCOVERY_PORT_OFFSET,
            secret.clone(),
            config.boot_enrs.clone(),
            config.base_store_path.clone(),
        )
        .await;

        let base_dir = secret_dir.parent().unwrap().to_path_buf();
        let db = Database::new(base_dir.join(CONTRACT_DATABASE_FILE)).map_err(|e| {
            error!("can't create contract database {:?}", e);
            ConfigError::ReadError {
                file: CONTRACT_DATABASE_FILE.to_string(),
                message: "can't create contract database".to_string(),
            }
        })?;
        DATABASE.set(db.clone()).unwrap();
        let node = Self {
            config,
            secret: secret.clone(),
            tx_handler_map: Arc::clone(&tx_handler_map),
            mempool_handler_map: Arc::clone(&mempool_handler_map),
            consensus_handler_map: Arc::clone(&consensus_handler_map),
            signature_handler_map: Arc::clone(&signature_handler_map),
            validator_store: None,
            discovery: Arc::new(discovery),
            db: db.clone(),
        };

        Contract::spawn(base_dir, secret.name, db.clone());
        let node = Arc::new(RwLock::new(node));
        Node::process_contract_command(Arc::clone(&node), db);
        StatusReport::spawn(
            base_address,
            *SELF_OPERATOR_ID.get().unwrap(),
            secret.secret,
        );

        info!("Node {} successfully booted", secret.name);
        Ok(node)
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

    pub fn process_contract_command(node: Arc<RwLock<Node<T>>>, db: Database) {
        tokio::spawn(async move {
            let mut query_interval = tokio::time::interval(Duration::from_secs(6));
            loop {
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
                                    validator.clone(),
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
                                        let _ = remove_validator(node.clone(), validator).await;
                                    }
                                }
                            }
                            ContractCommand::RemoveValidator(validator) => {
                                info!("RemoveValidator");
                                let va_pubkey = hex::encode(validator.public_key.clone());
                                match remove_validator(node.clone(), validator).await {
                                    Ok(_) => {
                                        db.delete_validator(va_pubkey).await;
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to remove validator:  {} {}", e, va_pubkey);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::ActivateValidator(validator) => {
                                info!("ActivateValidator");
                                let va_id = validator.id;
                                let validator_pubkey = hex::encode(validator.public_key.clone());
                                match activate_validator(node.clone(), validator).await {
                                    Ok(_) => {
                                        db.enable_validator(validator_pubkey).await;
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
                                let validator_pubkey = hex::encode(validator.public_key.clone());
                                match stop_validator(node.clone(), validator).await {
                                    Ok(_) => {
                                        db.disable_validator(validator_pubkey).await;
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
                                match start_initiator(node.clone(), initiator, operator_pks, &db)
                                    .await
                                {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to start initiator:  {} {}",
                                            e, initiator_id
                                        );
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
                                    &db,
                                    1_000_000_000,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to process minpool created: {} {}",
                                            e, initiator_id
                                        );
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
                                    &db,
                                    31_000_000_000,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to process minpool ready: {} {}",
                                            e, initiator_id
                                        );
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                            ContractCommand::RemoveInitiator(initiator, op_pks) => {
                                info!("Remove initiator, exit validator");
                                match remove_initiator(node.clone(), initiator, op_pks, &db).await {
                                    Ok(_) => {
                                        db.delete_contract_command(id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to process remove initiator ready: {}", e);
                                        db.updatetime_contract_command(id).await;
                                    }
                                }
                            }
                        }
                    }
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
        exit: exit_future::Exit,
    ) {
        tokio::spawn(async move {
            let validator_dir = {
                let node_ = node.read().await;
                node_.config.validator_dir.clone()
            };
            let db = {
                let node_ = node.read().await;
                node_.db.clone()
            };
            let mut query_interval =
                tokio::time::interval(Duration::from_secs(COMMITTEE_IP_HEARTBEAT_INTERVAL));
            loop {
                let exit_clone = exit.clone();
                let validator_pk = committee_def.validator_public_key.clone();
                tokio::select! {
                    _ = query_interval.tick() => {
                        let node_lock = node.read().await;
                        // Query IP for each operator in this committee. If any of them changed, should restart the VA.
                        let mut restart = false;
                        for i in 0..committee_def.node_public_keys.len() {
                            let boot_idx = rand::random::<usize>() % 2;
                            if let Some(addr) = node_lock.discovery.query_addr_from_boot(boot_idx, &committee_def.node_public_keys[i].0).await {
                                if let Some(socket) = committee_def.base_socket_addresses[i].as_mut() {
                                    if *socket != addr {
                                        info!("op id: {}, local committee definition address {}, queried result {}", committee_def.operator_ids[i], socket, addr);
                                        *socket = addr;
                                        restart = true;
                                    }
                                }
                                else {
                                    committee_def.base_socket_addresses[i] = Some(addr);
                                    restart = true;
                                }
                            }
                        }
                        drop(node_lock);
                        if restart {
                            // Save the committee definition to file, as the file will be used to restart the VA.
                            let committee_def_path =
                                default_operator_committee_definition_path(&validator_pk, validator_dir.clone());
                            info!("Committee ip Changed. Saving definition file to path {:?}", &committee_def_path);
                            if let Err(e) = committee_def.save(committee_def_path.parent().unwrap()) {
                                error!("Unable to save committee definition. Error: {:?}", e);
                                continue;
                            }
                            let va = db.query_validator_by_public_key(hex::encode(validator_pk.serialize().to_vec())).await.unwrap();
                            match va {
                                Some(va) => {
                                    let va_id = va.id;
                                    let cmd = ContractCommand::StopValidator(va.clone());
                                    db.insert_contract_command(va_id, serde_json::to_string(&cmd).unwrap()).await;
                                    let cmd = ContractCommand::ActivateValidator(va);
                                    db.insert_contract_command(va_id, serde_json::to_string(&cmd).unwrap()).await;
                                },
                                None => {
                                    error!("Unable to find validator with public key {:?}", validator_pk);
                                }
                            }
                            // loop {
                            //     match restart_validator(node.clone(), committee_def.validator_id, committee_def.validator_public_key.clone()).await {
                            //         Ok(_) => {
                            //             info!("Successfully restart validator: {}, pk: {}",
                            //                 committee_def.validator_id, committee_def.validator_public_key);
                            //             break;
                            //         }
                            //         Err(DvfError::ValidatorStoreNotReady) => {
                            //             error!("Failed to restart validator: {}, pk: {}. Error:
                            //                 validator store is not ready yet, will try again in 1 minute.",
                            //                 committee_def.validator_id, committee_def.validator_public_key);
                            //             tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                            //             continue;
                            //         }
                            //         Err(e) => {
                            //             error!("Failed to restart validator: {}, pk: {}. Error: {:?}",
                            //                 committee_def.validator_id, committee_def.validator_public_key, e);
                            //             break;
                            //         }
                            //     };
                            // }
                        }
                    }
                    () = exit_clone => {
                        break;
                    }
                }
            }
        });
    }

    pub async fn set_validators_fee_recipient(&self) -> Result<(), String> {
        let secret_dir = self.config.secrets_dir.clone();
        let db_path = secret_dir
            .parent()
            .unwrap()
            .to_path_buf()
            .join(CONTRACT_DATABASE_FILE);
        let validators_fee_recipients = db::query_validators_fee_recipient(&db_path)
            .map_err(|e| format!("query validators fee recipient failed {}", e))?;
        for (validator_publickey, fee_recipient) in validators_fee_recipients {
            match &self.validator_store {
                Some(validator_store) => {
                    let publickey =
                        BlsPublicKey::deserialize(&hex::decode(validator_publickey).unwrap())
                            .unwrap();
                    match validator_store
                        .suggested_fee_recipient(&publickey.compress())
                        .await
                    {
                        Some(_) => {}
                        None => {
                            validator_store
                                .set_fee_recipient_for_validator(&publickey, fee_recipient)
                                .await;
                        }
                    }
                }
                None => {}
            }
        }
        Ok(())
    }
}

pub async fn add_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
    operator_public_keys: OperatorPublicKeys,
    shared_public_keys: SharedPublicKeys,
    encrypted_secret_keys: EncryptedSecretKeys,
) -> Result<(), String> {
    let node = node.read().await;
    let validator_dir = node.config.validator_dir.clone();
    let secret_dir = node.config.secrets_dir.clone();
    let secret = node.secret.clone();
    let sk = &secret.secret;
    let self_pk = &secret.name;
    let total = operator_public_keys.len();
    let secret_key = secp256k1::SecretKey::from_slice(&sk.0).expect("Unable to load secret key");

    let validator_id = validator.id;
    let validator_pk = BlsPublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("Unable to deserialize validator public key: {:?}", e))?;
    info!("[VA {}] adding validator {}", validator_id, validator_pk);
    let added_validator_dir = validator_dir.join(format!("{}", validator_pk));
    if added_validator_dir.exists() {
        return Err("Validator exists".to_string());
    }

    let operator_base_address: Vec<Option<SocketAddr>> =
        { node.discovery.query_addrs(&operator_public_keys).await };

    let operator_ids: Vec<u64> = validator
        .releated_operators
        .iter()
        .map(|x| *x as u64)
        .collect();
    let operator_bls_pks: Vec<Result<BlsPublicKey, String>> = shared_public_keys
        .iter()
        .map(|pk| {
            Ok(BlsPublicKey::deserialize(&pk).map_err(|e| {
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
        threshold: *THRESHOLD_MAP.get(&(total as u64)).unwrap(),
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
                    Some(validator.owner_address),
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
            set_int_gauge(
                &metrics::DVT_VC_BALANCE_USED_UP,
                &[&validator_pk.as_hex_string()],
                BALANCE_STILL_AVAILABLE,
            );
            return Ok(());
        }
        _ => {
            return Err(format!(
                "[VA {}] failed to add validator {}. Error: no validator store is set.",
                validator_id, validator_pk
            ));
        }
    }
}

pub async fn activate_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = BlsPublicKey::deserialize(&validator.public_key)
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
            validator_store
                .start_validator_keystore(&validator_pk)
                .await;
            info!("[VA {}] validator {} activated", validator_id, validator_pk);
            set_int_gauge(
                &metrics::DVT_VC_BALANCE_USED_UP,
                &[&validator_pk.as_hex_string()],
                BALANCE_STILL_AVAILABLE,
            );
            Ok(())
        }
        _ => {
            Err(format!(
                "[VA {}] failed to activate validator {}. Error: no validator store is set. please wait",
                validator_id, validator_pk
            ))
        }
    }
}

pub async fn remove_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator: Validator,
) -> Result<(), String> {
    let validator_id = validator.id;
    let validator_pk = BlsPublicKey::deserialize(&validator.public_key)
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
    let validator_pk = BlsPublicKey::deserialize(&validator.public_key)
        .map_err(|e| format!("[VA {}] Deserialize error ({:?})", validator_id, e))?;
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
            info!("[VA {}] stopped validator {}", validator_id, validator_pk);
        }
        _ => {
            return Err(format!(
                "[VA {}] failed to stop validator {}. Error: no validator store is set. please wait, please wait",
                validator_id, validator_pk
            ));
        }
    }
    set_int_gauge(
        &metrics::DVT_VC_BALANCE_USED_UP,
        &[&validator_pk.as_hex_string()],
        BALANCE_USED_UP,
    );

    Ok(())
}

pub async fn start_initiator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    initiator: Initiator,
    operator_public_keys: OperatorPublicKeys,
    db: &Database,
) -> Result<(), String> {
    let (base_port, operator_addrs, secret) = {
        let node = node.read().await;
        (
            node.config.base_address.port(),
            node.discovery.query_addrs(&operator_public_keys).await,
            node.secret.secret.clone(),
        )
    };
    let secp = secp256k1::Secp256k1::new();
    let node_secret_key =
        secp256k1::SecretKey::from_slice(&secret.0).expect("Unable to load secret key");
    let node_public_key = secp256k1::PublicKey::from_secret_key(&secp, &node_secret_key);
    if operator_addrs.iter().any(|x| x.is_none()) {
        sleep(Duration::from_secs(10)).await;
        return Err("StartInitiator: Insufficient operators discovered for DKG".to_string());
    }
    let operator_addrs: Vec<SocketAddr> = operator_addrs.iter().map(|x| x.unwrap()).collect();

    let self_op_id = *SELF_OPERATOR_ID
        .get()
        .ok_or("Self operator has not been set".to_string())?;
    let op_ids: Vec<u64> = initiator
        .releated_operators
        .iter()
        .map(|x| *x as u64)
        .collect();
    let io = Arc::new(
        SecureNetIOCommittee::new(
            self_op_id as u64,
            base_port + DKG_PORT_OFFSET,
            &op_ids,
            &operator_addrs,
        )
        .await,
    );
    let dkg = DKGMalicious::new(self_op_id as u64, io, THRESHOLD as usize);
    let (keypair, va_pk, shared_pks) = dkg
        .run()
        .await
        .map_err(|e| format!("run dkg failed {:?}", e))?;

    // encrypt shared secret key
    let encrypted_shared_secret_key = {
        let rng = rand::thread_rng();
        let mut elgamal = Elgamal::new(rng);
        let shared_secret_key = keypair.sk.serialize();
        let encrypted_shared_secret_key = elgamal
            .encrypt(shared_secret_key.as_bytes(), &node_public_key)
            .map_err(|_e| format!("elgamal encrypt shared secret failed "))?
            .to_bytes();
        hex::encode(encrypted_shared_secret_key)
    };

    let shared_public_key = shared_pks
        .get(&(self_op_id as u64))
        .unwrap()
        .as_hex_string()[2..]
        .to_string();

    let pk_str: String = va_pk.as_hex_string()[2..].to_string();
    // push va pk to web server
    let mut request_body = ValidatorPkRequest {
        validator_pk: pk_str,
        initiator_id: initiator.id,
        initializer_address: format!("{0:0x}", initiator.owner_address),
        operators: op_ids,
        operator_id: self_op_id,
        encrypted_shared_key: encrypted_shared_secret_key,
        shared_public_key: shared_public_key,
        sign_hex: None,
    };
    request_body.sign_hex = Some(request_body.sign_digest(&secret)?);
    let url_str = API_ADDRESS.get().unwrap().to_owned() + VALIDATOR_PK_URL;
    request_to_web_server(request_body, &url_str).await?;
    db.insert_initiator_store(InitiatorStoreRecord {
        id: initiator.id,
        share_bls_sk: keypair.sk,
        validator_pk: va_pk,
        share_bls_pks: shared_pks,
    })
    .await;
    info!("dkg success!");
    Ok(())
}

pub async fn remove_initiator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    initiator: Initiator,
    operator_public_keys: OperatorPublicKeys,
    db: &Database,
) -> Result<(), String> {
    let (base_port, operator_addrs, beacon_node_urls) = {
        let node = node.read().await;
        (
            node.config.base_address.port(),
            node.discovery.query_addrs(&operator_public_keys).await,
            node.config.beacon_nodes.clone(),
        )
    };
    let initiator_id = initiator.id;
    if operator_addrs.iter().any(|x| x.is_none()) {
        sleep(Duration::from_secs(10)).await;
        return Err("RemoveInitiator: Insufficient operators discovered for DKG".to_string());
    }
    let operator_addrs: Vec<SocketAddr> = operator_addrs.iter().map(|x| x.unwrap()).collect();
    let self_op_id = *SELF_OPERATOR_ID
        .get()
        .ok_or("Self operator has not been set".to_string())?;
    let op_ids: Vec<u64> = initiator
        .releated_operators
        .iter()
        .map(|x| *x as u64)
        .collect();
    let io_committee = Arc::new(
        SecureNetIOCommittee::new(
            self_op_id as u64,
            base_port + DKG_PORT_OFFSET,
            &op_ids,
            &operator_addrs,
        )
        .await,
    );
    let initiator_store = db
        .query_initiator_store(initiator_id)
        .await
        .map_err(|e| format!("Can't find initiator store {:?}", e))?
        .ok_or(format!("Can't find initiator store"))?;
    let keypair = BlsKeypair::from_components(
        initiator_store.share_bls_sk.public_key(),
        initiator_store.share_bls_sk,
    );
    let va_pk = initiator_store.validator_pk;
    let op_bls_pks = initiator_store.share_bls_pks;

    let signer = SimpleDistributedSigner::new(
        self_op_id as u64,
        keypair.clone(),
        va_pk.clone(),
        op_bls_pks.clone(),
        io_committee,
        THRESHOLD as usize,
    );
    let mpk = BlsPublicKey::deserialize(&initiator.validator_pk.unwrap())
        .map_err(|e| format!("Can't deserilize bls pk {:?}", e))?;
    if mpk != va_pk {
        return Err(format!(
            "validator pks don't match, local stored: {:?}, received {:?}",
            va_pk, mpk
        ));
    }
    let _ = get_distributed_voluntary_exit::<SecureNetIOCommittee, SecureNetIOChannel, T>(
        &signer,
        &beacon_node_urls,
        &mpk,
    )
    .await
    .map_err(|e| format!("Can't get distributed voluntary exit {:?}", e))?;
    Ok(())
}

pub async fn minipool_deposit<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    initiator_id: u32,
    validator_pk: Vec<u8>,
    operator_public_keys: OperatorPublicKeys,
    operator_ids: OperatorIds,
    minipool_address: H160,
    // _initiator_store : InitiatorStore,
    db: &Database,
    amount: u64,
) -> Result<(), String> {
    let (base_port, operator_addrs, beacon_node_urls, secret) = {
        let node = node.read().await;
        (
            node.config.base_address.port(),
            node.discovery.query_addrs(&operator_public_keys).await,
            node.config.beacon_nodes.clone(),
            node.secret.secret.clone(),
        )
    };
    if operator_addrs.iter().any(|x| x.is_none()) {
        error!("Some operators are not online, it's critical error, minipool exiting");
        return Err(
            "MinipoolDeposit: Insufficient operators discovered for distributed signing"
                .to_string(),
        );
    }
    let operator_addrs: Vec<SocketAddr> = operator_addrs.iter().map(|x| x.unwrap()).collect();

    let op_ids: Vec<u64> = operator_ids.into_iter().map(|x| x as u64).collect();
    let self_op_id = *SELF_OPERATOR_ID
        .get()
        .ok_or("Self operator has not been set".to_string())?;
    let initiator_store = db
        .query_initiator_store(initiator_id)
        .await
        .map_err(|e| format!("Can't find initiator store {:?}", e))?
        .ok_or(format!("Can't find initiator store"))?;
    let keypair = BlsKeypair::from_components(
        initiator_store.share_bls_sk.public_key(),
        initiator_store.share_bls_sk,
    );
    let va_pk = initiator_store.validator_pk;
    let op_bls_pks = initiator_store.share_bls_pks;

    let io_committee = Arc::new(
        SecureNetIOCommittee::new(
            self_op_id as u64,
            base_port + DKG_PORT_OFFSET,
            &op_ids,
            &operator_addrs,
        )
        .await,
    );
    let signer = SimpleDistributedSigner::new(
        self_op_id as u64,
        keypair.clone(),
        va_pk.clone(),
        op_bls_pks.clone(),
        io_committee,
        THRESHOLD as usize,
    );
    let mpk = BlsPublicKey::deserialize(&validator_pk)
        .map_err(|e| format!("Can't deserilize bls pk {:?}", e))?;
    if mpk != va_pk {
        return Err(format!(
            "validator pks don't match, local stored: {:?}, received {:?}",
            va_pk, mpk
        ));
    }
    let withdraw_cret = convert_address_to_withdraw_crendentials(minipool_address);
    let deposit_data = get_distributed_deposit::<SecureNetIOCommittee, SecureNetIOChannel, T>(
        &signer,
        &withdraw_cret,
        amount,
        &beacon_node_urls,
    )
    .await
    .map_err(|e| format!("Can't get distributed deposit data {:?}", e))?;
    let mut request_body = DepositRequest::convert(deposit_data);
    request_body.sign_hex = Some(request_body.sign_digest(&secret)?);
    let url = {
        if amount == 1_000_000_000 {
            PRESTAKE_SIGNATURE_URL
        } else if amount == 31_000_000_000 {
            STAKE_SIGNATURE_URL
        } else {
            error!("invalid amount");
            "error url"
        }
    };
    let url_str = API_ADDRESS.get().unwrap().to_owned() + url;
    request_to_web_server(request_body, &url_str)
        .await
        .map_err(|e| format!("can't send request to server {:?}, url: {}", e, url_str))?;
    Ok(())
}

pub async fn restart_validator<T: EthSpec>(
    node: Arc<RwLock<Node<T>>>,
    validator_id: u64,
    validator_pk: BlsPublicKey,
) -> Result<(), DvfError> {
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
            validator_store
                .restart_validator_keystore(&validator_pk)
                .await;
            Ok(())
        }
        _ => Err(DvfError::ValidatorStoreNotReady),
    }
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
    validator_pk: &BlsPublicKey,
) {
    match validator_store {
        Some(validator_store) => {
            validator_store
                .remove_validator_keystore(validator_pk)
                .await;
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
    validator_pk: &BlsPublicKey,
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
    validator_pk: &BlsPublicKey,
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

pub fn create_node_key_hex_backup(path: PathBuf, secret: &Secret) -> Result<(), ConfigError> {
    if !path.exists() {
        info!("{:?}", path);
        secret.write_hex(path.to_str().unwrap())?;
    }
    Ok(())
}

pub async fn query_validator_registration_timestamp(public_key: &[u8]) -> u64 {
    DATABASE
        .get()
        .unwrap()
        .query_validator_registration_timestamp(hex::encode(public_key))
        .await
        .unwrap()
}
