use super::db::Database;
use super::utils::{convert_va_pk_to_u64, FromFile, ToFile};
use async_trait::async_trait;
use bls::{PublicKey as BlsPublickey, SecretKey as BlsSecretKey};
use core::panic;
use hscrypto::PublicKey;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;
use web3::ethabi::{token, Event, EventParam, ParamType, RawLog};
use web3::{
    contract::{Contract as EthContract, Options},
    transports::WebSocket,
    types::{Address, BlockNumber, FilterBuilder, Log, H256, U256, U64},
    Error as Web3Error, Web3,
};
use lazy_static::lazy_static;

const CONTRACT_CONFIG_FILE: &str = "contract_config/configs.yml";
const CONTRACT_RECORD_FILE: &str = "contract_record.yml";
pub const CONTRACT_DATABASE_FILE: &str = "contract_database.db";
const CONTRACT_VA_REG_EVENT_NAME: &str = "ValidatorRegistration";
const CONTRACT_VA_RM_EVENT_NAME: &str = "ValidatorRemoval";
const CONTRACT_INI_REG_EVENT_NAME: &str = "InitiatorRegistration";
const CONTRACT_MINIPOOL_CREATED_EVENT_NAME: &str = "InitiatorMiniPoolCreated";
const CONTRACT_MINIPOOL_READY_EVENT_NAME: &str = "InitiatorMiniPoolReady";
const CONTRACT_INI_RM_EVENT_NAME: &str = "InitiatorRemoval";
pub static SELF_OPERATOR_ID: OnceCell<u32> = OnceCell::const_new();
pub static DEFAULT_TRANSPORT_URL: OnceCell<String> = OnceCell::const_new();
pub static REGISTRY_CONTRACT: OnceCell<String> = OnceCell::const_new();
pub static NETWORK_CONTRACT: OnceCell<String> = OnceCell::const_new();
const QUERY_LOGS_INTERVAL: u64 = 60;
const QUERY_BLOCK_INTERVAL: u64 = 500;
lazy_static! {
    pub static ref THRESHOLD_MAP: HashMap<u64, u64> = {
        let mut threshold_map = HashMap::new();
        threshold_map.insert(4, 3);
        threshold_map.insert(7, 5);
        threshold_map
    };
    static ref ALLOWED_COMMITTEE_SIZE: HashSet<u64> = {
        HashSet::from([4, 7])
    };
}
#[derive(Debug)]
pub enum ContractError {
    StoreError,
    Web3Error(Web3Error),
    BlockNumberError(Web3Error),
    LogError,
    RecordFileError,
    LogParseError,
    NoEnoughOperatorError,
    DatabaseError,
    InvalidArgumentError,
    FileError,
    ContractParseError,
    QueryError,
}

impl ContractError {
    fn to_string(&self) -> String {
        match self {
            ContractError::StoreError => format!("[ERROR!]: Can't interact with store."),
            ContractError::Web3Error(e) => format!("[ERROR]: Web3 error ({:?}).", e),
            ContractError::BlockNumberError(e) => {
                format!("[ERROR]: Can't get blocknumber from rpc service ({:?}).", e)
            }
            ContractError::LogError => format!("[ERROR]: Can't get logs from rpc service."),
            ContractError::RecordFileError => format!("[ERROR]: Error happens with record file."),
            ContractError::LogParseError => format!("[ERROR]: Can't parse eth log."),
            ContractError::NoEnoughOperatorError => {
                format!("[ERROR]: There are not enough operators in local database")
            }
            ContractError::DatabaseError => format!("[ERROR]: Can't get result from local databse"),
            ContractError::InvalidArgumentError => {
                format!("[ERROR]: Invalid Argument from contract")
            }
            ContractError::FileError => format!("[ERROR]: Error happens when processing file"),
            ContractError::ContractParseError => {
                format!("[ERROR]: Can't parse contract from abi json")
            }
            ContractError::QueryError => {
                format!("[ERROR]: Can't query from contract from rpc service")
            }
        }
    }
}

type ValidatorPublicKey = Vec<u8>;
type OperatorPublicKey = Vec<u8>;

#[derive(Clone, Debug)]
pub struct Operator {
    pub id: u32,
    pub name: String,
    pub address: Address,
    pub public_key: OperatorPublicKey, // ecc256 public key
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: u64,
    pub owner_address: Address,
    pub public_key: ValidatorPublicKey,
    // bls public key
    pub releated_operators: Vec<u32>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Initiator {
    pub id: u32,
    pub owner_address: Address,
    pub releated_operators: Vec<u32>,
    pub validator_pk: Option<ValidatorPublicKey>,
    pub minipool_address: Option<Address>,
}

pub type SharedPublicKeys = Vec<Vec<u8>>;
pub type EncryptedSecretKeys = Vec<Vec<u8>>;
pub type OperatorPublicKeys = Vec<Vec<u8>>;
pub type OperatorIds = Vec<u32>;

#[derive(Clone, Serialize, Deserialize)]
pub enum ContractCommand {
    StartValidator(
        Validator,
        OperatorPublicKeys,
        SharedPublicKeys,
        EncryptedSecretKeys,
    ),
    RemoveValidator(Validator),
    ActivateValidator(Validator),
    StopValidator(Validator),
    StartInitiator(Initiator, OperatorPublicKeys),
    MiniPoolCreated(
        u32,
        ValidatorPublicKey,
        OperatorPublicKeys,
        OperatorIds,
        Address,
    ),
    MiniPoolReady(
        u32,
        ValidatorPublicKey,
        OperatorPublicKeys,
        OperatorIds,
        Address,
    ),
    RemoveInitiator(Initiator, OperatorPublicKeys),
}

#[derive(Clone)]
pub struct InitiatorStoreRecord {
    pub id: u32,
    pub share_bls_sk: BlsSecretKey,
    pub validator_pk: BlsPublickey,
    pub share_bls_pks: HashMap<u64, BlsPublickey>,
}

#[async_trait]
pub trait TopicHandler: Send + Sync + 'static {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        operator_pk_base64: &String,
        config: &ContractConfig,
        web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError>;
}

#[derive(Clone)]
pub struct ValidatorRegistrationHandler {}

#[async_trait]
impl TopicHandler for ValidatorRegistrationHandler {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        operator_pk_base64: &String,
        config: &ContractConfig,
        web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError> {
        process_validator_registration(log, db, operator_pk_base64, config, web3)
            .await
            .map_err(|e| {
                error!("error happens when process validator registration");
                e
            })
    }
}

#[derive(Clone)]
pub struct ValidatorRemovalHandler {}

#[async_trait]
impl TopicHandler for ValidatorRemovalHandler {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        _operator_pk_base64: &String,
        _config: &ContractConfig,
        _web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError> {
        process_validator_removal(log, db).await.map_err(|e| {
            error!("error happens when process validator removal");
            e
        })
    }
}

#[derive(Clone)]
pub struct InitiatorRegistrationHandler {}

#[async_trait]
impl TopicHandler for InitiatorRegistrationHandler {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        operator_pk_base64: &String,
        config: &ContractConfig,
        web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError> {
        process_initiator_registration(log, db, operator_pk_base64, config, web3)
            .await
            .map_err(|e| {
                error!("error happens when process initiator registration");
                e
            })
    }
}

#[derive(Clone)]
pub struct MinipoolCreatedHandler {}

#[async_trait]
impl TopicHandler for MinipoolCreatedHandler {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        _operator_pk_base64: &String,
        _config: &ContractConfig,
        _web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError> {
        process_minipool_created(log, db).await.map_err(|e| {
            error!("error happens when process minipool created");
            e
        })
    }
}

#[derive(Clone)]
pub struct MinipoolReadyHandler {}

#[async_trait]
impl TopicHandler for MinipoolReadyHandler {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        _operator_pk_base64: &String,
        _config: &ContractConfig,
        _web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError> {
        process_minipool_ready(log, db).await.map_err(|e| {
            error!("error happens when process minipool ready");
            e
        })
    }
}

#[derive(Clone)]
pub struct InitiatorRemovalHandler {}

#[async_trait]
impl TopicHandler for InitiatorRemovalHandler {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        _operator_pk_base64: &String,
        _config: &ContractConfig,
        _web3: &Web3<WebSocket>,
    ) -> Result<(), ContractError> {
        process_initiator_removal(log, db).await.map_err(|e| {
            error!("error happens when process initiator removal");
            e
        })
    }
}

#[derive(Debug, DeriveSerialize, DeriveDeserialize, Clone)]
pub struct ContractConfig {
    pub validator_registration_topic: String,
    pub validator_removal_topic: String,
    pub initiator_registration_topic: String,
    pub initiator_minipool_created_topic: String,
    pub initiator_minipool_ready_topic: String,
    pub initiator_removal_topic: String,
    pub safestake_network_abi_path: String,
    pub safestake_registry_abi_path: String,
}

impl FromFile<ContractConfig> for ContractConfig {}

impl ToFile for ContractConfig {}

#[derive(Clone, DeriveSerialize, DeriveDeserialize, Debug)]
pub struct ContractRecord {
    pub block_num: u64,
}

impl FromFile<ContractRecord> for ContractRecord {}

impl ToFile for ContractRecord {}

pub struct Contract {
    pub config: ContractConfig,
    pub record: ContractRecord,
    pub db: Database,
    pub operator_pk: PublicKey,
    pub base_dir: PathBuf,
    pub handlers: Arc<RwLock<HashMap<H256, Box<dyn TopicHandler>>>>,
    pub va_filter_builder: Option<FilterBuilder>,
    pub initiator_filter_builder: Option<FilterBuilder>,
    pub web3: Arc<Mutex<Web3<WebSocket>>>,
}

impl Contract {
    pub async fn new<P: AsRef<Path>>(
        base_dir: P,
        operator_pk: PublicKey,
        db: Database,
    ) -> Result<Self, String> {
        let config = ContractConfig::from_file(CONTRACT_CONFIG_FILE)?;
        let url = DEFAULT_TRANSPORT_URL.get().unwrap();
        let transport = WebSocket::new(&url)
            .await
            .map_err(|e| format!("failed connect to {}: {:?}", url, e))?;
        let web3 = Web3::new(transport);

        let record = match ContractRecord::from_file(base_dir.as_ref().join(CONTRACT_RECORD_FILE)) {
            Ok(record) => record,
            Err(err_str) => {
                warn!("Can't recover from contract record file {}, get current block number from contract", err_str);
                let block_num = get_current_block(&web3)
                    .await
                    .map_err(|e| format!("can't get current block number {:?}", e))?
                    .as_u64();
                ContractRecord { block_num }
            }
        };
        Ok(Self {
            config,
            record,
            db,
            operator_pk,
            base_dir: base_dir.as_ref().to_path_buf(),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            va_filter_builder: None,
            initiator_filter_builder: None,
            web3: Arc::new(Mutex::new(web3)),
        })
    }

    pub async fn check_operator_id(&self) {
        let web3_arc: Arc<Mutex<Web3<WebSocket>>> = Arc::clone(&self.web3);
        let mut web3 = web3_arc.lock().await;
        let url = DEFAULT_TRANSPORT_URL.get().unwrap();
        match query_operator_from_contract(&self.config, *SELF_OPERATOR_ID.get().unwrap(), &web3)
            .await
        {
            Ok(op) => {
                if op.public_key != self.operator_pk.0 {
                    panic!("operator id is not consistent with smart contract! Please input right operator id");
                }
                self.db.insert_operator(op).await;
            }
            Err(e) => {
                error!("query operator from contract error {:?}", e);
                re_connect_web3(&mut web3, url).await;
            }
        };
    }

    pub fn spawn(base_dir: PathBuf, operator_pk: PublicKey, db: Database) {
        tokio::spawn(async move {
            match Contract::new(base_dir, operator_pk, db).await {
                Ok(mut contract) => {
                    contract.construct_filter().await;
                    contract.check_operator_id().await;
                    contract.get_logs_from_contract().await;
                    contract.monitor_validator_paidblock();
                }
                Err(e) => {
                    error!("can't create contract object {}", e);
                    std::process::exit(1);
                }
            }
        });
    }

    pub async fn construct_filter(&mut self) {
        let config = &self.config;
        let va_reg_topic =
            H256::from_slice(&hex::decode(&config.validator_registration_topic).unwrap());
        let va_rm_topic = H256::from_slice(&hex::decode(&config.validator_removal_topic).unwrap());
        let ini_reg_topic =
            H256::from_slice(&hex::decode(&config.initiator_registration_topic).unwrap());
        let minipool_created_topic =
            H256::from_slice(&hex::decode(&config.initiator_minipool_created_topic).unwrap());
        let minipool_ready_topic =
            H256::from_slice(&hex::decode(&config.initiator_minipool_ready_topic).unwrap());
        let ini_rm_topic = H256::from_slice(&hex::decode(&config.initiator_removal_topic).unwrap());
        let va_filter_builder = FilterBuilder::default()
            .address(vec![Address::from_slice(
                &hex::decode(NETWORK_CONTRACT.get().unwrap()).unwrap(),
            )])
            .topics(Some(vec![va_reg_topic, va_rm_topic]), None, None, None);
        self.va_filter_builder = Some(va_filter_builder);
        let initiator_filter_builder = FilterBuilder::default()
            .address(vec![Address::from_slice(
                &hex::decode(REGISTRY_CONTRACT.get().unwrap()).unwrap(),
            )])
            .topics(
                Some(vec![
                    ini_reg_topic,
                    minipool_created_topic,
                    minipool_ready_topic,
                    ini_rm_topic,
                ]),
                None,
                None,
                None,
            );
        self.initiator_filter_builder = Some(initiator_filter_builder);
        let mut handlers = self.handlers.write().await;
        handlers.insert(va_reg_topic, Box::new(ValidatorRegistrationHandler {}));
        handlers.insert(va_rm_topic, Box::new(ValidatorRemovalHandler {}));
        handlers.insert(ini_reg_topic, Box::new(InitiatorRegistrationHandler {}));
        handlers.insert(minipool_created_topic, Box::new(MinipoolCreatedHandler {}));
        handlers.insert(minipool_ready_topic, Box::new(MinipoolReadyHandler {}));
        handlers.insert(ini_rm_topic, Box::new(InitiatorRemovalHandler {}));
    }

    pub fn monitor_validator_paidblock(&mut self) {
        let config = self.config.clone();
        let db = self.db.clone();
        let web3 = Arc::clone(&self.web3);
        let url = DEFAULT_TRANSPORT_URL.get().unwrap();
        tokio::spawn(async move {
            sleep(Duration::from_secs(30)).await;
            let mut query_interval = tokio::time::interval(Duration::from_secs(60 * 10));
            loop {
                query_interval.tick().await;
                let mut web3 = web3.lock().await;
                match db.query_all_validator_publickeys().await {
                    Ok(public_keys) => {
                        for public_key in public_keys {
                            match check_validators(&config, public_key.clone(), &web3).await {
                                Ok(used_up) => {
                                    match db.query_validator_by_public_key(public_key).await {
                                        Ok(validator) => {
                                            if let Some(va) = validator {
                                                if used_up && va.active {
                                                    let va_id = va.id;
                                                    let cmd = ContractCommand::StopValidator(va);
                                                    db.insert_contract_command(
                                                        va_id,
                                                        serde_json::to_string(&cmd).unwrap(),
                                                    )
                                                    .await;
                                                } else if !used_up && !va.active {
                                                    let va_id = va.id;
                                                    let cmd =
                                                        ContractCommand::ActivateValidator(va);
                                                    db.insert_contract_command(
                                                        va_id,
                                                        serde_json::to_string(&cmd).unwrap(),
                                                    )
                                                    .await;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "failed to query validator by public keys {:?}",
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("check validator failed {}", e.to_string());
                                    re_connect_web3(&mut web3, url).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("query validator address failed {:?}", e);
                    }
                }
            }
        });
    }

    pub async fn get_logs_from_contract(&mut self) {
        let mut record = self.record.clone();
        let config = self.config.clone();
        let record_path = self.base_dir.join(CONTRACT_RECORD_FILE);
        let db = self.db.clone();
        let operator_pk = self.operator_pk.clone();
        let operator_pk_base64 = base64::encode(&operator_pk);
        let va_filter_builder = self.va_filter_builder.as_ref().unwrap().clone();
        let initiator_filter_builder = self.initiator_filter_builder.as_ref().unwrap().clone();
        let handlers = self.handlers.clone();
        let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
        let web3: Arc<Mutex<Web3<WebSocket>>> = Arc::clone(&self.web3);
        tokio::spawn(async move {
            let mut query_interval =
                tokio::time::interval(Duration::from_secs(QUERY_LOGS_INTERVAL));
            query_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                query_interval.tick().await;
                let mut web3 = web3.lock().await;
                let mut all_logs: Vec<Log> = Vec::new();
                match get_current_block(&web3).await {
                    Ok(current_block) => {
                        let va_filter = va_filter_builder
                            .clone()
                            .from_block(BlockNumber::Number(U64::from(record.block_num)))
                            .to_block(BlockNumber::Number(std::cmp::min(
                                U64::from(record.block_num + QUERY_BLOCK_INTERVAL),
                                current_block,
                            )))
                            .build();
                        let initiator_filter = initiator_filter_builder
                            .clone()
                            .from_block(BlockNumber::Number(U64::from(record.block_num)))
                            .to_block(BlockNumber::Number(std::cmp::min(
                                U64::from(record.block_num + QUERY_BLOCK_INTERVAL),
                                current_block,
                            )))
                            .build();

                        match web3.eth().logs(va_filter).await {
                            Ok(mut logs) => {
                                info!("Get {} va logs.", &logs.len());
                                all_logs.append(&mut logs);
                            }
                            Err(e) => {
                                error!("{}, {}", ContractError::LogError.to_string(), e);
                                re_connect_web3(&mut web3, transport_url).await;
                                continue;
                            }
                        }
                        match web3.eth().logs(initiator_filter).await {
                            Ok(mut logs) => {
                                info!("Get {} initiator logs.", &logs.len());
                                all_logs.append(&mut logs);
                            }
                            Err(e) => {
                                error!("{}, {}", ContractError::LogError.to_string(), e);
                                re_connect_web3(&mut web3, transport_url).await;
                                continue;
                            }
                        }
                        if all_logs.len() == 0 {
                            record.block_num = std::cmp::min(
                                current_block.as_u64(),
                                record.block_num + QUERY_BLOCK_INTERVAL + 1,
                            );
                        } else {
                            all_logs.sort_by(|a, b| {
                                a.block_number.unwrap().cmp(&b.block_number.unwrap())
                            });
                            for log in all_logs {
                                record.block_num = log.block_number.unwrap().as_u64() + 1;
                                let topic = log.topics[0].clone();
                                match handlers.read().await.get(&topic) {
                                    Some(handler) => {
                                        match handler
                                            .process(log, &db, &operator_pk_base64, &config, &web3)
                                            .await
                                        {
                                            Ok(_) => {}
                                            Err(e) => {
                                                error!("error hapens, reason: {}", e.to_string());
                                            }
                                        }
                                    }
                                    None => {
                                        error!("Can't find handler");
                                    }
                                };
                            }
                        }
                        update_record_file(&record, &record_path);
                    }
                    Err(_) => {
                        re_connect_web3(&mut web3, transport_url).await;
                    }
                }
            }
        });
    }
}

pub async fn re_connect_web3(web3: &mut Web3<WebSocket>, transport_url: &String) {
    match WebSocket::new(transport_url).await {
        Ok(t) => {
            *web3 = Web3::new(t);
        }
        Err(e) => {
            error!("Failed to connect {}", e);
        }
    }
}

pub async fn get_current_block(web3: &Web3<WebSocket>) -> Result<U64, ContractError> {
    web3.eth()
        .block_number()
        .await
        .map_err(ContractError::BlockNumberError)
}

pub fn update_record_file<P: AsRef<Path>>(record: &ContractRecord, path: P) {
    record
        .to_file(path)
        .map_err(|e| {
            error!(
                "{} error: {}",
                ContractError::RecordFileError.to_string(),
                e
            );
        })
        .unwrap();
}

pub async fn process_validator_registration(
    raw_log: Log,
    db: &Database,
    operator_pk_base64: &String,
    config: &ContractConfig,
    web3: &Web3<WebSocket>,
) -> Result<(), ContractError> {
    info!("process_validator_registration");
    let validator_reg_event = Event {
        name: CONTRACT_VA_REG_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "publicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false,
            },
            EventParam {
                name: "operatorIds".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(32))),
                indexed: false,
            },
            EventParam {
                name: "sharesPublicKeys".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Bytes)),
                indexed: false,
            },
            EventParam {
                name: "encryptedKeys".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Bytes)),
                indexed: false,
            },
            EventParam {
                name: "paidBlockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
        ],
        anonymous: false,
    };
    let log = validator_reg_event
        .parse_log(RawLog {
            topics: raw_log.topics,
            data: raw_log.data.0,
        })
        .map_err(|_| ContractError::LogParseError)?;
    let address = log.params[0]
        .value
        .clone()
        .into_address()
        .ok_or(ContractError::LogParseError)?;
    let va_pk = log.params[1]
        .value
        .clone()
        .into_bytes()
        .ok_or(ContractError::LogParseError)?;
    let validator_id = convert_va_pk_to_u64(&va_pk);
    let operator_tokens = log.params[2]
        .value
        .clone()
        .into_array()
        .ok_or(ContractError::LogParseError)?;
    let op_ids: Vec<u32> = operator_tokens
        .into_iter()
        .map(|token| {
            let op_id = token.into_uint().unwrap();
            op_id.as_u32()
        })
        .collect();
    info!("operator ids {:?}", op_ids);
    if !ALLOWED_COMMITTEE_SIZE.contains(&(op_ids.len() as u64)) {
        error!("unkown operator committee size {}", op_ids.len());
        return Err(ContractError::InvalidArgumentError);
    }
    let mut operator_pks: Vec<String> = Vec::new();
    // query local database first, if not existing, query from contract
    for op_id in &op_ids {
        match db
            .query_operator_public_key_by_id(*op_id)
            .await
            .map_err(|_| ContractError::DatabaseError)?
        {
            Some(pk_str) => {
                operator_pks.push(pk_str);
            }
            None => {
                let operator = query_operator_from_contract(config, *op_id, web3).await?;
                operator_pks.push(base64::encode(&operator.public_key));
                db.insert_operator(operator).await;
            }
        };
    }
    if operator_pks.contains(operator_pk_base64) {
        let shared_pks = parse_bytes_token(log.params[3].value.clone())?;
        let encrypted_sks = parse_bytes_token(log.params[4].value.clone())?;
        let _paid_block_number = log.params[5]
            .value
            .clone()
            .into_uint()
            .ok_or(ContractError::LogParseError)?
            .as_u64();
        // check array length should be same
        if shared_pks.len() != encrypted_sks.len() {
            return Err(ContractError::InvalidArgumentError);
        }
        if operator_pks.len() != shared_pks.len() {
            return Err(ContractError::InvalidArgumentError);
        }
        // binary operator publics
        let op_pk_bn: Vec<Vec<u8>> = operator_pks
            .into_iter()
            .map(|s| base64::decode(s).unwrap())
            .collect();
        //send command to node
        let validator = Validator {
            id: validator_id,
            owner_address: address,
            public_key: va_pk.try_into().unwrap(),
            releated_operators: op_ids,
            active: true,
        };
        // save validator in local database
        db.insert_validator(validator.clone()).await;
        let cmd = ContractCommand::StartValidator(validator, op_pk_bn, shared_pks, encrypted_sks);
        db.insert_contract_command(validator_id, serde_json::to_string(&cmd).unwrap())
            .await;
    }
    Ok(())
}

pub async fn process_validator_removal(raw_log: Log, db: &Database) -> Result<(), ContractError> {
    info!("process_validator_removal");
    let validator_rm_event = Event {
        name: CONTRACT_VA_RM_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "publicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false,
            },
        ],
        anonymous: false,
    };
    let log = validator_rm_event
        .parse_log(RawLog {
            topics: raw_log.topics,
            data: raw_log.data.0,
        })
        .map_err(|_| ContractError::LogParseError)?;
    let owner_address = log.params[0]
        .value
        .clone()
        .into_address()
        .ok_or(ContractError::LogParseError)?;
    let va_pk = log.params[1]
        .value
        .clone()
        .into_bytes()
        .ok_or(ContractError::LogParseError)?;
    let id = convert_va_pk_to_u64(&va_pk);

    // let va_str = hex::encode(&va_pk);

    // db.delete_validator(va_str).await;

    let cmd = ContractCommand::RemoveValidator(Validator {
        id,
        owner_address,
        public_key: va_pk.try_into().unwrap(),
        releated_operators: vec![],
        active: true,
    });
    db.insert_contract_command(id, serde_json::to_string(&cmd).unwrap())
        .await;
    Ok(())
}

pub async fn process_initiator_registration(
    raw_log: Log,
    db: &Database,
    operator_pk_base64: &String,
    config: &ContractConfig,
    web3: &Web3<WebSocket>,
) -> Result<(), ContractError> {
    let ini_reg_event = Event {
        name: CONTRACT_INI_REG_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "initiatorId".to_string(),
                kind: ParamType::Uint(32),
                indexed: false,
            },
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: false,
            },
            EventParam {
                name: "operatorIds".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(32))),
                indexed: false,
            },
        ],
        anonymous: false,
    };
    let log = ini_reg_event
        .parse_log(RawLog {
            topics: raw_log.topics,
            data: raw_log.data.0,
        })
        .map_err(|_| ContractError::LogParseError)?;
    let id = log.params[0]
        .value
        .clone()
        .into_uint()
        .ok_or(ContractError::LogParseError)?
        .as_u32();
    let address = log.params[1]
        .value
        .clone()
        .into_address()
        .ok_or(ContractError::LogParseError)?;
    let operator_tokens = log.params[2]
        .value
        .clone()
        .into_array()
        .ok_or(ContractError::LogParseError)?;
    let op_ids: Vec<u32> = operator_tokens
        .into_iter()
        .map(|token| {
            let op_id = token.into_uint().unwrap();
            op_id.as_u32()
        })
        .collect();

    let mut operator_pks: Vec<String> = Vec::new();
    for op_id in &op_ids {
        match db
            .query_operator_public_key_by_id(*op_id)
            .await
            .map_err(|_| ContractError::DatabaseError)?
        {
            Some(pk_str) => {
                operator_pks.push(pk_str);
            }
            None => {
                let operator = query_operator_from_contract(config, *op_id, web3).await?;
                operator_pks.push(base64::encode(&operator.public_key));
                db.insert_operator(operator).await;
            }
        };
    }
    if operator_pks.contains(operator_pk_base64) {
        let initiator = Initiator {
            id,
            owner_address: address,
            releated_operators: op_ids,
            validator_pk: None,
            minipool_address: None,
        };
        let op_pk_bn: Vec<Vec<u8>> = operator_pks
            .into_iter()
            .map(|s| base64::decode(s).unwrap())
            .collect();
        db.insert_initiator(initiator.clone()).await;
        let cmd = ContractCommand::StartInitiator(initiator, op_pk_bn);
        db.insert_contract_command(id.into(), serde_json::to_string(&cmd).unwrap())
            .await;
    } else {
        info!("This node is not included in this initiator registration event. Continue.");
    }
    Ok(())
}

pub async fn process_initiator_removal(raw_log: Log, db: &Database) -> Result<(), ContractError> {
    let ini_rm_event = Event {
        name: CONTRACT_INI_RM_EVENT_NAME.to_string(),
        inputs: vec![EventParam {
            name: "initiatorId".to_string(),
            kind: ParamType::Uint(32),
            indexed: false,
        }],
        anonymous: false,
    };
    let log = ini_rm_event
        .parse_log(RawLog {
            topics: raw_log.topics,
            data: raw_log.data.0,
        })
        .map_err(|_| ContractError::LogParseError)?;
    let id = log.params[0]
        .value
        .clone()
        .into_uint()
        .ok_or(ContractError::LogParseError)?
        .as_u32();
    let initiator = db
        .query_initiator(id)
        .await
        .map_err(|_| ContractError::DatabaseError)?;
    match initiator {
        Some(initiator) => {
            if initiator.validator_pk.is_none() {
                return Err(ContractError::DatabaseError);
            }
            let (op_pks, _) = db.query_initiator_releated_op_pks(id).await.map_err(|_| {
                error!("Can't query initiator related op pks");
                ContractError::DatabaseError
            })?;
            let op_pk_bns = op_pks
                .into_iter()
                .map(|s| base64::decode(s).unwrap())
                .collect();
            let cmd = ContractCommand::RemoveInitiator(initiator, op_pk_bns);
            db.insert_contract_command(id as u64, serde_json::to_string(&cmd).unwrap())
                .await;
        }
        None => {
            error!(
                "can't delete initiator {}, can't find it in local store",
                id
            );
            return Err(ContractError::DatabaseError);
        }
    }
    Ok(())
}

pub async fn process_minipool_created(raw_log: Log, db: &Database) -> Result<(), ContractError> {
    let minipool_created_event = Event {
        name: CONTRACT_MINIPOOL_CREATED_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "initiatorId".to_string(),
                kind: ParamType::Uint(32),
                indexed: false,
            },
            EventParam {
                name: "validatorPublicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false,
            },
            EventParam {
                name: "minipoolAddress".to_string(),
                kind: ParamType::Address,
                indexed: false,
            },
        ],
        anonymous: false,
    };
    let log = minipool_created_event
        .parse_log(RawLog {
            topics: raw_log.topics,
            data: raw_log.data.0,
        })
        .map_err(|_| ContractError::LogParseError)?;
    let id = log.params[0]
        .value
        .clone()
        .into_uint()
        .ok_or(ContractError::LogParseError)?
        .as_u32();
    let va_pk = log.params[1]
        .value
        .clone()
        .into_bytes()
        .ok_or(ContractError::LogParseError)?;
    let minipool_address = log.params[2]
        .value
        .clone()
        .into_address()
        .ok_or(ContractError::LogParseError)?;

    match db
        .update_initiator(id, hex::encode(&va_pk), format!("{0:0x}", minipool_address))
        .await
    {
        Ok(updated) => {
            if updated != 0 {
                let (op_pks, op_ids) =
                    db.query_initiator_releated_op_pks(id).await.map_err(|_| {
                        error!("Can't query initiator related op pks");
                        ContractError::DatabaseError
                    })?;
                let op_pk_bns = op_pks
                    .into_iter()
                    .map(|s| base64::decode(s).unwrap())
                    .collect();
                let cmd = ContractCommand::MiniPoolCreated(
                    id,
                    va_pk.try_into().unwrap(),
                    op_pk_bns,
                    op_ids,
                    minipool_address,
                );
                db.insert_contract_command(id.into(), serde_json::to_string(&cmd).unwrap())
                    .await;
            }
            Ok(())
        }
        Err(e) => {
            error!("Can't update initiator {}", e);
            Err(ContractError::DatabaseError)
        }
    }
}

pub async fn process_minipool_ready(raw_log: Log, db: &Database) -> Result<(), ContractError> {
    let minipool_ready_event = Event {
        name: CONTRACT_MINIPOOL_READY_EVENT_NAME.to_string(),
        inputs: vec![EventParam {
            name: "initiatorId".to_string(),
            kind: ParamType::Uint(32),
            indexed: false,
        }],
        anonymous: false,
    };
    let log = minipool_ready_event
        .parse_log(RawLog {
            topics: raw_log.topics,
            data: raw_log.data.0,
        })
        .map_err(|_| ContractError::LogParseError)?;
    let id = log.params[0]
        .value
        .clone()
        .into_uint()
        .ok_or(ContractError::LogParseError)?
        .as_u32();
    match db.query_initiator(id).await {
        Ok(initiator_option) => match initiator_option {
            Some(initiator) => {
                let validator_pk = initiator.validator_pk.ok_or(ContractError::DatabaseError)?;
                let minipool_address = initiator
                    .minipool_address
                    .ok_or(ContractError::DatabaseError)?;
                let (op_pks, op_ids) =
                    db.query_initiator_releated_op_pks(id).await.map_err(|_| {
                        error!("Can't query initiator related op pks");
                        ContractError::DatabaseError
                    })?;

                let op_pks_bn = op_pks
                    .into_iter()
                    .map(|s| base64::decode(s).unwrap())
                    .collect();
                let cmd = ContractCommand::MiniPoolReady(
                    id,
                    validator_pk,
                    op_pks_bn,
                    op_ids,
                    minipool_address,
                );
                db.insert_contract_command(id.into(), serde_json::to_string(&cmd).unwrap())
                    .await;
                Ok(())
            }
            None => Ok(()),
        },
        Err(_) => Err(ContractError::DatabaseError),
    }
}

pub async fn query_operator_from_contract(
    config: &ContractConfig,
    id: u32,
    web3: &Web3<WebSocket>,
) -> Result<Operator, ContractError> {
    let raw_abi = std::fs::read_to_string(&config.safestake_registry_abi_path)
        .or_else(|e| {
            error!(
                "Can't read from {} {}",
                &config.safestake_registry_abi_path, e
            );
            Err(ContractError::FileError)
        })
        .unwrap();
    let raw_json: Value = serde_json::from_str(&raw_abi).unwrap();
    let abi = raw_json["abi"].to_string();
    let address = Address::from_slice(&hex::decode(REGISTRY_CONTRACT.get().unwrap()).unwrap());
    let contract = EthContract::from_json(web3.eth(), address, abi.as_bytes())
        .or_else(|e| {
            error!("Can't create contract from json {}", e);
            Err(ContractError::ContractParseError)
        })
        .unwrap();
    let (name, pk, address, _, _, _, _, _): (
        String,
        Vec<u8>,
        Address,
        U256,
        U256,
        bool,
        bool,
        bool,
    ) = contract
        .query("_operators", (id,), None, Options::default(), None)
        .await
        .or_else(|e| {
            error!("Can't query from contract {}", e);
            Err(ContractError::QueryError)
        })?;
    Ok(Operator {
        id,
        name,
        address,
        public_key: pk.try_into().unwrap(),
    })
}

// check the paid block number of validators. If the block is behind the current block number, stop the validator.
pub async fn check_validators(
    config: &ContractConfig,
    validator_public_keys: String,
    web3: &Web3<WebSocket>,
) -> Result<bool, ContractError> {
    let raw_abi = std::fs::read_to_string(&config.safestake_network_abi_path)
        .or_else(|e| {
            error!(
                "Can't read from {} {}",
                &config.safestake_network_abi_path, e
            );
            Err(ContractError::FileError)
        })
        .unwrap();
    let raw_json: Value = serde_json::from_str(&raw_abi).unwrap();
    let abi = raw_json["abi"].to_string();
    let address = Address::from_slice(&hex::decode(NETWORK_CONTRACT.get().unwrap()).unwrap());
    let contract = EthContract::from_json(web3.eth(), address, abi.as_bytes())
        .or_else(|e| {
            error!("Can't create contract from json {}", e);
            Err(ContractError::ContractParseError)
        })
        .unwrap();
    let (_, paid_block, _, _, _): (U256, U256, U256, U256, bool) = contract
        .query(
            "_validatorDatas",
            (hex::decode(validator_public_keys.clone()).unwrap(),),
            None,
            Options::default(),
            None,
        )
        .await
        .or_else(|e| {
            error!("Can't getAccountPaidBlockNumber from contract {}", e);
            Err(ContractError::QueryError)
        })?;
    let current_block = get_current_block(web3).await?;
    info!(
        "current block {:?}, paid block {:?} , validator {}",
        current_block, paid_block, validator_public_keys
    );
    if current_block.as_u64() >= paid_block.as_u64() {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn parse_bytes_token(tk: token::Token) -> Result<Vec<Vec<u8>>, ContractError> {
    let token_arr = tk.into_array().ok_or(ContractError::LogParseError)?;
    let res: Vec<Vec<u8>> = token_arr
        .into_iter()
        .map(|token| token.into_bytes().unwrap())
        .collect();
    Ok(res)
}
