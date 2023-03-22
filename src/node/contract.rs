use super::db::Database;
use super::utils::{convert_va_pk_to_u64, FromFile, ToFile};
use async_trait::async_trait;
use hscrypto::PublicKey;
use hsutils::monitored_channel::MonitoredSender;
use tokio::select;
use tokio::sync::RwLock;
use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};
use serde_json::Value;
use core::panic;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

// use async_trait::async_trait;
// use hscrypto::PublicKey;
// use hsutils::monitored_channel::MonitoredSender;
// use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};
// use serde_json::Value;
use store::Store;
use tokio::sync::OnceCell;
// use tokio::sync::RwLock;
use tracing::{debug, error, info, log, warn};
use web3::{
    contract::{Contract as EthContract, Options},
    futures::TryStreamExt,
    transports::WebSocket,
    types::{Address, BlockNumber, FilterBuilder, H256, Log, U256, U64},
    Web3,
};
use web3::ethabi::{Event, EventParam, ParamType, RawLog, token};

// use super::db::Database;
// use super::utils::{convert_va_pk_to_u64, FromFile, ToFile};

const CONTRACT_CONFIG_FILE: &str = "contract_config/configs.yml";
const CONTRACT_RECORD_FILE: &str = "contract_record.yml";
const CONTRACT_STORE_FILE: &str = "contract_store";
const CONTRACT_DATABASE_FILE: &str = "contract_database.db";
const CONTRACT_VA_REG_EVENT_NAME: &str = "ValidatorRegistration";
const CONTRACT_VA_RM_EVENT_NAME: &str = "ValidatorRemoval";
const CONTRACT_INI_REG_EVENT_NAME: &str = "InitiatorRegistration";
const CONTRACT_MINIPOOL_CREATED_EVENT_NAME: &str = "InitiatorMiniPoolCreated";
const CONTRACT_MINIPOOL_READY_EVENT_NAME: &str = "InitiatorMiniPoolReady";
pub static SELF_OPERATOR_ID: OnceCell<u32> = OnceCell::const_new();
pub static DEFAULT_TRANSPORT_URL: OnceCell<String> = OnceCell::const_new();
pub static REGISTRY_CONTRACT: OnceCell<String> = OnceCell::const_new();
pub static NETWORK_CONTRACT: OnceCell<String> = OnceCell::const_new();

#[derive(Debug)]
pub enum ContractError {
    StoreError,
    BlockNumberError,
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
    fn as_str(&self) -> &'static str {
        match self {
            ContractError::StoreError => "[ERROR!]: Can't interact with store.",
            ContractError::BlockNumberError => "[ERROR]: Can't get blocknumber from infura.",
            ContractError::LogError => "[ERROR]: Can't get logs from infura.",
            ContractError::RecordFileError => "[ERROR]: Error happens with record file.",
            ContractError::LogParseError => "[ERROR]: Can't parse eth log.",
            ContractError::NoEnoughOperatorError => {
                "[ERROR]: There are not enough operators in local database"
            }
            ContractError::DatabaseError => "[ERROR]: Can't get result from local databse",
            ContractError::InvalidArgumentError => "[ERROR]: Invalid Argument from contract",
            ContractError::FileError => "[ERROR]: Error happens when processing file",
            ContractError::ContractParseError => "[ERROR]: Can't parse contract from abi json",
            ContractError::QueryError => "[ERROR]: Can't query from contract",
        }
    }
}

type ValidatorPublicKey = [u8; 48];
type OperatorPublicKey = [u8; 33];

#[derive(Clone, Debug)]
pub struct Operator {
    pub id: u32,
    pub name: String,
    pub address: Address,
    pub public_key: OperatorPublicKey, // ecc256 public key
}

#[derive(Clone, Debug)]
pub struct Validator {
    pub id: u64,
    pub owner_address: Address,
    pub public_key: ValidatorPublicKey,
    // bls public key
    pub releated_operators: Vec<u32>,
    pub active: bool,
}

#[derive(Clone, Debug)]
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

#[derive(Clone)]
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
    MiniPoolCreated(u32, ValidatorPublicKey, OperatorPublicKeys, OperatorIds, Address),
    MiniPoolReady(u32, ValidatorPublicKey, OperatorPublicKeys, OperatorIds, Address),
}

#[async_trait]
pub trait TopicHandler: Send + Sync + 'static {
    async fn process(
        &self,
        log: Log,
        db: &Database,
        operator_pk_base64: &String,
        config: &ContractConfig,
        sender: &MonitoredSender<ContractCommand>,
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
        sender: &MonitoredSender<ContractCommand>,
    ) -> Result<(), ContractError> {
        process_validator_registration(log, db, operator_pk_base64, config, sender)
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
        operator_pk_base64: &String,
        config: &ContractConfig,
        sender: &MonitoredSender<ContractCommand>,
    ) -> Result<(), ContractError> {
        process_validator_removal(log, db, operator_pk_base64, config, sender)
            .await
            .map_err(|e| {
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
        sender: &MonitoredSender<ContractCommand>,
    ) -> Result<(), ContractError> {
        process_initiator_registration(log, db, operator_pk_base64, config, sender)
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
        operator_pk_base64: &String,
        config: &ContractConfig,
        sender: &MonitoredSender<ContractCommand>,
    ) -> Result<(), ContractError> {
        process_minipool_created(log, db, operator_pk_base64, config, sender)
            .await
            .map_err(|e| {
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
        operator_pk_base64: &String,
        config: &ContractConfig,
        sender: &MonitoredSender<ContractCommand>,
    ) -> Result<(), ContractError> {
        process_minipool_ready(log, db, operator_pk_base64, config, sender)
            .await
            .map_err(|e| {
                error!("error happens when process minipool ready");
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
    pub store: Store,
    pub base_dir: PathBuf,
    pub handlers: Arc<RwLock<HashMap<H256, Box<dyn TopicHandler>>>>,
    pub va_filter_builder: Option<FilterBuilder>,
    pub initiator_filter_builder: Option<FilterBuilder>
}

impl Contract {
    pub fn new<P: AsRef<Path>>(base_dir: P, operator_pk: PublicKey) -> Result<Self, String> {
        let config = ContractConfig::from_file(CONTRACT_CONFIG_FILE)?;
        let record = match ContractRecord::from_file(base_dir.as_ref().join(CONTRACT_RECORD_FILE)) {
            Ok(record) => record,
            Err(err_str) => {
                warn!("Can't recover from contract record file {}, get current block number from contract", err_str);
                ContractRecord { block_num: 0 }
            }
        };
        let contract_store_path = base_dir
            .as_ref()
            .join(CONTRACT_STORE_FILE)
            .to_str()
            .ok_or(("Can't get contract store path").to_string())?
            .to_owned();
        let store =
            Store::new(&contract_store_path).map_err(|e| format!("Can't create contract store {:?}", e))?;
        let db = Database::new(base_dir.as_ref().join(CONTRACT_DATABASE_FILE))
            .map_err(|e| format!("can't create contract database {:?}", e))?;
        Ok(Self {
            config,
            record,
            db,
            operator_pk,
            store,
            base_dir: base_dir.as_ref().to_path_buf(),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            va_filter_builder: None,
            initiator_filter_builder: None
        })
    }

    pub async fn check_operator_id(&self) {
        let op = query_operator_from_contract(&self.config, *SELF_OPERATOR_ID.get().unwrap()).await.unwrap();
        if op.public_key != self.operator_pk.0 {
            panic!("operator id is not consistent with smart contract! Please input right operator id");
        }
        self.db.insert_operator(op).await;
    }

    pub fn spawn(base_dir: PathBuf, operator_pk: PublicKey, tx: MonitoredSender<ContractCommand>) {
        tokio::spawn(async move {
            let mut contract = Contract::new(base_dir, operator_pk)
                .map_err(|e| {
                    error!("contract error: {}", e);
                })
                .unwrap();
            contract.construct_filter().await;
            contract.check_operator_id().await;
            contract.get_logs_from_contract(tx.clone()).await;
            contract.monitor_validator_paidblock(tx.clone());
            contract.listen_logs(tx).await;
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
        let va_filter_builder = FilterBuilder::default()
            .address(vec![Address::from_slice(
                &hex::decode({
                     NETWORK_CONTRACT.get().unwrap() 
                }).unwrap(),
            )])
            .topics(
                Some(vec![
                    va_reg_topic,
                    va_rm_topic
                ]),
                None,
                None,
                None,
            );
        self.va_filter_builder = Some(va_filter_builder);
        let initiator_filter_builder = FilterBuilder::default()
            .address(vec![Address::from_slice(
                &hex::decode({
                        REGISTRY_CONTRACT.get().unwrap() 
                }).unwrap(),
            )])
            .topics(
                Some(vec![
                    ini_reg_topic,
                    minipool_created_topic,
                    minipool_ready_topic
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
    }

    pub fn monitor_validator_paidblock(&mut self, sender: MonitoredSender<ContractCommand>) {
        let config = self.config.clone();
        let db = self.db.clone();
        tokio::spawn(async move {
            let mut query_interval = tokio::time::interval(Duration::from_secs(3600 * 6));
            loop {
                tokio::select! {
                    _ = query_interval.tick() => {
                        match db.query_all_validator_address().await {
                            Ok(owners) => {
                                for owner in owners {
                                    match check_account(&config, owner).await {
                                        Ok(t) => {
                                            if t {
                                                // stop validators releated to the block
                                                match db.query_validator_by_address(owner).await {
                                                    Ok(validators) => { 
                                                        for va in validators {
                                                            if va.active {
                                                                db.disable_validator(hex::encode(&va.public_key)).await;
                                                                let _ = sender.send(ContractCommand::StopValidator(va)).await;
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        error!("query validator releated to the address failed {:?}", e);
                                                    }
                                                }
                                            } else {
                                                match db.query_validator_by_address(owner).await {
                                                    Ok(validators) => { 
                                                        for va in validators {
                                                            if !va.active {
                                                                db.disable_validator(hex::encode(&va.public_key)).await;
                                                                let _ = sender.send(ContractCommand::ActivateValidator(va)).await;
                                                                
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        error!("query validator releated to the address failed {:?}", e);
                                                    }
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            error!("check account failed {}", e.as_str());
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                error!("query validator address failed {:?}", e);
                            }
                        }
                    }
                }
            }
        });
    }


    pub async fn get_logs_from_contract(&mut self, sender: MonitoredSender<ContractCommand>) {
        let mut record = self.record.clone();
        let config = self.config.clone();
        let record_path = self.base_dir.join(CONTRACT_RECORD_FILE);
        let store = self.store.clone();
        let db = self.db.clone();
        let operator_pk = self.operator_pk.clone();
        let operator_pk_base64 = base64::encode(&operator_pk);
        let filter_builder = self.va_filter_builder.as_ref().unwrap().clone();
        let handlers = self.handlers.clone();
        let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60 * 3)).await;
            if record.block_num == 0 {
                get_block_number(&mut record).await;
                update_record_file(&record, &record_path);
            }
            let mut query_interval = tokio::time::interval(Duration::from_secs(60 * 5));
            loop {
                tokio::select! {
                    _ = query_interval.tick() => {
                        let transport = WebSocket::new(transport_url).await;
                        match &transport {
                            Ok(_) => {},
                            Err(e) => {
                                warn!("can't connect to websocket {}", e);
                                tokio::time::sleep(Duration::from_secs(60 * 3)).await;
                                continue;
                            }
                        }
                        let web3 = Web3::new(transport.unwrap());
                        let filter = filter_builder
                            .clone()
                            .from_block(BlockNumber::Number(U64::from(record.block_num)))
                            .limit(20)
                            .build();
                        match web3.eth().logs(filter).await {
                            Ok(logs) => {
                                info!("Get {} logs.", &logs.len());
                                if logs.len() == 0 {
                                    get_block_number(&mut record).await;
                                }
                                for log in logs {
                                    record.block_num = log
                                        .block_number
                                        .map_or_else(|| record.block_num, |bn| bn.as_u64()) + 1;

                                    let listened = match log.transaction_hash {
                                        Some(hash) => log_listened(&store, &hash).await,
                                        None => false,
                                    };
                                    if listened {
                                        info!("This log has been listened, continue");
                                        continue;
                                    }
                                    let topic = log.topics[0].clone();
                                    match handlers.read().await.get(&topic) {
                                        Some(handler) => {
                                            match handler
                                                .process(
                                                    log,
                                                    &db,
                                                    &operator_pk_base64,
                                                    &config,
                                                    &sender,
                                                )
                                                .await
                                            {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    error!("error hapens, reason: {}", e.as_str());
                                                }
                                            }
                                        }
                                        None => {
                                            error!("Can't find handler");
                                        }
                                    };
                                }
                                
                            }
                            Err(e) => {
                                error!("{}, {}", ContractError::LogError.as_str(), e);
                                continue;
                            }
                        }
                        update_record_file(&record, &record_path);
                    }
                }
            }
        });
    }

    pub async fn listen_logs(&self, sender: MonitoredSender<ContractCommand>) {
        let config = self.config.clone();
        let store = self.store.clone();
        let db = self.db.clone();
        let operator_pk = self.operator_pk.clone();
        let operator_pk_base64 = base64::encode(&operator_pk);
        let va_filter_builder = self.va_filter_builder.as_ref().unwrap().clone();
        let va_filter = va_filter_builder.build();
        let initiator_filter_builder = self.initiator_filter_builder.as_ref().unwrap().clone();
        let initiator_filter = initiator_filter_builder.build();
        let handlers = self.handlers.clone();
        let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
        tokio::spawn(async move {
            loop {
                let transport = WebSocket::new(transport_url).await;
                match &transport {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("can't connect to websocket {}", e);
                        tokio::time::sleep(Duration::from_secs(60 * 3)).await;
                        continue;
                    }
                }
                let web3 = Web3::new(transport.unwrap());
                let mut va_sub = web3
                    .eth_subscribe()
                    .subscribe_logs(va_filter.clone())
                    .await
                    .unwrap();
                let mut initiator_sub = web3
                    .eth_subscribe()
                    .subscribe_logs(initiator_filter.clone())
                    .await
                    .unwrap();
                let mut logs = vec![];
                loop {
                    match va_sub.try_next().await.unwrap() {
                        Some(log) => {
                            logs.push(log)
                        },
                        None => {
                            error!("none event");
                            break;
                        }
                    }
                }
                loop {
                    match initiator_sub.try_next().await.unwrap() {
                        Some(log) => {
                            logs.push(log)
                        },
                        None => {
                            error!("none event");
                            break;
                        }
                    }
                }
                for log in logs {
                    let topic = log.topics[0].clone();
                    let transaction_hash = log.transaction_hash.clone();
                    match handlers.read().await.get(&topic) {
                        Some(handler) => {
                            match handler
                                .process(
                                    log,
                                    &db,
                                    &operator_pk_base64,
                                    &config,
                                    &sender,
                                )
                                .await
                            {
                                Ok(_) => {
                                    // store hash to local database
                                    match transaction_hash {
                                        Some(hash) => store.write(hash.as_bytes().to_vec(), vec![0]).await,
                                        None => {}
                                    };
                                }
                                Err(e) => {
                                    error!("error hapens, reason: {}", e.as_str());
                                }
                            }
                        }
                        None => {
                            error!("Can't find handler");
                        }
                    };
                }
            }
        });
    }
}

pub async fn get_block_number(record: &mut ContractRecord) {
    let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
    let web3 = Web3::new(WebSocket::new(transport_url).await.unwrap());
    // if can't get block number, reset to zero.
    record.block_num = web3.eth().block_number().await.map_or_else(
        |_| {
            error!("{}", ContractError::BlockNumberError.as_str());
            0
        },
        |number| number.as_u64(),
    );
}

pub async fn get_current_block() -> Result<U64, ContractError> {
    let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
    let web3 = Web3::new(WebSocket::new(transport_url).await.unwrap());
    web3.eth().block_number().await.or_else(|e| {
        error!("{:?} {}", e, ContractError::BlockNumberError.as_str());
        Err(ContractError::BlockNumberError)
    })
}

pub fn update_record_file<P: AsRef<Path>>(record: &ContractRecord, path: P) {
    record
        .to_file(path)
        .map_err(|e| {
            error!("{} error: {}", ContractError::RecordFileError.as_str(), e);
        })
        .unwrap();
}

pub async fn log_listened(store: &Store, log_hash: &H256) -> bool {
    match store.read(log_hash.as_fixed_bytes().to_vec()).await {
        Ok(res) => res.map_or_else(|| false, |_| true),
        Err(_) => {
            error!("{}", ContractError::StoreError.as_str());
            false
        }
    }
}

pub async fn process_validator_registration(
    raw_log: Log,
    db: &Database,
    operator_pk_base64: &String,
    config: &ContractConfig,
    sender: &MonitoredSender<ContractCommand>,
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
                let operator = query_operator_from_contract(config, *op_id).await?;
                operator_pks.push(base64::encode(&operator.public_key));
                db.insert_operator(operator).await;
            }
        };
    }
    if operator_pks.contains(operator_pk_base64) {
        set_global_operator_id(&operator_pks, &operator_pk_base64, &op_ids);
        let shared_pks = parse_bytes_token(log.params[3].value.clone())?;
        let encrypted_sks = parse_bytes_token(log.params[4].value.clone())?;
        // TODO paid block should store for tokenomics
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
        let _ = sender
            .send(ContractCommand::StartValidator(
                validator,
                op_pk_bn,
                shared_pks,
                encrypted_sks,
            ))
            .await;
    }
    Ok(())
}

pub async fn process_validator_removal(
    raw_log: Log,
    db: &Database,
    _operator_pk_base64: &String,
    _config: &ContractConfig,
    sender: &MonitoredSender<ContractCommand>,
) -> Result<(), ContractError> {
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

    let va_str = hex::encode(&va_pk);

    db.delete_validator(va_str).await;

    let _ = sender
        .send(ContractCommand::RemoveValidator(Validator {
            id,
            owner_address,
            public_key: va_pk.try_into().unwrap(),
            releated_operators: vec![],
            active: true,
        }))
        .await;
    Ok(())
}

pub async fn process_initiator_registration(
    raw_log: Log,
    db: &Database,
    operator_pk_base64: &String,
    config: &ContractConfig,
    sender: &MonitoredSender<ContractCommand>,
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
    println!("operator ids {:?}", op_ids);
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
                let operator = query_operator_from_contract(config, *op_id).await?;
                operator_pks.push(base64::encode(&operator.public_key));
                db.insert_operator(operator).await;
            }
        };
    }
    if operator_pks.contains(operator_pk_base64) {
        set_global_operator_id(&operator_pks, &operator_pk_base64, &op_ids);
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
        let _ = sender.send(ContractCommand::StartInitiator(initiator, op_pk_bn)).await;
    } else {
        info!("This node is not included in this initiator registration event. Continue.");
    }
    Ok(())
}

pub async fn process_minipool_created(
    raw_log: Log,
    db: &Database,
    _operator_pk_base64: &String,
    _config: &ContractConfig,
    sender: &MonitoredSender<ContractCommand>,
) -> Result<(), ContractError> {
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
                let (op_pks, op_ids) = db
                    .query_initiator_releated_op_pks(id)
                    .await
                    .map_err(|_| {
                        error!("Can't query initiator releated op pks");
                        ContractError::DatabaseError
                    })?;
                let op_pk_bns = op_pks.into_iter()
                    .map(|s| base64::decode(s).unwrap())
                    .collect();
                let _ = sender.send(ContractCommand::MiniPoolCreated(
                    id,
                    va_pk.try_into().unwrap(),
                    op_pk_bns,
                    op_ids,
                    minipool_address,
                )).await;
            }
            Ok(())
        }
        Err(e) => {
            error!("Can't update initiator {}", e);
            Err(ContractError::DatabaseError)
        }
    }
}

pub async fn process_minipool_ready(
    raw_log: Log,
    db: &Database,
    _operator_pk_base64: &String,
    _config: &ContractConfig,
    sender: &MonitoredSender<ContractCommand>,
) -> Result<(), ContractError> {
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
                let _ = initiator
                    .validator_pk
                    .ok_or(ContractError::DatabaseError)?;
                let _ = initiator
                    .minipool_address
                    .ok_or(ContractError::DatabaseError)?;
                let (op_pks, op_ids) = db
                    .query_initiator_releated_op_pks(id)
                    .await
                    .map_err(|_| {
                        error!("Can't query initiator releated op pks");
                        ContractError::DatabaseError
                    })?;

                let op_pks_bn = op_pks.into_iter()
                    .map(|s| base64::decode(s).unwrap())
                    .collect();
                let _ = sender.send(ContractCommand::MiniPoolReady(
                    id,
                    initiator.validator_pk.unwrap(),
                    op_pks_bn,
                    op_ids,
                    initiator.minipool_address.unwrap(),
                )).await;
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
) -> Result<Operator, ContractError> {
    let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
    let web3 = Web3::new(WebSocket::new(transport_url).await.unwrap());
    let raw_abi = std::fs::read_to_string(&config.safestake_registry_abi_path).or_else(|e| {
        error!(
            "Can't read from {} {}",
            &config.safestake_registry_abi_path, e
        );
        Err(ContractError::FileError)
    })?;
    let raw_json: Value = serde_json::from_str(&raw_abi).unwrap();
    let abi = raw_json["abi"].to_string();
    let address = Address::from_slice(&hex::decode({
        REGISTRY_CONTRACT.get().unwrap()
    }).unwrap());
    let contract = EthContract::from_json(web3.eth(), address, abi.as_bytes()).or_else(|e| {
        error!("Can't create contract from json {}", e);
        Err(ContractError::ContractParseError)
    })?;
    let (name, address, pk, _, _, _, _): (String, Address, Vec<u8>, U256, U256, U256, bool) =
        contract
            .query("getOperatorById", (id, ), None, Options::default(), None)
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

// check the paid block number of address. If the block is behind the current block number, stop validators releated to the address
pub async fn check_account(
    config: &ContractConfig,
    owner: Address,
) -> Result<bool, ContractError> {
    let transport_url = DEFAULT_TRANSPORT_URL.get().unwrap();
    let web3 = Web3::new(WebSocket::new(transport_url).await.unwrap());
    let raw_abi = std::fs::read_to_string(&config.safestake_network_abi_path).or_else(|e| {
        error!(
            "Can't read from {} {}",
            &config.safestake_network_abi_path, e
        );
        Err(ContractError::FileError)
    })?;
    let raw_json: Value = serde_json::from_str(&raw_abi).unwrap();
    let abi = raw_json["abi"].to_string();
    let address = Address::from_slice(&hex::decode({
        NETWORK_CONTRACT.get().unwrap()
    }).unwrap());
    let contract = EthContract::from_json(web3.eth(), address, abi.as_bytes()).or_else(|e| {
        error!("Can't create contract from json {}", e);
        Err(ContractError::ContractParseError)
    })?;
    let paid_block: U256 = contract.query("getAccountPaidBlockNumber", (owner, ), None, Options::default(), None).await.or_else(|e| {
        error!("Can't getAccountPaidBlockNumber from contract {}", e);
        Err(ContractError::QueryError)
    })?;
    let current_block = get_current_block().await?;
    info!("current block {:?}, paid block {:?} , account {}", current_block, paid_block,  owner);
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

// only call once
pub fn set_global_operator_id(pks: &Vec<String>, self_pk: &str, ids: &Vec<u32>) {
    if !SELF_OPERATOR_ID.initialized() {
        let index = pks.iter().position(|x| *x == *self_pk).unwrap();
        SELF_OPERATOR_ID.set(ids[index]).unwrap();
        info!("Set self operator id successfully")
    }
}
