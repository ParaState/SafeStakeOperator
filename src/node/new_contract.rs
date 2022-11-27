use serde::{Serialize};
use serde::de::DeserializeOwned;
use store::Store;
use web3::{Web3, transports::WebSocket, types::{Address, H256, FilterBuilder, Log, U64, BlockNumber}};
use web3::ethabi::{Event, EventParam, ParamType, RawLog, Hash, token};
use log::{info, warn, error};
use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};
use std::path::{Path, PathBuf};
use std::fs::File;
use crate::node::db::Database;
use crate::utils::error;
use hscrypto::PublicKey;
use std::time::Duration;
use hsutils::monitored_channel::{MonitoredSender};


const CONTRACT_CONFIG_FILE: &str = "contract_config/configs.yml";
const CONTRACT_RECORD_FILE: &str = "contract_record.yml";
const CONTRACT_DATABASE_FILE: &str = "contract_database.db";
const CONTRACT_VA_REG_EVENT_NAME: &str =  "ValidatorRegistration";
const CONTRACT_VA_RM_EVENT_NAME: &str =  "ValidatorRemoval";
const CONTRACT_OP_REG_EVENT_NAME: &str =  "OperatorRegistration";
const CONTRACT_OP_RM_EVENT_NAME: &str =  "OperatorRemoval";
const CONTRACT_INI_REG_EVENT_NAME: &str = "InitializerRegistration";
const CONTRACT_MINIPOOL_CREATED_EVENT_NAME: &str = "InitializerMiniPoolCreated";
const CONTRACT_MINIPOOL_READY_EVENT_NAME: &str = "InitializerMiniPoolReady";
pub enum ContractError{
    StoreError,
    BlockNumberError,
    LogError,
    RecordFileError,
    LogParseError,
    NoEnoughOperatorError,
    DatabaseError,
    InvalidArgumentError
}

impl ContractError {
    fn as_str(&self) -> &'static str {
        match self {
            ContractError::StoreError => "[ERROR!]: Can't interact with store.",
            ContractError::BlockNumberError => "[ERROR]: Can't get blocknumber from infura.",
            ContractError::LogError => "[ERROR]: Can't get logs from infura.",
            ContractError::RecordFileError => "[ERROR]: Error happens with record file.",
            ContractError::LogParseError => "[ERROR]: Can't parse eth log.",
            ContractError::NoEnoughOperatorError => "[ERROR]: There are not enough operators in local database",
            ContractError::DatabaseError => "[ERROR]: Can't get result from local databse",
            ContractError::InvalidArgumentError => "[ERROR]: Invalid Argument from contract"
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
    pub public_key: OperatorPublicKey // ecc256 public key
}

#[derive(Clone, Debug)]
pub struct Validator {
    pub id: u64,
    pub owner_address: Address,
    pub public_key: ValidatorPublicKey,    // bls public key
    pub releated_operators: Vec<u32>
}

#[derive(Clone, Debug)]
pub struct Initializer {
    pub id: u32, 
    pub owner_address: Address,
    pub releated_operators: Vec<u32>,
    pub validator_pk: Option<ValidatorPublicKey>,
    pub minipool_address: Option<Address>
}

type SharedPublicKeys = Vec<Vec<u8>>;
type EncryptedSecretKeys = Vec<Vec<u8>>;
type OperatorPublicKeys = Vec<Vec<u8>>;

pub enum ContractCommand {
    StartValidator(Validator, OperatorPublicKeys, SharedPublicKeys, EncryptedSecretKeys),
    StopValidator(Validator),
    StartInitializer(Initializer, OperatorPublicKeys),
    MiniPoolCreated(u32, ValidatorPublicKey, Address),
    MiniPoolReady(u32, ValidatorPublicKey, Address)
}

pub trait FromFile<T: DeserializeOwned> {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<T, String> {
        let file = File::options().read(true).open(path).map_err(|e| { format!("can't open file {:?}", e) } )?;
        serde_yaml::from_reader(file).map_err(|e| { format!("can't deserialize file {:?}", e) })
    }
}

pub trait ToFile<> {
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> where Self: Serialize{
        let file = File::options().write(true).create(true).truncate(true).open(path).map_err(|e| { format!("can't open file {:?}", e) } )?;
        serde_yaml::to_writer(file, self).map_err(|e| { format!("can't serialize to file {:?}", e) })
    }
}

#[derive(Debug, DeriveSerialize, DeriveDeserialize, Clone)]
pub struct ContractConfig {
    pub validator_registration_topic: String, 
    pub validator_removal_topic: String,
    pub operator_registration_topic: String, 
    pub operator_removal_topic: String,
    pub initializer_registration_topic: String,
    pub initializer_minipool_created_topic: String,
    pub initializer_minipool_ready_topic: String,
    pub transport_url: String,
    pub safestake_network_address: String,
    pub safestake_registry_address: String,
    pub safestake_network_abi_path: String,
    pub safestake_registry_abi_path: String
}
impl FromFile<ContractConfig> for ContractConfig {}
impl ToFile for ContractConfig {}

#[derive(Clone, DeriveSerialize, DeriveDeserialize, Debug)]
pub struct ContractRecord {
    pub block_num: u64
}

impl FromFile<ContractRecord> for ContractRecord {}
impl ToFile for ContractRecord {}


pub struct Contract {
    pub config: ContractConfig,
    pub record: ContractRecord,
    pub db: Database,
    pub operator_pk: PublicKey, 
    pub store: Store,
    pub base_dir: PathBuf
}

impl Contract {
    pub fn new<P: AsRef<Path>>(base_dir: P, operator_pk: PublicKey, store: Store) -> Result<Self, String> {
        let config = ContractConfig::from_file(CONTRACT_CONFIG_FILE)?;
        let record = match ContractRecord::from_file(base_dir.as_ref().join(CONTRACT_RECORD_FILE)) {
            Ok(record) => {
                record
            }, 
            Err(err_str) => {
                warn!("Can't recover from contract record file {}", err_str);
                ContractRecord { block_num: 0 } 
            }
        };
        let db = Database::new(base_dir.as_ref().join(CONTRACT_DATABASE_FILE)).map_err(|e| format!("can't create contract database {:?}", e))?;
        Ok(Self { config, record, db, operator_pk, store, base_dir : base_dir.as_ref().to_path_buf() })
    }

    pub fn get_logs_from_contract(
        &mut self,
        sender: MonitoredSender<ContractCommand>
    ) {
        let mut record = self.record.clone();
        let config = self.config.clone();
        let record_path = self.base_dir.join(CONTRACT_RECORD_FILE);
        let store = self.store.clone();
        let db = self.db.clone();
        let operator_pk = self.operator_pk.clone();
        let operator_pk_base64 = base64::encode(&operator_pk);

        let va_reg_topic = H256::from_slice(&hex::decode(&config.validator_registration_topic).unwrap());
        let va_rm_topic = H256::from_slice(&hex::decode(&config.validator_removal_topic).unwrap());
        let op_reg_topic = H256::from_slice(&hex::decode(&config.operator_registration_topic).unwrap());
        let op_rm_topic = H256::from_slice(&hex::decode(&config.operator_removal_topic).unwrap());
        let ini_reg_topic = H256::from_slice(&hex::decode(&config.initializer_registration_topic).unwrap());
        let minipool_created_topic = H256::from_slice(&hex::decode(&config.initializer_minipool_created_topic).unwrap());
        let minipool_ready_topic = H256::from_slice(&hex::decode(&config.initializer_minipool_ready_topic).unwrap());

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60 * 3)).await;
            if record.block_num == 0 {
                get_block_number(&mut record, &config).await;
                update_record_file(&record, record_path);
            }

            loop {
                let web3 = Web3::new(WebSocket::new(&config.transport_url).await.unwrap());
                let filter = FilterBuilder::default()
                    .address(vec![Address::from_slice(&hex::decode(&config.safestake_network_address).unwrap())])
                    .topics(
                        Some(vec![va_reg_topic, va_rm_topic, op_reg_topic, op_rm_topic]), 
                        None, 
                        None, 
                        None)
                    .from_block(BlockNumber::Number(U64::from(record.block_num)))
                    .build();
                match web3.eth().logs(filter).await {
                    Ok(logs) => {
                        info!("Get {} logs.", &logs.len());
                        for log in logs {
                            record.block_num = log.block_number.map_or_else(||record.block_num  , |bn| bn.as_u64());
                            
                            let listened = match log.transaction_hash {
                                Some(hash) => {
                                    log_listened(&store, &hash).await
                                },
                                None => false
                            };
                            if listened {
                                info!("This log has been lestened, continue");
                                continue;
                            }
                            if log.topics[0] == va_reg_topic {
                                info!("validator registration event");
                                match process_validator_registration_log(log, &va_reg_topic) {
                                    Ok(va_log) => {
                                        let _ = process_validator_registration(va_log, &db, &operator_pk_base64, &sender).await.map_err(|e| {error!("process validator registration event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process validator registration log failed {}", e.as_str()); continue; }
                                }
                            } else if log.topics[0] == va_rm_topic {
                                info!("validator removal event");
                                match process_validator_removal_log(log, &va_rm_topic) {
                                    Ok(va_log) => {
                                        let _ = process_validator_removal(va_log, &db, &sender).await.map_err(|e| {error!("process validator removal event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process validator removal log failed {}", e.as_str()); continue; }
                                }
                            } else if log.topics[0] == op_reg_topic {
                                info!("operator registration event");
                                match process_operator_registration_log(log, &op_reg_topic) {
                                    Ok(op_log) => {
                                        let _ = process_operator_registration(op_log, &db).await.map_err(|e| {error!("process operator registration event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process operator registration log failed {}", e.as_str()); continue; }
                                }
                            } else if log.topics[0] == op_rm_topic {
                                info!("operator removal event");
                                match process_operator_removal_log(log, &op_rm_topic) {
                                    Ok(op_log) => {
                                        let _ = process_operator_removal(op_log, &db).await.map_err(|e| {error!("process operator registration event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process operator registration log failed {}", e.as_str()); continue; }
                                }
                            } else if log.topics[0] == ini_reg_topic {
                                info!("initializer registration event");
                                match process_initializer_registration_log(log, &ini_reg_topic) {
                                    Ok(ini_log) => {
                                        let _ = process_initializer_registration(ini_log, &db, &operator_pk_base64, &sender).await.map_err(|e| {error!("process initializer registration event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process initializer registration log failed {}", e.as_str()); continue; }
                                }
                            } else if log.topics[0] == minipool_created_topic {
                                info!("minipool created event");
                                match process_minipool_created_log(log, &minipool_created_topic) {
                                    Ok(pool_log) => {
                                        let _ = process_minipool_created(pool_log, &db, &sender).await.map_err(|e| {error!("process minipool created event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process minipool created event failed {}", e.as_str()); continue; }
                                }
                            } else if log.topics[0] == minipool_ready_topic {
                                info!("minipool ready event");
                                match process_minipool_ready_log(log, &minipool_ready_topic) {
                                    Ok(pool_log) => {
                                        let _ = process_minipool_ready(pool_log, &db, &sender).await.map_err(|e| {error!("process minipool ready event failed {}", e.as_str())});
                                    },
                                    Err(e) => {error!("process minipool ready event failed {}", e.as_str()); continue; }
                                }
                            }
                            
                            else {
                                error!("unkown topic");
                            }
                            
                        }
                    },
                    Err(e) => {
                        error!("{}, {}", ContractError::LogError.as_str(), e);
                        continue;
                    }
                }
            }
        });
    }

}

pub async fn get_block_number(record: & mut ContractRecord, config: &ContractConfig) {
    let web3 = Web3::new(WebSocket::new(&config.transport_url).await.unwrap());
            // if can't get block number, reset to zero. 
    record.block_num = web3.eth().block_number().await.map_or_else(|_| { error!("{}", ContractError::BlockNumberError.as_str()); 0 }, |number| number.as_u64());
}

pub fn update_record_file<P: AsRef<Path>>(record: &ContractRecord, path: P) {
    record.to_file(path).map_err(|e| {
        error!("{} error: {}", ContractError::RecordFileError.as_str(), e);
    }).unwrap_err();
}

pub async fn log_listened(store: &Store, log_hash: &H256) -> bool {
    match store.read(log_hash.as_fixed_bytes().to_vec()).await {
        Ok(res) => {
            res.map_or_else(|| false, |_| { true})
        },
        Err(_) => { error!("{}", ContractError::StoreError.as_str()); false }
    }
}

pub fn process_validator_registration_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let validator_reg_event = Event {
        name: CONTRACT_VA_REG_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: true
            },
            EventParam {
                name: "publicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false
            },
            EventParam {
                name: "operatorIds".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(32))),
                indexed: false
            },
            EventParam {
                name: "sharesPublicKeys".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Bytes)),
                indexed: false
            },
            EventParam {
                name: "encryptedKeys".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Bytes)),
                indexed: false
            },
            EventParam {
                name: "paidBlockNumber".to_string(),
                kind: ParamType::Uint(256),
                indexed: false
            }
        ],
        anonymous: false
    };
    validator_reg_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| {
        ContractError::LogParseError
    })
}

pub async fn process_validator_registration(log: web3::ethabi::Log, db: &Database, operator_pk_base64: &String, sender: &MonitoredSender<ContractCommand>) -> Result<(), ContractError> {
    let address = log.params[0].value.clone().into_address().ok_or(ContractError::LogParseError)?;
    let va_pk = log.params[1].value.clone().into_bytes().ok_or(ContractError::LogParseError)?;
    let validator_id = convert_va_pk_to_u64(&va_pk);
    let operator_tokens = log.params[2].value.clone().into_array().ok_or(ContractError::LogParseError)?;
    let op_ids : Vec<u32> = operator_tokens.into_iter().map(|token| {
        let op_id = token.into_uint().unwrap();
        op_id.as_u32()
    }).collect();

    let operator_pks = db.query_operators_publick_key_by_ids(op_ids.clone()).await;
    match operator_pks {
        Ok(options) => {
            let op_pks = options.ok_or(ContractError::NoEnoughOperatorError)?;
            // check if found enough operators ?
            if op_pks.len() != op_ids.len() {
                return Err(ContractError::NoEnoughOperatorError);
            }
            if op_pks.contains(operator_pk_base64) {
                let shared_pks = parse_bytes_token(log.params[3].value.clone())?;
                let encrypted_sks = parse_bytes_token(log.params[4].value.clone())?;
                // TODO paid block should store for tokenomics
                let paid_block_number = log.params[5].value.clone().into_uint().ok_or(ContractError::LogParseError)?.as_u64();
                // check array length should be same
                if shared_pks.len() != encrypted_sks.len() {
                    return Err(ContractError::InvalidArgumentError);
                }
                if shared_pks.len() != op_ids.len() {
                    return Err(ContractError::InvalidArgumentError);
                }
                // binary operator publics
                let op_pk_bn: Vec<Vec<u8>> = op_pks.into_iter().map(|s| {
                    base64::decode(s).unwrap()
                }).collect();
                //send command to node 
                let validator = Validator {
                    id: validator_id,
                    owner_address: address,
                    public_key: va_pk.try_into().unwrap(),
                    releated_operators: op_ids
                };
                // save validator in local database
                db.insert_validator(validator.clone()).await;
                let _ = sender.send(ContractCommand::StartValidator(validator, op_pk_bn, shared_pks, encrypted_sks)).await;

                Ok(())
            } else {
                info!("This node is not included in this event. Continue.");
                Ok(())
            }
        },
        Err(_) => { 
            Err(ContractError::DatabaseError) 
        }
    }
}

pub fn process_validator_removal_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let validator_rm_event = Event {
        name: CONTRACT_VA_RM_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: true
            },
            EventParam {
                name: "publicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false
            },
        ],
        anonymous: false
    };
    validator_rm_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| { ContractError::LogParseError })
}

pub async fn process_validator_removal(log: web3::ethabi::Log, db: &Database, sender: &MonitoredSender<ContractCommand>) -> Result<(), ContractError> {
    let owner_address = log.params[0].value.clone().into_address().ok_or(ContractError::LogParseError)?;
    let va_pk = log.params[1].value.clone().into_bytes().ok_or(ContractError::LogParseError)?;
    let id = convert_va_pk_to_u64(&va_pk);

    let va_str = hex::encode(&va_pk);

    db.delete_validator(va_str).await;

    let _ = sender.send(ContractCommand::StopValidator(Validator {
        id, 
        owner_address,
        public_key: va_pk.try_into().unwrap(),
        releated_operators: vec![]
    })).await;
    Ok(())
}

pub fn process_operator_registration_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let op_reg_event = Event {
        name: CONTRACT_OP_REG_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "id".to_string(),
                kind: ParamType::Uint(32),
                indexed: true
            },
            EventParam {
                name: "name".to_string(),
                kind: ParamType::String,
                indexed: false
            },
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: true
            },
            EventParam {
                name: "publicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false
            }
        ],
        anonymous: false
    };
    op_reg_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| {ContractError::LogParseError })
}

pub async fn process_operator_registration(log: web3::ethabi::Log, db: &Database) -> Result<(), ContractError> {
    let id = log.params[0].value.clone().into_uint().ok_or(ContractError::LogParseError)?.as_u32();
    let name = log.params[1].value.clone().into_string().ok_or(ContractError::LogParseError)?;
    let address = log.params[2].value.clone().into_address().ok_or(ContractError::LogParseError)?;
    let pk = log.params[3].value.clone().into_bytes().ok_or(ContractError::LogParseError)?;
    let operator = Operator {
        id,
        name, 
        address,
        public_key: pk.try_into().unwrap()
    };
    db.insert_operator(operator).await;
    Ok(())
}

pub fn process_operator_removal_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let op_rm_event = Event {
        name: CONTRACT_OP_RM_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "operatorId".to_string(),
                kind: ParamType::Uint(32),
                indexed: true
            },
            EventParam {
                name: "address".to_string(),
                kind: ParamType::String,
                indexed: false
            }
        ],
        anonymous: false
    };
    op_rm_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| {ContractError::LogParseError })
}

pub async fn process_operator_removal(log: web3::ethabi::Log, db: &Database) -> Result<(), ContractError> {
    let id = log.params[0].value.clone().into_uint().ok_or(ContractError::LogParseError)?.as_u32();
    db.delete_operator(id).await;
    Ok(())
}

pub fn process_initializer_registration_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let ini_reg_event = Event {
        name: CONTRACT_INI_REG_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "initializerId".to_string(),
                kind: ParamType::Uint(32),
                indexed: false
            },
            EventParam {
                name: "ownerAddress".to_string(),
                kind: ParamType::Address,
                indexed: false
            },
            EventParam {
                name: "operatorIds".to_string(),
                kind: ParamType::Array(Box::new(ParamType::Uint(32))),
                indexed: false
            }
        ],
        anonymous: false
    };
    ini_reg_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| {
        ContractError::LogParseError
    })
}

pub async fn process_initializer_registration(log: web3::ethabi::Log, db: &Database, operator_pk_base64: &String, sender: &MonitoredSender<ContractCommand>) -> Result<(), ContractError>{
    let id = log.params[0].value.clone().into_uint().ok_or(ContractError::LogParseError)?.as_u32();
    let address = log.params[1].value.clone().into_address().ok_or(ContractError::LogParseError)?;
    let operator_tokens = log.params[2].value.clone().into_array().ok_or(ContractError::LogParseError)?;
    let op_ids : Vec<u32> = operator_tokens.into_iter().map(|token| {
        let op_id = token.into_uint().unwrap();
        op_id.as_u32()
    }).collect();

    let operator_pks = db.query_operators_publick_key_by_ids(op_ids.clone()).await;

    match operator_pks {
        Ok(options) => {
            let op_pks = options.ok_or(ContractError::NoEnoughOperatorError)?;
            if op_pks.len() != op_ids.len() {
                return Err(ContractError::NoEnoughOperatorError);
            }
            if op_pks.contains(operator_pk_base64) {
                let initializer = Initializer {
                    id,
                    owner_address: address,
                    releated_operators: op_ids,
                    validator_pk: None,
                    minipool_address: None
                };
                let op_pk_bn: Vec<Vec<u8>> = op_pks.into_iter().map(|s| {
                    base64::decode(s).unwrap()
                }).collect();
                db.insert_initializer(initializer.clone()).await;
                let _ = sender.send(ContractCommand::StartInitializer(initializer, op_pk_bn));
            } else {
                info!("This node is not included in this initializer registration event. Continue.");
            }
            Ok(())
        },
        Err(_) => { 
            Err(ContractError::DatabaseError) 
        }
    }
}

pub fn process_minipool_created_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let minipool_created_event = Event {
        name: CONTRACT_MINIPOOL_CREATED_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "initializerId".to_string(),
                kind: ParamType::Uint(32),
                indexed: false
            },
            EventParam {
                name: "validatorPublicKey".to_string(),
                kind: ParamType::Bytes,
                indexed: false
            },
            EventParam {
                name: "minipoolAddress".to_string(),
                kind: ParamType::Address,
                indexed: false
            }
        ],
        anonymous: false
    };
    minipool_created_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| {
        ContractError::LogParseError
    })
}

pub async fn process_minipool_created(log: web3::ethabi::Log, db: &Database, sender: &MonitoredSender<ContractCommand>) -> Result<(), ContractError> {
    let id = log.params[0].value.clone().into_uint().ok_or(ContractError::LogParseError)?.as_u32();
    let va_pk = log.params[1].value.clone().into_bytes().ok_or(ContractError::LogParseError)?;
    let minipool_address = log.params[2].value.clone().into_address().ok_or(ContractError::LogParseError)?;

    match db.update_initializer(id, hex::encode(&va_pk), format!("{0:0x}", minipool_address)).await {
        Ok(updated) => { 
            if updated != 0 {
                let _ = sender.send(ContractCommand::MiniPoolCreated(id, va_pk.try_into().unwrap(), minipool_address));
            }
            Ok(())
        },
        Err(e) => { error!("Can't update initializer"); Err(ContractError::DatabaseError) }
    }
}

pub fn process_minipool_ready_log(log: Log, topic: &H256) -> Result<web3::ethabi::Log, ContractError> {
    let minipool_ready_event = Event {
        name: CONTRACT_MINIPOOL_READY_EVENT_NAME.to_string(),
        inputs: vec![
            EventParam {
                name: "initializerId".to_string(),
                kind: ParamType::Uint(32),
                indexed: false
            }
        ],
        anonymous: false
    };
    minipool_ready_event.parse_log(RawLog {
        topics: vec![Hash::from_slice(&topic.0)],
        data: log.data.0
    }).map_err(|_| {
        ContractError::LogParseError
    })
}

pub async fn process_minipool_ready(log: web3::ethabi::Log, db: &Database, sender: &MonitoredSender<ContractCommand>) -> Result<(), ContractError> {
    let id = log.params[0].value.clone().into_uint().ok_or(ContractError::LogParseError)?.as_u32();
    match db.query_initializer(id).await {
        Ok(initializer_option) => {
            match initializer_option {
                Some(initializer) => {
                    let _ = initializer.validator_pk.ok_or(ContractError::DatabaseError)?;
                    let _ = initializer.minipool_address.ok_or(ContractError::DatabaseError)?;
                    let _ = sender.send(ContractCommand::MiniPoolReady(id, initializer.validator_pk.unwrap(), initializer.minipool_address.unwrap()));
                    Ok(())
                },
                None => { Ok(()) }
            }
        }, 
        Err(_) => {  Err(ContractError::DatabaseError)  }
    }
}

pub fn parse_bytes_token(tk: token::Token) -> Result<Vec<Vec<u8>>, ContractError> {
    let token_arr = tk.into_array().ok_or(ContractError::LogParseError)?;
    let res :Vec<Vec<u8>> = token_arr.into_iter().map(|token| {
        token.into_bytes().unwrap()
    }).collect();
    Ok(res)
}

pub fn convert_va_pk_to_u64(pk: &[u8]) -> u64 {
    let mut little_endian: [u8; 8] = [0; 8];
    let mut i = 0;
    for elem in little_endian.iter_mut() {
        *elem = pk[i];
        i = i + 1;
    } 
    let id = u64::from_le_bytes(little_endian);
    id 
  } 