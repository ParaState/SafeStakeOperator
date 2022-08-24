use web3::{
  Web3,
  transports::WebSocket,
  types::{FilterBuilder, Address, H256, Log, BlockNumber, U64}, 
  futures::{TryStreamExt}
}; 
use web3::ethabi::{Event, EventParam, ParamType, RawLog, Hash, token};
use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};
use log::{info, error};
use tokio::sync::{mpsc};
use std::sync::{Arc};
use tokio::sync::RwLock;
use std::collections::{HashMap, HashSet};
use std::fs::{File,remove_file};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::OnceCell;
const DEFAULT_ABI_JSON: &str = "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"validatorPublicKey\",\"type\":\"bytes\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"operatorPublicKey\",\"type\":\"bytes\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"sharedPublicKey\",\"type\":\"bytes\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"encryptedKey\",\"type\":\"bytes\"}],\"name\":\"OessAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"ownerAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"publicKey\",\"type\":\"bytes\"}],\"name\":\"OperatorAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"publicKey\",\"type\":\"bytes\"}],\"name\":\"OperatorDeleted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"ownerAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"publicKey\",\"type\":\"bytes\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"operatorPublicKey\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"sharedPublicKey\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"encryptedKey\",\"type\":\"bytes\"}],\"indexed\":false,\"internalType\":\"struct ISSVNetwork.Oess[]\",\"name\":\"oessList\",\"type\":\"tuple[]\"}],\"name\":\"ValidatorAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"ownerAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"publicKey\",\"type\":\"bytes\"}],\"name\":\"ValidatorDeleted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"ownerAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"publicKey\",\"type\":\"bytes\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"operatorPublicKey\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"sharedPublicKey\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"encryptedKey\",\"type\":\"bytes\"}],\"indexed\":false,\"internalType\":\"struct ISSVNetwork.Oess[]\",\"name\":\"oessList\",\"type\":\"tuple[]\"}],\"name\":\"ValidatorUpdated\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"_name\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"_ownerAddress\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"_publicKey\",\"type\":\"bytes\"}],\"name\":\"addOperator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_ownerAddress\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"_publicKey\",\"type\":\"bytes\"},{\"internalType\":\"bytes[]\",\"name\":\"_operatorPublicKeys\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes[]\",\"name\":\"_sharesPublicKeys\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes[]\",\"name\":\"_encryptedKeys\",\"type\":\"bytes[]\"}],\"name\":\"addValidator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_publicKey\",\"type\":\"bytes\"}],\"name\":\"deleteOperator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_publicKey\",\"type\":\"bytes\"}],\"name\":\"deleteValidator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"operatorCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"name\":\"operators\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"ownerAddress\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"publicKey\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"score\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_operatorPublicKey\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"_validatorsPerOperator\",\"type\":\"uint256\"}],\"name\":\"setValidatorsPerOperator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_validatorsPerOperatorLimit\",\"type\":\"uint256\"}],\"name\":\"setValidatorsPerOperatorLimit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_publicKey\",\"type\":\"bytes\"},{\"internalType\":\"bytes[]\",\"name\":\"_operatorPublicKeys\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes[]\",\"name\":\"_sharesPublicKeys\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes[]\",\"name\":\"_encryptedKeys\",\"type\":\"bytes[]\"}],\"name\":\"updateValidator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"validatorCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_operatorPublicKey\",\"type\":\"bytes\"}],\"name\":\"validatorsPerOperatorCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"validatorsPerOperatorLimit\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]";
const DEFAULT_TRANSPORT_URL: &str = "wss://ropsten.infura.io/ws/v3/3cda22fb4f704870b3d2fafa70688a2e";
// const DEFAULT_CONTRACT_ADDRESS: &str = "EE56aB0FfAD43e003a1c0517E6583D036A1A56b2";
pub static DEFAULT_CONTRACT_ADDRESS: OnceCell<String> = OnceCell::const_new();
const DEFAULT_ADD_VALIDATOR_TOPIC: &str = "8674c0b4bd63a0814bf1ae6d64d71cf4886880a8bdbd3d7c1eca89a37d1e9271";
const DEFAULT_UPDATE_VALIDATOR_TOPIC: &str = "4c63bf11b116f386ae0aee6d8d6df531b5ed877eb5d2073119ddb4769ba3f312";
const DEFAULT_DELETE_VALIDATOR_TOPIC: &str = "4c63bf11b116f386ae0aee6d8d6df531b5ed877eb5d2073119ddb4769ba3f312";
const CONTRACTRECORDFIL: &str = "contract_record.yml";
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Operator {
  pub id: u64, 
  pub node_public_key: Vec<u8>, 
  pub shared_public_key: Vec<u8>, 
  pub encrypted_key: Vec<u8> 
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Validator {
  pub id: u64, 
  pub validator_address: Address,
  pub validator_public_key: Vec<u8>
}

pub enum ValidatorCommand {
  Start(Validator),
  Stop(Validator)
}

pub enum ValidatorEventType {
  ADDED,
  UPDATED,
  DELETED
}

pub struct ListenContract {
  // web3: Web3<WebSocket>,
  node_public_key: Vec<u8>,
  channel: mpsc::Sender<ValidatorCommand>,
  validators_map: Arc<RwLock<HashMap<u64, Validator>>>,
  validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>
}

#[derive(Clone)]
pub struct ContractConfig {
  pub transport_url: String, 
  pub contract_address: String, 
  pub added_topic: String, 
  pub updated_topic: String,
  pub deleted_topic: String,
  pub abi_json: String
}

#[derive(Clone, PartialEq, DeriveSerialize, DeriveDeserialize)]
pub struct ContractRecord {
    pub block_num: u64
}


impl ContractRecord {
  pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
    let file = File::options()
        .read(true)
        .write(false)
        .create(false)
        .open(path)
        .unwrap();
    serde_yaml::from_reader(file).unwrap()
  }

  pub fn to_file<P: AsRef<Path>>(&self, path: P) {
    let file = File::options()
        .write(true)
        .read(true)
        .create_new(true)
        .open(path)
        .unwrap();
    serde_yaml::to_writer(file, self).unwrap()
  }
  
  pub fn open_or_create_contract_record(path: &PathBuf) -> Self {
    if path.exists() {
      ContractRecord::from_file(path)
    } else {
      Self { block_num: 0 }
    }
  }
}

impl ContractConfig {
  pub fn default() -> Self {
    Self {
      transport_url: DEFAULT_TRANSPORT_URL.to_string(),
      contract_address: DEFAULT_CONTRACT_ADDRESS.get().unwrap().to_string(),
      added_topic: DEFAULT_ADD_VALIDATOR_TOPIC.to_string(),
      updated_topic: DEFAULT_UPDATE_VALIDATOR_TOPIC.to_string(),
      deleted_topic: DEFAULT_DELETE_VALIDATOR_TOPIC.to_string(),
      abi_json: DEFAULT_ABI_JSON.to_string()
    }
  }
}

impl ListenContract {
  pub fn pull_from_contract(
    config: ContractConfig,
    node_public_key: Vec<u8>,
    channel: mpsc::Sender<ValidatorCommand>,
    validators_map: Arc<RwLock<HashMap<u64, Validator>>>,
    validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>,
    base_dir: PathBuf,
    ethlog_hashset: Arc<RwLock<HashSet<H256>>>
  ) {
    tokio::spawn(async move {
      let contract = Self {
        node_public_key,
        channel,
        validators_map,
        validator_operators_map
      };

      let contract_record_path = base_dir.join(CONTRACTRECORDFIL);
      
      let mut contract_record = ContractRecord::open_or_create_contract_record(&contract_record_path);

      if contract_record.block_num == 0 {
        let web3 : Web3<WebSocket> = Web3::new(WebSocket::new(&config.transport_url).await.unwrap());
        contract_record.block_num = match web3.eth().block_number().await {
          Ok(number) => { number.as_u64() },
          Err(error) => {
            error!("can't get current block number {:?}", error);
            12825550 
          }
        };
      }

      let added_topic = H256::from_slice(&hex::decode(config.added_topic).unwrap());
      let deleted_topic = H256::from_slice(&hex::decode(config.deleted_topic).unwrap());
      let mut query_interval = tokio::time::interval(Duration::from_secs(60 * 5));
      loop {
        tokio::select! {
          _ = query_interval.tick() => {
            let web3: Web3<WebSocket> = Web3::new(WebSocket::new(&config.transport_url).await.unwrap());
            let filter = FilterBuilder::default().
              address(vec![Address::from_slice(&hex::decode(&config.contract_address).unwrap())]).
              topics(Some(vec![added_topic.clone(), deleted_topic.clone()]), None, None, None)
              .from_block(BlockNumber::Number(U64::from(contract_record.block_num as u64)))
              .build();
            let logs = web3.eth().logs(filter).await.unwrap();
            info!("get {} logs", &logs.len());
            if logs.len() == 0 {
              contract_record.block_num = web3.eth().block_number().await.unwrap().as_u64();
            }
            for log in logs {
              let hash = log.transaction_hash.unwrap();
              let log_hashset = ethlog_hashset.read().await;
              if log_hashset.contains(&hash) {
                info!("this log has been listened, don't do anything");
                continue;
              }
              contract_record.block_num = log.block_number.unwrap().as_u64() + 1;
              if log.topics[0] == added_topic {
                info!("added topic");
                contract.process_validator_add_or_update_event(log, &added_topic, ValidatorEventType::ADDED).await;
              } else if log.topics[0] == deleted_topic {
                info!("deleted topic");
                contract.process_validator_deleted_event(log, &deleted_topic).await;
              } else {
                error!("unkown topic");
              }
            }
            if contract_record_path.exists() {
              remove_file(&contract_record_path).unwrap();
            }
            contract_record.to_file(&contract_record_path);
          }
        }
      }
    });
  }


  pub fn spawn (
    config: ContractConfig,
    node_public_key: Vec<u8>,
    channel: mpsc::Sender<ValidatorCommand>,
    validators_map: Arc<RwLock<HashMap<u64, Validator>>>,
    validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>,
    ethlog_hashset: Arc<RwLock<HashSet<H256>>>
  ) {

    tokio::spawn(async move {
      let listen_contract = Self {
        node_public_key,
        channel,
        validators_map,
        validator_operators_map
      };

      let added_topic = H256::from_slice(&hex::decode(config.added_topic).unwrap());
      // let updated_topic = H256::from_slice(&hex::decode(config.updated_topic).unwrap());
      let deleted_topic = H256::from_slice(&hex::decode(config.deleted_topic).unwrap());
      loop {
        let web3: Web3<WebSocket> = Web3::new(WebSocket::new(&config.transport_url).await.unwrap());
        // listen from smart contract
        let filter = FilterBuilder::default().address(vec![Address::from_slice(&hex::decode(&config.contract_address).unwrap())])
        // .topics(Some(vec![added_topic, updated_topic, deleted_topic]), None, None, None)
          .topics(Some(vec![added_topic.clone(), deleted_topic.clone()]), None, None, None)
          .build();
        let mut sub = web3.eth_subscribe().subscribe_logs(filter.clone()).await.unwrap();
        loop {
          // let eth_log = sub.try_next().await.unwrap().unwrap();
          match sub.try_next().await.unwrap() {
            Some(eth_log) => {
              let hash = eth_log.transaction_hash.unwrap();
              let mut log_set = ethlog_hashset.write().await;
              let _ = log_set.insert(hash);
              if eth_log.topics[0] == added_topic {
                info!("added topic");
                listen_contract.process_validator_add_or_update_event(eth_log, &added_topic, ValidatorEventType::ADDED).await;
              // } else if eth_log.topics[0] == updated_topic {
              //   info!("updated topic");
              //   listen_contract.process_validator_event(eth_log, &updated_topic, ValidatorEventType::UPDATED).await;
              } else if eth_log.topics[0] == deleted_topic {
                info!("deleted topic");
                listen_contract.process_validator_deleted_event(eth_log, &deleted_topic).await;
              } else {
                error!("unkown topic");
              }
            },
            None => { 
              error!("none event"); 
              break;
            }
          }
        }
      }
    });
    
  }

  pub async fn process_validator_info(&self, eth_log: web3::ethabi::Log, event_type: ValidatorEventType) {
    let address = match &eth_log.params[0].value {
      token::Token::Address(address) => Some(address),
      _ => None
    }.unwrap();

    // need a function convert address to id

    let public_key = match &eth_log.params[1].value {
      token::Token::Bytes(public_key) => Some(public_key),
      _ => None
    }.unwrap();

    let validator_id = ListenContract::convert_publick_key_to_u64(public_key);
  
    let validator = Validator {
      id: validator_id,
      validator_address: address.clone(),
      validator_public_key: public_key.clone()
    };
    if let token::Token::Array(operators) = &eth_log.params[2].value {

      let mut included_self = false;
      // check self is added to a validator
      let operators_list : Vec<Operator> = operators.into_iter().map(|operator_tuple| {
        let operator = match operator_tuple {
          token::Token::Tuple(tuple) => {
            let id = match tuple[0] {
              token::Token::Uint(id) => Some(id.as_u64()) ,
              _ => None
            };
            let node_public_key = match &tuple[1] {
              token::Token::Bytes(node_public_key) => Some(node_public_key),
              _ => None
            };
            if &self.node_public_key == node_public_key.unwrap() {
              included_self = true;
            }

            // check self is included in the list 

            let shared_publick_key = match &tuple[2] {
              token::Token::Bytes(shared_publick_key) => Some(shared_publick_key),
              _ => None
            };
            let encrypted_key = match &tuple[3] {
              token::Token::Bytes(encrypted_key) => Some(encrypted_key),
              _ => None
            };
            let opeartor = Operator {
              id : id.unwrap() + 1, // 0 is a reserved id for threshold signature, so operator id should start from 1
              node_public_key: node_public_key.unwrap().clone(),
              shared_public_key: shared_publick_key.unwrap().clone(),
              encrypted_key: encrypted_key.unwrap().clone()
            };
            Some(opeartor)
          },
          _ => None
        };
        operator.unwrap()
      }).collect();

      if included_self {
        {
          match self.validators_map.read().await.get(&validator_id) {
            Some(_) => { 
              info!("validator already exists");
              return; 
            },
            None => {}
          }
        }
        self.validators_map.write().await.insert(validator_id, Validator {
          id: validator_id,
          validator_address: address.clone(),
          validator_public_key: public_key.to_vec()
        });
        self.validator_operators_map.write().await.insert(validator_id, operators_list);

        // notify and send pk to start consensus
        match event_type {
          ValidatorEventType::ADDED => {
            let _ = self.channel.send(ValidatorCommand::Start(validator)).await;
          },
          ValidatorEventType::UPDATED => {
            // stop and start 
            let _ = self.channel.send(ValidatorCommand::Stop(validator.clone())).await;
            let _ = self.channel.send(ValidatorCommand::Start(validator)).await;
          },
          _ => {}
        };
        
      } else {
        info!("This node is not included in this event. Don't need to do anything.")
      }
      
    }
  }

  pub async fn process_validator_deleted(&self, eth_log: web3::ethabi::Log) {
    let address = match &eth_log.params[0].value {
      token::Token::Address(address) => Some(address),
      _ => None
    }.unwrap();

    let public_key = match &eth_log.params[1].value {
      token::Token::Bytes(public_key) => Some(public_key),
      _ => None
    }.unwrap();

    let validator_id = ListenContract::convert_publick_key_to_u64(public_key);

    // check self is included in this validators
    match self.validators_map.write().await.remove(&validator_id) {
      Some(validator) => {
        let _ = self.channel.send(ValidatorCommand::Stop (validator)).await;
      }, 
      None => {
        let validator = Validator {
          id: validator_id,
          validator_address: address.clone(),
          validator_public_key: public_key.clone()
        };
        let _ = self.channel.send(ValidatorCommand::Stop(validator)).await;
      }
    }
  }

  pub async fn process_validator_add_or_update_event(&self, log: Log, topic: &H256, event_type: ValidatorEventType) {
    let oess = ParamType::Tuple(vec![ParamType::Uint(256 as usize), ParamType::Bytes, ParamType::Bytes, ParamType::Bytes]);
    let event_name = match event_type {
      ValidatorEventType::ADDED => { "ValidatorAdded".to_string() },
      ValidatorEventType::UPDATED => { "ValidatorUpdated".to_string() },
      _ => { "ERROR".to_string() }
    };
    
    let validator_event = Event {
      name: event_name,
      inputs: vec![
        EventParam {
          name: "ownerAddress".to_string(),
          kind: ParamType::Address,
          indexed: false
        }, 
        EventParam {
          name: "publicKey".to_string(),
          kind: ParamType::Bytes,
          indexed: false
        },
        EventParam {
          name: "oessList".to_string(),
          kind: ParamType::Array(Box::new(oess)),
          indexed: false
        }],
      anonymous: false
    };

    let parse_log = validator_event.parse_log(RawLog {
      topics: vec![Hash::from_slice(&topic.0)],
      data: log.data.0
    }).unwrap();

    self.process_validator_info(parse_log, event_type).await;
  }


  pub async fn process_validator_deleted_event(&self, log: Log, topic: &H256) {
    let validators_deleted_event = Event {
      name: "ValidatorDeleted".to_string(),
      inputs: vec![
        EventParam {
          name: "ownerAddress".to_string(),
          kind: ParamType::Address,
          indexed: false
        },
        EventParam {
          name: "publicKey".to_string(),
          kind: ParamType::Bytes,
          indexed: false
        }
      ],
      anonymous: false
    };
    let parse_log = validators_deleted_event.parse_log(RawLog {
      topics: vec![Hash::from_slice(&topic.0)],
      data: log.data.0
    }).unwrap();
    self.process_validator_deleted(parse_log).await;
  }

  pub fn convert_publick_key_to_u64(public_key: &Vec<u8>) -> u64 {
    let mut little_endian: [u8; 8] = [0; 8];
    let mut i = 0;
    for elem in little_endian.iter_mut() {
        *elem = public_key[i];
        i = i + 1;
    } 
    let id = u64::from_le_bytes(little_endian);
    id 
  } 
}
