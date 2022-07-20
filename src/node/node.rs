use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use log::{info, error};
use consensus::{ConsensusReceiverHandler};
use mempool::{TxReceiverHandler, MempoolReceiverHandler};
use network::{Receiver as NetworkReceiver};
use std::sync::{Arc};
use std::collections::HashMap;
use tokio::sync::RwLock;
use parking_lot::RwLock as ParkingRwLock;
use std::net::SocketAddr;
use tokio::sync::mpsc::{channel, Receiver};
use slog::{Logger, o};
/// The default channel capacity for this module.
use crate::node::dvfcore::{ DvfSignatureReceiverHandler};
use crate::node::config::{NodeConfig, DISCOVERY_PORT_OFFSET, DEFAULT_BASE_PORT, BASE64_ENR};
use std::path::PathBuf;
use std::net::IpAddr;
use crate::node::contract::{ValidatorPublicKey, ValidatorCommand, Validator, Operator};
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::node::discovery::Discovery;
use crate::node::contract::{ListenContract, ContractConfig};
use types::PublicKey;
use crate::validation::account_utils::default_operator_committee_definition_path;
use crate::node::dvfcore::{DvfCore, DvfSigner};
const THRESHOLD: u64 = 3;
use types::EthSpec;
use crate::validation::validator_store::ValidatorStore;
use slot_clock::SystemTimeSlotClock;
use environment::RuntimeContext;

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

impl<T: EthSpec> Node<T> {

    pub fn new(
        config: NodeConfig
    ) -> Result<Option<Arc<ParkingRwLock<Self>>>, ConfigError> {
        let secret_exists = config.node_key_path.exists();
        let secret = Node::<T>::open_or_create_secret(config.node_key_path.clone())?;

        let tx_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let mempool_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let consensus_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let signature_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>> = Arc::new(RwLock::new(HashMap::new()));
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

        let (tx_validator_command, mut rx_validator_command) = channel(5);


        
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
        let node = Self { 
            config,
            secret, 
            //rx_dvfinfo, 
            tx_handler_map: Arc::clone(&tx_handler_map), 
            mempool_handler_map: Arc::clone(&mempool_handler_map), 
            consensus_handler_map: Arc::clone(&consensus_handler_map), 
            signature_handler_map: Arc::clone(&signature_handler_map),
            validator_store: None
            // key_ip_map: Arc::clone(&key_ip_map),
            // validators_map: Arc::clone(&validators_map),
            // validator_operators_map: Arc::clone(&validator_operators_map)
        };

        Discovery::spawn(node.config.clone().base_address.ip(), DEFAULT_BASE_PORT, key_ip_map.clone(), node.secret.clone(), Some(BASE64_ENR.to_string()));

        let contract_config = ContractConfig::default();
        ListenContract::spawn(contract_config, !secret_exists, node.secret.name.0.to_vec(), node.config.backend_address.clone(), tx_validator_command, validators_map.clone(), validator_operators_map.clone());

        let node = Arc::new(ParkingRwLock::new(node));

        Node::process_validator_command(Arc::clone(&node), validators_map, validator_operators_map, key_ip_map, rx_validator_command, DEFAULT_BASE_PORT, validator_dir, secrets_dir);
        
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

    pub fn process_validator_command(node: Arc<ParkingRwLock<Node<T>>>, validators_map: Arc<RwLock<HashMap<u64, Validator>>>, validator_operators_map: Arc<RwLock<HashMap<u64, Vec<Operator>>>>, operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,  mut rx_validator_command: Receiver<ValidatorCommand>, base_port: u16, validator_dir: PathBuf, secret_dir: PathBuf) {
        let log = Logger::root(slog::Discard, o!("service" => "process_validator_command"));
        tokio::spawn(async move {
            let node = node;
            loop {
                match rx_validator_command.recv().await {
                    Some(validator_command) => {
                        match validator_command {
                            ValidatorCommand::Start(validator) => {
                                let id = validator.id;
                                let validator_address = std::str::from_utf8(validator.validator_address.as_bytes()).unwrap();
                                let validator_operators = validator_operators_map.read().await;
                                let operators_vec = validator_operators.get(&id);

                                match operators_vec {
                                    Some(operators) => {
                                        let key_ip_map = operator_key_ip_map.read().await;

                                        let mut operator_base_address : Vec<SocketAddr> = Vec::default();
                                        let mut operator_ids: Vec<u64> = Vec::default();
                                        let mut operator_public_keys: Vec<PublicKey> = Vec::default();
                                        let mut node_public_keys: Vec<hscrypto::PublicKey> = Vec::default();
                                        for operator in operators {
                                            let operator_public_key = String::from_utf8(operator.node_public_key.clone()).unwrap();
                                            let ip = key_ip_map.get(&operator_public_key);
                                            // get all ips from 
                                            match ip {
                                                Some(ip) => {
                                                    operator_base_address.push(SocketAddr::new(ip.clone(), base_port + DISCOVERY_PORT_OFFSET));
                                                    operator_ids.push(operator.id);

                                                    let operator_pk = PublicKey::deserialize(&operator.shared_public_key).unwrap();
                                                    operator_public_keys.push(operator_pk);

                                                    let node_pk = hscrypto::PublicKey::decode_base64(&String::from_utf8(operator.node_public_key.clone()).unwrap()).unwrap();
                                                    node_public_keys.push(node_pk);
                                                },
                                                None => {
                                                    error!("can't discover the operator {}", operator_public_key);
                                                    break;
                                                }
                                            }
                                        }
                                        if operator_base_address.len() != operators.len() {
                                            error!("there are not sufficient operators being discovered");
                                            continue;
                                        }

                                        // generate keypair
                                        let validator_pk = PublicKey::deserialize(&validator.validator_public_key).unwrap();


                                        
                                        let def = OperatorCommitteeDefinition {
                                            total: operators.len() as u64,
                                            threshold: THRESHOLD,
                                            validator_id: id,
                                            validator_public_key: validator_pk.clone(),
                                            operator_ids: operator_ids,
                                            operator_public_keys: operator_public_keys,
                                            node_public_keys: node_public_keys,
                                            base_socket_addresses: operator_base_address
                                        };

                                        // TODO: save sk 

                                        let committee_def_path = default_operator_committee_definition_path(&validator_pk, validator_dir.clone());
                                        def.to_file(committee_def_path).map_err(|e| format!("Unable to save committee definition: {:?}", e)).unwrap();
                                        
                                        let node = node.read();
                                        match &node.validator_store {
                                            Some(validator_store) => {
                                                let initialized_validators_arc = validator_store.initialized_validators();
                                                let mut initialized_validators = initialized_validators_arc.write();
                                                
                                                let validator_definitions = initialized_validators.validator_definitions_();

                                                validator_definitions.discover_distributed_keystores(&validator_dir, &secret_dir, &log).unwrap();

                                                validator_definitions.save(&validator_dir).unwrap();
                                            },
                                            _ => {error!("unexpected error happen"); }
                                        }


                                    }, 
                                    None => {
                                        error!("can't find validator's releated operators");
                                    }
                                }


                            },
                            ValidatorCommand::Stop(validator) => {
                                


                            }
                        }
                    }
                    None => {
                        error!("channel is closed unexpected");
                    }
                }
            }
        });
    }

    //pub async fn process_dvfinfo(&mut self) {
        //while let Some(dvfinfo) = self.rx_dvfinfo.recv().await {
            //// This is where we can further process committed block.
            //info!("received validator {}", dvfinfo.validator_id);
        //}
      //}
}

