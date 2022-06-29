use hsconfig::Export as _;
use hsconfig::{ConfigError, Secret};
use log::{info};
use consensus::{ConsensusReceiverHandler};
use mempool::{TxReceiverHandler, MempoolReceiverHandler};
use network::{Receiver as NetworkReceiver};
use std::sync::{Arc};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::net::SocketAddr;
use tokio::sync::mpsc::{channel, Receiver};
use hscrypto::{PublicKey, SecretKey};
/// The default channel capacity for this module.
use crate::node::dvfcore::{DvfInfo, DvfReceiverHandler, DvfSignatureReceiverHandler};
use crate::node::config::NodeConfig;
use std::path::PathBuf;


fn with_wildcard_ip(mut addr: SocketAddr) -> SocketAddr {
    addr.set_ip("0.0.0.0".parse().unwrap());
    addr
}

pub struct Node {
    pub config: NodeConfig,
    pub secret : Secret,
    //pub rx_dvfinfo: Receiver<DvfInfo>,
    pub tx_handler_map : Arc<RwLock<HashMap<u64, TxReceiverHandler>>>,
    pub mempool_handler_map : Arc<RwLock<HashMap<u64, MempoolReceiverHandler>>>,
    pub consensus_handler_map: Arc<RwLock<HashMap<u64, ConsensusReceiverHandler>>>,
    pub signature_handler_map: Arc<RwLock<HashMap<u64, DvfSignatureReceiverHandler>>>,
}

impl Node {

    pub async fn new(
        config: NodeConfig,
    ) -> Result<Self, ConfigError> {

        let secret = Node::open_or_create_secret(config.node_key_path.clone())?;

        let tx_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let mempool_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let consensus_handler_map = Arc::new(RwLock::new(HashMap::new()));
        let signature_handler_map = Arc::new(RwLock::new(HashMap::new()));

        let transaction_address = with_wildcard_ip(config.transaction_address.clone());
        NetworkReceiver::spawn(transaction_address, Arc::clone(&tx_handler_map), "transaction");
        info!("Mempool listening to client transactions on {}", transaction_address);

        let mempool_address = with_wildcard_ip(config.mempool_address.clone());
        NetworkReceiver::spawn(mempool_address, Arc::clone(&mempool_handler_map), "mempool");
        info!("Mempool listening to mempool messages on {}", mempool_address);

        let consensus_address = with_wildcard_ip(config.consensus_address.clone());
        NetworkReceiver::spawn(consensus_address, Arc::clone(&consensus_handler_map), "consensus");
        info!(
            "Node {} Listening to consensus messages on {}",
            secret.name, consensus_address
        );

        let signature_address = with_wildcard_ip(config.signature_address.clone());
        NetworkReceiver::spawn(signature_address, Arc::clone(&signature_handler_map), "signature");
        info!(
            "Node {} listening to signature messages on {}",
            secret.name, signature_address
        );
        
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
        Ok(Self { 
            config,
            secret, 
            //rx_dvfinfo, 
            tx_handler_map: Arc::clone(&tx_handler_map), 
            mempool_handler_map: Arc::clone(&mempool_handler_map), 
            consensus_handler_map: Arc::clone(&consensus_handler_map), 
            signature_handler_map: Arc::clone(&signature_handler_map)}
        )
    }

    pub fn open_or_create_secret(path: PathBuf) -> Result<Secret, ConfigError> {
        if path.exists() {
            Secret::read(path.to_str().unwrap())
        }
        else {
            let secret = Secret::new();
            secret.write(path.to_str().unwrap())?;
            Ok(secret)
        }
    }

    //pub async fn process_dvfinfo(&mut self) {
        //while let Some(dvfinfo) = self.rx_dvfinfo.recv().await {
            //// This is where we can further process committed block.
            //info!("received validator {}", dvfinfo.validator_id);
        //}
      //}
}

