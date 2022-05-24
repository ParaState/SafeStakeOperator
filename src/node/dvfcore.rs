use hotstuff_config::{Committee, ConfigError, Parameters};
use crypto::{PublicKey, SecretKey};
use consensus::{Block, Consensus, ConsensusReceiverHandler};
use crypto::SignatureService;
use log::{info, error, warn};
use mempool::{Mempool, TxReceiverHandler, MempoolReceiverHandler, MempoolMessage};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use network::{MessageHandler, Writer};
use std::sync::{Arc};
use async_trait::async_trait;
use std::collections::HashMap;
use bytes::Bytes;
use std::error::Error;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::fmt;
pub const CHANNEL_CAPACITY: usize = 1_000;
use bls::{Hash256, Signature};
use types::Keypair;
use crate::validation::operator::{LocalOperator, TOperator};
use futures::SinkExt;
#[derive(Serialize, Deserialize, Clone)]
pub struct DvfInfo {
  pub validator_id : u64,
  pub committee: Committee
}

impl fmt::Debug for DvfInfo {
  fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
      write!(
          f,
          "{}: Commitee({:?})",
          self.validator_id,
          serde_json::to_string_pretty(&self.committee)
      )
  }
}

#[derive(Clone)]
pub struct DvfReceiverHandler {
  pub tx_dvfinfo : Sender<DvfInfo>
}

#[async_trait]
impl MessageHandler for DvfReceiverHandler {
    async fn dispatch(&mut self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let dvfinfo = serde_json::from_slice(&message.to_vec())?;
        self.tx_dvfinfo.send(dvfinfo).await.unwrap();
        // Give the change to schedule other tasks.
        tokio::task::yield_now().await;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlsSignature {
  pub pk : bls::PublicKey,
  pub signature: Signature,
  pub id: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureInfo {
  pub from : bls::PublicKey,
  pub signature: Signature,
  pub msg : Hash256,
  pub id: u32
}

impl fmt::Debug for SignatureInfo {
  fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
      write!(
          f,
          "from: {:?}, signature: {:?}, msg: {:?}, id: {}",
          self.from,
          self.signature,
          self.msg,
          self.id
      )
  }
}

#[derive(Clone)]
pub struct DvfSignatureReceiverHandler {
  pub store : Store
}

#[async_trait]
impl MessageHandler for DvfSignatureReceiverHandler {
    async fn dispatch(&mut self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
      let msg: Vec<u8> = message.slice(..).to_vec();  
      match self.store.read(msg).await {
        Ok(value) => {
          match value {
            Some(data) => {
              let _  = writer.send(Bytes::from(data)).await;
            }
            None => {
              let _ = writer.send(Bytes::from("can't find signature, please wait")).await;
            }
          }
        },
        Err(e) => {
          error!("can't read database, {}", e)
        }
      }
      // Give the change to schedule other tasks.
      tokio::task::yield_now().await;
      Ok(())
    }
}

pub struct DvfCore {
  pub store: Store,
  pub commit: Receiver<Block>,
  pub validator_id: u64, 
  pub bls_keypair: Keypair,
  pub bls_id: u64
}

impl DvfCore {
  pub async fn new(
    committee: Committee,
    name: PublicKey,
    secret_key: SecretKey,
    validator_id: u64,
    base_store_path: String,
    tx_handler_map : Arc<RwLock<HashMap<u64, TxReceiverHandler>>>,
    mempool_handler_map : Arc<RwLock<HashMap<u64, MempoolReceiverHandler>>>,
    consensus_handler_map: Arc<RwLock<HashMap<u64, ConsensusReceiverHandler>>>,
    signature_handler_map: Arc<RwLock<HashMap<u64, DvfSignatureReceiverHandler>>>,
    keypair: Keypair,
    bls_id : u64
  ) -> Result<Self, ConfigError> {
    let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);
    let (tx_consensus_to_mempool, rx_consensus_to_mempool) = channel(CHANNEL_CAPACITY);
    let (tx_mempool_to_consensus, rx_mempool_to_consensus) = channel(CHANNEL_CAPACITY);

    let parameters = Parameters::default();
    let store_path = format!("{}/{}", base_store_path, validator_id);
    let store = Store::new(&store_path).expect("Failed to create store");

    // Run the signature service.
    let signature_service = SignatureService::new(secret_key);

    info!(
      "Node {} create a dvfcore instance with validator id {}",
      name, validator_id.clone()
    );

    {
      let mut handler_map = signature_handler_map.write().await;
      handler_map.insert(validator_id, DvfSignatureReceiverHandler{store : store.clone()});
      info!("insert into signature handler_map");
    }

    Mempool::spawn(
      name,
      committee.mempool,
      parameters.mempool,
      store.clone(),
      rx_consensus_to_mempool,
      tx_mempool_to_consensus,
      validator_id,
      Arc::clone(&tx_handler_map),
      Arc::clone(&mempool_handler_map)
    );

    Consensus::spawn(
      name,
      committee.consensus,
      parameters.consensus,
      signature_service,
      store.clone(),
      rx_mempool_to_consensus,
      tx_consensus_to_mempool,
      tx_commit,
      validator_id,
      Arc::clone(&consensus_handler_map)
    );
    info!("dvfcore {} successfully booted", validator_id);
    Ok(Self { commit: rx_commit, store: store, validator_id: validator_id, bls_keypair: keypair, bls_id : bls_id})
    
  }

  pub async fn save_committed_block(&mut self) {
    let operator = LocalOperator::new(self.validator_id ,Arc::new(self.bls_keypair.clone()));
    while let Some(block) = self.commit.recv().await {
        // This is where we can further process committed block.
        if !block.payload.is_empty() {
          println!("committed block");
          for payload in block.payload {
            match self.store.read(payload.to_vec()).await {
              Ok(value) => {
                match value {
                  Some(data) => {
                    let message: MempoolMessage = bincode::deserialize(&data[..]).unwrap();
                    match message {
                      MempoolMessage::Batch(batches) => {
                        for batch in batches {
                          // construct hash256
                          let msg = Hash256::from_slice(&batch[..]);
                          let signature = operator.sign(msg.clone(), self.validator_id).unwrap();
                          let serialized_signature = bincode::serialize(&signature).unwrap();
                          // save to local db
                          self.store.write(batch, serialized_signature).await;
                        }
                      }
                      MempoolMessage::BatchRequest(_, _) => { }
                    }
                  }
                  None => {
                    warn!("block is empty");
                  }
                }
              },
              Err(e) => {
                error!("can't read database, {}", e)
              }
            }
          }
        }
    }
  }
}