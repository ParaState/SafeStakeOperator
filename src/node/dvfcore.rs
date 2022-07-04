use hsconfig::{Committee as HotstuffCommittee, ConfigError, Parameters};
use consensus::Committee as ConsensusCommittee;
use mempool::Committee as MempoolCommittee;
use consensus::{Block, Consensus};
use hscrypto::SignatureService;
use log::{info, error, warn};
use mempool::{Mempool, MempoolMessage};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use network::{MessageHandler, Writer};
use std::sync::{Arc};
use async_trait::async_trait;
use bytes::Bytes;
use std::error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
pub const CHANNEL_CAPACITY: usize = 1_000;
use bls::{Hash256, Signature};
use types::Keypair;
use crate::validation::operator::{LocalOperator, TOperator};
use futures::SinkExt;
use crate::node::node::Node;
use std::path::PathBuf;
use futures::executor::block_on;
use crate::utils::error::DvfError;
use crate::validation::{OperatorCommittee};
use tokio::sync::{RwLock};
use eth2_hashing::{Context, Sha256Context};
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition; 
use crate::node::config::{NodeConfig, TRANSACTION_PORT_OFFSET, MEMPOOL_PORT_OFFSET, CONSENSUS_PORT_OFFSET, SIGNATURE_PORT_OFFSET};
use std::net::SocketAddr;


#[derive(Serialize, Deserialize, Clone)]
pub struct DvfInfo {
  pub validator_id : u64,
  pub committee: HotstuffCommittee
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
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
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
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
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

pub struct DvfSigner {
    pub signal: Option<exit_future::Signal>,
    pub operator_committee: OperatorCommittee,
}

impl Drop for DvfSigner {
    fn drop(&mut self) {
        if let Some(signal) = self.signal.take() {
            info!("Shutting down Dvf Core");
            let _ = signal.fire();
        } 
    }
}

impl DvfSigner {
    pub async fn spawn(
        node: Arc<Node>,
        validator_id: u64,
        keypair: Keypair,
        committee_def: OperatorCommitteeDefinition,
    ) -> Self {
        let operator_id = node.config.id;
        // Construct the committee for validator signing
        let (mut operator_committee, tx_consensus) = OperatorCommittee::from_definition(committee_def.clone()).await;
        let local_operator = Arc::new(
            RwLock::new(LocalOperator::new(validator_id, operator_id, Arc::new(keypair.clone()), node.config.transaction_address))); 
        operator_committee.add_operator(operator_id, local_operator).await;


        // Construct the committee for hotstuff protocol
        let epoch = 1;
        let stake = 1;
        let mempool_committee = MempoolCommittee::new(
            committee_def.node_public_keys 
                .iter()
                .enumerate()
                .map(|(i, pk)| {
                    let addr = committee_def.base_socket_addresses[i]; 
                    (pk.clone(), 
                     stake, 
                     SocketAddr::new(addr.ip(), addr.port() + TRANSACTION_PORT_OFFSET), 
                     SocketAddr::new(addr.ip(), addr.port() + MEMPOOL_PORT_OFFSET), 
                     SocketAddr::new(addr.ip(), addr.port() + SIGNATURE_PORT_OFFSET), 
                    )
                })
                .collect(),
            epoch,
        );
        let consensus_committee = ConsensusCommittee::new(
            committee_def.node_public_keys 
                .iter()
                .enumerate()
                .map(|(i, pk)| {
                    let addr = committee_def.base_socket_addresses[i]; 
                    (pk.clone(), 
                     stake,
                     SocketAddr::new(addr.ip(), addr.port() + CONSENSUS_PORT_OFFSET),
                    )
                })
                .collect(),
            epoch,
        );
        let hotstuff_committee = HotstuffCommittee {
            mempool: mempool_committee,
            consensus: consensus_committee,
        };

        let signal = DvfCore::spawn(
            node,
            committee_def.validator_id,
            hotstuff_committee,
            keypair,
            tx_consensus,
        );

        Self {
            signal: Some(signal),
            operator_committee,
        }
    }

    pub async fn sign_str(&self, message: &str) -> Result<Signature, DvfError> {
        let mut context = Context::new();
        context.update(message.as_bytes());
        let message_hash = Hash256::from_slice(&context.finalize());

        self.operator_committee.sign(message_hash).await
    }

    pub async fn sign(&self, message: Hash256) -> Result<Signature, DvfError> {
        self.operator_committee.sign(message).await
    }
}

pub struct DvfCore {
    pub store: Store,
    pub commit: Receiver<Block>,
    pub validator_id: u64, 
    pub operator_id: u64,
    pub bls_keypair: Keypair,
    pub tx_consensus: Sender<Hash256>,
    pub operator: LocalOperator,

    pub exit: exit_future::Exit,
}

unsafe impl Send for DvfCore {}
unsafe impl Sync for DvfCore {}



impl DvfCore {
    pub fn spawn(
        node: Arc<Node>,
        validator_id: u64,
        committee: HotstuffCommittee,
        keypair: Keypair,
        tx_consensus: Sender<Hash256>,
    ) -> exit_future::Signal {
        let (tx_commit, rx_commit) = channel(CHANNEL_CAPACITY);
        let (tx_consensus_to_mempool, rx_consensus_to_mempool) = channel(CHANNEL_CAPACITY);
        let (tx_mempool_to_consensus, rx_mempool_to_consensus) = channel(CHANNEL_CAPACITY);

        let operator_id = node.config.id;
        let parameters = Parameters::default();
        let store_path = node.config.base_store_path.join(validator_id.to_string()).join(operator_id.to_string()); 
        let store = Store::new(&store_path.to_str().unwrap()).expect("Failed to create store");

        // Run the signature service.
        let signature_service = SignatureService::new(node.secret.secret.clone());


        {
            block_on(node.signature_handler_map.write())
                .insert(validator_id, DvfSignatureReceiverHandler{store : store.clone()});
            info!("Insert signature handler for validator: {}", validator_id);
        }

        Mempool::spawn(
            node.secret.name,
            committee.mempool,
            parameters.mempool,
            store.clone(),
            rx_consensus_to_mempool,
            tx_mempool_to_consensus,
            validator_id,
            Arc::clone(&node.tx_handler_map),
            Arc::clone(&node.mempool_handler_map)
        );

        Consensus::spawn(
            node.secret.name,
            committee.consensus,
            parameters.consensus,
            signature_service,
            store.clone(),
            rx_mempool_to_consensus,
            tx_consensus_to_mempool,
            tx_commit,
            validator_id,
            Arc::clone(&node.consensus_handler_map)
        );

        info!("[Dvf {}/{}] successfully booted", operator_id, validator_id);

        let operator = LocalOperator::new(validator_id, operator_id, Arc::new(keypair.clone()), node.config.transaction_address);

        let (signal, exit) = exit_future::signal();
        tokio::spawn(async move {
            Self {
                store: store, 
                commit: rx_commit, 
                validator_id: validator_id, 
                operator_id : operator_id,
                bls_keypair: keypair,
                tx_consensus,
                operator,

                exit
            }
            .run()
            .await
        });
        signal
    }

    pub async fn run(&mut self) {
        info!("[Dvf {}/{}] start receiving committed consensus blocks", self.operator_id, self.validator_id);
        loop {
            let exit = self.exit.clone();
            tokio::select!{
                Some(block) = self.commit.recv() => { 
                    // This is where we can further process committed block.
                    if block.payload.is_empty() {
                        continue;
                    }
                    info!("[Dvf {}/{}] received a non-empty committed block", self.operator_id, self.validator_id);
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
                                                    let signature = self.operator.sign(msg.clone()).await.unwrap();
                                                    let serialized_signature = bincode::serialize(&signature).unwrap();
                                                    // save to local db
                                                    self.store.write(batch, serialized_signature).await;

                                                    if let Err(e) = self.tx_consensus.send(msg).await {
                                                        error!("Failed to notify consensus status: {}", e);
                                                    }
                                                    else {
                                                        info!("[Dvf {}/{}] Sent out 1 consensus notification for msg: {}", self.operator_id, self.validator_id, msg);
                                                    }
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
                () = exit => {
                    break;
                }
            }
        }
        info!("[Dvf {}/{}] destroying dvf store", self.operator_id, self.validator_id);
        self.store.notify_destroy().await;
    }
}
