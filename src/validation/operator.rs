use types::{Hash256, Signature, Keypair, PublicKey};
use std::sync::Arc;
use crate::utils::error::DvfError;
use network::{ReliableSender, SimpleSender, DvfMessage};
use std::net::SocketAddr;
use bytes::Bytes;
use std::collections::HashSet;
use downcast_rs::DowncastSync;
use futures::executor::block_on;
use tokio::sync::mpsc::{self, Receiver};
use std::time::Duration;
use tokio::time::timeout;
use log::{info, warn};

pub enum OperatorMessage {
}

pub trait TOperator: DowncastSync + Sync + Send {
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>; 
    fn public_key(&self) -> PublicKey;
    fn propose(&self, msg: Hash256);
}
impl_downcast!(sync TOperator);

pub struct LocalOperator {
    pub validator_id: u64,
    pub operator_id: u64,
    pub operator_keypair: Arc<Keypair>,
    pub transaction_address: SocketAddr,
}

impl TOperator for LocalOperator {

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        Ok(self.operator_keypair.sk.sign(msg))
    }

    fn public_key(&self) -> PublicKey {
        self.operator_keypair.pk.clone()
    }

    fn propose(&self, msg: Hash256) {
        let mut sender = SimpleSender::new();
        let dvf_message = DvfMessage { validator_id: self.validator_id, message: msg.to_fixed_bytes().to_vec()};
        block_on(sender.send(self.transaction_address, Bytes::from(bincode::serialize(&dvf_message).unwrap())));
    }
}

impl LocalOperator {
    pub fn new(validator_id: u64, operator_id: u64, operator_keypair: Arc<Keypair>, transaction_address: SocketAddr) -> Self {
        Self {
            validator_id,
            operator_id,
            operator_keypair,
            transaction_address,
        }
    }
}

pub struct RemoteOperator {
    pub validator_id: u64,
    pub operator_id: u64,
    pub operator_public_key: PublicKey,
    pub signature_address: SocketAddr,
}

impl TOperator for RemoteOperator {
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> { 
        let timeout_mill :u64 = 200;
        // Err(DvfError::Unknown)
        let mut sender = ReliableSender::new();
        let dvf_message = DvfMessage { validator_id: self.validator_id, message: msg.to_fixed_bytes().to_vec()};
        let serialize_msg = bincode::serialize(&dvf_message).unwrap();
        for retry in 0..5 {
            let receiver = block_on(sender.send(self.signature_address, Bytes::from(serialize_msg.clone())));
            let result = block_on(timeout(Duration::from_millis(timeout_mill), receiver)); 
            match result {
                Ok(output) => {
                    match output {
                        Ok(data) => {
                            match bincode::deserialize::<Signature>(&data) {
                                Ok(bls_signature) =>{
                                    info!("Received a signature from operator {} ({:?})", self.operator_id, self.signature_address);
                                    return Ok(bls_signature);
                                }
                                Err(e) => {
                                    warn!("Deserialize failed, retry...");
                                }
                            }
                        },
                        Err(e) => {
                            warn!("recv is interrupted.");
                        }
                    }
                },
                Err(_) => {
                    warn!("Retry");
                }
            }
        }
        warn!("Failed to receive a signature from operator {} ({:?})", self.operator_id, self.signature_address);
        Err(DvfError::Unknown)
    }

    fn public_key(&self) -> PublicKey {
        self.operator_public_key.clone()
    }

    fn propose(&self, msg: Hash256) { }

}

impl RemoteOperator {
    pub fn new(validator_id: u64, operator_id: u64, operator_public_key: PublicKey, signature_address: SocketAddr) -> Self {
        Self {
            validator_id,
            operator_id,
            operator_public_key,
            signature_address, 
        }
    }

}

